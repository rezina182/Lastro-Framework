'use strict';

// Verificações estáticas do repositório (sem rede). Cada verificação devolve:
//   { state: 'verified'|'failed'|'unverified'|'not_applicable', findings: [...], notes: [...] }
// Princípio: "não sei" nunca vira "passou". Quando algo não pode ser avaliado, o estado é unverified.

const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { hasPrefix, parseDate, readJson } = require('../util');
const schema = require('../schema');

const verified = (notes = []) => ({ state: 'verified', findings: [], notes });
const failed = (findings, notes = []) => ({ state: findings.length ? 'failed' : 'verified', findings, notes });
const notApplicable = (note) => ({ state: 'not_applicable', findings: [], notes: [note] });
const unverified = (note) => ({ state: 'unverified', findings: [], notes: [note] });

const workflows = (ctx) => ctx.files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f));
const DAY_MS = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------------------------
// CORE: segredos, dependências, CI
// ---------------------------------------------------------------------------------------------

function envIgnored(ctx) {
  const findings = [];
  for (const f of ctx.files) {
    const base = f.split('/').pop();
    if (/^\.env(\..+)?$/.test(base) && !/\.(example|sample|template|dist)$/.test(base)) {
      findings.push({ severity: 'critical', key: `env:${f}`, location: f, message: `Arquivo de ambiente no repositório (rastreado ou prestes a ser): ${f}` });
    }
    if (/\.(pem|p12|pfx|key)$/i.test(base) || /^id_(rsa|ed25519|ecdsa)$/.test(base)) {
      findings.push({ severity: 'high', key: `key:${f}`, location: f, message: `Possível chave ou certificado privado no repositório: ${f}` });
    }
  }
  let ignored = false;
  if (ctx.isGit) {
    try {
      execFileSync('git', ['check-ignore', '-q', '.env'], { cwd: ctx.root, stdio: 'ignore' });
      ignored = true;
    } catch (e) {
      ignored = false;
    }
  } else {
    const gi = ctx.read('.gitignore');
    ignored = gi !== null && /^\s*\/?\.env(\*|\.\*|\.local)?\s*$/m.test(gi);
  }
  if (!ignored) {
    findings.push({ severity: 'high', key: 'gitignore-env', location: '.gitignore', message: '".env" não está no .gitignore: um segredo local pode ser commitado por engano.' });
  }
  return failed(findings);
}

const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const NODE_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'];

function lockfileExact(ctx) {
  const findings = [];
  const notes = [];
  let touched = false;

  const pkgText = ctx.read('package.json');
  if (pkgText !== null) {
    touched = true;
    let pkg = null;
    try {
      pkg = JSON.parse(pkgText);
    } catch (e) {
      findings.push({ severity: 'medium', key: 'package-json-invalid', location: 'package.json', message: 'package.json não é um JSON válido.' });
    }
    if (pkg) {
      const prod = { ...(pkg.dependencies || {}), ...(pkg.optionalDependencies || {}) };
      const dev = pkg.devDependencies || {};
      const total = Object.keys(prod).length + Object.keys(dev).length;
      if (total === 0) {
        notes.push('package.json sem dependências.');
      } else {
        if (!NODE_LOCKS.some((l) => ctx.has(l))) {
          findings.push({ severity: 'high', key: 'node-no-lockfile', location: 'package.json', message: 'Há dependências, mas nenhum lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml).' });
        }
        const loose = (deps, sev) => {
          for (const [name, v] of Object.entries(deps)) {
            if (typeof v !== 'string') continue;
            if (/^(workspace|file|link|npm):/.test(v)) continue;
            if (!EXACT.test(v)) findings.push({ severity: sev, key: `range:${name}`, location: 'package.json', message: `Versão não exata para "${name}": ${v}` });
          }
        };
        loose(prod, 'medium');
        loose(dev, 'low');
      }
    }
  }

  const reqs = ctx.files.filter((f) => /^requirements[^/]*\.txt$/.test(f));
  for (const f of reqs) {
    touched = true;
    const t = ctx.read(f) || '';
    t.split(/\r?\n/).forEach((line, i) => {
      const l = line.trim();
      if (!l || l.startsWith('#') || l.startsWith('-')) return;
      if (!/==/.test(l)) findings.push({ severity: 'medium', key: `py:${f}:${l.split(/[<>=~! ;]/)[0]}`, location: `${f}:${i + 1}`, message: `Dependência Python sem versão exata (==): ${l.slice(0, 60)}` });
    });
  }
  if (ctx.has('pyproject.toml')) {
    touched = true;
    if (!['poetry.lock', 'uv.lock', 'Pipfile.lock', 'pdm.lock'].some((l) => ctx.has(l)) && reqs.length === 0) {
      findings.push({ severity: 'high', key: 'py-no-lockfile', location: 'pyproject.toml', message: 'pyproject.toml sem lockfile (poetry.lock, uv.lock, pdm.lock).' });
    }
  }
  if (ctx.has('go.mod')) {
    touched = true;
    if (!ctx.has('go.sum')) findings.push({ severity: 'high', key: 'go-no-sum', location: 'go.mod', message: 'go.mod sem go.sum.' });
  }
  if (ctx.has('Cargo.toml')) {
    touched = true;
    if (!ctx.has('Cargo.lock')) findings.push({ severity: 'medium', key: 'rust-no-lock', location: 'Cargo.toml', message: 'Cargo.toml sem Cargo.lock.' });
  }

  if (!touched) return notApplicable('Nenhum gerenciador de pacotes reconhecido (Node, Python, Go, Rust).');
  return failed(findings, notes);
}

function actionsPinned(ctx) {
  const wf = workflows(ctx);
  if (wf.length === 0) return notApplicable('Nenhum workflow do GitHub Actions encontrado.');
  const findings = [];
  for (const f of wf) {
    (ctx.read(f) || '').split(/\r?\n/).forEach((raw, i) => {
      const line = raw.replace(/\s#.*$/, '');
      const m = /^\s*-?\s*uses:\s*['"]?([^\s'"]+)['"]?/.exec(line);
      if (!m) return;
      const ref = m[1];
      if (ref.startsWith('./')) return;
      if (ref.startsWith('docker://')) {
        if (!/@sha256:[0-9a-f]{64}/.test(ref)) findings.push({ severity: 'medium', key: `${f}:${ref}`, location: `${f}:${i + 1}`, message: `Imagem Docker sem digest: ${ref}` });
        return;
      }
      const at = /^([^@]+)@(.+)$/.exec(ref);
      if (!at || !/^[0-9a-f]{40}$/.test(at[2])) {
        findings.push({ severity: 'high', key: `${f}:${ref}`, location: `${f}:${i + 1}`, message: `Action não fixada por SHA de commit: ${ref}` });
      }
    });
  }
  return failed(findings);
}

function ciPermissions(ctx) {
  const wf = workflows(ctx);
  if (wf.length === 0) return notApplicable('Nenhum workflow do GitHub Actions encontrado.');
  const findings = [];
  for (const f of wf) {
    const t = ctx.read(f) || '';
    const hasTop = /^permissions\s*:/m.test(t);
    const jobsIdx = t.search(/^jobs\s*:/m);
    const jobsText = jobsIdx >= 0 ? t.slice(jobsIdx) : '';
    const jobCount = (jobsText.match(/^ {2}[A-Za-z0-9_-]+\s*:\s*$/gm) || []).length;
    const jobPerms = (jobsText.match(/^ {4}permissions\s*:/gm) || []).length;
    if (!hasTop && jobPerms < jobCount) findings.push({ severity: 'high', key: `perm:${f}`, location: f, message: 'Workflow sem bloco "permissions": o token padrão pode ter escrita em tudo.' });
    if (/permissions\s*:\s*write-all/.test(t)) findings.push({ severity: 'high', key: `writeall:${f}`, location: f, message: 'Workflow com permissions: write-all.' });
    if (/\bpull_request_target\b/.test(t)) findings.push({ severity: 'high', key: `prt:${f}`, location: f, message: 'Workflow usa pull_request_target (roda com segredos em contexto de PR externo).' });
  }
  return failed(findings);
}

const SECRET_SCANNERS = /gitleaks|trufflehog|detect-secrets|secretlint|git-secrets/i;

function ciSecretScan(ctx) {
  const wf = workflows(ctx);
  if (wf.length === 0) {
    if (['.gitlab-ci.yml', 'azure-pipelines.yml', 'Jenkinsfile', '.circleci/config.yml'].some((f) => ctx.has(f))) return unverified('CI diferente do GitHub Actions: a v0.1 não analisa. Registre uma atestação.');
    return failed([{ severity: 'high', key: 'no-ci', message: 'Nenhum CI encontrado: nenhuma varredura de segredos roda automaticamente.' }]);
  }
  const hit = wf.find((f) => SECRET_SCANNERS.test(ctx.read(f) || ''));
  if (hit) return verified([`Varredura de segredos referenciada em ${hit} (heurística por texto).`]);
  return failed([{ severity: 'high', key: 'no-secret-scan', message: 'Nenhum scanner de segredos (gitleaks, trufflehog...) nos workflows.' }]);
}

const DEP_AUDITORS = /npm audit|pnpm audit|yarn (npm )?audit|pip-audit|osv-scanner|safety check|cargo audit|govulncheck|dependency-review-action|trivy/i;

function ciDepAudit(ctx) {
  const wf = workflows(ctx);
  if (wf.length === 0) {
    if (['.gitlab-ci.yml', 'azure-pipelines.yml', 'Jenkinsfile', '.circleci/config.yml'].some((f) => ctx.has(f))) return unverified('CI diferente do GitHub Actions: a v0.1 não analisa. Registre uma atestação.');
    return failed([{ severity: 'high', key: 'no-ci', message: 'Nenhum CI encontrado: a auditoria de dependências não roda automaticamente.' }]);
  }
  const findings = [];
  let found = null;
  for (const f of wf) {
    (ctx.read(f) || '').split(/\r?\n/).forEach((line, i) => {
      if (!DEP_AUDITORS.test(line)) return;
      found = found || f;
      if (/\|\|\s*true\b/.test(line)) findings.push({ severity: 'medium', key: `audit-soft:${f}:${i + 1}`, location: `${f}:${i + 1}`, message: 'A auditoria de dependências não bloqueia (termina com "|| true").' });
    });
  }
  if (!found) return failed([{ severity: 'high', key: 'no-dep-audit', message: 'Nenhuma auditoria de dependências (npm audit, pip-audit, osv-scanner...) nos workflows.' }]);
  return failed(findings, [`Auditoria referenciada em ${found} (heurística por texto).`]);
}

function updateBot(ctx) {
  const has = ['.github/dependabot.yml', '.github/dependabot.yaml', 'renovate.json', '.github/renovate.json', '.renovaterc', '.renovaterc.json'].some((f) => ctx.has(f));
  return has ? verified() : failed([{ severity: 'low', key: 'no-update-bot', message: 'Sem Dependabot ou Renovate configurado.' }]);
}

function securityMd(ctx) {
  const f = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'].find((p) => ctx.has(p));
  if (!f) {
    // security.txt (RFC 9116), versionado ou servido pela própria aplicação, também é um canal de reporte.
    const txt = ctx.files.find((p) => /(^|\/)security\.txt$/.test(p));
    if (txt) return verified([`Canal de reporte em ${txt} (security.txt). Confira se há também um SECURITY.md para quem lê o repositório.`]);
    const served = codeFiles(ctx).find((p) => (ctx.read(p) || '').includes('.well-known/security.txt'));
    if (served) return verified([`security.txt servido pela aplicação (${served}, heurística por texto). Confira se há também um SECURITY.md para quem lê o repositório.`]);
    return failed([{ severity: 'medium', key: 'no-security-md', message: 'SECURITY.md ausente: não há canal público para reportar vulnerabilidades.' }]);
  }
  const t = ctx.read(f) || '';
  if (t.trim().length < 200 || !/(contato|contact|report|reportar|e-?mail|advisor|vulnerabilidade)/i.test(t)) {
    return failed([{ severity: 'medium', key: 'weak-security-md', location: f, message: `${f} existe, mas não descreve como reportar uma vulnerabilidade.` }]);
  }
  return verified([`Encontrado em ${f}.`]);
}

function threatModel(ctx) {
  const f = ['THREAT-MODEL.md', 'threat-model.md', 'docs/THREAT-MODEL.md', 'docs/threat-model.md', '.lastro/threat-model.md'].find((p) => ctx.has(p));
  if (!f) return failed([{ severity: 'high', key: 'no-threat-model', message: 'Nenhum threat model versionado (THREAT-MODEL.md).' }]);
  const t = ctx.read(f) || '';
  const m = /(Última revisão|Ultima revisao|Last reviewed)\s*:\s*(\d{4}-\d{2}-\d{2})/i.exec(t);
  if (!m) return failed([{ severity: 'medium', key: 'tm-no-date', location: f, message: `${f} não registra "Última revisão: AAAA-MM-DD".` }]);
  const ts = parseDate(m[2]);
  if (ts === null) return failed([{ severity: 'medium', key: 'tm-bad-date', location: f, message: 'Data de revisão inválida.' }]);
  if (ts > ctx.now.getTime() + DAY_MS) return failed([{ severity: 'medium', key: 'tm-future', location: f, message: 'Data de revisão no futuro.' }]);
  const idade = Math.floor((ctx.now.getTime() - ts) / DAY_MS);
  const max = ctx.thresholds.threatModelMaxAgeDays;
  if (idade > max) return failed([{ severity: 'medium', key: 'tm-stale', location: f, message: `Threat model sem revisão há ${idade} dias (limite ${max}).` }]);
  return verified([`Revisado há ${idade} dias.`]);
}

function risksValid(ctx) {
  const files = ctx.files.filter((f) => /^\.lastro\/risks\/[^/]+\.json$/.test(f));
  if (files.length === 0) return verified(['Nenhum risco aceito registrado.']);
  const findings = [];
  for (const f of files) {
    const j = readJson(ctx.root, f);
    if (!j.ok) {
      findings.push({ severity: 'high', key: `invalid:${f}`, location: f, message: `Risco inválido (${j.error}).` });
      continue;
    }
    const errs = schema.validateRisk(j.value, f);
    if (errs.length) {
      findings.push({ severity: 'high', key: `invalid:${f}`, location: f, message: `Risco com formato inválido: ${errs[0]}` });
      continue;
    }
    const r = j.value;
    const exp = parseDate(r.expires);
    if (exp <= ctx.now.getTime()) findings.push({ severity: 'high', key: `expired:${r.id}`, location: f, message: `Risco aceito ${r.id} expirou em ${r.expires}: volta a contar como achado.` });
    else if (exp - ctx.now.getTime() <= 14 * DAY_MS) findings.push({ severity: 'low', key: `expiring:${r.id}`, location: f, message: `Risco aceito ${r.id} expira em ${r.expires}: renove ou corrija.` });
    if (ctx.catalog && !ctx.catalog.byId.has(r.control)) findings.push({ severity: 'medium', key: `unknown-control:${r.id}`, location: f, message: `Risco ${r.id} aponta para controle inexistente (${r.control}).` });
  }
  return failed(findings);
}

// ---------------------------------------------------------------------------------------------
// CORE: padrões perigosos no código
// ---------------------------------------------------------------------------------------------

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.rb', '.php', '.go', '.java', '.cs', '.html', '.htm', '.vue', '.svelte', '.sh', '.ps1']);
const SUPPRESS = /lastro-ignore\s+([\w.-]+)\s*:\s*(\S.*)$/;

function codeFiles(ctx) {
  return ctx.files.filter((f) => CODE_EXT.has(path.extname(f).toLowerCase()) && !/\.min\.js$/.test(f) && !hasPrefix(f, ctx.excludePrefixes));
}

/** Aplica uma lista de padrões linha a linha, respeitando supressões justificadas. */
function scanPatterns(ctx, ruleName, patterns, defaultSeverity) {
  const findings = [];
  const suppressed = [];
  for (const f of codeFiles(ctx)) {
    const ext = path.extname(f).toLowerCase();
    const t = ctx.read(f);
    if (t === null) continue;
    t.split(/\r?\n/).forEach((line, i) => {
      if (line.length > 2000) return;
      for (const p of patterns) {
        if (p.ext && !p.ext.includes(ext)) continue;
        const m = p.re.exec(line);
        if (!m) continue;
        if (p.skip && p.skip(line, m)) continue;
        const sup = SUPPRESS.exec(line);
        if (sup && sup[1] === ruleName) {
          if (sup[2].trim().length >= 4) {
            suppressed.push(`${f}:${i + 1} (${ruleName}): ${sup[2].trim().slice(0, 80)}`);
            continue;
          }
          findings.push({ severity: 'medium', key: `${ruleName}:nojust:${f}:${i + 1}`, location: `${f}:${i + 1}`, message: 'Supressão sem justificativa (escreva o motivo depois de ":").' });
          continue;
        }
        const severity = p.severityFn ? p.severityFn(line, m) : (p.severity || defaultSeverity);
        findings.push({ severity, key: `${ruleName}:${p.id}:${f}:${i + 1}`, location: `${f}:${i + 1}`, message: p.message });
      }
    });
  }
  const notes = suppressed.length ? [`${suppressed.length} supressão(ões) justificada(s):`, ...suppressed] : [];
  return failed(findings, notes);
}

const TLS_PATTERNS = [
  { id: 'reject-unauthorized', re: /rejectUnauthorized\s*:\s*false/, message: 'Verificação de certificado TLS desligada (opção do Node).' },
  { id: 'node-tls-env', re: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0/, message: 'Verificação de TLS desligada por variável de ambiente.' },
  { id: 'py-verify', re: /\bverify\s*=\s*False\b/, ext: ['.py'], message: 'Verificação de TLS desligada (verify=False).' },
  { id: 'go-insecure', re: /InsecureSkipVerify\s*:\s*true/, ext: ['.go'], message: 'Verificação de TLS desligada (InsecureSkipVerify).' },
  { id: 'py-unverified-ctx', re: new RegExp('_create_' + 'unverified_context'), ext: ['.py'], message: 'Contexto SSL sem verificação.' },
];

function tlsVerification(ctx) {
  return scanPatterns(ctx, 'tls-verification', TLS_PATTERNS, 'high');
}

const EVAL_PATTERNS = [
  { id: 'eval', re: /(^|[^\w$.])eval\s*\(/, message: 'Execução dinâmica de código (eval): risco de injeção de código.' },
  { id: 'new-function', re: /\bnew\s+Function\s*\(/, message: 'Execução dinâmica de código (construtor Function).' },
  { id: 'py-shell', re: /\bshell\s*=\s*True\b/, ext: ['.py'], message: 'Chamada de shell com shell=True: risco de injeção de comando.' },
  { id: 'py-os-system', re: /\bos\.system\s*\(/, ext: ['.py'], message: 'Chamada os.system: risco de injeção de comando.' },
  { id: 'py-exec', re: /(^|[^\w.])exec\s*\(/, ext: ['.py'], message: 'Execução dinâmica de código (exec).' },
  { id: 'node-shell', re: /\bshell\s*:\s*true\b/, ext: ['.js', '.mjs', '.cjs', '.ts'], message: 'child_process com shell ligado: risco de injeção de comando.' },
];

function dynamicEval(ctx) {
  return scanPatterns(ctx, 'dynamic-eval', EVAL_PATTERNS, 'high');
}

const LITERAL_ONLY = /^\s*(['"`])(?:(?!\1)[^\\$+]|\\.)*\1\s*;?\s*(\/\/.*)?$/;
const XSS_PATTERNS = [
  {
    id: 'inner-html',
    re: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)(.*)$/,
    // Template literal (`...`) é analisado por inteiro em templateAssignments, não só pela primeira linha.
    skip: (line, m) => LITERAL_ONLY.test(m[1]) || /^\s*`/.test(m[1]),
    // Variável solta (innerHTML = html) é evidência fraca: o escape depende de como ela foi montada (veja os templates).
    severityFn: (line, m) => (/^\s*[A-Za-z_$][\w$.]*\s*;?\s*(?:\/\/.*)?$/.test(m[1]) ? 'low' : 'medium'),
    message: 'Escrita de HTML por atribuição (innerHTML/outerHTML) com conteúdo não literal: risco de XSS.',
  },
  { id: 'insert-adjacent', re: /insertAdjacentHTML\s*\(/, message: 'insertAdjacentHTML: risco de XSS se o conteúdo vier de fora.' },
  { id: 'document-write', re: /document\.write(?:ln)?\s*\(/, message: 'document.write: risco de XSS.' },
  { id: 'react-danger', re: new RegExp('dangerously' + 'SetInnerHTML'), message: 'Renderização de HTML cru no React.' },
  { id: 'vue-vhtml', re: new RegExp('\\bv' + '-html\\b'), message: 'Renderização de HTML cru no Vue.' },
];

// Funções reconhecidas como escape ou conversão segura de saída. O perfil acrescenta as do projeto em scan.safeFunctions.
// Início de um template de HTML: atribuído a innerHTML/outerHTML, ou um template que começa com uma tag e é
// atribuído, acrescentado (+=), retornado ou devolvido por uma arrow function.
const ASSIGN_HTML = /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*`/g;
const HTML_TEMPLATE = /(?:=>|\+=|(?<![=!<>+])=(?![=>])|\breturn\b)\s*`\s*<[A-Za-z!]/g;

const DEFAULT_SAFE_FUNCTIONS = [
  'escHtml', 'escHTML', 'escapeHtml', 'escapeHTML', 'esc', 'escape', 'sanitize', 'sanitizeHtml', 'DOMPurify.sanitize',
  'encodeURIComponent', 'encodeURI', 'Number', 'parseInt', 'parseFloat', 'Boolean',
];

function skipString(src, from) {
  const quote = src[from];
  let j = from + 1;
  while (j < src.length && src[j] !== quote && src[j] !== '\n') {
    if (src[j] === '\\') j += 1;
    j += 1;
  }
  return j + 1;
}

/** Lê um template literal (src[start] é a crase de abertura). Devolve as interpolações, com os templates aninhados dentro delas. */
function readTemplate(src, start) {
  const exprs = [];
  let i = start + 1;
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '`') return { end: i + 1, exprs };
    if (c === '$' && src[i + 1] === '{') {
      let depth = 1;
      let j = i + 2;
      const nested = [];
      while (j < src.length && depth > 0) {
        const ch = src[j];
        if (ch === '`') {
          const inner = readTemplate(src, j);
          nested.push(...inner.exprs);
          j = inner.end;
          continue;
        }
        if (ch === '"' || ch === "'") { j = skipString(src, j); continue; }
        if (ch === '{') depth += 1;
        else if (ch === '}') depth -= 1;
        j += 1;
      }
      exprs.push({ text: src.slice(i + 2, j - 1), nested });
      i = j;
      continue;
    }
    i += 1;
  }
  return { end: src.length, exprs };
}

const leavesOf = (exprs) => exprs.flatMap((e) => (e.nested.length ? leavesOf(e.nested) : [e]));
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const MEMBER_ACCESS = /^[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]]*\])+$/;

/** 'safe' (escape, número, literal), 'object' (dado de um objeto, como r.nome) ou 'other' (variável ou chamada desconhecida). */
function classifyInterpolation(text, safeRe) {
  const head = text.trim().split(/\s*(?:\|\||\?\?)\s*/)[0].trim();
  const ternary = /^[^?]+\?\s*([\s\S]+?)\s:\s*([\s\S]+)$/.exec(head);
  if (ternary) {
    const parts = [classifyInterpolation(ternary[1], safeRe), classifyInterpolation(ternary[2], safeRe)];
    if (parts.every((p) => p === 'safe')) return 'safe';
    return parts.includes('object') ? 'object' : 'other';
  }
  if (head === '' || /^(['"`]).*\1$/.test(head) || /^\d+(?:\.\d+)?$/.test(head)) return 'safe';
  if (safeRe.test(head) || /\.toFixed\s*\(\s*\d*\s*\)$/.test(head) || /\.length$/.test(head)) return 'safe';
  if (MEMBER_ACCESS.test(head)) return 'object';
  return 'other';
}

/** Atribuições de HTML por template literal (innerHTML = `...`): analisa o template inteiro, mesmo em várias linhas. */
function templateAssignments(ctx) {
  const safeNames = [...DEFAULT_SAFE_FUNCTIONS, ...(ctx.safeFunctions || [])];
  const safeRe = new RegExp(`^(?:${safeNames.map(escapeRegex).join('|')})\\s*\\(`);
  const findings = [];
  const suppressed = [];
  for (const f of codeFiles(ctx)) {
    if (!JS_EXT.includes(path.extname(f).toLowerCase())) continue;
    const src = ctx.read(f);
    if (src === null) continue;
    const starts = new Set();
    for (const re of [ASSIGN_HTML, HTML_TEMPLATE]) {
      re.lastIndex = 0;
      let hit;
      while ((hit = re.exec(src)) !== null) starts.add(src.indexOf('`', hit.index));
    }
    let lineNo = 1;
    let counted = 0;
    let covered = -1;
    for (const tick of [...starts].sort((a, b) => a - b)) {
      if (tick < covered) continue; // template aninhado: já analisado dentro do externo
      for (; counted < tick; counted += 1) if (src.charCodeAt(counted) === 10) lineNo += 1;
      const lineStart = src.lastIndexOf('\n', tick) + 1;
      const lineEnd = src.indexOf('\n', tick);
      const line = src.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
      const sup = SUPPRESS.exec(line);
      if (sup && sup[1] === 'xss-sinks') {
        if (sup[2].trim().length >= 4) { suppressed.push(`${f}:${lineNo} (xss-sinks): ${sup[2].trim().slice(0, 80)}`); continue; }
        findings.push({ severity: 'medium', key: `xss-sinks:nojust:${f}:${lineNo}`, location: `${f}:${lineNo}`, message: 'Supressão sem justificativa (escreva o motivo depois de ":").' });
        continue;
      }
      const tpl = readTemplate(src, tick);
      covered = tpl.end;
      const classes = leavesOf(tpl.exprs).map((l) => ({ text: l.text.trim(), cls: classifyInterpolation(l.text, safeRe) }));
      const objects = classes.filter((c) => c.cls === 'object');
      const others = classes.filter((c) => c.cls === 'other');
      if (!objects.length && !others.length) continue;
      const ex = objects.length ? `, ex.: \${${objects[0].text.slice(0, 40)}}` : '';
      findings.push({
        severity: objects.length ? 'medium' : 'low',
        key: `xss-sinks:inner-html-template:${f}:${lineNo}`,
        location: `${f}:${lineNo}`,
        message: `HTML montado por template com ${objects.length + others.length} interpolação(ões) sem escape reconhecido (${objects.length} de dado de objeto${ex}). Use escHtml ou textContent; se o valor é fixo ou já escapado, justifique com lastro-ignore ou liste a função em scan.safeFunctions.`,
      });
    }
  }
  return { findings, suppressed };
}

function xssSinks(ctx) {
  const base = scanPatterns(ctx, 'xss-sinks', XSS_PATTERNS, 'medium');
  const tpl = templateAssignments(ctx);
  const notes = [...base.notes, ...(tpl.suppressed.length ? [`${tpl.suppressed.length} supressão(ões) justificada(s) em templates:`, ...tpl.suppressed] : [])];
  return failed([...base.findings, ...tpl.findings], notes);
}

// ---------------------------------------------------------------------------------------------
// CORE: SQL montado por texto, aleatoriedade e hash fracos, segredos no código
// Varreduras por padrão de texto, linha a linha: heurísticas. Elas pegam o comum, erram para os dois lados
// (falso positivo e falso negativo) e não substituem revisão. As palavras-chave são montadas por partes para
// o padrão não casar com o próprio código-fonte do verificador.
// ---------------------------------------------------------------------------------------------

const JS_EXT = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'];
// Só maiúsculas, que é o jeito usual de escrever SQL: evita casar com frases comuns ("select a file from ...").
const SQL_SHAPE = '(?:SEL' + 'ECT\\b[^"\'`]*\\bFR' + 'OM|INS' + 'ERT\\s+INTO|UPD' + 'ATE\\b[^"\'`]*\\bSET|DEL' + 'ETE\\s+FR' + 'OM)';
const QUOTE = '["\'`]';
const NOT_QUOTE = '[^"\'`]*';

// Interpolar um fragmento fixo (nome de coluna, lista de campos) e passar os valores por parâmetro é um padrão
// comum e legítimo. Texto não distingue isso de injeção, então a gravidade segue a força da evidência:
// "alta" só com dado de requisição à vista na própria linha; nos demais casos "média" (revisar, não bloqueia).
const REQUEST_DATA = /\b(?:req|request)\s*\.\s*(?:query|params|body|headers|cookies|args|form|json|GET|POST)\b|\$_(?:GET|POST|REQUEST|COOKIE)\b/;
const interpolationSeverity = (line) => (REQUEST_DATA.test(line) ? 'high' : 'medium');
// Constantes em MAIÚSCULAS_COM_SUBLINHADO são tratadas como fixas por convenção.
const onlyConstants = (line) => {
  const parts = [...line.matchAll(/\$\{([^}]*)\}/g)];
  return parts.length > 0 && parts.every((p) => /^\s*[A-Z][A-Z0-9_]*\s*$/.test(p[1]));
};

const SQL_PATTERNS = [
  {
    id: 'js-template', ext: JS_EXT, re: new RegExp('`[^`]*\\b' + SQL_SHAPE + '[^`]*\\$\\{'),
    skip: (line) => /\bsql\s*`/.test(line) || onlyConstants(line),
    severityFn: interpolationSeverity,
    message: 'Consulta SQL montada com interpolação de texto: confirme que o trecho interpolado é fixo ou validado e que os valores vão por parâmetro (placeholders).',
  },
  {
    id: 'concat', re: new RegExp(QUOTE + NOT_QUOTE + '\\b' + SQL_SHAPE + NOT_QUOTE + QUOTE + '\\s*\\+\\s*[\\w(]'),
    message: 'Consulta SQL montada por concatenação com variável: risco de injeção de SQL. Use parâmetros (placeholders).',
  },
  {
    id: 'py-fstring', ext: ['.py'], re: new RegExp('\\bf["\'][^"\']*\\b' + SQL_SHAPE + '[^"\']*\\{'),
    severityFn: interpolationSeverity,
    message: 'Consulta SQL montada com f-string: confirme que o trecho interpolado é fixo ou validado e que os valores vão por parâmetro (placeholders).',
  },
  {
    id: 'py-percent', ext: ['.py'], re: new RegExp('["\'][^"\']*\\b' + SQL_SHAPE + '[^"\']*["\']\\s*%\\s*[\\w(]'),
    message: 'Consulta SQL montada com o operador % do Python: risco de injeção de SQL. Passe os valores como parâmetros do driver.',
  },
  {
    id: 'py-format', ext: ['.py'], re: new RegExp('["\'][^"\']*\\b' + SQL_SHAPE + '[^"\']*["\']\\.format\\s*\\('),
    message: 'Consulta SQL montada com str.format: risco de injeção de SQL. Use parâmetros (placeholders).',
  },
  {
    id: 'php-interpolation', ext: ['.php'], re: new RegExp('"[^"]*\\b' + SQL_SHAPE + '[^"]*\\$\\w'),
    severityFn: interpolationSeverity,
    message: 'Consulta SQL montada com variável interpolada: confirme que ela é fixa ou validada e prefira consultas preparadas.',
  },
];

function sqlConcat(ctx) {
  return scanPatterns(ctx, 'sql-concat', SQL_PATTERNS, 'high');
}

const SECURITY_WORDS = /token|secret|passw|senha|\bkey\b|nonce|\bsalt\b|\botp\b|csrf|session|sess\w*id|\bcode\b|c[oó]digo|apikey|api_key|reset|verif|invite|convite|uuid/i;
const onlyWithSecurityWords = (line) => !SECURITY_WORDS.test(line);

const RANDOM_PATTERNS = [
  {
    id: 'js-math-random', ext: JS_EXT, re: /Math\.random\s*\(/, skip: onlyWithSecurityWords,
    message: 'Gerador pseudoaleatório do navegador (Math.random) em linha que parece gerar segredo ou token: é previsível. Use crypto.randomBytes ou crypto.randomUUID.',
  },
  {
    id: 'py-random', ext: ['.py'], re: /\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\s*\(/, skip: onlyWithSecurityWords,
    message: 'Módulo random do Python em linha que parece gerar segredo ou token: é previsível. Use o módulo secrets.',
  },
  {
    id: 'java-random', ext: ['.java'], re: /\bnew\s+Random\s*\(/, skip: onlyWithSecurityWords,
    message: 'java.util.Random em linha que parece gerar segredo ou token: é previsível. Use SecureRandom.',
  },
  {
    id: 'php-rand', ext: ['.php'], re: /\b(?:mt_rand|rand)\s*\(/, skip: onlyWithSecurityWords,
    message: 'rand ou mt_rand em linha que parece gerar segredo ou token: é previsível. Use random_bytes ou random_int.',
  },
];

function weakRandom(ctx) {
  return scanPatterns(ctx, 'weak-random', RANDOM_PATTERNS, 'medium');
}

const WEAK_HASH_MESSAGE = 'Função de hash fraca (MD5 ou SHA-1). Para fim criptográfico use SHA-256 ou superior; para senha, Argon2id ou scrypt. Para checksum sem fim de segurança, justifique com lastro-ignore.';
const HASH_PATTERNS = [
  { id: 'node-hash', ext: JS_EXT, re: /create(?:Hash|Hmac)\s*\(\s*['"`](?:md5|sha-?1)['"`]/i, message: WEAK_HASH_MESSAGE },
  { id: 'py-hashlib', ext: ['.py'], re: /hashlib\.(?:md5|sha1)\s*\(|hashlib\.new\s*\(\s*['"](?:md5|sha-?1)['"]/i, message: WEAK_HASH_MESSAGE },
  { id: 'java-digest', ext: ['.java'], re: /MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"/i, message: WEAK_HASH_MESSAGE },
  { id: 'php-hash', ext: ['.php'], re: /\b(?:md5|sha1)\s*\(/, message: WEAK_HASH_MESSAGE },
  { id: 'go-hash', ext: ['.go'], re: /"crypto\/(?:md5|sha1)"/, message: WEAK_HASH_MESSAGE },
  { id: 'cs-hash', ext: ['.cs'], re: /\b(?:MD5|SHA1)\.Create\s*\(|new\s+(?:MD5|SHA1)CryptoServiceProvider/, message: WEAK_HASH_MESSAGE },
  { id: 'ruby-digest', ext: ['.rb'], re: /Digest::(?:MD5|SHA1)\b/, message: WEAK_HASH_MESSAGE },
];

function weakHash(ctx) {
  return scanPatterns(ctx, 'weak-hash', HASH_PATTERNS, 'medium');
}

const SECRET_PLACEHOLDER = /example|changeme|change-me|placeholder|your[_-]?|xxx|\*{3}|dummy|sample|todo|fake|test|<|>|\$\{|%\(|\{\{/i;
const SECRET_FORMATS = [
  { id: 'private-key', re: new RegExp('-----BEGIN ' + '(?:[A-Z]+ )*PRIVATE KEY-----'), severity: 'high', message: 'Bloco de chave privada no código-fonte.' },
  { id: 'aws-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, severity: 'high', message: 'Padrão de chave de acesso da AWS no código-fonte.' },
  { id: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, severity: 'high', message: 'Padrão de token do GitHub no código-fonte.' },
  { id: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, severity: 'high', message: 'Padrão de token do Slack no código-fonte.' },
  { id: 'stripe-live', re: /\bsk_live_[0-9A-Za-z]{16,}\b/, severity: 'high', message: 'Padrão de chave secreta de produção do Stripe no código-fonte.' },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'high', message: 'Padrão de chave de API do Google no código-fonte.' },
  {
    id: 'generic-assignment',
    re: /\b(?:password|passwd|pwd|senha|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\w*\s*[:=]\s*(["'`])([^"'`\s]{8,})\1/i,
    severity: 'medium',
    skip: (line, m) => !/[A-Za-z]/.test(m[2]) || !/\d/.test(m[2]) || SECRET_PLACEHOLDER.test(m[2]) || /process\.env|os\.environ|getenv|ENV\[/.test(line),
    message: 'Valor literal atribuído a um nome que parece segredo (senha, chave, token). Leia de variável de ambiente ou de um cofre.',
  },
];

function hardcodedSecrets(ctx) {
  return scanPatterns(ctx, 'hardcoded-secrets', SECRET_FORMATS, 'high');
}

// ---------------------------------------------------------------------------------------------
// ASSETS: proveniência e licença
// ---------------------------------------------------------------------------------------------

const MEDIA_EXT = new Set(['.mp3', '.wav', '.ogg', '.flac', '.m4a', '.mp4', '.webm', '.mov', '.ttf', '.otf', '.woff', '.woff2', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.svg', '.psd']);

function assetsProvenance(ctx) {
  const media = ctx.files.filter((f) => MEDIA_EXT.has(path.extname(f).toLowerCase()) && !f.startsWith('.lastro/') && !hasPrefix(f, ctx.excludePrefixes));
  if (media.length === 0) return verified(['Nenhum arquivo de mídia versionado.']);
  const findings = [];
  const j = readJson(ctx.root, '.lastro/assets.json');
  let entries = [];
  if (!j.ok) {
    findings.push({ severity: 'medium', key: 'assets-file', location: '.lastro/assets.json', message: `Inventário de ativos ausente ou inválido (${j.error}).` });
  } else {
    const errs = schema.validateAssets(j.value);
    if (errs.length) findings.push({ severity: 'medium', key: 'assets-invalid', location: '.lastro/assets.json', message: `Inventário de ativos inválido: ${errs[0]}` });
    else entries = j.value.assets;
  }
  const covered = (f) => entries.some((e) => e.path === f || (e.path.endsWith('/') && f.startsWith(e.path)));
  for (const f of media) {
    if (!covered(f)) findings.push({ severity: 'medium', key: `asset:${f}`, location: f, message: `Arquivo de mídia sem origem e licença registradas: ${f}` });
  }
  return failed(findings);
}

// ---------------------------------------------------------------------------------------------
// AGENT: arquivos de instrução, hooks e orçamento de contexto
// ---------------------------------------------------------------------------------------------

const INSTR_BASENAMES = new Set(['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.mcp.json', 'copilot-instructions.md', 'SKILL.md']);
const INSTR_DIRS = ['.kiro/', '.claude/', '.cursor/', '.windsurf/', '.agents/', '.codex/', '.github/instructions/', '.github/agents/', '.github/prompts/'];
const INSTR_FILES = ['.vscode/tasks.json', '.vscode/mcp.json'];
const TEXT_EXT = new Set(['.md', '.mdc', '.json', '.yml', '.yaml', '.toml', '.txt', '.sh', '.ps1', '.js', '.py', '']);

function isInstructionFile(rel, extra = []) {
  const base = rel.split('/').pop();
  const ext = path.extname(rel).toLowerCase();
  if (!TEXT_EXT.has(ext) && ext !== '.mdc') return false;
  if (INSTR_BASENAMES.has(base) || ext === '.mdc') return true;
  if (INSTR_FILES.includes(rel)) return true;
  if (INSTR_DIRS.some((d) => rel.startsWith(d))) return true;
  return extra.some((p) => rel === p || rel.startsWith(p.endsWith('/') ? p : `${p}/`));
}

function instructionFiles(ctx) {
  const extra = (ctx.profile.agent && ctx.profile.agent.instructionPaths) || [];
  return ctx.files.filter((f) => isInstructionFile(f, extra));
}

const CP_NAMES = {
  0x200b: 'ZERO WIDTH SPACE', 0x2060: 'WORD JOINER', 0x2061: 'FUNCTION APPLICATION', 0x2062: 'INVISIBLE TIMES',
  0x2063: 'INVISIBLE SEPARATOR', 0x2064: 'INVISIBLE PLUS', 0x180e: 'MONGOLIAN VOWEL SEPARATOR', 0x200e: 'LEFT-TO-RIGHT MARK',
  0x200f: 'RIGHT-TO-LEFT MARK', 0x202a: 'LRE', 0x202b: 'RLE', 0x202c: 'PDF', 0x202d: 'LRO', 0x202e: 'RLO',
  0x2066: 'LRI', 0x2067: 'RLI', 0x2068: 'FSI', 0x2069: 'PDI', 0x00ad: 'SOFT HYPHEN', 0x034f: 'COMBINING GRAPHEME JOINER',
  0x061c: 'ARABIC LETTER MARK', 0x115f: 'HANGUL CHOSEONG FILLER', 0x1160: 'HANGUL JUNGSEONG FILLER', 0x3164: 'HANGUL FILLER',
  0xffa0: 'HALFWIDTH HANGUL FILLER', 0xfeff: 'BYTE ORDER MARK (fora do início)', 0xfff9: 'INTERLINEAR ANNOTATION', 0xfffa: 'INTERLINEAR ANNOTATION',
  0xfffb: 'INTERLINEAR ANNOTATION', 0x200c: 'ZERO WIDTH NON-JOINER (entre letras ASCII)', 0x200d: 'ZERO WIDTH JOINER (entre letras ASCII)',
};

/** Procura caracteres invisíveis ou de controle. Devolve [{ line, col, cp, name }]. */
function findHiddenChars(text, limit = 20) {
  const out = [];
  let line = 1;
  let col = 0;
  const chars = Array.from(text);
  for (let idx = 0; idx < chars.length && out.length < limit; idx++) {
    const ch = chars[idx];
    const cp = ch.codePointAt(0);
    col += 1;
    if (ch === '\n') { line += 1; col = 0; continue; }
    let name = null;
    if (cp === 0x09 || cp === 0x0d) continue;
    if (cp === 0xfeff) {
      if (idx !== 0) name = CP_NAMES[cp];
    } else if (cp === 0x200c || cp === 0x200d) {
      const prev = chars[idx - 1] || '';
      const next = chars[idx + 1] || '';
      if (/[A-Za-z0-9]/.test(prev) || /[A-Za-z0-9]/.test(next)) name = CP_NAMES[cp];
    } else if (cp >= 0xe0000 && cp <= 0xe007f) {
      const back = chars.slice(Math.max(0, idx - 12), idx);
      if (!back.some((c) => c.codePointAt(0) === 0x1f3f4)) name = 'TAG CHARACTER (U+E0000 a U+E007F)';
    } else if (CP_NAMES[cp]) {
      name = CP_NAMES[cp];
    } else if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      name = cp === 0x1b ? 'ESC (sequência ANSI)' : 'CARACTERE DE CONTROLE';
    }
    if (name) out.push({ line, col, cp, name });
  }
  return out;
}

function hiddenUnicode(ctx) {
  const files = instructionFiles(ctx);
  if (files.length === 0) return verified(['Nenhum arquivo de instrução, skill, hook ou configuração de agente encontrado.']);
  const findings = [];
  for (const f of files) {
    const t = ctx.read(f);
    if (t === null) {
      findings.push({ severity: 'medium', key: `unreadable:${f}`, location: f, message: `Arquivo de instrução grande demais ou ilegível: ${f}` });
      continue;
    }
    for (const h of findHiddenChars(t)) {
      const hex = h.cp.toString(16).toUpperCase().padStart(4, '0');
      findings.push({ severity: 'high', key: `hidden:${f}:${h.line}:${h.col}:${hex}`, location: `${f}:${h.line}:${h.col}`, message: `Caractere invisível ou de controle (U+${hex}, ${h.name}) em arquivo de instrução.` });
    }
  }
  return failed(findings, [`${files.length} arquivo(s) de instrução analisado(s).`]);
}

function ownerRules(text) {
  const rules = [];
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.replace(/\s#.*$/, '').trim();
    if (!l || l.startsWith('#')) continue;
    const parts = l.split(/\s+/);
    // Padrão sem dono remove a propriedade (semântica do GitHub): entra com lista vazia.
    const owners = parts.slice(1).filter((o) => o.startsWith('@') || /@.+\..+/.test(o));
    rules.push({ pattern: parts[0], owners });
  }
  return rules;
}

function patternRegex(p) {
  const anchored = p.startsWith('/');
  let s = p.replace(/^\//, '');
  const dirOnly = s.endsWith('/');
  if (dirOnly) s = s.slice(0, -1);
  const directChildren = /(^|\/)\*$/.test(s) && !s.endsWith('**') && s.includes('/');
  const body = s
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '[^/]');
  const head = anchored || s.includes('/') ? '^' : '^(?:.*/)?';
  return new RegExp(`${head}${body}${directChildren ? '$' : '(?:/.*)?$'}`);
}

function codeowners(ctx) {
  const files = instructionFiles(ctx);
  if (files.length === 0) return notApplicable('Sem arquivos de instrução para proteger.');
  const f = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'].find((p) => ctx.has(p));
  if (!f) return failed([{ severity: 'high', key: 'no-codeowners', message: 'CODEOWNERS ausente: ninguém é obrigado a revisar mudanças nos arquivos de instrução, hooks e MCP.' }]);
  const rules = ownerRules(ctx.read(f) || '').map((r) => ({ ...r, re: patternRegex(r.pattern) }));
  const uncovered = new Set();
  for (const file of files) {
    let owners = [];
    for (const r of rules) if (r.re.test(file)) owners = r.owners;
    if (owners.length === 0) uncovered.add(file.split('/').slice(0, 2).join('/'));
  }
  const findings = [...uncovered].slice(0, 10).map((u) => ({ severity: 'high', key: `uncovered:${u}`, location: f, message: `Sem dono no CODEOWNERS: ${u}` }));
  return failed(findings);
}

const ALWAYS_ON_FILES = ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.github/copilot-instructions.md', '.cursorrules', '.windsurfrules'];

function instructionBudget(ctx) {
  const candidates = ctx.files.filter((f) => ALWAYS_ON_FILES.includes(f) || /^\.kiro\/steering\/[^/]+\.md$/.test(f));
  if (candidates.length === 0) return notApplicable('Nenhum arquivo de instrução sempre ativo.');
  let total = 0;
  const parts = [];
  for (const f of candidates) {
    const t = ctx.read(f) || '';
    if (f.startsWith('.kiro/steering/')) {
      const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(t);
      const inc = fm ? /inclusion\s*:\s*['"]?(\w+)/.exec(fm[1]) : null;
      if (inc && inc[1] !== 'always') continue;
    }
    const bytes = Buffer.byteLength(t, 'utf8');
    total += bytes;
    parts.push(`${f}=${bytes}`);
  }
  const limit = ctx.thresholds.alwaysOnInstructionBytes;
  if (total > limit) {
    return failed([{ severity: 'low', key: 'budget', message: `Instruções sempre ativas somam ${total} bytes (limite ${limit}): consome contexto em toda conversa. Mova o detalhe para skills ou regras por arquivo.` }], parts);
  }
  return verified([`Instruções sempre ativas: ${total} de ${limit} bytes (${parts.join(', ') || 'nenhuma'}).`]);
}

const HOOK_PATTERNS = [
  { id: 'curl-wget', re: /\b(?:curl|wget)\b/i, label: 'curl/wget' },
  { id: 'ps-web', re: /Invoke-(?:WebRequest|RestMethod)|\b(?:iwr|irm)\b/i, label: 'PowerShell web' },
  { id: 'netcat', re: /\b(?:nc|ncat|netcat)\b\s/i, label: 'netcat' },
  { id: 'url', re: /https?:\/\/[^\s'"]+/i, label: 'URL' },
  { id: 'pipe-shell', re: /\|\s*(?:sh|bash|zsh|pwsh|powershell)\b/i, label: 'pipe para shell' },
  { id: 'enc-cmd', re: /-enc(?:odedcommand)?\b/i, label: 'comando codificado' },
  { id: 'b64', re: /base64\s+(?:-d|--decode)/i, label: 'base64 decode' },
  { id: 'js-net', re: /\bfetch\s*\(|XMLHttpRequest|new\s+WebSocket/, label: 'rede em script' },
];

function isHookFile(rel) {
  return /^\.kiro\/hooks\/[^/]+$/.test(rel) || /^\.claude\/settings(\.local)?\.json$/.test(rel) || /^\.claude\/hooks\//.test(rel)
    || /^\.cursor\/hooks/.test(rel) || /^\.codex\/hooks/.test(rel) || /^\.husky\//.test(rel);
}

function hooksOffline(ctx) {
  const files = ctx.files.filter(isHookFile);
  if (files.length === 0) return verified(['Nenhum hook de agente encontrado.']);
  const findings = [];
  for (const f of files) {
    const t = ctx.read(f);
    if (t === null) continue;
    t.split(/\r?\n/).forEach((line, i) => {
      for (const p of HOOK_PATTERNS) {
        if (p.re.test(line)) findings.push({ severity: 'high', key: `hook:${f}:${p.id}:${i + 1}`, location: `${f}:${i + 1}`, message: `Hook com acesso a rede ou código remoto (${p.label}).` });
      }
    });
  }
  return failed(findings, [`${files.length} arquivo(s) de hook analisado(s).`]);
}

module.exports = {
  checks: {
    'repo.secrets.env-ignored': envIgnored,
    'repo.deps.lockfile-exact': lockfileExact,
    'repo.ci.actions-pinned': actionsPinned,
    'repo.ci.permissions': ciPermissions,
    'repo.ci.secret-scan': ciSecretScan,
    'repo.ci.dep-audit': ciDepAudit,
    'repo.deps.update-bot': updateBot,
    'repo.docs.security-md': securityMd,
    'repo.docs.threat-model': threatModel,
    'repo.risks.valid': risksValid,
    'repo.code.tls-verification': tlsVerification,
    'repo.code.dynamic-eval': dynamicEval,
    'repo.code.xss-sinks': xssSinks,
    'repo.code.sql-concat': sqlConcat,
    'repo.code.weak-random': weakRandom,
    'repo.code.weak-hash': weakHash,
    'repo.code.hardcoded-secrets': hardcodedSecrets,
    'repo.assets.provenance': assetsProvenance,
    'repo.agent.hidden-unicode': hiddenUnicode,
    'repo.agent.codeowners': codeowners,
    'repo.agent.budget': instructionBudget,
    'repo.agent.hooks-offline': hooksOffline,
  },
  findHiddenChars,
  isInstructionFile,
  patternRegex,
};
