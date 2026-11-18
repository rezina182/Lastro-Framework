'use strict';

// Motor do LASTRO: carrega o catálogo e o perfil, executa as verificações e calcula o veredito.
//
// Regras de projeto (ver docs/PRINCIPLES.md):
//  - "não sei" nunca vira "passou": sem prova o estado é unverified;
//  - afirmação de quem escreveu o código (atestação) nunca verifica um controle automático;
//  - o portão só bloqueia achados NOVOS de severidade alta/crítica (fora do baseline e sem risco aceito vigente);
//  - risco aceito exige dono, aprovador e validade; vencido, volta a contar como achado;
//  - atestação manual tem validade (no máximo 366 dias).

const fs = require('node:fs');
const path = require('node:path');
const U = require('./util');
const schema = require('./schema');
const { loadCatalog, validateCatalog } = require('./catalog');
const { registry } = require('./checks');
const { request } = require('./http');
const { runAuthProbes, readAccounts } = require('./authprobe');
const { runAssists } = require('./assist');
const { computeScore } = require('./score');
const { deriveContext, describeScope } = require('./context');
const { engineeringFacts } = require('./engineering');
const { analyzeRisk } = require('./risk');
const { loadAuditFile, directDeps } = require('./audit');
const TM = require('./threatmodel');
const { buildArchitecture, buildSystemArchitecture } = require('./architecture');
const { loadSystem, resolveRepos, FILE: SYSTEM_FILE } = require('./system');
const { discover } = require('./discover');
const { packLegend } = require('./legend');

class ConfigError extends Error {}

const DEFAULT_THRESHOLDS = { hstsMinSeconds: 31536000, threatModelMaxAgeDays: 180, alwaysOnInstructionBytes: 8192 };
const BLOCKING_SEVERITIES = new Set(['critical', 'high']);
const STATES = new Set(['verified', 'failed', 'unverified', 'not_applicable']);
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_ATTESTATION_DAYS = 366;

function kitVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch (e) {
    return '0.0.0';
  }
}

function loadProfile(root) {
  const j = U.readJson(root, '.lastro/profile.json');
  if (!j.ok) throw new ConfigError(`.lastro/profile.json ausente ou inválido (${j.error}). Rode "lastro init".`);
  const errs = schema.validateProfile(j.value);
  if (errs.length) throw new ConfigError(`.lastro/profile.json inválido:\n- ${errs.join('\n- ')}`);
  return j.value;
}

function loadOptional(root, rel, validator, empty) {
  if (!U.exists(root, rel)) return empty;
  const j = U.readJson(root, rel);
  if (!j.ok) throw new ConfigError(`${rel} inválido (${j.error}).`);
  const errs = validator(j.value);
  if (errs.length) throw new ConfigError(`${rel} inválido:\n- ${errs.join('\n- ')}`);
  return j.value;
}

function loadRisks(root) {
  const dir = path.join(root, '.lastro', 'risks');
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  } catch (e) {
    return [];
  }
  const out = [];
  for (const n of names) {
    const j = U.readJson(root, `.lastro/risks/${n}`);
    // Risco inválido não vale como aceitação; o check repo.risks.valid o reporta.
    if (j.ok && schema.validateRisk(j.value, n).length === 0) out.push({ ...j.value, scope: j.value.scope || 'findings' });
  }
  return out;
}

function isApplicable(control, packs, flags) {
  const req = (packs[control.pack] && packs[control.pack].requires) || [];
  return req.every((f) => flags[f]) && (control.appliesIf || []).every((f) => flags[f]);
}

// Freios de segurança do verificador contra a aplicação alvo (padrões usados pelo CLI).
const DEFAULT_DELAY_MS = 150;
const MIN_DELAY_MS = 50;
const DEFAULT_MAX_REQUESTS = 120;
const ACTIVE_MAX_REQUESTS = 250;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch (e) {
    return false;
  }
}

function buildContext({ root, profile, catalog, url, active, now, delayMs = 0, maxRequests = DEFAULT_MAX_REQUESTS }) {
  const files = U.listFiles(root);
  const fileSet = new Set(files);
  const readCache = new Map();
  const httpCache = new Map();
  let sent = 0;
  let lastAt = 0;
  let base = null;
  if (url) {
    const u = new URL(url);
    base = `${u.origin}${u.pathname.replace(/\/$/, '')}`;
  }
  return {
    root,
    now,
    profile,
    catalog,
    url,
    active: !!active,
    files,
    thresholds: { ...DEFAULT_THRESHOLDS, ...(profile.thresholds || {}) },
    excludePrefixes: (profile.scan && profile.scan.excludePrefixes) || [],
    safeFunctions: (profile.scan && profile.scan.safeFunctions) || [],
    isGit: fs.existsSync(path.join(root, '.git')),
    has: (rel) => fileSet.has(rel),
    read(rel) {
      if (!readCache.has(rel)) readCache.set(rel, U.readText(root, rel));
      return readCache.get(rel);
    },
    async fetch(p, o = {}) {
      const key = o.cacheKey || `${o.method || 'GET'} ${p} ${o.maxRedirects || 0}`;
      if (httpCache.has(key)) return httpCache.get(key);
      // Teto de requisições: passado dele, nenhuma sonda chega à aplicação e o resultado vira "não verificado".
      if (sent >= maxRequests) {
        return { ok: false, url: `${base}${p}`, status: 0, headers: {}, setCookie: [], body: '', truncated: false, error: `teto de ${maxRequests} requisições do verificador atingido`, redirects: [] };
      }
      sent += 1;
      const wait = lastAt + delayMs - Date.now();
      if (wait > 0) await sleep(wait);
      const res = await request(`${base}${p}`, { method: o.method || 'GET', headers: o.headers, body: o.body, maxRedirects: o.maxRedirects || 0 });
      lastAt = Date.now();
      httpCache.set(key, res);
      return res;
    },
    requestCount: () => sent,
    allSetCookies: () => [...httpCache.values()].flatMap((r) => r.setCookie || []),
  };
}

function evaluateManual(control, status, now) {
  const a = status.attestations[control.id];
  if (!a) return { state: 'unverified', findings: [], notes: ['Sem atestação registrada em .lastro/status.json.'], evidence: null };
  const col = U.parseDate(a.collectedAt);
  const exp = U.parseDate(a.expiresAt);
  if (exp === null || col === null || exp <= now.getTime()) return { state: 'unverified', findings: [], notes: ['Atestação expirada.'], evidence: null };
  if (col > now.getTime() + DAY_MS) return { state: 'unverified', findings: [], notes: ['Atestação com data de coleta no futuro.'], evidence: null };
  if ((exp - col) / DAY_MS > MAX_ATTESTATION_DAYS) return { state: 'unverified', findings: [], notes: [`Atestação com validade acima de ${MAX_ATTESTATION_DAYS} dias não é aceita.`], evidence: null };
  if (a.state === 'not_applicable') {
    return {
      state: 'not_applicable',
      findings: [],
      notes: [`Não se aplica, segundo ${a.attestedBy} (até ${a.expiresAt.slice(0, 10)}): ${a.note}`],
      evidence: { source: 'manual-attestation', attestedBy: a.attestedBy, collectedAt: a.collectedAt, expiresAt: a.expiresAt, ref: a.evidenceRef || null, decision: 'not_applicable' },
    };
  }
  return {
    state: 'verified',
    findings: [],
    notes: [`Atestado por ${a.attestedBy} (autodeclaração com prazo, até ${a.expiresAt.slice(0, 10)}).`],
    evidence: { source: 'manual-attestation', attestedBy: a.attestedBy, collectedAt: a.collectedAt, expiresAt: a.expiresAt, ref: a.evidenceRef || null },
  };
}

/**
 * Combina o resultado de um controle manual com o da sonda autenticada. A sonda que acha a falha vence a atestação
 * (prova de máquina contra autodeclaração). A que passa só acrescenta uma nota: o estado manual continua valendo.
 */
function overlayProbe(r, probe, now) {
  // Achado "soft" é ausência que a máquina não viu (hook, banco no CI), não falha medida: o mecanismo pode estar
  // fora do repositório. Ele não derruba a decisão de uma pessoa; vira aviso para ela conferir.
  const hard = probe.findings.filter((f) => !f.soft);
  if (!hard.length && probe.findings.length && r.state !== 'unverified') {
    return { ...r, notes: [...probe.findings.map((f) => `A máquina não confirmou o que foi atestado: ${f.message}`), ...probe.notes, ...r.notes] };
  }
  if (probe.findings.length) {
    return { state: 'failed', findings: probe.findings, notes: [...probe.notes, ...r.notes], evidence: { source: probe.source || 'verifier-http', collectedAt: now.toISOString() } };
  }
  // "Não se aplica" decidido por uma pessoa não ganha nota de prova parcial: a máquina não muda essa decisão.
  if (r.state === 'not_applicable') return r;
  return { ...r, notes: [...probe.notes, ...r.notes] };
}

/** Junta o resultado da sonda autenticada e o da prova assistida do mesmo controle (qualquer um pode faltar). */
function mergeProbes(a, b) {
  if (!a) return b || null;
  if (!b) return a;
  return { findings: [...a.findings, ...b.findings], notes: [...a.notes, ...b.notes], tested: (a.tested || 0) + (b.tested || 0), source: b.findings.length && !a.findings.length ? b.source : 'verifier-http' };
}

async function runCheck(opts = {}) {
  const root = path.resolve(opts.root || process.cwd());
  const now = opts.now || new Date();
  const catalog = loadCatalog(opts.catalogDir);
  const catErrors = validateCatalog(catalog, new Set(registry.keys()));
  if (catErrors.length) throw new ConfigError(`Catálogo inválido:\n- ${catErrors.slice(0, 15).join('\n- ')}`);
  // Perfil derivado (lastro app): o repositório não precisa de .lastro/profile.json. Vem validado pelo chamador.
  let profile;
  if (opts.profile) {
    const perrs = schema.validateProfile(opts.profile);
    if (perrs.length) throw new ConfigError(`perfil derivado inválido:\n- ${perrs.join('\n- ')}`);
    profile = opts.profile;
  } else profile = loadProfile(root);
  const baselineFile = loadOptional(root, '.lastro/baseline.json', schema.validateBaseline, null);
  const baseline = new Set(baselineFile ? baselineFile.fingerprints : []);
  const status = loadOptional(root, '.lastro/status.json', schema.validateStatus, { schemaVersion: 1, attestations: {} });
  const risks = loadRisks(root);
  if (opts.url && !/^https?:\/\//.test(opts.url)) throw new ConfigError('--url deve começar com http:// ou https://');

  // Sondas ativas podem gerar carga, ruído em logs e alarmes. Só rodam com confirmação explícita e fora de produção.
  if (opts.active) {
    if (!opts.url) throw new ConfigError('--active exige --url.');
    if (!opts.confirmNonProduction) {
      throw new ConfigError('As sondas ativas (TRACE, OPTIONS com Origin falsa, JSON malformado) podem gerar carga e alarmes. Rode-as só em ambiente de staging ou homologação que você controla, e confirme com --confirm-non-production.');
    }
    const prod = profile.urls && profile.urls.production;
    if (prod && sameOrigin(prod, opts.url)) {
      throw new ConfigError(`A URL informada é a de produção do perfil (${prod}). Sondas ativas nunca rodam em produção: use a URL de staging.`);
    }
  }
  // Sondas autenticadas entram com contas de teste e mudam estado (login, logout, escrita). Mesma trava das ativas.
  let authAccounts = null;
  if (opts.auth) {
    if (!opts.url) throw new ConfigError('--auth exige --url.');
    if (!opts.confirmNonProduction) {
      throw new ConfigError('As sondas autenticadas entram com contas de teste e mudam estado (login, logout e requisições de escrita). Rode-as só em staging ou local que você controla, e confirme com --confirm-non-production.');
    }
    const prodUrl = profile.urls && profile.urls.production;
    if (prodUrl && sameOrigin(prodUrl, opts.url)) {
      throw new ConfigError(`A URL informada é a de produção do perfil (${prodUrl}). Sondas autenticadas nunca rodam em produção: use a URL de staging.`);
    }
    if (!profile.authProbes) throw new ConfigError('--auth exige o bloco "authProbes" no perfil (veja docs/SONDAS-AUTENTICADAS.md).');
    const read = readAccounts(profile.authProbes, opts.env || process.env);
    if (read.missing.length) throw new ConfigError(`Defina as variáveis de ambiente das contas de teste (só os nomes são mostrados): ${read.missing.join(', ')}.`);
    if (read.sameUser) throw new ConfigError('As duas contas de teste têm o mesmo usuário: a sonda de acesso por objeto precisa de duas contas diferentes.');
    authAccounts = read.accounts;
  }
  const delayMs = opts.delayMs === undefined ? DEFAULT_DELAY_MS : opts.delayMs;
  if (!Number.isInteger(delayMs) || delayMs < MIN_DELAY_MS) throw new ConfigError(`--delay deve ser um inteiro de pelo menos ${MIN_DELAY_MS} ms.`);

  // Sondas ativas e autenticadas fazem mais requisições (tentativas de login, duas contas): o teto padrão sobe.
  const maxRequests = opts.maxRequests || (opts.active || opts.auth ? ACTIVE_MAX_REQUESTS : DEFAULT_MAX_REQUESTS);
  const ctx = buildContext({ root, profile, catalog, url: opts.url || null, active: opts.active, now, delayMs, maxRequests });
  const only = opts.only ? new Set(opts.only) : null;
  const warnings = [];
  // As sondas rodam antes dos controles: o login e as respostas ficam no cache e alimentam a análise dos cookies (AUTH-003).
  const authProbe = authAccounts ? await runAuthProbes(ctx, profile.authProbes, authAccounts) : null;
  // Prova assistida dos controles manuais (assist.js): só os que se aplicam e foram pedidos.
  const wanted = new Set(catalog.controls.filter((c) => c.check.type === 'manual' && (!only || only.has(c.id)) && isApplicable(c, catalog.packs, profile.flags)).map((c) => c.id));
  const assists = opts.noAssist ? {} : await runAssists(ctx, profile, { active: !!opts.active, disc: discover(ctx), want: (id) => wanted.has(id) });
  const validRisk = (rk) => U.parseDate(rk.expires) > now.getTime();

  const controls = [];
  let notApplicable = 0;
  for (const c of catalog.controls) {
    if (only && !only.has(c.id)) continue;
    if (!isApplicable(c, catalog.packs, profile.flags)) {
      notApplicable += 1;
      continue;
    }
    let r;
    if (c.check.type === 'automated') {
      if (status.attestations[c.id]) warnings.push(`${c.id}: atestação ignorada (controle automático não aceita autodeclaração).`);
      const chk = registry.get(c.check.id);
      try {
        r = await chk.run(ctx);
      } catch (e) {
        r = { state: 'unverified', findings: [], notes: [`Erro interno na verificação: ${e.message}`] };
      }
      if (!r || !STATES.has(r.state)) r = { state: 'unverified', findings: [], notes: ['A verificação devolveu um resultado inválido.'] };
      r.evidence = { source: chk.kind === 'http' ? 'verifier-http' : 'verifier-repo', collectedAt: now.toISOString() };
    } else {
      r = evaluateManual(c, status, now);
      const probe = mergeProbes(authProbe && authProbe.results[c.id], assists[c.id]);
      if (probe) r = overlayProbe(r, probe, now);
    }

    const controlRisk = risks.find((rk) => rk.control === c.id && rk.scope === 'control' && validRisk(rk)) || null;
    const findings = (r.findings || []).map((f) => {
      const fp = U.fingerprint(c.id, f.key || f.message);
      const severity = f.severity || c.severity;
      const risk = risks.find((rk) => rk.control === c.id && rk.scope === 'findings' && rk.fingerprints.includes(fp) && validRisk(rk)) || null;
      const accepted = !!risk || !!controlRisk;
      const inBaseline = baseline.has(fp);
      const blocking = r.state === 'failed' && BLOCKING_SEVERITIES.has(severity) && !accepted && !inBaseline;
      return {
        fingerprint: fp, severity, message: f.message, location: f.location || null,
        accepted, riskId: risk ? risk.id : controlRisk ? controlRisk.id : null, inBaseline, blocking,
      };
    });
    controls.push({
      id: c.id, title: c.title, pack: c.pack, tier: c.tier, severity: c.severity, enforcement: c.enforcement, phase: c.phase, remediation: c.remediation, checkType: c.check.type,
      state: r.state, notes: r.notes || [], evidence: r.evidence || null, findings,
      controlRiskAccepted: r.state === 'unverified' && !!controlRisk ? controlRisk.id : null,
    });
  }

  const count = (s) => controls.filter((x) => x.state === s).length;
  const allFindings = controls.flatMap((x) => x.findings);
  const blocking = allFindings.filter((f) => f.blocking).length;
  const summary = {
    applicable: controls.length,
    verified: count('verified'),
    failed: count('failed'),
    unverified: count('unverified'),
    notApplicable: notApplicable + count('not_applicable'),
    blocking,
    debt: allFindings.filter((f) => f.inBaseline && !f.accepted).length,
    accepted: allFindings.filter((f) => f.accepted).length,
  };
  const incomplete = controls.some((x) => x.state === 'unverified' && BLOCKING_SEVERITIES.has(x.severity) && !x.controlRiskAccepted);
  const verdict = blocking > 0 ? 'fail' : incomplete ? 'incomplete' : 'pass';

  const packTitles = Object.fromEntries(Object.entries(catalog.packs).map(([k, v]) => [k, v.title]));
  const score = computeScore({ controls, summary }, { packTitles });
  // Contexto: o risco inerente da aplicação define a meta de maturidade razoável para ela.
  const context = deriveContext(profile);
  context.gap = Math.max(0, context.targetLevel - score.level);
  context.meetsTarget = score.level >= context.targetLevel;
  // Se a dívida atual fosse registrada como baseline, o portão só bloquearia achados novos.
  const blockingCauses = new Set(controls.filter((x) => x.findings.some((f) => f.blocking)).map((x) => x.id)).size;
  let audit = null;
  if (opts.auditFile) {
    const a = loadAuditFile(path.resolve(String(opts.auditFile)), directDeps(ctx.read('package.json')));
    if (!a.ok) throw new ConfigError(`--audit-file: ${a.error}`);
    audit = a.value;
  }
  // Modelo de ameaças: rascunho gerado agora, combinado com as decisões já gravadas (se houver).
  let tmPersisted = null;
  const tmFile = TM.loadFile(root);
  if (tmFile) {
    if (!tmFile.ok) warnings.push(`${TM.FILE} ilegível (${tmFile.error}): ignorado na análise.`);
    else {
      const tmErrs = TM.validateModel(tmFile.value);
      if (tmErrs.length) warnings.push(`${TM.FILE} inválido (${tmErrs[0]}): ignorado na análise.`);
      else tmPersisted = tmFile.value;
    }
  }
  const threatModel = TM.buildThreatModel({ ctx, controls, riskMap: catalog.riskMap, profile, persisted: tmPersisted, now });
  threatModel.architecture = buildArchitecture({ model: threatModel, profile, controls });

  // Sistema com mais de um componente ou repositório, descrito em .lastro/system.json.
  const sys = opts.noSystem ? null : loadSystem(root);
  if (sys && !sys.ok) warnings.push(`${SYSTEM_FILE} inválido (${sys.error}): usado o desenho automático.`);
  if (sys && sys.ok) {
    const repos = resolveRepos(root, sys.value, { allowExternal: !!opts.allowExternalRepos });
    const primary = { model: threatModel, controls, disc: threatModel.discovery, flags: profile.flags, name: path.basename(root), dir: root };
    const perRepo = new Map();
    for (const [key, r] of repos) {
      if (r.status !== 'ok') continue;
      if (r.same) { perRepo.set(key, primary); continue; }
      let hasProfile = false;
      try { hasProfile = fs.existsSync(path.join(r.dir, '.lastro', 'profile.json')); } catch (e) { hasProfile = false; }
      if (hasProfile) {
        try {
          const sub = await runCheck({ root: r.dir, now, noSystem: true, catalogDir: opts.catalogDir });
          perRepo.set(key, { model: sub.threatModel, controls: sub.controls, disc: sub.threatModel.discovery, flags: sub.profile.flags, name: path.basename(r.dir), dir: r.dir });
          continue;
        } catch (e) {
          warnings.push(`Repositório "${key}": a verificação falhou (${String(e.message).split('\n')[0].slice(0, 120)}). Usada só a descoberta.`);
        }
      } else warnings.push(`Repositório "${key}" não tem .lastro/profile.json: o kit leu o código, mas as ameaças e os controles vêm do repositório principal. Rode "lastro init" nele para um modelo próprio.`);
      const subCtx = buildContext({ root: r.dir, profile, catalog, url: null, active: false, now });
      perRepo.set(key, { model: threatModel, controls, disc: discover(subCtx), flags: profile.flags, name: path.basename(r.dir), dir: r.dir });
    }
    threatModel.architecture = buildSystemArchitecture({ system: sys.value, repos, perRepo, primary });
  }
  const risk = analyzeRisk({ controls }, { riskMap: catalog.riskMap, catalog, profile, audit, threatLikelihood: TM.likelihoodOverrides(threatModel) });
  const baselineView = blocking > 0 ? { findings: blocking, causes: blockingCauses, verdictIfAdopted: incomplete ? 'incomplete' : 'pass' } : null;
  return {
    tool: { name: 'lastro', version: kitVersion() },
    catalogVersion: catalog.version,
    generatedAt: now.toISOString(),
    target: { root: path.basename(root), url: opts.url || null, active: !!opts.active, authProbes: !!authProbe, requestsSent: ctx.requestCount(), delayMs },
    authProbe: authProbe ? { ran: true, inconclusive: authProbe.inconclusive } : null,
    profile: { name: profile.name, flags: profile.flags, derived: !!opts.profile },
    verdict,
    summary,
    score,
    context,
    scope: describeScope(catalog.packs, profile.flags),
    baselineView,
    legend: { packs: packLegend(catalog) },
    risk,
    threatModel,
    dependencyVulns: audit,
    engineering: engineeringFacts(ctx),
    controls,
    warnings,
  };
}

module.exports = { DEFAULT_DELAY_MS, MIN_DELAY_MS, DEFAULT_MAX_REQUESTS, runCheck, buildContext, loadProfile, loadRisks, isApplicable, ConfigError, DEFAULT_THRESHOLDS, MAX_ATTESTATION_DAYS };
