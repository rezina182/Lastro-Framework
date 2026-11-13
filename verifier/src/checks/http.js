'use strict';

// Verificações HTTP "caixa-preta" contra uma URL informada com --url.
// Padrão: somente GET (passivo). Sondas que enviam métodos incomuns ou corpo malformado exigem --active.
// Use apenas contra aplicações suas ou com autorização.

const verified = (notes = []) => ({ state: 'verified', findings: [], notes });
const failed = (findings, notes = []) => ({ state: findings.length ? 'failed' : 'verified', findings, notes });
const notApplicable = (note) => ({ state: 'not_applicable', findings: [], notes: [note] });
const unverified = (note) => ({ state: 'unverified', findings: [], notes: [note] });

const NO_URL = 'Informe --url para executar esta verificação.';

function parseCsp(value) {
  const d = {};
  for (const part of String(value || '').split(';')) {
    const t = part.trim();
    if (!t) continue;
    const [name, ...vals] = t.split(/\s+/);
    const k = name.toLowerCase();
    if (!(k in d)) d[k] = vals;
  }
  return d;
}

const lower = (arr) => (arr || []).map((v) => v.toLowerCase());

async function pageOrFail(ctx) {
  if (!ctx.url) return { early: unverified(NO_URL) };
  const page = await ctx.fetch('/', { maxRedirects: 3 });
  if (!page.ok) return { early: unverified(`Não foi possível acessar a URL (${page.error}).`) };
  return { page };
}

const PROBE_404 = '/__lastro_probe_404__';

const isHtml = (res) => /html/i.test(String((res && res.headers && res.headers['content-type']) || ''));

/**
 * Amostra respostas de tipos diferentes: página inicial, erro 404, saúde e as rotas declaradas no perfil
 * (paths.login, paths.api, paths.static). Cabeçalhos de segurança costumam existir na página inicial e faltar
 * no erro, na API e nos arquivos estáticos. A amostra reduz esse ponto cego, mas nunca prova "todas as respostas".
 */
async function sampleResponses(ctx) {
  const paths = (ctx.profile && ctx.profile.paths) || {};
  const plan = [
    { kind: 'página', path: '/', opts: { maxRedirects: 3 } },
    { kind: 'erro 404', path: PROBE_404, opts: {} },
    { kind: 'saúde', path: paths.health || '/health', opts: {} },
  ];
  if (paths.login) plan.push({ kind: 'login', path: paths.login, opts: { maxRedirects: 3 } });
  if (paths.api) plan.push({ kind: 'api', path: paths.api, opts: {} });
  if (paths.static) plan.push({ kind: 'estático', path: paths.static, opts: {} });
  const seen = new Set();
  const out = [];
  for (const s of plan) {
    if (seen.has(s.path)) continue;
    seen.add(s.path);
    const res = await ctx.fetch(s.path, s.opts);
    if (res.ok) out.push({ kind: s.kind, path: s.path, res });
  }
  return out;
}

const sampleNote = (samples) => `Amostra: ${samples.map((s) => `${s.kind} (${s.path})`).join(', ')}. Não prova "todas as respostas".`;

function scriptPolicyFindings(raw) {
  const d = parseCsp(raw);
  const src = lower(d['script-src'] || d['default-src']);
  const findings = [];
  if (!d['script-src'] && !d['default-src']) {
    findings.push({ severity: 'high', key: 'csp-no-script-src', message: 'CSP sem script-src nem default-src.' });
  } else {
    const protectedByNonce = src.some((v) => /^'(nonce-|sha(256|384|512)-)/.test(v)) || src.includes("'strict-dynamic'");
    if (src.includes("'unsafe-inline'") && !protectedByNonce) findings.push({ severity: 'high', key: 'csp-unsafe-inline', message: "script-src permite 'unsafe-inline'." });
    if (src.includes("'unsafe-eval'")) findings.push({ severity: 'high', key: 'csp-unsafe-eval', message: "script-src permite 'unsafe-eval'." });
    if (src.includes('*')) findings.push({ severity: 'high', key: 'csp-wildcard', message: 'script-src com curinga (*).' });
    if (src.includes('data:')) findings.push({ severity: 'high', key: 'csp-data', message: 'script-src permite data:.' });
    if (src.includes('http:')) findings.push({ severity: 'high', key: 'csp-http', message: 'script-src permite qualquer origem http:.' });
    if (src.includes('https:')) findings.push({ severity: 'medium', key: 'csp-https-scheme', message: 'script-src permite qualquer origem https: (esquema inteiro).' });
    if (src.some((v) => /^(https?:\/\/)?\*\./.test(v))) findings.push({ severity: 'medium', key: 'csp-wildcard-subdomain', message: 'script-src com curinga de subdomínio.' });
  }
  const attr = lower(d['script-src-attr']);
  if (attr.includes("'unsafe-inline'")) findings.push({ severity: 'medium', key: 'csp-attr-unsafe-inline', message: "script-src-attr permite handlers inline (dívida a migrar para addEventListener)." });
  const style = lower(d['style-src'] || d['default-src']);
  if (style.includes("'unsafe-inline'")) findings.push({ severity: 'low', key: 'csp-style-unsafe-inline', message: "style-src permite 'unsafe-inline'." });
  return findings;
}

async function cspScript(ctx) {
  const { early, page } = await pageOrFail(ctx);
  if (early) return early;
  const raw = page.headers['content-security-policy'];
  if (!raw) {
    const ro = page.headers['content-security-policy-report-only'] ? ' (existe apenas em modo relatório)' : '';
    return failed([{ severity: 'high', key: 'csp-missing', message: `Content-Security-Policy ausente${ro}.` }]);
  }
  const findings = scriptPolicyFindings(raw);
  const keys = new Set(findings.map((f) => f.key));
  // Outras respostas HTML (login, erro com página) também precisam da política.
  const samples = await sampleResponses(ctx);
  for (const s of samples.filter((x) => x.path !== '/' && isHtml(x.res))) {
    const other = s.res.headers['content-security-policy'];
    if (!other) {
      findings.push({ severity: 'high', key: `csp-missing:${s.kind}`, location: s.path, message: `Content-Security-Policy ausente na resposta HTML de ${s.kind} (${s.path}).` });
      continue;
    }
    for (const f of scriptPolicyFindings(other)) {
      if (keys.has(f.key)) continue;
      keys.add(f.key);
      findings.push({ ...f, location: s.path, message: `${f.message} (resposta de ${s.kind}, ${s.path})` });
    }
  }
  return failed(findings, [sampleNote(samples)]);
}

async function cspComplementary(ctx) {
  const { early, page } = await pageOrFail(ctx);
  if (early) return early;
  const raw = page.headers['content-security-policy'];
  if (!raw) return failed([{ severity: 'medium', key: 'csp-missing', message: 'Content-Security-Policy ausente: as diretivas complementares não existem.' }]);
  const samples = await sampleResponses(ctx);
  const findings = [];
  const seen = new Set();
  const add = (f, s) => {
    const key = s.kind === 'página' ? f.key : `${f.key}:${s.kind}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ...f, key, location: s.path, message: s.kind === 'página' ? f.message : `${f.message} (resposta de ${s.kind}, ${s.path})` });
  };
  for (const s of samples) {
    const h = s.res.headers;
    const rawS = h['content-security-policy'];
    const d = parseCsp(rawS);
    // Diretivas de documento só valem para respostas HTML; frame-ancestors vale para qualquer resposta.
    if (isHtml(s.res) || s === samples[0]) {
      if (!rawS) {
        add({ severity: 'medium', key: 'csp-missing', message: 'Content-Security-Policy ausente na resposta HTML.' }, s);
      } else {
        const objectNone = lower(d['object-src']).includes("'none'") || (!d['object-src'] && lower(d['default-src']).includes("'none'"));
        if (!objectNone) add({ severity: 'medium', key: 'csp-object-src', message: "object-src não é 'none'." }, s);
        if (!d['base-uri']) add({ severity: 'medium', key: 'csp-base-uri', message: "Falta a diretiva base-uri (o ASVS V3.4.3 pede 'none')." }, s);
        else if (!lower(d['base-uri']).includes("'none'")) add({ severity: 'low', key: 'csp-base-uri-not-none', message: "base-uri não é 'none' (o ASVS V3.4.3 pede 'none')." }, s);
        if (!d['form-action']) add({ severity: 'low', key: 'csp-form-action', message: 'Falta a diretiva form-action.' }, s);
      }
    }
    const xfo = String(h['x-frame-options'] || '').toLowerCase();
    if (!d['frame-ancestors'] && !/^(deny|sameorigin)$/.test(xfo)) add({ severity: 'medium', key: 'csp-frame-ancestors', message: 'Falta frame-ancestors (ou X-Frame-Options): risco de clickjacking.' }, s);
  }
  return failed(findings, [sampleNote(samples)]);
}

async function hsts(ctx) {
  const { early, page } = await pageOrFail(ctx);
  if (early) return early;
  const u = new URL(ctx.url);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:') {
    if (local) return notApplicable('Ambiente local em http: HSTS não se aplica.');
    return failed([{ severity: 'high', key: 'http-plain', message: 'A aplicação é servida por http sem TLS.' }]);
  }
  const min = ctx.thresholds.hstsMinSeconds;
  const samples = await sampleResponses(ctx);
  const findings = [];
  for (const s of samples) {
    const h = s.res.headers['strict-transport-security'];
    const where = s.kind === 'página' ? '' : ` (resposta de ${s.kind}, ${s.path})`;
    const base = { location: s.path };
    if (!h) {
      findings.push({ ...base, severity: 'medium', key: `hsts-missing:${s.kind}`, message: `Strict-Transport-Security ausente${where}.` });
      continue;
    }
    const m = /max-age\s*=\s*(\d+)/i.exec(h);
    if (!m || Number(m[1]) < min) findings.push({ ...base, severity: 'medium', key: `hsts-short:${s.kind}`, message: `HSTS com max-age menor que ${min} segundos${where} (o ASVS V3.4.1 pede ao menos 1 ano).` });
    else if (!/includesubdomains/i.test(h)) findings.push({ ...base, severity: 'low', key: `hsts-subdomains:${s.kind}`, message: `HSTS sem includeSubDomains${where} (o ASVS V3.4.1 pede subdomínios a partir do L2).` });
  }
  return failed(findings, [sampleNote(samples)]);
}

async function headersBasic(ctx) {
  const { early, page } = await pageOrFail(ctx);
  if (early) return early;
  const samples = await sampleResponses(ctx);
  const findings = [];
  for (const s of samples) {
    const h = s.res.headers;
    const where = s.kind === 'página' ? '' : ` (resposta de ${s.kind}, ${s.path})`;
    const base = { location: s.path };
    // nosniff vale para toda resposta; Referrer-Policy e Permissions-Policy fazem sentido em documentos HTML.
    if (String(h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') findings.push({ ...base, severity: 'medium', key: `nosniff:${s.kind}`, message: `X-Content-Type-Options: nosniff ausente${where}.` });
    if (s.kind === 'página' || isHtml(s.res)) {
      const ref = String(h['referrer-policy'] || '').toLowerCase();
      if (!ref) findings.push({ ...base, severity: 'low', key: `referrer-missing:${s.kind}`, message: `Referrer-Policy ausente${where}.` });
      else if (ref === 'unsafe-url') findings.push({ ...base, severity: 'low', key: `referrer-unsafe:${s.kind}`, message: `Referrer-Policy: unsafe-url${where}.` });
      if (!h['permissions-policy']) findings.push({ ...base, severity: 'low', key: `permissions-policy:${s.kind}`, message: `Permissions-Policy ausente${where}.` });
    }
  }
  return failed(findings, [sampleNote(samples)]);
}

async function disclosure(ctx) {
  const { early, page } = await pageOrFail(ctx);
  if (early) return early;
  const h = page.headers;
  const findings = [];
  if (h['x-powered-by']) findings.push({ severity: 'low', key: 'x-powered-by', message: 'Cabeçalho X-Powered-By revela a tecnologia.' });
  if (/\d+\.\d+/.test(String(h.server || ''))) findings.push({ severity: 'low', key: 'server-version', message: 'Cabeçalho Server revela versão.' });
  for (const k of ['x-aspnet-version', 'x-aspnetmvc-version']) if (h[k]) findings.push({ severity: 'low', key: k, message: `Cabeçalho ${k} revela versão.` });
  return failed(findings);
}

async function healthMinimal(ctx) {
  if (!ctx.url) return unverified(NO_URL);
  const p = (ctx.profile.paths && ctx.profile.paths.health) || '/health';
  const r = await ctx.fetch(p);
  if (!r.ok) return unverified(`Não foi possível acessar ${p} (${r.error}).`);
  if (r.status === 404 || r.status === 405) return notApplicable(`Sem endpoint de saúde em ${p}.`);
  if (r.status === 401 || r.status === 403) return notApplicable(`${p} exige autenticação.`);
  if (r.status !== 200) return unverified(`${p} respondeu ${r.status}.`);
  const ct = String(r.headers['content-type'] || '');
  if (/html/i.test(ct)) return notApplicable(`${p} devolve HTML (provável fallback de SPA).`);
  let j;
  try {
    j = JSON.parse(r.body);
  } catch (e) {
    return r.body.trim().length <= 64 ? verified(['Resposta curta, não JSON.']) : failed([{ severity: 'medium', key: 'health-long', message: `${p} devolve texto longo.` }]);
  }
  if (j === null || typeof j !== 'object' || Array.isArray(j)) return verified();
  const extra = Object.keys(j).filter((k) => k !== 'status');
  if (extra.length) return failed([{ severity: 'medium', key: 'health-extra', message: `${p} expõe campos além de "status": ${extra.slice(0, 6).join(', ')}.` }]);
  return verified();
}

const STACK_MARKERS = [
  { id: 'js-stack', re: /\bat\s+(?:async\s+)?[\w$.<>[\]\s]+\s\((?:[A-Za-z]:)?[^)\n]*:\d+:\d+\)/, severity: 'medium', label: 'stack trace de JavaScript' },
  { id: 'js-stack2', re: /\bat\s+\S+:\d+:\d+/, severity: 'medium', label: 'stack trace de JavaScript' },
  { id: 'py-trace', re: /Traceback \(most recent call last\)/, severity: 'medium', label: 'traceback de Python' },
  { id: 'java-stack', re: /\bat\s+[\w.$]+\([\w.]+:\d+\)|java\.lang\.|org\.springframework/, severity: 'medium', label: 'stack trace de Java' },
  { id: 'php-error', re: /(?:Fatal error|Warning|Notice):.*\bon line \d+/i, severity: 'medium', label: 'erro de PHP' },
  { id: 'sql-error', re: /SQLSTATE|ORA-\d{5}|PG::|SequelizeDatabaseError|mysqli_sql_exception|psycopg2/i, severity: 'medium', label: 'erro de banco de dados' },
  { id: 'fs-path', re: /node_modules[\\/]|[A-Za-z]:\\+(?:Users|Windows|inetpub)|\/(?:home|var\/www|usr\/src)\//, severity: 'medium', label: 'caminho interno do servidor' },
  { id: 'debug-console', re: /werkzeug|Whoops, looks like something went wrong|DEBUG = True/i, severity: 'high', label: 'console ou modo de depuração' },
  { id: 'framework-404', re: /Cannot (?:GET|POST|PUT|DELETE) \//, severity: 'low', label: 'página 404 padrão do framework' },
];

function scanErrorBody(body, label, findings) {
  for (const m of STACK_MARKERS) {
    if (m.re.test(body)) findings.push({ severity: m.severity, key: `${label}:${m.id}`, message: `Resposta a "${label}" expõe ${m.label}.` });
  }
}

async function errorsGeneric(ctx) {
  if (!ctx.url) return unverified(NO_URL);
  const probes = [
    { label: 'GET rota inexistente', path: '/__lastro_probe_404__' },
    { label: 'GET percent-encoding inválido', path: '/%E0%A4%A' },
  ];
  const findings = [];
  let answered = 0;
  for (const p of probes) {
    const r = await ctx.fetch(p.path);
    if (!r.ok) continue;
    answered += 1;
    scanErrorBody(r.body, p.label, findings);
  }
  if (ctx.active) {
    const r = await ctx.fetch('/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{lastro-invalid-json', cacheKey: 'post-invalid-json' });
    if (r.ok) {
      answered += 1;
      scanErrorBody(r.body, 'POST JSON malformado', findings);
    }
  }
  if (answered === 0) return unverified('Nenhuma sonda de erro obteve resposta.');
  return failed(findings, ctx.active ? [] : ['Sondas passivas apenas; use --active para incluir JSON malformado.']);
}

const SENSITIVE = [
  { path: '/.env', severity: 'critical', test: (b) => /^\s*[A-Z][A-Z0-9_]*\s*=/m.test(b), what: 'arquivo .env' },
  { path: '/.git/config', severity: 'critical', test: (b) => /\[core\]|\[remote /.test(b), what: 'configuração do Git' },
  { path: '/.git/HEAD', severity: 'critical', test: (b) => /^ref:\s*refs\//m.test(b), what: 'HEAD do Git' },
  { path: '/.npmrc', severity: 'critical', test: (b) => /_authToken|registry\s*=/.test(b), what: '.npmrc' },
  { path: '/package.json', severity: 'medium', test: (b) => /"(name|dependencies|scripts)"\s*:/.test(b), what: 'package.json' },
  { path: '/package-lock.json', severity: 'medium', test: (b) => /"lockfileVersion"\s*:/.test(b), what: 'package-lock.json' },
  { path: '/server.js', severity: 'high', test: (b) => /require\(|import\s.+from|\.listen\(/.test(b), what: 'código-fonte do servidor' },
  { path: '/app.js', severity: 'high', test: (b) => /require\(['"](express|http|fs)['"]\)|\.listen\(/.test(b), what: 'código-fonte do servidor' },
  { path: '/docker-compose.yml', severity: 'medium', test: (b) => /^services\s*:/m.test(b), what: 'docker-compose.yml' },
  { path: '/Dockerfile', severity: 'medium', test: (b) => /^FROM\s/m.test(b), what: 'Dockerfile' },
  { path: '/config.json', severity: 'high', test: (b) => /(password|secret|connectionstring|api[_-]?key)/i.test(b), what: 'config.json com credenciais' },
  { path: '/dump.sql', severity: 'critical', test: (b) => /INSERT INTO|CREATE TABLE/i.test(b), what: 'dump de banco' },
  { path: '/backup.sql', severity: 'critical', test: (b) => /INSERT INTO|CREATE TABLE/i.test(b), what: 'backup de banco' },
  { path: '/.DS_Store', severity: 'low', test: (b) => b.startsWith('\u0000\u0000\u0000\u0001Bud1'), what: '.DS_Store' },
];

async function sensitivePaths(ctx) {
  if (!ctx.url) return unverified(NO_URL);
  const findings = [];
  let answered = 0;
  for (const s of SENSITIVE) {
    const r = await ctx.fetch(s.path);
    if (!r.ok) continue;
    answered += 1;
    if ((r.status === 200 || r.status === 206) && s.test(r.body)) {
      findings.push({ severity: s.severity, key: `exposed:${s.path}`, location: s.path, message: `Exposto publicamente: ${s.what} (${s.path}).` });
    }
  }
  if (answered === 0) return unverified('Nenhuma sonda obteve resposta.');
  return failed(findings);
}

async function methodsCors(ctx) {
  if (!ctx.url) return unverified(NO_URL);
  if (!ctx.active) return unverified('Verificação ativa: execute com --active (envia TRACE e OPTIONS com Origin falsa).');
  const findings = [];
  const trace = await ctx.fetch('/', { method: 'TRACE', headers: { 'x-lastro-probe': 'trace-echo' } });
  if (trace.ok && trace.status === 200 && /x-lastro-probe/i.test(trace.body)) findings.push({ severity: 'medium', key: 'trace-enabled', message: 'O método TRACE está habilitado e devolve a requisição.' });
  const evil = 'https://lastro-probe.invalid';
  const opt = await ctx.fetch('/', { method: 'OPTIONS', headers: { origin: evil, 'access-control-request-method': 'GET' } });
  if (opt.ok) {
    const acao = opt.headers['access-control-allow-origin'];
    const cred = String(opt.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    if (acao === evil && cred) findings.push({ severity: 'high', key: 'cors-reflect-credentials', message: 'CORS reflete qualquer Origin e permite credenciais.' });
    else if (acao === 'null' && cred) findings.push({ severity: 'high', key: 'cors-null-credentials', message: 'CORS aceita Origin "null" com credenciais.' });
    else if (acao === '*' && cred) findings.push({ severity: 'high', key: 'cors-star-credentials', message: 'CORS com * e credenciais.' });
    else if (acao === evil) findings.push({ severity: 'low', key: 'cors-reflect', message: 'CORS reflete qualquer Origin (sem credenciais).' });
  }
  if (!trace.ok && !opt.ok) return unverified('As sondas ativas não obtiveram resposta.');
  return failed(findings);
}

function parseCookie(line) {
  const parts = line.split(';').map((s) => s.trim());
  const [name, ...rest] = parts[0].split('=');
  const attrs = {};
  for (const p of parts.slice(1)) {
    const [k, ...v] = p.split('=');
    attrs[k.toLowerCase()] = v.join('=') || true;
  }
  return { name: name.trim(), value: rest.join('='), attrs };
}

async function cookiesFlags(ctx) {
  if (!ctx.url) return unverified(NO_URL);
  await ctx.fetch('/', { maxRedirects: 3 });
  const login = ctx.profile.paths && ctx.profile.paths.login;
  if (login) await ctx.fetch(login, { maxRedirects: 3 });
  const lines = ctx.allSetCookies();
  if (lines.length === 0) return unverified('Nenhum cookie observado nas páginas públicas. Informe paths.login no perfil ou registre uma atestação.');
  const https = new URL(ctx.url).protocol === 'https:';
  const findings = [];
  const seen = new Set();
  for (const line of lines) {
    const c = parseCookie(line);
    if (seen.has(c.name)) continue;
    seen.add(c.name);
    const sessionLike = /sess|sid|auth|token|jwt|login/i.test(c.name);
    if (https && !c.attrs.secure) findings.push({ severity: 'high', key: `cookie-secure:${c.name}`, message: `Cookie "${c.name}" sem o atributo Secure.` });
    if (!c.attrs.httponly) findings.push({ severity: sessionLike ? 'high' : 'medium', key: `cookie-httponly:${c.name}`, message: `Cookie "${c.name}" sem HttpOnly.` });
    const ss = String(c.attrs.samesite || '').toLowerCase();
    if (!ss) findings.push({ severity: 'medium', key: `cookie-samesite:${c.name}`, message: `Cookie "${c.name}" sem SameSite.` });
    else if (ss === 'none' && !c.attrs.secure) findings.push({ severity: 'high', key: `cookie-none-insecure:${c.name}`, message: `Cookie "${c.name}" com SameSite=None sem Secure.` });
    if (sessionLike && !/^__(Host|Secure)-/.test(c.name)) findings.push({ severity: 'low', key: `cookie-prefix:${c.name}`, message: `Cookie de sessão "${c.name}" sem prefixo __Host- ou __Secure-.` });
  }
  return failed(findings, [`${seen.size} cookie(s) observado(s).`]);
}

module.exports = {
  checks: {
    'http.csp.script': cspScript,
    'http.csp.complementary': cspComplementary,
    'http.hsts': hsts,
    'http.headers.basic': headersBasic,
    'http.disclosure': disclosure,
    'http.health.minimal': healthMinimal,
    'http.errors.generic': errorsGeneric,
    'http.paths.sensitive': sensitivePaths,
    'http.methods.cors': methodsCors,
    'http.cookies.flags': cookiesFlags,
  },
  parseCsp,
};
