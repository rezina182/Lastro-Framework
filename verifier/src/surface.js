'use strict';

// Descoberta mais funda da superfície, só por leitura de texto (nada executa, nada vai à rede). Alimenta o desenho
// da arquitetura com o que o código mostra: módulos de rotas (pelo prefixo de montagem), defesas vistas no código,
// tabelas do banco e jobs do CI. Tudo é INDÍCIO para o desenho e para a conversa: nada aqui verifica um controle.

const path = require('node:path');

const MAX_MODULES = 10;
const MAX_TABLES = 40;

// Prefixo de cada arquivo de rotas, a partir de app.use('/prefixo', ..., roteador) em uma linha.
function mountPrefixes(ctx, files, resolveTarget) {
  const edges = [];
  for (const f of files) {
    if (f.endsWith('.py')) continue;
    const text = ctx.read(f) || '';
    if (!text.includes('.use(')) continue;
    for (const line of text.split(/\r?\n/)) {
      const m = /\.use\s*\(\s*(['"`])(\/[^'"`]*)\1\s*,(.*)\)\s*;?\s*$/.exec(line);
      if (!m) continue;
      const to = resolveTarget(f, text, m[3]);
      if (to) edges.push({ from: f, to, prefix: m[2] === '/' ? '' : m[2].replace(/\/$/, '') });
    }
  }
  const prefix = new Map();
  const targets = new Set(edges.map((e) => e.to));
  const roots = [...new Set(edges.map((e) => e.from))].filter((f) => !targets.has(f));
  // Busca em largura a partir dos arquivos que montam e não são montados (server.js, app.js). Primeiro caminho vence.
  for (const r of roots) prefix.set(r, '');
  const queue = [...roots];
  while (queue.length) {
    const f = queue.shift();
    for (const e of edges.filter((x) => x.from === f)) {
      if (prefix.has(e.to)) continue;
      prefix.set(e.to, `${prefix.get(f)}${e.prefix}`);
      queue.push(e.to);
    }
  }
  return prefix;
}

const PROTECTED = new Set(['visivel', 'global', 'montagem']);

function moduleKey(full) {
  const segs = full.split('/').filter(Boolean);
  if (!segs.length) return '/';
  if (segs[0] === 'api' && segs.length > 1 && !segs[1].startsWith(':')) return `/api/${segs[1]}`;
  return `/${segs[0].startsWith(':') ? '*' : segs[0]}`;
}

/** Agrupa as rotas em módulos pelo prefixo completo (montagem + rota). */
function routeModules(routes, prefixOf) {
  const groups = new Map();
  for (const r of routes) {
    const full = `${prefixOf.get(r.file) || ''}${r.path}`.replace(/\/{2,}/g, '/') || '/';
    const key = moduleKey(full);
    const g = groups.get(key) || { prefix: key, routes: 0, methods: new Set(), protectedCount: 0, publicCount: 0, notSeen: 0, files: new Set() };
    g.routes += 1;
    g.methods.add(r.method);
    if (PROTECTED.has(r.auth)) g.protectedCount += 1;
    else if (r.auth === 'publica-esperada') g.publicCount += 1;
    else g.notSeen += 1;
    g.files.add(r.file);
    groups.set(key, g);
  }
  const all = [...groups.values()].sort((a, b) => b.routes - a.routes || a.prefix.localeCompare(b.prefix));
  const out = all.slice(0, MAX_MODULES).map((g) => ({
    prefix: g.prefix, routes: g.routes, methods: [...g.methods].sort(), protected: g.protectedCount, public: g.publicCount, notSeen: g.notSeen,
    writes: [...g.methods].some((m) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)), files: [...g.files].slice(0, 3),
  }));
  const rest = all.slice(MAX_MODULES);
  if (rest.length) {
    out.push({
      prefix: `outras (${rest.length} grupo(s))`, routes: rest.reduce((s, g) => s + g.routes, 0), methods: [], protected: rest.reduce((s, g) => s + g.protectedCount, 0),
      public: rest.reduce((s, g) => s + g.publicCount, 0), notSeen: rest.reduce((s, g) => s + g.notSeen, 0), writes: true, files: [],
    });
  }
  return out;
}

// Defesas vistas no código: dependência conhecida ou padrão de código. Indício, nunca prova.
const DEFENSES = [
  { id: 'headers', label: 'Cabeçalhos de segurança e CSP', deps: ['helmet', '@fastify/helmet', 'flask-talisman'], code: /Content-Security-Policy|contentSecurityPolicy/ },
  { id: 'cors', label: 'CORS configurado', deps: ['cors', '@fastify/cors', 'flask-cors', 'django-cors-headers'] },
  { id: 'ratelimit', label: 'Limite de requisições', deps: ['express-rate-limit', 'rate-limiter-flexible', '@fastify/rate-limit', 'slowapi', 'flask-limiter'], code: /rate.?limit|limiteMemoria|limiter\s*\(/i },
  { id: 'csrf', label: 'Proteção contra CSRF', deps: ['csurf', 'csrf-csrf', 'lusca', '@fastify/csrf-protection'], code: /x-csrf-token|csrf_?token|exigirCsrf|csrfProtect/i },
  { id: 'origin', label: 'Conferência de origem (Origin/Host)', code: /get\(\s*['"]origin['"]\s*\)|headers\.origin|headers\[['"]origin['"]\]/i },
  { id: 'cookie', label: 'Cookie de sessão com HttpOnly', code: /httpOnly\s*:\s*true|HttpOnly/ },
  { id: 'password', label: 'Hash de senha forte', deps: ['bcrypt', 'bcryptjs', 'argon2', '@node-rs/argon2', '@node-rs/bcrypt', 'passlib', 'argon2-cffi'], code: /\bscrypt(?:Sync)?\s*\(|hashlib\.scrypt|argon2/ },
  { id: 'mfa', label: 'Segundo fator (TOTP)', deps: ['otpauth', 'speakeasy', 'otplib', 'pyotp'] },
  { id: 'tokens', label: 'Tokens assinados (JWT)', deps: ['jsonwebtoken', 'jose', 'pyjwt', 'python-jose'] },
  { id: 'validation', label: 'Validação de entrada por esquema', deps: ['zod', 'joi', 'yup', 'ajv', 'express-validator', 'class-validator', 'pydantic', 'marshmallow'] },
  { id: 'bodylimit', label: 'Limite de tamanho do corpo', code: /express\.json\(\s*\{[^}]*limit|bodyLimit|MAX_CONTENT_LENGTH/ },
  { id: 'image', label: 'Reprocessamento de imagem enviada', deps: ['sharp', 'jimp', 'pillow'] },
  { id: 'captcha', label: 'Anti-robô (captcha)', code: /turnstile|recaptcha|hcaptcha/i },
  { id: 'audit', label: 'Trilha de auditoria', code: /\baudit\w*\.(registrar|log|record)\s*\(|audit_?log/i },
];

function discoverDefenses(ctx, files, deps) {
  const out = [];
  for (const d of DEFENSES) {
    const dep = (d.deps || []).find((x) => deps.has(x));
    if (dep) { out.push({ id: d.id, label: d.label, evidence: `dependência ${dep}` }); continue; }
    if (!d.code) continue;
    const hit = files.find((f) => d.code.test(ctx.read(f) || ''));
    if (hit) out.push({ id: d.id, label: d.label, evidence: hit });
  }
  return out;
}

// Tabelas criadas nas migrações SQL, com as categorias de dado que as colunas sugerem.
function discoverTables(ctx, categories) {
  const files = ctx.files.filter((f) => /\.sql$/i.test(f) && !/(^|\/)(test|tests|__tests__)\//.test(f)).slice(0, 200);
  const tables = new Map();
  for (const f of files) {
    const text = ctx.read(f) || '';
    for (const m of text.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?[\w]+"?\.)?"?([A-Za-z_][\w]*)"?\s*\(([\s\S]*?)\);/gi)) {
      const name = m[1].toLowerCase();
      const cats = categories.filter((c) => new RegExp(c.re.source, 'i').test(m[2])).map((c) => c.id);
      const t = tables.get(name) || { name, categories: new Set(), file: f };
      for (const c of cats) t.categories.add(c);
      tables.set(name, t);
    }
  }
  // Modelos do Prisma (schema.prisma): cada "model X { ... }" vira uma tabela, com as categorias que os campos sugerem.
  for (const f of ctx.files.filter((x) => /\.prisma$/i.test(x)).slice(0, 20)) {
    const text = ctx.read(f) || '';
    for (const m of text.matchAll(/^\s*model\s+([A-Za-z_]\w*)\s*\{([\s\S]*?)^\s*\}/gm)) {
      const name = m[1].toLowerCase();
      if (tables.has(name)) continue;
      const cats = categories.filter((c) => new RegExp(c.re.source, 'i').test(m[2])).map((c) => c.id);
      tables.set(name, { name, categories: new Set(cats), file: f });
    }
  }
  return [...tables.values()].slice(0, MAX_TABLES).map((t) => ({ name: t.name, categories: [...t.categories], file: t.file }));
}

// Jobs dos workflows do GitHub Actions (nomes), para o desenho da cadeia de entrega.
function discoverCiJobs(ctx) {
  const out = [];
  for (const f of ctx.files.filter((x) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(x))) {
    const text = ctx.read(f) || '';
    const at = text.search(/^jobs\s*:/m);
    if (at < 0) continue;
    for (const m of text.slice(at).matchAll(/^ {2}([A-Za-z0-9_-]+)\s*:\s*$/gm)) out.push({ workflow: path.posix.basename(f), job: m[1] });
  }
  return out.slice(0, 20);
}

// Mapa da aplicação para quem não é técnico: áreas (módulos de rotas), o que cada uma faz (consultar, criar, alterar,
// apagar), quem pode usar, e que dados ela toca. A ligação área -> tabela é INDÍCIO: o nome da tabela ou do modelo
// aparece no código das rotas da área (prisma.modelo, FROM tabela, Modelo.find...). Não segue importações.
const MAX_AREAS = 14;
const ACTION = { GET: 'consultar', POST: 'criar ou enviar', PUT: 'alterar', PATCH: 'alterar', DELETE: 'apagar', ALL: 'várias', ROUTE: 'várias' };
const ADMIN_KEY = /(^|\/)(admin|administra\w*|gestao|manage|internal|interno|backoffice)(\/|$)/i;

function tableRefRe(name) {
  const n = name.replace(/[^a-z0-9_]/gi, '');
  return new RegExp(`prisma\\.${n}\\b|\\b(?:from|into|update|join|table)\\s+["'\`]?${n}["'\`]?\\b|\\b${n}\\s*\\.\\s*(?:find\\w*|create\\w*|update\\w*|delete\\w*|upsert|count|aggregate|destroy|insert\\w*)\\s*\\(`, 'i');
}

function appMap(ctx, routes, prefixOf, tables) {
  const areas = new Map();
  for (const r of routes) {
    const full = `${prefixOf.get(r.file) || ''}${r.path}`.replace(/\/{2,}/g, '/') || '/';
    const key = moduleKey(full);
    const a = areas.get(key) || { key, routes: 0, actions: {}, access: { protegida: 0, publica: 0, naoVista: 0 }, files: new Set(), list: [] };
    a.routes += 1;
    a.list.push({ method: r.method, path: full.slice(0, 120), auth: PROTECTED.has(r.auth) ? 'protegida' : r.auth === 'publica-esperada' ? 'publica' : 'nao-vista' });
    const act = ACTION[r.method] || 'várias';
    a.actions[act] = (a.actions[act] || 0) + 1;
    if (PROTECTED.has(r.auth)) a.access.protegida += 1;
    else if (r.auth === 'publica-esperada') a.access.publica += 1;
    else a.access.naoVista += 1;
    a.files.add(r.file);
    areas.set(key, a);
  }
  const res = tables.map((t) => ({ ...t, re: tableRefRe(t.name) }));
  const list = [...areas.values()].sort((x, y) => y.routes - x.routes || x.key.localeCompare(y.key)).slice(0, MAX_AREAS).map((a) => {
    const text = [...a.files].map((f) => ctx.read(f) || '').join('\n');
    const who = ADMIN_KEY.test(a.key) ? 'admin' : a.access.protegida === 0 && a.access.naoVista === 0 ? 'publico' : 'logado';
    return {
      key: a.key, routes: a.routes, actions: a.actions, access: a.access, who,
      tables: res.filter((t) => t.re.test(text)).map((t) => t.name).slice(0, 8),
      files: [...a.files].slice(0, 4),
      list: a.list.slice(0, 40),
    };
  });
  const byTable = tables.map((t) => ({ name: t.name, categories: t.categories, areas: list.filter((a) => a.tables.includes(t.name)).map((a) => a.key) }));
  return { areas: list, more: Math.max(0, areas.size - MAX_AREAS), tables: byTable };
}

module.exports = { mountPrefixes, routeModules, discoverDefenses, discoverTables, discoverCiJobs, moduleKey, appMap, DEFENSES };
