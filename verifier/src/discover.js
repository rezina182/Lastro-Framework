'use strict';

// Descoberta da superfície da aplicação, só por leitura de texto do repositório (nada é executado nem acessado
// pela rede). Alimenta o rascunho do modelo de ameaças com fatos: rotas, armazenamentos, tempo real, uploads,
// chamadas externas, variáveis de ambiente (só os NOMES) e indícios de tipos de dado (só categorias e arquivos).
//
// São heurísticas por texto, linha a linha. "Não vista" não quer dizer "pública" nem "desprotegida": quer dizer
// que o kit não enxergou autenticação ali, e que alguém precisa olhar. Nunca se registra valor de dado,
// segredo ou variável.

const path = require('node:path');
const { hasPrefix } = require('./util');
const { isTestPath } = require('./engineering');

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.py']);
const MAX_FILES = 500;
const MAX_ROUTES = 2000;
const MAX_EXAMPLES = 12;

const JS_ROUTE = /\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])(\/[^'"`]*)\3\s*(.*)$/;
const JS_GLOBAL_USE = /\b(?:app|server|api|router)\.use\s*\(\s*([^)]*)\)/;
const PY_ROUTE = /^\s*@\s*\w+\.(?:route|get|post|put|patch|delete)\s*\(\s*(['"])(\/[^'"]*)\1(.*)$/;
const AUTH_HINT = /(auth|login|session|sess[aã]o|autentic|autoriz|exigir|permiss|logado|token|jwt|passport|protect|guard|role|admin|verify|credential)/i;
const PUBLIC_PATH = /(^\/$|login|logout|signin|signup|register|health|status|ping|public|webhook|callback|manifest|robots|favicon|\.well-known|static|assets|nps|reset|forgot|recover|verify-email|sw\.js)/i;

const STORE_DEPS = {
  pg: 'PostgreSQL', mysql: 'MySQL', mysql2: 'MySQL', sqlite3: 'SQLite', 'better-sqlite3': 'SQLite', mongoose: 'MongoDB', mongodb: 'MongoDB',
  redis: 'Redis', ioredis: 'Redis', sequelize: 'ORM (Sequelize)', prisma: 'ORM (Prisma)', '@prisma/client': 'ORM (Prisma)', typeorm: 'ORM (TypeORM)', knex: 'Knex',
  psycopg2: 'PostgreSQL', 'psycopg2-binary': 'PostgreSQL', sqlalchemy: 'ORM (SQLAlchemy)', pymongo: 'MongoDB',
};
const REALTIME_DEPS = { ws: 'WebSocket (ws)', 'socket.io': 'Socket.IO', websocket: 'WebSocket', sockjs: 'SockJS' };
const UPLOAD_DEPS = { multer: 'multer', formidable: 'formidable', busboy: 'busboy', 'express-fileupload': 'express-fileupload', 'multer-s3': 'multer-s3' };

const DATA_CATEGORIES = [
  { id: 'identificacao', name: 'identificação pessoal', re: /\b(cpf|cnpj|rg|passaporte|cnh|ssn|document[oa]?_?id)\b/i, sensitive: false },
  { id: 'contato', name: 'contato', re: /\b(e-?mail|telefone|celular|phone|whatsapp|endereco|endereço|address|cep)\b/i, sensitive: false },
  { id: 'credencial', name: 'credenciais', re: /\b(senha|password|passwd|password_?hash|token_?hash|api_?key|secret)\b/i, sensitive: false },
  { id: 'financeiro', name: 'financeiro', re: /\b(cartao|cartão|card_?number|cvv|salario|salário|pix|iban|conta_?bancaria)\b/i, sensitive: false },
  { id: 'nascimento', name: 'data de nascimento', re: /\b(nascimento|birth_?date|data_?nasc|dob|idade)\b/i, sensitive: false },
  { id: 'sensivel', name: 'possível dado sensível (LGPD, art. 5º, II)', re: /\b(saude|saúde|health_?(data|record|condition)|medical|medico|médico|prontuario|prontuário|diagnostico|diagnóstico|doenca|doença|biometri\w*|digital_?impressao|religiao|religião|etnia|raca|raça|orientacao_?sexual|filiacao_?sindical|genetic\w*)\b/i, sensitive: true },
];

function codeFiles(ctx) {
  return ctx.files
    .filter((f) => CODE_EXT.has(path.extname(f).toLowerCase()) && !isTestPath(f) && !hasPrefix(f, ctx.excludePrefixes) && !/\.min\./.test(f))
    .slice(0, MAX_FILES);
}

function depNames(ctx) {
  const names = new Set();
  const pkgFiles = ctx.files.filter((f) => /(^|\/)package\.json$/.test(f) && f.split('/').length <= 3);
  for (const f of pkgFiles) {
    try {
      const pkg = JSON.parse(ctx.read(f) || 'null');
      if (pkg) for (const k of ['dependencies', 'devDependencies', 'optionalDependencies']) for (const n of Object.keys(pkg[k] || {})) names.add(n);
    } catch (e) { /* package.json inválido: segue sem dependências */ }
  }
  for (const f of ctx.files.filter((x) => /(^|\/)requirements[\w.-]*\.txt$/.test(x))) {
    for (const line of (ctx.read(f) || '').split(/\r?\n/)) {
      const m = /^\s*([A-Za-z0-9_.-]+)/.exec(line);
      if (m && !line.trim().startsWith('#')) names.add(m[1].toLowerCase());
    }
  }
  return names;
}

// --- Ligação entre a montagem do roteador e o arquivo das rotas (Express e semelhantes) ---

const EXT_TRY = ['', '.js', '.mjs', '.cjs', '.ts', '/index.js', '/index.mjs', '/index.ts'];

function resolveSpec(fileSet, fromFile, spec) {
  if (!spec.startsWith('.')) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), spec));
  for (const e of EXT_TRY) if (fileSet.has(base + e)) return base + e;
  return null;
}

/** Nomes importados por arquivo: identificador -> caminho resolvido (const x = require('./y'), import x from './y', desestruturação). */
function importMap(ctx, fileSet, file, text) {
  const map = new Map();
  const add = (names, spec) => {
    const target = resolveSpec(fileSet, file, spec);
    if (target) for (const n of names) map.set(n, target);
  };
  for (const m of text.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g)) add([m[1]], m[2]);
  for (const m of text.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g)) add(m[1].split(',').map((s) => s.split(':').pop().trim()).filter(Boolean), m[2]);
  for (const m of text.matchAll(/import\s+([A-Za-z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/g)) add([m[1]], m[2]);
  for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]/g)) add(m[1].split(',').map((s) => s.split(/\s+as\s+/).pop().trim()).filter(Boolean), m[2]);
  return map;
}

function splitArgs(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) depth -= 1;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Texto do valor atribuído a `nome` no arquivo (const nome = ...;), até o ponto e vírgula do mesmo nível. */
function definitionOf(text, name) {
  const m = new RegExp(`(?:const|let|var)\\s+${name.replace(/[$]/g, '\\$')}\\s*=\\s*`).exec(text);
  if (!m) return '';
  let depth = 0;
  let i = m.index + m[0].length;
  const start = i;
  for (; i < text.length && i - start < 800; i += 1) {
    const ch = text[i];
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) depth -= 1;
    else if (ch === ';' && depth <= 0) break;
  }
  return text.slice(start, i);
}

/** O middleware tem pista de autenticação, pelo nome ou, se for uma variável do mesmo arquivo, pela definição dela. */
function isAuthMiddleware(mw, text) {
  if (AUTH_HINT.test(mw)) return true;
  const id = /^([A-Za-z_$][\w$]*)$/.exec(mw.trim());
  return !!(id && AUTH_HINT.test(definitionOf(text, id[1])));
}

/**
 * Arquivos de rotas cobertos por um middleware de autenticação aplicado na montagem, como
 * app.use('/api', requireAuth, require('./rotas')) ou router.use('/x', auth, sub). A cobertura desce pelos roteadores
 * montados por um arquivo coberto. Heurística de texto: não segue importações dinâmicas nem fábricas complexas.
 */
function authMountedFiles(ctx, files) {
  const fileSet = new Set(ctx.files);
  const edges = [];
  for (const f of files) {
    if (f.endsWith('.py')) continue;
    const text = ctx.read(f);
    if (!text || !text.includes('.use(')) continue;
    const imports = importMap(ctx, fileSet, f, text);
    for (const line of text.split(/\r?\n/)) {
      const m = /\.use\s*\(\s*(['"`])\/[^'"`]*\1\s*,(.*)\)\s*;?\s*$/.exec(line);
      if (!m) continue;
      const args = splitArgs(m[2]);
      if (!args.length) continue;
      const target = args[args.length - 1];
      const mws = args.slice(0, -1);
      let file = null;
      const req = /require\(\s*['"]([^'"]+)['"]\s*\)/.exec(target);
      if (req) file = resolveSpec(fileSet, f, req[1]);
      else {
        const id = /^([A-Za-z_$][\w$]*)/.exec(target);
        if (id && imports.has(id[1])) file = imports.get(id[1]);
      }
      if (file) edges.push({ from: f, to: file, auth: mws.some((a) => isAuthMiddleware(a, text)) });
    }
  }
  const covered = new Set(edges.filter((e) => e.auth).map((e) => e.to));
  for (let changed = true; changed;) {
    changed = false;
    for (const e of edges) if (covered.has(e.from) && !covered.has(e.to)) { covered.add(e.to); changed = true; }
  }
  return covered;
}

function discoverRoutes(ctx, files) {
  const routes = [];
  const mounted = authMountedFiles(ctx, files);
  for (const f of files) {
    const text = ctx.read(f);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    const isPy = f.endsWith('.py');
    let globalAuthLine = Infinity;
    if (!isPy) {
      lines.forEach((line, i) => {
        const m = JS_GLOBAL_USE.exec(line);
        if (m && !/^\s*['"`]\//.test(m[1]) && AUTH_HINT.test(m[1]) && !/express\.(static|json|urlencoded)|cors|helmet|compression|cookieParser|morgan/i.test(m[1]) && i + 1 < globalAuthLine) globalAuthLine = i + 1;
      });
    }
    lines.forEach((line, i) => {
      if (routes.length >= MAX_ROUTES) return;
      let method;
      let route;
      let rest;
      if (isPy) {
        const m = PY_ROUTE.exec(line);
        if (!m) return;
        route = m[2];
        method = /\.(get|post|put|patch|delete)\b/.exec(line) ? /\.(get|post|put|patch|delete)\b/.exec(line)[1].toUpperCase() : 'ROUTE';
        rest = `${m[3]} ${lines.slice(i + 1, i + 4).join(' ')}`;
      } else {
        const m = JS_ROUTE.exec(line);
        if (!m || /^(console|Math|Object|Array|JSON|process)$/.test(m[1])) return;
        method = m[2].toUpperCase();
        route = m[4];
        rest = m[5];
      }
      let auth;
      if (PUBLIC_PATH.test(route)) auth = 'publica-esperada';
      else if (AUTH_HINT.test(rest)) auth = 'visivel';
      else if (!isPy && i + 1 > globalAuthLine) auth = 'global';
      else if (mounted.has(f)) auth = 'montagem';
      else auth = 'nao-vista';
      routes.push({ method, path: route.slice(0, 120), file: f, line: i + 1, auth });
    });
  }
  return routes;
}

/** Montagens de roteador com autenticação, como app.use('/api', requireAuth, router). O kit não liga a montagem aos arquivos de rotas. */
function countAuthMounts(ctx, files) {
  let n = 0;
  for (const f of files) {
    if (f.endsWith('.py')) continue;
    const text = ctx.read(f) || '';
    for (const line of text.split(/\r?\n/)) {
      const m = /\.use\s*\(\s*(['"`])\/[^'"`]*\1\s*,(.*)\)/.exec(line);
      if (m && splitArgs(m[2]).slice(0, -1).some((a) => isAuthMiddleware(a, text))) n += 1;
    }
  }
  return n;
}

function discoverEnv(ctx, files) {
  const names = new Set();
  for (const f of files) {
    const text = ctx.read(f);
    if (!text) continue;
    for (const m of text.matchAll(/process\.env\.([A-Z][A-Z0-9_]{1,60})|os\.environ(?:\.get)?\s*[\[(]\s*['"]([A-Z][A-Z0-9_]{1,60})['"]/g)) names.add(m[1] || m[2]);
  }
  const all = [...names].sort();
  return { total: all.length, credentials: all.filter((n) => /(SECRET|KEY|TOKEN|PASS|PASSWORD|DATABASE_URL|PRIVATE|CREDENTIAL)/.test(n)).slice(0, 30) };
}

function discoverExternal(ctx, files) {
  const hosts = new Set();
  for (const f of files) {
    const text = ctx.read(f);
    if (!text) continue;
    for (const line of text.split(/\r?\n/)) {
      if (!/(fetch|axios|request|http\.get|https\.get|got\(|urlopen|requests\.)/i.test(line)) continue;
      for (const m of line.matchAll(/https?:\/\/([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/gi)) {
        const h = m[1].toLowerCase();
        if (!/^(localhost|127\.|www\.w3\.org|example\.)/.test(h)) hosts.add(h);
      }
    }
  }
  return [...hosts].sort().slice(0, 20);
}

/** Indícios de tipos de dado: procura nomes de campo em esquemas SQL, migrações e código. Registra só categorias e arquivos. */
function discoverDataHints(ctx) {
  const files = ctx.files.filter((f) => (/\.sql$/i.test(f) || CODE_EXT.has(path.extname(f).toLowerCase())) && !isTestPath(f) && !hasPrefix(f, ctx.excludePrefixes) && !/\.min\./.test(f)).slice(0, MAX_FILES);
  const found = new Map();
  for (const f of files) {
    const text = ctx.read(f);
    if (!text) continue;
    const isSql = /\.sql$/i.test(f) || /migrat/i.test(f);
    for (const cat of DATA_CATEGORIES) {
      // Em código, só conta se o nome aparece como campo/coluna (chave de objeto, coluna, parâmetro SQL), não em qualquer texto.
      const re = new RegExp(cat.re.source, 'gi');
      const m = isSql ? re.exec(text) : new RegExp(`(?:['"\`.]|\\b)(${cat.re.source.replace(/^\\b\(/, '(').replace(/\)\\b$/, ')')})(?:['"\`:,\\s=)])`, 'i').exec(text);
      if (!m) continue;
      const entry = found.get(cat.id) || { category: cat.id, name: cat.name, sensitive: cat.sensitive, files: [] };
      if (entry.files.length < 4 && !entry.files.includes(f)) entry.files.push(f);
      found.set(cat.id, entry);
    }
  }
  return [...found.values()];
}

function discover(ctx) {
  const files = codeFiles(ctx);
  const deps = depNames(ctx);
  const routes = discoverRoutes(ctx, files);
  const withoutAuth = routes.filter((r) => r.auth === 'nao-vista');
  const byAuth = { visivel: 0, global: 0, montagem: 0, 'publica-esperada': 0, 'nao-vista': 0 };
  for (const r of routes) byAuth[r.auth] += 1;
  const pick = (map) => [...new Set([...deps].filter((d) => map[d]).map((d) => map[d]))];
  const sse = files.some((f) => /text\/event-stream/.test(ctx.read(f) || ''));
  const realtime = [...pick(REALTIME_DEPS), ...(sse ? ['SSE (text/event-stream)'] : [])];
  const pyUploads = files.some((f) => f.endsWith('.py') && /request\.files/.test(ctx.read(f) || ''));
  const uploads = [...pick(UPLOAD_DEPS), ...(pyUploads ? ['request.files (Python)'] : [])];
  const workflows = ctx.files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f)).length;
  return {
    sourceFilesRead: files.length,
    routes: {
      total: routes.length,
      byAuth,
      authMounts: countAuthMounts(ctx, files),
      examples: withoutAuth.slice(0, MAX_EXAMPLES).map((r) => ({ method: r.method, path: r.path, location: `${r.file}:${r.line}` })),
      uploadRoutes: routes.filter((r) => /(upload|import|attach|arquivo|file|media|foto|imagem|avatar)/i.test(r.path) && r.method !== 'GET').slice(0, 6).map((r) => `${r.method} ${r.path}`),
    },
    stores: pick(STORE_DEPS),
    realtime,
    uploads,
    externalHosts: discoverExternal(ctx, files),
    env: discoverEnv(ctx, files),
    dataHints: discoverDataHints(ctx),
    workflows,
  };
}

module.exports = { discover, AUTH_HINT, PUBLIC_PATH };
