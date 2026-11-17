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
const AUTH_HINT = /(auth|login|session|token|jwt|passport|protect|guard|role|permission|admin|verify|credential)/i;
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
  try {
    const pkg = JSON.parse(ctx.read('package.json') || 'null');
    if (pkg) for (const k of ['dependencies', 'devDependencies', 'optionalDependencies']) for (const n of Object.keys(pkg[k] || {})) names.add(n);
  } catch (e) { /* package.json inválido: segue sem dependências */ }
  for (const f of ctx.files.filter((x) => /(^|\/)requirements[\w.-]*\.txt$/.test(x))) {
    for (const line of (ctx.read(f) || '').split(/\r?\n/)) {
      const m = /^\s*([A-Za-z0-9_.-]+)/.exec(line);
      if (m && !line.trim().startsWith('#')) names.add(m[1].toLowerCase());
    }
  }
  return names;
}

function discoverRoutes(ctx, files) {
  const routes = [];
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
    for (const line of (ctx.read(f) || '').split(/\r?\n/)) {
      const m = /\.use\s*\(\s*(['"`])\/[^'"`]*\1\s*,(.*)\)/.exec(line);
      if (m && AUTH_HINT.test(m[2])) n += 1;
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
  const byAuth = { visivel: 0, global: 0, 'publica-esperada': 0, 'nao-vista': 0 };
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
