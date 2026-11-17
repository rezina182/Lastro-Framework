'use strict';

// SERVIDOR DE TESTE COM FALHAS PLANTADAS. Nunca use como modelo. Só roda por `lastro bench`,
// em 127.0.0.1, na porta recebida em PORT. Todos os valores secretos aqui são falsos.
const http = require('node:http');

const port = Number(process.env.PORT);
const USERS = { alice: 'senha-alice-falsa', bob: 'senha-bob-falsa' };
const OWNER = { 1: 'alice', 2: 'bob' };
const sessions = new Map();
let counter = 0;

function send(res, status, type, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.end(body);
}
const json = (res, status, obj) => send(res, status, 'application/json', JSON.stringify(obj));

const server = http.createServer((req, res) => {
  // D-006: revela a tecnologia.
  res.setHeader('X-Powered-By', 'Express');
  // D-009: reflete qualquer Origin e permite credenciais.
  if (req.headers.origin) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }
  const url = new URL(req.url, 'http://localhost');
  const sid = (/(?:^|;\s*)sid=(\w+)/.exec(req.headers.cookie || '') || [])[1];
  const user = sessions.get(sid) || null;
  let raw = '';
  req.on('data', (c) => { raw += c; });
  return req.on('end', () => {
    if (url.pathname === '/') {
      // D-001, D-002, D-003: cookie de sessão sem HttpOnly, sem SameSite e sem prefixo.
      // D-004, D-005, D-011: nenhuma política de segurança nos cabeçalhos.
      res.setHeader('Set-Cookie', 'sid=abc123; Path=/');
      return send(res, 200, 'text/html; charset=utf-8', '<!doctype html><html><body><h1>Loja</h1></body></html>');
    }
    if (url.pathname === '/login' && req.method === 'POST') {
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch (e) { body = {}; }
      if (USERS[body.username] !== body.password) return json(res, 401, { error: 'credenciais' });
      counter += 1;
      sessions.set(`s${counter}x`, body.username);
      res.setHeader('Set-Cookie', `sid=s${counter}x; Path=/`);
      return json(res, 200, { ok: true });
    }
    if (url.pathname === '/api/me') return user ? json(res, 200, { user }) : json(res, 401, { error: 'login' });
    // D-010: a rota de saúde expõe versão e dados internos.
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', version: '1.2.3', db: 'postgres://db.internal/app', uptime: 12345 });
    // D-008: arquivo de ambiente exposto (valores falsos).
    if (url.pathname === '/.env') return send(res, 200, 'text/plain', 'DB_PASSWORD=falso-nao-usar\nSESSION_SECRET=falso-nao-usar\n');
    // L-005: qualquer pessoa lê qualquer pedido, sem login e sem conferir o dono.
    let m = /^\/api\/orders\/(\d+)$/.exec(url.pathname);
    if (m && req.method === 'GET') return json(res, 200, { id: Number(m[1]), owner: OWNER[m[1]] || null, total: 99 });
    // L-007: exige login, mas qualquer conta logada lê a nota fiscal de outra (não confere o dono).
    m = /^\/api\/invoices\/(\d+)$/.exec(url.pathname);
    if (m && req.method === 'GET') return user ? json(res, 200, { id: Number(m[1]), owner: OWNER[m[1]] || null, valor: 150 }) : json(res, 401, { error: 'login' });
    // L-006: rota que muda estado com cookie de sessão, aceita de qualquer origem e sem token anti-CSRF.
    if (url.pathname === '/api/profile' && req.method === 'POST') return user ? json(res, 200, { ok: true }) : json(res, 401, { error: 'login' });
    // L-008: o logout só manda apagar o cookie; a sessão continua válida no servidor.
    if (url.pathname === '/logout' && req.method === 'POST') {
      res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
      return json(res, 200, { ok: true });
    }
    // D-007: erro com rastro de pilha e caminho interno.
    return send(res, 500, 'text/plain', 'TypeError: Cannot read properties of undefined\n    at handler (/home/app/server.js:42:13)\n    at Layer.handle (/home/app/node_modules/express/lib/router/layer.js:95:5)\n');
  });
});

server.listen(port, '127.0.0.1');
