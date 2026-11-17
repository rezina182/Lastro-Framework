'use strict';

// Gêmeo limpo de vuln-web. Só roda por `lastro bench`, em 127.0.0.1, na porta recebida em PORT.
const http = require('node:http');

const port = Number(process.env.PORT);
const USERS = { alice: 'senha-alice-falsa', bob: 'senha-bob-falsa' };
const OWNER = { 1: 'alice', 2: 'bob' };
const sessions = new Map();
let counter = 0;

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const COOKIE_FLAGS = 'Path=/; Secure; HttpOnly; SameSite=Strict';

function send(res, status, type, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.end(body);
}
const json = (res, status, obj) => send(res, status, 'application/json', JSON.stringify(obj));

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const sid = (/(?:^|;\s*)__Host-sid=(\w+)/.exec(req.headers.cookie || '') || [])[1];
  const user = sessions.get(sid) || null;
  let raw = '';
  req.on('data', (c) => { raw += c; });
  return req.on('end', () => {
    if (req.method === 'OPTIONS') return send(res, 204, 'text/plain', '');
    if (url.pathname === '/' && req.method === 'GET') {
      res.setHeader('Set-Cookie', `__Host-sid=abc123; ${COOKIE_FLAGS}`);
      return send(res, 200, 'text/html; charset=utf-8', '<!doctype html><html><body><h1>Loja</h1></body></html>');
    }
    if (url.pathname === '/login' && req.method === 'POST') {
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch (e) { body = {}; }
      if (USERS[body.username] !== body.password) return json(res, 401, { error: 'credenciais' });
      counter += 1;
      sessions.set(`s${counter}x`, body.username);
      res.setHeader('Set-Cookie', `__Host-sid=s${counter}x; ${COOKIE_FLAGS}`);
      return json(res, 200, { ok: true });
    }
    if (url.pathname === '/api/me' && req.method === 'GET') return user ? json(res, 200, { user }) : json(res, 401, { error: 'login' });
    if (url.pathname === '/health' && req.method === 'GET') return json(res, 200, { status: 'ok' });
    // Objetos: exige login E confere o dono (403 para outra conta).
    const m = /^\/api\/(orders|invoices)\/(\d+)$/.exec(url.pathname);
    if (m && req.method === 'GET') {
      if (!user) return json(res, 401, { error: 'login' });
      if (OWNER[m[2]] !== user) return json(res, 403, { error: 'proibido' });
      return json(res, 200, { id: Number(m[2]), owner: user });
    }
    // Rota que muda estado: exige sessão e só aceita requisição da própria origem.
    if (url.pathname === '/api/profile' && req.method === 'POST') {
      if (!user) return json(res, 401, { error: 'login' });
      const same = req.headers['sec-fetch-site'] === 'same-origin' && req.headers.origin === `http://${req.headers.host}`;
      return same ? json(res, 200, { ok: true }) : json(res, 403, { error: 'origem' });
    }
    // Logout de verdade: a sessão deixa de existir no servidor.
    if (url.pathname === '/logout' && req.method === 'POST') {
      sessions.delete(sid);
      res.setHeader('Set-Cookie', `__Host-sid=; ${COOKIE_FLAGS}; Max-Age=0`);
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { error: 'nao encontrado' });
  });
});

server.listen(port, '127.0.0.1');
