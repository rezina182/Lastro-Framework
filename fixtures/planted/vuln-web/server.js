'use strict';

// SERVIDOR DE TESTE COM FALHAS PLANTADAS. Nunca use como modelo. Só roda por `lastro bench`,
// em 127.0.0.1, na porta recebida em PORT. Todos os valores secretos aqui são falsos.
const http = require('node:http');

const port = Number(process.env.PORT);
const orders = { 1: { id: 1, owner: 'alice', total: 10 }, 2: { id: 2, owner: 'bob', total: 99 } };

function send(res, status, type, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.end(body);
}

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

  if (url.pathname === '/') {
    // D-001, D-002, D-003: cookie de sessão sem HttpOnly, sem SameSite e sem prefixo.
    // D-004, D-005, D-011: nenhuma política de segurança nos cabeçalhos.
    res.setHeader('Set-Cookie', 'sid=abc123; Path=/');
    return send(res, 200, 'text/html; charset=utf-8', '<!doctype html><html><body><h1>Loja</h1></body></html>');
  }
  // D-010: a rota de saúde expõe versão e dados internos.
  if (url.pathname === '/health') {
    return send(res, 200, 'application/json', JSON.stringify({ status: 'ok', version: '1.2.3', db: 'postgres://db.internal/app', uptime: 12345 }));
  }
  // D-008: arquivo de ambiente exposto (valores falsos).
  if (url.pathname === '/.env') {
    return send(res, 200, 'text/plain', 'DB_PASSWORD=falso-nao-usar\nSESSION_SECRET=falso-nao-usar\n');
  }
  // DL-001: qualquer pessoa lê qualquer pedido, sem login e sem conferir o dono.
  const m = /^\/api\/orders\/(\d+)$/.exec(url.pathname);
  if (m && req.method === 'GET') {
    return send(res, 200, 'application/json', JSON.stringify(orders[m[1]] || {}));
  }
  // DL-002: rota que muda estado, aceita de qualquer origem, sem token anti-CSRF.
  if (url.pathname === '/api/profile' && req.method === 'POST') {
    return send(res, 200, 'application/json', JSON.stringify({ ok: true }));
  }
  // D-007: erro com rastro de pilha e caminho interno.
  return send(res, 500, 'text/plain', 'TypeError: Cannot read properties of undefined\n    at handler (/home/app/server.js:42:13)\n    at Layer.handle (/home/app/node_modules/express/lib/router/layer.js:95:5)\n');
});

server.listen(port, '127.0.0.1');
