'use strict';

// Gêmeo limpo de vuln-web. Só roda por `lastro bench`, em 127.0.0.1, na porta recebida em PORT.
const http = require('node:http');

const port = Number(process.env.PORT);

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

function send(res, status, type, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'OPTIONS') return send(res, 204, 'text/plain', '');
  if (url.pathname === '/' && req.method === 'GET') {
    res.setHeader('Set-Cookie', '__Host-sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict');
    return send(res, 200, 'text/html; charset=utf-8', '<!doctype html><html><body><h1>Loja</h1></body></html>');
  }
  if (url.pathname === '/health' && req.method === 'GET') {
    return send(res, 200, 'application/json', JSON.stringify({ status: 'ok' }));
  }
  return send(res, 404, 'application/json', JSON.stringify({ error: 'nao encontrado' }));
});

server.listen(port, '127.0.0.1');
