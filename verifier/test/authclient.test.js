'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeClient, login, encodeBody, granted, is2xx, looksDenied } = require('../src/authclient');
const { ctxFor, serve } = require('./helpers');

const cfg = { login: { path: '/login' }, protected: '/api/me' };
const legit = { origin: 'http://x' };

function app() {
  const sessions = new Set();
  return serve((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (req.url === '/login' && req.method === 'POST') {
        const j = JSON.parse(body || '{}');
        if (j.username === 'alice' && j.password === 'certa') {
          sessions.add('s1');
          res.setHeader('Set-Cookie', 'sid=s1; Path=/; HttpOnly');
          return res.end('{"ok":true}');
        }
        res.statusCode = 401;
        return res.end('{"error":"credenciais"}');
      }
      if (req.url === '/semcookie' && req.method === 'POST') return res.end('{"ok":true}');
      if (req.url === '/api/me') {
        const m = /sid=(\w+)/.exec(req.headers.cookie || '');
        if (m && sessions.has(m[1])) return res.end('{"user":"alice"}');
        res.statusCode = 401;
        return res.end('{"error":"login"}');
      }
      res.statusCode = 404;
      return res.end('{}');
    });
  });
}

test('authclient: login com a conta certa guarda o cookie e a sessão passa na rota protegida', async () => {
  const srv = await app();
  try {
    const ctx = ctxFor('.', { url: srv.url });
    const r = await login(makeClient(ctx), cfg, { user: 'alice', password: 'certa' }, 'a', legit);
    assert.equal(r.ok, true);
    assert.equal(r.jar.names().join(), 'sid');
  } finally { await srv.close(); }
});

test('authclient: senha errada, rota sem cookie e sessão rejeitada são inconclusivos, sem vazar credencial', async () => {
  const srv = await app();
  try {
    const ctx = ctxFor('.', { url: srv.url });
    const bad = await login(makeClient(ctx), cfg, { user: 'alice', password: 'senha-secreta-errada' }, 'a', legit);
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /recusado \(HTTP 401\)/);
    assert.doesNotMatch(bad.reason, /senha-secreta-errada|alice/);
    const noCookie = await login(makeClient(ctx), { login: { path: '/semcookie' }, protected: '/api/me' }, { user: 'alice', password: 'certa' }, 'a', legit);
    assert.match(noCookie.reason, /não devolveu cookie/);
  } finally { await srv.close(); }
});

test('authclient: codifica JSON e formulário, e 2xx com texto de negação não é acesso concedido', () => {
  assert.equal(encodeBody('json', { a: 1 }), '{"a":1}');
  assert.equal(encodeBody('form', { a: 'x y', n: 2 }), 'a=x+y&n=2');
  assert.equal(is2xx({ ok: true, status: 204 }), true);
  assert.equal(is2xx({ ok: false, status: 0 }), false);
  assert.equal(granted({ ok: true, status: 200, body: '{"id":2,"total":99}' }), true);
  assert.equal(granted({ ok: true, status: 200, body: '{"error":"Forbidden"}' }), false);
  assert.equal(granted({ ok: true, status: 403, body: '{}' }), false);
  assert.equal(looksDenied({ body: `${'x'.repeat(400)} forbidden` }), false);
});
