'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeProject, cleanup, ctxFor, runOne, serve } = require('./helpers');
const { request } = require('../src/http');
const { parseCsp } = require('../src/checks/http');

const GOOD_CSP = "default-src 'self'; script-src 'self'; script-src-attr 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

const COMMON = {
  'content-security-policy': GOOD_CSP,
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
};

function goodHandler(req, res) {
  if (req.url === '/health') {
    res.writeHead(200, { ...COMMON, 'content-type': 'application/json' });
    return res.end('{"status":"ok"}');
  }
  if (req.url === '/api/status') {
    res.writeHead(200, { ...COMMON, 'content-type': 'application/json' });
    return res.end('{"status":"ok"}');
  }
  if (req.url === '/app.js') {
    res.writeHead(200, { ...COMMON, 'content-type': 'text/javascript' });
    return res.end('console.log(1)');
  }
  if (req.url === '/') {
    res.writeHead(200, {
      ...COMMON,
      'content-type': 'text/html',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'camera=()',
      'set-cookie': ['__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict'],
    });
    return res.end('<html></html>');
  }
  res.writeHead(404, { ...COMMON, 'content-type': 'application/json' });
  return res.end('{"error":"nao encontrado"}');
}

// Cabeçalhos só na página inicial: o erro típico que a amostragem existe para pegar.
function homeOnlyHandler(req, res) {
  if (req.url === '/') return goodHandler(req, res);
  if (req.url === '/oops.html') {
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end('<html></html>');
  }
  res.writeHead(req.url === '/__lastro_probe_404__' ? 404 : 200, { 'content-type': req.url === '/app.js' ? 'text/javascript' : 'application/json' });
  return res.end(req.url === '/app.js' ? 'console.log(1)' : '{"status":"ok"}');
}

function badHandler(req, res) {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end('{"status":"ok","version":"1.2.3","db":"postgres://x"}');
  }
  if (req.url === '/.env') {
    res.writeHead(200);
    return res.end('SECRET_KEY=abc\n');
  }
  if (req.url === '/.git/HEAD') {
    res.writeHead(200);
    return res.end('ref: refs/heads/main\n');
  }
  if (req.method === 'TRACE') {
    res.writeHead(200, { 'content-type': 'message/http' });
    return res.end(`TRACE / HTTP/1.1\r\nx-lastro-probe: ${req.headers['x-lastro-probe']}\r\n`);
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'access-control-allow-origin': req.headers.origin, 'access-control-allow-credentials': 'true' });
    return res.end();
  }
  if (req.url === '/') {
    res.writeHead(200, {
      'content-type': 'text/html',
      'content-security-policy': "script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",
      'x-powered-by': 'Express',
      server: 'nginx/1.18.0',
      'set-cookie': ['connect.sid=abc; Path=/'],
    });
    return res.end('<html></html>');
  }
  res.writeHead(500, { 'content-type': 'text/plain' });
  return res.end('Error: falhou\n    at handler (C:\\Users\\dev\\app\\server.js:10:5)\n');
}

async function withServer(handler, fn) {
  const s = await serve(handler);
  try {
    return await fn(s.url);
  } finally {
    await s.close();
  }
}

async function run(id, url, opts = {}) {
  const root = makeProject({});
  try {
    return await runOne(id, ctxFor(root, { url, ...opts }));
  } finally {
    cleanup(root);
  }
}

test('parseCsp lê diretivas e ignora repetição', () => {
  const d = parseCsp("default-src 'self'; script-src 'none'; script-src *");
  assert.deepEqual(d['script-src'], ["'none'"]);
});

test('servidor bom: todas as verificações passivas passam', () =>
  withServer(goodHandler, async (url) => {
    for (const id of ['http.csp.script', 'http.csp.complementary', 'http.headers.basic', 'http.disclosure', 'http.health.minimal', 'http.errors.generic', 'http.paths.sensitive', 'http.cookies.flags']) {
      const r = await run(id, url);
      assert.equal(r.state, 'verified', `${id}: ${JSON.stringify(r.findings)}`);
    }
    // HSTS não se aplica em http local
    assert.equal((await run('http.hsts', url)).state, 'not_applicable');
  }));

test('servidor ruim: CSP, cabeçalhos, saúde, erros, caminhos e cookies falham', () =>
  withServer(badHandler, async (url) => {
    const csp = await run('http.csp.script', url);
    assert.equal(csp.state, 'failed');
    assert.ok(csp.findings.some((f) => f.key === 'csp-unsafe-inline'));
    assert.ok(csp.findings.some((f) => f.key === 'csp-unsafe-eval'));
    assert.equal((await run('http.csp.complementary', url)).state, 'failed');
    assert.equal((await run('http.headers.basic', url)).state, 'failed');
    const disc = await run('http.disclosure', url);
    assert.deepEqual(disc.findings.map((f) => f.key).sort(), ['server-version', 'x-powered-by']);
    const health = await run('http.health.minimal', url);
    assert.equal(health.state, 'failed');
    assert.ok(health.findings[0].message.includes('version'));
    const err = await run('http.errors.generic', url);
    assert.equal(err.state, 'failed');
    const paths = await run('http.paths.sensitive', url);
    assert.deepEqual(paths.findings.map((f) => f.location).sort(), ['/.env', '/.git/HEAD']);
    assert.ok(paths.findings.every((f) => f.severity === 'critical'));
    const cookies = await run('http.cookies.flags', url);
    assert.equal(cookies.state, 'failed');
    assert.ok(cookies.findings.some((f) => f.key === 'cookie-httponly:connect.sid' && f.severity === 'high'));
  }));

test('métodos e CORS: sem --active fica unverified; com --active acha TRACE e CORS refletido', () =>
  withServer(badHandler, async (url) => {
    assert.equal((await run('http.methods.cors', url)).state, 'unverified');
    const r = await run('http.methods.cors', url, { active: true });
    assert.equal(r.state, 'failed');
    assert.deepEqual(r.findings.map((f) => f.key).sort(), ['cors-reflect-credentials', 'trace-enabled']);
  }));

test('métodos e CORS: servidor bom passa com --active', () =>
  withServer((req, res) => { res.writeHead(405); res.end(); }, async (url) => {
    assert.equal((await run('http.methods.cors', url, { active: true })).state, 'verified');
  }));

test('sem --url ou servidor fora do ar o estado é unverified, nunca verified', async () => {
  assert.equal((await run('http.csp.script', null)).state, 'unverified');
  const dead = await serve((q, s) => s.end());
  const url = dead.url;
  await dead.close();
  for (const id of ['http.csp.script', 'http.health.minimal', 'http.paths.sensitive', 'http.errors.generic']) {
    assert.equal((await run(id, url)).state, 'unverified', id);
  }
});

test('HSTS: https fora de localhost sem cabeçalho falha; http público falha', async () => {
  const ctx = (url, headers) => ({ url, thresholds: { hstsMinSeconds: 31536000 }, fetch: async () => ({ ok: true, status: 200, headers, body: '', setCookie: [] }) });
  const { checks } = require('../src/checks/http');
  assert.equal((await checks['http.hsts'](ctx('https://exemplo.test', {}))).state, 'failed');
  assert.equal((await checks['http.hsts'](ctx('https://exemplo.test', { 'strict-transport-security': 'max-age=300' }))).state, 'failed');
  assert.equal((await checks['http.hsts'](ctx('https://exemplo.test', { 'strict-transport-security': 'max-age=31536000' }))).findings[0].key, 'hsts-subdomains:página');
  assert.equal((await checks['http.hsts'](ctx('https://exemplo.test', { 'strict-transport-security': 'max-age=31536000; includeSubDomains' }))).state, 'verified');
  assert.equal((await checks['http.hsts'](ctx('http://exemplo.test', {}))).state, 'failed');
});

test('cliente HTTP: não segue redirecionamento para outra origem e respeita o limite de tamanho', async () => {
  const outro = await serve((q, s) => { s.writeHead(200); s.end('chegou'); });
  const origem = await serve((q, s) => {
    if (q.url === '/r') { s.writeHead(302, { location: `${outro.url}/` }); return s.end(); }
    if (q.url === '/mesma') { s.writeHead(302, { location: '/fim' }); return s.end(); }
    if (q.url === '/fim') { s.writeHead(200); return s.end('ok'); }
    s.writeHead(200);
    return s.end('x'.repeat(2000));
  });
  try {
    const cross = await request(`${origem.url}/r`, { maxRedirects: 3 });
    assert.equal(cross.status, 302);
    assert.equal(cross.redirectStopped, true);
    const same = await request(`${origem.url}/mesma`, { maxRedirects: 3 });
    assert.equal(same.body, 'ok');
    const big = await request(`${origem.url}/grande`, { maxBytes: 100 });
    assert.equal(big.truncated, true);
    assert.ok(big.body.length <= 100);
    const cred = await request('http://usuario:senha@127.0.0.1:1/');
    assert.equal(cred.ok, false);
    const proto = await request('ftp://127.0.0.1/');
    assert.equal(proto.ok, false);
  } finally {
    await outro.close();
    await origem.close();
  }
});

test('cliente HTTP: tempo esgotado devolve falha em vez de travar', async () => {
  const lento = await serve(() => { /* nunca responde */ });
  try {
    const r = await request(`${lento.url}/`, { timeoutMs: 300 });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'tempo esgotado');
  } finally {
    await lento.close();
  }
});

const PROFILE_WITH_PATHS = {
  schemaVersion: 1,
  name: 'teste',
  flags: {},
  paths: { health: '/health', login: '/oops.html', api: '/api/status', static: '/app.js' },
};

test('amostragem: servidor com cabeçalhos em todas as respostas passa nas sondas, inclusive com rotas do perfil', () =>
  withServer(goodHandler, async (url) => {
    const profile = { ...PROFILE_WITH_PATHS, paths: { health: '/health', api: '/api/status', static: '/app.js' } };
    for (const id of ['http.csp.script', 'http.csp.complementary', 'http.headers.basic']) {
      const r = await run(id, url, { profile });
      assert.equal(r.state, 'verified', `${id}: ${JSON.stringify(r.findings)}`);
      assert.ok(r.notes.join(' ').includes('api (/api/status)'), `${id} deveria listar a amostra`);
      assert.ok(r.notes.join(' ').includes('estático (/app.js)'));
    }
  }));

test('amostragem: cabeçalhos só na página inicial são pegos no erro 404, na API, no estático e no login', () =>
  withServer(homeOnlyHandler, async (url) => {
    const basic = await run('http.headers.basic', url, { profile: PROFILE_WITH_PATHS });
    assert.equal(basic.state, 'failed');
    const keys = basic.findings.map((f) => f.key);
    for (const k of ['nosniff:erro 404', 'nosniff:saúde', 'nosniff:login', 'nosniff:api', 'nosniff:estático']) assert.ok(keys.includes(k), `faltou ${k}`);
    assert.ok(!keys.includes('nosniff:página'));
    assert.ok(basic.findings.every((f) => f.location), 'todo achado indica o caminho');
    assert.ok(keys.includes('referrer-missing:login'), 'HTML do login também precisa de Referrer-Policy');
    assert.ok(!keys.includes('referrer-missing:api'), 'JSON não precisa de Referrer-Policy');

    const script = await run('http.csp.script', url, { profile: PROFILE_WITH_PATHS });
    assert.equal(script.state, 'failed');
    assert.ok(script.findings.some((f) => f.key === 'csp-missing:login' && f.location === '/oops.html'));

    const comp = await run('http.csp.complementary', url, { profile: PROFILE_WITH_PATHS });
    assert.equal(comp.state, 'failed');
    assert.ok(comp.findings.some((f) => f.key === 'csp-frame-ancestors:erro 404'));
    assert.ok(comp.findings.some((f) => f.key === 'csp-frame-ancestors:api'));
  }));

test('amostragem: rota declarada que não responde é ignorada e a página inicial continua sendo exigida', () =>
  withServer(goodHandler, async (url) => {
    const profile = { ...PROFILE_WITH_PATHS, paths: { api: '/api/status', static: '/nao-existe.js' } };
    const r = await run('http.headers.basic', url, { profile });
    // /nao-existe.js cai no 404 do servidor bom, que também tem os cabeçalhos
    assert.equal(r.state, 'verified');
  }));

test('amostragem: o HSTS é exigido em cada resposta amostrada, não só na página', async () => {
  const { checks } = require('../src/checks/http');
  const good = { 'strict-transport-security': 'max-age=31536000; includeSubDomains' };
  const ctx = (url) => ({
    url,
    profile: { paths: { api: '/api/x' } },
    thresholds: { hstsMinSeconds: 31536000 },
    fetch: async (p) => ({ ok: true, status: 200, headers: p === '/api/x' ? {} : good, body: '', setCookie: [] }),
  });
  const r = await checks['http.hsts'](ctx('https://exemplo.test'));
  assert.equal(r.state, 'failed');
  assert.deepEqual(r.findings.map((f) => f.key), ['hsts-missing:api']);
  assert.equal(r.findings[0].location, '/api/x');
});
