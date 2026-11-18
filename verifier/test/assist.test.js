'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const A = require('../src/assist');
const { runCheck } = require('../src/engine');
const { ctxFor, makeProject, profileJson, cleanup, serve } = require('./helpers');

const NOW = new Date('2026-11-17T12:00:00Z');
const WF = (body) => `name: ci\non: [push]\npermissions:\n  contents: read\njobs:\n  testes:\n    runs-on: ubuntu-latest\n${body}`;

function withCtx(files, fn, opts = {}) {
  const root = makeProject(files);
  try { return fn(ctxFor(root, opts)); } finally { cleanup(root); }
}

test('CORE-015: CI sem testes, testes sem banco (quando a aplicação usa banco) e testes com banco real', () => {
  withCtx({ '.github/workflows/ci.yml': WF('    steps:\n      - run: npm ci\n') }, (ctx) => {
    assert.deepEqual(A.ciTestsWithDb(ctx, { stores: ['PostgreSQL'] }).findings.map((f) => f.key), ['ci-no-tests']);
  });
  withCtx({ '.github/workflows/ci.yml': WF('    steps:\n      - run: npm test\n') }, (ctx) => {
    assert.deepEqual(A.ciTestsWithDb(ctx, { stores: ['PostgreSQL'] }).findings.map((f) => f.key), ['ci-no-db']);
    assert.deepEqual(A.ciTestsWithDb(ctx, { stores: [] }).findings, [], 'sem banco na aplicação, não exige banco no CI');
  });
  withCtx({ '.github/workflows/ci.yml': WF('    services:\n      postgres:\n        image: postgres:16\n    steps:\n      - run: npm test\n') }, (ctx) => {
    const r = A.ciTestsWithDb(ctx, { stores: ['PostgreSQL'] });
    assert.deepEqual(r.findings, []);
    assert.match(r.notes[0], /com um banco real no CI.*deploy/);
  });
  withCtx({}, (ctx) => assert.equal(A.ciTestsWithDb(ctx, {}).tested, 0, 'sem CI não opina (CORE-003 já aponta)'));
});

test('AUTH-002: custo baixo do bcrypt e scrypt fraco viram achado; custo bom vira prova parcial', () => {
  withCtx({ 'src/senha.js': "const bcrypt = require('bcrypt');\nexports.h = (s) => bcrypt.hash(s, 8);\n" }, (ctx) => {
    const r = A.passwordHash(ctx);
    assert.equal(r.findings[0].severity, 'high');
    assert.match(r.findings[0].message, /Custo do bcrypt 8/);
  });
  withCtx({ 'src/senha.js': "const bcrypt = require('bcryptjs');\nconst SALT_ROUNDS = 12;\nexports.h = (s) => bcrypt.hash(s, SALT_ROUNDS);\n" }, (ctx) => {
    const r = A.passwordHash(ctx);
    assert.deepEqual(r.findings, []);
    assert.match(r.notes[0], /bcryptjs.*custo 12.*72 bytes/);
  });
  withCtx({ 'src/senha.js': "const c = require('node:crypto');\nexports.h = (s, salt) => c.scryptSync(s, salt, 64, { N: 1024 });\n" }, (ctx) => {
    assert.match(A.passwordHash(ctx).findings[0].message, /scrypt com N=1024/);
  });
  withCtx({ 'src/x.js': 'module.exports = 1;\n' }, (ctx) => assert.equal(A.passwordHash(ctx).tested, 0));
});

test('AG-001 e AG-007: sem hook nem deny é achado médio (não bloqueia); com o hook do adaptador vira prova parcial', () => {
  const flags = { aiCodingAgents: true };
  withCtx({}, (ctx) => {
    const r = A.agentGuard(ctx, { flags });
    for (const id of ['AG-001', 'AG-007']) assert.equal(r[id].findings[0].severity, 'medium', id);
  });
  const hook = { '.kiro/hooks/lastro-protect.json': '{"hooks":[{"trigger":"PreToolUse","action":{"command":"node lastro-protect.js"}}]}', '.kiro/hooks/lastro-protect.js': "// bloqueia .env, .kiro/settings e hooks\nif (bad) process.exit(2);\n" };
  withCtx(hook, (ctx) => {
    const r = A.agentGuard(ctx, { flags });
    for (const id of ['AG-001', 'AG-007']) { assert.deepEqual(r[id].findings, [], id); assert.match(r[id].notes[0], /há mecanismo/, id); }
  });
  withCtx({}, (ctx) => assert.equal(A.agentGuard(ctx, { flags: {} })['AG-001'].tested, 0, 'sem agentes de IA no perfil, não opina'));
});

async function withServer(handler, fn) {
  const srv = await serve(handler);
  const root = makeProject({});
  try { return await fn(ctxFor(root, { url: srv.url })); } finally { await srv.close(); cleanup(root); }
}

test('WEB-016 e WEB-018: documentação e listagem expostas, Content-Type ausente ou sem charset', async () => {
  await withServer((req, res) => {
    if (req.url === '/swagger.json') { res.setHeader('Content-Type', 'application/json'); return res.end('{"openapi":"3.0.0","paths":{}}'); }
    if (req.url === '/uploads/') { res.setHeader('Content-Type', 'text/html'); return res.end('<html><title>Index of /uploads</title></html>'); }
    if (req.url === '/') { res.setHeader('Content-Type', 'text/html'); return res.end('<p>oi</p>'); }
    res.statusCode = 404;
    return res.end('nada');
  }, async (ctx) => {
    const e = await A.exposedPaths(ctx);
    assert.deepEqual(e.findings.map((f) => f.key).sort(), ['exposed:/swagger.json', 'exposed:/uploads/']);
    const c = await A.contentTypes(ctx);
    assert.deepEqual(c.findings.map((f) => f.key).sort(), ['ct-charset:página inicial', 'ct-missing:rota inexistente']);
  });
  await withServer((req, res) => { res.statusCode = req.url === '/' ? 200 : 404; res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end('<p>ok</p>'); }, async (ctx) => {
    assert.deepEqual((await A.exposedPaths(ctx)).findings, []);
    assert.match((await A.exposedPaths(ctx)).notes[0], /sem exposição/);
    assert.deepEqual((await A.contentTypes(ctx)).findings, []);
  });
});

const LOGIN = { path: '/login' };
function loginServer({ limitAfter = null, defaultAdmin = false } = {}) {
  let n = 0;
  return (req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      if (req.url !== '/login') { res.statusCode = 404; return res.end('{}'); }
      n += 1;
      const j = JSON.parse(raw || '{}');
      if (limitAfter && n > limitAfter) { res.statusCode = 429; return res.end('{"erro":"muitas tentativas"}'); }
      if (defaultAdmin && j.username === 'admin' && j.password === 'admin') { res.setHeader('Set-Cookie', 'sid=abc123456789; HttpOnly'); return res.end('{"ok":true}'); }
      res.statusCode = 401;
      return res.end('{"erro":"credenciais"}');
    });
  };
}

test('AUTH-011: credencial padrão aceita é crítica; recusadas viram prova parcial', async () => {
  await withServer(loginServer({ defaultAdmin: true }), async (ctx) => {
    const r = await A.defaultCreds(ctx, LOGIN);
    assert.deepEqual(r.findings.map((f) => f.key), ['default-cred:admin']);
    assert.equal(r.findings[0].severity, 'critical');
    assert.doesNotMatch(r.findings[0].message, /"admin" \(HTTP 200, com cookie de sessão\).*abc123/);
  });
  await withServer(loginServer(), async (ctx) => {
    const r = await A.defaultCreds(ctx, LOGIN);
    assert.deepEqual(r.findings, []);
    assert.match(r.notes[0], /credenciais padrão comuns recusadas/);
  });
});

test('AUTH-016: sem limite depois de 25 erros é achado alto; com 429 vira prova parcial com o número de tentativas', async () => {
  await withServer(loginServer(), async (ctx) => {
    const r = await A.bruteForce(ctx, LOGIN);
    assert.equal(r.findings[0].severity, 'high');
    assert.equal(r.tested, A.BRUTE_ATTEMPTS);
  });
  await withServer(loginServer({ limitAfter: 5 }), async (ctx) => {
    const r = await A.bruteForce(ctx, LOGIN);
    assert.deepEqual(r.findings, []);
    assert.match(r.notes[0], /passou a limitar depois de 6 tentativa/);
  });
});

test('motor: prova assistida que acha falha vence a atestação; a que passa só deixa nota; "não se aplica" fica intacto', async () => {
  const attest = (id, extra = {}) => ({ [id]: { state: 'verified', attestedBy: 'Fulana', collectedAt: '2026-11-01', expiresAt: '2027-05-01', ...extra } });
  const files = {
    '.lastro/profile.json': profileJson({ hasAuth: true, aiCodingAgents: true }),
    '.lastro/status.json': JSON.stringify({ schemaVersion: 1, attestations: { ...attest('AUTH-002'), ...attest('AG-007', { state: 'not_applicable', note: 'Nenhum agente edita a própria configuração aqui.' }) } }),
    'src/senha.js': "const bcrypt = require('bcrypt');\nexports.h = (s) => bcrypt.hash(s, 6);\n",
  };
  const root = makeProject(files);
  try {
    const r = await runCheck({ root, now: NOW });
    const a42 = r.controls.find((c) => c.id === 'AUTH-042');
    assert.equal(a42.state, 'failed', 'o pedaço automático (AUTH-042) mede o custo 6 e falha');
    assert.equal(r.controls.find((c) => c.id === 'AUTH-002').state, 'verified', 'o AUTH-002 manual fica só com a parte humana (atestada)');
    const ag1 = r.controls.find((c) => c.id === 'AG-001');
    assert.equal(ag1.state, 'failed');
    assert.ok(ag1.findings.every((f) => !f.blocking), 'heurística média não bloqueia');
    const ag7 = r.controls.find((c) => c.id === 'AG-007');
    assert.equal(ag7.state, 'not_applicable', 'ausência suspeita (soft) não derruba a decisão de uma pessoa');
    assert.match(ag7.notes[0], /A máquina não confirmou o que foi atestado/);
  } finally { cleanup(root); }
  const ok = makeProject({ ...files, 'src/senha.js': "const bcrypt = require('bcrypt');\nexports.h = (s) => bcrypt.hash(s, 12);\n", '.lastro/status.json': JSON.stringify({ schemaVersion: 1, attestations: {} }) });
  try {
    const r = await runCheck({ root: ok, now: NOW });
    assert.equal(r.controls.find((c) => c.id === 'AUTH-042').state, 'verified', 'o pedaço automático passa por inteiro');
    const cf = r.controls.find((c) => c.id === 'CORE-015');
    assert.equal(cf.state, 'unverified', 'sem CI, a prova assistida do CORE-015 não opina');
    const ag1 = r.controls.find((c) => c.id === 'AG-001');
    assert.equal(ag1.state, 'failed', 'ausência suspeita sem atestação vira achado (médio, não bloqueia)');
  } finally { cleanup(ok); }
});

test('playbook: mostra o que a máquina já testou e pré-preenche a atestação com essa prova parcial', async () => {
  const { buildPlaybook, formatPlaybookMarkdown } = require('../src/playbook');
  const { loadCatalog } = require('../src/catalog');
  const hook = { '.kiro/hooks/lastro-protect.json': '{"hooks":[{"trigger":"PreToolUse"}]}', '.kiro/hooks/lastro-protect.js': '// bloqueia .env e .kiro/settings\nif (x) process.exit(2);\n' };
  const root = makeProject({ '.lastro/profile.json': profileJson({ aiCodingAgents: true }), ...hook });
  try {
    const r = await runCheck({ root, now: NOW });
    const pb = buildPlaybook(r, loadCatalog(), { now: NOW, only: ['AG-001'] });
    const item = pb.items[0];
    assert.match(item.machine[0], /há mecanismo que barra a leitura/);
    assert.match(item.attestation.json['AG-001'].evidenceRef, /prova parcial da máquina/);
    assert.match(item.attestation.json['AG-001'].note, /^Máquina: há mecanismo/);
    if (formatPlaybookMarkdown) assert.match(formatPlaybookMarkdown(pb), /O que a máquina já testou/);
  } finally { cleanup(root); }
});

test('controles automáticos novos: AUTH-040 e AUTH-041 provam por inteiro com --active; sem --active ou sem rota de login, sem prova', async () => {
  const { checks } = require('../src/checks/assisted');
  const prof = { schemaVersion: 1, name: 't', flags: { hasAuth: true }, authProbes: { login: LOGIN } };
  const run = async (handler, { active = true, profile = prof } = {}) => {
    const srv = await serve(handler);
    const root = makeProject({});
    try {
      const ctx = ctxFor(root, { url: srv.url, active, profile });
      return { bf: await checks['http.login.bruteforce'](ctx), dc: await checks['http.login.default-creds'](ctx) };
    } finally { await srv.close(); cleanup(root); }
  };
  const semLimite = await run(loginServer());
  assert.equal(semLimite.bf.state, 'failed');
  assert.equal(semLimite.dc.state, 'verified', 'nenhuma credencial padrão entrou, todas tentadas');
  const comLimite = await run(loginServer({ limitAfter: 3 }));
  assert.equal(comLimite.bf.state, 'verified');
  assert.match(comLimite.bf.notes[0], /passou a limitar depois de 4 tentativa\(s\).*o limite já vinha do teste de contas padrão/);
  assert.equal(comLimite.dc.state, 'unverified', 'o limitador cortou o teste das credenciais: não dá para afirmar');
  const padrao = await run(loginServer({ defaultAdmin: true }));
  assert.equal(padrao.dc.state, 'failed');
  const passivo = await run(loginServer(), { active: false });
  assert.match(passivo.bf.notes[0], /--active/);
  const semLogin = await run(loginServer(), { profile: { ...prof, authProbes: undefined } });
  assert.match(semLogin.dc.notes[0], /authProbes\.login/);
});

test('controles automáticos novos: AUTH-042 lê o hash do código; WEB-022 e WEB-023 precisam de --url', async () => {
  const { checks } = require('../src/checks/assisted');
  withCtx({ 'src/senha.js': "const bcrypt = require('bcrypt');\nexports.h = (s) => bcrypt.hash(s, 13);\n" }, (ctx) => assert.equal(checks['repo.code.password-hash'](ctx).state, 'verified'));
  withCtx({ 'src/senha.js': "const bcrypt = require('bcrypt');\nexports.h = (s) => bcrypt.hash(s, 5);\n" }, (ctx) => assert.equal(checks['repo.code.password-hash'](ctx).state, 'failed'));
  withCtx({ 'src/x.js': '1;\n' }, (ctx) => assert.equal(checks['repo.code.password-hash'](ctx).state, 'unverified'));
  await withCtx({}, async (ctx) => {
    assert.match((await checks['http.paths.exposed'](ctx)).notes[0], /--url/);
    assert.match((await checks['http.content-type'](ctx)).notes[0], /--url/);
  });
});

test('AUTH-043: conta semeada ou redefinida com senha fixa é achada, sem copiar o valor; senha aleatória passa', () => {
  const { checks } = require('../src/checks/assisted');
  const seed = "const bcrypt = require('bcryptjs');\nconst SENHA_PADRAO = \"Troca@123\";\nasync function boot() {\n  const h = bcrypt.hashSync(SENHA_PADRAO, 10);\n}\nfunction reset(s) { return bcrypt.hashSync(s || SENHA_PADRAO, 10); }\n";
  withCtx({ 'server.js': seed }, (ctx) => {
    const r = checks['repo.code.default-password'](ctx);
    assert.equal(r.state, 'failed');
    assert.match(r.findings[0].message, /SENHA_PADRAO, 2 uso\(s\) em server\.js, linhas 4, 6/);
    assert.doesNotMatch(JSON.stringify(r), /Troca@123/, 'o valor da senha nunca vai para o achado');
  });
  withCtx({ 'server.js': "const bcrypt = require('bcrypt');\nconst h = bcrypt.hash('segredo-fixo', 12);\n" }, (ctx) => assert.match(checks['repo.code.default-password'](ctx).findings[0].message, /texto literal/));
  withCtx({ 'server.js': "const bcrypt = require('bcrypt');\nconst c = require('node:crypto');\nconst h = bcrypt.hash(c.randomBytes(12).toString('hex'), 12);\n" }, (ctx) => assert.equal(checks['repo.code.default-password'](ctx).state, 'verified'));
  withCtx({ 'x.js': '1;\n' }, (ctx) => assert.equal(checks['repo.code.default-password'](ctx).state, 'unverified'));
});

test('WEB-022: testa também as rotas de métrica e diagnóstico que o próprio código declara', async () => {
  const srv = await serve((req, res) => {
    if (req.url === '/api/metrics/internal') { res.setHeader('Content-Type', 'text/plain'); return res.end('# HELP memoria\n# TYPE memoria gauge\nmemoria 1\n'); }
    res.statusCode = 404;
    return res.end('nada');
  });
  const root = makeProject({ 'server.js': "app.get('/api/metrics/internal', h);\napp.get('/api/clientes/:id', auth, h);\n" });
  try {
    const { checks } = require('../src/checks/assisted');
    const r = await checks['http.paths.exposed'](ctxFor(root, { url: srv.url }));
    assert.equal(r.state, 'failed');
    assert.deepEqual(r.findings.map((f) => f.key), ['exposed:/api/metrics/internal']);
  } finally { await srv.close(); cleanup(root); }
});
