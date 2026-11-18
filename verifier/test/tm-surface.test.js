'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { signature, diffSurface } = require('../src/tm-surface');
const { runCheck } = require('../src/engine');
const { makeProject, profileJson, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const cli = (root, ...args) => spawnSync(process.execPath, [CLI, ...args, '--root', root], { encoding: 'utf8' });
const disc = (over = {}) => ({ modules: [{ prefix: '/api/a', routes: 2 }], tables: [{ name: 'u' }], stores: ['PostgreSQL'], realtime: [], uploads: [], externalHosts: [], routes: { total: 2 }, ...over });

test('assinatura: só o que muda a superfície; diferença descrita em frases curtas', () => {
  const a = signature(disc());
  assert.equal(a.hash, signature(disc()).hash, 'estável');
  assert.doesNotMatch(JSON.stringify(a), /\.js|\.sql|senha/);
  const b = signature(disc({ modules: [{ prefix: '/api/a', routes: 3 }, { prefix: '/api/b', routes: 1 }], tables: [{ name: 'u' }, { name: 'pagamentos' }], uploads: ['multer'] }));
  const d = diffSurface(a, b);
  for (const s of ['/api/a: 2 → 3 rota(s)', 'módulo novo /api/b (1 rota(s))', 'tabela novo: pagamentos', 'upload novo: multer']) assert.ok(d.includes(s), `faltou: ${s} em ${JSON.stringify(d)}`);
  assert.deepEqual(diffSurface(a, a), []);
  assert.deepEqual(diffSurface(null, a), []);
});

test('modelo vivo: superfície que muda depois da gravação faz o CORE-012 avisar o que mudou; nova gravação limpa o aviso', async () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ webApp: true }),
    'server.js': "const r = require('./rotas');\napp.use('/api/pedidos', exigirSessao, r);\n",
    'rotas.js': "router.get('/', listar);\n",
  });
  try {
    assert.equal(cli(root, 'threat-model', '--write').status, 0);
    const file = path.join(root, '.lastro', 'threat-model.json');
    const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.match(saved.surface.hash, /^[0-9a-f]{16}$/);
    assert.ok(saved.surface.summary.modules.includes('/api/pedidos:1'));
    const now = new Date();
    let r = await runCheck({ root, now, only: ['CORE-012'] });
    assert.ok(!r.controls[0].findings.some((f) => /superfície da aplicação mudou/.test(f.message)));
    // O código ganha uma rota de escrita e uma tabela nova.
    fs.writeFileSync(path.join(root, 'rotas.js'), "router.get('/', listar);\nrouter.post('/', criar);\n");
    fs.mkdirSync(path.join(root, 'migrations'));
    fs.writeFileSync(path.join(root, 'migrations', '1.sql'), 'CREATE TABLE pagamentos (id int, cartao text);\n');
    r = await runCheck({ root, now, only: ['CORE-012'] });
    const msg = r.controls[0].findings.map((f) => f.message).join(' | ');
    assert.match(msg, /superfície da aplicação mudou/);
    assert.match(msg, /\/api\/pedidos: 1 → 2 rota\(s\)/);
    assert.match(msg, /tabela novo: pagamentos/);
    assert.deepEqual(r.threatModel.surface.changes.includes('tabela novo: pagamentos'), true);
    // Gravar de novo: preserva as decisões, atualiza a assinatura e a data de mudança.
    assert.equal(cli(root, 'threat-model', '--write').status, 0);
    const again = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.notEqual(again.surface.hash, saved.surface.hash);
    r = await runCheck({ root, now, only: ['CORE-012'] });
    assert.ok(!r.controls[0].findings.some((f) => /superfície da aplicação mudou/.test(f.message)));
  } finally { cleanup(root); }
});

test('modelo vivo: revisão anterior à última mudança da superfície pede nova revisão; a data de mudança não anda sem mudança', async () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ webApp: true }), 'server.js': "app.get('/api/x', exigirSessao, h);\n" });
  try {
    assert.equal(cli(root, 'threat-model', '--write').status, 0);
    const file = path.join(root, '.lastro', 'threat-model.json');
    const m = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(m.surface.changedAt, undefined, 'a primeira gravação da assinatura não conta como mudança');
    m.reviewedBy = 'Pessoa Revisora';
    m.reviewedAt = '2020-01-01';
    m.surface.changedAt = '2026-01-01T00:00:00.000Z';
    fs.writeFileSync(file, JSON.stringify(m));
    const r = await runCheck({ root, now: new Date(), only: ['CORE-012'] });
    assert.ok(r.controls[0].findings.some((f) => /anterior à última mudança da superfície \(2026-01-01\)/.test(f.message)));
    assert.equal(cli(root, 'threat-model', '--write').status, 0);
    const kept = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(kept.surface.changedAt, '2026-01-01T00:00:00.000Z', 'sem mudança de superfície, a data fica');
    assert.equal(kept.reviewedBy, 'Pessoa Revisora', 'a revisão humana nunca é apagada');
  } finally { cleanup(root); }
});
