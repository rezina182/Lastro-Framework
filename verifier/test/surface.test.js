'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { discover } = require('../src/discover');
const { moduleKey } = require('../src/surface');
const { ctxFor, makeProject, cleanup } = require('./helpers');

const APP = {
  'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { express: '4.19.2', helmet: '8.0.0', pg: '8.11.0', otpauth: '9.0.0', sharp: '0.33.0' } }),
  'src/app.js': [
    "const { criarRotasQuizzes } = require('./quizzes/rotas');",
    "const auth = require('./auth/rotas');",
    'const professor = [verificarOrigem, sessao, csrfEmMutacao];',
    'app.use(express.json({ limit: "100kb" }));',
    "app.get('/health', (req, res) => res.json({ status: 'ok' }));",
    "app.use('/api/auth', auth);",
    "app.use('/api/quizzes', ...professor, criarRotasQuizzes(pool));",
    '',
  ].join('\n'),
  'src/auth/rotas.js': ["router.post('/login', entrar);", "router.post('/logout', sair);", "router.get('/me', exigirSessao, eu);", "res.cookie('sid', id, { httpOnly: true });", "const t = req.get('x-csrf-token');", ''].join('\n'),
  'src/quizzes/rotas.js': ["router.get('/', listar);", "router.get('/:id', ler);", "router.post('/', criar);", "router.delete('/:id', apagar);", "const h = crypto.scryptSync(senha, sal, 64);", ''].join('\n'),
  'migrations/001.sql': 'CREATE TABLE professores (id uuid primary key, email citext, senha_hash text);\nCREATE TABLE IF NOT EXISTS quizzes (id uuid, titulo text);\n',
  '.github/workflows/ci.yml': 'name: CI\non: [push]\njobs:\n  testes:\n    runs-on: ubuntu-latest\n  segredos:\n    runs-on: ubuntu-latest\n',
};

test('superfície: módulos de rotas pelo prefixo de montagem, com proteção vista na montagem (inclusive lista espalhada)', () => {
  const root = makeProject(APP);
  try {
    const d = discover(ctxFor(root));
    const byPrefix = Object.fromEntries(d.modules.map((m) => [m.prefix, m]));
    assert.equal(byPrefix['/api/quizzes'].routes, 4);
    assert.equal(byPrefix['/api/quizzes'].protected, 4, 'protegidas pela montagem com ...professor');
    assert.equal(byPrefix['/api/quizzes'].writes, true);
    assert.equal(byPrefix['/api/auth'].routes, 3);
    assert.ok(byPrefix['/health']);
  } finally { cleanup(root); }
});

test('superfície: defesas vistas no código, tabelas com categoria de dado e jobs do CI', () => {
  const root = makeProject(APP);
  try {
    const d = discover(ctxFor(root));
    const ids = d.defenses.map((x) => x.id);
    for (const id of ['headers', 'password', 'mfa', 'image', 'bodylimit', 'cookie', 'csrf']) assert.ok(ids.includes(id), `faltou a defesa ${id}`);
    assert.ok(!ids.includes('tokens'));
    assert.equal(d.defenses.find((x) => x.id === 'headers').evidence, 'dependência helmet');
    const prof = d.tables.find((t) => t.name === 'professores');
    assert.ok(prof.categories.includes('credencial') && prof.categories.includes('contato'));
    assert.deepEqual(d.tables.find((t) => t.name === 'quizzes').categories, []);
    assert.deepEqual(d.ciJobs.map((j) => j.job), ['testes', 'segredos']);
  } finally { cleanup(root); }
});

test('superfície: chave do módulo agrupa /api/<recurso> e o primeiro segmento no resto', () => {
  assert.equal(moduleKey('/api/quizzes/:id/duplicar'), '/api/quizzes');
  assert.equal(moduleKey('/api/:id'), '/api');
  assert.equal(moduleKey('/login'), '/login');
  assert.equal(moduleKey('/'), '/');
  assert.equal(moduleKey('/:slug'), '/*');
});
