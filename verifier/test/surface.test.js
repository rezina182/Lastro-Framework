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

// Achado no App C (Next.js com App Router): as rotas vêm do caminho do arquivo e o middleware cobre os caminhos do
// matcher. Sem isso a descoberta via "0 rotas", o perfil saía como frontend e o modelo de ameaças ficava vazio.
test('superfície: rotas do Next.js (App Router e pages/api), middleware com matcher e modelos do Prisma', () => {
  const root = makeProject({
    'package.json': JSON.stringify({ name: 'n', version: '1.0.0', dependencies: { next: '15.0.0', react: '19.0.0', '@prisma/client': '6.0.0', bcryptjs: '2.4.3' } }),
    'middleware.ts': "import { getToken } from 'next-auth/jwt';\nexport async function middleware(req) { const token = await getToken({ req }); }\nexport const config = { matcher: ['/api/contas/:path*', '/painel/:path*'] };\n",
    'app/api/contas/[id]/route.ts': "export async function GET(req) { return Response.json({}); }\nexport async function DELETE(req) { return new Response(null); }\n",
    'app/api/relatorios/route.ts': 'export async function GET() { return Response.json([]); }\n',
    'app/api/usuarios/route.ts': "import { auth } from '@/lib/auth';\nexport async function POST(req) { const s = await auth(); }\n",
    'app/(site)/api/health/route.ts': "export const GET = () => Response.json({ status: 'ok' });\n",
    'pages/api/legado.ts': 'export default function handler(req, res) { res.json({}); }\n',
    'prisma/schema.prisma': 'model Usuario {\n  id    String @id\n  email String @unique\n  senhaHash String\n}\n\nmodel Lancamento {\n  id String @id\n  valor Decimal\n  pix String?\n}\n',
  });
  try {
    const d = discover(ctxFor(root));
    assert.equal(d.routes.total, 6);
    assert.equal(d.routes.byAuth.global, 2, 'GET e DELETE de /api/contas/:id, cobertos pelo matcher do middleware');
    assert.equal(d.routes.byAuth.visivel, 1, 'POST /api/usuarios chama auth() no próprio arquivo');
    assert.equal(d.routes.byAuth['publica-esperada'], 1, '/api/health, sem o grupo (site) no caminho');
    const sem = d.routes.examples.map((e) => `${e.method} ${e.path}`).sort();
    assert.deepEqual(sem, ['ALL /api/legado', 'GET /api/relatorios']);
    const t = Object.fromEntries(d.tables.map((x) => [x.name, x.categories]));
    assert.deepEqual(t.usuario.sort(), ['contato', 'credencial']);
    assert.deepEqual(t.lancamento, ['financeiro']);
  } finally { cleanup(root); }
});

// Mapa para quem não é técnico: áreas, quem usa, o que fazem e que dados tocam (indício pelo nome no código da área).
test('superfície: mapa da aplicação com áreas, quem usa, ações e dados tocados', () => {
  const root = makeProject({
    'package.json': JSON.stringify({ name: 'n', version: '1.0.0', dependencies: { next: '15.0.0' } }),
    'app/api/contas/route.ts': "import { requireAuth } from '@/lib/auth';\nexport async function GET() { await requireAuth(); return prisma.conta.findMany() }\nexport async function POST() { await requireAuth(); return prisma.conta.create({ data: {} }) }\n",
    'app/api/admin/limpar/route.ts': 'export async function POST() { await prisma.transacao.deleteMany() }\n',
    'app/api/health/route.ts': "export const GET = () => Response.json({ status: 'ok' })\n",
    'prisma/schema.prisma': 'model Conta {\n  id String @id\n  saldo Decimal\n}\n\nmodel Transacao {\n  id String @id\n}\n\nmodel Log {\n  id String @id\n}\n',
  });
  try {
    const m = discover(ctxFor(root)).map;
    const by = Object.fromEntries(m.areas.map((a) => [a.key, a]));
    assert.deepEqual(by['/api/contas'].actions, { consultar: 1, 'criar ou enviar': 1 });
    assert.equal(by['/api/contas'].who, 'logado');
    assert.deepEqual(by['/api/contas'].tables, ['conta']);
    assert.equal(by['/api/admin'].who, 'admin');
    assert.equal(by['/api/admin'].access.naoVista, 1);
    assert.deepEqual(by['/api/admin'].tables, ['transacao']);
    assert.equal(by['/api/health'].who, 'publico');
    assert.deepEqual(m.tables.find((t) => t.name === 'log').areas, []);
  } finally { cleanup(root); }
});
