'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const TM = require('../src/threatmodel');
const { discover } = require('../src/discover');
const { runCheck } = require('../src/engine');
const { formatMarkdown } = require('../src/report');
const { formatHtml } = require('../src/html');
const { loadTickets } = require('../src/backlog');
const { makeProject, profileJson, cleanup, ctxFor, badHrefs } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const NOW = new Date('2026-11-12T12:00:00Z');
const cli = (root, ...args) => spawnSync(process.execPath, [CLI, ...args, '--root', root], { encoding: 'utf8' });

const FILES = () => ({
  '.lastro/profile.json': profileJson({ webApp: true, hasAuth: true, personalData: true, publicInternet: true, uploads: true }),
  'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { express: '4.19.2', pg: '8.11.0', multer: '1.4.5', ws: '8.0.0' } }),
  'server.js': [
    "const express = require('express');",
    'const app = express();',
    "const SECRET = process.env.JWT_SECRET || 'S3cr3tValue-xyz-9';",
    "app.get('/health', (req, res) => res.send('ok'));",
    "app.post('/api/login', login);",
    "app.get('/api/clientes', requireAuth, list);",
    "app.delete('/api/clientes/:id', remove);",
    "app.post('/api/upload', upload.single('f'), up);",
    "fetch('https://api.exemplo.com.br/v1/dados');",
    '',
  ].join('\n'),
  'schema.sql': 'CREATE TABLE c (id int, cpf text, email text, diagnostico text);\n',
  'tests/a.test.js': "app.get('/so-no-teste', x);\n",
});

test('STRIDE: categorias derivadas dos pilares e das CWE', () => {
  assert.deepEqual(TM.strideOf({ pillars: 'A', cwe: [] }), ['S']);
  assert.deepEqual(TM.strideOf({ pillars: 'CI', cwe: [862] }), ['T', 'I', 'E']);
  assert.deepEqual(TM.strideOf({ pillars: 'UN', cwe: [] }), ['R']);
  assert.deepEqual(TM.strideOf({ pillars: 'D', cwe: [] }), ['D']);
  assert.deepEqual(TM.strideOf({ pillars: 'L', cwe: [] }), []);
});

test('modelo: o validador aceita o rascunho e recusa id inválido, duplicado, aceitação sem dono e campo desconhecido', () => {
  const base = { schemaVersion: 1, generatedAt: '2026-11-12', assets: [{ id: 'A-01', name: 'Dados', kind: 'dado', source: 'declarado' }], threats: [{ id: 'TM-S-web', decision: null }] };
  assert.deepEqual(TM.validateModel(base), []);
  const ruim = JSON.parse(JSON.stringify(base));
  ruim.threats = [{ id: 'TM-X-web', decision: null }, { id: 'TM-S-web', decision: 'accept', rationale: 'curto' }, { id: 'TM-S-web', decision: 'mitigate' }, { id: 'TM-T-web', decision: 'talvez' }];
  ruim.extra = 1;
  const errs = TM.validateModel(ruim).join('\n');
  assert.match(errs, /formato TM-S-web/);
  assert.match(errs, /duplicado/);
  assert.match(errs, /aceitar exige/);
  assert.match(errs, /decision/);
  assert.match(errs, /campo desconhecido "extra"/);
  assert.match(TM.validateModel({ ...base, threats: [{ id: 'TM-S-web', decision: 'not_applicable' }] }).join('\n'), /exige rationale/);
  assert.match(TM.validateModel({ ...base, threats: [{ id: 'TM-S-web', decision: null, likelihood: 9 }] }).join('\n'), /likelihood/);
});

test('decisão pendente: sem decisão e aceitação vencida contam como pendentes', () => {
  assert.equal(TM.isPending({ decision: null }, NOW), true);
  assert.equal(TM.isPending({ decision: 'mitigate' }, NOW), false);
  assert.equal(TM.isPending({ decision: 'accept', expires: '2026-01-01' }, NOW), true);
  assert.equal(TM.isPending({ decision: 'accept', expires: '2027-01-01' }, NOW), false);
});

test('descoberta: rotas, autenticação vista, armazenamento, tempo real, upload, host externo, variáveis só pelo nome e indícios de dado', () => {
  const root = makeProject(FILES());
  try {
    const d = discover(ctxFor(root));
    assert.equal(d.routes.total, 5, 'o arquivo de teste não conta');
    assert.equal(d.routes.byAuth.visivel, 1);
    assert.equal(d.routes.byAuth['publica-esperada'], 2);
    assert.equal(d.routes.authMounts, 0);
    assert.equal(d.routes.byAuth['nao-vista'], 2);
    assert.deepEqual(d.routes.examples.map((x) => `${x.method} ${x.path}`).sort(), ['DELETE /api/clientes/:id', 'POST /api/upload']);
    assert.ok(d.routes.examples[0].location.startsWith('server.js:'));
    assert.deepEqual(d.stores, ['PostgreSQL']);
    assert.deepEqual(d.realtime, ['WebSocket (ws)']);
    assert.deepEqual(d.uploads, ['multer']);
    assert.deepEqual(d.externalHosts, ['api.exemplo.com.br']);
    assert.deepEqual(d.env.credentials, ['JWT_SECRET']);
    assert.ok(!JSON.stringify(d).includes('S3cr3tValue'), 'nunca guarda valor');
    const cats = d.dataHints.map((h) => h.category).sort();
    assert.deepEqual(cats, ['contato', 'credencial', 'identificacao', 'sensivel'], 'credencial vem da constante SECRET no código');
    assert.equal(d.dataHints.find((h) => h.category === 'sensivel').sensitive, true);
  } finally { cleanup(root); }
});

test('descoberta: middleware global de autenticação cobre as rotas seguintes', () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ webApp: true }),
    'app.js': "app.get('/antes', a);\napp.use(requireAuth);\napp.get('/depois', b);\napp.use('/api', requireAuth, router);\napp.use('/pub', router2);\n",
  });
  try {
    const d = discover(ctxFor(root));
    assert.equal(d.routes.byAuth['nao-vista'], 1);
    assert.equal(d.routes.byAuth.global, 1);
    assert.equal(d.routes.authMounts, 1, 'só a montagem com autenticação conta');
    assert.equal(d.routes.byAuth.montagem, 0, 'a montagem não aponta para um arquivo de rotas');
  } finally { cleanup(root); }
});

test('descoberta: autenticação aplicada na montagem do roteador cobre o arquivo de rotas e os roteadores montados por ele', () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ webApp: true }),
    'src/app.js': [
      "const rotas = require('./rotas');",
      "const sub = require('./sub');",
      "app.use('/api', requireAuth, rotas);",
      "app.use('/adm', requireAdmin, require('./admin2'));",
      "app.use('/livre', sub);",
      '',
    ].join('\n'),
    'src/rotas.js': "const inner = require('./inner');\nrouter.get('/a', h);\nrouter.use('/in', inner);\n",
    'src/inner.js': "router.post('/x', h);\n",
    'src/admin2.js': "router.get('/z', h);\n",
    'src/sub.js': "router.get('/s', h);\n",
  });
  try {
    const d = discover(ctxFor(root));
    assert.equal(d.routes.total, 4);
    assert.equal(d.routes.byAuth.montagem, 3, 'rotas, inner (por herança) e admin2 (require direto na montagem)');
    assert.equal(d.routes.byAuth['nao-vista'], 1);
    assert.deepEqual(d.routes.examples.map((x) => x.path), ['/s']);
    assert.equal(d.routes.authMounts, 2);
  } finally { cleanup(root); }
});

test('descoberta: middleware em português e lista de middlewares guardada numa variável também contam como autenticação', () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ webApp: true }),
    'src/app.js': [
      "const { criarRotasAcesso } = require('./acesso/rotas');",
      "const { criarRotasPub } = require('./pub/rotas');",
      'const sessao = exigirSessao(pool, config);',
      'const professor = [',
      '  verificarOrigem,',
      '  sessao,',
      '  csrfEmMutacao,',
      '];',
      "app.use('/api/acesso', professor, criarRotasAcesso(pool));",
      "app.use('/api/publico', criarRotasPub(pool));",
      "app.get('/api/painel', sessao, painel);",
      '',
    ].join('\n'),
    'src/acesso/rotas.js': "router.post('/convites', h);\n",
    'src/pub/rotas.js': "router.get('/vitrine', h);\n",
  });
  try {
    const d = discover(ctxFor(root));
    assert.equal(d.routes.byAuth.montagem, 1, 'a lista professor traz sessao, e sessao vem de exigirSessao');
    assert.equal(d.routes.byAuth.visivel, 1, 'sessao na própria rota');
    assert.equal(d.routes.byAuth['nao-vista'], 1);
    assert.deepEqual(d.routes.examples.map((x) => x.path), ['/vitrine']);
    assert.equal(d.routes.authMounts, 1);
  } finally { cleanup(root); }
});

test('descoberta: "saúde" como endpoint de saúde não é dado sensível, e text/event-stream solto não é tempo real', () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ webApp: true }),
    'src/checks.js': "const tipos = [{ kind: 'saúde', path: '/health' }];\n// regex que procura 'text/event-stream' em outros projetos\nconst RE = 'text/event-stream';\n",
    'src/pacientes.js': "const campos = { dados_saude: true, cpf: 1 };\n",
    'src/sse.js': "res.writeHead(200, { 'Content-Type': 'text/event-stream' });\n",
  });
  const semSse = makeProject({ '.lastro/profile.json': profileJson({}), 'a.js': "const RE = 'text/event-stream';\n" });
  try {
    const d = discover(ctxFor(root));
    const sens = d.dataHints.find((h) => h.category === 'sensivel');
    assert.deepEqual(sens.files, ['src/pacientes.js'], 'só o campo dados_saude conta');
    assert.deepEqual(d.realtime, ['SSE (text/event-stream)'], 'o cabeçalho de verdade conta');
    assert.deepEqual(discover(ctxFor(semSse)).realtime, [], 'a string solta não conta');
  } finally { cleanup(root); cleanup(semSse); }
});

test('motor: o relatório traz o rascunho, com ameaças de id estável, estado derivado dos controles e pistas', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const t = r.threatModel;
    assert.equal(t.persisted, false);
    assert.equal(t.reviewed, false);
    assert.ok(t.threats.length >= 10);
    assert.ok(t.threats.every((x) => TM.ID_THREAT.test(x.id)));
    assert.ok(t.threats.every((x) => x.pending && x.decision === null));
    assert.equal(t.counts.pending, t.counts.threats);
    const web = t.threats.find((x) => x.id === 'TM-E-web') || t.threats.find((x) => x.surface === 'web');
    assert.ok(web.evidence.some((e) => /sem autenticação vista/.test(e)), 'a pista de rota sem autenticação aparece');
    assert.ok(t.assets.some((a) => /Dados pessoais/.test(a.name)));
    assert.ok(t.assets.some((a) => a.source === 'descoberto' && /sensíveis/.test(a.name)), 'indício de dado sensível vira ativo descoberto');
    const auth = t.threats.filter((x) => x.surface === 'auth');
    assert.ok(auth.length > 0);
    // Controles manuais sem atestação: sem prova. A exceção é a rota de escrita sem autenticação vista do projeto de
    // teste, que o AUTH-044 (automático) acusa: a ameaça fica exposta.
    assert.ok(auth.every((x) => x.state === 'unproven' || (x.state === 'exposed' && x.controls.includes('AUTH-044'))), 'controles manuais sem atestação: sem prova');
    assert.ok(auth.some((x) => x.state === 'unproven'));
    assert.ok(!JSON.stringify(r).includes('S3cr3tValue'));
  } finally { cleanup(root); }
});

test('CLI threat-model: não grava sem --write, grava com --write, preserva decisões e recusa arquivo inválido', async () => {
  const root = makeProject(FILES());
  try {
    let out = cli(root, 'threat-model');
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /Rascunho não gravado/);
    assert.match(out.stdout, /ATENÇÃO: indício de/);
    assert.ok(!fs.existsSync(path.join(root, '.lastro', 'threat-model.json')));

    out = cli(root, 'threat-model', '--write');
    assert.equal(out.status, 0, out.stderr);
    const file = path.join(root, '.lastro', 'threat-model.json');
    const m = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.deepEqual(TM.validateModel(m), []);
    assert.ok(m.threats.length >= 10);
    assert.ok(m.threats.every((t) => t.decision === null));

    m.threats[0].decision = 'mitigate';
    m.threats[0].likelihood = 4;
    m.reviewedBy = 'Fulano';
    fs.writeFileSync(file, JSON.stringify(m));
    out = cli(root, 'threat-model', '--write');
    assert.equal(out.status, 0, out.stderr);
    const again = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(again.threats.find((t) => t.id === m.threats[0].id).decision, 'mitigate');
    assert.equal(again.threats.find((t) => t.id === m.threats[0].id).likelihood, 4);
    assert.equal(again.reviewedBy, 'Fulano', 'a revisão registrada é preservada');

    fs.writeFileSync(file, '{ruim');
    out = cli(root, 'threat-model', '--write');
    assert.equal(out.status, 3);
    assert.match(out.stderr, /ilegível/);
    assert.equal(fs.readFileSync(file, 'utf8'), '{ruim', 'arquivo inválido nunca é sobrescrito');
  } finally { cleanup(root); }
});

test('CORE-012 com modelo estruturado: rascunho falha, pendência falha, revisado passa, vencido falha', async () => {
  const root = makeProject(FILES());
  const file = path.join(root, '.lastro', 'threat-model.json');
  const core12 = async () => (await runCheck({ root, now: NOW, only: ['CORE-012'] })).controls[0];
  try {
    cli(root, 'threat-model', '--write');
    let c = await core12();
    assert.equal(c.state, 'failed');
    assert.ok(c.findings.some((f) => /rascunho/.test(f.message)));
    assert.ok(c.findings.some((f) => /sem decisão/.test(f.message)));

    const m = JSON.parse(fs.readFileSync(file, 'utf8'));
    m.threats.forEach((t) => { t.decision = 'mitigate'; });
    fs.writeFileSync(file, JSON.stringify(m));
    c = await core12();
    assert.ok(c.findings.every((f) => !/sem decisão/.test(f.message)));
    assert.ok(c.findings.some((f) => /rascunho/.test(f.message)), 'sem revisão registrada ainda é rascunho');

    m.reviewedBy = 'Fulano';
    m.reviewedAt = '2026-11-01';
    fs.writeFileSync(file, JSON.stringify(m));
    c = await core12();
    assert.equal(c.state, 'verified', JSON.stringify(c.findings));
    assert.match(c.notes[0], /revisado por Fulano/);

    m.reviewedAt = '2025-01-01';
    fs.writeFileSync(file, JSON.stringify(m));
    c = await core12();
    assert.equal(c.state, 'failed');
    assert.ok(c.findings.some((f) => /sem revisão há/.test(f.message)));

    m.reviewedAt = '2026-11-01';
    m.threats[0] = { id: m.threats[0].id, decision: 'accept', rationale: 'aceito por ser uma ferramenta interna e sem dado real', owner: 'Fulano', expires: '2026-01-01' };
    fs.writeFileSync(file, JSON.stringify(m));
    c = await core12();
    assert.equal(c.state, 'failed', 'aceitação vencida volta a ser pendência');
  } finally { cleanup(root); }
});

test('modelo inválido no disco: o CORE-012 acusa e a análise segue sem ele, com aviso', async () => {
  const root = makeProject({ ...FILES(), '.lastro/threat-model.json': JSON.stringify({ schemaVersion: 1, generatedAt: '2026-11-12', assets: [], threats: [{ id: 'xx', decision: null }] }) });
  try {
    const r = await runCheck({ root, now: NOW });
    assert.ok(r.warnings.some((w) => /threat-model\.json inválido/.test(w)));
    assert.equal(r.threatModel.persisted, false);
    assert.equal(r.controls.find((c) => c.id === 'CORE-012').state, 'failed');
  } finally { cleanup(root); }
});

test('probabilidade informada no modelo entra na análise de risco, com o motivo', async () => {
  const root = makeProject(FILES());
  const file = path.join(root, '.lastro', 'threat-model.json');
  try {
    const base = await runCheck({ root, now: NOW });
    const before = base.risk.security.find((i) => i.id === 'AUTH-027');
    cli(root, 'threat-model', '--write');
    const m = JSON.parse(fs.readFileSync(file, 'utf8'));
    const t = m.threats.find((x) => x.id === 'TM-E-auth');
    assert.ok(t, 'ameaça de elevação de privilégio em autenticação e autorização existe');
    t.decision = 'mitigate';
    t.likelihood = 1;
    fs.writeFileSync(file, JSON.stringify(m));
    const r = await runCheck({ root, now: NOW });
    const after = r.risk.security.find((i) => i.id === 'AUTH-027');
    assert.equal(after.likelihood, 1);
    assert.ok(before.likelihood > after.likelihood);
    assert.match(after.reasons.likelihood.join(' '), /informada por uma pessoa no modelo de ameaças \(TM-E-auth\)/);
    assert.equal(after.assumed, true, 'o controle continua sem prova: o teto de "crítico exige evidência" vale');
  } finally { cleanup(root); }
});

test('backlog: ameaça marcada para mitigar sobe a prioridade e o ticket cita a ameaça', async () => {
  const root = makeProject(FILES());
  const file = path.join(root, '.lastro', 'threat-model.json');
  try {
    cli(root, 'threat-model', '--write');
    cli(root, 'backlog', '--write');
    const before = loadTickets(root).tickets.find((t) => t.control === 'AUTH-029');
    assert.ok(before);
    fs.rmSync(path.join(root, '.lastro', 'backlog'), { recursive: true, force: true });
    const m = JSON.parse(fs.readFileSync(file, 'utf8'));
    m.threats.filter((t) => t.id.endsWith('-auth')).forEach((t) => { t.decision = 'mitigate'; });
    fs.writeFileSync(file, JSON.stringify(m));
    const out = cli(root, 'backlog', '--write');
    assert.equal(out.status, 0, out.stderr);
    const after = loadTickets(root);
    assert.deepEqual(after.errors, []);
    const t = after.tickets.find((x) => x.control === 'AUTH-029');
    assert.ok(t.threat && /^TM-[STRIDE]-auth$/.test(t.threat));
    assert.match(t.summary, /Mitiga TM-/);
    assert.ok(Number(t.priority[1]) < Number(before.priority[1]) || before.priority === 'P0', `${before.priority} -> ${t.priority}`);
  } finally { cleanup(root); }
});

test('relatórios: Markdown e HTML mostram o modelo de ameaças, com as pistas, sem script nem link externo', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const md = formatMarkdown(r);
    for (const s of ['## Modelo de ameaças', '### Ativos', 'Rotas sem autenticação vista', 'DELETE /api/clientes/:id', 'Perguntas para a revisão', 'Rascunho gerado nesta execução']) assert.ok(md.includes(s), `faltou no Markdown: ${s}`);
    const html = formatHtml(r);
    for (const s of ['id="ameacas"', 'Modelo de ameaças', 'DELETE /api/clientes/:id', 'não quer dizer desprotegida', 'confirme se há dado sensível']) assert.ok(html.includes(s), `faltou no HTML: ${s}`);
    assert.ok(!/<script|<link|<iframe|<img/i.test(html));
    assert.deepEqual(badHrefs(html), []);
    assert.ok(!/\bsrc=/i.test(html));
    const out = cli(root, 'threat-model', '--out', path.join(root, 'tm.md'));
    assert.equal(out.status, 0, out.stderr);
    assert.match(fs.readFileSync(path.join(root, 'tm.md'), 'utf8'), /^# Modelo de ameaças/);
  } finally { cleanup(root); }
});
