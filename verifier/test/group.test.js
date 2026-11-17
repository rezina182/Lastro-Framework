'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { findRepoDirs, globToRe, analyzeGroup, generateSystem } = require('../src/group');
const { classifyRepo } = require('../src/classify');
const { discover } = require('../src/discover');
const { formatGroupMarkdown, formatGroupHtml } = require('../src/group-report');
const { validateSystem } = require('../src/system');
const { makeProject, cleanup, ctxFor, badHrefs } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const NOW = new Date('2026-11-12T12:00:00Z');
const cli = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });

const ORG = () => ({
  'app-x-web/package.json': JSON.stringify({ name: 'app-x-web', version: '1.0.0', dependencies: { react: '18.2.0', vite: '5.0.0' } }),
  'app-x-web/index.html': '<!doctype html><html><body><div id="root"></div></body></html>\n',
  'app-x-web/src/main.js': "const API = 'https://app-x-api.onrender.com';\nfetch(API + '/api/clientes');\n",
  'app-x-api/package.json': JSON.stringify({ name: 'app-x-api', version: '1.0.0', dependencies: { express: '4.19.2', pg: '8.11.0', jsonwebtoken: '9.0.2' } }),
  'app-x-api/server.js': "const SECRET = process.env.JWT_SECRET;\napp.get('/health', (req, res) => res.send('ok'));\napp.post('/api/login', login);\napp.get('/api/clientes', requireAuth, list);\napp.delete('/api/clientes/:id', remove);\n",
  'app-x-api/schema.sql': 'CREATE TABLE clientes (id int, cpf text, email text);\n',
  'app-x-worker/package.json': JSON.stringify({ name: 'app-x-worker', version: '1.0.0', dependencies: { bullmq: '5.0.0', pg: '8.11.0' } }),
  'app-x-worker/src/jobs.js': "fetch('https://api.pagamento.example.com/cobrar');\n",
  'app-x-infra/main.tf': 'resource "x" "y" {}\n',
  'app-x-infra/docker-compose.yml': 'services:\n  api:\n    image: x\n',
  'outro-projeto/package.json': JSON.stringify({ name: 'outro', version: '1.0.0' }),
  'outro-projeto/a.js': 'const a = 1;\n',
});

test('padrão de nomes: * e ? funcionam, sem tratar o resto como regex', () => {
  const re = globToRe('app-x-*');
  assert.ok(re.test('app-x-web') && re.test('APP-X-API'));
  assert.ok(!re.test('outro-app-x-web') && !re.test('app-y-web'));
  assert.ok(globToRe('a.b?').test('a.bc'));
  assert.ok(!globToRe('a.b').test('axb'), 'o ponto não é curinga');
});

test('repositórios: acha as subpastas que parecem repositório, filtra por padrão e recusa pasta vazia ou excesso', () => {
  const root = makeProject(ORG());
  try {
    const all = findRepoDirs(root).map((d) => path.basename(d));
    assert.deepEqual(all, ['app-x-api', 'app-x-infra', 'app-x-web', 'app-x-worker', 'outro-projeto']);
    assert.deepEqual(findRepoDirs(root, { match: 'app-x-*' }).map((d) => path.basename(d)), ['app-x-api', 'app-x-infra', 'app-x-web', 'app-x-worker']);
    assert.deepEqual(findRepoDirs(root, { repos: ['app-x-web'] }).map((d) => path.basename(d)), ['app-x-web']);
    assert.throws(() => findRepoDirs(root, { repos: ['nao-existe'] }), /não encontrado/);
    assert.throws(() => findRepoDirs(root, { match: 'zzz*' }), /Nenhum repositório/);
  } finally { cleanup(root); }
  const vazio = makeProject({ 'LEIAME.txt': 'x\n' });
  try { assert.throws(() => findRepoDirs(vazio), /Nenhum repositório/); } finally { cleanup(vazio); }
  const muitos = makeProject(Object.fromEntries(Array.from({ length: 13 }, (_, i) => [`r${i}/package.json`, '{}'])));
  try { assert.throws(() => findRepoDirs(muitos), /máximo 12/); } finally { cleanup(muitos); }
});

test('classificação: frontend, backend, worker e infraestrutura pelo código, com motivo e confiança', () => {
  const root = makeProject(ORG());
  try {
    const cls = (name) => {
      const ctx = ctxFor(path.join(root, name));
      return classifyRepo(ctx, discover(ctx), name);
    };
    const web = cls('app-x-web');
    assert.equal(web.role, 'frontend');
    assert.equal(web.confidence, 'alta');
    assert.ok(web.reasons.some((r) => /react/.test(r)));
    assert.equal(web.flags.webApp, true);
    assert.equal(web.flags.hasAuth, false);
    const api = cls('app-x-api');
    assert.equal(api.role, 'backend');
    assert.equal(api.flags.hasAuth, true, 'jsonwebtoken e campos de credencial');
    assert.equal(api.flags.tokenAuth, true);
    assert.equal(api.flags.personalData, true, 'cpf e email no esquema');
    assert.equal(api.flags.publicInternet, true);
    assert.equal(api.flags.minorsData, false, 'o que o código não mostra fica desligado');
    assert.ok(api.reasons.some((r) => /rota/.test(r)));
    const worker = cls('app-x-worker');
    assert.equal(worker.role, 'worker');
    assert.equal(worker.flags.webApp, false);
    const infra = cls('app-x-infra');
    assert.equal(infra.role, 'infra');
    assert.ok(infra.reasons.some((r) => /infraestrutura/.test(r)));
  } finally { cleanup(root); }
});

test('classificação: servidor que entrega páginas HTML e API no mesmo repositório é backend full stack', () => {
  const root = makeProject({
    'tudo/package.json': JSON.stringify({ name: 'tudo', version: '1.0.0', dependencies: { express: '4.19.2' } }),
    'tudo/server.js': "app.use(express.static('public'));\napp.get('/api/a', h);\napp.post('/api/b', h);\n",
    'tudo/public/index.html': '<!doctype html><title>x</title>\n',
  });
  try {
    const ctx = ctxFor(path.join(root, 'tudo'));
    const c = classifyRepo(ctx, discover(ctx), 'tudo');
    assert.equal(c.role, 'backend');
    assert.equal(c.fullstack, true);
    assert.ok(c.reasons.some((r) => /full stack/.test(r)));
  } finally { cleanup(root); }
});

test('classificação: sem sinal nenhum o papel é assumido com confiança baixa, e biblioteca é reconhecida', () => {
  const root = makeProject({
    'algo/package.json': JSON.stringify({ name: 'algo', version: '1.0.0' }),
    'algo/a.js': 'const a = 1;\n',
    'util-lib/package.json': JSON.stringify({ name: 'util-lib', version: '1.0.0', main: 'index.js' }),
  });
  try {
    const c1 = ctxFor(path.join(root, 'algo'));
    const r1 = classifyRepo(c1, discover(c1), 'algo');
    assert.equal(r1.confidence, 'baixa');
    assert.ok(r1.reasons.some((r) => /confirme/.test(r)));
    const c2 = ctxFor(path.join(root, 'util-lib'));
    assert.equal(classifyRepo(c2, discover(c2), 'util-lib').role, 'library');
  } finally { cleanup(root); }
});

test('aplicação: o kit identifica os papéis sozinho, liga os repositórios e gera componentes, fluxos e arquitetura', async () => {
  const root = makeProject(ORG());
  try {
    const { group, reports } = await analyzeGroup({ dir: root, name: 'App X', match: 'app-x-*', now: NOW });
    assert.equal(group.repos.length, 4);
    assert.equal(reports.length, 4);
    const role = Object.fromEntries(group.repos.map((r) => [r.name, r.role]));
    assert.deepEqual(role, { 'app-x-api': 'backend', 'app-x-infra': 'infra', 'app-x-web': 'frontend', 'app-x-worker': 'worker' });
    assert.ok(group.repos.every((r) => r.profile === 'derivado'));
    assert.deepEqual(validateSystem(group.system), []);
    const comps = group.system.components;
    assert.ok(comps.find((c) => c.role === 'database' && c.name === 'PostgreSQL'));
    assert.ok(comps.find((c) => c.role === 'external' && c.name === 'api.pagamento.example.com'));
    assert.ok(!comps.some((c) => c.role === 'external' && /app-x-api/.test(c.name)), 'o host da própria aplicação não é serviço externo');
    assert.ok(comps.every((c) => c.inferred === true));
    const f = group.system.flows.map((x) => `${x.from}>${x.to}`);
    for (const e of ['user>app-x-web', 'user>app-x-api', 'app-x-web>app-x-api']) assert.ok(f.includes(e), `faltou ${e}: ${f}`);
    assert.ok(group.system.flows.find((x) => x.from === 'app-x-web' && x.to === 'app-x-api').label === 'Chamadas à API', 'o frontend cita o backend: ligação por menção');
    assert.ok(f.some((x) => /^app-x-api>db-/.test(x)) && f.some((x) => /^app-x-worker>db-/.test(x)));
    assert.ok(f.some((x) => /^app-x-worker>ext-/.test(x)));
    const a = group.architecture;
    assert.equal(a.mode, 'aplicação');
    assert.equal(a.name, 'App X');
    assert.ok(a.flows.length >= 6);
    assert.ok(a.flows.every((x) => x.threats > 0));
    assert.ok(a.nodes.some((n) => n.id === 'app-x-web' && n.source === 'inferido'));
    assert.ok(group.warnings.some((w) => /sem \.lastro\/profile\.json/.test(w) && /app-x-api/.test(w)));
    assert.ok(group.totals.confirmed.total >= 0 && group.totals.analyzed === 4);
    assert.ok(Array.isArray(group.risks));
    for (const e of fs.readdirSync(root)) assert.ok(!fs.existsSync(path.join(root, e, '.lastro')), `${e}: o kit não pode escrever no repositório`);
  } finally { cleanup(root); }
});

test('aplicação: relatórios em Markdown e HTML com papéis, arquitetura, riscos, avisos, legenda e só links oficiais', async () => {
  const root = makeProject(ORG());
  try {
    const { group } = await analyzeGroup({ dir: root, name: 'App X', match: 'app-x-*', now: NOW });
    const md = formatGroupMarkdown(group);
    for (const s of ['# Relatório da aplicação: App X', '## Repositórios identificados', 'Frontend', 'Backend (API)', 'Worker (tarefas)', 'Infraestrutura', '### Arquitetura: fluxo de dados e fronteiras de confiança', '```mermaid', 'Desenho da aplicação **"App X"**', '## Riscos de segurança confirmados, de todos os repositórios', '## Privacidade e dados pessoais', '## Avisos', '## Legenda', '| `AUTH` |']) assert.ok(md.includes(s), `faltou no Markdown: ${s}`);
    const html = formatGroupHtml(group);
    for (const s of ['<title>Aplicação: App X</title>', 'id="repos"', 'id="arquitetura"', '<svg', 'id="riscos"', 'id="legenda"', 'Perfil derivado é rascunho']) assert.ok(html.includes(s), `faltou no HTML: ${s}`);
    assert.ok(!/<script|<link|<iframe|<img/i.test(html));
    assert.ok(!/\bsrc=/i.test(html));
    assert.deepEqual(badHrefs(html), []);
    assert.ok(html.includes(`default-src 'none'`));
  } finally { cleanup(root); }
});

test('aplicação: system.json corrigido pelo usuário vale sobre a identificação automática', async () => {
  const root = makeProject(ORG());
  try {
    const { group: auto } = await analyzeGroup({ dir: root, name: 'App X', match: 'app-x-*', now: NOW });
    const sys = JSON.parse(JSON.stringify(auto.system));
    sys.components.find((c) => c.repo === 'app-x-worker').role = 'backend';
    sys.components.forEach((c) => { delete c.inferred; });
    const { group } = await analyzeGroup({ dir: root, name: 'App X', system: sys, now: NOW });
    const w = group.repos.find((r) => r.name === 'app-x-worker');
    assert.equal(w.role, 'backend');
    assert.equal(w.confidence, 'declarado');
    assert.deepEqual(w.reasons, ['papel declarado no system.json']);
    assert.equal(group.architecture.nodes.find((n) => n.id === 'app-x-worker').source, 'declarado');
    await assert.rejects(() => analyzeGroup({ dir: root, name: 'App X', system: { schemaVersion: 1, name: 'x', components: [{ id: 'A', name: 'A', role: 'zzz' }] }, now: NOW }), /system inválido/);
    await assert.rejects(() => analyzeGroup({ dir: root, name: 'A', match: 'app-x-*', now: NOW }), /nome da aplicação/);
  } finally { cleanup(root); }
});

test('aplicação: repositório com perfil declarado usa o perfil dele, sem aviso de derivado', async () => {
  const files = ORG();
  files['app-x-api/.lastro/profile.json'] = JSON.stringify({ schemaVersion: 1, name: 'API', flags: { webApp: true, hasAuth: true, anonymousUsers: false, realtime: false, uploads: false, personalData: true, minorsData: true, thirdPartyAssets: false, aiCodingAgents: false, publicInternet: true, federatedLogin: false, tokenAuth: true, oauthProvider: false } });
  const root = makeProject(files);
  try {
    const { group } = await analyzeGroup({ dir: root, name: 'App X', match: 'app-x-*', now: NOW });
    const api = group.repos.find((r) => r.name === 'app-x-api');
    assert.equal(api.profile, 'declarado');
    assert.ok(api.flags.includes('minorsData'));
    assert.ok(!group.warnings.some((w) => /"app-x-api": sem \.lastro\/profile\.json/.test(w)));
    assert.ok(group.warnings.some((w) => /"app-x-web": sem \.lastro\/profile\.json/.test(w)));
  } finally { cleanup(root); }
});

test('CLI app: relatório HTML, rascunho de system.json que não se sobrescreve, reuso do system, relatórios por repositório e redação', () => {
  const root = makeProject(ORG());
  const out = path.join(root, '..', `lastro-app-${process.pid}`);
  try {
    let r = cli('app', '--name', 'App X', '--root', root, '--match', 'app-x-*', '--out', path.join(out, 'app.html'), '--write-system', path.join(out, 'system.json'), '--out-dir', path.join(out, 'repos'));
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Aplicação "App X": 4 repositório\(s\)/);
    assert.match(r.stdout, /app-x-web: frontend/);
    assert.match(r.stdout, /app-x-worker: worker/);
    assert.ok(fs.existsSync(path.join(out, 'app.html')));
    assert.ok(fs.existsSync(path.join(out, 'repos', 'app-x-api.html')));
    const sys = JSON.parse(fs.readFileSync(path.join(out, 'system.json'), 'utf8'));
    assert.deepEqual(validateSystem(sys), []);
    r = cli('app', '--name', 'App X', '--root', root, '--match', 'app-x-*', '--write-system', path.join(out, 'system.json'));
    assert.equal(r.status, 3);
    assert.match(r.stderr, /já existe/);
    r = cli('app', '--name', 'App X', '--root', root, '--system', path.join(out, 'system.json'), '--out', path.join(out, 'app2.md'), '--redact', 'app-x');
    assert.equal(r.status, 0, r.stderr);
    const md = fs.readFileSync(path.join(out, 'app2.md'), 'utf8');
    assert.ok(md.startsWith('# Relatório da aplicação:'));
    assert.ok(!/app-x/i.test(md), 'a redação troca o nome do repositório em todo o relatório');
    assert.equal(cli('app', '--root', root).status, 3, 'sem --name é erro de uso');
    assert.equal(cli('app', '--name', 'X Y', '--root', root, '--match', 'zzz*').status, 3);
    assert.equal(cli('app', '--name', 'X Y', '--root', root, '--match', 'app-x-*', '--theme', path.join(out, 'nao-existe.css'), '--out', path.join(out, 'z.html')).status, 3);
  } finally { cleanup(root); fs.rmSync(out, { recursive: true, force: true }); }
});

test('rascunho de system.json: host da própria aplicação não vira externo e banco compartilhado vem com a nota de suposição', () => {
  const mk = (base, role, stores, hosts, flags = {}) => ({ base, rel: base, cls: { role, confidence: 'alta', fullstack: false, flags: { personalData: false, ...flags } }, disc: { stores, externalHosts: hosts, routes: { total: role === 'backend' ? 2 : 0 } }, ctx: { files: [], read: () => '' }, pkgName: base });
  const sys = generateSystem('App', [mk('minha-api', 'backend', ['PostgreSQL'], ['minha-api.exemplo.com', 'stripe.com']), mk('meu-worker', 'worker', ['PostgreSQL'], [])]);
  assert.deepEqual(validateSystem(sys), []);
  assert.ok(sys.components.find((c) => c.role === 'database' && /compartilhado/.test(c.note)));
  assert.deepEqual(sys.components.filter((c) => c.role === 'external').map((c) => c.name), ['stripe.com']);
});
