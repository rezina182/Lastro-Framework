'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { validateSystem, loadSystem, resolveRepos } = require('../src/system');
const { runCheck } = require('../src/engine');
const { toMermaid, toSvg } = require('../src/architecture');
const { formatMarkdown } = require('../src/report');
const { formatHtml } = require('../src/html');
const { makeProject, profileJson, cleanup, badHrefs } = require('./helpers');

const NOW = new Date('2026-11-12T12:00:00Z');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const SYSTEM = (over = {}) => ({
  schemaVersion: 1,
  name: 'Plataforma de teste',
  components: [
    { id: 'web', name: 'Frontend', role: 'frontend', repo: 'apps/web', exposure: 'internet' },
    { id: 'api', name: 'API', role: 'backend', repo: 'apps/api', exposure: 'internet', dataClasses: ['pessoal'] },
    { id: 'db', name: 'Banco de dados', role: 'database', exposure: 'privada' },
    { id: 'pay', name: 'Gateway de pagamento', role: 'external' },
  ],
  flows: [
    { from: 'user', to: 'web', label: 'Navegação', protocol: 'https' },
    { from: 'web', to: 'api', label: 'API REST', protocol: 'https' },
    { from: 'api', to: 'db', label: 'Consultas', protocol: 'sql' },
    { from: 'api', to: 'pay', label: 'Cobrança', protocol: 'https' },
  ],
  ...over,
});

const FILES = (system = SYSTEM()) => ({
  '.lastro/profile.json': profileJson({ webApp: true, hasAuth: true, publicInternet: true, personalData: true }),
  '.lastro/system.json': JSON.stringify(system),
  'apps/web/.lastro/profile.json': profileJson({ webApp: true, publicInternet: true }),
  'apps/web/package.json': JSON.stringify({ name: 'web', version: '1.0.0' }),
  'apps/web/src/app.js': "fetch('https://cdn.exemplo.com/lib.js');\n",
  'apps/api/.lastro/profile.json': profileJson({ webApp: true, hasAuth: true, publicInternet: true, personalData: true }),
  'apps/api/package.json': JSON.stringify({ name: 'api', version: '1.0.0', dependencies: { express: '4.19.2', pg: '8.11.0' } }),
  'apps/api/server.js': "app.get('/health', (req, res) => res.send('ok'));\napp.delete('/api/x/:id', remove);\n",
});

test('system.json: validador aceita o sistema e recusa id repetido ou reservado, fluxo para componente desconhecido e repo em banco', () => {
  assert.deepEqual(validateSystem(SYSTEM()), []);
  const ruim = SYSTEM({
    components: [
      { id: 'user', name: 'Reservado', role: 'frontend' },
      { id: 'a', name: 'A', role: 'backend' },
      { id: 'a', name: 'A2', role: 'backend' },
      { id: 'db', name: 'Banco', role: 'database', repo: 'x' },
      { id: 'z', name: 'Z', role: 'robô' },
    ],
    flows: [{ from: 'a', to: 'fantasma', label: 'x' }, { from: 'a', to: 'db', label: 'ok', protocol: 'smtp' }],
  });
  const errs = validateSystem(ruim).join('\n');
  assert.match(errs, /repetido ou reservado/);
  assert.match(errs, /só componente com código/);
  assert.match(errs, /role: frontend/);
  assert.match(errs, /componente ou ator desconhecido/);
  assert.match(errs, /protocol/);
  assert.match(validateSystem({ ...SYSTEM(), extra: 1 }).join('\n'), /campo desconhecido "extra"/);
  assert.match(validateSystem({ ...SYSTEM(), components: [] }).join('\n'), /1 a 20/);
  assert.match(validateSystem({ ...SYSTEM(), flows: [{ from: 'user', to: 'web', label: 'x', surfaces: ['xyz'] }] }).join('\n'), /surfaces/);
});

test('repositórios: dentro da pasta é permitido; fora exige a opção; inexistente é acusado', () => {
  const root = makeProject(FILES(SYSTEM({ components: [
    { id: 'web', name: 'Frontend', role: 'frontend', repo: 'apps/web' },
    { id: 'api', name: 'API', role: 'backend', repo: '../fora-daqui' },
    { id: 'w2', name: 'Worker', role: 'worker', repo: 'apps/nao-existe' },
  ], flows: [] })));
  try {
    const sys = loadSystem(root);
    assert.equal(sys.ok, true);
    let repos = resolveRepos(root, sys.value);
    assert.equal(repos.get('apps/web').status, 'ok');
    assert.equal(repos.get('../fora-daqui').status, 'fora-do-repositorio');
    assert.equal(repos.get('apps/nao-existe').status, 'nao-encontrado');
    repos = resolveRepos(root, sys.value, { allowExternal: true });
    assert.equal(repos.get('../fora-daqui').status, 'nao-encontrado', 'com a opção, tenta ler (e a pasta não existe)');
  } finally { cleanup(root); }
});

test('motor: sistema declarado com vários repositórios gera componentes, fluxos com origem e o que foi descoberto e não declarado', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const a = r.threatModel.architecture;
    assert.equal(a.mode, 'declarado');
    assert.equal(a.name, 'Plataforma de teste');
    const ids = a.nodes.map((n) => n.id);
    for (const id of ['user', 'web', 'api', 'db', 'pay', 'dev', 'ci-0', 'ci-1']) assert.ok(ids.includes(id), `faltou o nó ${id}: ${ids}`);
    const declared = a.flows.filter((f) => f.source === 'declarado');
    assert.deepEqual(declared.map((f) => `${f.from}>${f.to}`), ['user>web', 'web>api', 'api>db', 'api>pay']);
    assert.ok(declared.every((f) => f.threats > 0 && f.controls > 0));
    assert.equal(declared[0].boundary, 'Internet para aplicação');
    assert.equal(declared[1].boundary, 'Entre componentes');
    assert.equal(declared[2].boundary, 'Aplicação para dados');
    assert.equal(declared[3].boundary, 'Aplicação para terceiros');
    // O frontend chama um host externo que ninguém declarou: aparece marcado, ligado ao componente certo.
    const x = a.nodes.find((n) => n.id === 'x-0' || n.id === 'x-1');
    assert.ok(x, 'serviço externo descoberto e não declarado');
    assert.equal(x.source, 'descoberto');
    assert.ok(a.flows.some((f) => f.source === 'descoberto' && f.to === x.id && f.from === 'web' && /cdn\.exemplo\.com/.test(f.note)));
    // O banco foi declarado para a API: não aparece um armazenamento "descoberto" para ela.
    assert.ok(!a.nodes.some((n) => /^d-/.test(n.id)), 'banco declarado não é duplicado como descoberto');
    assert.ok(a.nodes.find((n) => n.id === 'web').note.startsWith('repo: apps/web'));
    assert.deepEqual(a.warnings.filter((w) => /não foi lido/.test(w)), []);
    assert.equal(a.repos.length, 2);
  } finally { cleanup(root); }
});

test('motor: repositório fora da pasta não é lido sem --allow-external-repos, e o aviso diz isso', async () => {
  const root = makeProject(FILES(SYSTEM({ components: [
    { id: 'web', name: 'Frontend', role: 'frontend', repo: 'apps/web', exposure: 'internet' },
    { id: 'api', name: 'API', role: 'backend', repo: '../vizinho', exposure: 'internet' },
  ], flows: [{ from: 'user', to: 'web', label: 'Navegação' }, { from: 'user', to: 'api', label: 'API' }] })));
  try {
    const r = await runCheck({ root, now: NOW });
    const a = r.threatModel.architecture;
    assert.ok(a.warnings.some((w) => /"\.\.\/vizinho" não foi lido \(fora do repositorio\)/.test(w)), a.warnings.join('|'));
    assert.match(a.nodes.find((n) => n.id === 'api').note, /fora do analisado|não lido/);
    const f = a.flows.find((x) => x.from === 'user' && x.to === 'api');
    assert.match(f.note, /repositório principal/, 'sem repositório lido, o fluxo avisa que usou as ameaças do principal');
  } finally { cleanup(root); }
});

test('motor: sem fluxos declarados o kit infere o básico pelos papéis e marca como inferido', async () => {
  const root = makeProject(FILES(SYSTEM({ flows: undefined })));
  try {
    const r = await runCheck({ root, now: NOW });
    const a = r.threatModel.architecture;
    const inf = a.flows.filter((f) => f.source === 'inferido').map((f) => `${f.from}>${f.to}`);
    for (const e of ['user>web', 'web>api', 'api>db', 'api>pay']) assert.ok(inf.includes(e), `faltou ${e}: ${inf}`);
  } finally { cleanup(root); }
});

test('motor: system.json inválido vira aviso e o desenho automático continua', async () => {
  const root = makeProject({ ...FILES(), '.lastro/system.json': JSON.stringify({ schemaVersion: 1, name: 'x', components: [{ id: 'A', name: 'A', role: 'x' }] }) });
  try {
    const r = await runCheck({ root, now: NOW });
    assert.ok(r.warnings.some((w) => /system\.json inválido/.test(w)));
    assert.equal(r.threatModel.architecture.mode, 'automático');
  } finally { cleanup(root); }
});

test('motor: repositório sem perfil próprio é lido, mas o aviso explica de onde vêm as ameaças', async () => {
  const f = FILES();
  delete f['apps/api/.lastro/profile.json'];
  const root = makeProject(f);
  try {
    const r = await runCheck({ root, now: NOW });
    assert.ok(r.warnings.some((w) => /apps\/api" não tem \.lastro\/profile\.json/.test(w)));
    assert.equal(r.threatModel.architecture.mode, 'declarado');
  } finally { cleanup(root); }
});

test('desenho declarado: Mermaid e SVG com zonas, ids seguros, texto escapado e relatórios com origem e aviso', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const a = r.threatModel.architecture;
    const m = toMermaid(a);
    for (const s of ['subgraph internet', 'subgraph app', 'subgraph dados', 'subgraph entrega', 'ci_0["', '-->|']) assert.ok(m.code.includes(s), `faltou: ${s}`);
    assert.ok(!/ci-0/.test(m.code), 'hífen do id vira sublinhado no Mermaid');
    assert.ok(m.code.includes('(descoberto)'));
    const svg = toSvg(a, esc);
    assert.ok(svg.includes('arch-desc'), 'componente descoberto tem borda própria');
    assert.ok(/viewBox="0 0 1170 \d+"/.test(svg));
    assert.ok(!/<script|href=|src=/i.test(svg));
    const md = formatMarkdown(r);
    for (const s of ['Desenho **declarado**', '| Fluxo | Fronteira | Origem |', 'declarado', 'descoberto']) assert.ok(md.includes(s), `faltou no Markdown: ${s}`);
    const html = formatHtml(r);
    for (const s of ['Desenho <strong>declarado</strong>', 'Borda tracejada', '<th scope="col">Origem</th>']) assert.ok(html.includes(s), `faltou no HTML: ${s}`);
    assert.deepEqual(badHrefs(html), []);
  } finally { cleanup(root); }
});

test('desenho: nomes maliciosos no system.json não quebram o Mermaid nem o SVG', () => {
  const arch = {
    mode: 'declarado', name: 'x', warnings: [], repos: [],
    nodes: [{ id: 'a-b', label: 'x"]\n<script>alert(1)</script>', zone: 'app', source: 'declarado', note: '"><img src=x>' }, { id: 'user', label: 'U', zone: 'internet', source: 'declarado', note: '' }],
    flows: [{ id: 'F1', from: 'user', to: 'a-b', label: '"|]x<b>', boundary: 'b', threats: 1, exposed: 1, source: 'declarado' }],
  };
  const m = toMermaid(arch).code;
  assert.ok(!m.includes('<script>') && !m.includes('<b>'));
  assert.ok(m.includes('a_b['));
  const svg = toSvg(arch, esc);
  assert.ok(!svg.includes('<script>') && !svg.includes('<img') && !svg.includes('<b>'));
  assert.ok(svg.includes('&lt;script&gt;') || svg.includes('script'));
});
