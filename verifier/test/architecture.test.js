'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildArchitecture, toMermaid, toSvg } = require('../src/architecture');
const { runCheck } = require('../src/engine');
const { formatMarkdown } = require('../src/report');
const { formatHtml } = require('../src/html');
const { makeProject, profileJson, cleanup, badHrefs } = require('./helpers');

const NOW = new Date('2026-11-12T12:00:00Z');
const FILES = (flags = {}) => ({
  '.lastro/profile.json': profileJson({ webApp: true, hasAuth: true, personalData: true, publicInternet: true, uploads: true, realtime: true, aiCodingAgents: true, ...flags }),
  'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { express: '4.19.2', pg: '8.11.0', multer: '1.4.5', ws: '8.0.0' } }),
  'server.js': [
    "app.get('/health', (req, res) => res.send('ok'));",
    "app.delete('/api/clientes/:id', remove);",
    "fetch('https://api.exemplo.com.br/v1/dados');",
    '',
  ].join('\n'),
});
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

test('arquitetura: um app completo gera os fluxos de internet, dados, terceiros, upload, tempo real, CI e agente', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const a = r.threatModel.architecture;
    assert.deepEqual(a.flows.map((f) => f.id), ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8']);
    const ids = a.nodes.map((n) => n.id).sort();
    assert.deepEqual(ids, ['A', 'D', 'Dev', 'G', 'P', 'U', 'X']);
    const f1 = a.flows[0];
    assert.equal(f1.from, 'U');
    assert.equal(f1.to, 'A');
    assert.ok(f1.threats > 0 && f1.controls > 0);
    assert.equal(f1.verified + f1.failed + f1.unverified, f1.controls);
    assert.match(f1.note, /sem autenticação vista/);
    assert.match(a.flows.find((f) => f.id === 'F5').note, /api\.exemplo\.com\.br/);
    assert.ok(a.nodes.find((n) => n.id === 'D').label.includes('PostgreSQL'));
  } finally { cleanup(root); }
});

test('arquitetura: sem web, upload, tempo real, dados e agente, só a cadeia de entrega aparece', async () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({}), 'a.js': 'const x = 1;\n' });
  try {
    const r = await runCheck({ root, now: NOW });
    const a = r.threatModel.architecture;
    assert.deepEqual(a.flows.map((f) => f.id), ['F6', 'F7']);
    assert.ok(!a.nodes.some((n) => ['U', 'X', 'D', 'G'].includes(n.id)));
  } finally { cleanup(root); }
});

test('Mermaid: zonas, nós, fluxos com o número de ameaças, e rótulos sem aspas ou colchetes que quebrem o diagrama', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const m = toMermaid(r.threatModel.architecture);
    assert.ok(m.code.startsWith('flowchart LR'));
    for (const s of ['subgraph internet', 'subgraph app', 'subgraph dados', 'subgraph entrega', 'U -->|', 'A -->|', 'Dev -->|', 'G -->|']) assert.ok(m.code.includes(s), `faltou: ${s}`);
    assert.match(m.code, /F1: \d+ ameaça\(s\), \d+ exposta\(s\)/);
    const malicioso = { nodes: [{ id: 'U', label: 'a"]\nx[<script>' }, { id: 'A', label: 'App' }], flows: [{ id: 'F1', from: 'U', to: 'A', label: 'x"|y]', boundary: 'b', threats: 1, exposed: 1 }] };
    const mm = toMermaid(malicioso).code;
    assert.ok(!/[<>\[\]{}`\\]/.test(mm.replace(/\["[^"]*"\]/g, '').replace(/\|"[^"]*"\|/g, '').replace(/-->/g, '')), mm);
    assert.ok(!mm.includes('<script>'));
    assert.ok(m.exposedFlows.length > 0);
  } finally { cleanup(root); }
});

test('SVG: acessível, sem script e sem recurso externo, com texto escapado e fluxo exposto destacado', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const svg = toSvg(r.threatModel.architecture, esc);
    assert.ok(svg.startsWith('<svg'));
    assert.ok(svg.includes('role="img"') && svg.includes('aria-label='));
    assert.ok(!/<script|<image|<foreignObject|href=|src=/i.test(svg));
    assert.ok(svg.includes('arch-exposto'));
    const ruim = { nodes: [{ id: 'U', label: '<script>alert(1)</script>' }, { id: 'A', label: 'App' }], flows: [{ id: 'F1', from: 'U', to: 'A', label: '"><b>', boundary: 'b', threats: 1, exposed: 0 }] };
    const s2 = toSvg(ruim, esc);
    assert.ok(!s2.includes('<script>') && !s2.includes('<b>'));
    assert.ok(s2.includes('&lt;script&gt;'));
  } finally { cleanup(root); }
});

test('relatórios: Markdown traz o bloco Mermaid e a tabela de fluxos; HTML traz o SVG e a tabela, sem link externo', async () => {
  const root = makeProject(FILES());
  try {
    const r = await runCheck({ root, now: NOW });
    const md = formatMarkdown(r);
    for (const s of ['### Arquitetura: fluxo de dados e fronteiras de confiança', '```mermaid', 'flowchart LR', '| Fluxo | Fronteira |', 'Ele não inventa a arquitetura']) assert.ok(md.includes(s), `faltou no Markdown: ${s}`);
    const html = formatHtml(r);
    for (const s of ['Arquitetura: fluxo de dados e fronteiras de confiança', '<svg', 'class="arch"', 'Fluxos, ameaças e controles exigidos', 'Linha vermelha']) assert.ok(html.includes(s), `faltou no HTML: ${s}`);
    assert.ok(!/<script|<link|<iframe|<img/i.test(html));
    assert.deepEqual(badHrefs(html), []);
    assert.ok(!/\bsrc=/i.test(html));
  } finally { cleanup(root); }
});

test('arquitetura: sem modelo de ameaças com fluxos, o relatório não quebra', () => {
  const a = buildArchitecture({ model: { discovery: { routes: { total: 0, byAuth: {}, examples: [] }, stores: [], externalHosts: [], uploads: [], realtime: [], workflows: 0 }, threats: [] }, profile: { flags: {} }, controls: [] });
  assert.deepEqual(a.flows, []);
  assert.equal(toMermaid(a).code, 'flowchart LR');
});

test('SVG novo: componentes mostram módulos, defesas e tabelas; fluxos viram números; nada de texto de fluxo solto no desenho', async () => {
  const files = FILES();
  files['package.json'] = JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { express: '4.19.2', pg: '8.11.0', multer: '1.4.5', ws: '8.0.0', helmet: '8.0.0' } });
  files['src/rotas.js'] = "router.get('/', listar);\nrouter.post('/', criar);\n";
  files['server.js'] = `${files['server.js']}const rotas = require('./src/rotas');\napp.use('/api/pedidos', exigirSessao, rotas);\n`;
  files['migrations/001.sql'] = 'CREATE TABLE usuarios (id int, email text, senha_hash text);\n';
  const root = makeProject(files);
  try {
    const r = await runCheck({ root, now: NOW });
    const a = r.threatModel.architecture;
    const app = a.nodes.find((n) => n.id === 'A');
    assert.ok(app.modules.some((m) => m.prefix === '/api/pedidos' && m.protected === 2));
    assert.ok(app.defenses.some((d) => d.id === 'headers'));
    assert.ok(a.nodes.find((n) => n.id === 'D').tables.some((t) => t.name === 'usuarios' && t.categories.includes('credencial')));
    const svg = toSvg(a, esc);
    for (const s of ['/api/pedidos', 'Módulos de rotas', 'Defesas vistas no código', 'usuarios [', 'class="arch-badge']) assert.ok(svg.includes(s), `faltou no SVG: ${s}`);
    for (const f of a.flows) assert.ok(svg.includes(`class="arch-badge-txt">${f.id}</text>`), `fluxo ${f.id} sem número`);
    assert.ok(!svg.includes('arch-rotulo'), 'rótulos de fluxo soltos no meio da linha não existem mais');
    if (a.flows.some((f) => f.exposed > 0)) assert.ok(svg.includes('arch-badge-bad'));
    const html = formatHtml(r);
    for (const s of ['Componentes descobertos no código', 'Módulos de rotas descobertos', 'Tabelas do banco', 'Os números nas linhas']) assert.ok(html.includes(s), `faltou no HTML: ${s}`);
  } finally { cleanup(root); }
});

test('SVG novo: nome comprido quebra em linhas e texto vindo do código é escapado nos detalhes', () => {
  const a = {
    nodes: [
      { id: 'U', label: 'Usuário' },
      { id: 'A', label: 'Aplicação com um nome bem comprido que precisaria ser cortado no desenho antigo', modules: [{ prefix: '/api/<b>x</b>', routes: 3, methods: ['GET'], protected: 1, public: 0, notSeen: 2, files: [] }], defenses: [{ id: 'h', label: '<i>y</i>', evidence: 'z' }] },
    ],
    flows: [{ id: 'F1', from: 'U', to: 'A', label: 'web', boundary: 'b', threats: 2, exposed: 1, source: 'descoberto' }],
  };
  const svg = toSvg(a, esc);
  assert.ok(!svg.includes('<b>') && !svg.includes('<i>'));
  assert.ok(svg.includes('&lt;b&gt;x&lt;/b&gt;'));
  assert.ok(svg.includes('arch-det-warn'), 'módulo com rota sem proteção vista fica destacado');
  const titleLines = (svg.match(/class="arch-notexto">/g) || []).length;
  assert.ok(titleLines >= 3, 'o título comprido foi quebrado em mais de uma linha');
  assert.ok(!svg.includes('…') || svg.indexOf('…') > 0);
});

test('SVG novo: números de fluxos paralelos (mesmo par de caixas) nunca se sobrepõem', () => {
  const a = {
    nodes: [{ id: 'U', label: 'Usuário' }, { id: 'A', label: 'App' }],
    flows: ['F1', 'F2', 'F3'].map((id) => ({ id, from: 'U', to: 'A', label: id, boundary: 'b', threats: 1, exposed: 0, source: 'descoberto' })),
  };
  const svg = toSvg(a, esc);
  const ys = [...svg.matchAll(/<circle cx="(\d+)" cy="(\d+)" r="12"/g)].map((m) => Number(m[2])).sort((x, y) => x - y);
  assert.equal(ys.length, 3);
  for (let i = 1; i < ys.length; i += 1) assert.ok(ys[i] - ys[i - 1] >= 26, `números a ${ys[i] - ys[i - 1]}px um do outro`);
});
