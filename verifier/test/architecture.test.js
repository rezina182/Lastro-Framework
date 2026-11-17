'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildArchitecture, toMermaid, toSvg } = require('../src/architecture');
const { runCheck } = require('../src/engine');
const { formatMarkdown } = require('../src/report');
const { formatHtml } = require('../src/html');
const { makeProject, profileJson, cleanup } = require('./helpers');

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
    assert.ok(!/(?:src|href)=["'](?!#)/i.test(html));
  } finally { cleanup(root); }
});

test('arquitetura: sem modelo de ameaças com fluxos, o relatório não quebra', () => {
  const a = buildArchitecture({ model: { discovery: { routes: { total: 0, byAuth: {}, examples: [] }, stores: [], externalHosts: [], uploads: [], realtime: [], workflows: 0 }, threats: [] }, profile: { flags: {} }, controls: [] });
  assert.deepEqual(a.flows, []);
  assert.equal(toMermaid(a).code, 'flowchart LR');
});
