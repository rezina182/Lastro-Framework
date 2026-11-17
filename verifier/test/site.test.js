'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const H = require('../src/history');
const { buildSite, writeSite, evolutionSvg, attestationAlerts, PAGE_NAMES, MARKER } = require('../src/site');
const { runCheck } = require('../src/engine');
const { buildPlaybook } = require('../src/playbook');
const { loadCatalog } = require('../src/catalog');
const { makeProject, profileJson, cleanup, badHrefs } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const cli = (root, ...args) => spawnSync(process.execPath, [CLI, ...args, '--root', root], { encoding: 'utf8' });
const NOW = new Date('2026-11-17T12:00:00Z');
const project = (files = {}) => makeProject({ '.lastro/profile.json': profileJson({}), 'src/a.js': 'const o = { rejectUnauthorized: false };\n', ...files });

test('história: o registro guarda só números, IDs e estados (nada de caminho, mensagem nem URL)', async () => {
  const root = project();
  try {
    const rep = await runCheck({ root, now: NOW });
    const s = H.snapshot(rep);
    assert.deepEqual(H.validateSnapshot(s), []);
    assert.equal(s.controls['CORE-007'], 'failed');
    const text = JSON.stringify(s);
    assert.doesNotMatch(text, /rejectUnauthorized|src\/a\.js|https?:|lastro-test-/);
    assert.ok(Buffer.byteLength(text) < 8000, 'registro compacto');
  } finally { cleanup(root); }
});

test('história: grava sem sobrescrever, lê em ordem, ignora registro inválido com aviso e calcula o que mudou', async () => {
  const root = project();
  try {
    const s1 = H.snapshot(await runCheck({ root, now: NOW }));
    const f1 = H.writeSnapshot(root, s1);
    const f2 = H.writeSnapshot(root, s1);
    assert.notEqual(f1, f2, 'mesmo horário: segundo nome ganha sufixo');
    fs.writeFileSync(path.join(root, 'src', 'a.js'), 'const x = 1;\n');
    const s2 = H.snapshot(await runCheck({ root, now: new Date('2026-11-18T12:00:00Z') }));
    H.writeSnapshot(root, s2);
    fs.writeFileSync(path.join(root, H.DIR, '20260101T000000Z.json'), '{"schemaVersion":1}');
    fs.writeFileSync(path.join(root, H.DIR, 'nome-qualquer.json'), '{}');
    const { items, warnings } = H.loadHistory(root);
    assert.equal(items.length, 3);
    assert.equal(items[2].generatedAt, s2.generatedAt);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /20260101T000000Z\.json ignorado/);
    const d = H.diff(items[0], items[2]);
    assert.deepEqual(d.improved.map((x) => `${x.id}:${x.from}->${x.to}`), ['CORE-007:failed->verified']);
    assert.deepEqual(d.worsened, []);
    assert.deepEqual(H.diff(null, s2), { improved: [], worsened: [], added: [], removed: [] });
    assert.throws(() => H.writeSnapshot(root, { ...s2, level: 9 }), /registro inválido/);
  } finally { cleanup(root); }
});

test('portal: quatro páginas sem script, com CSP, links só para as próprias páginas ou fontes oficiais, e texto escapado', async () => {
  const root = project({ '.lastro/profile.json': profileJson({}, { name: 'App <b>x</b>' }) });
  try {
    const report = await runCheck({ root, now: NOW });
    const current = H.snapshot(report);
    // Registro antigo em que o CORE-007 estava verificado: a página de histórico precisa mostrar que ele piorou.
    const older = { ...current, generatedAt: '2026-11-10T12:00:00.000Z', provenPct: 1, failedPct: 50, controls: { ...current.controls, 'CORE-007': 'verified' } };
    const pages = buildSite({ report, history: [older], current, playbook: buildPlaybook(report, loadCatalog(), {}), now: NOW });
    assert.deepEqual(Object.keys(pages).sort(), [...PAGE_NAMES].sort());
    for (const [name, html] of Object.entries(pages)) {
      // Tag <script>, atributo de evento (onclick=...) dentro de uma tag, ou javascript: num href/src. O catálogo cita
      // "javascript:alert(1)" como texto de teste, e esse texto sai escapado: não é link.
      assert.doesNotMatch(html, /<script|<[^>]*\son[a-z]+\s*=|<[^>]*\b(?:href|src)\s*=\s*["']?\s*javascript:/i, name);
      assert.match(html, /Content-Security-Policy" content="default-src 'none'/, name);
      const bad = badHrefs(html).filter((u) => !PAGE_NAMES.has(u));
      assert.deepEqual(bad, [], `${name}: link fora da lista`);
      assert.ok(!html.includes('<b>x</b>'), `${name}: nome do perfil escapado`);
      for (const other of PAGE_NAMES) if (other !== name) assert.ok(html.includes(`href="${other}"`), `${name}: navega para ${other}`);
    }
    const idx = pages['index.html'];
    for (const re of [/Para quem desenvolve/, /Para o time de segurança/, /\[CORE-007\]|CORE-007/, /<svg role="img"/, /Atestações que vencem/, /ponto\(s\) desde o último registro/]) assert.match(idx, re);
    assert.match(pages['historico.html'], /<td>piorou<\/td><td>CORE-007<\/td><td>verificado<\/td><td>falhando<\/td>/);
  } finally { cleanup(root); }
});

test('portal: gráfico pede dois pontos, e alerta de atestação que vence em 30 dias', () => {
  assert.match(evolutionSvg([{ generatedAt: '2026-11-17T00:00:00Z', provenPct: 10, failedPct: 5 }]), /a partir de dois registros/);
  const svg = evolutionSvg([{ generatedAt: '2026-11-10T00:00:00Z', provenPct: 10, failedPct: 5 }, { generatedAt: '2026-11-17T00:00:00Z', provenPct: 999, failedPct: -3 }]);
  assert.match(svg, /<polyline class="l-ok"/);
  assert.doesNotMatch(svg, /NaN|999/);
  const rep = { controls: [
    { id: 'AUTH-027', title: 't', state: 'verified', evidence: { source: 'manual-attestation', attestedBy: 'Fulana', expiresAt: '2026-12-01' }, notes: [] },
    { id: 'AUTH-028', title: 't', state: 'verified', evidence: { source: 'manual-attestation', attestedBy: 'Fulana', expiresAt: '2027-06-01' }, notes: [] },
    { id: 'WEB-013', title: 't', state: 'unverified', evidence: null, notes: ['Atestação expirada.'] },
  ] };
  const al = attestationAlerts(rep, NOW);
  assert.deepEqual(al.soon.map((a) => a.id), ['AUTH-027']);
  assert.deepEqual(al.expired.map((a) => a.id), ['WEB-013']);
});

test('portal: só grava em pasta nova, vazia ou que já seja portal; nunca mistura com outros arquivos', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'lastro-site-'));
  try {
    const pages = { 'index.html': '<p>x</p>' };
    const nova = path.join(base, 'nova');
    writeSite(nova, pages);
    assert.ok(fs.existsSync(path.join(nova, MARKER)));
    writeSite(nova, pages);
    const alheia = path.join(base, 'alheia');
    fs.mkdirSync(alheia);
    fs.writeFileSync(path.join(alheia, 'meu.txt'), 'meu');
    assert.throws(() => writeSite(alheia, pages), /não está vazia e não é um portal/);
    fs.writeFileSync(path.join(nova, 'extra.txt'), 'x');
    assert.throws(() => writeSite(nova, pages), /arquivos que não são do portal/);
    assert.throws(() => writeSite(path.join(base, 'p2'), { 'outra.html': 'x' }), /página desconhecida/);
    assert.equal(fs.readFileSync(path.join(alheia, 'meu.txt'), 'utf8'), 'meu');
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('CLI: history sem --write não grava; com --write grava; site exige --out e respeita --redact', () => {
  const root = project({ '.lastro/profile.json': profileJson({}, { name: 'Empresa Secreta' }) });
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'lastro-site-cli-'));
  fs.rmSync(out, { recursive: true, force: true });
  try {
    let r = cli(root, 'history');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Rode com --write/);
    assert.ok(!fs.existsSync(path.join(root, H.DIR)));
    r = cli(root, 'history', '--write');
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.readdirSync(path.join(root, H.DIR)).length, 1);
    assert.equal(cli(root, 'site').status, 3);
    r = cli(root, 'site', '--out', out, '--redact', 'Secreta');
    assert.equal(r.status, 0, r.stderr);
    for (const p of PAGE_NAMES) {
      const html = fs.readFileSync(path.join(out, p), 'utf8');
      assert.ok(!/Secreta/.test(html), `${p}: termo redigido`);
    }
  } finally { cleanup(root); fs.rmSync(out, { recursive: true, force: true }); }
});
