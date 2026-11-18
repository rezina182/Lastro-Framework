'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const PM = require('../src/proofmap');
const { detectTech } = require('../src/tech');
const { loadCatalog } = require('../src/catalog');
const { runCheck } = require('../src/engine');
const { validateStatus } = require('../src/schema');
const { buildPlaybook } = require('../src/playbook');
const { makeProject, profileJson, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const NOW = new Date('2026-11-17T12:00:00Z');
const ALL = { webApp: true, hasAuth: true, anonymousUsers: true, realtime: true, uploads: true, personalData: true, minorsData: true, thirdPartyAssets: true, aiCodingAgents: true, publicInternet: true, federatedLogin: true, tokenAuth: true, oauthProvider: true };

test('mapa de prova: todo controle manual do catálogo tem um caminho, uma vez só, e nada aponta para controle inexistente ou automático', () => {
  const cat = loadCatalog();
  const manual = cat.controls.filter((c) => c.check.type === 'manual').map((c) => c.id).sort();
  const mapped = Object.values(PM.ROUTE).flat();
  assert.equal(new Set(mapped).size, mapped.length, 'id repetido no mapa');
  assert.deepEqual([...mapped].sort(), manual, 'o mapa precisa cobrir exatamente os controles manuais');
  for (const id of Object.keys(PM.NEEDS_TECH)) assert.ok(manual.includes(id), `${id} em NEEDS_TECH não é manual`);
});

test('tecnologia: dependência ou código marcam presença; ausência vira "provavelmente não se aplica" só para o controle ligado a ela', () => {
  const root = makeProject({
    'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { graphql: '16.8.0', express: '4.19.2' } }),
    'server.js': "const pc = new RTCPeerConnection();\napp.get('/api/a', h);\n",
  });
  try {
    const ctx = { files: ['package.json', 'server.js'], read: (f) => fs.readFileSync(path.join(root, f), 'utf8') };
    const t = detectTech(ctx, ['server.js'], new Set(['graphql', 'express']));
    assert.equal(t.graphql.present, true);
    assert.equal(t.webrtc.present, true);
    assert.equal(t.webrtc.evidence, 'server.js');
    assert.equal(t.ldap.present, false);
    const disc = { tech: t, defenses: [{ id: 'password', label: 'Hash de senha forte', evidence: 'dependência bcrypt' }] };
    assert.equal(PM.proofFor({ id: 'WEB-020' }, disc).likelyNA, null, 'tem GraphQL: se aplica');
    assert.match(PM.proofFor({ id: 'CORE-033' }, disc).likelyNA, /nenhum sinal de LDAP ou XPath/);
    assert.equal(PM.proofFor({ id: 'RT-005' }, disc).likelyNA, null);
    const a2 = PM.proofFor({ id: 'AUTH-002' }, disc);
    assert.equal(a2.via, 'codigo');
    assert.deepEqual(a2.hints, ['Hash de senha forte (dependência bcrypt)']);
    assert.equal(PM.proofFor({ id: 'AUTH-027' }, disc).runsToday, true);
    assert.equal(PM.proofFor({ id: 'WEB-020' }, {}).likelyNA, null, 'sem descoberta não há palpite');
  } finally { cleanup(root); }
});

test('lacunas: explica o porquê com números, separa os automáticos sem --url e o tipo de falha', async () => {
  const root = makeProject({ '.lastro/profile.json': profileJson(ALL), 'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { express: '4.19.2', bcrypt: '5.1.1' } }) });
  try {
    const r = await runCheck({ root, now: NOW });
    const g = PM.analyzeGaps(r);
    assert.ok(g.manualOpen > 50 && g.attested === 0);
    assert.ok(g.likelyNA.some((x) => x.id === 'WEB-020'), 'sem GraphQL');
    assert.ok(g.automatedNotRun.some((x) => x.id === 'WEB-008'), 'sondas HTTP sem --url');
    assert.ok(g.withHints.some((x) => x.id === 'AUTH-002' && /bcrypt/.test(x.hints[0])));
    const sum = Object.values(g.byVia).reduce((a, b) => a + b, 0);
    assert.equal(sum + g.likelyNA.length, g.manualOpen);
    const why = PM.explainGaps(g);
    assert.match(why[0], new RegExp(`^${g.manualOpen} de ${g.applicable} controles aplicáveis dependem`));
    assert.ok(why.some((l) => /provavelmente não se aplicam/.test(l)));
    assert.ok(why.some((l) => /não rodaram .*--url/.test(l)));
    const txt = PM.formatGaps(g, { now: NOW, name: 'x' });
    assert.match(txt, /"state": "not_applicable"/);
    assert.match(txt, /Pedem sonda com duas contas de teste/);
  } finally { cleanup(root); }
});

test('não se aplica atestado: exige justificativa, tira o controle da conta e do playbook, e vale com prazo', async () => {
  const base = { state: 'not_applicable', attestedBy: 'Fulana', collectedAt: '2026-11-01', expiresAt: '2027-05-01' };
  assert.match(validateStatus({ schemaVersion: 1, attestations: { 'WEB-020': base } }).join(' '), /exige note/);
  assert.deepEqual(validateStatus({ schemaVersion: 1, attestations: { 'WEB-020': { ...base, note: 'A aplicação não usa GraphQL em nenhum serviço.' } } }), []);
  const status = { schemaVersion: 1, attestations: { 'WEB-020': { ...base, note: 'A aplicação não usa GraphQL em nenhum serviço.' } } };
  const root = makeProject({ '.lastro/profile.json': profileJson(ALL), '.lastro/status.json': JSON.stringify(status) });
  const sem = makeProject({ '.lastro/profile.json': profileJson(ALL) });
  try {
    const r = await runCheck({ root, now: NOW });
    const c = r.controls.find((x) => x.id === 'WEB-020');
    assert.equal(c.state, 'not_applicable');
    assert.match(c.notes[0], /Não se aplica, segundo Fulana/);
    const r0 = await runCheck({ root: sem, now: NOW });
    assert.equal(r.score.applicableControls, r0.score.applicableControls - 1);
    assert.ok(!buildPlaybook(r, loadCatalog(), { now: NOW }).items.some((i) => i.id === 'WEB-020'));
    const vencido = await runCheck({ root, now: new Date('2027-06-01T00:00:00Z') });
    assert.equal(vencido.controls.find((x) => x.id === 'WEB-020').state, 'unverified', 'vencida, volta a contar');
  } finally { cleanup(root); cleanup(sem); }
});

test('lastro gaps: texto e --json, sem gravar nada', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson(ALL) });
  try {
    const before = fs.readdirSync(path.join(root, '.lastro')).sort();
    const t = spawnSync(process.execPath, [CLI, 'gaps', '--root', root], { encoding: 'utf8' });
    assert.equal(t.status, 0, t.stderr);
    assert.match(t.stdout, /por que a nota está assim/);
    const j = spawnSync(process.execPath, [CLI, 'gaps', '--root', root, '--json'], { encoding: 'utf8' });
    assert.equal(j.status, 0, j.stderr);
    assert.ok(JSON.parse(j.stdout).manualOpen > 0);
    assert.deepEqual(fs.readdirSync(path.join(root, '.lastro')).sort(), before);
  } finally { cleanup(root); }
});
