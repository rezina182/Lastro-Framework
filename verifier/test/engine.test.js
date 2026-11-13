'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { runCheck, ConfigError } = require('../src/engine');
const { fingerprint } = require('../src/util');
const { makeProject, profileJson, cleanup } = require('./helpers');

const NOW = new Date('2026-11-12T12:00:00Z');
const run = (root, extra = {}) => runCheck({ root, now: NOW, ...extra });
const byId = (rep, id) => rep.controls.find((c) => c.id === id);

const BASE = (flags = {}, extra = {}) => ({ '.lastro/profile.json': profileJson(flags, extra), '.gitignore': '.env\n' });

test('perfil ausente ou inválido é erro de configuração', async () => {
  const root = makeProject({});
  try {
    await assert.rejects(run(root), ConfigError);
    const bad = makeProject({ '.lastro/profile.json': '{"schemaVersion":1,"name":"x","flags":{"webApp":"sim"}}' });
    try {
      await assert.rejects(run(bad), ConfigError);
    } finally { cleanup(bad); }
  } finally { cleanup(root); }
});

test('controle de pacote desligado no perfil não se aplica', async () => {
  const root = makeProject(BASE());
  try {
    const rep = await run(root);
    assert.equal(byId(rep, 'WEB-001'), undefined);
    assert.ok(rep.summary.notApplicable >= 30);
  } finally { cleanup(root); }
});

test('sem CI, o portão falha e bloqueia por achados novos de severidade alta', async () => {
  const root = makeProject(BASE());
  try {
    const rep = await run(root);
    assert.equal(rep.verdict, 'fail');
    assert.ok(byId(rep, 'CORE-003').findings[0].blocking);
    assert.ok(rep.summary.blocking >= 2);
  } finally { cleanup(root); }
});

const GOOD_CI = [
  'name: ci', 'on: push', 'permissions:', '  contents: read', 'jobs:', '  v:', '    steps:',
  '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
  '      - run: npm audit --audit-level=high', '      - run: ./gitleaks git .', '',
].join('\n');
const TM = 'Última revisão: 2026-10-20\n';
const SEC = `# Segurança\nPara reportar uma vulnerabilidade, escreva ao responsável. ${'x'.repeat(200)}\n`;

function compliantFiles(extra = {}) {
  return {
    ...BASE(),
    '.github/workflows/ci.yml': GOOD_CI,
    '.github/dependabot.yml': 'version: 2\n',
    'THREAT-MODEL.md': TM,
    'SECURITY.md': SEC,
    ...extra,
  };
}

test('projeto em ordem, mas com controles manuais sem atestação, dá "incompleto" e não "aprovado"', async () => {
  const root = makeProject(compliantFiles());
  try {
    const rep = await run(root);
    assert.equal(rep.summary.blocking, 0);
    assert.equal(rep.verdict, 'incomplete');
    assert.equal(byId(rep, 'CORE-014').state, 'unverified');
  } finally { cleanup(root); }
});

function attestAll(root, rep, over = {}) {
  const attestations = {};
  for (const c of rep.controls) {
    if (c.state === 'unverified') {
      attestations[c.id] = { state: 'verified', attestedBy: 'Fulano', collectedAt: '2026-11-01', expiresAt: '2027-05-01', ...over };
    }
  }
  return JSON.stringify({ schemaVersion: 1, attestations });
}

test('com atestações válidas de todos os manuais, o veredito é "aprovado"', async () => {
  const root = makeProject(compliantFiles());
  try {
    const first = await run(root);
    const fs = require('node:fs');
    fs.writeFileSync(path.join(root, '.lastro', 'status.json'), attestAll(root, first));
    const rep = await run(root);
    assert.equal(rep.verdict, 'pass');
    assert.equal(byId(rep, 'CORE-014').state, 'verified');
    assert.equal(byId(rep, 'CORE-014').evidence.source, 'manual-attestation');
  } finally { cleanup(root); }
});

test('atestação expirada, no futuro ou com validade acima de 366 dias não verifica', async () => {
  const root = makeProject(compliantFiles());
  const fs = require('node:fs');
  try {
    const first = await run(root);
    for (const over of [{ expiresAt: '2026-11-01' }, { collectedAt: '2026-12-30', expiresAt: '2027-03-01' }, { collectedAt: '2025-01-01', expiresAt: '2027-12-01' }]) {
      fs.writeFileSync(path.join(root, '.lastro', 'status.json'), attestAll(root, first, over));
      const rep = await run(root);
      assert.equal(byId(rep, 'CORE-014').state, 'unverified', JSON.stringify(over));
      assert.equal(rep.verdict, 'incomplete');
    }
  } finally { cleanup(root); }
});

test('atestação nunca verifica um controle automático', async () => {
  const root = makeProject(BASE({}, {}));
  const fs = require('node:fs');
  try {
    fs.writeFileSync(path.join(root, '.lastro', 'status.json'), JSON.stringify({
      schemaVersion: 1,
      attestations: { 'CORE-003': { state: 'verified', attestedBy: 'Fulano', collectedAt: '2026-11-01', expiresAt: '2027-05-01' } },
    }));
    const rep = await run(root);
    assert.equal(byId(rep, 'CORE-003').state, 'failed');
    assert.ok(rep.warnings.some((w) => w.includes('CORE-003')));
    assert.equal(rep.verdict, 'fail');
  } finally { cleanup(root); }
});

test('baseline: achado conhecido não bloqueia, achado novo bloqueia', async () => {
  const root = makeProject(compliantFiles({ 'src/a.js': 'const x = eval(y);\n' }));
  const fs = require('node:fs');
  try {
    const rep = await run(root);
    const f = byId(rep, 'CORE-008').findings[0];
    assert.ok(f.blocking);
    fs.writeFileSync(path.join(root, '.lastro', 'baseline.json'), JSON.stringify({ schemaVersion: 1, generatedAt: '2026-11-12', fingerprints: [f.fingerprint] }));
    const withBase = await run(root);
    assert.equal(withBase.summary.blocking, 0);
    assert.equal(withBase.summary.debt, 1);
    assert.equal(byId(withBase, 'CORE-008').state, 'failed');
    fs.writeFileSync(path.join(root, 'src', 'b.js'), 'const z = eval(w);\n');
    const novo = await run(root);
    assert.equal(novo.summary.blocking, 1);
    assert.equal(novo.verdict, 'fail');
  } finally { cleanup(root); }
});

function riskFor(fp, over = {}) {
  return JSON.stringify({
    schemaVersion: 1, id: 'RISK-0001', control: 'CORE-008', fingerprints: [fp], owner: 'Fulano', approvedBy: 'Beltrana',
    justification: 'Entrada vem de fonte confiável interna.', createdAt: '2026-10-01', expires: '2027-02-01', ...over,
  });
}

test('risco aceito vigente libera o portão; vencido volta a bloquear', async () => {
  const root = makeProject(compliantFiles({ 'src/a.js': 'const x = eval(y);\n' }));
  const fs = require('node:fs');
  try {
    const fp = byId(await run(root), 'CORE-008').findings[0].fingerprint;
    fs.mkdirSync(path.join(root, '.lastro', 'risks'), { recursive: true });
    fs.writeFileSync(path.join(root, '.lastro', 'risks', 'RISK-0001.json'), riskFor(fp));
    const ok = await run(root);
    const f = byId(ok, 'CORE-008').findings[0];
    assert.equal(f.accepted, true);
    assert.equal(f.riskId, 'RISK-0001');
    assert.equal(ok.summary.blocking, 0);
    fs.writeFileSync(path.join(root, '.lastro', 'risks', 'RISK-0001.json'), riskFor(fp, { expires: '2026-11-01' }));
    const expired = await run(root);
    // O achado original volta a bloquear e o próprio risco vencido vira achado em CORE-013.
    assert.equal(byId(expired, 'CORE-008').findings[0].blocking, true);
    assert.equal(byId(expired, 'CORE-008').findings[0].accepted, false);
    assert.equal(byId(expired, 'CORE-013').state, 'failed');
    assert.equal(expired.summary.blocking, 2);
  } finally { cleanup(root); }
});

test('risco de outro achado não libera este achado', async () => {
  const root = makeProject(compliantFiles({ 'src/a.js': 'const x = eval(y);\n' }));
  const fs = require('node:fs');
  try {
    fs.mkdirSync(path.join(root, '.lastro', 'risks'), { recursive: true });
    fs.writeFileSync(path.join(root, '.lastro', 'risks', 'RISK-0001.json'), riskFor('0123456789abcdef'));
    assert.equal((await run(root)).summary.blocking, 1);
  } finally { cleanup(root); }
});

test('--only limita aos controles pedidos e --url inválida é erro de uso', async () => {
  const root = makeProject(BASE());
  try {
    const rep = await run(root, { only: ['CORE-011'] });
    assert.deepEqual(rep.controls.map((c) => c.id), ['CORE-011']);
    await assert.rejects(run(root, { url: 'ftp://x' }), ConfigError);
  } finally { cleanup(root); }
});

test('impressão digital é estável e depende do controle', () => {
  assert.equal(fingerprint('CORE-001', 'a'), fingerprint('CORE-001', 'a'));
  assert.notEqual(fingerprint('CORE-001', 'a'), fingerprint('CORE-002', 'a'));
  assert.match(fingerprint('CORE-001', 'a'), /^[0-9a-f]{16}$/);
});

test('o repositório do próprio LASTRO não tem achado bloqueante', async () => {
  const rep = await runCheck({ root: path.join(__dirname, '..', '..'), now: new Date() });
  const bloqueantes = rep.controls.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => `${c.id}: ${f.message}`));
  assert.deepEqual(bloqueantes, []);
  assert.notEqual(rep.verdict, 'fail');
});

test('sondas ativas: exigem --url, exigem confirmação e recusam a URL de produção do perfil', async () => {
  const root = makeProject(BASE({ webApp: true }, { urls: { production: 'https://app.exemplo.test', staging: 'https://stg.exemplo.test' } }));
  try {
    await assert.rejects(run(root, { active: true }), /exige --url/);
    await assert.rejects(run(root, { active: true, url: 'http://127.0.0.1:9' }), /confirm-non-production/);
    await assert.rejects(run(root, { active: true, url: 'https://app.exemplo.test/', confirmNonProduction: true }), /produção/);
    await assert.rejects(run(root, { url: 'http://127.0.0.1:9', delayMs: 10 }), /--delay/);
  } finally { cleanup(root); }
});

test('sondas ativas: com confirmação e alvo que não é produção, rodam, com ritmo e contagem no relatório', async () => {
  const { serve } = require('./helpers');
  const server = await serve((q, s) => { s.writeHead(405); s.end(); });
  const root = makeProject(BASE({ webApp: true }, { urls: { production: 'https://app.exemplo.test' } }));
  try {
    const rep = await run(root, { url: server.url, active: true, confirmNonProduction: true, only: ['WEB-009'], delayMs: 50 });
    assert.equal(byId(rep, 'WEB-009').state, 'verified');
    assert.equal(rep.target.active, true);
    assert.equal(rep.target.requestsSent, 2);
    assert.equal(rep.target.delayMs, 50);
    const passive = await run(root, { url: server.url, only: ['WEB-009'], delayMs: 50 });
    assert.equal(byId(passive, 'WEB-009').state, 'unverified', 'sem --active a sonda ativa não roda');
    assert.equal(passive.target.requestsSent, 0);
  } finally {
    cleanup(root);
    await server.close();
  }
});
