'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { computeScore, WEIGHT } = require('../src/score');
const { formatMarkdown, formatReport } = require('../src/report');
const { runCheck } = require('../src/engine');
const { makeProject, profileJson, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');

const ctl = (id, pack, severity, state, source = null) => ({ id, title: `Controle ${id}`, pack, severity, state, notes: [], findings: [], evidence: source ? { source } : null });
const rep = (controls, blocking = 0) => ({ controls, summary: { blocking } });

test('pesos por gravidade e só "verificado" vale ponto; falhando e sem prova valem zero', () => {
  assert.deepEqual(WEIGHT, { critical: 8, high: 5, medium: 3, low: 1 });
  const s = computeScore(rep([
    ctl('A', 'core', 'critical', 'verified', 'verifier-repo'),
    ctl('B', 'core', 'high', 'unverified'),
    ctl('C', 'web', 'medium', 'failed'),
    ctl('D', 'web', 'low', 'verified', 'manual-attestation'),
  ]));
  assert.equal(s.provenPct, 52.9);
  assert.equal(s.machinePct, 47.1);
  assert.equal(s.attestedPct, 5.9);
  assert.equal(s.failedPct, 17.6);
  assert.equal(s.unverifiedPct, 29.4);
  assert.equal(s.applicableControls, 4);
  assert.equal(s.highOrCriticalOpen, 1);
  assert.equal(s.level, 2);
  assert.equal(s.levelName, 'Estruturado');
});

test('o que não se aplica não entra na conta', () => {
  const base = [ctl('A', 'core', 'high', 'verified', 'verifier-repo')];
  const com = computeScore(rep([...base, ctl('X', 'web', 'critical', 'not_applicable')]));
  const sem = computeScore(rep(base));
  assert.equal(com.applicableControls, 1);
  assert.equal(com.provenPct, sem.provenPct);
  assert.equal(com.provenPct, 100);
});

test('níveis: bloqueante derruba para 0; abaixo de 30% é 1; 30% é 2', () => {
  const quase = [ctl('A', 'core', 'low', 'verified', 'verifier-repo'), ctl('B', 'core', 'high', 'unverified'), ctl('C', 'core', 'high', 'unverified')];
  assert.equal(computeScore(rep(quase)).level, 1);
  assert.equal(computeScore(rep([ctl('A', 'core', 'high', 'verified', 'verifier-repo'), ctl('B', 'core', 'high', 'unverified'), ctl('C', 'core', 'low', 'unverified')])).level, 2);
  const perfeito = rep([ctl('A', 'core', 'high', 'verified', 'verifier-repo')], 3);
  assert.equal(computeScore(perfeito).level, 0, 'achado bloqueante vale mais que qualquer percentual');
});

test('nível 3 exige 60% e nenhum alto ou crítico aberto; nível 4 exige 90% e nenhuma falha', () => {
  const alto = ctl('H1', 'core', 'high', 'verified', 'manual-attestation');
  const alto2 = ctl('H2', 'core', 'high', 'verified', 'verifier-repo');
  const medAberto = ctl('M1', 'core', 'medium', 'unverified');
  assert.equal(computeScore(rep([alto, alto2, medAberto])).level, 3);
  // 100% provado mas um alto sem prova: não passa de 2
  assert.equal(computeScore(rep([alto, ctl('H3', 'core', 'high', 'unverified'), ctl('M', 'core', 'medium', 'verified', 'manual-attestation'), ctl('M2', 'core', 'medium', 'verified', 'manual-attestation')])).level, 2);
  const tudo = [alto, alto2, ctl('M2', 'core', 'medium', 'verified', 'verifier-repo')];
  assert.equal(computeScore(rep(tudo)).level, 4);
  assert.equal(computeScore(rep(tudo)).nextStep, 'Manter as atestações dentro da validade e rodar o kit a cada PR.');
  // 90%+ com uma falha baixa: fica em 3
  const muitos = Array.from({ length: 20 }, (_, i) => ctl(`H${i}`, 'core', 'high', 'verified', 'verifier-repo'));
  assert.equal(computeScore(rep([...muitos, ctl('L', 'core', 'low', 'failed')])).level, 3);
});

test('o próximo passo diz o que falta, com os números', () => {
  const s0 = computeScore(rep([ctl('A', 'core', 'high', 'verified', 'verifier-repo')], 4));
  assert.ok(s0.nextStep.includes('4 achado(s) bloqueante(s)'));
  assert.ok(s0.nextStep.includes('nível 1'));
  const s1 = computeScore(rep([ctl('A', 'core', 'low', 'verified', 'verifier-repo'), ctl('B', 'core', 'high', 'unverified')]));
  assert.ok(s1.nextStep.includes('30%'));
  const s2 = computeScore(rep([ctl('A', 'core', 'high', 'verified', 'verifier-repo'), ctl('B', 'core', 'high', 'unverified'), ctl('C', 'core', 'low', 'unverified')]));
  assert.ok(s2.nextStep.includes('60%'));
  assert.ok(s2.nextStep.includes('1 controle(s) alto(s) ou crítico(s)'));
});

test('por pacote: agrupa, ordena, usa o título do catálogo e separa máquina de autodeclarado', () => {
  const s = computeScore(
    rep([ctl('W1', 'web', 'high', 'verified', 'verifier-http'), ctl('C1', 'core', 'high', 'verified', 'manual-attestation'), ctl('C2', 'core', 'high', 'failed')]),
    { packTitles: { core: 'Base', web: 'Aplicação web' } }
  );
  assert.deepEqual(s.byPack.map((p) => p.pack), ['core', 'web']);
  const core = s.byPack[0];
  assert.equal(core.title, 'Base');
  assert.equal(core.controls, 2);
  assert.equal(core.attestedPct, 50);
  assert.equal(core.machinePct, 0);
  assert.equal(core.failedPct, 50);
  assert.equal(s.byPack[1].machinePct, 100);
});

test('sem nenhum controle aplicável não quebra e não inventa nota', () => {
  const s = computeScore(rep([]));
  assert.equal(s.provenPct, 0);
  assert.equal(s.level, 1);
  assert.equal(s.applicableControls, 0);
});

test('a pontuação sempre carrega o aviso de que mede evidência e não segurança', () => {
  const s = computeScore(rep([ctl('A', 'core', 'high', 'verified', 'verifier-repo')]));
  assert.ok(s.disclaimer.includes('não a segurança da aplicação'));
  assert.ok(formatReport({ ...fakeFullReport(), score: s }).includes('não a segurança da aplicação'));
});

function fakeFullReport(over = {}) {
  return {
    tool: { version: '0.1.0' }, catalogVersion: '0.1.0', generatedAt: '2026-11-12T12:00:00.000Z',
    target: { root: 'x', url: null, active: false, requestsSent: 0, delayMs: 150 },
    profile: { name: 'Meu | App', flags: {} }, verdict: 'fail',
    summary: { applicable: 2, verified: 0, failed: 1, unverified: 1, notApplicable: 0, blocking: 1, debt: 0, accepted: 0 },
    controls: [
      { ...ctl('CORE-007', 'core', 'high', 'failed'), findings: [{ fingerprint: 'a'.repeat(16), severity: 'high', message: 'TLS | desligado', location: 'db.js:13', blocking: true, accepted: false, inBaseline: false }] },
      { ...ctl('CORE-009', 'core', 'medium', 'failed'), findings: [{ fingerprint: 'b'.repeat(16), severity: 'medium', message: 'HTML por template', location: 'app.js:9', blocking: false, accepted: false, inBaseline: false }] },
      { ...ctl('AUTH-001', 'auth', 'high', 'unverified'), notes: ['Sem atestação registrada em .lastro/status.json.'] },
    ],
    warnings: [],
    ...over,
  };
}

test('relatório em Markdown: seções, escape de barra vertical e aviso de escopo estático', () => {
  const r = fakeFullReport();
  r.score = computeScore(r, { packTitles: { core: 'Base' } });
  const md = formatMarkdown(r);
  for (const trecho of ['# Relatório LASTRO: Meu \\| App', '## Maturidade', '## Achados que bloqueiam', '## Outros achados', '## Controles sem prova', '## Limites']) {
    assert.ok(md.includes(trecho), `faltou: ${trecho}`);
  }
  assert.ok(md.includes('TLS \\| desligado'), 'a barra vertical é escapada para não quebrar a tabela');
  assert.ok(md.includes('| CORE-007 | alta | db.js:13 |'));
  assert.ok(md.includes('Nenhuma requisição foi feita à aplicação'));
  assert.ok(!md.includes('## Cobertura do ASVS'), 'sem cobertura informada, a seção não aparece');
});

test('o motor devolve o score no relatório e atestação conta como autodeclarado', async () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ aiCodingAgents: true }), '.gitignore': '.env\n' });
  try {
    const r = await runCheck({ root, now: new Date('2026-11-12T12:00:00Z') });
    assert.equal(r.score.method, 'v1');
    assert.equal(r.score.level, 0, 'sem CI nem threat model há bloqueantes');
    assert.ok(r.score.byPack.some((p) => p.pack === 'agent'));
    assert.ok(r.score.byPack.find((p) => p.pack === 'agent').title.length > 5, 'usa o título do pacote do catálogo');
    fs.writeFileSync(path.join(root, '.lastro', 'status.json'), JSON.stringify({
      schemaVersion: 1,
      attestations: { 'AG-001': { state: 'verified', attestedBy: 'Fulano', collectedAt: '2026-11-01', expiresAt: '2027-05-01' } },
    }));
    const r2 = await runCheck({ root, now: new Date('2026-11-12T12:00:00Z') });
    assert.ok(r2.score.attestedPct > 0, 'a atestação aparece como autodeclarada');
    assert.ok(r2.score.provenPct > r.score.provenPct);
  } finally { cleanup(root); }
});

test('CLI report: grava o Markdown, inclui o ASVS e cria a pasta de destino', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ aiCodingAgents: true }), '.gitignore': '.env\n' });
  const outDir = path.join(root, 'saida', 'relatorios');
  try {
    const out = path.join(outDir, 'app.md');
    const r = spawnSync(process.execPath, [CLI, 'report', '--root', root, '--out', out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes('Relatório gravado em'));
    const md = fs.readFileSync(out, 'utf8');
    assert.ok(md.includes('## Maturidade'));
    assert.ok(md.includes('## Cobertura do ASVS 5.0.0 (até L2)'));
    assert.ok(md.includes('Nível 0: Inicial'));
    const stdout = spawnSync(process.execPath, [CLI, 'report', '--root', root], { encoding: 'utf8' });
    assert.equal(stdout.status, 0);
    assert.ok(stdout.stdout.includes('# Relatório LASTRO'));
  } finally { cleanup(root); }
});
