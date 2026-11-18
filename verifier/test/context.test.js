'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { deriveContext, describeScope } = require('../src/context');
const { groupCauses } = require('../src/causes');
const { engineeringFacts, BIG_FILE_LINES } = require('../src/engineering');
const { runCheck } = require('../src/engine');
const { computeScore } = require('../src/score');
const { formatMarkdown, formatReport } = require('../src/report');
const { formatHtml } = require('../src/html');
const schema = require('../src/schema');
const { loadCatalog } = require('../src/catalog');
const { ALL_FALSE, makeProject, profileJson, cleanup, ctxFor } = require('./helpers');

const flags = (over) => ({ ...ALL_FALSE, ...over });

test('contexto: o risco inerente vem do que a aplicação declara e define a meta de maturidade', () => {
  const kit = deriveContext({ flags: flags({ aiCodingAgents: true }) });
  assert.equal(kit.risk, 'baixo');
  assert.equal(kit.targetGrade, 6);
  const painel = deriveContext({ flags: flags({ webApp: true, hasAuth: true, anonymousUsers: true, personalData: true, publicInternet: true, aiCodingAgents: true }) });
  assert.equal(painel.risk, 'moderado');
  assert.equal(painel.points, 7);
  assert.equal(painel.targetGrade, 7);
  const quiz = deriveContext({ flags: flags({ webApp: true, hasAuth: true, anonymousUsers: true, realtime: true, uploads: true, personalData: true, minorsData: true, publicInternet: true, aiCodingAgents: true }) });
  assert.equal(quiz.risk, 'alto');
  assert.equal(quiz.targetGrade, 8);
  assert.ok(quiz.factors.includes('trata dados de crianças ou adolescentes'));
  assert.equal(quiz.riskSource, 'estimado pelos flags do perfil');
});

test('contexto: o perfil pode sobrescrever o risco e a meta, e a origem aparece', () => {
  const c = deriveContext({ flags: flags({ aiCodingAgents: true }), context: { criticality: 'high', targetGrade: 5.5 } });
  assert.equal(c.risk, 'alto');
  assert.equal(c.targetGrade, 5.5);
  assert.equal(c.riskSource, 'definido no perfil');
  assert.equal(c.targetSource, 'definida no perfil');
  const soRisco = deriveContext({ flags: flags({}), context: { criticality: 'medium' } });
  assert.equal(soRisco.targetGrade, 7, 'sem meta própria, usa o padrão do risco');
  assert.equal(soRisco.targetSource, 'padrão para risco moderado');
  // Perfil antigo com targetLevel (0 a 4) continua valendo, convertido para a nota.
  const antigo = deriveContext({ flags: flags({}), context: { targetLevel: 3 } });
  assert.equal(antigo.targetGrade, 8);
  assert.match(antigo.targetSource, /targetLevel 3 convertido/);
});

test('contexto: o schema do perfil valida criticality, targetGrade e o targetLevel antigo', () => {
  const base = { schemaVersion: 1, name: 't', flags: Object.fromEntries(schema.FLAGS.map((f) => [f, false])) };
  assert.deepEqual(schema.validateProfile({ ...base, context: { criticality: 'low', targetGrade: 7.5 } }), []);
  assert.ok(schema.validateProfile({ ...base, context: { targetGrade: 11 } }).length > 0);
  assert.deepEqual(schema.validateProfile({ ...base, context: { criticality: 'low', targetLevel: 0 } }), []);
  assert.ok(schema.validateProfile({ ...base, context: { criticality: 'enorme' } }).length > 0);
  assert.ok(schema.validateProfile({ ...base, context: { targetLevel: 5 } }).length > 0);
  assert.ok(schema.validateProfile({ ...base, context: { targetLevel: 2.5 } }).length > 0);
  assert.ok(schema.validateProfile({ ...base, context: { outro: 1 } }).length > 0);
});

test('escopo: lista os pacotes ativos e os que ficaram de fora, com a flag que falta', () => {
  const cat = loadCatalog();
  const s = describeScope(cat.packs, flags({ webApp: true, hasAuth: true }));
  assert.ok(s.on.some((p) => p.pack === 'core') && s.on.some((p) => p.pack === 'web') && s.on.some((p) => p.pack === 'auth'));
  const uploads = s.off.find((p) => p.pack === 'uploads');
  assert.deepEqual(uploads.missing, ['uploads']);
  assert.ok(!s.off.some((p) => p.pack === 'web'));
});

const ctl = (id, severity, findings, over = {}) => ({ id, title: `Título ${id}`, pack: 'core', severity, state: 'failed', notes: [], evidence: null, remediation: `Corrija ${id}.`, findings, ...over });
const fnd = (severity, message, location, blocking = true) => ({ fingerprint: 'a'.repeat(16), severity, message, location, blocking, accepted: false, inBaseline: false });

test('causas: cinco ocorrências do mesmo controle viram uma causa, ordenada por gravidade e depois por volume', () => {
  const report = {
    controls: [
      ctl('CORE-006', 'high', Array.from({ length: 5 }, (_, i) => fnd('high', 'Action sem SHA', `ci.yml:${i + 1}`))),
      ctl('CORE-007', 'high', [fnd('high', 'TLS desligado', 'db.js:13')]),
      ctl('CORE-012', 'critical', [fnd('critical', 'Sem threat model', null)]),
      ctl('CORE-009', 'medium', [fnd('medium', 'innerHTML', 'a.js:1', false)]),
      ctl('CORE-001', 'high', [], { state: 'verified' }),
    ],
  };
  const causas = groupCauses(report);
  assert.deepEqual(causas.map((c) => c.id), ['CORE-012', 'CORE-006', 'CORE-007']);
  assert.equal(causas[1].count, 5);
  assert.deepEqual(causas[1].locations, ['ci.yml:1', 'ci.yml:2', 'ci.yml:3', 'ci.yml:4', 'ci.yml:5']);
  assert.equal(causas[0].locations.length, 0, 'achado sem local não inventa local');
  assert.equal(causas[1].remediation, 'Corrija CORE-006.');
  assert.ok(!causas.some((c) => c.id === 'CORE-009'), 'achado que não bloqueia não é causa de bloqueio');
});

function lines(n) { return `${Array.from({ length: n }, (_, i) => `const x${i} = ${i};`).join('\n')}\n`; }

test('engenharia: conta código, testes, CI, ferramentas e documentação sem dar nota', () => {
  const root = makeProject({
    'src/app.js': lines(100),
    'src/util.js': lines(50),
    'tests/app.test.js': lines(60),
    '.github/workflows/ci.yml': 'jobs:\n  t:\n    steps:\n      - run: npm test\n      - run: npm run lint\n',
    'eslint.config.js': 'module.exports = [];\n',
    'package.json': JSON.stringify({ scripts: { test: 'jest', lint: 'eslint .' }, dependencies: { a: '1.0.0' }, devDependencies: { b: '1.0.0', c: '1.0.0' } }),
    'package-lock.json': '{}',
    'README.md': '# app\n',
    'ARCHITECTURE.md': '# arq\n',
  });
  try {
    const e = engineeringFacts(ctxFor(root));
    assert.equal(e.sourceFiles, 3, 'o eslint.config.js também é código-fonte');
    assert.equal(e.sourceLines, 150 + 1, 'app.js (100) + util.js (50) + eslint.config.js (1)');
    assert.equal(e.testFiles, 1);
    assert.equal(e.testLines, 60);
    assert.equal(e.largest[0].file, 'src/app.js');
    assert.equal(e.ci.runsTests, true);
    assert.equal(e.ci.runsLint, true);
    assert.equal(e.tooling.lintConfig, true);
    assert.equal(e.tooling.lockfile, true);
    assert.equal(e.docs.readme, true);
    assert.equal(e.docs.architecture, true);
    assert.equal(e.docs.changelog, false);
    assert.deepEqual(e.dependencies, { prod: 1, dev: 2 });
    assert.deepEqual(e.observations, [], 'um projeto em ordem não gera observações');
  } finally { cleanup(root); }
});

test('engenharia: observações para arquivo enorme, falta de teste, teste fora do CI e teste pequeno', () => {
  const grande = makeProject({ 'src/server.js': lines(BIG_FILE_LINES + 50), 'README.md': '# x\n' });
  try {
    const e = engineeringFacts(ctxFor(grande));
    assert.ok(e.observations.some((o) => o.includes('src/server.js') && o.includes('muito grandes')));
    assert.ok(e.observations.includes('Nenhum arquivo de teste encontrado.'));
    assert.ok(e.observations.some((o) => o.includes('Nenhum workflow de CI')));
    assert.ok(e.observations.some((o) => o.includes('lint')));
  } finally { cleanup(grande); }
  const foraDoCi = makeProject({
    'src/a.js': lines(1000),
    'tests/a.test.js': lines(20),
    '.github/workflows/ci.yml': 'jobs:\n  t:\n    steps:\n      - run: echo oi\n',
    'README.md': '# x\n',
    'package.json': '{}',
  });
  try {
    const e = engineeringFacts(ctxFor(foraDoCi));
    assert.ok(e.observations.some((o) => o.includes('volume pequeno')), 'testes são 2% do código');
    assert.ok(e.observations.some((o) => o.includes('nenhum workflow parece executar os testes')));
    assert.ok(e.observations.some((o) => o.includes('sem lockfile')));
  } finally { cleanup(foraDoCi); }
});

test('engenharia: projeto sem código e sem README não quebra', () => {
  const root = makeProject({ 'notas.txt': 'x' });
  try {
    const e = engineeringFacts(ctxFor(root));
    assert.equal(e.sourceFiles, 0);
    assert.equal(e.testToSourcePct, 0);
    assert.ok(e.observations.some((o) => o.includes('Nenhum arquivo de código-fonte')));
    assert.ok(e.observations.includes('Sem README.'));
  } finally { cleanup(root); }
});

test('score por fase: um controle conta em cada fase em que atua e a ordem segue o ciclo de vida', () => {
  const controls = [
    { id: 'A', pack: 'core', severity: 'high', state: 'verified', evidence: { source: 'verifier-repo' }, phase: ['design', 'build'] },
    { id: 'B', pack: 'core', severity: 'high', state: 'failed', evidence: null, phase: ['build'] },
    { id: 'C', pack: 'core', severity: 'medium', state: 'unverified', evidence: null, phase: ['respond', 'runtime'] },
  ];
  const s = computeScore({ controls, summary: { blocking: 0 } });
  assert.deepEqual(s.byPhase.map((p) => p.phase), ['design', 'build', 'runtime', 'respond']);
  const build = s.byPhase.find((p) => p.phase === 'build');
  assert.equal(build.controls, 2);
  assert.equal(build.provenPct, 50);
  assert.equal(build.failedPct, 50);
  assert.equal(s.byPhase.find((p) => p.phase === 'design').provenPct, 100);
  assert.equal(s.byPhase.find((p) => p.phase === 'respond').unverifiedPct, 100);
  assert.equal(s.byPhase[0].name, 'Projeto');
});

test('motor: o relatório traz contexto, escopo, fases, engenharia e a visão com baseline', async () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ aiCodingAgents: true }),
    '.gitignore': '.env\n',
    'src/a.js': lines(10),
  });
  try {
    const r = await runCheck({ root, now: new Date('2026-11-12T12:00:00Z') });
    assert.equal(r.context.risk, 'baixo');
    assert.equal(r.context.targetGrade, 6);
    assert.equal(r.context.meetsTarget, false);
    assert.equal(r.context.gap, Math.round((6 - r.score.grade) * 10) / 10);
    assert.ok(r.scope.off.some((p) => p.pack === 'web' && p.missing.includes('webApp')));
    assert.ok(r.scope.on.some((p) => p.pack === 'agent'));
    assert.ok(r.score.byPhase.some((p) => p.phase === 'build'));
    assert.equal(r.engineering.sourceFiles, 1);
    assert.ok(r.baselineView && r.baselineView.causes >= 2, 'sem CI nem threat model há causas de bloqueio');
    assert.equal(r.baselineView.findings, r.summary.blocking);
    assert.equal(r.baselineView.verdictIfAdopted, 'incomplete', 'ainda há controles críticos sem prova');
    assert.ok(r.controls.every((c) => Array.isArray(c.phase) && typeof c.remediation === 'string' && c.remediation.length > 10));
  } finally { cleanup(root); }
});

test('motor: sem bloqueantes não há visão de baseline, e uma meta própria no perfil vale', async () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({}, { context: { targetGrade: 0 } }),
    '.gitignore': '.env\n',
  });
  try {
    const r = await runCheck({ root, now: new Date('2026-11-12T12:00:00Z'), only: ['CORE-011'] });
    assert.equal(r.baselineView === null || r.baselineView.findings === r.summary.blocking, true);
    assert.equal(r.context.targetGrade, 0);
    assert.equal(r.context.meetsTarget, true);
  } finally { cleanup(root); }
});

function fullReport() {
  const controls = [
    ctl('CORE-006', 'high', Array.from({ length: 3 }, (_, i) => fnd('high', 'Action sem SHA', `ci.yml:${i + 1}`)), { phase: ['build', 'deploy'] }),
    ctl('AUTH-001', 'high', [], { state: 'unverified', phase: ['design'], notes: ['Sem atestação.'] }),
  ];
  const summary = { applicable: 2, verified: 0, failed: 1, unverified: 1, notApplicable: 0, blocking: 3, debt: 0, accepted: 0 };
  const score = computeScore({ controls, summary }, { packTitles: { core: 'Base: cadeia de suprimentos' } });
  return {
    tool: { version: '0.1.0' }, catalogVersion: '0.1.0', generatedAt: '2026-11-12T12:00:00.000Z',
    target: { root: 'x', url: null, active: false, requestsSent: 0, delayMs: 150 },
    profile: { name: 'App de teste', flags: {} }, verdict: 'fail', summary, controls, warnings: [], score,
    context: { risk: 'moderado', points: 7, factors: ['é acessível pela internet', 'trata dados pessoais'], riskSource: 'estimado pelos flags do perfil', targetGrade: 7, targetSource: 'padrão para risco moderado', gap: 7, meetsTarget: false },
    scope: { on: [{ pack: 'core', title: 'Base: cadeia' }], off: [{ pack: 'uploads', title: 'Upload de arquivos', missing: ['uploads'] }] },
    baselineView: { findings: 3, causes: 1, verdictIfAdopted: 'incomplete' },
    engineering: {
      sourceFiles: 4, sourceLines: 9000, largest: [{ file: '<b>grande</b>.js', lines: 8000 }], testFiles: 1, testLines: 100, testToSourcePct: 1.1,
      ci: { workflows: 1, runsTests: false, runsLint: false },
      tooling: { testScript: true, lintScript: false, lintConfig: false, typeConfig: false, lockfile: true },
      docs: { readme: true, architecture: false, changelog: false, license: false, docsFolder: false },
      dependencies: { prod: 3, dev: 1 },
      observations: ['<script>alert(1)</script> tem 8000 linhas'],
    },
  };
}

test('relatório em Markdown: contexto, fases, causas agrupadas, baseline e engenharia', () => {
  const md = formatMarkdown(fullReport());
  for (const t of ['## Contexto e meta', 'Risco inerente: moderado', 'Meta para este contexto: nota 7,0', 'Faltam 7,0 ponto(s)', 'Fora do escopo, porque o perfil declara que a aplicação não tem: Upload de arquivos (upload de arquivos)',
    '## Aderência por fase do ciclo de vida (SSDLC)', '| Projeto |', '| Desenvolvimento |', '## Causas dos bloqueios', '3 achado(s) em 1 causa(s)', 'Corrija CORE-006.', 'ci.yml:1, ci.yml:2, ci.yml:3',
    'lastro baseline --write', 'o portão ficaria incompleto', '### Todas as ocorrências', '## Fatos de engenharia (não entram na pontuação)', 'portão de CI: **FALHA**']) {
    assert.ok(md.includes(t), `faltou: ${t}`);
  }
});

test('relatório em texto: linhas de contexto e de baseline', () => {
  const txt = formatReport(fullReport());
  assert.ok(txt.includes('Contexto: risco moderado (7 pontos) | meta: nota 7,0 | hoje: 0,0 (faltam 7,0 ponto(s))'), txt.split('\n').find((l) => l.startsWith('Contexto')));
  assert.ok(txt.includes('3 achado(s) bloqueante(s) em 1 causa(s)'));
  assert.ok(txt.includes('deixaria o portão incompleto'));
});

test('relatório em HTML: novas seções existem, o conteúdo do projeto é escapado e continua autocontido', () => {
  const html = formatHtml(fullReport());
  for (const t of ['id="contexto"', 'id="ssdlc"', 'id="engenharia"', 'Portão de CI', 'Causas dos bloqueios', '<details open><summary>CORE-006', 'Como corrigir:', 'Todas as ocorrências', 'Risco inerente', 'Meta de maturidade', 'Fora do escopo']) {
    assert.ok(html.includes(t), `faltou: ${t}`);
  }
  assert.ok(!html.includes('<script') && !html.includes('<b>grande</b>'));
  assert.ok(html.includes('&lt;b&gt;grande&lt;/b&gt;.js'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt; tem 8000 linhas'));
  assert.ok(!/(?:src|href)=["'](?!#)/i.test(html));
  assert.ok(/<a href="#contexto">/.test(html) && /<a href="#engenharia">/.test(html));
});

test('relatório: relatórios antigos, sem as seções novas, ainda são gerados', () => {
  const r = fullReport();
  delete r.context; delete r.scope; delete r.baselineView; delete r.engineering;
  r.score = { ...r.score };
  delete r.score.byPhase;
  assert.doesNotThrow(() => formatMarkdown(r));
  assert.doesNotThrow(() => formatHtml(r));
  assert.doesNotThrow(() => formatReport(r));
  assert.ok(!formatHtml(r).includes('id="contexto"'));
});
