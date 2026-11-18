'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { computeScore } = require('../src/score');
const { buildStory, scopes, decisions, proofOf } = require('../src/story');

const NOW = new Date('2026-11-17T12:00:00Z');
const ctl = (id, pack, severity, state, over = {}) => ({
  id, title: `Controle ${id}`, pack, severity, state, checkType: 'manual', phase: ['build'], remediation: `Corrija ${id}.`, notes: [], findings: [], evidence: null, ...over,
});
const attest = (by, collectedAt, expiresAt) => ({ source: 'manual-attestation', attestedBy: by, collectedAt, expiresAt });

function report(controls, extra = {}) {
  const summary = { blocking: controls.flatMap((c) => c.findings).filter((f) => f.blocking).length, debt: 0, accepted: 0 };
  const r = { controls, summary, target: { url: null }, catalogVersion: '1.0.0', context: { meetsTarget: false, targetLevel: 3 }, ...extra };
  r.score = computeScore(r, { packTitles: { core: 'Base: higiene', web: 'Web: navegador' } });
  return r;
}

const CONTROLS = () => [
  ctl('CORE-001', 'core', 'high', 'verified', { checkType: 'automated', evidence: { source: 'verifier-repo' } }),
  ctl('CORE-006', 'core', 'high', 'failed', { checkType: 'automated', findings: [{ severity: 'high', blocking: true, accepted: false }] }),
  ctl('WEB-001', 'web', 'medium', 'verified', { evidence: attest('Fulana', '2026-11-01', '2026-12-01') }),
  ctl('WEB-002', 'web', 'high', 'unverified'),
  ctl('WEB-003', 'web', 'low', 'unverified', { checkType: 'automated' }),
];

test('história: já feito, atenção, o que fazer e o que decidir saem do relatório', () => {
  const st = buildStory(report(CONTROLS()), { now: NOW });
  assert.match(st.headline, /^Nota \d+,\d de 10 \((Inicial|Em evolução)\)\. 1 controle\(s\) bloqueiam o portão\./);
  assert.ok(st.done.some((x) => /1 controle\(s\) provado\(s\) pela máquina/.test(x)));
  assert.ok(st.done.some((x) => /1 controle\(s\) testado\(s\) por uma pessoa/.test(x)));
  assert.ok(st.attention.some((x) => /atestação de WEB-001 vence em 13 dia\(s\) \(Fulana\)/.test(x)));
  assert.ok(st.attention.some((x) => /Nenhuma sonda HTTP rodou/.test(x)));
  assert.ok(st.todo.some((x) => /^Corrigir CORE-006 \(Controle CORE-006\): Corrija CORE-006\./.test(x)));
  assert.ok(st.todo.some((x) => /lastro fix/.test(x)), 'CORE-006 tem correção previsível');
  assert.ok(st.todo.some((x) => /WEB-002/.test(x)), 'alto sem prova vira tarefa de playbook');
  assert.ok(st.decide.some((x) => /aceitar o risco com dono/.test(x)));
  assert.ok(st.decide.some((x) => /meta de maturidade/.test(x)));
});

test('história: compara com o registro anterior (melhorou, piorou, nota subiu) e ignora o registro igual ao atual', () => {
  const r = report(CONTROLS());
  const current = { generatedAt: '2026-11-17T12:00:00.000Z', grade: r.score.grade, catalog: '1.0.0', controls: Object.fromEntries(r.controls.map((c) => [c.id, c.state])) };
  const before = { generatedAt: '2026-11-10T12:00:00.000Z', grade: 0.5, catalog: '1.0.0', controls: { ...current.controls, 'CORE-001': 'failed', 'WEB-001': 'unverified', 'CORE-006': 'verified' } };
  const st = buildStory(r, { history: [before, current], current, now: NOW });
  assert.ok(st.done.some((x) => x === 'Desde o registro anterior, melhoraram: CORE-001, WEB-001.'));
  assert.ok(st.done.some((x) => /A nota subiu de 0,5 para/.test(x)));
  assert.ok(st.attention.some((x) => x === 'Pioraram desde o registro anterior: CORE-006 (verificado para falhando).'));
  const sem = buildStory(r, { history: [], current, now: NOW });
  assert.ok(!sem.done.some((x) => /melhoraram/.test(x)));
});

test('por escopo: separa implementado, falhando e falta provar, e diz como foi provado', () => {
  const list = scopes(report(CONTROLS()), { now: NOW });
  assert.deepEqual(list.map((s) => s.pack), ['core', 'web']);
  const web = list.find((s) => s.pack === 'web');
  assert.deepEqual(web.done.map((c) => c.id), ['WEB-001']);
  assert.deepEqual(web.missing.map((c) => c.id), ['WEB-002', 'WEB-003']);
  assert.match(web.done[0].proof, /atestado por Fulana em 2026-11-01, vale até 2026-12-01 \(vence em 13 dia\(s\)\)/);
  assert.match(web.missing[0].next, /lastro playbook --only WEB-002/);
  assert.match(web.missing[1].next, /--url/);
  const core = list.find((s) => s.pack === 'core');
  assert.match(core.done[0].proof, /leitura do repositório/);
  assert.match(core.failing[0].proof, /1 achado\(s\), 1 bloqueante\(s\)/);
  assert.equal(core.failing[0].next, 'Corrija CORE-006.');
  assert.ok(Number.isFinite(web.grade));
});

test('prova: sonda autenticada que passou ajuda, mas não verifica; falha da sonda é dita', () => {
  const passou = ctl('AUTH-027', 'auth', 'critical', 'unverified', { notes: ['Sonda autenticada: passou em 2 teste(s) (x) nas rotas declaradas no perfil.'] });
  assert.match(proofOf(passou, NOW), /ajuda a atestação mas não verifica/);
  const falhou = ctl('AUTH-027', 'auth', 'critical', 'failed', { evidence: { source: 'verifier-http' }, findings: [{ severity: 'critical', blocking: true }] });
  assert.match(proofOf(falhou, NOW), /falha achada por sonda autenticada/);
  const inconclusiva = ctl('AUTH-027', 'auth', 'critical', 'unverified', { notes: ['Sonda autenticada: inconclusiva: sem contas.'] });
  assert.equal(proofOf(inconclusiva, NOW), 'sem prova: teste manual e atestação');
});

test('decisões: atestações, riscos aceitos e decisões de ameaças, com aviso de vencimento', () => {
  const cs = CONTROLS();
  cs.push(ctl('WEB-010', 'web', 'high', 'failed', { findings: [{ severity: 'high', blocking: false, accepted: true, riskId: 'RISK-0001' }] }));
  const tm = {
    persisted: true, reviewed: false, reviewedBy: 'Beltrano', reviewedAt: '2026-11-05', counts: { threats: 2, pending: 1, mitigated: 0, exposed: 0 }, surface: { changes: [] },
    threats: [
      { id: 'TM-S-web', title: 'Falsificação na web', decision: 'accept', rationale: 'Risco baixo para o público interno.', owner: 'Fulana', expires: '2026-11-30', pending: false },
      { id: 'TM-T-web', title: 'Adulteração na web', decision: null, pending: true },
    ],
  };
  const list = decisions(report(cs, { threatModel: tm }), { now: NOW });
  assert.deepEqual(list.map((d) => d.kind), ['Atestação', 'Risco aceito', 'Revisão do modelo de ameaças', 'Ameaça: aceitar']);
  assert.equal(list[0].expiring, true);
  assert.equal(list[1].what, 'RISK-0001: Controle WEB-010');
  assert.equal(list[3].until, '2026-11-30');
  assert.equal(list[3].expiring, true);
  const st = buildStory(report(cs, { threatModel: tm }), { now: NOW });
  assert.ok(st.decide.some((x) => /Revisar o modelo de ameaças/.test(x)));
  assert.ok(st.decide.some((x) => /aceitação de TM-S-web \(Fulana\) vence em 12 dia\(s\)/.test(x)));
});
