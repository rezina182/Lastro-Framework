'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const B = require('../src/bench');

const report = (controls) => ({ controls });
const ctl = (id, state, findings = []) => ({ id, state, findings });
const planted = (extra = {}) => ({ id: 'P-001', app: 'a', kind: 'planted', category: 'code', control: 'CORE-059', title: 't', expect: 'detected', ...extra });
const clean = (extra = {}) => ({ id: 'C-001', app: 'a', kind: 'clean', control: 'CORE-059', title: 't', expect: 'clean', ...extra });

test('bench: falha plantada só conta como detectada quando o achado aponta o ponto plantado', () => {
  const c = planted({ file: 'src/a.js' });
  const hit = report([ctl('CORE-059', 'failed', [{ location: 'src/a.js:3', message: 'SQL' }])]);
  assert.equal(B.evaluateCase(c, hit).outcome, 'detected');
  const elsewhere = report([ctl('CORE-059', 'failed', [{ location: 'src/b.js:3', message: 'SQL' }])]);
  assert.equal(B.evaluateCase(c, elsewhere).outcome, 'missed');
  // Prefixo de nome não vale: src/a.js não é src/a.jsx.
  const prefix = report([ctl('CORE-059', 'failed', [{ location: 'src/a.jsx:1', message: 'SQL' }])]);
  assert.equal(B.evaluateCase(c, prefix).outcome, 'missed');
  const byMessage = planted({ messageIncludes: 'HttpOnly' });
  assert.equal(B.evaluateCase(byMessage, report([ctl('CORE-059', 'failed', [{ location: null, message: 'Cookie sem HttpOnly.' }])])).outcome, 'detected');
  assert.equal(B.evaluateCase(byMessage, report([ctl('CORE-059', 'failed', [{ location: null, message: 'Cookie sem SameSite.' }])])).outcome, 'missed');
});

test('bench: sem prova é pergunta, e passou ou não se aplica é perda (desconhecido nunca vira detectado)', () => {
  assert.equal(B.evaluateCase(planted(), report([ctl('CORE-059', 'unverified')])).outcome, 'question');
  assert.equal(B.evaluateCase(planted(), report([ctl('CORE-059', 'verified')])).outcome, 'missed');
  assert.equal(B.evaluateCase(planted(), report([ctl('CORE-059', 'not_applicable')])).outcome, 'missed');
  assert.equal(B.evaluateCase(planted(), report([])).outcome, 'missed');
});

test('bench: em aplicação limpa, falhar é falso positivo e não medir não conta como limpo', () => {
  assert.equal(B.evaluateCase(clean(), report([ctl('CORE-059', 'verified')])).outcome, 'clean');
  assert.equal(B.evaluateCase(clean(), report([ctl('CORE-059', 'failed', [{ location: 'x.js:1', message: 'm' }])])).outcome, 'false-positive');
  assert.equal(B.evaluateCase(clean(), report([ctl('CORE-059', 'unverified')])).outcome, 'unmeasured');
  assert.equal(B.evaluateCase(clean(), report([])).outcome, 'unmeasured');
  assert.equal(B.compare(clean(), 'unmeasured'), 'regressed');
  assert.equal(B.compare(clean(), 'false-positive'), 'regressed');
});

test('bench: comparação com o esperado distingue piora e melhora', () => {
  assert.equal(B.compare(planted({ expect: 'detected' }), 'detected'), 'ok');
  assert.equal(B.compare(planted({ expect: 'detected' }), 'question'), 'regressed');
  assert.equal(B.compare(planted({ expect: 'question' }), 'missed'), 'regressed');
  assert.equal(B.compare(planted({ expect: 'question' }), 'detected'), 'improved');
});

test('bench: resumo calcula recall e cobertura por categoria, sem dividir por zero', () => {
  const s = B.summarize([
    { kind: 'planted', category: 'code', outcome: 'detected', status: 'ok' },
    { kind: 'planted', category: 'logic', outcome: 'question', status: 'ok' },
    { kind: 'planted', category: 'logic', outcome: 'missed', status: 'regressed' },
    { kind: 'clean', outcome: 'false-positive', status: 'regressed' },
  ]);
  assert.equal(s.planted.recall, 0.333);
  assert.equal(s.planted.coverage, 0.667);
  assert.equal(s.planted.byCategory.logic.recall, 0);
  assert.equal(s.clean.falsePositives, 1);
  assert.equal(s.regressed, 2);
  assert.equal(B.summarize([]).planted.recall, null);
});

test('bench: manifesto inválido é recusado (caminho com "..", id repetido, esperado desconhecido)', () => {
  const ok = { schemaVersion: 1, referenceDate: '2026-11-17', apps: { a: { dir: 'a' } }, cases: [planted({ app: 'a' })] };
  assert.deepEqual(B.validateManifest(ok), []);
  const bad = {
    schemaVersion: 1, referenceDate: '17/11/2026',
    apps: { a: { dir: '../fora', server: '/abs/server.js' } },
    cases: [planted({ app: 'a', expect: 'talvez' }), planted({ app: 'a' }), clean({ app: 'x', id: 'C-01' })],
  };
  const errs = B.validateManifest(bad).join('\n');
  for (const re of [/referenceDate/, /apps\.a\.dir/, /apps\.a\.server/, /expect/, /repetido/, /aplicação desconhecida/, /formato P-001/]) assert.match(errs, re);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lastro-bench-'));
  try {
    const f = path.join(dir, 'm.json');
    fs.writeFileSync(f, '{ quebrado');
    assert.equal(B.loadManifest(f).ok, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('bench: o banco de falhas plantadas do kit não regride (recall, perguntas e falso positivo)', { timeout: 120000 }, async () => {
  const res = await B.runBench();
  const bad = res.results.filter((r) => r.status === 'regressed').map((r) => `${r.id} ${r.outcome} (esperado ${r.expect}): ${r.detail}`);
  assert.deepEqual(bad, []);
  assert.equal(res.summary.clean.falsePositives, 0);
  // As falhas de lógica precisam pelo menos virar pergunta: perder uma delas é pior que não detectar.
  assert.equal(res.summary.planted.byCategory.logic.missed, 0);
});

test('bench: caso limpo com sonda só vale como limpo se a sonda rodou e passou (controle manual segue sem prova)', () => {
  const c = clean({ control: 'AUTH-027', probe: true });
  const passed = report([{ id: 'AUTH-027', state: 'unverified', findings: [], notes: ['Sonda autenticada: passou em 3 teste(s). Isso não verifica o controle.'] }]);
  assert.equal(B.evaluateCase(c, passed).outcome, 'clean');
  const notRun = report([{ id: 'AUTH-027', state: 'unverified', findings: [], notes: ['Sonda autenticada: inconclusiva: login recusado.'] }]);
  assert.equal(B.evaluateCase(c, notRun).outcome, 'unmeasured');
  const found = report([{ id: 'AUTH-027', state: 'failed', findings: [{ location: '/x', message: 'm' }], notes: [] }]);
  assert.equal(B.evaluateCase(c, found).outcome, 'false-positive');
  // Sem "probe", o mesmo estado manual sem prova não conta como limpo.
  assert.equal(B.evaluateCase(clean({ control: 'AUTH-027' }), passed).outcome, 'unmeasured');
});

test('bench: manifesto valida auth, env (só contas falsas BENCH_*) e probe', () => {
  const base = { schemaVersion: 1, referenceDate: '2026-11-17' };
  const ok = { ...base, apps: { a: { dir: 'a', server: 's.js', auth: true, env: { BENCH_A_USER: 'alice' } } }, cases: [clean({ app: 'a', probe: true })] };
  assert.deepEqual(B.validateManifest(ok), []);
  const bad = {
    ...base,
    apps: { a: { dir: 'a', auth: true, env: { HOME: 'x' } }, b: { dir: 'b', server: 's.js', auth: 'sim' } },
    cases: [planted({ app: 'a', probe: true }), clean({ id: 'C-002', app: 'b', probe: 'sim' })],
  };
  const errs = B.validateManifest(bad).join('\n');
  for (const re of [/precisam de um servidor de teste/, /nomes BENCH_/, /auth: use true ou false/, /probe: só em caso limpo/]) assert.match(errs, re);
});
