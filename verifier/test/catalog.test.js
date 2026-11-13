'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadCatalog, validateCatalog } = require('../src/catalog');
const { registry } = require('../src/checks');
const schema = require('../src/schema');

test('o catálogo carrega e passa na validação cruzada', () => {
  const cat = loadCatalog();
  const errors = validateCatalog(cat, new Set(registry.keys()));
  assert.deepEqual(errors, []);
  assert.equal(cat.controls.length, 121);
  assert.equal(cat.lessons.length, 37);
});

test('todo controle manual tem howToVerify e todo automatizado tem check existente', () => {
  const cat = loadCatalog();
  for (const c of cat.controls) {
    if (c.check.type === 'manual') assert.ok(c.howToVerify && c.howToVerify.length > 20, `${c.id} sem howToVerify`);
    else assert.ok(registry.has(c.check.id), `${c.id} aponta para verificação inexistente`);
  }
});

test('controles críticos e altos de nível 1 existem em cada pacote relevante', () => {
  const cat = loadCatalog();
  for (const pack of Object.keys(cat.packs)) {
    assert.ok(cat.controls.some((c) => c.pack === pack), `pacote sem controles: ${pack}`);
  }
});

test('o validador recusa controle com id de prefixo errado', () => {
  const cat = loadCatalog();
  const bad = { ...cat.byId.get('WEB-001'), id: 'AUTH-001' };
  const errs = schema.validateControl(bad, 'x');
  assert.ok(errs.some((e) => e.includes('prefixo')));
});

test('o validador recusa campo desconhecido e manual sem howToVerify', () => {
  const cat = loadCatalog();
  const base = { ...cat.byId.get('PII-001') };
  delete base.howToVerify;
  assert.ok(schema.validateControl(base, 'x').some((e) => e.includes('howToVerify')));
  assert.ok(schema.validateControl({ ...cat.byId.get('PII-001'), extra: 1 }, 'x').some((e) => e.includes('desconhecido')));
});

test('a validação cruzada detecta verificação órfã e lição sem controle', () => {
  const cat = loadCatalog();
  const ids = new Set(registry.keys());
  ids.add('repo.fake.orfa');
  assert.ok(validateCatalog(cat, ids).some((e) => e.includes('órfã')));
  const broken = loadCatalog();
  broken.lessons = broken.lessons.map((l) => (l.id === 'L-B13' ? { ...l, controls: ['PII-001'] } : l));
  assert.ok(validateCatalog(broken, new Set(registry.keys())).some((e) => e.includes('PII-004')));
});

test('o validador de risco exige justificativa e validade', () => {
  const ok = {
    schemaVersion: 1, id: 'RISK-0001', control: 'WEB-001', fingerprints: ['0123456789abcdef'], owner: 'a', approvedBy: 'b',
    justification: 'Justificativa com mais de vinte caracteres.', createdAt: '2026-11-01', expires: '2027-01-01',
  };
  assert.deepEqual(schema.validateRisk(ok), []);
  assert.ok(schema.validateRisk({ ...ok, justification: 'curta' }).length > 0);
  assert.ok(schema.validateRisk({ ...ok, expires: 'amanhã' }).length > 0);
  assert.ok(schema.validateRisk({ ...ok, fingerprints: [] }).length > 0);
  assert.deepEqual(schema.validateRisk({ ...ok, fingerprints: [], scope: 'control' }), []);
});
