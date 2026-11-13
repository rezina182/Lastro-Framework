'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const A = require('../src/asvs');
const schema = require('../src/schema');
const { loadCatalog, validateCatalog, DEFAULT_CATALOG_DIR } = require('../src/catalog');
const { registry } = require('../src/checks');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const HEAD = 'chapter_id,chapter_name,section_id,section_name,req_id,req_description,L';

function csvFrom(reqs) {
  const lines = [HEAD];
  for (const [id, lv] of Object.entries(reqs)) {
    const [c, s] = id.split('.');
    lines.push(`${c},"Nome, com vírgula",${c}.${s},"Seção ""x""",${id},"texto fictício\nem duas linhas",${lv}`);
  }
  return lines.join('\r\n');
}

test('parseCsv: aspas, vírgula, aspas duplas, quebra de linha no campo, CRLF e BOM', () => {
  const rows = A.parseCsv('\ufeffa,b\r\n"x,y","he said ""oi""\nlinha2"\r\n1,2\n');
  assert.deepEqual(rows, [['a', 'b'], ['x,y', 'he said "oi"\nlinha2'], ['1', '2']]);
  assert.throws(() => A.parseCsv('a,"b'), /aspas/);
});

test('requirementsFromCsv: lê ID e nível e recusa formatos inesperados', () => {
  assert.deepEqual(A.requirementsFromCsv(csvFrom({ 'V1.1.1': 2, 'V3.4.1': 1 })), { 'V1.1.1': 2, 'V3.4.1': 1 });
  assert.throws(() => A.requirementsFromCsv('a,b\n1,2\n'), /colunas/);
  assert.throws(() => A.requirementsFromCsv(`${HEAD}\nV1,x,V1.1,y,1.1.1,z,2\n`), /inválido/);
  assert.throws(() => A.requirementsFromCsv(`${HEAD}\nV1,x,V1.1,y,V1.1.1,z,9\n`), /Nível/);
  assert.throws(() => A.requirementsFromCsv(`${HEAD}\nV1,x,V1.1,y,V1.1.1,z,1\nV1,x,V1.1,y,V1.1.1,z,1\n`), /duplicado/);
  assert.throws(() => A.requirementsFromCsv(HEAD), /sem linhas/);
});

test('buildMap ordena por número (V1.2.10 depois de V1.2.2) e só preserva N/A de IDs existentes', () => {
  const map = A.buildMap(
    { 'V1.2.10': 2, 'V1.2.2': 1, 'V10.1.1': 2, 'V2.1.1': 1 },
    { notApplicable: { 'V1.2.2': 'não há esse recurso neste produto', 'V9.9.9': 'id que sumiu do padrão oficial' } }
  );
  assert.deepEqual(Object.keys(map.requirements), ['V1.2.2', 'V1.2.10', 'V2.1.1', 'V10.1.1']);
  assert.deepEqual(Object.keys(map.notApplicable), ['V1.2.2']);
  assert.deepEqual(schema.validateAsvsMap(map), []);
});

test('verifyMap acusa requisito faltando, a mais e nível diferente', () => {
  const map = A.buildMap({ 'V1.1.1': 1, 'V1.1.2': 2 }, null);
  assert.deepEqual(A.verifyMap(map, { 'V1.1.1': 1, 'V1.1.2': 2 }), []);
  const errs = A.verifyMap(map, { 'V1.1.1': 2, 'V1.1.3': 1 });
  assert.equal(errs.length, 3);
  assert.ok(errs.some((e) => e.includes('Nível diferente em V1.1.1')));
  assert.ok(errs.some((e) => e.includes('Falta no mapa: V1.1.3')));
  assert.ok(errs.some((e) => e.includes('inexistente no CSV oficial: V1.1.2')));
});

test('o mapa versionado é válido e tem os 345 requisitos do ASVS 5.0.0 (70/183/92 por nível)', () => {
  const cat = loadCatalog();
  assert.deepEqual(schema.validateAsvsMap(cat.asvsMap), []);
  const levels = Object.values(cat.asvsMap.requirements);
  assert.equal(levels.length, 345);
  assert.equal(levels.filter((l) => l === 1).length, 70);
  assert.equal(levels.filter((l) => l === 2).length, 183);
  assert.equal(levels.filter((l) => l === 3).length, 92);
});

test('o mapa não carrega texto da norma: só ID e nível', () => {
  const text = fs.readFileSync(path.join(DEFAULT_CATALOG_DIR, 'asvs-map.json'), 'utf8');
  assert.ok(!/Verify that/i.test(text));
  assert.ok(text.length < 20000);
});

test('catálogo recusa controle que cita ID ASVS inexistente no mapa', () => {
  const cat = loadCatalog();
  const c = cat.byId.get('WEB-003');
  c.refs = [...c.refs, { std: 'ASVS', id: 'V99.9.9' }];
  const errs = validateCatalog(cat, new Set(registry.keys()));
  assert.ok(errs.some((e) => e.includes('V99.9.9')));
});

test('o catálogo real não tem referência ASVS fora do mapa', () => {
  const cat = loadCatalog();
  assert.deepEqual(validateCatalog(cat, new Set(registry.keys())), []);
});

function fakeControl(id, type, ids, covers) {
  return { id, check: { type }, refs: ids.map((x) => ({ std: 'ASVS', id: x, ...(covers ? { covers } : {}) })) };
}

test('coverage: separa automático, só manual, sem controle e não se aplica; respeita o nível', () => {
  const map = A.buildMap({ 'V1.1.1': 1, 'V1.1.2': 1, 'V1.1.3': 2, 'V6.1.1': 1, 'V6.1.2': 3 }, null);
  map.notApplicable = { 'V1.1.3': 'não há esse recurso neste produto' };
  const controls = [fakeControl('C-1', 'automated', ['V1.1.1']), fakeControl('C-2', 'manual', ['V1.1.1', 'V1.1.2'])];
  const l1 = A.coverage(controls, map, { level: 1 });
  assert.equal(l1.totals.total, 3);
  assert.equal(l1.totals.automated, 1);
  assert.equal(l1.totals.manual, 1);
  assert.equal(l1.totals.none, 1);
  assert.deepEqual(l1.uncited, ['V6.1.1']);
  assert.equal(l1.byChapter.V1.total, 2);
  const l2 = A.coverage(controls, map, { level: 2 });
  assert.equal(l2.totals.total, 4);
  assert.equal(l2.totals.notApplicable, 1);
  assert.equal(A.coverage(controls, map, { level: 3 }).totals.total, 5);
});

test('coverage com estado: falha vence, verificado exige todos verificados, fora do perfil à parte', () => {
  const map = A.buildMap({ 'V1.1.1': 1, 'V1.1.2': 1, 'V1.1.3': 1, 'V1.1.4': 1 }, null);
  const controls = [
    fakeControl('A', 'automated', ['V1.1.1'], 'full'), fakeControl('B', 'automated', ['V1.1.1'], 'full'),
    fakeControl('C', 'manual', ['V1.1.2'], 'full'),
    fakeControl('D', 'manual', ['V1.1.3'], 'full'),
  ];
  const states = new Map([['A', 'verified'], ['B', 'failed'], ['C', 'unverified'], ['D', 'not_applicable']]);
  const t = A.coverage(controls, map, { level: 1, states }).totals;
  assert.equal(t.failed, 1);
  assert.equal(t.unverified, 1);
  assert.equal(t.outOfProfile, 1);
  assert.equal(t.verified, 0);
  assert.equal(t.none, 1);
  const ok = A.coverage([fakeControl('A', 'automated', ['V1.1.1'], 'full')], map, { level: 1, states: new Map([['A', 'verified']]) });
  assert.equal(ok.totals.verified, 1);
});

test('coverage: controle verificado que cobre só em parte ou sem classificação não verifica o requisito', () => {
  const map = A.buildMap({ 'V1.1.1': 1, 'V1.1.2': 1 }, null);
  const controls = [fakeControl('P', 'manual', ['V1.1.1'], 'partial'), fakeControl('U', 'manual', ['V1.1.2'])];
  const t = A.coverage(controls, map, { level: 1, states: new Map([['P', 'verified'], ['U', 'verified']]) }).totals;
  assert.equal(t.verified, 0);
  assert.equal(t.unverified, 2);
  assert.equal(t.partial, 1);
  assert.equal(t.unclassified, 1);
  assert.equal(t.full, 0);
});

test('coverage: a melhor profundidade entre os controles vence', () => {
  const map = A.buildMap({ 'V1.1.1': 1 }, null);
  const controls = [fakeControl('P', 'manual', ['V1.1.1'], 'partial'), fakeControl('F', 'manual', ['V1.1.1'], 'full')];
  assert.equal(A.coverage(controls, map, { level: 1 }).totals.full, 1);
});

test('V6 (autenticação) e V7 (sessão) estão totalmente classificados até L2, sem requisito sem controle', () => {
  const cat = loadCatalog();
  const cov = A.coverage(cat.controls, cat.asvsMap, { level: 2 });
  for (const ch of ['V6', 'V7']) {
    const b = cov.byChapter[ch];
    assert.equal(b.none, 0, `${ch} tem requisito sem controle`);
    assert.equal(b.unclassified, 0, `${ch} tem requisito não classificado`);
    assert.equal(b.partial, 0, `${ch} tem requisito só parcial`);
    assert.equal(b.full, b.total, `${ch} não está inteiro`);
  }
  assert.equal(cov.byChapter.V6.total, 35);
  assert.equal(cov.byChapter.V7.total, 18);
});

test('V3, V5, V8, V13 e V16 estão classificados até L2: nenhum requisito sem controle nem sem classificação', () => {
  const cat = loadCatalog();
  const cov = A.coverage(cat.controls, cat.asvsMap, { level: 2 });
  const expected = { V3: 19, V5: 9, V8: 7, V13: 13, V16: 16 };
  for (const [ch, total] of Object.entries(expected)) {
    const b = cov.byChapter[ch];
    assert.equal(b.total, total, `${ch}: total`);
    assert.equal(b.none, 0, `${ch} tem requisito sem controle: ${cov.uncited.filter((id) => id.startsWith(`${ch}.`)).join(', ')}`);
    assert.equal(b.unclassified, 0, `${ch} tem requisito não classificado`);
    assert.equal(b.full + b.partial, total, `${ch}: full+partial`);
  }
});

test('sondas automáticas que só amostram a página inicial nunca são marcadas como cobertura inteira', () => {
  const cat = loadCatalog();
  for (const id of ['WEB-001', 'WEB-002', 'WEB-003', 'WEB-004', 'WEB-007', 'WEB-008', 'WEB-009', 'AUTH-003']) {
    const c = cat.byId.get(id);
    for (const r of c.refs.filter((x) => x.std === 'ASVS')) assert.notEqual(r.covers, 'full', `${id} ${r.id}`);
  }
});

test('o schema aceita covers full/partial só em referência ASVS', () => {
  const cat = loadCatalog();
  const base = cat.byId.get('AUTH-008');
  assert.deepEqual(schema.validateControl(base, 'x'), []);
  const bad = { ...base, refs: [{ std: 'ASVS', id: 'V6.2.1', covers: 'tudo' }] };
  assert.ok(schema.validateControl(bad, 'x').some((e) => e.includes('covers')));
  const other = { ...base, refs: [{ std: 'NIST', id: 'PO.1.1', covers: 'full' }] };
  assert.ok(schema.validateControl(other, 'x').some((e) => e.includes('só vale para')));
});

test('controles que cobrem requisitos federados só se aplicam com federatedLogin', () => {
  const cat = loadCatalog();
  for (const id of ['AUTH-020', 'AUTH-021']) assert.deepEqual(cat.byId.get(id).appliesIf, ['federatedLogin']);
});

test('formatCoverage mostra o aviso de que citado não é coberto por inteiro', () => {
  const map = A.buildMap({ 'V1.1.1': 1 }, null);
  const out = A.formatCoverage(A.coverage([], map, { level: 1 }));
  assert.ok(out.includes('não é "coberto por inteiro"'));
  assert.ok(out.includes('V1'));
});

// --- CLI ---------------------------------------------------------------------------------------

const cli = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });

test('CLI asvs: cobertura roda, recusa nível inválido e subcomando desconhecido', () => {
  assert.equal(cli(['asvs']).status, 0);
  assert.equal(cli(['asvs', '--level', '1']).status, 0);
  assert.equal(cli(['asvs', '--level', '4']).status, 3);
  assert.equal(cli(['asvs', 'xyz']).status, 3);
  const j = JSON.parse(cli(['asvs', '--json']).stdout);
  assert.equal(j.totals.total, 253);
});

test('CLI asvs verify: confere com CSV igual, acusa divergência, exige --csv e não grava no sync sem --write', () => {
  const map = loadCatalog().asvsMap;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lastro-asvs-'));
  try {
    const good = path.join(dir, 'ok.csv');
    fs.writeFileSync(good, csvFrom(map.requirements));
    assert.equal(cli(['asvs', 'verify', '--csv', good]).status, 0);
    const bad = path.join(dir, 'bad.csv');
    const changed = { ...map.requirements, 'V1.1.1': 3 };
    delete changed['V3.4.1'];
    fs.writeFileSync(bad, csvFrom(changed));
    const r = cli(['asvs', 'verify', '--csv', bad]);
    assert.equal(r.status, 3);
    assert.ok(r.stderr.includes('Falta no mapa: V3.4.1') === false);
    assert.ok(r.stderr.includes('inexistente no CSV oficial: V3.4.1'));
    assert.equal(cli(['asvs', 'verify']).status, 3);
    assert.equal(cli(['asvs', 'verify', '--csv', path.join(dir, 'nao-existe.csv')]).status, 3);
    const before = fs.readFileSync(path.join(DEFAULT_CATALOG_DIR, 'asvs-map.json'), 'utf8');
    assert.equal(cli(['asvs', 'sync', '--csv', good]).status, 0);
    assert.equal(fs.readFileSync(path.join(DEFAULT_CATALOG_DIR, 'asvs-map.json'), 'utf8'), before);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
