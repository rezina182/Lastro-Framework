'use strict';

// Carrega e valida o catálogo de controles (catalog/).

const fs = require('node:fs');
const path = require('node:path');
const schema = require('./schema');
const { loadAsvsMap } = require('./asvs');

const DEFAULT_CATALOG_DIR = path.join(__dirname, '..', '..', 'catalog');

function readJsonStrict(file) {
  try {
    return { ok: true, value: JSON.parse(fs.readFileSync(file, 'utf8')) };
  } catch (e) {
    return { ok: false, error: `${path.basename(file)}: ${e.message}` };
  }
}

function loadCatalog(dir = DEFAULT_CATALOG_DIR) {
  const errors = [];
  const packsFile = readJsonStrict(path.join(dir, 'packs.json'));
  const lessonsFile = readJsonStrict(path.join(dir, 'lessons.json'));
  if (!packsFile.ok) errors.push(packsFile.error);
  if (!lessonsFile.ok) errors.push(lessonsFile.error);

  const controls = [];
  const controlsDir = path.join(dir, 'controls');
  let files = [];
  try {
    files = fs.readdirSync(controlsDir).filter((f) => f.endsWith('.json')).sort();
  } catch (e) {
    errors.push(`catalog/controls: ${e.message}`);
  }
  for (const f of files) {
    const j = readJsonStrict(path.join(controlsDir, f));
    if (!j.ok) {
      errors.push(j.error);
      continue;
    }
    errors.push(...schema.validateControlFile(j.value, `controls/${f}`));
    if (Array.isArray(j.value.controls)) controls.push(...j.value.controls);
  }
  const asvs = loadAsvsMap(dir);
  if (!asvs.ok) errors.push(asvs.error);
  else errors.push(...schema.validateAsvsMap(asvs.value));
  const riskFile = readJsonStrict(path.join(dir, 'risk-map.json'));
  if (!riskFile.ok) errors.push(riskFile.error);
  if (packsFile.ok) errors.push(...schema.validatePacks(packsFile.value));
  if (lessonsFile.ok) errors.push(...schema.validateLessons(lessonsFile.value));

  const byId = new Map();
  for (const c of controls) {
    if (c && typeof c.id === 'string') {
      if (byId.has(c.id)) errors.push(`Controle duplicado: ${c.id}`);
      byId.set(c.id, c);
    }
  }
  if (riskFile.ok) errors.push(...schema.validateRiskMap(riskFile.value, new Set(byId.keys())));
  return {
    dir,
    riskMap: riskFile.ok && riskFile.value && riskFile.value.entries ? riskFile.value.entries : {},
    version: packsFile.ok ? packsFile.value.catalogVersion : '0.0.0',
    packs: packsFile.ok ? packsFile.value.packs : {},
    lessons: lessonsFile.ok && Array.isArray(lessonsFile.value.lessons) ? lessonsFile.value.lessons : [],
    asvsMap: asvs.ok ? asvs.value : null,
    controls,
    byId,
    errors,
  };
}

/** Validação cruzada: ids de verificação, lições e coerência nos dois sentidos. */
function validateCatalog(cat, checkIds) {
  const errors = [...cat.errors];
  const lessonIds = new Map(cat.lessons.map((l) => [l.id, l]));
  if (lessonIds.size !== cat.lessons.length) errors.push('lessons.json: ids de lição duplicados');

  const used = new Set();
  for (const c of cat.controls) {
    if (!c || !c.check) continue;
    if (c.check.type === 'automated') {
      if (!checkIds.has(c.check.id)) errors.push(`${c.id}: check.id "${c.check.id}" não existe no registro de verificações`);
      else used.add(c.check.id);
    }
    if (cat.asvsMap && cat.asvsMap.requirements) {
      for (const r of c.refs || []) {
        if (r.std === 'ASVS' && !(r.id in cat.asvsMap.requirements)) errors.push(`${c.id}: referência ASVS inexistente no mapa: ${r.id}`);
      }
    }
    for (const o of c.origin || []) {
      const l = lessonIds.get(o);
      if (!l) errors.push(`${c.id}: lição de origem inexistente ${o}`);
      else if (!l.controls.includes(c.id)) errors.push(`${c.id}: a lição ${o} não lista este controle`);
    }
  }
  for (const l of cat.lessons) {
    for (const cid of l.controls || []) {
      const c = cat.byId.get(cid);
      if (!c) errors.push(`${l.id}: controle inexistente ${cid}`);
      else if (!(c.origin || []).includes(l.id)) errors.push(`${l.id}: o controle ${cid} não cita esta lição em origin`);
    }
  }
  for (const id of checkIds) if (!used.has(id)) errors.push(`Verificação órfã (nenhum controle a usa): ${id}`);
  for (const pack of Object.keys(cat.packs)) {
    if (!cat.controls.some((c) => c.pack === pack)) errors.push(`Pacote sem controles: ${pack}`);
  }
  return errors;
}

module.exports = { loadCatalog, validateCatalog, DEFAULT_CATALOG_DIR };
