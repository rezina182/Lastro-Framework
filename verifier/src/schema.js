'use strict';

// Validadores dos formatos do LASTRO. Escritos à mão para o kit não ter dependências de execução.
// Cada função devolve uma lista de erros (vazia = válido). Campos desconhecidos são recusados.

const { parseDate } = require('./util');

const FLAGS = [
  'webApp', 'hasAuth', 'anonymousUsers', 'realtime', 'uploads', 'personalData',
  'minorsData', 'thirdPartyAssets', 'aiCodingAgents', 'publicInternet', 'federatedLogin', 'tokenAuth', 'oauthProvider',
];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const PHASES = ['design', 'build', 'test', 'deploy', 'runtime', 'respond'];
const ENFORCEMENT = ['hard', 'soft', 'advisory'];
const PACKS = ['core', 'web', 'auth', 'pii', 'realtime', 'uploads', 'assets', 'agent'];
const PACK_PREFIX = {
  core: 'CORE', web: 'WEB', auth: 'AUTH', pii: 'PII', realtime: 'RT', uploads: 'UP', assets: 'AST', agent: 'AG',
};
const CHECK_TYPES = ['automated', 'manual'];
const TICKET_STATUS = ['open', 'in_progress', 'done', 'accepted'];
const PRIORITIES = ['P0', 'P1', 'P2', 'P3'];
const LESSON_SOURCES = { A: 'app-a', B: 'app-b', R: 'research' };

const ID_CONTROL = /^(CORE|WEB|AUTH|PII|RT|UP|AST|AG)-\d{3}$/;
const ID_LESSON = /^L-[ABR]\d{2}$/;
const ID_RISK = /^RISK-\d{4}$/;
const ID_TICKET = /^T-\d{4}$/;
const ID_CHECK = /^(repo|http)\.[a-z0-9][a-z0-9.-]*$/;
const FINGERPRINT = /^[0-9a-f]{16}$/;

function isObj(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function checkKeys(obj, required, optional, where, errs) {
  for (const k of required) if (!(k in obj)) errs.push(`${where}: campo obrigatório ausente "${k}"`);
  for (const k of Object.keys(obj)) {
    if (!required.includes(k) && !optional.includes(k)) errs.push(`${where}: campo desconhecido "${k}"`);
  }
}

function text(v, where, errs, max = 500, min = 1) {
  if (typeof v !== 'string' || v.trim().length < min || v.length > max) {
    errs.push(`${where}: texto inválido (${min} a ${max} caracteres)`);
  }
}

function oneOf(v, list, where, errs) {
  if (!list.includes(v)) errs.push(`${where}: valor inválido "${String(v)}" (esperado: ${list.join('|')})`);
}

function date(v, where, errs) {
  if (parseDate(v) === null) errs.push(`${where}: data inválida (use AAAA-MM-DD ou ISO 8601)`);
}

function stringList(v, where, errs, { min = 0, max = 50, itemMax = 300 } = {}) {
  if (!Array.isArray(v) || v.length < min || v.length > max) {
    errs.push(`${where}: lista inválida (${min} a ${max} itens)`);
    return;
  }
  v.forEach((s, i) => text(s, `${where}[${i}]`, errs, itemMax));
}

function validateControl(c, where) {
  const errs = [];
  if (!isObj(c)) return [`${where}: o controle deve ser um objeto`];
  checkKeys(
    c,
    ['id', 'title', 'summary', 'pack', 'tier', 'severity', 'phase', 'check', 'enforcement', 'rationale', 'remediation', 'refs', 'origin'],
    ['appliesIf', 'howToVerify'],
    where,
    errs
  );
  if (typeof c.id !== 'string' || !ID_CONTROL.test(c.id)) errs.push(`${where}.id: formato inválido`);
  text(c.title, `${where}.title`, errs, 140);
  text(c.summary, `${where}.summary`, errs, 500);
  text(c.rationale, `${where}.rationale`, errs, 900);
  text(c.remediation, `${where}.remediation`, errs, 900);
  oneOf(c.pack, PACKS, `${where}.pack`, errs);
  if (typeof c.id === 'string' && PACKS.includes(c.pack) && !c.id.startsWith(`${PACK_PREFIX[c.pack]}-`)) {
    errs.push(`${where}.id: o prefixo não confere com o pacote "${c.pack}"`);
  }
  if (![1, 2, 3].includes(c.tier)) errs.push(`${where}.tier: use 1, 2 ou 3`);
  oneOf(c.severity, SEVERITIES, `${where}.severity`, errs);
  oneOf(c.enforcement, ENFORCEMENT, `${where}.enforcement`, errs);
  if (!Array.isArray(c.phase) || c.phase.length === 0) errs.push(`${where}.phase: lista vazia`);
  else c.phase.forEach((p, i) => oneOf(p, PHASES, `${where}.phase[${i}]`, errs));
  if (c.appliesIf !== undefined) {
    if (!Array.isArray(c.appliesIf)) errs.push(`${where}.appliesIf: deve ser lista`);
    else c.appliesIf.forEach((f, i) => oneOf(f, FLAGS, `${where}.appliesIf[${i}]`, errs));
  }
  if (!isObj(c.check)) {
    errs.push(`${where}.check: deve ser objeto`);
  } else {
    checkKeys(c.check, ['type'], ['id'], `${where}.check`, errs);
    oneOf(c.check.type, CHECK_TYPES, `${where}.check.type`, errs);
    if (c.check.type === 'automated') {
      if (typeof c.check.id !== 'string' || !ID_CHECK.test(c.check.id)) errs.push(`${where}.check.id: obrigatório e no formato repo.* ou http.*`);
    } else if (c.check.type === 'manual') {
      if ('id' in c.check) errs.push(`${where}.check.id: controle manual não tem id de verificação`);
      text(c.howToVerify, `${where}.howToVerify`, errs, 900);
    }
  }
  if (!Array.isArray(c.refs) || c.refs.length === 0) {
    errs.push(`${where}.refs: informe ao menos uma referência`);
  } else {
    c.refs.forEach((r, i) => {
      const w = `${where}.refs[${i}]`;
      if (!isObj(r)) return errs.push(`${w}: deve ser objeto`);
      checkKeys(r, ['std', 'id'], ['note', 'covers'], w, errs);
      if (r.covers !== undefined) oneOf(r.covers, ['full', 'partial'], `${w}.covers`, errs);
      if (r.covers !== undefined && r.std !== 'ASVS') errs.push(`${w}.covers: só vale para referências ASVS`);
      text(r.std, `${w}.std`, errs, 40);
      text(r.id, `${w}.id`, errs, 80);
      if (r.note !== undefined) text(r.note, `${w}.note`, errs, 240);
      return undefined;
    });
  }
  if (!Array.isArray(c.origin) || c.origin.length === 0) {
    errs.push(`${where}.origin: informe ao menos uma lição de origem`);
  } else {
    c.origin.forEach((o, i) => {
      if (typeof o !== 'string' || !ID_LESSON.test(o)) errs.push(`${where}.origin[${i}]: id de lição inválido`);
    });
  }
  return errs;
}

function validateControlFile(f, where) {
  const errs = [];
  if (!isObj(f)) return [`${where}: arquivo deve ser objeto`];
  checkKeys(f, ['schemaVersion', 'pack', 'controls'], [], where, errs);
  if (f.schemaVersion !== 1) errs.push(`${where}.schemaVersion: use 1`);
  oneOf(f.pack, PACKS, `${where}.pack`, errs);
  if (!Array.isArray(f.controls)) errs.push(`${where}.controls: deve ser lista`);
  else {
    f.controls.forEach((c, i) => {
      errs.push(...validateControl(c, `${where}.controls[${i}]`));
      if (isObj(c) && c.pack !== f.pack) errs.push(`${where}.controls[${i}].pack: diferente do pacote do arquivo`);
    });
  }
  return errs;
}

function validatePacks(p) {
  const errs = [];
  if (!isObj(p)) return ['packs.json: deve ser objeto'];
  checkKeys(p, ['schemaVersion', 'catalogVersion', 'packs'], [], 'packs.json', errs);
  if (p.schemaVersion !== 1) errs.push('packs.json.schemaVersion: use 1');
  if (typeof p.catalogVersion !== 'string' || !/^\d+\.\d+\.\d+$/.test(p.catalogVersion)) errs.push('packs.json.catalogVersion: use semver X.Y.Z');
  if (!isObj(p.packs)) return [...errs, 'packs.json.packs: deve ser objeto'];
  for (const name of PACKS) {
    const e = p.packs[name];
    if (!isObj(e)) {
      errs.push(`packs.json.packs.${name}: ausente`);
      continue;
    }
    checkKeys(e, ['title', 'requires'], [], `packs.${name}`, errs);
    text(e.title, `packs.${name}.title`, errs, 120);
    if (!Array.isArray(e.requires)) errs.push(`packs.${name}.requires: deve ser lista`);
    else e.requires.forEach((f, i) => oneOf(f, FLAGS, `packs.${name}.requires[${i}]`, errs));
  }
  for (const k of Object.keys(p.packs)) if (!PACKS.includes(k)) errs.push(`packs.json.packs: pacote desconhecido "${k}"`);
  return errs;
}

function validateLessons(l) {
  const errs = [];
  if (!isObj(l)) return ['lessons.json: deve ser objeto'];
  checkKeys(l, ['schemaVersion', 'lessons'], [], 'lessons.json', errs);
  if (l.schemaVersion !== 1) errs.push('lessons.json.schemaVersion: use 1');
  if (!Array.isArray(l.lessons)) return [...errs, 'lessons.json.lessons: deve ser lista'];
  l.lessons.forEach((x, i) => {
    const w = `lessons[${i}]`;
    if (!isObj(x)) return errs.push(`${w}: deve ser objeto`);
    checkKeys(x, ['id', 'source', 'title', 'summary', 'controls'], [], w, errs);
    if (typeof x.id !== 'string' || !ID_LESSON.test(x.id)) errs.push(`${w}.id: formato inválido`);
    else if (LESSON_SOURCES[x.id[2]] !== x.source) errs.push(`${w}.source: não confere com o id (${x.id})`);
    text(x.title, `${w}.title`, errs, 140);
    text(x.summary, `${w}.summary`, errs, 700);
    if (!Array.isArray(x.controls) || x.controls.length === 0) errs.push(`${w}.controls: informe ao menos um controle`);
    else x.controls.forEach((c, j) => { if (typeof c !== 'string' || !ID_CONTROL.test(c)) errs.push(`${w}.controls[${j}]: id inválido`); });
    return undefined;
  });
  return errs;
}

function validateProfile(p) {
  const errs = [];
  if (!isObj(p)) return ['profile.json: deve ser objeto'];
  checkKeys(p, ['schemaVersion', 'name', 'flags'], ['urls', 'paths', 'thresholds', 'scan', 'agent'], 'profile', errs);
  if (p.schemaVersion !== 1) errs.push('profile.schemaVersion: use 1');
  text(p.name, 'profile.name', errs, 80);
  if (!isObj(p.flags)) errs.push('profile.flags: deve ser objeto');
  else {
    checkKeys(p.flags, FLAGS, [], 'profile.flags', errs);
    for (const f of FLAGS) if (f in p.flags && typeof p.flags[f] !== 'boolean') errs.push(`profile.flags.${f}: deve ser true ou false`);
  }
  if (p.urls !== undefined) {
    if (!isObj(p.urls)) errs.push('profile.urls: deve ser objeto');
    else {
      checkKeys(p.urls, [], ['staging', 'production'], 'profile.urls', errs);
      for (const [k, v] of Object.entries(p.urls)) if (typeof v !== 'string' || !/^https?:\/\//.test(v)) errs.push(`profile.urls.${k}: use http(s)://...`);
    }
  }
  if (p.paths !== undefined) {
    if (!isObj(p.paths)) errs.push('profile.paths: deve ser objeto');
    else {
      checkKeys(p.paths, [], ['health', 'login'], 'profile.paths', errs);
      for (const [k, v] of Object.entries(p.paths)) if (typeof v !== 'string' || !v.startsWith('/')) errs.push(`profile.paths.${k}: deve começar com /`);
    }
  }
  if (p.thresholds !== undefined) {
    if (!isObj(p.thresholds)) errs.push('profile.thresholds: deve ser objeto');
    else {
      checkKeys(p.thresholds, [], ['hstsMinSeconds', 'threatModelMaxAgeDays', 'alwaysOnInstructionBytes'], 'profile.thresholds', errs);
      for (const [k, v] of Object.entries(p.thresholds)) if (!Number.isInteger(v) || v <= 0) errs.push(`profile.thresholds.${k}: inteiro positivo`);
    }
  }
  if (p.scan !== undefined) {
    if (!isObj(p.scan)) errs.push('profile.scan: deve ser objeto');
    else {
      checkKeys(p.scan, [], ['excludePrefixes'], 'profile.scan', errs);
      if (p.scan.excludePrefixes !== undefined) stringList(p.scan.excludePrefixes, 'profile.scan.excludePrefixes', errs, { max: 100, itemMax: 200 });
    }
  }
  if (p.agent !== undefined) {
    if (!isObj(p.agent)) errs.push('profile.agent: deve ser objeto');
    else {
      checkKeys(p.agent, [], ['instructionPaths'], 'profile.agent', errs);
      if (p.agent.instructionPaths !== undefined) stringList(p.agent.instructionPaths, 'profile.agent.instructionPaths', errs, { max: 100, itemMax: 200 });
    }
  }
  return errs;
}

function validateRisk(r, where = 'risk') {
  const errs = [];
  if (!isObj(r)) return [`${where}: deve ser objeto`];
  checkKeys(r, ['schemaVersion', 'id', 'control', 'fingerprints', 'owner', 'approvedBy', 'justification', 'createdAt', 'expires'], ['scope', 'compensating'], where, errs);
  if (r.schemaVersion !== 1) errs.push(`${where}.schemaVersion: use 1`);
  if (typeof r.id !== 'string' || !ID_RISK.test(r.id)) errs.push(`${where}.id: formato RISK-0001`);
  if (typeof r.control !== 'string' || !ID_CONTROL.test(r.control)) errs.push(`${where}.control: id de controle inválido`);
  const scope = r.scope === undefined ? 'findings' : r.scope;
  oneOf(scope, ['findings', 'control'], `${where}.scope`, errs);
  if (!Array.isArray(r.fingerprints)) errs.push(`${where}.fingerprints: deve ser lista`);
  else {
    r.fingerprints.forEach((f, i) => { if (typeof f !== 'string' || !FINGERPRINT.test(f)) errs.push(`${where}.fingerprints[${i}]: 16 hexadecimais`); });
    if (scope === 'findings' && r.fingerprints.length === 0) errs.push(`${where}.fingerprints: informe ao menos uma (ou use scope "control")`);
  }
  text(r.owner, `${where}.owner`, errs, 120);
  text(r.approvedBy, `${where}.approvedBy`, errs, 120);
  text(r.justification, `${where}.justification`, errs, 900, 20);
  if (r.compensating !== undefined) stringList(r.compensating, `${where}.compensating`, errs, { max: 20 });
  date(r.createdAt, `${where}.createdAt`, errs);
  date(r.expires, `${where}.expires`, errs);
  return errs;
}

function validateTicket(t, where = 'ticket') {
  const errs = [];
  if (!isObj(t)) return [`${where}: deve ser objeto`];
  checkKeys(t, ['schemaVersion', 'id', 'control', 'type', 'priority', 'status', 'title', 'acceptance', 'createdAt'], ['summary', 'owner', 'risk', 'source'], where, errs);
  if (t.schemaVersion !== 1) errs.push(`${where}.schemaVersion: use 1`);
  if (typeof t.id !== 'string' || !ID_TICKET.test(t.id)) errs.push(`${where}.id: formato T-0001`);
  if (typeof t.control !== 'string' || !ID_CONTROL.test(t.control)) errs.push(`${where}.control: id de controle inválido`);
  oneOf(t.type, ['fix', 'verify'], `${where}.type`, errs);
  oneOf(t.priority, PRIORITIES, `${where}.priority`, errs);
  oneOf(t.status, TICKET_STATUS, `${where}.status`, errs);
  text(t.title, `${where}.title`, errs, 200);
  stringList(t.acceptance, `${where}.acceptance`, errs, { min: 1, max: 20 });
  date(t.createdAt, `${where}.createdAt`, errs);
  if (t.owner !== undefined && t.owner !== null) text(t.owner, `${where}.owner`, errs, 120);
  if (t.risk !== undefined && t.risk !== null && (typeof t.risk !== 'string' || !ID_RISK.test(t.risk))) errs.push(`${where}.risk: formato RISK-0001`);
  return errs;
}

function validateStatus(s) {
  const errs = [];
  if (!isObj(s)) return ['status.json: deve ser objeto'];
  checkKeys(s, ['schemaVersion', 'attestations'], [], 'status', errs);
  if (s.schemaVersion !== 1) errs.push('status.schemaVersion: use 1');
  if (!isObj(s.attestations)) return [...errs, 'status.attestations: deve ser objeto'];
  for (const [id, a] of Object.entries(s.attestations)) {
    const w = `status.attestations.${id}`;
    if (!ID_CONTROL.test(id)) errs.push(`${w}: id de controle inválido`);
    if (!isObj(a)) { errs.push(`${w}: deve ser objeto`); continue; }
    checkKeys(a, ['state', 'attestedBy', 'collectedAt', 'expiresAt'], ['evidenceRef', 'note'], w, errs);
    oneOf(a.state, ['verified'], `${w}.state`, errs);
    text(a.attestedBy, `${w}.attestedBy`, errs, 120);
    date(a.collectedAt, `${w}.collectedAt`, errs);
    date(a.expiresAt, `${w}.expiresAt`, errs);
    if (a.evidenceRef !== undefined) text(a.evidenceRef, `${w}.evidenceRef`, errs, 300);
    if (a.note !== undefined) text(a.note, `${w}.note`, errs, 400);
  }
  return errs;
}

function validateAssets(a) {
  const errs = [];
  if (!isObj(a)) return ['assets.json: deve ser objeto'];
  checkKeys(a, ['schemaVersion', 'assets'], [], 'assets', errs);
  if (a.schemaVersion !== 1) errs.push('assets.schemaVersion: use 1');
  if (!Array.isArray(a.assets)) return [...errs, 'assets.assets: deve ser lista'];
  a.assets.forEach((x, i) => {
    const w = `assets[${i}]`;
    if (!isObj(x)) return errs.push(`${w}: deve ser objeto`);
    checkKeys(x, ['path', 'source', 'license', 'attestedBy', 'attestedAt'], ['note'], w, errs);
    text(x.path, `${w}.path`, errs, 300);
    text(x.source, `${w}.source`, errs, 300);
    text(x.license, `${w}.license`, errs, 200);
    text(x.attestedBy, `${w}.attestedBy`, errs, 120);
    date(x.attestedAt, `${w}.attestedAt`, errs);
    return undefined;
  });
  return errs;
}

function validateBaseline(b) {
  const errs = [];
  if (!isObj(b)) return ['baseline.json: deve ser objeto'];
  checkKeys(b, ['schemaVersion', 'generatedAt', 'fingerprints'], ['note'], 'baseline', errs);
  if (b.schemaVersion !== 1) errs.push('baseline.schemaVersion: use 1');
  date(b.generatedAt, 'baseline.generatedAt', errs);
  if (!Array.isArray(b.fingerprints)) errs.push('baseline.fingerprints: deve ser lista');
  else b.fingerprints.forEach((f, i) => { if (typeof f !== 'string' || !FINGERPRINT.test(f)) errs.push(`baseline.fingerprints[${i}]: 16 hexadecimais`); });
  return errs;
}

const ID_ASVS = /^V\d{1,2}\.\d{1,2}\.\d{1,2}$/;

/** Mapa de requisitos do ASVS: somente IDs e nível mínimo (sem texto da norma). */
function validateAsvsMap(m) {
  const errs = [];
  if (!isObj(m)) return ['asvs-map.json: deve ser objeto'];
  checkKeys(m, ['schemaVersion', 'standard', 'version', 'source', 'requirements', 'notApplicable'], [], 'asvs-map', errs);
  if (m.schemaVersion !== 1) errs.push('asvs-map.schemaVersion: use 1');
  if (m.standard !== 'ASVS') errs.push('asvs-map.standard: use "ASVS"');
  text(m.version, 'asvs-map.version', errs, 20);
  text(m.source, 'asvs-map.source', errs, 300);
  if (!isObj(m.requirements)) return [...errs, 'asvs-map.requirements: deve ser objeto'];
  for (const [id, lv] of Object.entries(m.requirements)) {
    if (!ID_ASVS.test(id)) errs.push(`asvs-map.requirements: id inválido "${id}"`);
    if (![1, 2, 3].includes(lv)) errs.push(`asvs-map.requirements.${id}: nível deve ser 1, 2 ou 3`);
  }
  if (Object.keys(m.requirements).length === 0) errs.push('asvs-map.requirements: vazio');
  if (!isObj(m.notApplicable)) errs.push('asvs-map.notApplicable: deve ser objeto');
  else {
    for (const [id, why] of Object.entries(m.notApplicable)) {
      if (!(id in m.requirements)) errs.push(`asvs-map.notApplicable: "${id}" não está em requirements`);
      text(why, `asvs-map.notApplicable.${id}`, errs, 300, 15);
    }
  }
  return errs;
}

module.exports = {
  ID_ASVS, validateAsvsMap,
  FLAGS, SEVERITIES, PHASES, ENFORCEMENT, PACKS, PACK_PREFIX, CHECK_TYPES, TICKET_STATUS, PRIORITIES, LESSON_SOURCES,
  ID_CONTROL, ID_LESSON, ID_RISK, ID_TICKET, ID_CHECK, FINGERPRINT,
  validateControl, validateControlFile, validatePacks, validateLessons, validateProfile,
  validateRisk, validateTicket, validateStatus, validateAssets, validateBaseline,
};
