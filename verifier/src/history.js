'use strict';

// Histórico das execuções (.lastro/history/). Cada registro guarda só números, IDs e estados: nada de caminho,
// mensagem de achado, segredo ou URL. Assim ele pode ser versionado e publicado como artefato do CI sem expor nada.
// Registro inválido é ignorado com aviso (nunca vira dado do gráfico), e nenhum registro é sobrescrito.

const fs = require('node:fs');
const path = require('node:path');
const U = require('./util');

const DIR = '.lastro/history';
const STATES = ['verified', 'failed', 'unverified', 'not_applicable'];
const ID = /^[A-Z]+-\d{3}$/;
const FILE = /^\d{8}T\d{6}Z(-\d+)?\.json$/;
const MAX_FILES = 500;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const n = (v) => (Number.isFinite(v) ? v : 0);

function tally(t) {
  const x = t || {};
  return { critical: n(x.critical), high: n(x.high), medium: n(x.medium), low: n(x.low) };
}

/** Registro compacto de uma execução do lastro check. */
function snapshot(report) {
  const controls = {};
  for (const c of report.controls) controls[c.id] = c.state;
  const tm = (report.threatModel && report.threatModel.counts) || {};
  return {
    schemaVersion: 1,
    generatedAt: report.generatedAt,
    tool: report.tool.version,
    catalog: report.catalogVersion,
    name: report.profile.name,
    verdict: report.verdict,
    grade: report.score.grade,
    provenPct: report.score.provenPct,
    machinePct: report.score.machinePct,
    attestedPct: report.score.attestedPct,
    failedPct: report.score.failedPct,
    partialPct: report.score.partialPct || 0,
    automatedPassRatePct: report.score.automated.passRatePct,
    summary: {
      applicable: report.summary.applicable, verified: report.summary.verified, failed: report.summary.failed,
      unverified: report.summary.unverified, blocking: report.summary.blocking, debt: report.summary.debt,
    },
    risk: { confirmed: tally(report.risk.summary.confirmed), potential: tally(report.risk.summary.potential) },
    threats: { total: n(tm.threats), exposed: n(tm.exposed), mitigated: n(tm.mitigated), pending: n(tm.pending) },
    http: !!report.target.url,
    // Que sondas rodaram: comparar uma execução com --active com outra só com --auth mistura medidas diferentes.
    active: !!(report.target.url && report.target.active),
    auth: !!(report.target.url && report.target.authProbes),
    controls,
  };
}

function validateSnapshot(s) {
  const errs = [];
  if (!isObj(s)) return ['registro deve ser objeto'];
  if (s.schemaVersion !== 1) errs.push('schemaVersion: use 1');
  if (U.parseDate(s.generatedAt) === null) errs.push('generatedAt: data inválida');
  if (typeof s.name !== 'string' || s.name.length > 80) errs.push('name: texto de até 80 caracteres');
  if (!['pass', 'fail', 'incomplete'].includes(s.verdict)) errs.push('verdict inválido');
  // A nota (grade, 0 a 10) é o número do kit. Registros antigos podem ter só o nível de 0 a 4 (level), já descontinuado.
  if (s.grade === undefined && s.level === undefined) errs.push('grade: obrigatório (nota de 0 a 10)');
  if (s.grade !== undefined && !(Number.isFinite(s.grade) && s.grade >= 0 && s.grade <= 10)) errs.push('grade: 0 a 10');
  if (s.level !== undefined && !(Number.isInteger(s.level) && s.level >= 0 && s.level <= 4)) errs.push('level (registro antigo): 0 a 4');
  for (const k of ['http', 'active', 'auth']) if (s[k] !== undefined && typeof s[k] !== 'boolean') errs.push(`${k}: verdadeiro ou falso`);
  if (s.partialPct !== undefined && !(Number.isFinite(s.partialPct) && s.partialPct >= 0 && s.partialPct <= 100)) errs.push('partialPct: 0 a 100');
  for (const k of ['provenPct', 'machinePct', 'attestedPct', 'failedPct']) if (!Number.isFinite(s[k]) || s[k] < 0 || s[k] > 100) errs.push(`${k}: 0 a 100`);
  if (s.automatedPassRatePct !== null && !(Number.isFinite(s.automatedPassRatePct) && s.automatedPassRatePct >= 0 && s.automatedPassRatePct <= 100)) errs.push('automatedPassRatePct: 0 a 100 ou null');
  if (!isObj(s.summary) || !isObj(s.risk) || !isObj(s.threats)) errs.push('summary, risk e threats são obrigatórios');
  if (!isObj(s.controls)) errs.push('controls deve ser objeto');
  else for (const [id, st] of Object.entries(s.controls)) if (!ID.test(id) || !STATES.includes(st)) { errs.push(`controls.${id}: id ou estado inválido`); break; }
  return errs;
}

/** Lê o histórico em ordem cronológica. Devolve { items, warnings }. */
function loadHistory(root) {
  const dir = path.join(root, DIR);
  let names = [];
  try { names = fs.readdirSync(dir).filter((f) => FILE.test(f)).sort(); } catch (e) { return { items: [], warnings: [] }; }
  const warnings = [];
  if (names.length > MAX_FILES) {
    warnings.push(`${DIR} tem ${names.length} registros: só os ${MAX_FILES} mais recentes entram.`);
    names = names.slice(-MAX_FILES);
  }
  const items = [];
  for (const f of names) {
    const j = U.readJson(root, `${DIR}/${f}`);
    const errs = j.ok ? validateSnapshot(j.value) : [j.error];
    if (errs.length) { warnings.push(`${DIR}/${f} ignorado: ${errs[0]}`); continue; }
    items.push(j.value);
  }
  items.sort((a, b) => U.parseDate(a.generatedAt) - U.parseDate(b.generatedAt));
  return { items, warnings };
}

function fileNameFor(snap) {
  return `${snap.generatedAt.replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')}.json`;
}

/** Grava um registro novo. Nunca sobrescreve: se o nome já existe, acrescenta um sufixo. */
function writeSnapshot(root, snap) {
  const errs = validateSnapshot(snap);
  if (errs.length) throw new Error(`registro inválido: ${errs[0]}`);
  const dir = path.join(root, DIR);
  fs.mkdirSync(dir, { recursive: true });
  const base = fileNameFor(snap).replace(/\.json$/, '');
  for (let i = 0; i < 100; i += 1) {
    const name = i === 0 ? `${base}.json` : `${base}-${i}.json`;
    try {
      fs.writeFileSync(path.join(dir, name), `${JSON.stringify(snap, null, 2)}\n`, { flag: 'wx' });
      return `${DIR}/${name}`;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
    }
  }
  throw new Error('não foi possível escolher um nome livre para o registro');
}

const RANK = { verified: 3, not_applicable: 2, unverified: 1, failed: 0 };

/** O que mudou entre dois registros: controles que melhoraram, pioraram, entraram e saíram. */
function diff(prev, cur) {
  const out = { improved: [], worsened: [], added: [], removed: [] };
  if (!prev) return out;
  for (const [id, st] of Object.entries(cur.controls)) {
    const before = prev.controls[id];
    if (before === undefined) out.added.push({ id, to: st });
    else if (before !== st) (RANK[st] > RANK[before] ? out.improved : out.worsened).push({ id, from: before, to: st });
  }
  for (const id of Object.keys(prev.controls)) if (!(id in cur.controls)) out.removed.push({ id, from: prev.controls[id] });
  for (const k of Object.keys(out)) out[k].sort((a, b) => a.id.localeCompare(b.id));
  return out;
}

module.exports = { DIR, snapshot, validateSnapshot, loadHistory, writeSnapshot, diff, fileNameFor };
