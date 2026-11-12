'use strict';

// Mapa e cobertura do OWASP ASVS 5.0. O kit guarda só IDs e o nível mínimo de cada requisito.
// O texto da norma (CC BY-SA) não é copiado: o CSV oficial é lido em tempo de execução, nunca versionado.

const fs = require('node:fs');
const path = require('node:path');
const { ID_ASVS } = require('./schema');

const ASVS_VERSION = '5.0.0';
const ASVS_SOURCE = 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv';

// Nomes dos capítulos escritos aqui, em português, com palavras próprias.
const CHAPTERS = {
  V1: 'Codificação e sanitização',
  V2: 'Validação e lógica de negócio',
  V3: 'Segurança do frontend web',
  V4: 'API e serviços web',
  V5: 'Tratamento de arquivos',
  V6: 'Autenticação',
  V7: 'Gestão de sessão',
  V8: 'Autorização',
  V9: 'Tokens autocontidos',
  V10: 'OAuth e OIDC',
  V11: 'Criptografia',
  V12: 'Comunicação segura',
  V13: 'Configuração',
  V14: 'Proteção de dados',
  V15: 'Código seguro e arquitetura',
  V16: 'Registro de eventos e tratamento de erros',
  V17: 'WebRTC',
};

/** Leitor de CSV (RFC 4180): aspas, aspas duplas escapadas e quebras de linha dentro de campo. */
function parseCsv(input) {
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 1; } else quoted = false;
      } else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i += 1;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += ch;
  }
  if (quoted) throw new Error('CSV malformado: aspas não fechadas');
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function compareIds(a, b) {
  const pa = a.slice(1).split('.').map(Number);
  const pb = b.slice(1).split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

/** Extrai { id: nível } do CSV oficial. Falha se o formato não for o esperado. */
function requirementsFromCsv(csvText) {
  const rows = parseCsv(csvText);
  if (rows.length < 2) throw new Error('CSV sem linhas de dados');
  const head = rows[0].map((h) => h.trim());
  const iId = head.indexOf('req_id');
  const iLv = head.indexOf('L');
  if (iId < 0 || iLv < 0) throw new Error('CSV sem as colunas "req_id" e "L" (formato inesperado)');
  const out = {};
  for (const r of rows.slice(1)) {
    const id = (r[iId] || '').trim();
    if (!id) continue;
    if (!ID_ASVS.test(id)) throw new Error(`ID de requisito inválido no CSV: "${id}"`);
    const lv = Number(r[iLv]);
    if (![1, 2, 3].includes(lv)) throw new Error(`Nível inválido para ${id}: "${r[iLv]}"`);
    if (id in out) throw new Error(`Requisito duplicado no CSV: ${id}`);
    out[id] = lv;
  }
  if (Object.keys(out).length === 0) throw new Error('Nenhum requisito encontrado no CSV');
  return out;
}

function buildMap(requirements, previous) {
  const ids = Object.keys(requirements).sort(compareIds);
  const reqs = {};
  for (const id of ids) reqs[id] = requirements[id];
  const prevNa = (previous && previous.notApplicable) || {};
  const notApplicable = {};
  for (const id of Object.keys(prevNa).sort(compareIds)) if (id in reqs) notApplicable[id] = prevNa[id];
  return { schemaVersion: 1, standard: 'ASVS', version: ASVS_VERSION, source: ASVS_SOURCE, requirements: reqs, notApplicable };
}

/** Confere o mapa versionado contra os requisitos lidos do CSV oficial. */
function verifyMap(map, requirements) {
  const errs = [];
  for (const [id, lv] of Object.entries(requirements)) {
    if (!(id in map.requirements)) errs.push(`Falta no mapa: ${id}`);
    else if (map.requirements[id] !== lv) errs.push(`Nível diferente em ${id}: mapa=${map.requirements[id]}, oficial=${lv}`);
  }
  for (const id of Object.keys(map.requirements)) if (!(id in requirements)) errs.push(`No mapa, mas inexistente no CSV oficial: ${id}`);
  return errs;
}

function loadAsvsMap(catalogDir) {
  const file = path.join(catalogDir, 'asvs-map.json');
  try {
    return { ok: true, value: JSON.parse(fs.readFileSync(file, 'utf8')), file };
  } catch (e) {
    return { ok: false, error: `asvs-map.json: ${e.message}`, file };
  }
}

/** Índice requisito → controles do catálogo que o citam. */
function citations(controls) {
  const idx = new Map();
  for (const c of controls) {
    for (const r of c.refs || []) {
      if (r.std !== 'ASVS') continue;
      if (!idx.has(r.id)) idx.set(r.id, []);
      if (!idx.get(r.id).includes(c)) idx.get(r.id).push(c);
    }
  }
  return idx;
}

/**
 * Cobertura por capítulo, até o nível pedido (1, 2 ou 3; o nível 2 inclui o 1).
 * "Citado" significa que algum controle referencia o requisito. Não significa que o controle o cobre por inteiro.
 * Com `states` (id do controle → estado do último check), mostra também o que está verificado, falhando ou sem prova.
 */
function refOf(control, id) {
  return (control.refs || []).find((r) => r.std === 'ASVS' && r.id === id);
}

/** Profundidade da citação: "full" se algum controle cobre por inteiro; "partial" se classificado como parcial; senão "unclassified". */
function depthOf(controls, id) {
  const ds = controls.map((c) => (refOf(c, id) || {}).covers);
  if (ds.includes('full')) return 'full';
  if (ds.includes('partial')) return 'partial';
  return 'unclassified';
}

function coverage(controls, map, { level = 2, states = null } = {}) {
  const idx = citations(controls);
  const byChapter = {};
  const totals = blank();
  function blank() {
    return {
      total: 0, automated: 0, manual: 0, none: 0, notApplicable: 0,
      full: 0, partial: 0, unclassified: 0,
      verified: 0, failed: 0, unverified: 0, outOfProfile: 0,
    };
  }
  const uncited = [];
  for (const id of Object.keys(map.requirements).sort(compareIds)) {
    if (map.requirements[id] > level) continue;
    const ch = id.split('.')[0];
    const b = (byChapter[ch] = byChapter[ch] || { name: CHAPTERS[ch] || ch, ...blank() });
    b.total += 1; totals.total += 1;
    if (id in map.notApplicable) { b.notApplicable += 1; totals.notApplicable += 1; continue; }
    const cs = idx.get(id) || [];
    if (cs.length === 0) { b.none += 1; totals.none += 1; uncited.push(id); continue; }
    const kind = cs.some((c) => c.check.type === 'automated') ? 'automated' : 'manual';
    b[kind] += 1; totals[kind] += 1;
    const depth = depthOf(cs, id);
    b[depth] += 1; totals[depth] += 1;
    if (states) {
      const live = cs.filter((c) => states.has(c.id) && states.get(c.id) !== 'not_applicable');
      let st;
      // Verificado exige um controle que cobre o requisito por inteiro e está verificado, sem nenhuma falha entre os ligados.
      const fullVerified = live.some((c) => (refOf(c, id) || {}).covers === 'full' && states.get(c.id) === 'verified');
      if (live.length === 0) st = 'outOfProfile';
      else if (live.some((c) => states.get(c.id) === 'failed')) st = 'failed';
      else if (fullVerified) st = 'verified';
      else st = 'unverified';
      b[st] += 1; totals[st] += 1;
    }
  }
  return { level, version: map.version, totals, byChapter, uncited, withState: !!states };
}

function pct(n, d) {
  return d === 0 ? '0%' : `${Math.round((n / d) * 100)}%`;
}

function formatCoverage(cov) {
  const t = cov.totals;
  const out = [];
  out.push(`ASVS ${cov.version} | nível alvo L${cov.level} (acumulado) | ${t.total} requisitos`);
  const cited = t.automated + t.manual;
  out.push(`Citados por algum controle: ${cited} (${pct(cited, t.total)}) | por verificação automática: ${t.automated} | só por controle manual: ${t.manual} | sem controle: ${t.none} | não se aplicam: ${t.notApplicable}`);
  out.push(`Profundidade: coberto por inteiro ${t.full} (${pct(t.full, t.total)}) | parcial ${t.partial} | ainda não classificado ${t.unclassified}`);
  if (cov.withState) {
    out.push(`Estado no projeto: verificados ${t.verified} (${pct(t.verified, t.total)}) | com falha ${t.failed} | sem prova ${t.unverified} | fora do perfil ${t.outOfProfile} | sem controle ${t.none}`);
  }
  out.push('');
  const head = ['Cap', 'Nome', 'Total', 'Auto', 'Manual', 'Sem', 'N/A', 'Inteiro', 'Parcial', 'N/class'];
  if (cov.withState) head.push('Verif', 'Falha', 'S/prova', 'Fora');
  const rows = [head];
  for (const ch of Object.keys(cov.byChapter).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)))) {
    const b = cov.byChapter[ch];
    const r = [ch, b.name, b.total, b.automated, b.manual, b.none, b.notApplicable, b.full, b.partial, b.unclassified];
    if (cov.withState) r.push(b.verified, b.failed, b.unverified, b.outOfProfile);
    rows.push(r.map(String));
  }
  const w = head.map((_, i) => Math.max(...rows.map((r) => String(r[i]).length)));
  for (const r of rows) out.push(r.map((c, i) => (i === 1 ? String(c).padEnd(w[i]) : String(c).padStart(w[i]))).join('  '));
  out.push('');
  out.push('Atenção: "citado" não é "coberto por inteiro". Só os capítulos já classificados distinguem cobertura inteira de');
  out.push('parcial; nos demais, "não classificado" quer dizer que a referência existe, mas ninguém avaliou o quanto ela cobre.');
  out.push('Estes números medem progresso do kit, não conformidade da aplicação.');
  return out.join('\n');
}

module.exports = {
  CHAPTERS, ASVS_VERSION, ASVS_SOURCE, parseCsv, requirementsFromCsv, buildMap, verifyMap, loadAsvsMap, citations, coverage, formatCoverage, compareIds,
};
