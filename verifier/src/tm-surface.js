'use strict';

// Assinatura da superfície da aplicação, para o modelo de ameaças acompanhar o código. Guarda só o que muda a
// superfície de ataque (módulos e quantidade de rotas, tabelas, armazenamento, tempo real, upload, hosts externos),
// nunca caminho de arquivo, valor ou segredo. Comparar a assinatura gravada com a de agora diz o que mudou.

const crypto = require('node:crypto');

const LIMIT = 60;

function signature(disc) {
  const summary = {
    modules: (disc.modules || []).filter((m) => !/^outras /.test(m.prefix)).map((m) => `${m.prefix}:${m.routes}`).sort().slice(0, LIMIT),
    tables: (disc.tables || []).map((t) => t.name).sort().slice(0, LIMIT),
    stores: [...(disc.stores || [])].sort(),
    realtime: [...(disc.realtime || [])].sort(),
    uploads: [...(disc.uploads || [])].sort(),
    externalHosts: [...(disc.externalHosts || [])].sort().slice(0, 20),
    routes: (disc.routes && disc.routes.total) || 0,
  };
  const hash = crypto.createHash('sha256').update(JSON.stringify(summary)).digest('hex').slice(0, 16);
  return { hash, summary };
}

const LABEL = { tables: 'tabela', stores: 'armazenamento', realtime: 'tempo real', uploads: 'upload', externalHosts: 'host externo' };

/** O que mudou entre duas assinaturas, em frases curtas. */
function diffSurface(prev, cur) {
  if (!prev || !prev.summary || !cur) return [];
  if (prev.hash === cur.hash) return [];
  const out = [];
  const mods = (s) => new Map((s.modules || []).map((x) => { const i = x.lastIndexOf(':'); return [x.slice(0, i), Number(x.slice(i + 1))]; }));
  const a = mods(prev.summary);
  const b = mods(cur.summary);
  for (const [p, n] of b) {
    if (!a.has(p)) out.push(`módulo novo ${p} (${n} rota(s))`);
    else if (a.get(p) !== n) out.push(`${p}: ${a.get(p)} → ${n} rota(s)`);
  }
  for (const p of a.keys()) if (!b.has(p)) out.push(`módulo removido ${p}`);
  for (const k of Object.keys(LABEL)) {
    const was = new Set(prev.summary[k] || []);
    const now = new Set(cur.summary[k] || []);
    for (const x of now) if (!was.has(x)) out.push(`${LABEL[k]} novo: ${x}`);
    for (const x of was) if (!now.has(x)) out.push(`${LABEL[k]} removido: ${x}`);
  }
  if (!out.length && prev.summary.routes !== cur.summary.routes) out.push(`rotas: ${prev.summary.routes} → ${cur.summary.routes}`);
  return out.length ? out : ['a superfície mudou'];
}

function validateSurface(s, errs) {
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (!isObj(s)) { errs.push('threat-model.surface: deve ser objeto'); return; }
  for (const k of Object.keys(s)) if (!['hash', 'changedAt', 'summary'].includes(k)) errs.push(`threat-model.surface: campo desconhecido "${k}"`);
  if (typeof s.hash !== 'string' || !/^[0-9a-f]{16}$/.test(s.hash)) errs.push('threat-model.surface.hash: 16 caracteres hexadecimais');
  // changedAt só existe depois da primeira mudança real; a primeira gravação da assinatura não é mudança.
  if (s.changedAt !== undefined && (typeof s.changedAt !== 'string' || Number.isNaN(Date.parse(s.changedAt)))) errs.push('threat-model.surface.changedAt: data inválida');
  if (!isObj(s.summary) || JSON.stringify(s.summary).length > 20000) errs.push('threat-model.surface.summary: objeto de até 20000 caracteres');
}

module.exports = { signature, diffSurface, validateSurface };
