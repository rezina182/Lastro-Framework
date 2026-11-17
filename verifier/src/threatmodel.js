'use strict';

// Modelo de ameaças assistido. O kit gera um RASCUNHO a partir do que enxerga (perfil, catálogo e descoberta do
// repositório) e pergunta; a decisão é de uma pessoa. Rascunho não é prova: o CORE-012 só passa quando o modelo
// foi revisado, com todas as ameaças decididas, dentro do prazo.
//
// Ameaça = categoria STRIDE x superfície da aplicação, com id estável (TM-S-auth). As mitigações são os controles
// de segurança aplicáveis daquela categoria e superfície, e o estado da ameaça vem do estado desses controles.
// Só as decisões humanas são gravadas em `.lastro/threat-model.json`; o resto é recalculado a cada execução.

const fs = require('node:fs');
const path = require('node:path');
const U = require('./util');
const { discover } = require('./discover');

const STRIDE = {
  S: { name: 'Falsificação de identidade', en: 'Spoofing', ask: 'Quem poderia se passar por outro usuário, sistema ou componente, e o que ganharia com isso?' },
  T: { name: 'Adulteração', en: 'Tampering', ask: 'O que poderia ser alterado sem autorização (dado, código, configuração, mensagem), e quem se beneficiaria?' },
  R: { name: 'Repúdio', en: 'Repudiation', ask: 'Que ação importante alguém poderia negar ter feito, e os registros bastariam para provar o contrário?' },
  I: { name: 'Divulgação de informação', en: 'Information disclosure', ask: 'Que dado poderia vazar ou ser lido por quem não deve, e qual seria o pior caso?' },
  D: { name: 'Negação de serviço', en: 'Denial of service', ask: 'O que um usuário, ou um robô, poderia fazer para deixar o serviço lento ou fora do ar, ou esgotar um recurso?' },
  E: { name: 'Elevação de privilégio', en: 'Elevation of privilege', ask: 'Como alguém com menos permissão conseguiria fazer o que só outro papel pode, ou acessar o dado de outro usuário?' },
};

const SURFACES = {
  web: 'Interface web e API',
  auth: 'Autenticação e sessão',
  data: 'Dados e comunicações',
  realtime: 'Tempo real (WebSocket ou SSE)',
  uploads: 'Upload de arquivos',
  pipeline: 'Desenvolvimento, CI e cadeia de suprimentos',
  agent: 'Agente de IA no desenvolvimento',
};

const DECISIONS = ['mitigate', 'accept', 'not_applicable'];
const DECISION_PT = { mitigate: 'mitigar', accept: 'aceitar', not_applicable: 'não se aplica' };
const ID_THREAT = /^TM-[STRIDE]-(web|auth|data|realtime|uploads|pipeline|agent)$/;
const FILE = '.lastro/threat-model.json';
const E_CWE = new Set([862, 863, 639, 284, 285, 269, 250, 653, 915, 732]);
const AUTH_LABEL = { visivel: 'autenticação visível na rota', global: 'coberta por middleware global anterior', 'publica-esperada': 'pública esperada (login, saúde, estáticos...)', 'nao-vista': 'autenticação não vista' };

/** Categorias STRIDE de um controle, derivadas dos pilares e das CWE (regra documentada em docs/THREAT-MODEL-ASSISTIDO.md). */
function strideOf(entry) {
  const p = entry.pillars || '';
  const s = [];
  if (p.includes('A')) s.push('S');
  if (p.includes('I')) s.push('T');
  if (p.includes('N') || p.includes('U')) s.push('R');
  if (p.includes('C') || p.includes('P')) s.push('I');
  if (p.includes('D')) s.push('D');
  if ((entry.cwe || []).some((n) => E_CWE.has(n))) s.push('E');
  return s;
}

function surfaceOf(control, entry) {
  switch (control.pack) {
    case 'web': return 'web';
    case 'auth': return 'auth';
    case 'realtime': return 'realtime';
    case 'uploads': return 'uploads';
    case 'pii': return 'data';
    case 'agent': return 'agent';
    case 'assets': return 'pipeline';
    default: {
      const reach = entry.reach || 'internet';
      return reach === 'pipeline' ? 'pipeline' : reach === 'internet' ? 'web' : 'data';
    }
  }
}

function loadFile(root) {
  if (!U.exists(root, FILE)) return null;
  const j = U.readJson(root, FILE);
  return j;
}

function validateModel(m) {
  const errs = [];
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (!isObj(m)) return ['threat-model.json: deve ser objeto'];
  const allowed = ['schemaVersion', 'generatedAt', 'reviewedBy', 'reviewedAt', 'note', 'assets', 'threats'];
  for (const k of Object.keys(m)) if (!allowed.includes(k)) errs.push(`threat-model: campo desconhecido "${k}"`);
  if (m.schemaVersion !== 1) errs.push('threat-model.schemaVersion: use 1');
  if (U.parseDate(m.generatedAt) === null) errs.push('threat-model.generatedAt: data inválida');
  if (m.reviewedAt !== undefined && U.parseDate(m.reviewedAt) === null) errs.push('threat-model.reviewedAt: data inválida');
  if (m.reviewedBy !== undefined && (typeof m.reviewedBy !== 'string' || m.reviewedBy.trim().length < 2 || m.reviewedBy.length > 120)) errs.push('threat-model.reviewedBy: texto de 2 a 120 caracteres');
  if (m.note !== undefined && (typeof m.note !== 'string' || m.note.length > 500)) errs.push('threat-model.note: até 500 caracteres');
  if (!Array.isArray(m.assets) || m.assets.length > 60) errs.push('threat-model.assets: lista de até 60 itens');
  else {
    m.assets.forEach((a, i) => {
      const w = `threat-model.assets[${i}]`;
      if (!isObj(a)) { errs.push(`${w}: deve ser objeto`); return; }
      for (const k of Object.keys(a)) if (!['id', 'name', 'kind', 'source', 'note'].includes(k)) errs.push(`${w}: campo desconhecido "${k}"`);
      if (typeof a.id !== 'string' || !/^A-\d{2}$/.test(a.id)) errs.push(`${w}.id: formato A-01`);
      if (typeof a.name !== 'string' || a.name.trim().length < 2 || a.name.length > 140) errs.push(`${w}.name: texto de 2 a 140 caracteres`);
      if (!['dado', 'credencial', 'servico', 'codigo', 'outro'].includes(a.kind)) errs.push(`${w}.kind: dado|credencial|servico|codigo|outro`);
      if (!['declarado', 'descoberto', 'revisado'].includes(a.source)) errs.push(`${w}.source: declarado|descoberto|revisado`);
      if (a.note !== undefined && (typeof a.note !== 'string' || a.note.length > 300)) errs.push(`${w}.note: até 300 caracteres`);
    });
  }
  if (!Array.isArray(m.threats) || m.threats.length > 80) errs.push('threat-model.threats: lista de até 80 itens');
  else {
    const seen = new Set();
    m.threats.forEach((t, i) => {
      const w = `threat-model.threats[${i}]`;
      if (!isObj(t)) { errs.push(`${w}: deve ser objeto`); return; }
      for (const k of Object.keys(t)) if (!['id', 'title', 'decision', 'rationale', 'owner', 'expires', 'likelihood'].includes(k)) errs.push(`${w}: campo desconhecido "${k}"`);
      if (typeof t.id !== 'string' || !ID_THREAT.test(t.id)) errs.push(`${w}.id: formato TM-S-web (categoria STRIDE e superfície conhecidas)`);
      else if (seen.has(t.id)) errs.push(`${w}.id: duplicado (${t.id})`);
      else seen.add(t.id);
      if (t.decision !== null && !DECISIONS.includes(t.decision)) errs.push(`${w}.decision: null|${DECISIONS.join('|')}`);
      if (t.likelihood !== undefined && !(Number.isInteger(t.likelihood) && t.likelihood >= 1 && t.likelihood <= 4)) errs.push(`${w}.likelihood: inteiro de 1 a 4`);
      if (t.rationale !== undefined && (typeof t.rationale !== 'string' || t.rationale.length > 600)) errs.push(`${w}.rationale: até 600 caracteres`);
      if (t.owner !== undefined && (typeof t.owner !== 'string' || t.owner.trim().length < 2 || t.owner.length > 120)) errs.push(`${w}.owner: texto de 2 a 120 caracteres`);
      if (t.expires !== undefined && U.parseDate(t.expires) === null) errs.push(`${w}.expires: data inválida`);
      if (t.decision === 'accept') {
        if (typeof t.rationale !== 'string' || t.rationale.trim().length < 20) errs.push(`${w}: aceitar exige rationale com ao menos 20 caracteres`);
        if (!t.owner) errs.push(`${w}: aceitar exige owner`);
        if (!t.expires) errs.push(`${w}: aceitar exige expires`);
      }
      if (t.decision === 'not_applicable' && (typeof t.rationale !== 'string' || t.rationale.trim().length < 20)) errs.push(`${w}: "não se aplica" exige rationale com ao menos 20 caracteres`);
    });
  }
  return errs;
}

/** Decisão ainda pendente? (sem decisão, ou aceitação vencida). */
function isPending(t, now) {
  if (!t || t.decision === null || t.decision === undefined) return true;
  if (t.decision === 'accept') {
    const exp = U.parseDate(t.expires);
    return exp === null || exp <= now.getTime();
  }
  return false;
}

/**
 * Avalia o arquivo persistido para o CORE-012. Devolve a lista de problemas (vazia = modelo em dia).
 */
function evaluateFile(model, now, maxAgeDays) {
  const problems = [];
  const errs = validateModel(model);
  if (errs.length) return [{ key: 'tm-invalid', severity: 'medium', message: `threat-model.json inválido: ${errs[0]}` }];
  const pending = model.threats.filter((t) => isPending(t, now));
  if (!model.reviewedBy || !model.reviewedAt) problems.push({ key: 'tm-draft', severity: 'high', message: 'O modelo de ameaças é um rascunho: ninguém o revisou (reviewedBy e reviewedAt).' });
  if (model.threats.length === 0) problems.push({ key: 'tm-empty', severity: 'high', message: 'O modelo de ameaças não tem nenhuma ameaça. Rode "lastro threat-model --write".' });
  if (pending.length) problems.push({ key: 'tm-pending', severity: 'medium', message: `${pending.length} ameaça(s) sem decisão ou com aceitação vencida: ${pending.slice(0, 6).map((t) => t.id).join(', ')}${pending.length > 6 ? '...' : ''}.` });
  if (model.reviewedAt) {
    const ts = U.parseDate(model.reviewedAt);
    const age = Math.floor((now.getTime() - ts) / (24 * 60 * 60 * 1000));
    if (ts > now.getTime() + 24 * 60 * 60 * 1000) problems.push({ key: 'tm-future', severity: 'medium', message: 'Data de revisão do modelo de ameaças no futuro.' });
    else if (age > maxAgeDays) problems.push({ key: 'tm-stale', severity: 'medium', message: `Modelo de ameaças sem revisão há ${age} dias (limite ${maxAgeDays}).` });
  }
  return problems;
}

function draftAssets(profile, disc) {
  const f = profile.flags || {};
  const ctx = profile.context || {};
  const out = [];
  const add = (name, kind, source, note) => out.push({ name, kind, source, ...(note ? { note } : {}) });
  if (f.personalData) add('Dados pessoais de usuários', 'dado', 'declarado');
  if (f.minorsData) add('Dados de crianças e adolescentes', 'dado', 'declarado', 'LGPD, art. 14: melhor interesse e consentimento específico');
  const sens = disc.dataHints.find((h) => h.sensitive);
  if (ctx.sensitiveData) add('Dados pessoais sensíveis', 'dado', 'declarado');
  else if (sens) add('Possíveis dados sensíveis', 'dado', 'descoberto', `indício em ${sens.files.slice(0, 2).join(', ')}; confirme e, se for o caso, declare context.sensitiveData`);
  if (f.hasAuth) add('Credenciais, sessões e tokens', 'credencial', 'declarado');
  if (disc.env.credentials.length) add('Segredos de configuração (variáveis de ambiente)', 'credencial', 'descoberto', `${disc.env.credentials.length} variável(is) com nome de segredo`);
  if (disc.stores.length) add(`Banco de dados (${disc.stores.join(', ')})`, 'dado', 'descoberto');
  if (f.uploads) add('Arquivos enviados por usuários', 'dado', 'declarado');
  if (f.thirdPartyAssets) add('Mídia de terceiros (licenças)', 'outro', 'declarado');
  if (f.publicInternet || f.webApp) add('Disponibilidade do serviço', 'servico', 'declarado');
  add('Código-fonte e pipeline de entrega', 'codigo', 'declarado');
  return out;
}

/** Evidências da descoberta, por superfície: pistas concretas para quem revisa. */
function evidenceFor(surface, disc, profile) {
  const ev = [];
  const r = disc.routes;
  if (surface === 'web') {
    if (r.total) ev.push(`${r.total} rota(s) HTTP encontrada(s): ${r.byAuth.visivel} com autenticação visível, ${r.byAuth.global} cobertas por middleware global, ${r.byAuth['publica-esperada']} públicas esperadas, ${r.byAuth['nao-vista']} sem autenticação vista.`);
    if (r.authMounts && r.byAuth['nao-vista']) ev.push(`${r.authMounts} montagem(ns) de roteador com middleware de autenticação encontrada(s): as rotas "sem autenticação vista" podem estar protegidas por elas, e o kit não faz essa ligação. Confira.`);
    for (const x of r.examples.slice(0, 6)) ev.push(`Sem autenticação vista: ${x.method} ${x.path} (${x.location})`);
  }
  if (surface === 'auth' && r.total) ev.push(`${r.byAuth.visivel + r.byAuth.global} rota(s) com autenticação visível ou global; confirme a autorização por papel e por objeto nas demais.`);
  if (surface === 'data') {
    if (disc.stores.length) ev.push(`Armazenamento: ${disc.stores.join(', ')}.`);
    if (disc.externalHosts.length) ev.push(`Chamadas externas: ${disc.externalHosts.slice(0, 8).join(', ')}.`);
    for (const h of disc.dataHints) ev.push(`Indício de dado (${h.name}) em ${h.files.slice(0, 2).join(', ')}.`);
    if (disc.env.credentials.length) ev.push(`Variáveis de ambiente com nome de segredo: ${disc.env.credentials.slice(0, 8).join(', ')} (só os nomes).`);
  }
  if (surface === 'realtime' && disc.realtime.length) ev.push(`Tempo real: ${disc.realtime.join(', ')}.`);
  if (surface === 'uploads') {
    if (disc.uploads.length) ev.push(`Biblioteca de upload: ${disc.uploads.join(', ')}.`);
    if (disc.routes.uploadRoutes.length) ev.push(`Rotas que parecem receber arquivos: ${disc.routes.uploadRoutes.join('; ')}.`);
  }
  if (surface === 'pipeline') ev.push(`${disc.workflows} workflow(s) do GitHub Actions.`);
  if (surface === 'agent' && profile.flags && profile.flags.aiCodingAgents) ev.push('O perfil declara agentes de IA escrevendo código.');
  return ev;
}

/**
 * Monta o modelo de ameaças da execução: ativos, descoberta e ameaças com mitigações e estado derivados,
 * combinados com as decisões persistidas (se houver).
 */
function buildThreatModel({ ctx, controls, riskMap, profile, persisted = null, now }) {
  const disc = discover(ctx);
  const byControl = new Map(controls.map((c) => [c.id, c]));
  const slots = new Map();
  for (const c of controls) {
    const e = riskMap[c.id];
    if (!e || e.kind !== 'security') continue;
    const surface = surfaceOf(c, e);
    for (const s of strideOf(e)) {
      const key = `TM-${s}-${surface}`;
      if (!slots.has(key)) slots.set(key, { id: key, stride: s, surface, controls: [], cwe: new Set(), pillars: new Set() });
      const slot = slots.get(key);
      slot.controls.push(c.id);
      for (const n of e.cwe) slot.cwe.add(n);
      for (const p of e.pillars) slot.pillars.add(p);
    }
  }
  const decided = new Map(((persisted && persisted.threats) || []).map((t) => [t.id, t]));
  const threats = [...slots.values()].map((s) => {
    const states = s.controls.map((id) => byControl.get(id).state);
    const state = states.includes('failed') ? 'exposed' : states.every((x) => x === 'verified') ? 'mitigated' : 'unproven';
    const d = decided.get(s.id) || {};
    const t = {
      id: s.id, stride: s.stride, strideName: STRIDE[s.stride].name, surface: s.surface, surfaceName: SURFACES[s.surface],
      title: `${STRIDE[s.stride].name} em ${SURFACES[s.surface].toLowerCase()}`,
      question: STRIDE[s.stride].ask,
      controls: s.controls.sort(), cwe: [...s.cwe].sort((a, b) => a - b).slice(0, 8), pillars: [...s.pillars].join(''),
      state, evidence: evidenceFor(s.surface, disc, profile),
      decision: d.decision === undefined ? null : d.decision, rationale: d.rationale || null, owner: d.owner || null, expires: d.expires || null,
      likelihood: d.likelihood || null,
    };
    t.pending = isPending(t, now);
    return t;
  }).sort((a, b) => a.surface.localeCompare(b.surface) || 'STRIDE'.indexOf(a.stride) - 'STRIDE'.indexOf(b.stride));

  // Decisões de ameaças que não existem mais (a superfície sumiu) continuam avisadas, nunca apagadas em silêncio.
  const orphans = [...decided.keys()].filter((id) => !slots.has(id));
  const counts = {
    threats: threats.length,
    pending: threats.filter((t) => t.pending).length,
    mitigate: threats.filter((t) => t.decision === 'mitigate').length,
    accept: threats.filter((t) => t.decision === 'accept' && !t.pending).length,
    notApplicable: threats.filter((t) => t.decision === 'not_applicable').length,
    exposed: threats.filter((t) => t.state === 'exposed').length,
    unproven: threats.filter((t) => t.state === 'unproven').length,
    mitigated: threats.filter((t) => t.state === 'mitigated').length,
  };
  const assets = persisted && Array.isArray(persisted.assets) && persisted.assets.length
    ? persisted.assets
    : draftAssets(profile, disc).map((a, i) => ({ id: `A-${String(i + 1).padStart(2, '0')}`, ...a }));
  return {
    persisted: !!persisted,
    reviewed: !!(persisted && persisted.reviewedBy && persisted.reviewedAt && counts.pending === 0),
    reviewedBy: (persisted && persisted.reviewedBy) || null,
    reviewedAt: (persisted && persisted.reviewedAt) || null,
    generatedAt: now.toISOString(),
    assets, discovery: disc, threats, counts, orphans,
  };
}

/** Mapa controle -> maior probabilidade informada por uma pessoa nas ameaças que o citam (1 a 4). */
function likelihoodOverrides(model) {
  const map = new Map();
  if (!model || !model.persisted) return map;
  for (const t of model.threats) {
    if (!t.likelihood) continue;
    for (const id of t.controls) {
      const cur = map.get(id);
      if (!cur || t.likelihood > cur.value) map.set(id, { value: t.likelihood, threat: t.id });
    }
  }
  return map;
}

/** Controle -> ameaças com decisão "mitigar" que o citam (para priorizar tickets). */
function threatsToMitigate(model) {
  const map = new Map();
  if (!model) return map;
  for (const t of model.threats) {
    if (t.decision !== 'mitigate') continue;
    for (const id of t.controls) map.set(id, [...(map.get(id) || []), t.id]);
  }
  return map;
}

/** Conteúdo a gravar em .lastro/threat-model.json: só o que é humano ou estável. Preserva decisões e revisão. */
function serialize(model, persisted, now) {
  const prev = new Map(((persisted && persisted.threats) || []).map((t) => [t.id, t]));
  const threats = model.threats.map((t) => {
    const p = prev.get(t.id) || {};
    const out = { id: t.id, title: t.title, decision: p.decision === undefined ? null : p.decision };
    for (const k of ['rationale', 'owner', 'expires', 'likelihood']) if (p[k] !== undefined) out[k] = p[k];
    return out;
  });
  // Ameaças cuja superfície sumiu ficam no arquivo, para a decisão não se perder em silêncio.
  for (const [id, p] of prev) if (!model.threats.some((t) => t.id === id)) threats.push(p);
  const out = { schemaVersion: 1, generatedAt: now.toISOString() };
  if (persisted && persisted.reviewedBy) out.reviewedBy = persisted.reviewedBy;
  if (persisted && persisted.reviewedAt) out.reviewedAt = persisted.reviewedAt;
  out.note = 'Rascunho gerado pelo LASTRO. Decida cada ameaça (decision: mitigate, accept ou not_applicable), informe a probabilidade (likelihood de 1 a 4) quando souber, e preencha reviewedBy e reviewedAt ao terminar. Só as decisões são gravadas aqui.';
  out.assets = model.assets;
  out.threats = threats;
  return out;
}

function writeModel(root, content) {
  const dir = path.join(root, '.lastro');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'threat-model.json'), `${JSON.stringify(content, null, 2)}\n`);
}

module.exports = {
  STRIDE, SURFACES, DECISIONS, DECISION_PT, ID_THREAT, FILE, AUTH_LABEL,
  strideOf, surfaceOf, loadFile, validateModel, isPending, evaluateFile, buildThreatModel, likelihoodOverrides, threatsToMitigate, serialize, writeModel,
};
