'use strict';

// Contexto da aplicação: nem toda aplicação precisa do mesmo nível de rigor.
// O risco inerente é estimado a partir do que o perfil declara (exposição, dados, superfície), e define uma
// META de maturidade. A meta não muda quais controles se aplicam (isso é o papel dos flags), só diz quanto
// de evidência é razoável esperar dessa aplicação (uma nota de 0 a 10). O perfil pode sobrescrever o risco ou a meta.

const FACTORS = [
  ['publicInternet', 2, 'é acessível pela internet'],
  ['personalData', 2, 'trata dados pessoais'],
  ['minorsData', 2, 'trata dados de crianças ou adolescentes'],
  ['oauthProvider', 2, 'atua como servidor de autorização'],
  ['hasAuth', 1, 'tem login e sessão'],
  ['anonymousUsers', 1, 'aceita usuários anônimos'],
  ['uploads', 1, 'aceita arquivos enviados por usuários'],
  ['realtime', 1, 'mantém conexões de tempo real'],
  ['tokenAuth', 1, 'emite ou valida tokens'],
  ['aiCodingAgents', 1, 'usa agentes de IA para escrever código'],
];

const RISK_BY_LEVEL = { low: 'baixo', medium: 'moderado', high: 'alto' };
// Meta: nota de 0 a 10 que é razoável esperar para o risco (faixas em score.js: 6 Bom, 8 Forte).
const TARGET_BY_RISK = { baixo: 6, moderado: 7, alto: 8 };
// Perfis antigos declaravam "targetLevel" (0 a 4): cada nível vira a nota equivalente.
const GRADE_BY_LEGACY_LEVEL = [0, 4, 6, 8, 9];

function targetOf(given, risk) {
  if (Number.isFinite(given.targetGrade)) return { grade: given.targetGrade, source: 'definida no perfil' };
  if (Number.isInteger(given.targetLevel)) return { grade: GRADE_BY_LEGACY_LEVEL[given.targetLevel], source: `definida no perfil (targetLevel ${given.targetLevel} convertido)` };
  return { grade: TARGET_BY_RISK[risk], source: `padrão para risco ${risk}` };
}

function deriveContext(profile) {
  const flags = profile.flags || {};
  const hit = FACTORS.filter(([flag]) => flags[flag]);
  const given = profile.context || {};
  const sensitive = given.sensitiveData === true;
  const points = hit.reduce((s, [, p]) => s + p, 0) + (sensitive ? 2 : 0);
  const derived = points >= 8 ? 'alto' : points >= 4 ? 'moderado' : 'baixo';
  const risk = given.criticality ? RISK_BY_LEVEL[given.criticality] : derived;
  const target = targetOf(given, risk);
  return {
    risk,
    points,
    factors: [...hit.map(([, , text]) => text), ...(sensitive ? ['trata dados pessoais sensíveis (LGPD, art. 5º, II)'] : [])],
    data: { personal: !!flags.personalData, minors: !!flags.minorsData, sensitive },
    riskSource: given.criticality ? 'definido no perfil' : 'estimado pelos flags do perfil',
    targetGrade: target.grade,
    targetSource: target.source,
  };
}

/** Quais pacotes de controles estão no escopo e quais ficaram de fora (e por quê). */
function describeScope(catalogPacks, flags) {
  const on = [];
  const off = [];
  for (const [pack, def] of Object.entries(catalogPacks)) {
    const missing = (def.requires || []).filter((f) => !flags[f]);
    if (missing.length === 0) on.push({ pack, title: def.title });
    else off.push({ pack, title: def.title, missing });
  }
  return { on, off };
}

const FLAG_LABELS = {
  webApp: 'aplicação web',
  hasAuth: 'login e sessão',
  anonymousUsers: 'usuários anônimos',
  realtime: 'tempo real',
  uploads: 'upload de arquivos',
  personalData: 'dados pessoais',
  minorsData: 'dados de menores',
  thirdPartyAssets: 'ativos de mídia de terceiros',
  aiCodingAgents: 'agentes de IA no desenvolvimento',
  publicInternet: 'exposição à internet',
  federatedLogin: 'login federado',
  tokenAuth: 'tokens autocontidos',
  oauthProvider: 'servidor de autorização OAuth',
};

module.exports = { FACTORS, FLAG_LABELS, TARGET_BY_RISK, deriveContext, describeScope };
