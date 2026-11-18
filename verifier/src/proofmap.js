'use strict';

// Mapa de prova dos controles manuais: por qual caminho cada um pode ser provado, que indícios o código já mostra
// e quais provavelmente não se aplicam pela tecnologia. Responde "por que tanta coisa está sem prova e o que dá
// para automatizar". Nada aqui muda o estado de um controle: indício não é prova, e "provavelmente não se aplica"
// só vira decisão quando uma pessoa registra a justificativa em .lastro/status.json (state "not_applicable").

const VIA = {
  sonda: 'sonda HTTP do kit (local ou staging)',
  'sonda-auth': 'sonda com duas contas de teste (--auth)',
  codigo: 'leitura do código, com confirmação de uma pessoa',
  plataforma: 'configuração da plataforma (GitHub, nuvem)',
  pessoa: 'processo, documento ou teste feito por uma pessoa',
};
// Caminhos que o kit já executa hoje, em parte, para o controle (a sonda que passa ajuda a atestação).
// Sondas autenticadas (authprobe.js) e prova assistida (assist.js).
// AUTH-002, AUTH-011, AUTH-016, WEB-016 e WEB-018 têm um irmão automático (AUTH-042, AUTH-041, AUTH-040, WEB-022, WEB-023).
const RUNS_TODAY = new Set(['AUTH-027', 'WEB-013', 'AUTH-023', 'AUTH-022', 'WEB-010', 'CORE-056', 'AUTH-028', 'CORE-015', 'AG-001', 'AG-007', 'AUTH-002', 'AUTH-011', 'AUTH-016', 'WEB-016', 'WEB-018']);

// Caminho principal de prova de cada controle manual do catálogo.
const ROUTE = {
  sonda: ['AUTH-005', 'AUTH-011', 'AUTH-016', 'WEB-011', 'WEB-012', 'WEB-015', 'WEB-016', 'WEB-017', 'WEB-018', 'WEB-019', 'WEB-020', 'CORE-048', 'CORE-055', 'RT-004'],
  'sonda-auth': ['AUTH-001', 'AUTH-004', 'AUTH-006', 'AUTH-007', 'AUTH-008', 'AUTH-010', 'AUTH-013', 'AUTH-014', 'AUTH-017', 'AUTH-022', 'AUTH-023', 'AUTH-024', 'AUTH-025',
    'AUTH-027', 'AUTH-028', 'AUTH-029', 'AUTH-030', 'AUTH-031', 'WEB-010', 'WEB-013', 'WEB-021', 'CORE-030', 'CORE-031', 'CORE-032', 'CORE-035', 'CORE-036', 'CORE-039',
    'CORE-041', 'CORE-056', 'RT-001', 'RT-003', 'UP-001', 'UP-002', 'UP-003', 'UP-005', 'UP-006', 'UP-007'],
  codigo: ['AG-001', 'AG-005', 'AG-007', 'AG-014', 'AUTH-002', 'AUTH-012', 'AUTH-018', 'CORE-015', 'CORE-016', 'CORE-018', 'CORE-019', 'CORE-020', 'CORE-021',
    'CORE-022', 'CORE-024', 'CORE-025', 'CORE-028', 'CORE-029', 'CORE-037', 'CORE-044', 'CORE-045', 'CORE-046', 'CORE-047', 'CORE-049', 'CORE-053', 'CORE-057', 'CORE-058',
    'PII-003', 'WEB-014'],
  plataforma: ['CORE-014', 'AG-009', 'AG-010'],
  pessoa: ['AG-008', 'AG-011', 'AG-012', 'AG-013', 'AUTH-009', 'AUTH-015', 'AUTH-019', 'AUTH-020', 'AUTH-021', 'AUTH-026', 'AUTH-032', 'AUTH-033', 'AUTH-034', 'AUTH-035',
    'AUTH-036', 'AUTH-037', 'AUTH-038', 'AUTH-039', 'CORE-023', 'CORE-026', 'CORE-027', 'CORE-033', 'CORE-034', 'CORE-038', 'CORE-040', 'CORE-042', 'CORE-043', 'CORE-050',
    'CORE-051', 'CORE-052', 'CORE-054', 'PII-001', 'PII-002', 'PII-004', 'RT-002', 'RT-005', 'RT-006', 'UP-004'],
};
const VIA_OF = new Map(Object.entries(ROUTE).flatMap(([via, ids]) => ids.map((id) => [id, via])));

// Controle que provavelmente não se aplica quando a tecnologia não aparece no código nem nas dependências.
const NEEDS_TECH = {
  'WEB-020': ['graphql'],
  'AUTH-019': ['sms'],
  'AUTH-020': ['oauthClient'], 'AUTH-021': ['oauthClient'], 'AUTH-032': ['oauthClient'], 'AUTH-033': ['oauthClient'], 'AUTH-034': ['oauthClient', 'jwt'],
  'AUTH-035': ['oauthServer'], 'AUTH-036': ['oauthServer'], 'AUTH-037': ['oauthServer'], 'AUTH-038': ['oauthServer'], 'AUTH-039': ['oauthServer'],
  'AUTH-030': ['jwt'], 'AUTH-031': ['jwt'],
  'CORE-033': ['ldap'],
  'CORE-038': ['nativeCode'],
  'RT-004': ['websocket'],
  'RT-005': ['webrtc'], 'RT-006': ['webrtc'],
  'UP-006': ['archives'],
};

// Indícios no código (defesas descobertas, surface.js DEFENSES) que ajudam quem vai atestar o controle.
const HINT_DEFENSES = {
  'AUTH-002': ['password'], 'AUTH-016': ['ratelimit', 'captcha'], 'AUTH-005': ['ratelimit'], 'WEB-011': ['ratelimit'], 'WEB-017': ['ratelimit', 'captcha'],
  'AUTH-001': ['mfa'], 'AUTH-014': ['mfa'], 'AUTH-017': ['mfa'], 'AUTH-006': ['mfa'], 'AUTH-013': ['mfa'],
  'AUTH-022': ['cookie'], 'AUTH-030': ['tokens'], 'AUTH-031': ['tokens'],
  'WEB-013': ['csrf', 'origin'], 'WEB-012': ['headers'],
  'UP-001': ['image'], 'UP-002': ['bodylimit', 'image'], 'CORE-054': ['bodylimit', 'ratelimit'],
  'CORE-016': ['audit'], 'CORE-025': ['audit'],
  'CORE-041': ['validation'], 'CORE-056': ['validation'], 'AUTH-028': ['validation'],
};

/** Caminho de prova, indícios e "provavelmente não se aplica" de um controle manual. */
function proofFor(control, disc) {
  const via = VIA_OF.get(control.id) || 'pessoa';
  const tech = (disc && disc.tech) || {};
  const defenses = (disc && disc.defenses) || [];
  const needs = NEEDS_TECH[control.id];
  let likelyNA = null;
  if (needs && Object.keys(tech).length && needs.every((t) => tech[t] && !tech[t].present)) {
    likelyNA = `nenhum sinal de ${needs.map((t) => tech[t].label).join(' nem de ')} nas dependências ou no código`;
  }
  const hints = (HINT_DEFENSES[control.id] || []).map((id) => defenses.find((d) => d.id === id)).filter(Boolean).map((d) => `${d.label} (${d.evidence})`);
  if (control.id === 'CORE-015' && disc && (disc.ciJobs || []).length) hints.push(`jobs do CI: ${disc.ciJobs.map((j) => j.job).slice(0, 5).join(', ')}`);
  if (control.id === 'CORE-020' && disc && (disc.externalHosts || []).length) hints.push(`hosts externos no código: ${disc.externalHosts.slice(0, 5).join(', ')}`);
  return { via, viaLabel: VIA[via], runsToday: RUNS_TODAY.has(control.id), likelyNA, hints };
}

/**
 * Diagnóstico das lacunas: o que está sem prova e por quê, o que falha e de que tipo, e quanto dá para automatizar.
 * `report` é o resultado de runCheck.
 */
function analyzeGaps(report) {
  const disc = report.threatModel && report.threatModel.discovery;
  const applicable = report.controls.filter((c) => c.state !== 'not_applicable');
  const manualOpen = applicable.filter((c) => c.checkType === 'manual' && c.state === 'unverified');
  const items = manualOpen.map((c) => ({ id: c.id, title: c.title, pack: c.pack, severity: c.severity, ...proofFor(c, disc) }));
  const byVia = Object.fromEntries(Object.keys(VIA).map((v) => [v, 0]));
  for (const i of items) if (!i.likelyNA) byVia[i.via] += 1;
  const autoNotRun = applicable.filter((c) => c.checkType === 'automated' && c.state === 'unverified');
  const failing = applicable.filter((c) => c.state === 'failed');
  const testOnly = (c) => c.findings.length > 0 && c.findings.every((f) => /arquivo de teste/.test(f.message || ''));
  return {
    applicable: applicable.length,
    manual: applicable.filter((c) => c.checkType === 'manual').length,
    automated: applicable.filter((c) => c.checkType === 'automated').length,
    attested: applicable.filter((c) => c.checkType === 'manual' && c.state === 'verified').length,
    manualOpen: items.length,
    likelyNA: items.filter((i) => i.likelyNA).map((i) => ({ id: i.id, title: i.title, reason: i.likelyNA })),
    byVia,
    withHints: items.filter((i) => !i.likelyNA && i.hints.length).map((i) => ({ id: i.id, title: i.title, hints: i.hints })),
    items,
    automatedNotRun: autoNotRun.map((c) => ({ id: c.id, title: c.title, why: (c.notes || [])[0] || '' })),
    failing: {
      blocking: failing.filter((c) => c.findings.some((f) => f.blocking)).map((c) => c.id),
      testOnly: failing.filter((c) => !c.findings.some((f) => f.blocking) && testOnly(c)).map((c) => c.id),
      review: failing.filter((c) => !c.findings.some((f) => f.blocking) && !testOnly(c)).map((c) => c.id),
    },
  };
}

/** Frases curtas que explicam a nota: o porquê, em ordem de peso. */
function explainGaps(g) {
  const out = [];
  if (g.manualOpen) {
    out.push(`${g.manualOpen} de ${g.applicable} controles aplicáveis dependem de um teste ou de uma decisão de uma pessoa e ainda não têm atestação (${g.attested} atestado(s) até agora). É a maior causa da nota baixa: sem prova conta como zero.`);
    if (g.likelyNA.length) out.push(`${g.likelyNA.length} desses provavelmente não se aplicam à tecnologia desta aplicação (${g.likelyNA.slice(0, 5).map((x) => x.id).join(', ')}${g.likelyNA.length > 5 ? '...' : ''}). Uma pessoa confirma e registra "não se aplica" com a justificativa, e eles saem da conta.`);
    const v = g.byVia;
    out.push(`Dos demais: ${v.sonda} uma sonda do kit pode provar, ${v['sonda-auth']} pedem sonda com duas contas de teste, ${v.codigo} se confirmam lendo o código, ${v.plataforma} pela configuração da plataforma e ${v.pessoa} só por processo ou documento.`);
    if (g.withHints.length) out.push(`${g.withHints.length} já têm indício no código (por exemplo, ${g.withHints.slice(0, 3).map((x) => `${x.id}: ${x.hints[0]}`).join('; ')}). Indício não é prova, mas encurta a atestação.`);
  }
  if (g.automatedNotRun.length) out.push(`${g.automatedNotRun.length} controle(s) automáticos não rodaram (${g.automatedNotRun.slice(0, 6).map((x) => x.id).join(', ')}${g.automatedNotRun.length > 6 ? '...' : ''}): precisam do endereço de um ambiente local ou de staging (--url).`);
  const f = g.failing;
  const nf = f.blocking.length + f.testOnly.length + f.review.length;
  if (nf) out.push(`${nf} controle(s) falhando: ${f.blocking.length} bloqueiam o portão (${f.blocking.join(', ') || '-'}), ${f.review.length} pedem revisão sem bloquear (${f.review.join(', ') || '-'}) e ${f.testOnly.length} só aparecem em arquivos de teste (${f.testOnly.join(', ') || '-'}).`);
  return out;
}

const SEV_PT = { critical: 'crítica', high: 'alta', medium: 'média', low: 'baixa' };
const DAY = 24 * 60 * 60 * 1000;

/** Texto do comando "lastro gaps": o porquê, depois o que fazer em cada grupo, com o trecho pronto para o "não se aplica". */
function formatGaps(g, { now = new Date(), name = '' } = {}) {
  const out = [`Lacunas de "${name}": por que a nota está assim e o que dá para automatizar`, ''];
  for (const l of explainGaps(g)) out.push(`- ${l}`);
  if (g.likelyNA.length) {
    out.push('', 'Provavelmente não se aplicam (confirme e registre em .lastro/status.json; troque o nome e revise o motivo):');
    for (const x of g.likelyNA) out.push(`  ${x.id} ${x.title}: ${x.reason}`);
    const day = (d) => d.toISOString().slice(0, 10);
    const snippet = Object.fromEntries(g.likelyNA.map((x) => [x.id, { state: 'not_applicable', attestedBy: 'NOME DE QUEM CONFIRMOU', collectedAt: day(now), expiresAt: day(new Date(now.getTime() + 365 * DAY)), note: `Não se aplica: ${x.reason}.` }]));
    out.push('', JSON.stringify(snippet, null, 2).split('\n').map((l) => `    ${l}`).join('\n'));
  }
  const group = (via, title) => {
    const list = g.items.filter((i) => i.via === via && !i.likelyNA);
    if (!list.length) return;
    out.push('', `${title} (${list.length}):`);
    for (const i of list.slice(0, 40)) out.push(`  ${i.id} [${SEV_PT[i.severity]}] ${i.title}${i.runsToday ? ' (a máquina já testa em parte)' : ''}${i.hints.length ? ` | indício: ${i.hints.join('; ')}` : ''}`);
    if (list.length > 40) out.push(`  e mais ${list.length - 40}.`);
  };
  group('sonda', 'Uma sonda HTTP pode provar');
  group('sonda-auth', 'Pedem sonda com duas contas de teste');
  group('codigo', 'Se confirmam lendo o código');
  group('plataforma', 'Pela configuração da plataforma');
  group('pessoa', 'Só por processo, documento ou teste de uma pessoa');
  if (g.automatedNotRun.length) out.push('', `Automáticos que não rodaram: ${g.automatedNotRun.map((x) => x.id).join(', ')}. Rode "lastro check --url http://localhost:PORTA" num ambiente local ou de staging.`);
  out.push('', 'Indício não é prova e "provavelmente não se aplica" não é decisão: nada aqui muda a nota até uma pessoa testar ou registrar a justificativa.');
  return out.join('\n');
}

module.exports = { VIA, ROUTE, NEEDS_TECH, proofFor, analyzeGaps, explainGaps, formatGaps };
