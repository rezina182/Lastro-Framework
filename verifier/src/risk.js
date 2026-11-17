'use strict';

// Análise de risco do LASTRO. Separa o que é RISCO DE SEGURANÇA do que é boa prática ou qualidade e, para o
// risco de segurança, estima probabilidade x impacto, os pilares da segurança da informação afetados, as CWE
// associadas e a relação com privacidade e LGPD.
//
// É uma estimativa transparente, não um cálculo atuarial: cada número traz o motivo (reasons). Sem modelo de
// ameaças, a probabilidade é uma suposição a partir do estado do controle e da exposição declarada no perfil.
// O modelo de ameaças é o que torna a probabilidade específica (quem ataca, por onde, o que já existe).

const PILLARS = {
  C: 'Confidencialidade',
  I: 'Integridade',
  D: 'Disponibilidade',
  A: 'Autenticidade',
  N: 'Irretratabilidade',
  P: 'Privacidade',
  L: 'Conformidade',
  U: 'Auditabilidade',
};

const PILLAR_HELP = {
  C: 'só quem deve vê, vê',
  I: 'o dado e o código não mudam sem autorização',
  D: 'o serviço e os dados estão disponíveis quando precisam',
  A: 'quem diz ser alguém, é',
  N: 'quem fez uma ação não consegue negar depois',
  P: 'dados pessoais tratados com finalidade, minimização e direitos do titular',
  L: 'atende leis, contratos e licenças',
  U: 'dá para reconstruir o que aconteceu',
};

const KINDS = {
  security: { label: 'Risco de segurança', help: 'a falta do controle abre uma fraqueza que alguém pode explorar, ou expõe dado, código ou cadeia de suprimentos' },
  practice: { label: 'Boa prática', help: 'hábito de processo ou governança que reduz a chance de falha futura ou ajuda a detectar e responder; a falta dele não é, sozinha, uma brecha' },
  quality: { label: 'Qualidade', help: 'afeta manutenção, confiabilidade e clareza; vira risco só de forma indireta' },
};

const CLASSES = ['critical', 'high', 'medium', 'low'];
const CLASS_PT = { critical: 'Crítico', high: 'Alto', medium: 'Médio', low: 'Baixo' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const IMPACT_BY_SEVERITY = { critical: 4, high: 3, medium: 2, low: 1 };
const LIKELIHOOD_PT = { 1: 'rara', 2: 'possível', 3: 'provável', 4: 'quase certa' };
const IMPACT_PT = { 1: 'pequeno', 2: 'moderado', 3: 'grande', 4: 'severo' };
const DEFAULT_REACH = { web: 'internet', auth: 'internet', realtime: 'internet', uploads: 'internet', core: 'internet', pii: 'internal', agent: 'pipeline', assets: 'pipeline' };
const REACH_PT = {
  internet: 'alcançável por requisição remota',
  network: 'exige posição na rede (interceptação)',
  internal: 'depende de acesso interno, de um vazamento prévio ou de erro de operação',
  pipeline: 'ataca o desenvolvimento, o CI ou a cadeia de suprimentos',
};
// Pilares por CWE das vulnerabilidades de dependência. CWE fora da tabela não infla o impacto: fica sem pilar
// declarado (o relatório mostra "não informado") e o impacto sai só da gravidade do aviso.
const CWE_PILLARS = {
  79: 'IC', 89: 'CI', 78: 'CID', 94: 'CID', 95: 'CID', 22: 'C', 23: 'C', 918: 'CI', 601: 'I', 352: 'I', 1321: 'I', 20: 'I', 502: 'CID', 611: 'CID',
  200: 'C', 201: 'C', 209: 'C', 532: 'C', 287: 'A', 306: 'A', 295: 'CI', 347: 'AI', 345: 'I', 284: 'CI', 285: 'CI', 862: 'CI', 863: 'CI', 639: 'CI',
  400: 'D', 405: 'D', 407: 'D', 770: 'D', 674: 'D', 835: 'D', 1333: 'D', 185: 'D', 1050: 'D', 444: 'IC', 113: 'I', 93: 'I', 74: 'CI', 77: 'CID', 327: 'C', 328: 'C', 330: 'CA',
};

/** Classe de risco pela matriz 4x4: probabilidade x impacto (1 a 16). */
function classOf(score) {
  if (score >= 12) return 'critical';
  if (score >= 8) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

const ASSUMED_MAX_SCORE = 11;
const clamp = (n) => Math.min(4, Math.max(1, n));

function dataContext(profile) {
  const flags = (profile && profile.flags) || {};
  const given = (profile && profile.context) || {};
  return {
    personal: !!flags.personalData,
    minors: !!flags.minorsData,
    sensitive: given.sensitiveData === true,
    publicInternet: !!flags.publicInternet,
  };
}

function likelihoodOf({ state, findings, reach, override = null }, d) {
  const why = [];
  let value;
  let assumed = false;
  if (override) {
    // Quem revisou o modelo de ameaças conhece o contexto melhor que a estimativa genérica: a exposição já está embutida.
    return { value: clamp(override.value), assumed: state !== 'failed', why: [`probabilidade informada por uma pessoa no modelo de ameaças (${override.threat})`] };
  }
  if (state === 'failed') {
    const worst = findings.length ? findings.map((f) => f.severity).sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b])[0] : null;
    value = worst === 'medium' ? 2 : worst === 'low' ? 1 : 3;
    why.push(worst === 'medium'
      ? 'achado de gravidade média (varredura por heurística: exige revisão humana para confirmar)'
      : worst ? `achado de gravidade ${worst === 'critical' ? 'crítica' : worst === 'high' ? 'alta' : 'baixa'}` : 'o controle falhou na verificação');
  } else {
    value = 2;
    assumed = true;
    why.push('sem prova: probabilidade assumida como média até alguém provar o controle');
  }
  // A exposição só agrava o que tem evidência forte ou o que ninguém provou; achado de gravidade média ou baixa
  // (heurístico) não sobe por estar na internet. O que exige posição na rede ou acesso interno é menos provável.
  if (reach === 'internet') {
    if (!d.publicInternet) { value -= 1; why.push('o perfil diz que a aplicação não está exposta à internet'); }
    else if (assumed || value >= 3) { value += 1; why.push('a aplicação está exposta à internet'); }
  } else if (reach === 'network' || reach === 'internal') {
    value -= 1;
    why.push(reach === 'network' ? 'exige posição privilegiada na rede para explorar' : 'depende de acesso interno ou de vazamento prévio');
  }
  return { value: clamp(value), assumed, why };
}

function impactOf({ severity, pillars }, d) {
  const why = [`gravidade ${severity === 'critical' ? 'crítica' : severity === 'high' ? 'alta' : severity === 'medium' ? 'média' : 'baixa'} do controle`];
  let value = IMPACT_BY_SEVERITY[severity] || 1;
  const touchesData = pillars.includes('C') || pillars.includes('P');
  if (touchesData && d.personal) { value += 1; why.push('afeta dado pessoal'); }
  if (touchesData && (d.minors || d.sensitive)) { value += 1; why.push(d.minors ? 'envolve dados de crianças ou adolescentes' : 'envolve dado pessoal sensível'); }
  return { value: clamp(value), why };
}

function asvsIds(catalog, id) {
  const c = catalog && catalog.byId && catalog.byId.get(id);
  return c ? c.refs.filter((r) => r.std === 'ASVS').map((r) => r.id).slice(0, 8) : [];
}

function vulnItems(audit, d) {
  if (!audit) return [];
  // Um risco por pacote que tem aviso próprio; os que só herdam o aviso aparecem como "afeta".
  return audit.items.filter((v) => !v.inherited).map((v) => {
    const cwe = [...new Set(v.advisories.flatMap((a) => a.cwe))].slice(0, 8);
    const pillars = [...new Set(cwe.flatMap((n) => (CWE_PILLARS[n] || '').split('')))].join('');
    let l = v.severity === 'low' ? 2 : 3;
    const lWhy = ['vulnerabilidade pública e conhecida'];
    if (v.devOnly) { l = 1; lWhy.push(`só entra por dependência de desenvolvimento (${(v.via || []).join(', ') || 'devDependencies'}): não vai para produção`); }
    else if (!d.publicInternet) { l -= 1; lWhy.push('o perfil diz que a aplicação não está exposta à internet'); }
    if (!pillars) lWhy.push('CWE sem pilar mapeado: o impacto vem só da gravidade do aviso');
    const imp = impactOf({ severity: v.severity, pillars }, d);
    const likelihood = clamp(l);
    const score = likelihood * imp.value;
    return {
      type: 'vuln', id: `VULN:${v.package}`, title: `Dependência vulnerável: ${v.package}`, kind: 'security', pack: 'deps',
      state: 'failed', severity: v.severity, likelihood, impact: imp.value, score, class: classOf(score), assumed: false, accepted: false,
      pillars: pillars ? pillars.split('') : [], cwe, lgpd: null, privacy: false, reach: 'internet', findings: v.advisories.length, locations: [], asvs: [],
      reasons: { likelihood: lWhy, impact: imp.why }, direct: v.direct, fix: v.fix, devOnly: v.devOnly, affects: v.effects || [],
      advisories: v.advisories.slice(0, 6).map((a) => ({ id: a.id, url: a.url, title: a.title, cvss: a.cvss, cve: a.cve })),
    };
  });
}

/**
 * Monta a análise de risco a partir do relatório do motor.
 * `riskMap`: entradas do catalog/risk-map.json. `audit`: resultado de audit.parseAudit (opcional).
 */
function analyzeRisk(report, { riskMap, catalog = null, profile, audit = null, threatLikelihood = new Map() }) {
  const d = dataContext(profile);
  const dataApplies = d.personal || d.minors || d.sensitive;
  const all = [];
  let verifiedSecurity = 0;
  for (const c of report.controls) {
    const e = riskMap[c.id] || { kind: 'practice', pillars: '', cwe: [] };
    if (c.state === 'verified') {
      if (e.kind === 'security') verifiedSecurity += 1;
      continue;
    }
    if (c.state !== 'failed' && c.state !== 'unverified') continue;
    const pillars = e.pillars.split('').filter(Boolean);
    const reach = e.reach || DEFAULT_REACH[c.pack] || 'internet';
    const open = c.findings || [];
    const privacy = pillars.includes('P') || (dataApplies && e.kind === 'security' && pillars.includes('C'));
    const item = {
      type: 'control', id: c.id, title: c.title, kind: e.kind, pack: c.pack, state: c.state, severity: c.severity,
      pillars, cwe: e.cwe, lgpd: e.lgpd || (privacy && e.kind === 'security' ? 'Art. 46 (medidas de segurança)' : null), privacy, reach,
      findings: open.length, locations: open.map((f) => f.location).filter(Boolean).slice(0, 3),
      accepted: open.length > 0 && open.every((f) => f.accepted), asvs: asvsIds(catalog, c.id), remediation: c.remediation,
    };
    if (e.kind === 'security') {
      const L = likelihoodOf({ state: c.state, findings: open, reach, override: threatLikelihood.get(c.id) || null }, d);
      const I = impactOf({ severity: c.severity, pillars }, d);
      item.likelihood = L.value;
      item.impact = I.value;
      item.score = L.value * I.value;
      item.assumed = L.assumed;
      item.reasons = { likelihood: L.why, impact: I.why, reach: REACH_PT[reach] };
      // "Crítico" exige evidência: o que ninguém provou fica no máximo em "Alto".
      if (L.assumed && item.score > ASSUMED_MAX_SCORE) {
        item.score = ASSUMED_MAX_SCORE;
        item.reasons.likelihood.push('crítico exige evidência: sem prova, a classe fica limitada a Alto');
      }
      item.class = classOf(item.score);
    }
    all.push(item);
  }
  const vulns = vulnItems(audit, d);

  const byScore = (a, b) => b.score - a.score || (a.state === b.state ? 0 : a.state === 'failed' ? -1 : 1) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id);
  const bySeverity = (a, b) => (a.state === b.state ? 0 : a.state === 'failed' ? -1 : 1) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id);
  const security = [...all.filter((i) => i.kind === 'security'), ...vulns].sort(byScore);
  const practices = all.filter((i) => i.kind === 'practice').sort(bySeverity);
  const quality = all.filter((i) => i.kind === 'quality').sort(bySeverity);

  const tally = (list) => {
    const t = { critical: 0, high: 0, medium: 0, low: 0, total: list.length };
    for (const i of list) t[i.class] += 1;
    return t;
  };
  const confirmed = security.filter((i) => i.state === 'failed');
  const potential = security.filter((i) => i.state === 'unverified');

  const matrix = [];
  for (let imp = 4; imp >= 1; imp -= 1) {
    for (let lik = 1; lik <= 4; lik += 1) {
      const count = confirmed.filter((i) => i.impact === imp && i.likelihood === lik).length;
      matrix.push({ impact: imp, likelihood: lik, count, class: classOf(imp * lik) });
    }
  }

  const pillars = Object.keys(PILLARS).map((code) => {
    const list = [...security, ...practices, ...quality].filter((i) => i.pillars.includes(code));
    const sec = security.filter((i) => i.pillars.includes(code));
    const worst = sec.length ? sec.map((i) => i.class).sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b])[0] : null;
    return {
      code, name: PILLARS[code], help: PILLAR_HELP[code], open: list.length,
      confirmed: sec.filter((i) => i.state === 'failed').length, potential: sec.filter((i) => i.state === 'unverified').length,
      worstClass: worst,
    };
  });

  const privacyItems = [...security, ...practices].filter((i) => i.privacy).sort((a, b) => (b.score || 0) - (a.score || 0) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const privacy = {
    applies: dataApplies,
    data: { personal: d.personal, minors: d.minors, sensitive: d.sensitive },
    items: privacyItems,
    confirmed: privacyItems.filter((i) => i.state === 'failed').length,
    potential: privacyItems.filter((i) => i.state === 'unverified').length,
    note: 'Quando o risco envolve dado pessoal, a LGPD (art. 46) exige medidas de segurança, e o art. 48 manda comunicar à ANPD e ao titular um incidente que possa causar risco ou dano relevante. Este relatório aponta onde olhar; não é parecer jurídico.',
  };

  return {
    method: 'v1',
    summary: {
      confirmed: tally(confirmed),
      potential: tally(potential),
      practicesOpen: practices.length,
      qualityOpen: quality.length,
      securityVerified: verifiedSecurity,
    },
    security,
    matrix,
    pillars,
    privacy,
    practices,
    quality,
    dependencies: audit ? { source: audit.source, total: audit.total, bySeverity: audit.bySeverity } : null,
  };
}

module.exports = {
  PILLARS, PILLAR_HELP, KINDS, CLASSES, CLASS_PT, LIKELIHOOD_PT, IMPACT_PT, REACH_PT, DEFAULT_REACH,
  classOf, analyzeRisk,
};
