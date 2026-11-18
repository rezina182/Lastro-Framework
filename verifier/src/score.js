'use strict';

// Pontuação de maturidade do LASTRO. Mede EVIDÊNCIA verificável, não a segurança da aplicação:
//  - cada controle aplicável pesa pela gravidade (crítica 8, alta 5, média 3, baixa 1);
//  - só "verificado" vale ponto; "sem prova" e "falhando" não valem (desconhecido não é aprovado);
//  - o que foi provado por máquina é separado do que é autodeclarado por atestação, que tem prazo;
//  - os níveis são uma convenção do kit (docs/SCORE.md), não um padrão de mercado.

const WEIGHT = { critical: 8, high: 5, medium: 3, low: 1 };

const LEVELS = [
  { level: 0, name: 'Inicial', rule: 'há achados bloqueantes: o portão falha' },
  { level: 1, name: 'Básico', rule: 'sem bloqueantes, mas com menos de 30% do peso provado' },
  { level: 2, name: 'Estruturado', rule: 'sem bloqueantes e com 30% ou mais do peso provado' },
  { level: 3, name: 'Verificado', rule: '60% ou mais provado e nenhum controle alto ou crítico falhando ou sem prova' },
  { level: 4, name: 'Comprovado', rule: '90% ou mais provado, nenhum controle falhando e nenhum alto ou crítico sem prova' },
];

const DISCLAIMER = 'A pontuação mede a evidência que existe, não a segurança da aplicação. Controle sem prova conta como zero, e atestação é autodeclaração com prazo.';

const pct = (n, d) => (d === 0 ? 0 : Math.round((n / d) * 1000) / 10);

// Fases do ciclo de vida de desenvolvimento seguro (SSDLC), na ordem em que acontecem.
const PHASES = [
  ['design', 'Projeto'],
  ['build', 'Desenvolvimento'],
  ['test', 'Teste'],
  ['deploy', 'Entrega'],
  ['runtime', 'Operação'],
  ['respond', 'Resposta a incidentes'],
];

// Notas de 0 a 10 (docs/SCORE.md). Leitura humana do mesmo dado; o nível 0 a 4 continua valendo para o alvo.
//  - postura: do que foi decidido (verificado ou falhando), quanto passou, pelo peso;
//  - cobertura: quanto do peso aplicável tem prova (máquina ou atestação);
//  - geral: média das duas, com teto quando há bloqueante (crítico: 4; qualquer bloqueante: 6).
const BANDS = [
  { min: 9, name: 'Exemplar' },
  { min: 8, name: 'Forte' },
  { min: 6, name: 'Bom' },
  { min: 4, name: 'Em evolução' },
  { min: 0, name: 'Inicial' },
];
const round1 = (n) => Math.round(n * 10) / 10;
const bandOf = (g) => (g === null || g === undefined ? null : BANDS.find((b) => g >= b.min).name);
// "6,2" (vírgula decimal, uma casa) ou "n/d" quando não há o que medir.
const gradeText = (g) => (Number.isFinite(g) ? g.toFixed(1).replace('.', ',') : 'n/d');

function computeGrades(report, sum, provenPct) {
  const decided = sum.machine + sum.attested + sum.failed;
  const posture = decided === 0 ? null : round1((10 * (sum.machine + sum.attested)) / decided);
  const coverage = round1(provenPct / 10);
  const findings = (report.controls || []).flatMap((c) => c.findings || []);
  const blocking = findings.filter((f) => f.blocking);
  const criticalBlocking = blocking.filter((f) => f.severity === 'critical').length;
  const cap = criticalBlocking > 0 ? 4 : blocking.length > 0 ? 6 : 10;
  const raw = posture === null ? coverage : 0.5 * posture + 0.5 * coverage;
  const overall = round1(Math.min(raw, cap));
  const capReason = raw > cap
    ? (criticalBlocking > 0 ? `limitada a 4: ${criticalBlocking} achado(s) crítico(s) bloqueante(s)` : `limitada a 6: ${blocking.length} achado(s) bloqueante(s)`)
    : null;
  return { overall, band: bandOf(overall), posture, coverage, cap, capReason };
}

// Nota 0 a 10 de um recorte (escopo ou fase): mesma média, sem teto (o teto é do portão, que é geral).
function sliceGrade(b) {
  if (b.total === 0) return null;
  const proven = b.machine + b.attested;
  const decided = proven + b.failed;
  const coverage = (10 * proven) / b.total;
  return round1(decided === 0 ? coverage : 0.5 * ((10 * proven) / decided) + 0.5 * coverage);
}

function computeScore(report, { packTitles = {} } = {}) {
  const sum = { total: 0, machine: 0, attested: 0, failed: 0, unverified: 0 };
  const byPack = {};
  const byPhase = Object.fromEntries(PHASES.map(([k, name]) => [k, { phase: k, name, controls: 0, total: 0, machine: 0, attested: 0, failed: 0, unverified: 0 }]));
  const open = [];
  let applicable = 0;
  for (const c of report.controls) {
    if (c.state === 'not_applicable') continue;
    applicable += 1;
    const w = WEIGHT[c.severity] || 1;
    const p = (byPack[c.pack] = byPack[c.pack] || { pack: c.pack, title: packTitles[c.pack] || c.pack, controls: 0, total: 0, machine: 0, attested: 0, failed: 0, unverified: 0 });
    p.controls += 1;
    sum.total += w;
    p.total += w;
    if (c.state === 'verified') {
      const key = c.evidence && c.evidence.source === 'manual-attestation' ? 'attested' : 'machine';
      sum[key] += w;
      p[key] += w;
    } else if (c.state === 'failed') {
      sum.failed += w;
      p.failed += w;
    } else {
      sum.unverified += w;
      p.unverified += w;
    }
    if ((c.severity === 'critical' || c.severity === 'high') && c.state !== 'verified') open.push(c.id);
    // Um controle conta em cada fase em que atua (o peso total por fase pode somar mais que o geral).
    for (const ph of c.phase || []) {
      const b = byPhase[ph];
      if (!b) continue;
      b.controls += 1;
      b.total += w;
      if (c.state === 'verified') b[c.evidence && c.evidence.source === 'manual-attestation' ? 'attested' : 'machine'] += w;
      else if (c.state === 'failed') b.failed += w;
      else b.unverified += w;
    }
  }

  // Controles automáticos: o que a máquina de fato rodou. Separa quem passou de quem falhou, e o que não rodou
  // (por exemplo, as sondas HTTP sem --url) fica de fora da taxa, sem virar aprovação.
  const auto = report.controls.filter((c) => c.state !== 'not_applicable' && c.checkType === 'automated');
  const autoVerified = auto.filter((c) => c.state === 'verified').length;
  const autoFailed = auto.filter((c) => c.state === 'failed').length;
  const autoNotRun = auto.filter((c) => c.state === 'unverified').length;
  const automated = {
    controls: auto.length, verified: autoVerified, failed: autoFailed, notRun: autoNotRun,
    passRatePct: autoVerified + autoFailed === 0 ? null : pct(autoVerified, autoVerified + autoFailed),
  };
  const provenPct = pct(sum.machine + sum.attested, sum.total);
  const blocking = (report.summary && report.summary.blocking) || 0;
  let level;
  if (blocking > 0) level = 0;
  else if (provenPct >= 90 && sum.failed === 0 && open.length === 0) level = 4;
  else if (provenPct >= 60 && open.length === 0) level = 3;
  else if (provenPct >= 30) level = 2;
  else level = 1;

  const grades = computeGrades(report, sum, provenPct);

  const needs = [];
  if (level === 0) needs.push(`corrigir, ou aceitar com dono e validade, os ${blocking} achado(s) bloqueante(s)`);
  else if (level < 4) {
    const target = level === 3 ? 90 : level === 2 ? 60 : 30;
    if (provenPct < target) needs.push(`chegar a ${target}% do peso provado (hoje ${provenPct}%)`);
    if (level >= 2 && open.length > 0) needs.push(`provar ou corrigir os ${open.length} controle(s) alto(s) ou crítico(s) que falham ou estão sem prova`);
    if (level === 3 && sum.failed > 0) needs.push('zerar os controles que falham');
  }
  const nextStep = level === 4
    ? 'Manter as atestações dentro da validade e rodar o kit a cada PR.'
    : `Para o nível ${level + 1} (${LEVELS[level + 1].name}): ${needs.join('; ') || 'continuar provando controles'}.`;

  return {
    method: 'v2',
    disclaimer: DISCLAIMER,
    grade: grades.overall,
    gradeBand: grades.band,
    grades,
    level,
    levelName: LEVELS[level].name,
    levelRule: LEVELS[level].rule,
    applicableControls: applicable,
    provenPct,
    machinePct: pct(sum.machine, sum.total),
    attestedPct: pct(sum.attested, sum.total),
    failedPct: pct(sum.failed, sum.total),
    unverifiedPct: pct(sum.unverified, sum.total),
    highOrCriticalOpen: open.length,
    automated,
    nextStep,
    byPhase: PHASES.map(([k]) => byPhase[k]).filter((b) => b.controls > 0).map((b) => ({
      phase: b.phase,
      name: b.name,
      controls: b.controls,
      grade: sliceGrade(b),
      provenPct: pct(b.machine + b.attested, b.total),
      machinePct: pct(b.machine, b.total),
      attestedPct: pct(b.attested, b.total),
      failedPct: pct(b.failed, b.total),
      unverifiedPct: pct(b.unverified, b.total),
    })),
    byPack: Object.values(byPack)
      .sort((a, b) => a.pack.localeCompare(b.pack))
      .map((p) => ({
        pack: p.pack,
        title: p.title,
        controls: p.controls,
        grade: sliceGrade(p),
        provenPct: pct(p.machine + p.attested, p.total),
        machinePct: pct(p.machine, p.total),
        attestedPct: pct(p.attested, p.total),
        failedPct: pct(p.failed, p.total),
        unverifiedPct: pct(p.unverified, p.total),
      })),
  };
}

module.exports = { WEIGHT, LEVELS, PHASES, BANDS, DISCLAIMER, computeScore, computeGrades, bandOf, gradeText };
