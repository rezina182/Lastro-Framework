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

function computeScore(report, { packTitles = {} } = {}) {
  const sum = { total: 0, machine: 0, attested: 0, failed: 0, unverified: 0 };
  const byPack = {};
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
  }

  const provenPct = pct(sum.machine + sum.attested, sum.total);
  const blocking = (report.summary && report.summary.blocking) || 0;
  let level;
  if (blocking > 0) level = 0;
  else if (provenPct >= 90 && sum.failed === 0 && open.length === 0) level = 4;
  else if (provenPct >= 60 && open.length === 0) level = 3;
  else if (provenPct >= 30) level = 2;
  else level = 1;

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
    method: 'v1',
    disclaimer: DISCLAIMER,
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
    nextStep,
    byPack: Object.values(byPack)
      .sort((a, b) => a.pack.localeCompare(b.pack))
      .map((p) => ({
        pack: p.pack,
        title: p.title,
        controls: p.controls,
        provenPct: pct(p.machine + p.attested, p.total),
        machinePct: pct(p.machine, p.total),
        attestedPct: pct(p.attested, p.total),
        failedPct: pct(p.failed, p.total),
        unverifiedPct: pct(p.unverified, p.total),
      })),
  };
}

module.exports = { WEIGHT, LEVELS, DISCLAIMER, computeScore };
