'use strict';

// Agrupa os achados bloqueantes por CAUSA (o controle), em vez de listar cada ocorrência.
// Cinco Actions sem SHA são uma causa só, com uma correção só.

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function groupCauses(report) {
  const out = [];
  for (const c of report.controls) {
    const blocking = c.findings.filter((f) => f.blocking);
    if (!blocking.length) continue;
    const severity = blocking.map((f) => f.severity).sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b])[0];
    out.push({
      id: c.id,
      title: c.title,
      severity,
      count: blocking.length,
      locations: [...new Set(blocking.map((f) => f.location).filter(Boolean))],
      example: blocking[0].message,
      remediation: c.remediation || '',
    });
  }
  return out.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.count - a.count || a.id.localeCompare(b.id));
}

module.exports = { groupCauses };
