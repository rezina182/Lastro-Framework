'use strict';

// Relatório legível em texto puro (sem cores, para funcionar igual em terminal, CI e arquivo).

const VERDICT = { pass: 'APROVADO', fail: 'FALHA', incomplete: 'INCOMPLETO' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function formatReport(r) {
  const s = r.summary;
  const out = [];
  out.push(`LASTRO ${r.tool.version} | catálogo ${r.catalogVersion} | perfil "${r.profile.name}" | veredito: ${VERDICT[r.verdict]}`);
  out.push(`Controles aplicáveis: ${s.applicable} | verificados: ${s.verified} | com falha: ${s.failed} | não verificados: ${s.unverified} | não se aplicam: ${s.notApplicable}`);
  out.push(`Achados bloqueantes (novos, alta/crítica): ${s.blocking} | dívida em baseline: ${s.debt} | riscos aceitos: ${s.accepted}`);
  if (r.target.url) out.push(`Alvo HTTP: ${r.target.url}${r.target.active ? ' (sondas ativas ligadas)' : ' (somente sondas passivas)'}`);

  const blocking = r.controls.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => ({ c, f })));
  if (blocking.length) {
    out.push('', 'BLOQUEIAM A PUBLICAÇÃO:');
    for (const { c, f } of blocking.sort((a, b) => SEV_ORDER[a.f.severity] - SEV_ORDER[b.f.severity])) {
      out.push(`  [${c.id}] ${f.severity.toUpperCase()} ${f.message}${f.location ? ` (${f.location})` : ''}  #${f.fingerprint}`);
    }
  }

  const others = r.controls.flatMap((c) => c.findings.filter((f) => !f.blocking).map((f) => ({ c, f })));
  if (others.length) {
    out.push('', 'OUTROS ACHADOS (não bloqueiam):');
    for (const { c, f } of others.sort((a, b) => SEV_ORDER[a.f.severity] - SEV_ORDER[b.f.severity]).slice(0, 40)) {
      const tag = f.accepted ? 'aceito' : f.inBaseline ? 'baseline' : f.severity;
      out.push(`  [${c.id}] ${tag}: ${f.message}${f.location ? ` (${f.location})` : ''}  #${f.fingerprint}`);
    }
    if (others.length > 40) out.push(`  ... e mais ${others.length - 40}.`);
  }

  const unverified = r.controls.filter((c) => c.state === 'unverified');
  if (unverified.length) {
    out.push('', 'NÃO VERIFICADOS (sem prova, não contam como aprovados):');
    for (const c of unverified.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])) {
      out.push(`  [${c.id}] ${c.severity}: ${c.title}${c.notes[0] ? ` - ${c.notes[0]}` : ''}`);
    }
  }
  if (r.warnings.length) {
    out.push('', 'AVISOS:');
    for (const w of r.warnings) out.push(`  ${w}`);
  }
  return out.join('\n');
}

module.exports = { formatReport };
