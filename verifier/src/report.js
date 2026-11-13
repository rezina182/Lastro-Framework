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
  if (r.score) {
    const k = r.score;
    out.push(`Maturidade: nível ${k.level} (${k.levelName}) | provado ${k.provenPct}% (máquina ${k.machinePct}%, autodeclarado ${k.attestedPct}%) | falhando ${k.failedPct}% | sem prova ${k.unverifiedPct}%`);
    out.push(`  ${k.nextStep}`);
    out.push(`  ${k.disclaimer}`);
  }
  if (r.target.url) out.push(`Alvo HTTP: ${r.target.url}${r.target.active ? ' (sondas ativas ligadas)' : ' (somente sondas passivas)'} | ${r.target.requestsSent} requisições, intervalo mínimo de ${r.target.delayMs} ms`);

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

const md = (s) => String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const STATE_PT = { verified: 'verificado', failed: 'falhando', unverified: 'sem prova', not_applicable: 'não se aplica' };
const SEV_PT = { critical: 'crítica', high: 'alta', medium: 'média', low: 'baixa' };

/**
 * Relatório em Markdown para leitura humana (adoção, revisão, conversa com a equipe).
 * `coverage` (opcional) é o resultado de asvs.coverage(..., { states }) para incluir a cobertura do ASVS.
 */
function formatMarkdown(r, { coverage = null } = {}) {
  const k = r.score;
  const s = r.summary;
  const out = [];
  out.push(`# Relatório LASTRO: ${md(r.profile.name)}`, '');
  out.push(`Gerado em ${r.generatedAt.slice(0, 10)} | LASTRO ${r.tool.version} | catálogo ${r.catalogVersion} | veredito: **${VERDICT[r.verdict]}**`);
  out.push(r.target.url
    ? `Alvo HTTP: ${md(r.target.url)} (${r.target.active ? 'sondas ativas ligadas' : 'somente sondas passivas'}, ${r.target.requestsSent} requisições).`
    : 'Escopo: somente verificações estáticas do repositório. Nenhuma requisição foi feita à aplicação, então cabeçalhos, cookies, CSP e HSTS ficaram sem verificação.');
  out.push('');
  if (k) {
    out.push('## Maturidade', '');
    out.push(`**Nível ${k.level}: ${k.levelName}.** Regra do nível: ${k.levelRule}.`, '');
    out.push('| Provado | Por máquina | Autodeclarado | Falhando | Sem prova |', '|---|---|---|---|---|');
    out.push(`| ${k.provenPct}% | ${k.machinePct}% | ${k.attestedPct}% | ${k.failedPct}% | ${k.unverifiedPct}% |`, '');
    out.push(`Próximo passo: ${k.nextStep}`, '');
    out.push(`> ${k.disclaimer}`, '');
    out.push('### Por pacote', '', '| Pacote | Controles | Provado | Falhando | Sem prova |', '|---|---|---|---|---|');
    for (const p of k.byPack) out.push(`| ${md(p.title.split(':')[0])} | ${p.controls} | ${p.provenPct}% | ${p.failedPct}% | ${p.unverifiedPct}% |`);
    out.push('');
  }
  out.push('## Resumo', '');
  out.push(`- Controles aplicáveis: ${s.applicable} (verificados ${s.verified}, falhando ${s.failed}, sem prova ${s.unverified}); não se aplicam: ${s.notApplicable}.`);
  out.push(`- Achados bloqueantes: ${s.blocking}. Dívida em baseline: ${s.debt}. Riscos aceitos: ${s.accepted}.`, '');

  const blocking = r.controls.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => ({ c, f })));
  out.push('## Achados que bloqueiam', '');
  if (!blocking.length) out.push('Nenhum.', '');
  else {
    out.push('| Controle | Gravidade | Onde | O que |', '|---|---|---|---|');
    for (const { c, f } of blocking.sort((a, b) => SEV_ORDER[a.f.severity] - SEV_ORDER[b.f.severity])) {
      out.push(`| ${c.id} | ${SEV_PT[f.severity]} | ${md(f.location || '-')} | ${md(f.message)} |`);
    }
    out.push('');
  }

  const failing = r.controls.filter((c) => c.findings.some((f) => !f.blocking));
  out.push('## Outros achados (não bloqueiam)', '');
  if (!failing.length) out.push('Nenhum.', '');
  else {
    out.push('Agrupados por controle. Cada um pede uma decisão: corrigir, justificar ou aceitar o risco com dono e validade.', '');
    out.push('| Controle | Título | Achados | Maior gravidade | Exemplo |', '|---|---|---|---|---|');
    for (const c of failing.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id))) {
      const fs = c.findings.filter((f) => !f.blocking);
      const worst = fs.map((f) => f.severity).sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b])[0];
      out.push(`| ${c.id} | ${md(c.title)} | ${fs.length} | ${SEV_PT[worst]} | ${md(fs[0].message.slice(0, 140))}${fs[0].location ? ` (${md(fs[0].location)})` : ''} |`);
    }
    out.push('');
  }

  const open = r.controls.filter((c) => c.state === 'unverified').sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id));
  out.push('## Controles sem prova', '');
  out.push(`${open.length} controle(s) sem prova não contam como aprovados. A maioria é manual: a prova é uma atestação com responsável e validade em \`.lastro/status.json\`, ou uma verificação HTTP que exige \`--url\`.`, '');
  if (open.length) {
    out.push('| Controle | Gravidade | Título | Por quê |', '|---|---|---|---|');
    for (const c of open) out.push(`| ${c.id} | ${SEV_PT[c.severity]} | ${md(c.title)} | ${md((c.notes[0] || '').slice(0, 90))} |`);
    out.push('');
  }

  if (coverage) {
    const t = coverage.totals;
    out.push(`## Cobertura do ASVS ${coverage.version} (até L${coverage.level})`, '');
    out.push(`${t.total} requisitos. Verificados: ${t.verified}. Falhando: ${t.failed}. Sem prova: ${t.unverified}. Fora do perfil: ${t.outOfProfile}. Sem controle: ${t.none}.`, '');
    out.push('Um requisito só conta como verificado quando um controle que o cobre por inteiro está verificado.', '');
    out.push('| Capítulo | Total | Verificados | Falhando | Sem prova | Fora do perfil |', '|---|---|---|---|---|---|');
    for (const ch of Object.keys(coverage.byChapter).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)))) {
      const b = coverage.byChapter[ch];
      out.push(`| ${ch} ${md(b.name)} | ${b.total} | ${b.verified} | ${b.failed} | ${b.unverified} | ${b.outOfProfile} |`);
    }
    out.push('');
  }

  if (r.warnings.length) out.push('## Avisos', '', ...r.warnings.map((w) => `- ${md(w)}`), '');
  out.push('## Limites', '');
  out.push('- As varreduras de código são heurísticas por texto, linha a linha: erram para os dois lados e não substituem revisão.');
  out.push('- A pontuação e a cobertura medem evidência e progresso do kit. Elas não certificam a aplicação nem provam conformidade com o ASVS.');
  out.push('- Atestação é autodeclaração com prazo. Quem escreveu o código não deve ser o único a atestar controles de nível alto.', '');
  return out.join('\n');
}

module.exports = { formatReport, formatMarkdown };
