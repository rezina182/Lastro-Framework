'use strict';

// A história dos resultados, contada para gente: o que já foi feito, o que precisa de atenção, o que fazer agora
// e o que alguém precisa decidir. Também monta o retrato de cada escopo (pacote): o que já está implementado e
// como foi provado. Só organiza o que o relatório já tem; não inventa prova nem muda estado de controle.
// Saída em texto puro: quem desenha (HTML, Markdown) escapa.

const { diff } = require('./history');
const { gradeText } = require('./score');
const PM = require('./proofmap');

const DAY_MS = 24 * 60 * 60 * 1000;
const EXPIRING_DAYS = 30;
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_PT = { critical: 'crítica', high: 'alta', medium: 'média', low: 'baixa' };
const MAX_ITEMS = 8;
const STATE_PT = { verified: 'verificado', failed: 'falhando', unverified: 'sem prova', not_applicable: 'não se aplica' };

const isAttested = (c) => !!(c.evidence && c.evidence.source === 'manual-attestation');
const bySev = (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id);
const daysLeft = (iso, now) => Math.floor((Date.parse(iso) - now.getTime()) / DAY_MS);
// Notas das sondas autenticadas (authprobe.js): "Sonda autenticada: passou em N teste(s)..." ou "...inconclusiva...".
const probePassed = (c) => (c.notes || []).some((n) => /^Sonda autenticada: passou/.test(n));
// Controle manual que falhou com evidência de sonda HTTP: a falha veio da sonda autenticada (engine.overlayProbe).
const probeFailed = (c) => c.checkType === 'manual' && c.state === 'failed' && !!(c.evidence && c.evidence.source === 'verifier-http');

/** Como o controle foi (ou não foi) provado, em uma frase. */
function proofOf(c, now, disc = null) {
  if (c.state === 'verified') {
    if (isAttested(c)) {
      const left = daysLeft(c.evidence.expiresAt, now);
      return `atestado por ${c.evidence.attestedBy} em ${String(c.evidence.collectedAt).slice(0, 10)}, vale até ${String(c.evidence.expiresAt).slice(0, 10)}${left <= EXPIRING_DAYS ? ` (vence em ${Math.max(0, left)} dia(s))` : ''}`;
    }
    return c.evidence && c.evidence.source === 'verifier-http' ? 'provado por sonda HTTP do kit' : 'provado pela leitura do repositório';
  }
  if (c.state === 'failed') {
    const n = c.findings.length;
    const b = c.findings.filter((f) => f.blocking).length;
    const acc = c.findings.filter((f) => f.accepted).length;
    return `${n} achado(s)${b ? `, ${b} bloqueante(s)` : ''}${acc ? `, ${acc} com risco aceito` : ''}${probeFailed(c) ? '; falha achada por sonda autenticada' : ''}`;
  }
  if (c.state === 'unverified') {
    if (c.controlRiskAccepted) return `sem prova, com risco aceito (${c.controlRiskAccepted})`;
    if ((c.notes || []).some((x) => /Atestação expirada/.test(x))) return 'atestação vencida: o teste precisa ser repetido';
    if (c.checkType === 'automated') return 'verificação automática não rodou (por exemplo, sonda HTTP sem --url)';
    if (probePassed(c)) return 'sem prova; a sonda autenticada passou nas rotas do perfil, o que ajuda a atestação mas não verifica';
    if (!disc) return 'sem prova: teste manual e atestação';
    const p = PM.proofFor(c, disc);
    if (p.likelyNA) return `sem prova; provavelmente não se aplica (${p.likelyNA})`;
    return `sem prova; caminho: ${p.viaLabel}${p.hints.length ? `; indício no código: ${p.hints.join('; ')}` : ''}`;
  }
  return 'não se aplica';
}

/** O que fazer com o controle, em uma frase. */
function nextOf(c, disc = null) {
  if (c.state === 'verified') return isAttested(c) ? 'manter: repetir o teste antes do vencimento' : 'manter: o kit confere a cada execução';
  if (c.state === 'failed') return c.remediation || 'corrigir e rodar o kit de novo';
  if (c.state === 'unverified') {
    if (c.checkType === 'automated') return 'rodar o kit com --url num ambiente local ou de staging';
    const p = disc ? PM.proofFor(c, disc) : null;
    if (p && p.likelyNA) return 'confirmar e registrar "não se aplica" com a justificativa (lastro gaps traz o trecho)';
    if (p && p.via === 'sonda-auth' && p.runsToday) return 'rodar lastro check --url ... --auth com duas contas de teste, e atestar o que a sonda não cobre';
    if (p && p.via === 'sonda' && p.runsToday) return 'rodar lastro check --url ... --active --confirm-non-production em local ou staging, e atestar o que a sonda não cobre';
    if (p && p.via === 'codigo') return `confirmar no código${p.hints.length ? ' (veja o indício)' : ''} e registrar a atestação (lastro playbook --only ${c.id})`;
    return `seguir o playbook (lastro playbook --only ${c.id}) e registrar a atestação`;
  }
  return '-';
}

/** Retrato por escopo (pacote): nota, contagens e cada controle com prova e próximo passo. */
function scopes(report, { now = new Date() } = {}) {
  const k = report.score;
  const packs = (k && k.byPack) || [];
  return packs.map((p) => {
    const list = report.controls.filter((c) => c.pack === p.pack && c.state !== 'not_applicable')
      .map((c) => ({ ...c, findings: c.findings || [], notes: c.notes || [] })).sort(bySev);
    const disc = (report.threatModel && report.threatModel.discovery) || null;
    const row = (c) => ({ id: c.id, title: c.title, severity: c.severity, severityName: SEV_PT[c.severity], state: c.state, proof: proofOf(c, now, disc), next: nextOf(c, disc) });
    return {
      pack: p.pack,
      title: p.title,
      grade: p.grade,
      provenPct: p.provenPct,
      machinePct: p.machinePct,
      attestedPct: p.attestedPct,
      failedPct: p.failedPct,
      done: list.filter((c) => c.state === 'verified').map(row),
      failing: list.filter((c) => c.state === 'failed').map(row),
      missing: list.filter((c) => c.state === 'unverified').map(row),
    };
  });
}

const cap = (arr) => (arr.length > MAX_ITEMS ? [...arr.slice(0, MAX_ITEMS), `e mais ${arr.length - MAX_ITEMS}.`] : arr);

/**
 * A história desta execução. `history` é a lista de registros gravados (pode ser vazia) e `current` o registro
 * da execução atual (history.snapshot). Devolve listas de frases.
 */
function buildStory(report, { history = [], current = null, now = new Date() } = {}) {
  const k = report.score;
  const tm = report.threatModel;
  const ctl = report.controls.filter((c) => c.state !== 'not_applicable').map((c) => ({ ...c, findings: c.findings || [], notes: c.notes || [] }));
  const prev = history.length ? history[history.length - 1] : null;
  const same = prev && current && prev.generatedAt === current.generatedAt;
  const before = same ? (history.length > 1 ? history[history.length - 2] : null) : prev;
  const d = current ? diff(before, current) : { improved: [], worsened: [], added: [], removed: [] };

  const done = [];
  const machine = ctl.filter((c) => c.state === 'verified' && !isAttested(c));
  const attested = ctl.filter((c) => c.state === 'verified' && isAttested(c));
  if (machine.length) done.push(`${machine.length} controle(s) provado(s) pela máquina a cada execução.`);
  if (attested.length) done.push(`${attested.length} controle(s) testado(s) por uma pessoa e atestado(s) com prazo.`);
  for (const s of scopes({ ...report, controls: ctl }, { now }).filter((x) => x.missing.length === 0 && x.failing.length === 0 && x.done.length)) done.push(`Escopo "${s.title.split(':')[0]}" com todos os controles provados.`);
  if (tm && tm.counts.mitigated) done.push(`${tm.counts.mitigated} ameaça(s) do modelo com todos os controles provados.`);
  if (tm && tm.reviewed) done.push(`Modelo de ameaças revisado por ${tm.reviewedBy} em ${String(tm.reviewedAt).slice(0, 10)}.`);
  if (d.improved.length) done.push(`Desde o registro anterior, melhoraram: ${d.improved.map((x) => x.id).join(', ')}.`);
  if (before && current && Number.isFinite(current.grade) && Number.isFinite(before.grade) && current.grade > before.grade) done.push(`A nota subiu de ${gradeText(before.grade)} para ${gradeText(current.grade)}.`);

  const attention = [];
  // Se a execução anterior rodou as sondas HTTP e esta não, o que virou "sem prova" não piorou: só não foi medido agora.
  const lostHttp = !!(before && current && before.http && !current.http);
  const notMeasured = lostHttp ? d.worsened.filter((x) => x.to === 'unverified') : [];
  const worsened = d.worsened.filter((x) => !notMeasured.includes(x));
  if (worsened.length) attention.push(`Pioraram desde o registro anterior: ${worsened.map((x) => `${x.id} (${STATE_PT[x.from]} para ${STATE_PT[x.to]})`).join(', ')}.`);
  if (notMeasured.length) attention.push(`${notMeasured.length} controle(s) ficaram sem prova só porque esta execução não rodou as sondas HTTP e a anterior rodou (${notMeasured.slice(0, 6).map((x) => x.id).join(', ')}${notMeasured.length > 6 ? '...' : ''}). Não é piora da aplicação: compare execuções do mesmo tipo.`);
  const failingNonBlocking = ctl.filter((c) => c.state === 'failed' && !c.findings.some((f) => f.blocking)).sort(bySev);
  if (failingNonBlocking.length) attention.push(`Falhando sem bloquear o portão (gravidade menor, baseline ou risco aceito): ${failingNonBlocking.map((c) => c.id).join(', ')}.`);
  for (const c of attested) {
    const left = daysLeft(c.evidence.expiresAt, now);
    if (left <= EXPIRING_DAYS) attention.push(`A atestação de ${c.id} vence em ${Math.max(0, left)} dia(s) (${c.evidence.attestedBy}).`);
  }
  const expired = ctl.filter((c) => c.state === 'unverified' && (c.notes || []).some((x) => /Atestação expirada/.test(x)));
  if (expired.length) attention.push(`Atestações vencidas, voltaram a "sem prova": ${expired.map((c) => c.id).join(', ')}.`);
  if (tm && tm.surface && tm.surface.changes && tm.surface.changes.length) attention.push(`O código mudou a superfície desde a gravação do modelo de ameaças: ${tm.surface.changes.slice(0, 4).join('; ')}.`);
  if (tm && tm.surface && tm.surface.reviewBeforeChange) attention.push('A revisão do modelo de ameaças é anterior à última mudança da superfície.');
  if (tm && tm.counts.exposed) attention.push(`${tm.counts.exposed} ameaça(s) exposta(s): algum controle delas está falhando.`);
  if (report.target && !report.target.url) attention.push('Nenhuma sonda HTTP rodou: cabeçalhos, cookies, CSP e HSTS ficaram sem prova. Rode com --url em local ou staging.');
  if (report.catalogVersion && before && before.catalog && before.catalog !== report.catalogVersion) attention.push(`O catálogo mudou (${before.catalog} para ${report.catalogVersion}): parte da variação vem de controles novos.`);

  const todo = [];
  const blockers = ctl.filter((c) => c.findings.some((f) => f.blocking)).sort(bySev);
  // O motivo concreto vem do achado bloqueante; o texto genérico do catálogo só entra quando o achado não diz nada.
  for (const c of blockers) {
    const why = (c.findings.find((f) => f.blocking) || {}).message;
    todo.push(`Corrigir ${c.id} (${c.title}): ${String(why || c.remediation || 'ver o relatório').replace(/\.\s*$/, '')}.`);
  }
  if (blockers.length && blockers.some((c) => ['CORE-006', 'CORE-010', 'CORE-011'].includes(c.id))) todo.push('Parte disso é previsível: "lastro fix" prepara a correção num branch novo.');
  const openHigh = ctl.filter((c) => c.state === 'unverified' && (c.severity === 'critical' || c.severity === 'high') && !c.controlRiskAccepted).sort(bySev);
  if (openHigh.length) todo.push(`Provar os ${openHigh.length} controle(s) alto(s) ou crítico(s) sem prova, começando por ${openHigh.slice(0, 4).map((c) => c.id).join(', ')} (lastro playbook).`);
  if (k && k.nextStep) todo.push(k.nextStep);

  const decide = [];
  if (tm && !tm.reviewed) decide.push(tm.persisted ? `Revisar o modelo de ameaças e registrar reviewedBy e reviewedAt (${tm.counts.pending} ameaça(s) sem decisão).` : 'Gravar e revisar o modelo de ameaças (lastro threat-model --write).');
  else if (tm && tm.counts.pending) decide.push(`${tm.counts.pending} ameaça(s) sem decisão ou com aceitação vencida.`);
  if (tm) for (const t of tm.threats.filter((x) => x.decision === 'accept' && x.expires && !x.pending && daysLeft(x.expires, now) <= EXPIRING_DAYS)) decide.push(`A aceitação de ${t.id} (${t.owner}) vence em ${Math.max(0, daysLeft(t.expires, now))} dia(s): renovar ou mitigar.`);
  if (report.summary && report.summary.debt) decide.push(`${report.summary.debt} achado(s) no baseline: dívida conhecida, que precisa de dono e prazo.`);
  if (blockers.length) decide.push('Para cada bloqueante que não der para corrigir agora: aceitar o risco com dono, justificativa e validade (.lastro/risks), ou registrar no baseline.');
  if (k && report.context && !report.context.meetsTarget) decide.push(`A meta de maturidade para o risco desta aplicação é o nível ${report.context.targetLevel}; hoje é ${k.level}. Confirmar a meta ou o prazo para chegar.`);

  const why = PM.explainGaps(PM.analyzeGaps({ ...report, controls: report.controls.map((c) => ({ ...c, findings: c.findings || [], notes: c.notes || [] })) }));
  const g = k && k.grades;
  const headline = g
    ? `Nota ${gradeText(g.overall)} de 10 (${g.band}). ${blockers.length ? `${blockers.length} controle(s) bloqueiam o portão.` : 'Nada bloqueia o portão.'} ${k.provenPct}% do peso tem prova.`
    : null;
  return { headline, why, done: cap(done), attention: cap(attention), todo: cap(todo), decide: cap(decide) };
}

/** Registro de decisões: quem decidiu o quê, quando e até quando. */
function decisions(report, { now = new Date() } = {}) {
  const out = [];
  for (const c of report.controls) {
    const na = isAttested(c) && c.evidence.decision === 'not_applicable';
    if (isAttested(c)) out.push({ kind: na ? 'Não se aplica' : 'Atestação', ref: c.id, what: na ? `${c.title}: ${String((c.notes || [])[0] || '').replace(/^.*?\):\s*/, '')}` : c.title, who: c.evidence.attestedBy, when: String(c.evidence.collectedAt).slice(0, 10), until: String(c.evidence.expiresAt).slice(0, 10), expiring: daysLeft(c.evidence.expiresAt, now) <= EXPIRING_DAYS });
    const riskIds = [...new Set([c.controlRiskAccepted, ...c.findings.filter((f) => f.accepted).map((f) => f.riskId)].filter(Boolean))];
    for (const id of riskIds) out.push({ kind: 'Risco aceito', ref: c.id, what: `${id}: ${c.title}`, who: '-', when: '-', until: '-', expiring: false });
  }
  const tm = report.threatModel;
  if (tm) {
    if (tm.reviewedBy) out.push({ kind: 'Revisão do modelo de ameaças', ref: 'threat-model', what: `${tm.counts.threats} ameaça(s)`, who: tm.reviewedBy, when: String(tm.reviewedAt).slice(0, 10), until: '-', expiring: false });
    for (const t of tm.threats.filter((x) => x.decision)) {
      const label = { mitigate: 'Ameaça: mitigar', accept: 'Ameaça: aceitar', not_applicable: 'Ameaça: não se aplica' }[t.decision];
      out.push({ kind: label, ref: t.id, what: t.rationale || t.title, who: t.owner || '-', when: '-', until: t.expires ? String(t.expires).slice(0, 10) : '-', expiring: !!(t.expires && daysLeft(t.expires, now) <= EXPIRING_DAYS) });
    }
  }
  return out;
}

module.exports = { buildStory, scopes, decisions, proofOf, nextOf, EXPIRING_DAYS };
