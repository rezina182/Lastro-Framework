'use strict';

// Portal estático (lastro site): poucas páginas HTML autocontidas, sem script e sem servidor, para o dev e para o
// time de segurança verem a evolução, o relatório atual, o playbook e o histórico. Os links entre páginas só
// apontam para os arquivos do próprio portal (lista fechada); os demais, só para fontes oficiais.

const fs = require('node:fs');
const path = require('node:path');
const { formatHtml, ui } = require('./html');
const { formatPlaybookHtml } = require('./playbook');
const { diff } = require('./history');
const { gradeText } = require('./score');
const ST = require('./story');
const R = require('./risk');
const { loadCatalog } = require('./catalog');

const { h, num, table, htmlShell, pctText, sevBadge } = ui;

const PAGES = [
  ['index.html', 'Visão geral'], ['escopos.html', 'Implementado por escopo'], ['decisoes.html', 'Decisões'],
  ['relatorio.html', 'Relatório atual'], ['playbook.html', 'Playbook'], ['historico.html', 'Histórico'],
];
const PAGE_NAMES = new Set(PAGES.map(([f]) => f));
const MARKER = '.lastro-site';
const DAY_MS = 24 * 60 * 60 * 1000;
const EXPIRING_DAYS = 30;
const STATE_PT = { verified: 'verificado', failed: 'falhando', unverified: 'sem prova', not_applicable: 'não se aplica' };
const VERDICT_PT = { pass: 'aprovado', fail: 'falha', incomplete: 'incompleto' };

// Faixa da marca no topo de todas as páginas, com a navegação entre elas.
function siteNav(current) {
  const links = PAGES.map(([f, t]) => (f === current ? `<strong aria-current="page">${h(t)}</strong>` : `<a href="${h(f)}">${h(t)}</a>`));
  return `<div class="topbar"><div class="wrap"><span class="brand">LASTRO</span><nav aria-label="Páginas do portal">${links.join('')}</nav></div></div>`; // lastro-ignore xss-sinks: links montados acima com h()
}

// ---- Peças visuais do portal (texto do projeto sempre passa por h(); números por num()) ----

const shortTitle = (t) => String(t).split(':')[0];
const clamp10 = (v) => Math.min(10, Math.max(0, num(v)));
/** Cor da barra pela faixa da nota: Forte ou mais, Bom, Em evolução, Inicial. */
const toneOf = (g) => (!Number.isFinite(g) ? 'info' : g >= 8 ? 'ok' : g >= 6 ? 'info' : g >= 4 ? 'warn' : 'bad');

/** Lista de barras horizontais (nota de 0 a 10). `nameHtml` já vem escapado pelo chamador. */
function rankList(items, label) {
  const li = items.map((i) => `<li><span class="rank-name">${i.nameHtml}${i.sub ? `<small>${h(i.sub)}</small>` : ''}</span><span class="rank-track" role="img" aria-label="${h(`${i.name}: ${i.text}`)}"><span class="f-${toneOf(i.value)}" style="width:${num(Math.round(clamp10(i.value) * 10))}%"></span></span><span class="rank-val">${h(i.text)}</span></li>`); // lastro-ignore xss-sinks: nameHtml escapado pelo chamador; o resto com h() e num()
  return `<ul class="rank" aria-label="${h(label)}">${li.join('')}</ul>`; // lastro-ignore xss-sinks: itens montados acima
}

/** Cartão de indicador: rótulo, valor grande, nota e a cor da borda superior. `value` já vem escapado. */
const kpi = (label, value, note, tone) => `<div class="card kpi k-${tone}"><p class="card-label">${h(label)}</p><p class="card-value">${value}</p>${note ? `<p class="card-note">${h(note)}</p>` : ''}</div>`; // lastro-ignore xss-sinks: tone vem de toneOf (lista fixa) e value é escapado pelo chamador

/** "17/11/2026, 12:00 UTC" a partir do ISO gravado no relatório. */
function fmtDate(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(String(iso));
  return m ? `${m[3]}/${m[2]}/${m[1]}, ${m[4]}:${m[5]} UTC` : String(iso).slice(0, 10);
}

/** Que tipo de execução gerou o relatório: só o repositório, ou com as sondas HTTP (e quais). */
function runKind(report) {
  const t = report.target || {};
  if (!t.url) return 'estática (só o repositório)';
  const extra = [t.active ? 'ativas' : null, t.authProbes ? 'autenticadas' : null].filter(Boolean);
  return `com sondas HTTP${extra.length ? ` ${extra.join(' e ')}` : ' passivas'}`;
}

/** Barra de filtros comum às páginas: o recorte que o leitor está vendo. */
function filtersOf(report) {
  const packs = ((report.score && report.score.byPack) || []).map((p) => shortTitle(p.title));
  return [
    ['Escopo', packs.length ? packs.join(', ') : 'nenhum escopo aplicável'],
    ['Execução', runKind(report)],
    ['Gerado em', fmtDate(report.generatedAt)],
    ['Catálogo', report.catalogVersion],
  ];
}

let CATALOG = null;
const catalogOf = (c) => c || (CATALOG = CATALOG || loadCatalog());

/** Acrescenta a navegação do portal num documento já pronto (relatório). */
function withNav(html, current) {
  const at = html.indexOf('<a class="skip"');
  if (at < 0) return html;
  const end = html.indexOf('</a>', at) + 4;
  return `${html.slice(0, end)}\n${siteNav(current)}${html.slice(end)}`;
}

/** Gráfico de linhas em SVG estático: % provado e % falhando ao longo do tempo. */
function evolutionSvg(points) {
  if (points.length < 2) return '<p>O gráfico aparece a partir de dois registros no histórico (<code>lastro history --write</code>).</p>';
  const W = 720;
  const H = 240;
  const L = 44;
  const B = 34;
  // Coordenadas sempre numéricas (num) e formatadas; os textos vindos do histórico passam por h().
  const x = (i) => (L + (i * (W - L - 16)) / (points.length - 1)).toFixed(1);
  const y = (v) => (12 + ((100 - Math.min(100, Math.max(0, num(v)))) * (H - B - 12)) / 100).toFixed(1);
  const coords = (key) => points.map((p, i) => `${x(i)},${y(p[key])}`).join(' ');
  const line = (key, cls) => `<polyline class="${h(cls)}" fill="none" stroke-width="2.5" points="${h(coords(key))}"/>`;
  const grid = [0, 25, 50, 75, 100].map((v) => `<line x1="${num(L)}" x2="${num(W - 16)}" y1="${h(y(v))}" y2="${h(y(v))}" stroke="currentColor" stroke-opacity=".15"/><text x="${num(L - 6)}" y="${h((Number(y(v)) + 4).toFixed(1))}" text-anchor="end" font-size="11">${num(v)}%</text>`);
  const step = Math.max(1, Math.ceil(points.length / 8));
  const labels = points.map((p, i) => (i % step === 0 || i === points.length - 1 ? `<text x="${h(x(i))}" y="${num(H - 10)}" text-anchor="middle" font-size="11">${h(p.generatedAt.slice(5, 10))}</text>` : '')).join('');
  return [
    `<svg role="img" aria-labelledby="g-t g-d" viewBox="0 0 ${num(W)} ${num(H)}" width="100%" style="max-width:${num(W)}px;color:var(--text)">`,
    '<title id="g-t">Evolução da evidência</title>',
    `<desc id="g-d">Percentual do peso provado e percentual falhando em ${num(points.length)} execuções, da mais antiga à mais recente.</desc>`,
    '<style>.l-ok{stroke:var(--ok)}.l-bad{stroke:var(--bad)}</style>',
    ...grid, line('provenPct', 'l-ok'), line('failedPct', 'l-bad'), labels, '</svg>',
    '<p><span style="color:var(--ok)">━</span> provado (máquina e atestado) &nbsp; <span style="color:var(--bad)">━</span> falhando</p>',
  ].join('');
}

function attestationAlerts(report, now) {
  const soon = [];
  const expired = [];
  for (const c of report.controls) {
    if (c.evidence && c.evidence.source === 'manual-attestation') {
      const left = Math.floor((Date.parse(c.evidence.expiresAt) - now.getTime()) / DAY_MS);
      if (left <= EXPIRING_DAYS) soon.push({ id: c.id, title: c.title, by: c.evidence.attestedBy, left });
    }
    if (c.state === 'unverified' && (c.notes || []).some((x) => /Atestação expirada/.test(x))) expired.push({ id: c.id, title: c.title });
  }
  return { soon: soon.sort((a, b) => a.left - b.left), expired };
}

const STATE_CLS = { verified: 'ok', failed: 'bad', unverified: 'warn' };

function scopesPage({ report, now, theme }) {
  const list = ST.scopes(report, { now });
  const sections = [];
  sections.push('<section id="resumo-escopos" aria-labelledby="t-res"><h2 id="t-res">Resumo por escopo</h2>');
  sections.push('<p>Cada escopo é um pacote de controles do catálogo. "Já implementado" quer dizer provado: pela máquina a cada execução, ou por uma pessoa com atestação que tem prazo. Controle sem prova não conta como implementado, mesmo que o código pareça fazer a coisa certa.</p>');
  const ranked = [...list].sort((a, b) => num(b.grade) - num(a.grade) || a.pack.localeCompare(b.pack));
  sections.push('<div class="panel">', rankList(ranked.map((s) => ({
    name: shortTitle(s.title), nameHtml: `<a href="#esc-${h(s.pack)}">${h(shortTitle(s.title))}</a>`, value: s.grade, text: gradeText(s.grade),
    sub: `provado ${pctText(s.provenPct)} · ${s.done.length} implementado(s) · ${s.failing.length} falhando · ${s.missing.length} falta provar`,
  })), 'Nota de cada escopo, de 0 a 10'), '</div>');
  sections.push('</section>');
  for (const s of list) {
    sections.push(`<section id="esc-${h(s.pack)}" aria-labelledby="t-esc-${h(s.pack)}"><h2 id="t-esc-${h(s.pack)}">${h(shortTitle(s.title))}: nota ${h(gradeText(s.grade))} de 10</h2>`);
    sections.push('<div class="cards">',
      kpi('Nota do escopo', `${h(gradeText(s.grade))}<small> /10</small>`, '', toneOf(s.grade)),
      kpi('Peso provado', h(pctText(s.provenPct)), `máquina ${pctText(s.machinePct)}, atestado ${pctText(s.attestedPct)}`, 'info'),
      kpi('Falhando', String(num(s.failing.length)), `${pctText(s.failedPct)} do peso`, s.failing.length ? 'bad' : 'ok'),
      kpi('Falta provar', String(num(s.missing.length)), 'teste manual, sonda ou "não se aplica"', s.missing.length ? 'warn' : 'ok'),
      '</div>');
    const rows = [...s.done, ...s.failing, ...s.missing].map((c) => [
      `<strong>${h(c.id)}</strong> ${h(c.title)}`, h(c.severityName),
      `<span class="badge ${STATE_CLS[c.state] || 'info'}">${h(c.state === 'verified' ? 'implementado' : c.state === 'failed' ? 'falhando' : 'falta provar')}</span>`,
      h(c.proof), h(c.next),
    ]);
    sections.push(rows.length ? table(`Controles de ${s.title.split(':')[0]}`, ['Controle', 'Gravidade', 'Situação', 'Como foi provado', 'Próximo passo'], rows) : '<p class="empty">Nenhum controle aplicável.</p>');
    sections.push('</section>');
  }
  return htmlShell({
    title: `Implementado por escopo: ${report.profile.name}`, eyebrow: 'Portal LASTRO',
    meta: [`${list.length} escopo(s) aplicável(is): o que já está implementado, como foi provado e o que falta.`],
    nav: [['resumo-escopos', 'Resumo'], ...list.map((s) => [`esc-${s.pack}`, shortTitle(s.title)])],
    sections, theme, siteNav: siteNav('escopos.html'), filters: filtersOf(report),
  });
}

function decisionsPage({ report, now, theme }) {
  const list = ST.decisions(report, { now });
  const sections = ['<section id="registro" aria-labelledby="t-dec"><h2 id="t-dec">Registro de decisões</h2>'];
  sections.push('<p>O que uma pessoa decidiu e assinou: atestações (teste manual com prazo), riscos aceitos, a revisão do modelo de ameaças e a decisão sobre cada ameaça. O kit nunca cria nem muda essas decisões; ele só as lê dos arquivos em <code>.lastro/</code>.</p>');
  sections.push(list.length
    ? table('Decisões registradas', ['Tipo', 'Referência', 'O quê', 'Quem', 'Quando', 'Vale até'],
      list.map((d) => [h(d.kind), h(d.ref), h(d.what), h(d.who), h(d.when), d.expiring ? `<span class="warn">${h(d.until)} (vence logo)</span>` : h(d.until)]))
    : '<p class="empty">Nenhuma decisão registrada ainda. As decisões aparecem aqui quando alguém atesta um controle, aceita um risco ou revisa o modelo de ameaças.</p>');
  sections.push('</section>');
  const story = ST.buildStory(report, { now });
  sections.push('<section id="pendentes" aria-labelledby="t-pend"><h2 id="t-pend">Decisões pendentes</h2>');
  sections.push(story.decide.length ? `<ul>${story.decide.map((x) => `<li>${h(x)}</li>`).join('')}</ul>` : '<p class="empty">Nenhuma.</p>');
  sections.push('</section>');
  return htmlShell({
    title: `Decisões: ${report.profile.name}`, eyebrow: 'Portal LASTRO',
    meta: [`${list.length} decisão(ões) registrada(s)`],
    nav: [['registro', 'Registro'], ['pendentes', 'Pendentes']], sections, theme, siteNav: siteNav('decisoes.html'), filters: filtersOf(report),
  });
}

function riskCell(t) {
  return `${num(t.critical)} crítico, ${num(t.high)} alto, ${num(t.medium)} médio, ${num(t.low)} baixo`;
}

/** Sumário executivo em prosa: os números que importam e onde agir, no formato de um relatório de maturidade. */
function executiveSummary(report, list) {
  const s = report.score;
  const g = s.grades || {};
  const ctl = report.controls.filter((c) => c.state !== 'not_applicable');
  const blockers = ctl.filter((c) => (c.findings || []).some((f) => f.blocking));
  const b = (x) => `<strong>${h(x)}</strong>`;
  const out = [];
  out.push(`Foram avaliados ${b(`${num(s.applicableControls)} controles`)} em ${b(`${num(list.length)} escopo(s)`)}, com nota geral de ${b(`${gradeText(s.grade)} de 10`)} (${h(s.gradeBand || '-')}).`);
  out.push(`${b(pctText(s.provenPct))} do peso tem prova: ${h(pctText(s.machinePct))} pela máquina a cada execução e ${h(pctText(s.attestedPct))} por atestação com prazo${s.partialPct ? `; outros ${h(pctText(s.partialPct))} têm prova parcial da máquina e contam metade` : ''}.`);
  const ctx = report.context || {};
  if (Number.isFinite(ctx.targetGrade)) {
    out.push(ctx.meetsTarget
      ? `A meta para o risco desta aplicação (${h(gradeText(ctx.targetGrade))}) foi atingida.`
      : `A meta para o risco desta aplicação é ${b(gradeText(ctx.targetGrade))}: faltam ${h(gradeText(Math.round((ctx.targetGrade - s.grade) * 10) / 10))} ponto(s).`);
  }
  out.push(blockers.length
    ? `${b(`${blockers.length} controle(s)`)} bloqueiam o portão de CI${g.capReason ? ` e deixam a nota ${h(g.capReason)}` : ''}.`
    : 'Nada bloqueia o portão de CI.');
  const weak = priorityControls(report).filter((c) => c.state === 'failed').slice(0, 3);
  if (weak.length) out.push(`Os pontos mais frágeis no momento são ${weak.map((c) => b(`${c.id} ${c.title}`)).join(', ')}: prioridades para o próximo ciclo.`);
  const graded = list.filter((x) => Number.isFinite(x.grade));
  if (graded.length > 1) {
    const sorted = [...graded].sort((x, y) => y.grade - x.grade);
    const best = sorted[0];
    const worst = sorted[sorted.length - 1];
    if (best.grade !== worst.grade) out.push(`Por escopo, o destaque positivo é ${b(`${shortTitle(best.title)} (${gradeText(best.grade)})`)} e o maior ponto de atenção é ${b(`${shortTitle(worst.title)} (${gradeText(worst.grade)})`)}.`);
  }
  return `<p class="lead">${out.join(' ')}</p>`; // lastro-ignore xss-sinks: frases montadas acima com h()
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const blockingOf = (c) => (c.findings || []).some((f) => f.blocking);
/** Ordem de prioridade: bloqueante, falhando, alto ou crítico sem prova; dentro de cada grupo, pela gravidade. */
function priorityControls(report) {
  const ctl = report.controls.filter((c) => c.state !== 'not_applicable');
  const group = (c) => (blockingOf(c) ? 0 : c.state === 'failed' ? 1 : 2);
  return ctl
    .filter((c) => c.state === 'failed' || (c.state === 'unverified' && (c.severity === 'critical' || c.severity === 'high') && !c.controlRiskAccepted))
    .sort((a, b) => group(a) - group(b) || SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.id.localeCompare(b.id));
}

const STATE_BADGE = (c) => (blockingOf(c) ? ['bad', 'bloqueia o portão'] : c.state === 'failed' ? ['bad', 'falhando'] : ['warn', 'sem prova']);
const badge = ([cls, text]) => `<span class="badge ${cls}">${h(text)}</span>`; // lastro-ignore xss-sinks: cls vem de STATE_BADGE (lista fixa)
// A tabela de ação mostra só a primeira frase do "como corrigir"; o texto inteiro fica no cartão e no escopo.
const firstSentence = (s) => { const m = /^[\s\S]*?[.!?](?=\s+[A-ZÁÉÍÓÚÂÊÔÃÕÇ]|$)/.exec(String(s)); return m ? m[0] : String(s); };
const clip = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));

/** Cartões "por que importam": risco, o que o kit viu, pilares afetados e como corrigir, para os prioritários. */
function whyCards(report, catalog, now) {
  const disc = (report.threatModel && report.threatModel.discovery) || null;
  const list = priorityControls(report).slice(0, 6);
  if (!list.length) return '<p class="empty">Nenhum controle falhando nem controle alto ou crítico sem prova.</p>';
  const cards = list.map((c) => {
    const def = catalog.byId.get(c.id) || {};
    const pillars = String((catalog.riskMap[c.id] || {}).pillars || '').split('').filter((p) => R.PILLARS[p]).map((p) => R.PILLARS[p]);
    const finding = (c.findings || []).find((f) => f.blocking) || (c.findings || [])[0];
    const seen = finding ? clip(finding.message, 320) : ST.proofOf({ ...c, findings: c.findings || [], notes: c.notes || [] }, now, disc);
    return [
      `<article class="why-card ${c.state === 'failed' ? 'w-bad' : 'w-warn'}">`,
      `<h3>${h(c.id)} · ${h(c.title)}</h3>`,
      `<p>${sevBadge(c.severity)} · ${badge(STATE_BADGE(c))}</p>`,
      def.rationale ? `<span class="label">Risco para o negócio</span><p>${h(def.rationale)}</p>` : '',
      `<span class="label">${finding ? 'O que o kit encontrou' : 'Situação da prova'}</span><p>${h(seen)}</p>`,
      pillars.length ? `<span class="label">Impacto potencial</span><ul class="tags">${pillars.map((p) => `<li>${h(p)}</li>`).join('')}</ul>` : '',
      `<span class="label">Como corrigir</span><p>${h(c.state === 'failed' ? (c.remediation || def.remediation || '-') : ST.nextOf({ ...c, findings: [], notes: c.notes || [] }, disc))}</p>`,
      '</article>',
    ].join('');
  });
  return `<div class="why-grid">${cards.join('')}</div>`; // lastro-ignore xss-sinks: cartões montados acima com h()
}

function indexPage({ report, history, current, tickets, now, theme, catalog }) {
  const s = report.score;
  const prev = history.length ? history[history.length - 1] : null;
  // Comparar uma execução estática com uma que rodou as sondas HTTP mistura medidas diferentes: uma nota avisa.
  const lostProbes = prev && prev.generatedAt !== current.generatedAt ? ST.probesLost(prev, current) : [];
  const delta = (a, b) => (b === null || b === undefined ? '' : ` (${a - b >= 0 ? '+' : ''}${String(Math.round((a - b) * 10) / 10).replace('.', ',')} ponto(s) desde o último registro)`);
  const story = ST.buildStory(report, { history, current, now });
  const list = ST.scopes(report, { now });
  const disc = (report.threatModel && report.threatModel.discovery) || null;
  const sections = [];

  // 1. Indicadores: a nota, o portão, a prova e o maior gap.
  sections.push('<section id="indicadores" aria-labelledby="t-ind"><h2 id="t-ind">Indicadores</h2><div class="cards">');
  const prevGrade = prev && Number.isFinite(prev.grade) && prev.generatedAt !== current.generatedAt ? prev.grade : null;
  const gd = prevGrade === null ? '' : ` (${s.grade - prevGrade >= 0 ? '+' : ''}${gradeText(Math.round((s.grade - prevGrade) * 10) / 10)} desde o último registro)`;
  const target = report.context && Number.isFinite(report.context.targetGrade) ? `; meta ${gradeText(report.context.targetGrade)}` : '';
  sections.push(kpi('Nota geral', `${h(gradeText(s.grade))}<small> /10</small>`, `${s.gradeBand || '-'}${target}${s.grades ? `; postura ${gradeText(s.grades.posture)}, cobertura ${gradeText(s.grades.coverage)}` : ''}${gd}`, toneOf(s.grade)));
  sections.push(kpi('Portão de CI', h(VERDICT_PT[report.verdict]), `${num(report.summary.blocking)} achado(s) bloqueante(s)`, report.verdict === 'pass' ? 'ok' : report.verdict === 'fail' ? 'bad' : 'warn'));
  sections.push(kpi('Peso provado', h(pctText(s.provenPct)), `máquina ${pctText(s.machinePct)}, atestado ${pctText(s.attestedPct)}${s.partialPct ? `; mais ${pctText(s.partialPct)} com prova parcial (${num(s.partialControls)} controle(s))` : ''}${prev ? delta(s.provenPct, prev.provenPct) : ''}`, 'info'));
  const worst = [...list].filter((x) => Number.isFinite(x.grade)).sort((a, b) => a.grade - b.grade)[0];
  sections.push(worst
    ? kpi('Maior gap', h(gradeText(worst.grade)), `escopo ${shortTitle(worst.title)}: ${worst.failing.length} falhando, ${worst.missing.length} sem prova`, toneOf(worst.grade))
    : kpi('Maior gap', '-', 'nenhum escopo com nota', 'info'));
  sections.push('</div>');
  if (lostProbes.length) sections.push(`<p class="note">A execução anterior rodou ${h(lostProbes.join(' e '))} e esta não: a variação desde o último registro mistura medidas diferentes. Compare execuções do mesmo tipo.</p>`);
  sections.push('<p class="empty">Como ler: a nota mede quanto já foi <strong>provado</strong>, não quão segura a aplicação é. Controle sem prova conta zero.</p></section>');

  // 2. Sumário executivo, com o porquê da nota.
  sections.push('<section id="sumario" aria-labelledby="t-sum"><h2 id="t-sum">Sumário executivo</h2><div class="panel">');
  sections.push(executiveSummary(report, list));
  if (story.why.length) sections.push('<h3>Por que a nota está assim</h3>', `<ul>${story.why.map((x) => `<li>${h(x)}</li>`).join('')}</ul>`);
  sections.push('</div></section>');

  // 3. Nota por escopo e maturidade por fase do ciclo, lado a lado.
  const ranked = [...list].sort((a, b) => num(b.grade) - num(a.grade) || a.pack.localeCompare(b.pack));
  sections.push('<div class="cols" id="ranking">');
  sections.push('<section aria-labelledby="t-rank"><h2 id="t-rank">Nota por escopo</h2><div class="panel">', rankList(ranked.map((x) => ({
    name: shortTitle(x.title), nameHtml: `<a href="escopos.html">${h(shortTitle(x.title))}</a>`, value: x.grade, text: gradeText(x.grade),
    sub: `${x.done.length + x.failing.length + x.missing.length} controle(s) · provado ${pctText(x.provenPct)}`,
  })), 'Nota de cada escopo, de 0 a 10'), '</div></section>');
  const phases = [...(s.byPhase || [])].sort((a, b) => num(a.grade) - num(b.grade));
  sections.push('<section aria-labelledby="t-fase"><h2 id="t-fase">Maturidade por fase do ciclo</h2><div class="panel">', phases.length ? rankList(phases.map((p) => ({
    name: p.name, nameHtml: h(p.name), value: p.grade, text: gradeText(p.grade), sub: `${num(p.controls)} controle(s) · falhando ${pctText(p.failedPct)}`,
  })), 'Nota de cada fase do ciclo de desenvolvimento, de 0 a 10') : '<p class="empty">Sem dados por fase.</p>', '</div></section>');
  sections.push('</div>');

  // 4. Evolução.
  const points = [...history];
  if (!prev || prev.generatedAt !== current.generatedAt) points.push(current);
  sections.push('<section id="evolucao" aria-labelledby="t-evo"><h2 id="t-evo">Evolução</h2><div class="panel">', evolutionSvg(points), '</div></section>');

  // 5. Controles que exigem ação: a lista curta, em ordem de prioridade.
  const prio = priorityControls(report);
  sections.push('<section id="acao" aria-labelledby="t-acao"><h2 id="t-acao">Controles que exigem ação</h2>');
  sections.push(prio.length
    ? table(`Em ordem de prioridade${prio.length > 12 ? ` (12 de ${prio.length}; a lista completa está em Implementado por escopo)` : ''}`, ['Controle', 'Escopo', 'Gravidade', 'Situação', 'Próximo passo'],
      prio.slice(0, 12).map((c) => [`<strong>${h(c.id)}</strong> ${h(c.title)}`, h(c.pack), sevBadge(c.severity), badge(STATE_BADGE(c)), h(firstSentence(ST.nextOf({ ...c, findings: c.findings || [], notes: c.notes || [] }, disc)))]))
    : '<p class="empty">Nenhum controle falhando nem controle alto ou crítico sem prova.</p>');
  sections.push('</section>');

  // 6. Por que importam: risco para o negócio e impacto dos prioritários.
  sections.push('<section id="por-que-importam" aria-labelledby="t-pqi"><h2 id="t-pqi">Controles prioritários: por que importam</h2>', whyCards(report, catalog, now), '</section>');

  // 7. Em resumo: feito, atenção, fazer e decidir (sem repetir a manchete nem o porquê, que já estão acima).
  sections.push(...ui.storySectionHtml({ ...story, headline: null, why: [] }));

  // 8. Quem faz o quê: dev e time de segurança, lado a lado.
  const blockers = report.controls.filter((c) => (c.findings || []).some((f) => f.blocking));
  const al = attestationAlerts(report, now);
  const open = tickets.filter((t) => t.status === 'open' || t.status === 'in_progress');
  const byPri = ['P0', 'P1', 'P2', 'P3'].map((p) => `${p}: ${open.filter((t) => t.priority === p).length}`).join(', ');
  sections.push('<div class="cols" id="papeis">');
  sections.push('<section class="panel" id="dev" aria-labelledby="t-dev"><h2 id="t-dev">Para quem desenvolve: o que fazer agora</h2>');
  sections.push(blockers.length
    ? table('Bloqueiam o portão', ['Controle', 'Achados', 'Como corrigir'], blockers.map((c) => [`<strong>${h(c.id)}</strong> ${h(c.title)}`, String(c.findings.filter((f) => f.blocking).length), h(c.remediation || '-')]))
    : '<p>Nenhum achado novo bloqueia o portão.</p>');
  sections.push(`<p>Próximo passo para a maturidade: ${h(s.nextStep)}</p>`);
  sections.push('<p>Correções previsíveis: <code>lastro fix</code>. Requisitos de uma funcionalidade nova: <code>lastro scope &lt;assunto&gt;</code> ou a skill <code>lastro-requisitos</code> no Kiro. Caminho de prova de cada controle: <code>lastro gaps</code>.</p></section>');
  sections.push('<section class="panel" id="appsec" aria-labelledby="t-appsec"><h2 id="t-appsec">Para o time de segurança: decisões e prazos</h2>');
  sections.push(table('Pendências de governança e risco', ['Item', 'Situação'], [
    ['Atestações que vencem em até 30 dias', al.soon.length ? h(al.soon.map((a) => `${a.id} (${a.left < 0 ? 'vencida' : `${a.left} dia(s)`}, ${a.by})`).join('; ')) : 'nenhuma'],
    ['Atestações vencidas', al.expired.length ? h(al.expired.map((a) => a.id).join(', ')) : 'nenhuma'],
    ['Riscos aceitos em vigor', String(num(report.summary.accepted))],
    ['Dívida registrada no baseline', `${num(report.summary.debt)} achado(s)`],
    ['Risco confirmado', h(riskCell(report.risk.summary.confirmed))],
    ['Risco potencial (sem prova)', h(riskCell(report.risk.summary.potential))],
    ['Modelo de ameaças', h(`${num(current.threats.total)} ameaça(s): ${num(current.threats.exposed)} exposta(s), ${num(current.threats.mitigated)} mitigada(s), ${num(current.threats.pending)} sem decisão`)],
    ['Verificações automáticas', h(`${num(s.automated.verified)} passaram, ${num(s.automated.failed)} falharam, ${num(s.automated.notRun)} não rodaram`)],
    ['Tickets abertos (.lastro/backlog)', open.length ? h(`${open.length} (${byPri})`) : 'nenhum'],
  ]));
  sections.push('</section></div>');

  return htmlShell({
    title: report.profile.name, eyebrow: 'Portal LASTRO · Relatório de maturidade em segurança',
    meta: [`${history.length} registro(s) no histórico | ${num(s.applicableControls)} controle(s) aplicável(is)`],
    filters: filtersOf(report),
    nav: [['indicadores', 'Indicadores'], ['sumario', 'Sumário executivo'], ['ranking', 'Escopos e fases'], ['evolucao', 'Evolução'], ['acao', 'Exigem ação'], ['por-que-importam', 'Por que importam'], ['em-resumo', 'Em resumo'], ['papeis', 'Dev e segurança']],
    sections, theme, siteNav: siteNav('index.html'),
  });
}

function historyPage({ report, history, current, theme }) {
  const all = [...history];
  if (!all.length || all[all.length - 1].generatedAt !== current.generatedAt) all.push({ ...current, _current: true });
  const sections = ['<section id="registros" aria-labelledby="t-reg"><h2 id="t-reg">Registros</h2>'];
  if (!history.length) sections.push('<p>Ainda não há histórico gravado. Rode <code>lastro history --write</code> a cada versão (ou no CI) para acompanhar a evolução.</p>');
  sections.push(table('Execuções, da mais recente à mais antiga', ['Data', 'Portão', 'Nota', 'Provado', 'Falhando', 'Bloqueantes', 'Risco confirmado', 'Ameaças expostas'],
    [...all].reverse().map((s) => [h(`${s.generatedAt.slice(0, 16).replace('T', ' ')}${s._current ? ' (agora, não gravado)' : ''}`), h(VERDICT_PT[s.verdict]), h(gradeText(s.grade)), h(pctText(s.provenPct)), h(pctText(s.failedPct)), String(num(s.summary.blocking)), h(riskCell(s.risk.confirmed)), String(num(s.threats.exposed))])));
  sections.push('</section>');
  const prev = all.length > 1 ? all[all.length - 2] : null;
  const d = diff(prev, all[all.length - 1]);
  sections.push('<section id="mudancas" aria-labelledby="t-mud"><h2 id="t-mud">O que mudou desde o registro anterior</h2>');
  if (!prev) sections.push('<p>É preciso ao menos um registro anterior para comparar.</p>');
  else {
    const row = (x) => [h(x.id), h(x.from ? STATE_PT[x.from] : '-'), h(x.to ? STATE_PT[x.to] : '-')];
    const rows = [...d.worsened.map((x) => ['piorou', ...row(x)]), ...d.improved.map((x) => ['melhorou', ...row(x)]), ...d.added.map((x) => ['entrou', ...row(x)]), ...d.removed.map((x) => ['saiu', ...row(x)])];
    sections.push(rows.length ? table('Controles com estado diferente', ['Mudança', 'Controle', 'Antes', 'Agora'], rows.map((r) => [h(r[0]), r[1], r[2], r[3]])) : '<p>Nenhum controle mudou de estado.</p>');
    if (prev.catalog !== all[all.length - 1].catalog) sections.push('<p>Atenção: a versão do catálogo mudou entre os dois registros. Controles novos podem mudar os números sem que nada mude na aplicação.</p>');
  }
  sections.push('</section>');
  return htmlShell({
    title: `Histórico: ${report.profile.name}`, eyebrow: 'Portal LASTRO',
    meta: [`${history.length} registro(s) gravado(s) em .lastro/history`],
    nav: [['registros', 'Registros'], ['mudancas', 'Mudanças']], sections, theme, siteNav: siteNav('historico.html'), filters: filtersOf(report),
  });
}

/** Monta as páginas. Devolve { 'index.html': ..., ... }. */
function buildSite({ report, history, current, playbook, tickets = [], coverage = null, now = new Date(), theme = null, catalog = null }) {
  return {
    'index.html': indexPage({ report, history, current, tickets, now, theme, catalog: catalogOf(catalog) }),
    'escopos.html': scopesPage({ report, now, theme }),
    'decisoes.html': decisionsPage({ report, now, theme }),
    'relatorio.html': withNav(formatHtml(report, { coverage, theme }), 'relatorio.html'),
    'playbook.html': withNav(formatPlaybookHtml(playbook, { theme }), 'playbook.html'),
    'historico.html': historyPage({ report, history, current, theme }),
  };
}

/**
 * Grava o portal numa pasta. Só escreve numa pasta vazia, nova, ou que já seja um portal do LASTRO (tem o marcador):
 * assim o comando nunca apaga nem sobrescreve arquivos de outra coisa.
 */
function writeSite(dir, pages) {
  const target = path.resolve(dir);
  if (fs.existsSync(target)) {
    if (!fs.statSync(target).isDirectory()) throw new Error(`${target} existe e não é uma pasta.`);
    const entries = fs.readdirSync(target);
    if (entries.length && !entries.includes(MARKER)) throw new Error(`${target} não está vazia e não é um portal do LASTRO: escolha uma pasta nova.`);
    const foreign = entries.filter((e) => e !== MARKER && !PAGE_NAMES.has(e));
    if (foreign.length) throw new Error(`${target} tem arquivos que não são do portal (${foreign.slice(0, 3).join(', ')}): escolha uma pasta nova.`);
  }
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, MARKER), 'Pasta gerada por "lastro site". Pode ser apagada e gerada de novo.\n');
  for (const [name, html] of Object.entries(pages)) {
    if (!PAGE_NAMES.has(name)) throw new Error(`página desconhecida: ${name}`);
    fs.writeFileSync(path.join(target, name), html);
  }
  return target;
}

module.exports = { buildSite, writeSite, evolutionSvg, attestationAlerts, PAGES, PAGE_NAMES, MARKER };
