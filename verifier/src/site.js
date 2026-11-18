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

const { h, num, table, card, htmlShell, pctText } = ui;

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

function siteNav(current) {
  const links = PAGES.map(([f, t]) => (f === current ? `<strong aria-current="page">${h(t)}</strong>` : `<a href="${h(f)}">${h(t)}</a>`));
  return ['<nav class="toc" aria-label="Páginas do portal" style="padding:.6rem 1rem">', ...links, '</nav>'].join(' ');
}

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
  sections.push(table('Nota e situação de cada escopo', ['Escopo', 'Nota', 'Provado', 'Já implementado', 'Falhando', 'Falta provar'],
    list.map((s) => [`<a href="#esc-${h(s.pack)}">${h(s.title.split(':')[0])}</a>`, h(gradeText(s.grade)), h(pctText(s.provenPct)), String(num(s.done.length)), String(num(s.failing.length)), String(num(s.missing.length))]), [1, 2, 3, 4, 5]));
  sections.push('</section>');
  for (const s of list) {
    sections.push(`<section id="esc-${h(s.pack)}" aria-labelledby="t-esc-${h(s.pack)}"><h2 id="t-esc-${h(s.pack)}">${h(s.title.split(':')[0])}: nota ${h(gradeText(s.grade))} de 10</h2>`);
    sections.push(`<p>Provado ${h(pctText(s.provenPct))} do peso (máquina ${h(pctText(s.machinePct))}, atestado ${h(pctText(s.attestedPct))}); falhando ${h(pctText(s.failedPct))}.</p>`);
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
    meta: [`Gerado em ${report.generatedAt.slice(0, 10)} | ${list.length} escopo(s) aplicável(is)`],
    nav: [['resumo-escopos', 'Resumo'], ...list.map((s) => [`esc-${s.pack}`, s.title.split(':')[0]])],
    sections, theme, siteNav: siteNav('escopos.html'),
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
    nav: [['registro', 'Registro'], ['pendentes', 'Pendentes']], sections, theme, siteNav: siteNav('decisoes.html'),
  });
}

function riskCell(t) {
  return `${num(t.critical)} crítico, ${num(t.high)} alto, ${num(t.medium)} médio, ${num(t.low)} baixo`;
}

function indexPage({ report, history, current, tickets, now, theme }) {
  const s = report.score;
  const prev = history.length ? history[history.length - 1] : null;
  // Comparar uma execução estática com uma que rodou as sondas HTTP mistura medidas diferentes: o card avisa.
  const kindNote = prev && prev.http && !current.http ? '; a anterior rodou as sondas HTTP e esta não' : '';
  const delta = (a, b) => (b === null || b === undefined ? '' : ` (${a - b >= 0 ? '+' : ''}${String(Math.round((a - b) * 10) / 10).replace('.', ',')} ponto(s) desde o último registro${kindNote})`);
  const sections = [];

  const story = ST.buildStory(report, { history, current, now });
  sections.push('<section id="agora" aria-labelledby="t-agora"><h2 id="t-agora">Agora</h2>');
  if (story.headline) sections.push(`<p><strong>${h(story.headline)}</strong></p>`);
  sections.push('<div class="cards">');
  if (s.grades) {
    const prevGrade = prev && Number.isFinite(prev.grade) && prev.generatedAt !== current.generatedAt ? prev.grade : null;
    const gd = prevGrade === null ? '' : ` (${s.grade - prevGrade >= 0 ? '+' : ''}${gradeText(Math.round((s.grade - prevGrade) * 10) / 10)} desde o último registro${kindNote})`;
    sections.push(card('Nota geral', `${h(gradeText(s.grade))} de 10`, `${s.gradeBand}; postura ${gradeText(s.grades.posture)}, cobertura ${gradeText(s.grades.coverage)}${gd}`));
  }
  sections.push(card('Portão de CI', h(VERDICT_PT[report.verdict]), `${num(report.summary.blocking)} achado(s) bloqueante(s)`));
  sections.push(card('Maturidade', `nível ${num(s.level)} de 4`, s.levelName));
  sections.push(card('Peso provado', h(pctText(s.provenPct)), `máquina ${pctText(s.machinePct)}, atestado ${pctText(s.attestedPct)}${prev ? delta(s.provenPct, prev.provenPct) : ''}`));
  sections.push(card('Automáticos', s.automated.passRatePct === null ? 'n/d' : h(pctText(s.automated.passRatePct)), `${num(s.automated.verified)} passaram, ${num(s.automated.failed)} falharam, ${num(s.automated.notRun)} não rodaram`));
  sections.push('</div>');
  sections.push(table('Risco e ameaças', ['Item', 'Hoje'], [
    ['Risco confirmado', h(riskCell(report.risk.summary.confirmed))],
    ['Risco potencial (sem prova)', h(riskCell(report.risk.summary.potential))],
    ['Modelo de ameaças', h(`${num(current.threats.total)} ameaça(s): ${num(current.threats.exposed)} exposta(s), ${num(current.threats.mitigated)} mitigada(s), ${num(current.threats.pending)} sem decisão`)],
  ]));
  sections.push('</section>');
  // A história, sem repetir a manchete (já está no topo): a mesma função do relatório, com a comparação do histórico.
  sections.push(...ui.storySectionHtml({ ...story, headline: null }));

  // Visão do dev: o que fazer agora.
  const blockers = report.controls.filter((c) => c.findings.some((f) => f.blocking));
  sections.push('<section id="dev" aria-labelledby="t-dev"><h2 id="t-dev">Para quem desenvolve: o que fazer agora</h2>');
  if (blockers.length) {
    sections.push(table('Bloqueiam o portão', ['Controle', 'Achados', 'Como corrigir'], blockers.map((c) => [`<strong>${h(c.id)}</strong> ${h(c.title)}`, String(c.findings.filter((f) => f.blocking).length), h(c.remediation || '-')])));
  } else sections.push('<p>Nenhum achado novo bloqueia o portão.</p>');
  sections.push(`<p>Próximo passo para a maturidade: ${h(s.nextStep)}</p>`);
  sections.push('<p>Correções previsíveis: <code>lastro fix</code>. Requisitos de uma funcionalidade nova: <code>lastro scope &lt;assunto&gt;</code> ou a skill <code>lastro-requisitos</code> no Kiro.</p></section>');

  // Visão do time de segurança: decisões, prazos, exceções.
  const al = attestationAlerts(report, now);
  const open = tickets.filter((t) => t.status === 'open' || t.status === 'in_progress');
  const byPri = ['P0', 'P1', 'P2', 'P3'].map((p) => `${p}: ${open.filter((t) => t.priority === p).length}`).join(', ');
  sections.push('<section id="appsec" aria-labelledby="t-appsec"><h2 id="t-appsec">Para o time de segurança: decisões e prazos</h2>');
  sections.push(table('Pendências de governança', ['Item', 'Situação'], [
    ['Atestações que vencem em até 30 dias', al.soon.length ? h(al.soon.map((a) => `${a.id} (${a.left < 0 ? 'vencida' : `${a.left} dia(s)`}, ${a.by})`).join('; ')) : 'nenhuma'],
    ['Atestações vencidas', al.expired.length ? h(al.expired.map((a) => a.id).join(', ')) : 'nenhuma'],
    ['Riscos aceitos em vigor', String(num(report.summary.accepted))],
    ['Dívida registrada no baseline', `${num(report.summary.debt)} achado(s)`],
    ['Ameaças sem decisão', String(num(current.threats.pending))],
    ['Tickets abertos (.lastro/backlog)', open.length ? h(`${open.length} (${byPri})`) : 'nenhum'],
  ]));
  sections.push('</section>');

  const points = [...history];
  if (!prev || prev.generatedAt !== current.generatedAt) points.push(current);
  sections.push('<section id="evolucao" aria-labelledby="t-evo"><h2 id="t-evo">Evolução</h2>', evolutionSvg(points), '</section>');

  return htmlShell({
    title: `Portal LASTRO: ${report.profile.name}`, eyebrow: 'Portal LASTRO',
    meta: [`Gerado em ${report.generatedAt.slice(0, 10)} | catálogo ${report.catalogVersion} | ${history.length} registro(s) no histórico`],
    nav: [['agora', 'Agora'], ['em-resumo', 'A história'], ['dev', 'Para quem desenvolve'], ['appsec', 'Para segurança'], ['evolucao', 'Evolução']],
    sections, theme, siteNav: siteNav('index.html'),
  });
}

function historyPage({ report, history, current, theme }) {
  const all = [...history];
  if (!all.length || all[all.length - 1].generatedAt !== current.generatedAt) all.push({ ...current, _current: true });
  const sections = ['<section id="registros" aria-labelledby="t-reg"><h2 id="t-reg">Registros</h2>'];
  if (!history.length) sections.push('<p>Ainda não há histórico gravado. Rode <code>lastro history --write</code> a cada versão (ou no CI) para acompanhar a evolução.</p>');
  sections.push(table('Execuções, da mais recente à mais antiga', ['Data', 'Portão', 'Nota', 'Nível', 'Provado', 'Falhando', 'Bloqueantes', 'Risco confirmado', 'Ameaças expostas'],
    [...all].reverse().map((s) => [h(`${s.generatedAt.slice(0, 16).replace('T', ' ')}${s._current ? ' (agora, não gravado)' : ''}`), h(VERDICT_PT[s.verdict]), h(gradeText(s.grade)), String(num(s.level)), h(pctText(s.provenPct)), h(pctText(s.failedPct)), String(num(s.summary.blocking)), h(riskCell(s.risk.confirmed)), String(num(s.threats.exposed))])));
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
    nav: [['registros', 'Registros'], ['mudancas', 'Mudanças']], sections, theme, siteNav: siteNav('historico.html'),
  });
}

/** Monta as páginas. Devolve { 'index.html': ..., ... }. */
function buildSite({ report, history, current, playbook, tickets = [], coverage = null, now = new Date(), theme = null }) {
  return {
    'index.html': indexPage({ report, history, current, tickets, now, theme }),
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
