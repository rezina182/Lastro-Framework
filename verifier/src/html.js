'use strict';

// Relatório em HTML: um arquivo único, sem scripts, sem fontes nem imagens externas.
// Tudo que vem do projeto analisado (nomes, caminhos, mensagens) é texto não confiável e passa por escape.
// A identidade visual não faz parte do kit: o tema padrão é neutro e quem quiser outra aparência passa um
// arquivo de tema (--theme), que só pode redefinir variáveis e estilos, sem recursos externos.

const { groupCauses } = require('./causes');
const { FLAG_LABELS } = require('./context');
const { gradeText } = require('./score');
const STORY = require('./story');

// "Em resumo": a história desta execução (story.buildStory) em quatro listas. Os textos passam por h().
const STORY_PARTS = [['done', 'Já foi feito', 'ok'], ['attention', 'Precisa de atenção', 'warn'], ['todo', 'O que fazer agora', 'bad'], ['decide', 'O que alguém precisa decidir', 'info']];
function storySectionHtml(st) {
  const out = ['<section id="em-resumo" aria-labelledby="t-em-resumo"><h2 id="t-em-resumo">Em resumo</h2>'];
  if (st.headline) out.push(`<p><strong>${h(st.headline)}</strong></p>`);
  if (st.why && st.why.length) out.push('<h3>Por que a nota está assim</h3>', `<ul>${st.why.map((x) => `<li>${h(x)}</li>`).join('')}</ul>`, '<p class="empty">Detalhe de cada controle e o trecho pronto para registrar "não se aplica": <code>lastro gaps</code>.</p>'); // lastro-ignore xss-sinks: itens escapados com h()
  out.push('<div class="cards">');
  for (const [key, title, cls] of STORY_PARTS) {
    const items = st[key];
    out.push(`<div class="card"><p class="card-label ${cls}"><strong>${h(title)}</strong></p>${items.length ? `<ul>${items.map((x) => `<li>${h(x)}</li>`).join('')}</ul>` : '<p class="empty">Nada por aqui.</p>'}</div>`); // lastro-ignore xss-sinks: itens escapados com h()
  }
  out.push('</div></section>');
  return out;
}

const VERDICT = { pass: ['APROVADO', 'ok'], fail: ['FALHA', 'bad'], incomplete: ['INCOMPLETO', 'warn'] };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_PT = { critical: 'crítica', high: 'alta', medium: 'média', low: 'baixa' };
const SEV_TITLE = { critical: 'Crítica', high: 'Alta', medium: 'Média', low: 'Baixa' };
const MAX_FINDINGS_PER_CONTROL = 150;
const MAX_THEME_BYTES = 60000;

const h = (s) => String(s)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');
const num = (n) => (Number.isFinite(Number(n)) ? Number(n) : 0);
const clamp = (n) => Math.min(100, Math.max(0, num(n)));
const pctText = (n) => `${String(num(n)).replace('.', ',')}%`;

// Visual de relatório informativo: faixa da marca no topo, barra de filtros, cartões de indicador, títulos de seção
// com sublinhado de destaque, barras de ranking e tabelas zebradas. As cores de texto passam no contraste AA; as de
// preenchimento (barras) ficam em variáveis separadas. As cores padrão são neutras: a identidade de uma empresa
// (--brand, --highlight, --accent e as demais) entra por um arquivo de tema (--theme), fora do kit.
const BASE_CSS = `
:root{--bg:#f5f6fa;--surface:#ffffff;--surface-2:#fafbfd;--surface-3:#eef1f7;--text:#1f2430;--muted:#5a6275;--border:#e2e5ed;--border-2:#d3d8e2;
--brand:#1d4ed8;--brand-ink:#ffffff;--highlight:#f59e0b;--accent:#1d4ed8;
--ok:#0a7a3a;--warn:#9a5600;--bad:#c62828;--info:#1d5fd1;
--ok-fill:#16a34a;--warn-fill:#f59e0b;--bad-fill:#ef4444;--info-fill:#3b82f6;--none-fill:#b5b8c0;
--radius:12px;--shadow:0 1px 2px rgba(31,36,48,.06),0 4px 14px rgba(31,36,48,.06);
--font:"Inter","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#0e1118;--surface:#161a23;--surface-2:#1a1f2a;--surface-3:#232a38;--text:#e7eaf0;--muted:#a4adbd;
--border:#2b3242;--border-2:#363e50;--brand:#1e3a8a;--accent:#93b4ff;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--info:#7fb0ff;--shadow:none}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 var(--font)}
.skip{position:absolute;left:-999px;top:0;background:var(--surface);color:var(--text);padding:8px 12px}
.skip:focus{left:8px;top:8px;z-index:9}
.wrap{max-width:1120px;margin:0 auto}
.topbar{background:var(--brand);color:var(--brand-ink);padding:10px 24px}
.topbar .wrap{display:flex;flex-wrap:wrap;align-items:center;gap:6px 18px}
.brand{font-weight:800;letter-spacing:.12em;margin-right:8px}
.topbar nav{display:flex;flex-wrap:wrap;gap:4px}
.topbar a,.topbar strong{color:var(--brand-ink);text-decoration:none;padding:4px 10px;border-radius:999px;font-size:.88rem}
.topbar a:hover,.topbar a:focus{background:rgba(255,255,255,.14)}
.topbar strong{background:rgba(255,255,255,.2)}
.hero{padding:28px 24px 0;background:var(--surface);border-bottom:1px solid var(--border-2)}
.eyebrow{margin:0 0 4px;color:var(--accent);font-size:.8rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase}
h1{margin:0 0 6px;font-size:1.85rem;line-height:1.2;overflow-wrap:anywhere}
.meta{margin:0;color:var(--muted);font-size:.92rem}
.filters{display:flex;flex-wrap:wrap;gap:6px 28px;margin:16px 0 0;padding:10px 16px;background:var(--bg);border:1px solid var(--border);border-radius:10px}
.filters div{font-size:.88rem}
.filters dt{display:inline;color:var(--muted);margin-right:6px}
.filters dd{display:inline;margin:0;font-weight:600}
nav.toc{display:flex;flex-wrap:wrap;gap:8px;padding:12px 0 14px}
nav.toc a{color:var(--accent);text-decoration:none;border:1px solid var(--border);border-radius:999px;padding:3px 12px;font-size:.85rem;background:var(--surface)}
nav.toc a:hover,nav.toc a:focus{background:var(--surface-3)}
main{padding:8px 24px 48px}
section{margin-top:36px}
h2{margin:0 0 14px;padding-bottom:8px;font-size:1.2rem;border-bottom:2px solid var(--highlight)}
h3{margin:20px 0 8px;font-size:1.02rem}
h4{margin:16px 0 6px;font-size:.95rem}
p{margin:0 0 10px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin:12px 0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;box-shadow:var(--shadow)}
.card-label{margin:0;color:var(--muted);font-size:.8rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.card-value{margin:6px 0 0;font-size:1.9rem;font-weight:800;line-height:1.15;color:var(--brand)}
.card-note{margin:6px 0 0;color:var(--muted);font-size:.84rem}
@media (prefers-color-scheme:dark){.card-value{color:var(--accent)}}
.kpi{border-top:4px solid var(--brand)}
.kpi.k-ok{border-top-color:var(--ok-fill)}.kpi.k-warn{border-top-color:var(--warn-fill)}.kpi.k-bad{border-top-color:var(--bad-fill)}.kpi.k-info{border-top-color:var(--info-fill)}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;box-shadow:var(--shadow)}
.lead{font-size:1.02rem;line-height:1.7}
.lead strong{color:var(--brand)}
@media (prefers-color-scheme:dark){.lead strong{color:var(--accent)}}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px;margin-top:36px}
.card-value small{font-size:.95rem;font-weight:600;color:var(--muted)}
.cols>section{margin-top:0}
.rank{list-style:none;margin:0;padding:0}
.rank li{display:grid;grid-template-columns:minmax(120px,1.3fr) 2fr 3.2rem;align-items:center;gap:12px;padding:9px 0;border-top:1px solid var(--border)}
.rank li:first-child{border-top:0}
.rank-name{font-weight:600;overflow-wrap:anywhere}
.rank-name small{display:block;color:var(--muted);font-weight:400;font-size:.8rem}
.rank-track{height:10px;border-radius:999px;background:var(--surface-3);overflow:hidden}
.rank-track span{display:block;height:100%;border-radius:999px}
.rank-val{text-align:right;font-weight:700;white-space:nowrap}
.f-ok{background:var(--ok-fill)}.f-warn{background:var(--warn-fill)}.f-bad{background:var(--bad-fill)}.f-info{background:var(--info-fill)}
.why-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
.why-card{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--brand);border-radius:var(--radius);padding:16px 18px;box-shadow:var(--shadow)}
.why-card.w-bad{border-left-color:var(--bad-fill)}.why-card.w-warn{border-left-color:var(--warn-fill)}
.why-card h3{margin:0 0 8px;font-size:1rem}
.why-card .label{display:block;margin:12px 0 2px;color:var(--brand);font-size:.74rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
@media (prefers-color-scheme:dark){.why-card .label{color:var(--accent)}}
.why-card p{margin:0}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 0;padding:0;list-style:none}
.tags li{margin:0;background:var(--surface-3);color:var(--text);border-radius:999px;padding:1px 10px;font-size:.78rem;font-weight:600}
.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:1px 10px;font-size:.8rem;font-weight:600;white-space:nowrap}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.info{color:var(--info)}
.sev-critical,.sev-high{color:var(--bad)}.sev-medium{color:var(--warn)}.sev-low{color:var(--muted)}
.bar{display:flex;height:12px;border-radius:999px;overflow:hidden;background:var(--surface-2);border:1px solid var(--border)}
.bar span{display:block;height:100%}
.seg-ok{background:var(--ok-fill)}.seg-info{background:var(--info-fill)}.seg-bad{background:var(--bad-fill)}.seg-none{background:var(--none-fill)}.seg-warn{background:var(--warn-fill)}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin:8px 0 0;padding:0;list-style:none;color:var(--muted);font-size:.86rem}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:baseline}
.note{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:var(--radius);padding:12px 16px;margin:12px 0}
.table-wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
table{width:100%;border-collapse:collapse;font-size:.92rem}
caption{text-align:left;color:var(--muted);padding:10px 12px;font-size:.86rem}
th,td{padding:8px 12px;text-align:left;vertical-align:top;border-top:1px solid var(--border)}
thead th{border-top:0;background:var(--surface-3);color:var(--muted);font-size:.78rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}
tbody tr:nth-child(even){background:var(--surface-2)}
td.num,th.num{text-align:right;white-space:nowrap}
td .bar{min-width:140px}
code{font:.86em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--surface-2);padding:1px 6px;border-radius:6px;overflow-wrap:anywhere}
pre{background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;overflow-x:auto}
pre code{background:none;padding:0}
ol li,ul li{margin:4px 0}
details{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin:8px 0;padding:0 14px}
summary{cursor:pointer;padding:10px 0;font-weight:600}
summary:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
summary .count{color:var(--muted);font-weight:400;margin-left:8px}
details ul{margin:0 0 12px;padding-left:18px}
details li{margin:6px 0;overflow-wrap:anywhere}
.empty{color:var(--muted)}
.heat td{text-align:center;font-weight:600;white-space:nowrap}
.heat th{white-space:nowrap}
.heat-low{background:var(--surface-2)}
.heat-medium{background:var(--surface-2);box-shadow:inset 0 -3px 0 var(--warn)}
.heat-high{background:var(--surface-2);box-shadow:inset 0 -3px 0 var(--bad)}
.heat-critical{background:var(--surface-2);box-shadow:inset 0 0 0 2px var(--bad)}
@supports (background:color-mix(in srgb,red 10%,white)){
.heat-medium{background:color-mix(in srgb,var(--warn) 18%,var(--surface))}
.heat-high{background:color-mix(in srgb,var(--bad) 20%,var(--surface))}
.heat-critical{background:color-mix(in srgb,var(--bad) 38%,var(--surface))}}
.kinds{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:12px 0}
.arch-wrap{padding:8px}
.arch{width:100%;height:auto;max-width:1170px;min-width:900px;display:block;margin:0 auto}
.arch-zona{fill:none;stroke:var(--border);stroke-width:1.5;stroke-dasharray:6 4}
.arch-titulo{fill:var(--muted);font-size:12px}
.arch-no{fill:var(--surface);stroke:var(--accent);stroke-width:1.5}
.arch-desc{stroke-dasharray:5 3;stroke:var(--warn)}
.arch-inferido{stroke-dasharray:3 3}
.arch-rotulo{paint-order:stroke;stroke:var(--surface);stroke-width:3px;stroke-linejoin:round}
.arch-notexto{fill:var(--text);font-size:12px}
.arch-fluxo{stroke:var(--muted);stroke-width:1.5;fill:none}
.arch-exposto{stroke:var(--bad);stroke-width:2.5}
.arch-seta{fill:var(--muted)}
.arch-rotulo{fill:var(--text);font-size:11px}
.arch-sub{fill:var(--muted)}
.arch-det{fill:var(--text);font-size:11px}
.arch-det-tit{fill:var(--accent);font-size:10.5px;font-weight:600;letter-spacing:.02em}
.arch-det-warn{fill:var(--warn)}
.arch-notexto{font-weight:600;font-size:13px}
.arch-badge{fill:var(--surface);stroke:var(--muted);stroke-width:1.5}
.arch-badge-bad{stroke:var(--bad);stroke-width:2.5}
.arch-badge-txt{fill:var(--text);font-size:10px;font-weight:700}
.why{color:var(--muted);font-size:.84rem;margin:4px 0 0}
a{color:var(--accent)}
footer{padding:24px;color:var(--muted);font-size:.85rem;text-align:center}
footer .wrap{border-top:1px solid var(--border-2);padding-top:16px}
footer strong{color:var(--text)}
@media print{body{background:#fff;color:#000}.skip,nav.toc,.topbar nav{display:none}.card,.panel,.why-card,.table-wrap{box-shadow:none}details{border-color:#999}section{break-inside:avoid-page}}
`;

/** Valida o arquivo de tema: só CSS inofensivo, sem recursos externos nem nada que quebre o documento. */
function validateTheme(css) {
  const errs = [];
  if (typeof css !== 'string' || css.trim() === '') return ['o tema está vazio'];
  if (Buffer.byteLength(css, 'utf8') > MAX_THEME_BYTES) errs.push(`o tema passa de ${MAX_THEME_BYTES} bytes`);
  if (css.includes('<')) errs.push('o tema não pode conter "<"');
  if (css.includes('\\')) errs.push('o tema não pode conter barra invertida (escapes de CSS)');
  if (/@import/i.test(css)) errs.push('o tema não pode usar @import');
  if (/expression\s*\(|javascript:|behavior\s*:|-moz-binding/i.test(css)) errs.push('o tema contém construção não permitida');
  for (const m of css.matchAll(/url\s*\(\s*(['"]?)([^'")]*)\1\s*\)/gi)) {
    if (!/^data:/i.test(m[2].trim())) errs.push(`o tema referencia recurso externo em url(): ${m[2].trim().slice(0, 40)}`);
  }
  return errs;
}

const bar = (parts) => {
  const label = parts.map((p) => `${p.label} ${pctText(p.value)}`).join(', ');
  return `<div class="bar" role="img" aria-label="${h(label)}">${parts.map((p) => `<span class="${p.cls}" style="width:${clamp(p.value)}%"></span>`).join('')}</div>`; // lastro-ignore xss-sinks: p.cls vem de constantes do próprio gerador (seg-ok, seg-bad...)
};

const sevBadge = (sev) => `<span class="sev-${h(sev)}"><strong>${h(SEV_PT[sev] || sev)}</strong></span>`;
const card = (label, value, note = '') => `<div class="card"><p class="card-label">${h(label)}</p>${value ? `<p class="card-value">${value}</p>` : ''}${note ? `<p class="card-note">${h(note)}</p>` : ''}</div>`; // lastro-ignore xss-sinks: value é HTML montado pelo gerador com h() nos dados do projeto

// As células (c) chegam prontas: cada chamador escapa o dado do projeto com h() antes de montar a linha.
function table(caption, head, rows, numericCols = []) {
  const th = head.map((t, i) => `<th scope="col"${numericCols.includes(i) ? ' class="num"' : ''}>${h(t)}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.map((c, i) => `<td${numericCols.includes(i) ? ' class="num"' : ''}>${c}</td>`).join('')}</tr>`).join(''); // lastro-ignore xss-sinks: células já escapadas pelo chamador
  return `<div class="table-wrap"><table><caption>${h(caption)}</caption><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table></div>`; // lastro-ignore xss-sinks: th e body montados acima com h()
}

const R = require('./risk');

const CLASS_CSS = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info' };
const classBadge = (cls) => `<span class="badge ${CLASS_CSS[cls] || 'info'}">${h(R.CLASS_PT[cls] || cls)}</span>`; // lastro-ignore xss-sinks: a classe CSS vem da tabela fixa CLASS_CSS
// O arquivo continua autocontido (sem script, fonte ou imagem externa). Os únicos links são para fontes oficiais,
// montados a partir de identificadores validados (links.js): CWE (MITRE), CVE (NVD), GHSA (GitHub) e a LGPD (Planalto).
const L = require('./links');
const ext = (url, text) => (url ? `<a href="${h(url)}" rel="noopener noreferrer">${h(text)}</a>` : h(text));
const cweLinks = (list) => (list.length ? list.filter((n) => Number.isInteger(n) && n > 0).map((n) => ext(L.cweUrl(n), `CWE-${n}`)).join(', ') : '-');
const ghsaLink = (id, fallback = 'aviso') => (id ? ext(L.ghsaUrl(id), id) : h(fallback));
const cveLinks = (list) => (list && list.length ? list.map((c) => ext(L.cveUrl(c), c)).join(', ') : 'ver o aviso');
const pillarsText = (codes) => codes.map((c) => R.PILLARS[c] || c).join(', ');
const stateText = (i) => (i.state === 'failed' ? (i.type === 'vuln' ? 'vulnerável' : 'confirmado') : 'sem prova');

function riskRows(list, limit) {
  return list.slice(0, limit).map((i) => {
    let where;
    if (i.type === 'vuln') {
      where = i.advisories.map((a) => ghsaLink(a.id, a.title || 'aviso')).join(', ');
      where += ` (${i.direct ? 'dependência direta' : 'indireta'}; correção: ${h(i.fix)})`;
    } else where = i.locations.length ? i.locations.map((l) => `<code>${h(l)}</code>`).join(', ') : '';
    const why = `Probabilidade ${i.likelihood} (${R.LIKELIHOOD_PT[i.likelihood]}): ${i.reasons.likelihood.join('; ')}. Impacto ${i.impact} (${R.IMPACT_PT[i.impact]}): ${i.reasons.impact.join('; ')}.${i.reasons.reach ? ` Alcance: ${i.reasons.reach}.` : ''}`;
    return [
      `${classBadge(i.class)}${i.accepted ? ' <span class="empty">(aceito)</span>' : ''}`,
      `${i.likelihood} x ${i.impact} = ${i.score}`,
      `<strong>${h(i.id)}</strong> ${h(i.title)}${where ? `<br>${where}` : ''}<p class="why">${h(why)}</p>`,
      h(stateText(i)),
      h(pillarsText(i.pillars)),
      cweLinks(i.cwe),
      h(i.asvs.slice(0, 3).join(', ') || '-'),
    ];
  });
}

function riskHtml(r) {
  const k = r.risk;
  const out = ['<section id="risco" aria-labelledby="t-risco"><h2 id="t-risco">Análise de risco</h2>'];
  out.push('<p>Três coisas diferentes aparecem em um relatório de segurança, e misturá-las faz tudo parecer igualmente urgente. A estimativa de risco (probabilidade x impacto, de 1 a 4 cada) vale só para riscos de segurança.</p>');
  out.push('<div class="kinds">');
  for (const key of ['security', 'practice', 'quality']) out.push(card(R.KINDS[key].label, '', R.KINDS[key].help));
  out.push('</div>');

  const c = k.summary.confirmed;
  const p = k.summary.potential;
  out.push('<h3>Riscos de segurança por criticidade</h3>', '<div class="cards">');
  for (const cls of R.CLASSES) out.push(card(`${R.CLASS_PT[cls]}`, `<span class="${CLASS_CSS[cls]}">${num(c[cls])}</span>`, `confirmados; ${num(p[cls])} potencial(is) sem prova`));
  out.push('</div>');
  out.push(`<div class="note"><p><strong>Confirmado</strong> é o que a verificação encontrou. <strong>Potencial</strong> é o que ninguém provou ainda: a probabilidade é uma suposição média, ajustada pela exposição, e não quer dizer que a falha exista. ${num(k.summary.securityVerified)} controle(s) de segurança estão verificados e não entram na conta.</p></div>`);

  out.push('<h3>Matriz de risco</h3>', '<p>Só os riscos confirmados entram na matriz. Os potenciais (sem prova) ficam limitados a "Alto": crítico exige evidência.</p>');
  const head = '<thead><tr><th scope="col">Impacto \\ Probabilidade</th>' + [1, 2, 3, 4].map((l) => `<th scope="col">${num(l)} ${h(R.LIKELIHOOD_PT[l])}</th>`).join('') + '</tr></thead>';
  const body = [4, 3, 2, 1].map((imp) => {
    const cells = k.matrix.filter((m) => m.impact === imp).sort((a, b) => a.likelihood - b.likelihood);
    return `<tr><th scope="row">${num(imp)} ${h(R.IMPACT_PT[imp])}</th>${cells.map((m) => `<td class="heat-${h(m.class)}">${m.count ? `${num(m.count)}<br><span class="empty">${h(R.CLASS_PT[m.class])}</span>` : '·'}</td>`).join('')}</tr>`;
  }).join('');
  out.push(`<div class="table-wrap"><table class="heat"><caption>Quantidade de riscos de segurança confirmados por probabilidade e impacto</caption>${head}<tbody>${body}</tbody></table></div>`);

  const conf = k.security.filter((i) => i.state === 'failed');
  const pot = k.security.filter((i) => i.state === 'unverified');
  const cols = ['Classe', 'P x I', 'Controle e motivo', 'Estado', 'Pilares', 'CWE', 'ASVS'];
  out.push('<h3>Riscos de segurança confirmados</h3>');
  if (!conf.length) out.push('<p class="empty">Nenhum.</p>');
  else for (const cls of R.CLASSES) {
    const list = conf.filter((i) => i.class === cls);
    if (!list.length) continue;
    out.push(`<details${cls === 'critical' || cls === 'high' ? ' open' : ''}><summary>${h(R.CLASS_PT[cls])} <span class="count">${list.length} risco(s)</span></summary>`);
    out.push(table(`Riscos confirmados de classe ${R.CLASS_PT[cls].toLowerCase()}, do maior para o menor`, cols, riskRows(list, 60)));
    if (list.length > 60) out.push(`<p class="empty">... e mais ${list.length - 60}.</p>`);
    out.push('</details>');
  }
  out.push('<h3>Riscos potenciais (sem prova): onde olhar primeiro</h3>');
  out.push('<p>Controles que ninguém provou. A ordem mostra o que mais pesa se a falha existir, dado o contexto declarado. Provar o controle (ou corrigi-lo) tira o item daqui.</p>');
  if (!pot.length) out.push('<p class="empty">Nenhum.</p>');
  else for (const cls of R.CLASSES) {
    const list = pot.filter((i) => i.class === cls);
    if (!list.length) continue;
    out.push(`<details${cls === 'critical' ? ' open' : ''}><summary>${h(R.CLASS_PT[cls])} <span class="count">${list.length} controle(s)</span></summary>`);
    out.push(table(`Riscos potenciais de classe ${R.CLASS_PT[cls].toLowerCase()}`, cols, riskRows(list, 40)));
    if (list.length > 40) out.push(`<p class="empty">... e mais ${list.length - 40}.</p>`);
    out.push('</details>');
  }

  out.push('<h3>Pilares da segurança da informação</h3>');
  out.push('<p>Quais pilares os itens abertos tocam. "Pior classe" considera só riscos de segurança.</p>');
  out.push(table('Itens abertos por pilar', ['Pilar', 'Significa', 'Itens abertos', 'Confirmados', 'Potenciais', 'Pior classe'],
    k.pillars.map((pl) => [`<strong>${h(pl.name)}</strong>`, h(pl.help), String(num(pl.open)), String(num(pl.confirmed)), String(num(pl.potential)), pl.worstClass ? classBadge(pl.worstClass) : '-']), [2, 3, 4]));

  const pv = k.privacy;
  out.push('<h3>Privacidade e LGPD</h3>');
  if (!pv.applies) out.push('<p>O perfil declara que a aplicação não trata dados pessoais. Se isso mudar, declare <code>personalData</code> (e <code>minorsData</code> ou <code>context.sensitiveData</code>, se for o caso) para que o impacto dos riscos de confidencialidade suba.</p>');
  else {
    const classes = [pv.data.personal && 'dados pessoais', pv.data.minors && 'dados de crianças ou adolescentes', pv.data.sensitive && 'dados pessoais sensíveis'].filter(Boolean).join(', ');
    out.push(`<p>A aplicação trata ${h(classes)}. <strong>${num(pv.confirmed)}</strong> risco(s) confirmado(s) e <strong>${num(pv.potential)}</strong> potencial(is) tocam privacidade ou confidencialidade de dado pessoal.</p>`);
    out.push(`<div class="note"><p>${h(pv.note)}</p></div>`);
    if (pv.items.length) {
      out.push(table('Itens que tocam dado pessoal', ['Classe', 'Controle', 'Natureza', 'Estado', 'Base na LGPD'],
        pv.items.slice(0, 25).map((i) => [i.class ? classBadge(i.class) : '-', `<strong>${h(i.id)}</strong> ${h(i.title)}`, h(R.KINDS[i.kind].label), h(stateText(i)), h(i.lgpd || '-')])));
      if (pv.items.length > 25) out.push(`<p class="empty">... e mais ${pv.items.length - 25}.</p>`);
    }
  }

  if (r.dependencyVulns) {
    const v = r.dependencyVulns;
    out.push('<h3>Vulnerabilidades conhecidas em dependências</h3>');
    out.push(`<p>Fonte: ${h(v.source)}. ${num(v.total)} pacote(s) com aviso próprio (${num(v.bySeverity.critical)} crítico(s), ${num(v.bySeverity.high)} alto(s), ${num(v.bySeverity.medium)} médio(s), ${num(v.bySeverity.low)} baixo(s)), de ${num(v.packagesAffected === undefined ? v.total : v.packagesAffected)} pacote(s) afetados${v.devKnown ? `; ${num(v.devOnly)} só em desenvolvimento` : ''}. O npm audit informa o aviso do GitHub (GHSA), a CWE e o CVSS, mas não o CVE: o CVE está na página do aviso (clique no GHSA).</p>`);
    const own = v.items.filter((i) => !i.inherited);
    if (own.length) {
      out.push(table('Pacotes com aviso conhecido', ['Pacote', 'Gravidade', 'Onde entra', 'Aviso (GHSA)', 'CWE', 'CVSS', 'CVE', 'Afeta', 'Correção'],
        own.slice(0, 40).map((i) => {
          const a = i.advisories[0];
          const ghsa = a ? ghsaLink(a.id, a.title || '-') : '-';
          const where = i.devOnly === true ? 'só desenvolvimento' : i.devOnly === false ? 'produção' : '-';
          return [`<strong>${h(i.package)}</strong>${i.direct ? '' : ' (indireta)'}`, sevBadge(i.severity), h(where), ghsa, a ? cweLinks(a.cwe) : '-', a && a.cvss !== null ? h(String(a.cvss)) : '-', a ? cveLinks(a.cve) : 'ver o aviso', h((i.effects || []).slice(0, 4).join(', ') || '-'), h(i.fix)];
        })));
    }
  }

  const listKind = (title, help, list) => {
    out.push(`<h3>${h(title)}</h3>`, `<p>${h(help)}</p>`);
    if (!list.length) { out.push('<p class="empty">Nenhum item aberto.</p>'); return; }
    out.push(table(title, ['Gravidade', 'Controle', 'Estado', 'Pilares'],
      list.slice(0, 40).map((i) => [sevBadge(i.severity), `<strong>${h(i.id)}</strong> ${h(i.title)}`, h(stateText(i)), h(pillarsText(i.pillars))])));
    if (list.length > 40) out.push(`<p class="empty">... e mais ${list.length - 40}.</p>`);
  };
  listKind('Boas práticas pendentes', `${R.KINDS.practice.help}. Cobrar com prazo, mas sem tratar como brecha.`, k.practices);
  listKind('Qualidade pendente', `${R.KINDS.quality.help}.`, k.quality);

  out.push('<div class="note"><p>A probabilidade é uma estimativa a partir do estado do controle e da exposição declarada no perfil. Um modelo de ameaças (docs/THREAT-MODEL.md) a torna específica: quem ataca, por onde e o que já existe. Sem ele, use a classe para priorizar a investigação, não como medida do dano.</p></div>');
  out.push('</section>');
  return out;
}

const TMX = require('./threatmodel');
const { toSvg: archSvg } = require('./architecture');
const TM_STATE = { exposed: ['exposta', 'bad'], unproven: ['sem prova', 'warn'], mitigated: ['mitigada', 'ok'] };
const tmDecisionText = (t) => (t.pending ? (t.decision === 'accept' ? 'aceitação vencida' : 'pendente') : TMX.DECISION_PT[t.decision]);

function threatHtml(r) {
  const t = r.threatModel;
  const d = t.discovery;
  const status = t.reviewed
    ? `Modelo revisado por ${t.reviewedBy} em ${String(t.reviewedAt).slice(0, 10)}, com todas as ameaças decididas.`
    : t.persisted
      ? `Modelo gravado em .lastro/threat-model.json, ainda incompleto: ${num(t.counts.pending)} ameaça(s) sem decisão ou com aceitação vencida${t.reviewedBy ? '' : ', e sem revisão registrada'}.`
      : 'Rascunho gerado nesta execução e não gravado. Rode "lastro threat-model --write" para gravar .lastro/threat-model.json, decidir cada ameaça e registrar a revisão.';
  const out = ['<section id="ameacas" aria-labelledby="t-ameacas"><h2 id="t-ameacas">Modelo de ameaças</h2>'];
  out.push(`<p>${h(status)}</p>`);
  out.push('<div class="note"><p>O kit gera o rascunho a partir do perfil, do catálogo e da leitura do código. Rascunho não é prova: o CORE-012 só passa quando uma pessoa decide cada ameaça e registra a revisão. A descoberta é heurística de texto e nunca guarda valores, só nomes e caminhos.</p></div>');
  out.push('<div class="cards">');
  out.push(card('Ameaças', String(num(t.counts.threats)), `${num(t.counts.pending)} sem decisão`));
  out.push(card('Expostas', `<span class="bad">${num(t.counts.exposed)}</span>`, 'há controle falhando'));
  out.push(card('Sem prova', String(num(t.counts.unproven)), 'controles ainda não provados'));
  out.push(card('Mitigadas', `<span class="ok">${num(t.counts.mitigated)}</span>`, 'controles verificados'));
  out.push('</div>');

  out.push('<h3>Ativos</h3>');
  out.push(table('Ativos a proteger', ['Id', 'Ativo', 'Tipo', 'Origem'], t.assets.map((a) => [h(a.id), `${h(a.name)}${a.note ? `<p class="why">${h(a.note)}</p>` : ''}`, h(a.kind), h(a.source)])));

  out.push('<h3>O que o kit encontrou no código</h3>', '<ul>');
  out.push(`<li>Rotas HTTP: ${num(d.routes.total)}${d.routes.total ? ` (autenticação visível ${num(d.routes.byAuth.visivel)}, middleware global ${num(d.routes.byAuth.global)}, autenticação na montagem do roteador ${num(d.routes.byAuth.montagem || 0)}, públicas esperadas ${num(d.routes.byAuth['publica-esperada'])}, <strong>não vista ${num(d.routes.byAuth['nao-vista'])}</strong>)` : ''}.</li>`);
  if (d.stores.length) out.push(`<li>Armazenamento: ${h(d.stores.join(', '))}.</li>`);
  if (d.realtime.length) out.push(`<li>Tempo real: ${h(d.realtime.join(', '))}.</li>`);
  if (d.uploads.length) out.push(`<li>Upload de arquivos: ${h(d.uploads.join(', '))}.</li>`);
  if (d.externalHosts.length) out.push(`<li>Chamadas a serviços externos: ${h(d.externalHosts.slice(0, 10).join(', '))}.</li>`);
  out.push(`<li>Variáveis de ambiente lidas: ${num(d.env.total)}${d.env.credentials.length ? `, ${num(d.env.credentials.length)} com nome de segredo (só os nomes)` : ''}.</li>`);
  for (const x of d.dataHints) out.push(`<li>Indício de dado: ${h(x.name)}${x.sensitive ? ' <strong>(confirme se há dado sensível e declare <code>context.sensitiveData</code>)</strong>' : ''} em ${x.files.slice(0, 3).map((f) => `<code>${h(f)}</code>`).join(', ')}.</li>`);
  out.push('</ul>');
  if (d.routes.examples.length) {
    out.push('<details><summary>Rotas sem autenticação vista <span class="count">pistas para revisar a autorização, não um veredito</span></summary><ul>');
    if (d.routes.authMounts) out.push(`<li>Atenção: há ${num(d.routes.authMounts)} montagem(ns) de roteador com autenticação, mas o kit não ligou todas as rotas a elas (importação dinâmica ou fábrica de roteador, por exemplo). Estas rotas podem estar protegidas.</li>`);
    for (const x of d.routes.examples) out.push(`<li><code>${h(x.method)} ${h(x.path)}</code> (${h(x.location)})</li>`);
    if (d.routes.byAuth['nao-vista'] > d.routes.examples.length) out.push(`<li class="empty">... e mais ${num(d.routes.byAuth['nao-vista'] - d.routes.examples.length)}.</li>`);
    out.push('</ul><p class="why">"Não vista" não quer dizer desprotegida: o kit lê texto e não enxerga toda forma de proteger uma rota.</p></details>');
  }

  if (t.architecture && t.architecture.flows.length) {
    const a = t.architecture;
    out.push('<h3>Arquitetura: fluxo de dados e fronteiras de confiança</h3>');
    out.push(`<p>${a.mode === 'declarado'
      ? `Desenho <strong>declarado</strong> em <code>.lastro/system.json</code> (${h(a.name)}), combinado com o que o kit descobriu em ${num(a.repos.length || 1)} repositório(s). Origem do fluxo: declarado (você descreveu), descoberto (o kit viu no código e você não declarou) ou inferido (o kit deduziu pelos papéis). Borda tracejada: componente descoberto e não declarado.`
      : 'Desenho <strong>automático</strong>, só pelo que o kit descobriu em um repositório e pelo perfil. Para descrever vários repositórios ou componentes, crie <code>.lastro/system.json</code> (veja docs/THREAT-MODEL-ASSISTIDO.md).'}</p>`);
    out.push('<p>O kit desenha o que descobriu no código e o que foi declarado, e mostra, em cada fluxo, as ameaças e os controles que ele exige. Ele não inventa a arquitetura: onde colocar um proxy, como segmentar a rede e como separar ambientes são decisões de uma pessoa. Linha vermelha: o fluxo tem ameaça exposta.</p>');
    out.push(`<div class="table-wrap arch-wrap">${archSvg(a, h)}</div>`, ARCH_LEGEND);
    out.push(table('Fluxos, ameaças e controles exigidos', ['Fluxo', 'Fronteira', 'Origem', 'Ameaças', 'Controles exigidos', 'Falhando agora', 'Observação'],
      a.flows.map((f) => [`<strong>${h(f.id)}</strong> ${h(f.label)}`, h(f.boundary), h(f.source || '-'), `${num(f.threats)} (${num(f.exposed)} exposta(s), ${num(f.pending)} sem decisão)`,
        `${num(f.controls)}: ${num(f.verified)} verificado(s), ${num(f.failed)} falhando, ${num(f.unverified)} sem prova`, f.failing.length ? h(f.failing.join(', ')) : '-', h(f.note || '-')])));
    if ((a.warnings || []).length) out.push('<ul>', ...a.warnings.map((w) => `<li>Atenção: ${h(w)}</li>`), '</ul>');
    out.push(...archComponentsHtml(a));
  }
  out.push('<h3>Ameaças (STRIDE por superfície)</h3>');
  const order = { exposed: 0, unproven: 1, mitigated: 2 };
  for (const surface of Object.keys(TMX.SURFACES)) {
    const list = t.threats.filter((x) => x.surface === surface).sort((a, b) => order[a.state] - order[b.state] || a.id.localeCompare(b.id));
    if (!list.length) continue;
    const worst = list.some((x) => x.state === 'exposed');
    out.push(`<details${worst ? ' open' : ''}><summary>${h(TMX.SURFACES[surface])} <span class="count">${list.length} ameaça(s), ${list.filter((x) => x.state === 'exposed').length} exposta(s), ${list.filter((x) => x.pending).length} sem decisão</span></summary>`);
    const ev = list[0].evidence;
    if (ev.length) out.push('<ul>', ...ev.map((e) => `<li>${h(e)}</li>`), '</ul>');
    out.push(table(`Ameaças em ${TMX.SURFACES[surface].toLowerCase()}`, ['Ameaça', 'Estado', 'Controles', 'CWE', 'Decisão'],
      list.map((x) => [`<strong>${h(x.id)}</strong> ${h(x.strideName)}<p class="why">${h(x.question)}</p>`, `<span class="${TM_STATE[x.state][1]}">${h(TM_STATE[x.state][0])}</span>`, h(x.controls.join(', ')), cweLinks(x.cwe), h(tmDecisionText(x))])));
    out.push('</details>');
  }
  if (t.orphans.length) out.push(`<p class="empty">Decisões de ameaças que não existem mais (a superfície sumiu do perfil ou do código): ${h(t.orphans.join(', '))}.</p>`);
  out.push('</section>');
  return out;
}

const { staticLegend } = require('./legend');

function legendHtml(r) {
  const s = staticLegend();
  const out = ['<section id="legenda" aria-labelledby="t-legenda"><h2 id="t-legenda">Legenda</h2>', '<p>Para quem lê o relatório sem conhecer o kit.</p>'];
  out.push('<h3>Pacotes e prefixos dos controles</h3>', '<p>Todo controle tem um id com o prefixo do pacote: <code>CORE-012</code> é o controle 12 do pacote Base.</p>');
  out.push(table('Pacotes do catálogo', ['Prefixo', 'Pacote', 'O que cobre', 'Quando se aplica', 'Controles'],
    r.legend.packs.map((p) => [`<code>${h(p.prefix)}</code>`, `<strong>${h(p.name)}</strong>`, h(p.what), p.requires.length ? h(`só se o perfil declara: ${p.requires.join(', ')}`) : 'sempre', String(num(p.controls))]), [4]));
  out.push('<details><summary>Estados, natureza e classes de risco</summary>');
  out.push(table('Estados de um controle', ['Estado', 'Significa'], s.states.map(([a, b]) => [`<strong>${h(a)}</strong>`, h(b)])));
  out.push(table('Natureza do item', ['Natureza', 'Significa'], s.kinds.map(([a, b]) => [`<strong>${h(a)}</strong>`, h(b)])));
  out.push(table('Classes de risco', ['Classe', 'Regra'], [...s.classes, ...s.scales].map(([a, b]) => [`<strong>${h(a)}</strong>`, h(b)])));
  out.push('</details>');
  out.push('<details><summary>Pilares, STRIDE e superfícies</summary>');
  out.push(table('Pilares da segurança da informação', ['Pilar', 'Significa'], s.pillars.map(([a, b]) => [`<strong>${h(a)}</strong>`, h(b)])));
  out.push(table('Categorias STRIDE', ['Categoria', 'Pergunta'], s.stride.map(([a, b]) => [`<strong>${h(a)}</strong>`, h(b)])));
  out.push(`<p>Superfícies: ${h(s.surfaces.map(([, v]) => v).join('; '))}.</p>`);
  out.push('</details>');
  out.push('<details open><summary>Siglas e identificadores</summary>');
  out.push(table('Siglas', ['Sigla', 'O que é'], s.terms.map(([a, b, url]) => [`<strong>${ext(url, a)}</strong>`, h(b)])));
  out.push(table('Identificadores', ['Formato', 'O que é'], s.ids.map(([a, b]) => [`<code>${h(a)}</code>`, h(b)])));
  out.push('</details>', '</section>');
  return out;
}

function formatHtml(r, { coverage = null, theme = null } = {}) {
  const k = r.score;
  const s = r.summary;
  const [verdictText, verdictCls] = VERDICT[r.verdict] || ['?', 'warn'];
  const scope = r.target.url
    ? `Alvo HTTP: ${h(r.target.url)} (${r.target.active ? 'sondas ativas ligadas' : 'somente sondas passivas'}, ${num(r.target.requestsSent)} requisições).`
    : 'Escopo: somente verificações estáticas do repositório. Nenhuma requisição foi feita à aplicação, então cabeçalhos, cookies, CSP e HSTS ficaram sem verificação.';

  const out = [];
  out.push('<!doctype html>', '<html lang="pt-BR">', '<head>', '<meta charset="utf-8">');
  out.push('<meta name="viewport" content="width=device-width, initial-scale=1">');
  out.push(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`);
  out.push(`<title>Relatório LASTRO: ${h(r.profile.name)}</title>`);
  out.push(`<style>${BASE_CSS}${theme ? `\n/* tema */\n${theme}` : ''}</style>`, '</head>', '<body>');
  out.push('<a class="skip" href="#resumo">Ir para o resumo</a>');
  out.push('<header class="hero"><div class="wrap">');
  out.push('<p class="eyebrow">Relatório LASTRO</p>', `<h1>${h(r.profile.name)}</h1>`);
  out.push(`<p class="meta">Gerado em ${h(r.generatedAt.slice(0, 10))} | LASTRO ${h(r.tool.version)} | catálogo ${h(r.catalogVersion)}</p>`);
  out.push(`<p class="meta">${scope}</p>`);
  out.push('<nav class="toc" aria-label="Seções do relatório">');
  const links = [];
  if (k) links.push(['em-resumo', 'Em resumo']);
  if (r.risk) links.push(['risco', 'Análise de risco']);
  if (r.threatModel) links.push(['ameacas', 'Modelo de ameaças']);
  links.push(['resumo', 'Resumo']);
  if (r.context && k) links.push(['contexto', 'Contexto e meta']);
  if (k && k.byPhase && k.byPhase.length) links.push(['ssdlc', 'SSDLC por fase']);
  links.push(['pacotes', 'Por pacote'], ['bloqueantes', 'Causas dos bloqueios'], ['achados', 'Outros achados'], ['sem-prova', 'Sem prova']);
  if (coverage) links.push(['asvs', 'ASVS']);
  if (r.engineering) links.push(['engenharia', 'Engenharia']);
  links.push(['limites', 'Limites']);
  if (r.legend) links.push(['legenda', 'Legenda']);
  for (const [id, text] of links) out.push(`<a href="#${id}">${text}</a>`);
  out.push('</nav>', '</div></header>', '<main><div class="wrap">');

  if (k) out.push(...storySectionHtml(STORY.buildStory(r)));
  if (r.risk) out.push(...riskHtml(r));
  if (r.threatModel) out.push(...threatHtml(r));

  // Resumo e maturidade
  out.push('<section id="resumo" aria-labelledby="t-resumo"><h2 id="t-resumo">Resumo e maturidade</h2>');
  out.push('<div class="cards">');
  out.push(card('Portão de CI', `<span class="badge ${verdictCls}">${verdictText}</span>`, `${num(s.blocking)} achado(s) novo(s) de gravidade alta ou crítica`));
  if (k) {
    if (k.grades) {
      const g = k.grades;
      const cls = g.overall >= 8 ? 'ok' : g.overall >= 6 ? 'info' : g.overall >= 4 ? 'warn' : 'bad';
      out.push(card('Nota geral', `<span class="${cls}">${h(gradeText(g.overall))}</span> de 10`, `${g.band}${g.capReason ? `; ${g.capReason}` : ''}`));
      out.push(card('Postura', `${h(gradeText(g.posture))} de 10`, 'do que foi decidido, quanto passou'));
      out.push(card('Cobertura', `${h(gradeText(g.coverage))} de 10`, 'quanto do peso tem prova'));
    }
    out.push(card('Provado', pctText(k.provenPct), `por máquina ${pctText(k.machinePct)}, autodeclarado ${pctText(k.attestedPct)}`));
    if (k.automated && k.automated.controls) {
      const a = k.automated;
      out.push(card('Controles automáticos', a.passRatePct === null ? '-' : pctText(a.passRatePct), `${num(a.verified)} passaram, ${num(a.failed)} falharam, ${num(a.notRun)} não rodaram (fora da taxa)`));
    }
    out.push(card('Falhando', `<span class="bad">${h(pctText(k.failedPct))}</span>`));
    out.push(card('Sem prova', pctText(k.unverifiedPct), k.partialPct ? `dos quais ${pctText(k.partialPct)} com prova parcial da máquina (meio peso na nota)` : 'conta como zero'));
  }
  out.push(card('Controles aplicáveis', String(num(s.applicable)), `${num(s.verified)} verificados, ${num(s.failed)} falhando, ${num(s.unverified)} sem prova`));
  out.push('</div>');
  if (k) {
    out.push(bar([
      { cls: 'seg-ok', label: 'Provado por máquina', value: k.machinePct },
      { cls: 'seg-info', label: 'Autodeclarado', value: k.attestedPct },
      { cls: 'seg-bad', label: 'Falhando', value: k.failedPct },
      { cls: 'seg-none', label: 'Sem prova', value: k.unverifiedPct },
    ]));
    out.push('<ul class="legend"><li><i class="seg-ok"></i>Provado por máquina</li><li><i class="seg-info"></i>Autodeclarado (atestação)</li><li><i class="seg-bad"></i>Falhando</li><li><i class="seg-none"></i>Sem prova</li></ul>');
    out.push(`<div class="note"><p><strong>Próximo passo:</strong> ${h(k.nextStep)}</p></div>`);
    out.push(`<p class="empty">${h(k.disclaimer)}</p>`);
  }
  out.push('</section>');

  // Contexto e meta
  if (r.context && k) {
    const c = r.context;
    const riskCls = c.risk === 'alto' ? 'bad' : c.risk === 'moderado' ? 'warn' : 'ok';
    out.push('<section id="contexto" aria-labelledby="t-ctx"><h2 id="t-ctx">Contexto e meta</h2>', '<div class="cards">');
    out.push(card('Risco inerente', `<span class="badge ${riskCls}">${h(c.risk)}</span>`, `${num(c.points)} pontos, ${c.riskSource}`));
    out.push(card('Meta de maturidade', `nota ${h(gradeText(c.targetGrade))}`, c.targetSource));
    out.push(card('Hoje', `nota ${h(gradeText(k.grade))}`, c.meetsTarget ? 'meta atingida' : `faltam ${gradeText(c.gap)} ponto(s)`));
    out.push('</div>');
    out.push(`<p>A aplicação ${h(c.factors.length ? c.factors.join('; ') : 'não declara fatores de exposição no perfil')}.</p>`);
    if (r.scope) {
      out.push(`<p><strong>No escopo:</strong> ${h(r.scope.on.map((p) => p.title.split(':')[0]).join('; '))}.</p>`);
      if (r.scope.off.length) {
        const off = r.scope.off.map((p) => `${p.title.split(':')[0]} (${p.missing.map((f) => FLAG_LABELS[f] || f).join(', ')})`).join('; ');
        out.push(`<p><strong>Fora do escopo</strong>, porque o perfil declara que a aplicação não tem: ${h(off)}.</p>`);
      }
    }
    out.push('<div class="note"><p>Nem toda aplicação precisa do mesmo rigor. A meta acompanha o risco inerente, e o escopo depende do perfil: um perfil que subdeclara a aplicação melhora o número e piora a segurança. Revise o perfil com outra pessoa.</p></div>', '</section>');
  }

  // Aderência por fase do SSDLC
  if (k && k.byPhase && k.byPhase.length) {
    out.push('<section id="ssdlc" aria-labelledby="t-ssdlc"><h2 id="t-ssdlc">Aderência por fase do ciclo de vida (SSDLC)</h2>');
    out.push('<p>Cada controle conta em todas as fases em que atua, então as fases não somam o total. "Aderência" é a fatia do peso dos controles da fase que está provada, não uma certificação.</p>');
    out.push(table('Nota, peso provado, falhando e sem prova em cada fase', ['Fase', 'Controles', 'Nota', 'Provado', 'Falhando', 'Sem prova', 'Distribuição'],
      k.byPhase.map((p) => [
        h(p.name), String(num(p.controls)), h(gradeText(p.grade)), h(pctText(p.provenPct)), h(pctText(p.failedPct)), h(pctText(p.unverifiedPct)),
        bar([{ cls: 'seg-ok', label: 'Por máquina', value: p.machinePct }, { cls: 'seg-info', label: 'Autodeclarado', value: p.attestedPct }, { cls: 'seg-bad', label: 'Falhando', value: p.failedPct }, { cls: 'seg-none', label: 'Sem prova', value: p.unverifiedPct }]),
      ]), [1, 2, 3, 4, 5]));
    out.push('</section>');
  }

  // Por pacote
  out.push('<section id="pacotes" aria-labelledby="t-pacotes"><h2 id="t-pacotes">Por pacote</h2>');
  if (k) {
    out.push(table('Nota, peso provado, falhando e sem prova em cada pacote de controles', ['Pacote', 'Controles', 'Nota', 'Provado', 'Falhando', 'Sem prova', 'Distribuição'],
      k.byPack.map((p) => [
        h(p.title.split(':')[0]), String(num(p.controls)), h(gradeText(p.grade)), h(pctText(p.provenPct)), h(pctText(p.failedPct)), h(pctText(p.unverifiedPct)),
        bar([{ cls: 'seg-ok', label: 'Por máquina', value: p.machinePct }, { cls: 'seg-info', label: 'Autodeclarado', value: p.attestedPct }, { cls: 'seg-bad', label: 'Falhando', value: p.failedPct }, { cls: 'seg-none', label: 'Sem prova', value: p.unverifiedPct }]),
      ]), [1, 2, 3, 4, 5]));
  }
  out.push('</section>');

  // Bloqueantes
  const blocking = r.controls.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => ({ c, f })));
  out.push('<section id="bloqueantes" aria-labelledby="t-bloq"><h2 id="t-bloq">Causas dos bloqueios</h2>');
  if (!blocking.length) out.push('<p class="empty">Nenhum.</p>');
  else {
    const causes = groupCauses(r);
    out.push(`<p>${blocking.length} achado(s) novo(s), de gravidade alta ou crítica, fora do baseline e sem risco aceito vigente, em ${causes.length} causa(s). Cada causa tem uma correção só.</p>`);
    for (const cz of causes) {
      out.push(`<details open><summary>${h(cz.id)}: ${h(cz.title)} <span class="count">${cz.count} ocorrência(s), gravidade ${sevBadge(cz.severity)}</span></summary>`);
      if (cz.remediation) out.push(`<p><strong>Como corrigir:</strong> ${h(cz.remediation)}</p>`);
      if (cz.locations.length) {
        out.push('<ul>', ...cz.locations.slice(0, 30).map((l) => `<li><code>${h(l)}</code></li>`));
        if (cz.locations.length > 30) out.push(`<li class="empty">... e mais ${cz.locations.length - 30} local(is).</li>`);
        out.push('</ul>');
      }
      out.push('</details>');
    }
    if (r.baselineView) {
      const v = r.baselineView;
      const view = v.verdictIfAdopted === 'pass' ? 'aprovado' : 'incompleto (ainda há controles altos ou críticos sem prova)';
      out.push(`<div class="note"><p><strong>Com baseline:</strong> se esta dívida (${num(v.findings)} achado(s), ${num(v.causes)} causa(s)) fosse registrada com <code>lastro baseline --write</code>, o portão ficaria ${h(view)}: só achado novo passaria a bloquear. A dívida continua visível aqui e deve virar ticket ou risco aceito com dono e validade.</p></div>`);
    }
    out.push('<details><summary>Todas as ocorrências</summary>');
    out.push(table('Achados bloqueantes', ['Controle', 'Gravidade', 'Onde', 'O que'],
      blocking.sort((a, b) => SEV_ORDER[a.f.severity] - SEV_ORDER[b.f.severity] || a.c.id.localeCompare(b.c.id))
        .map(({ c, f }) => [`<strong>${h(c.id)}</strong>`, sevBadge(f.severity), f.location ? `<code>${h(f.location)}</code>` : '-', h(f.message)])));
    out.push('</details>');
  }
  out.push('</section>');

  // Outros achados
  const failing = r.controls.filter((c) => c.findings.some((f) => !f.blocking))
    .sort((a, b) => {
      const wa = Math.min(...a.findings.filter((f) => !f.blocking).map((f) => SEV_ORDER[f.severity]));
      const wb = Math.min(...b.findings.filter((f) => !f.blocking).map((f) => SEV_ORDER[f.severity]));
      return wa - wb || a.id.localeCompare(b.id);
    });
  out.push('<section id="achados" aria-labelledby="t-ach"><h2 id="t-ach">Outros achados (não bloqueiam)</h2>');
  if (!failing.length) out.push('<p class="empty">Nenhum.</p>');
  else {
    out.push('<p>Cada grupo pede uma decisão: corrigir, justificar com um comentário <code>lastro-ignore</code> ou aceitar o risco com dono e validade. Abra o grupo para ver os locais.</p>');
    for (const c of failing) {
      const fs = c.findings.filter((f) => !f.blocking).sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
      const shown = fs.slice(0, MAX_FINDINGS_PER_CONTROL);
      out.push('<details>');
      out.push(`<summary>${h(c.id)}: ${h(c.title)} <span class="count">${fs.length} achado(s), maior gravidade ${sevBadge(fs[0].severity)}</span></summary><ul>`);
      for (const f of shown) out.push(`<li>${sevBadge(f.severity)} ${f.location ? `<code>${h(f.location)}</code> ` : ''}${h(f.message)}</li>`);
      if (fs.length > shown.length) out.push(`<li class="empty">... e mais ${fs.length - shown.length} achado(s) do mesmo controle.</li>`);
      out.push('</ul></details>');
    }
  }
  out.push('</section>');

  // Sem prova
  const open = r.controls.filter((c) => c.state === 'unverified');
  out.push('<section id="sem-prova" aria-labelledby="t-prova"><h2 id="t-prova">Controles sem prova</h2>');
  out.push(`<p>${open.length} controle(s) sem prova não contam como aprovados. A maioria é manual: a prova é uma atestação com responsável e validade em <code>.lastro/status.json</code>. Os de HTTP exigem <code>--url</code>.</p>`);
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const list = open.filter((c) => c.severity === sev).sort((a, b) => a.id.localeCompare(b.id));
    if (!list.length) continue;
    out.push(`<details${sev === 'critical' || sev === 'high' ? ' open' : ''}><summary>${h(SEV_TITLE[sev])} <span class="count">${list.length} controle(s)</span></summary>`);
    out.push(table(`Controles de gravidade ${SEV_PT[sev]} sem prova`, ['Controle', 'Título', 'Por quê'],
      list.map((c) => [`<strong>${h(c.id)}</strong>`, h(c.title), h((c.notes[0] || '').slice(0, 120))])));
    out.push('</details>');
  }
  out.push('</section>');

  // ASVS
  if (coverage) {
    const t = coverage.totals;
    out.push(`<section id="asvs" aria-labelledby="t-asvs"><h2 id="t-asvs">Cobertura do ASVS ${h(coverage.version)} (até L${num(coverage.level)})</h2>`);
    out.push(`<p>${num(t.total)} requisitos: ${num(t.verified)} verificados, ${num(t.failed)} falhando, ${num(t.unverified)} sem prova, ${num(t.outOfProfile)} fora do perfil e ${num(t.none)} sem controle. Um requisito só conta como verificado quando um controle que o cobre por inteiro está verificado.</p>`);
    const chapters = Object.keys(coverage.byChapter).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
    out.push(table('Estado dos requisitos do ASVS por capítulo', ['Capítulo', 'Total', 'Verificados', 'Falhando', 'Sem prova', 'Fora do perfil', 'Distribuição'],
      chapters.map((ch) => {
        const b = coverage.byChapter[ch];
        const total = Math.max(1, num(b.total));
        const p = (n) => (num(n) / total) * 100;
        return [`${h(ch)} ${h(b.name)}`, String(num(b.total)), String(num(b.verified)), String(num(b.failed)), String(num(b.unverified)), String(num(b.outOfProfile)),
          bar([{ cls: 'seg-ok', label: 'Verificados', value: p(b.verified) }, { cls: 'seg-bad', label: 'Falhando', value: p(b.failed) }, { cls: 'seg-none', label: 'Sem prova', value: p(b.unverified) }, { cls: 'seg-warn', label: 'Fora do perfil', value: p(b.outOfProfile) }])];
      }), [1, 2, 3, 4, 5]));
    out.push('</section>');
  }

  if (r.warnings.length) out.push('<section aria-labelledby="t-avisos"><h2 id="t-avisos">Avisos</h2><ul>', ...r.warnings.map((w) => `<li>${h(w)}</li>`), '</ul></section>');

  if (r.engineering) {
    const e = r.engineering;
    const yes = (b) => (b ? 'sim' : 'não');
    out.push('<section id="engenharia" aria-labelledby="t-eng"><h2 id="t-eng">Fatos de engenharia (não entram na pontuação)</h2>');
    out.push('<p>O kit não dá nota à qualidade do código. Estes são indícios objetivos para a conversa sobre manutenção e revisão.</p>');
    out.push(table('Indícios objetivos do repositório', ['Item', 'O que foi observado'], [
      ['Código-fonte', `${num(e.sourceFiles)} arquivo(s), ${num(e.sourceLines)} linha(s)${e.largest.length ? `. Maiores: ${e.largest.map((x) => `<code>${h(x.file)}</code> (${num(x.lines)})`).join(', ')}` : ''}`],
      ['Testes', `${num(e.testFiles)} arquivo(s), ${num(e.testLines)} linha(s), ${h(pctText(e.testToSourcePct))} do código-fonte`],
      ['CI', `${num(e.ci.workflows)} workflow(s); executa testes: ${yes(e.ci.runsTests)}; executa lint: ${yes(e.ci.runsLint)}`],
      ['Ferramentas', `script de teste ${yes(e.tooling.testScript)}; lint configurado ${yes(e.tooling.lintConfig || e.tooling.lintScript)}; tipagem ${yes(e.tooling.typeConfig)}; lockfile ${yes(e.tooling.lockfile)}`],
      ['Documentação', `README ${yes(e.docs.readme)}; arquitetura ${yes(e.docs.architecture)}; registro de mudanças ${yes(e.docs.changelog)}; licença ${yes(e.docs.license)}`],
      ['Dependências', e.dependencies.prod === null ? 'sem package.json' : `${num(e.dependencies.prod)} de produção e ${num(e.dependencies.dev)} de desenvolvimento`],
    ]));
    if (e.observations.length) out.push('<h3>Observações</h3><ul>', ...e.observations.map((x) => `<li>${h(x)}</li>`), '</ul>');
    out.push('</section>');
  }

  out.push('<section id="limites" aria-labelledby="t-lim"><h2 id="t-lim">Limites</h2><ul>');
  out.push('<li>As varreduras de código são heurísticas por texto, linha a linha: erram para os dois lados e não substituem revisão.</li>');
  out.push('<li>A pontuação e a cobertura medem evidência e progresso do kit. Elas não certificam a aplicação nem provam conformidade com o ASVS.</li>');
  out.push('<li>Atestação é autodeclaração com prazo. Quem escreveu o código não deve ser o único a atestar controles de nível alto.</li>');
  out.push('</ul></section>');
  if (r.legend) out.push(...legendHtml(r));
  out.push('</div></main>', '<footer><div class="wrap"><strong>LASTRO</strong> · relatório gerado automaticamente a partir das verificações do kit e das decisões registradas em .lastro/.<br>Este arquivo é autocontido: não carrega scripts, fontes nem imagens externas. Os links levam só a fontes oficiais (CWE, CVE, GHSA, ASVS e LGPD).</div></footer>', '</body>', '</html>');
  return `${out.join('\n')}\n`;
}

/** Seção de arquitetura em HTML (relatório da aplicação com vários repositórios). */
function archSectionHtml(a) {
  const out = ['<h3>Arquitetura: fluxo de dados e fronteiras de confiança</h3>'];
  const modeText = a.mode === 'aplicação'
    ? `Desenho da aplicação <strong>${h(a.name)}</strong>, montado pelo kit a partir de ${num(a.repos.length)} repositório(s) lidos (papéis identificados pelo código). Origem: declarado (um system.json), descoberto (o kit viu no código), inferido (o kit deduziu pelos papéis e pelo que cada repositório usa). Confirme os papéis e as ligações. Borda tracejada: componente descoberto ou inferido.`
    : a.mode === 'declarado'
      ? `Desenho <strong>declarado</strong> em <code>.lastro/system.json</code> (${h(a.name)}). Borda tracejada: componente descoberto ou inferido.`
      : 'Desenho <strong>automático</strong>, só pelo que o kit descobriu em um repositório e pelo perfil.';
  out.push(`<p>${modeText}</p>`);
  out.push('<p>O kit desenha o que descobriu no código e o que foi declarado, e mostra, em cada fluxo, as ameaças e os controles que ele exige. Ele não inventa a arquitetura: onde colocar um proxy, como segmentar a rede e como separar ambientes são decisões de uma pessoa. Linha vermelha: o fluxo tem ameaça exposta.</p>');
  out.push(`<div class="table-wrap arch-wrap">${archSvg(a, h)}</div>`, ARCH_LEGEND);
  out.push(table('Fluxos, ameaças e controles exigidos', ['Fluxo', 'Fronteira', 'Origem', 'Ameaças', 'Controles exigidos', 'Falhando agora', 'Observação'],
    a.flows.map((f) => [`<strong>${h(f.id)}</strong> ${h(f.label)}`, h(f.boundary), h(f.source || '-'), `${num(f.threats)} (${num(f.exposed)} exposta(s), ${num(f.pending)} sem decisão)`,
      `${num(f.controls)}: ${num(f.verified)} verificado(s), ${num(f.failed)} falhando, ${num(f.unverified)} sem prova`, f.failing.length ? h(f.failing.join(', ')) : '-', h(f.note || '-')])));
  if ((a.warnings || []).length) out.push('<ul>', ...a.warnings.map((w) => `<li>Atenção: ${h(w)}</li>`), '</ul>');
  return out;
}

const ARCH_LEGEND = '<p class="why">Os números nas linhas (F1, F2...) são os fluxos da tabela logo abaixo. Linha e número em vermelho: o fluxo tem ameaça exposta. Borda tracejada: componente descoberto ou inferido, a confirmar.</p>';
const CAT_PT_HTML = { credencial: 'credenciais', contato: 'contato', identificacao: 'identificação', financeiro: 'financeiro', nascimento: 'nascimento', sensivel: 'possível dado sensível' };

/** O que o código revela de cada componente, em tabelas (o desenho mostra o resumo). */
function archComponentsHtml(a) {
  const out = [];
  const app = a.nodes.find((n) => n.modules && n.modules.length);
  if (app) {
    out.push(table('Módulos de rotas descobertos (prefixo de montagem + rota)', ['Módulo', 'Rotas', 'Métodos', 'Com proteção vista', 'Públicas esperadas', 'Sem proteção vista', 'Arquivos'],
      app.modules.map((m) => [`<code>${h(m.prefix)}</code>`, String(num(m.routes)), h(m.methods.join(', ') || '-'), String(num(m.protected)), String(num(m.public)), m.notSeen ? `<span class="warn">${num(m.notSeen)}</span>` : '0', h(m.files.join(', ') || '-')]), [1, 3, 4, 5]));
  }
  const def = a.nodes.find((n) => n.defenses && n.defenses.length);
  if (def) out.push(table('Defesas vistas no código (indício, não prova)', ['Defesa', 'Onde o kit viu'], def.defenses.map((d) => [h(d.label), `<code>${h(d.evidence)}</code>`])));
  const db = a.nodes.find((n) => n.tables && n.tables.length);
  if (db) out.push(table('Tabelas do banco (migrações SQL)', ['Tabela', 'Dados que as colunas sugerem', 'Arquivo'], db.tables.map((t) => [`<code>${h(t.name)}</code>`, h(t.categories.map((c) => CAT_PT_HTML[c] || c).join(', ') || '-'), h(t.file)])));
  const ci = a.nodes.find((n) => n.jobs && n.jobs.length);
  if (ci) out.push(table('Jobs do CI', ['Workflow', 'Job'], ci.jobs.map((j) => [h(j.workflow), h(j.job)])));
  if (out.length) out.unshift('<h4>Componentes descobertos no código</h4><p class="why">Lido do código, sem executar nada. Serve para conferir o desenho e para a revisão do modelo de ameaças; não verifica nenhum controle.</p>');
  return out;
}

/** Documento HTML completo com o mesmo estilo dos relatórios (sem script, CSP restritiva, tema opcional). */
// `filters`: pares [rótulo, valor] em texto puro, mostrados na barra abaixo do título (escopo, data, tipo de execução).
function htmlShell({ title, eyebrow, meta = [], nav = [], sections, theme = null, siteNav = null, filters = [] }) {
  const out = ['<!doctype html>', '<html lang="pt-BR">', '<head>', '<meta charset="utf-8">', '<meta name="viewport" content="width=device-width, initial-scale=1">'];
  out.push(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`);
  out.push(`<title>${h(title)}</title>`, `<style>${BASE_CSS}${theme ? `\n/* tema */\n${theme}` : ''}</style>`, '</head>', '<body>');
  out.push('<a class="skip" href="#principal">Ir para o conteúdo</a>');
  if (siteNav) out.push(siteNav);
  out.push('<header class="hero"><div class="wrap">');
  out.push(`<p class="eyebrow">${h(eyebrow)}</p>`, `<h1>${h(title)}</h1>`);
  for (const m of meta) out.push(`<p class="meta">${h(m)}</p>`);
  if (filters.length) out.push(`<dl class="filters">${filters.map(([k, v]) => `<div><dt>${h(k)}:</dt><dd>${h(v)}</dd></div>`).join('')}</dl>`); // lastro-ignore xss-sinks: rótulos e valores escapados com h()
  out.push('<nav class="toc" aria-label="Seções desta página">', ...nav.map(([id, text]) => `<a href="#${h(id)}">${h(text)}</a>`), '</nav>', '</div></header>');
  out.push('<main id="principal"><div class="wrap">', ...sections, '</div></main>');
  out.push('<footer><div class="wrap"><strong>LASTRO</strong> · relatório de maturidade gerado automaticamente a partir das verificações do kit e das decisões registradas em .lastro/.<br>Este arquivo é autocontido: não carrega scripts, fontes nem imagens externas. Os links levam só a fontes oficiais (CWE, CVE, GHSA, ASVS e LGPD).</div></footer>', '</body>', '</html>');
  return `${out.join('\n')}\n`;
}

const ui = { h, num, table, card, sevBadge, classBadge, cweLinks, ext, bar, pctText, archSectionHtml, legendHtml, htmlShell, storySectionHtml };

module.exports = { formatHtml, validateTheme, MAX_FINDINGS_PER_CONTROL, ui };
