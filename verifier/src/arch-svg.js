'use strict';

// Desenho da arquitetura em SVG estático (sem script, sem recurso externo). Cada componente mostra o que o código
// revela (módulos de rotas, defesas, tabelas, jobs do CI, hosts externos); cada fluxo é uma linha com um número,
// e o detalhe do fluxo fica na tabela abaixo do desenho. Assim nenhum texto fica cortado ou escondido atrás de caixa.
// Todo texto passa pelo escape do chamador (esc). A cor nunca é o único sinal: o número e a tabela dizem o mesmo.

const TOP_ZONES = [['internet', 10, 270], ['app', 320, 520], ['dados', 880, 280]];
const WIDTH = 1170;
const PAD = 14;
const LINE = 15;
const TITLE_LINE = 17;
const NODE_GAP = 16;
const ENT_W = 250;
const ENT_GAP = 28;
const BADGE_R = 12;
const MAX_DETAIL_LINES = 22;

const ZONE_TITLE = {
  internet: 'Internet e terceiros (não confiável)',
  app: 'Zona da aplicação',
  dados: 'Zona de dados',
  entrega: 'Cadeia de entrega',
};
const NODE_ZONE = { U: 'internet', X: 'internet', A: 'app', D: 'dados', Dev: 'entrega', P: 'entrega', G: 'entrega' };
const CAT_PT = { credencial: 'credenciais', contato: 'contato', identificacao: 'identificação', financeiro: 'financeiro', nascimento: 'nascimento', sensivel: 'sensível' };

const zoneOf = (n) => n.zone || NODE_ZONE[n.id] || 'app';
const charsFor = (w, size = 11) => Math.max(10, Math.floor((w - 2 * PAD) / (size * 0.56)));

/** Quebra o texto em linhas de até n caracteres, sem cortar palavras quando possível. */
function wrap(text, n) {
  const out = [];
  let cur = '';
  for (const word of String(text).split(/\s+/).filter(Boolean)) {
    const w = word.length > n ? `${word.slice(0, n - 1)}…` : word;
    if (!cur) cur = w;
    else if (cur.length + 1 + w.length <= n) cur += ` ${w}`;
    else { out.push(cur); cur = w; }
  }
  if (cur) out.push(cur);
  return out.length ? out : [''];
}

/** Linhas de texto de um componente: título, nota e o que o código revela. */
function nodeLines(n, w) {
  const c = charsFor(w);
  const lines = wrap(n.label, charsFor(w, 13)).map((t) => ({ t, cls: 'arch-notexto' }));
  const add = (text, cls = 'arch-det') => { for (const t of wrap(text, c)) lines.push({ t, cls }); };
  const head = (text) => lines.push({ t: text, cls: 'arch-det-tit' });
  if (n.note) add(n.note, 'arch-det arch-sub');
  if (n.modules && n.modules.length) {
    head('Módulos de rotas');
    for (const m of n.modules) {
      const prot = m.notSeen ? `${m.protected + m.public}/${m.routes} com proteção ou públicas; ${m.notSeen} sem proteção vista` : `${m.routes} rota(s), todas com proteção vista ou públicas`;
      add(`${m.prefix}: ${m.notSeen ? `${m.routes} rota(s); ` : ''}${prot}`, m.notSeen ? 'arch-det arch-det-warn' : 'arch-det');
    }
  }
  if ((n.realtime && n.realtime.length) || (n.uploads && n.uploads.length)) add([...(n.realtime || []).map((x) => `tempo real: ${x}`), ...(n.uploads || []).map((x) => `upload: ${x}`)].join('; '));
  if (n.defenses && n.defenses.length) { head('Defesas vistas no código'); add(n.defenses.map((d) => d.label).join(' · ')); }
  if (n.tables && n.tables.length) {
    head(`Tabelas (${n.tables.length})`);
    add(n.tables.map((t) => (t.categories.length ? `${t.name} [${t.categories.map((x) => CAT_PT[x] || x).join(', ')}]` : t.name)).join(', '));
  }
  if (n.jobs && n.jobs.length) { head(`CI: ${n.workflows || 0} workflow(s)`); add(n.jobs.map((j) => j.job).join(', ')); }
  if (n.hosts && n.hosts.length) { head('Hosts chamados'); add(n.hosts.join(', ')); }
  if (lines.length > MAX_DETAIL_LINES) {
    const extra = lines.length - MAX_DETAIL_LINES + 1;
    lines.splice(MAX_DETAIL_LINES - 1, lines.length, { t: `... e mais ${extra} linha(s) na tabela de componentes`, cls: 'arch-det arch-sub' });
  }
  return lines;
}

const heightOf = (lines) => PAD + lines.reduce((s, l) => s + (l.cls === 'arch-notexto' ? TITLE_LINE : LINE), 0) + PAD - 4;

/** Altura mínima de cada caixa para os fluxos paralelos (mesmo par de componentes) não se sobreporem. */
function minHeights(arch) {
  const pairs = new Map();
  for (const f of arch.flows || []) { const key = [f.from, f.to].sort().join('|'); pairs.set(key, (pairs.get(key) || 0) + 1); }
  const need = new Map();
  for (const [key, n] of pairs) for (const id of key.split('|')) need.set(id, Math.max(need.get(id) || 0, n));
  return (id) => (need.get(id) > 1 ? 2 * 16 + need.get(id) * 30 : 0);
}

function layout(arch) {
  const pos = new Map();
  const boxes = [];
  const minH = minHeights(arch);
  let topH = 0;
  for (const [zone, x, w] of TOP_ZONES) {
    const list = arch.nodes.filter((n) => zoneOf(n) === zone);
    if (!list.length) continue;
    let y = 14 + 34;
    for (const n of list) {
      const nw = w - 2 * 16;
      const lines = nodeLines(n, nw);
      const h = Math.max(heightOf(lines), minH(n.id));
      pos.set(n.id, { x: x + 16, y, w: nw, h, lines });
      y += h + NODE_GAP;
    }
    boxes.push({ zone, x, w, y: 14 });
    topH = Math.max(topH, y - 14);
  }
  for (const b of boxes) b.h = topH;
  let height = 14 + topH + 14;
  const ent = arch.nodes.filter((n) => zoneOf(n) === 'entrega');
  if (ent.length) {
    const perRow = 4;
    const y0 = 14 + topH + 44;
    let rowY = y0 + 34;
    let rowH = 0;
    ent.forEach((n, i) => {
      if (i && i % perRow === 0) { rowY += rowH + NODE_GAP; rowH = 0; }
      const lines = nodeLines(n, ENT_W);
      const h = Math.max(heightOf(lines), minH(n.id));
      pos.set(n.id, { x: 30 + (i % perRow) * (ENT_W + ENT_GAP + 20), y: rowY, w: ENT_W, h, lines });
      rowH = Math.max(rowH, h);
    });
    const entH = rowY + rowH + 16 - y0;
    boxes.push({ zone: 'entrega', x: 10, w: WIDTH - 20, y: y0, h: entH });
    height = y0 + entH + 14;
  }
  // As caixas da mesma linha de entrega ficam com a mesma altura, para as setas saírem alinhadas.
  return { pos, boxes, width: WIDTH, height };
}

/** Pontos de saída e chegada de um fluxo, conforme a posição relativa das caixas, com deslocamento para paralelos. */
function anchor(a, b, k, n) {
  const off = (k - (n - 1) / 2) * 30;
  const horizontal = a.x + a.w <= b.x || b.x + b.w <= a.x;
  const vertical = a.y + a.h <= b.y || b.y + b.h <= a.y;
  if (horizontal && !(vertical && Math.abs((a.y + a.h / 2) - (b.y + b.h / 2)) > Math.abs((a.x + a.w / 2) - (b.x + b.w / 2)))) {
    const top = Math.max(a.y, b.y);
    const bottom = Math.min(a.y + a.h, b.y + b.h);
    const base = top < bottom ? (top + bottom) / 2 : (a.y + a.h / 2 + b.y + b.h / 2) / 2;
    const y = Math.max(Math.max(a.y, b.y) + 14, Math.min(Math.min(a.y + a.h, b.y + b.h) - 14, base + off));
    const leftToRight = a.x < b.x;
    return { x1: leftToRight ? a.x + a.w : a.x, y1: top < bottom ? y : a.y + a.h / 2 + off, x2: leftToRight ? b.x : b.x + b.w, y2: top < bottom ? y : b.y + b.h / 2 + off };
  }
  const left = Math.max(a.x, b.x);
  const right = Math.min(a.x + a.w, b.x + b.w);
  const baseX = left < right ? (left + right) / 2 : (a.x + a.w / 2 + b.x + b.w / 2) / 2;
  const x = baseX + off;
  const down = a.y < b.y;
  return { x1: left < right ? x : a.x + a.w / 2 + off, y1: down ? a.y + a.h : a.y, x2: left < right ? x : b.x + b.w / 2 + off, y2: down ? b.y : b.y + b.h };
}

function toSvg(arch, esc) {
  const { pos, boxes, width, height } = layout(arch);
  const r = (v) => Math.round(Number(v) || 0);
  const summary = arch.flows.map((f) => `${f.id} ${f.label}: ${f.threats} ameaça(s), ${f.exposed} exposta(s)`).join('; ');
  const out = [`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${r(width)} ${r(height)}" role="img" aria-label="Arquitetura: componentes, fronteiras de confiança e fluxos de dados" class="arch">`];
  out.push(`<title>${esc(`Arquitetura. ${summary}`)}</title>`);
  out.push('<defs><marker id="seta" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="arch-seta"/></marker></defs>');
  for (const b of boxes) {
    out.push(`<rect x="${r(b.x)}" y="${r(b.y)}" width="${r(b.w)}" height="${r(b.h)}" rx="10" class="arch-zona"/>`);
    out.push(`<text x="${r(b.x + 12)}" y="${r(b.y + 22)}" class="arch-titulo">${esc(ZONE_TITLE[b.zone])}</text>`);
  }
  // Caixas primeiro, linhas e números depois: assim nada que importa fica escondido atrás de uma caixa.
  for (const n of arch.nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    out.push(`<rect x="${r(p.x)}" y="${r(p.y)}" width="${r(p.w)}" height="${r(p.h)}" rx="8" class="arch-no${n.source === 'descoberto' || n.source === 'inferido' ? ' arch-desc' : ''}"/>`);
    let y = p.y + PAD + 4;
    for (const l of p.lines) {
      const title = l.cls === 'arch-notexto';
      out.push(`<text x="${r(p.x + PAD)}" y="${r(y + (title ? 4 : 0))}" class="${esc(l.cls)}">${esc(l.t)}</text>`);
      y += title ? TITLE_LINE : LINE;
    }
  }
  const pairs = new Map();
  for (const f of arch.flows) { const key = [f.from, f.to].sort().join('|'); pairs.set(key, (pairs.get(key) || 0) + 1); }
  const seen = new Map();
  for (const f of arch.flows) {
    const a = pos.get(f.from);
    const b = pos.get(f.to);
    if (!a || !b) continue;
    const key = [f.from, f.to].sort().join('|');
    const k = seen.get(key) || 0;
    seen.set(key, k + 1);
    const { x1, y1, x2, y2 } = anchor(a, b, k, pairs.get(key));
    const exposed = f.exposed > 0;
    out.push(`<line x1="${r(x1)}" y1="${r(y1)}" x2="${r(x2)}" y2="${r(y2)}" class="arch-fluxo${exposed ? ' arch-exposto' : ''}${f.source === 'declarado' || f.source === 'descoberto' ? '' : ' arch-inferido'}" marker-end="url(#seta)"><title>${esc(`${f.id} ${f.label}: ${f.threats} ameaça(s), ${f.exposed} exposta(s)`)}</title></line>`);
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    out.push(`<circle cx="${r(mx)}" cy="${r(my)}" r="${BADGE_R}" class="arch-badge${exposed ? ' arch-badge-bad' : ''}"/>`);
    out.push(`<text x="${r(mx)}" y="${r(my + 4)}" text-anchor="middle" class="arch-badge-txt">${esc(f.id)}</text>`);
  }
  out.push('</svg>');
  return out.join('');
}

module.exports = { toSvg, nodeLines, wrap, layout };
