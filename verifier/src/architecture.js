'use strict';

// Arquitetura segura desenhada a partir do modelo de ameaças: fluxo de dados com fronteiras de confiança, e, em
// cada fluxo, as ameaças e os controles que ele exige (com o estado de cada um).
//
// O kit NÃO inventa a arquitetura: ele desenha o que descobriu (rotas, armazenamento, chamadas externas, tempo
// real, uploads, CI, agente) e o que o perfil declara, e mostra onde cada controle precisa estar. Decisões de
// desenho (onde colocar um proxy, como segmentar a rede) continuam sendo de uma pessoa. A saída é texto:
// Mermaid (para colar em documentação) e SVG estático sem script (para o relatório em HTML).

const NODE_LABEL = {
  U: 'Usuário / navegador',
  A: 'Aplicação (web e API)',
  D: 'Armazenamento de dados',
  X: 'Serviços externos',
  Dev: 'Desenvolvedor',
  P: 'Repositório e CI',
  G: 'Agente de IA',
};

const clean = (s) => String(s).replace(/["<>\[\]{}|`\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80);

/** Resumo de uma lista de ameaças: quantas, quantas expostas, controles exigidos e o estado deles. */
function summarize(threats, controlStates) {
  const ids = [...new Set(threats.flatMap((t) => t.controls))].sort();
  const count = { verified: 0, failed: 0, unverified: 0 };
  for (const id of ids) count[controlStates.get(id) || 'unverified'] += 1;
  return {
    threats: threats.length,
    exposed: threats.filter((t) => t.state === 'exposed').length,
    pending: threats.filter((t) => t.pending).length,
    controls: ids.length,
    verified: count.verified,
    failed: count.failed,
    unverified: count.unverified,
    failing: ids.filter((id) => controlStates.get(id) === 'failed').slice(0, 8),
  };
}

function buildArchitecture({ model, profile, controls }) {
  const flags = profile.flags || {};
  const d = model.discovery;
  const states = new Map(controls.map((c) => [c.id, c.state]));
  const bySurface = (...names) => model.threats.filter((t) => names.includes(t.surface));
  const nodes = new Set();
  const flows = [];
  const add = (id, from, to, label, boundary, surfaces, note) => {
    const threats = bySurface(...surfaces);
    if (!threats.length) return;
    nodes.add(from);
    nodes.add(to);
    flows.push({ id, from, to, label, boundary, surfaces, note: note || '', ...summarize(threats, states) });
  };

  if (flags.webApp || d.routes.total > 0) {
    add('F1', 'U', 'A', 'Requisições web e autenticação', 'Internet para aplicação', ['web', 'auth'],
      d.routes.total ? `${d.routes.total} rota(s); ${d.routes.byAuth['nao-vista']} sem autenticação vista` : '');
  }
  if (flags.uploads || d.uploads.length) add('F2', 'U', 'A', 'Arquivos enviados', 'Internet para aplicação', ['uploads'], d.uploads.join(', '));
  if (flags.realtime || d.realtime.length) add('F3', 'U', 'A', 'Conexão de tempo real', 'Internet para aplicação', ['realtime'], d.realtime.join(', '));
  if (d.stores.length || flags.personalData) add('F4', 'A', 'D', 'Leitura e escrita de dados', 'Aplicação para dados', ['data'], d.stores.join(', '));
  if (d.externalHosts.length) {
    const t = bySurface('data');
    if (t.length) {
      nodes.add('A'); nodes.add('X');
      flows.push({ id: 'F5', from: 'A', to: 'X', label: 'Chamadas a serviços externos', boundary: 'Aplicação para terceiros', surfaces: ['data'], note: d.externalHosts.slice(0, 4).join(', '), ...summarize(t, states) });
    }
  }
  add('F6', 'Dev', 'P', 'Código, revisão e CI', 'Entrega do software', ['pipeline'], `${d.workflows} workflow(s)`);
  if (nodes.has('P')) { nodes.add('A'); flows.push({ id: 'F7', from: 'P', to: 'A', label: 'Entrega (deploy)', boundary: 'Entrega do software', surfaces: ['pipeline'], note: '', ...summarize(bySurface('pipeline'), states) }); }
  if (flags.aiCodingAgents) add('F8', 'G', 'P', 'Agente de IA escreve código', 'Entrega do software', ['agent'], '');

  const nodeLabels = { ...NODE_LABEL };
  if (d.stores.length) nodeLabels.D = `Armazenamento (${clean(d.stores.join(', '))})`.slice(0, 30);
  return { nodes: [...nodes].map((id) => ({ id, label: nodeLabels[id] })), flows };
}

const flowText = (f) => `${f.id}: ${f.threats} ameaça(s), ${f.exposed} exposta(s)`;

function toMermaid(arch) {
  const has = (id) => arch.nodes.some((n) => n.id === id);
  const label = (id) => clean(arch.nodes.find((n) => n.id === id).label);
  const out = ['flowchart LR'];
  if (has('U') || has('X')) {
    out.push('  subgraph internet["Internet - não confiável"]');
    if (has('U')) out.push(`    U["${label('U')}"]`);
    if (has('X')) out.push(`    X["${label('X')}"]`);
    out.push('  end');
  }
  if (has('A')) out.push('  subgraph app["Zona da aplicação"]', `    A["${label('A')}"]`, '  end');
  if (has('D')) out.push('  subgraph dados["Zona de dados"]', `    D["${label('D')}"]`, '  end');
  if (has('Dev') || has('P') || has('G')) {
    out.push('  subgraph entrega["Cadeia de entrega"]');
    for (const id of ['Dev', 'P', 'G']) if (has(id)) out.push(`    ${id}["${label(id)}"]`);
    out.push('  end');
  }
  for (const f of arch.flows) out.push(`  ${f.from} -->|"${clean(`${f.label} (${flowText(f)})`)}"| ${f.to}`);
  const bad = arch.flows.filter((f) => f.exposed > 0).map((f) => f.id);
  return { code: out.join('\n'), exposedFlows: bad };
}

// Layout fixo e simples: três colunas (internet, aplicação, dados) e uma faixa de entrega embaixo.
const POS = { U: [40, 60], X: [40, 150], A: [330, 105], D: [640, 105], Dev: [40, 300], P: [330, 300], G: [640, 300] };
const BOXES = [
  { key: 'internet', title: 'Internet (não confiável)', x: 10, y: 14, w: 250, h: 190, nodes: ['U', 'X'] },
  { key: 'app', title: 'Zona da aplicação', x: 300, y: 14, w: 250, h: 190, nodes: ['A'] },
  { key: 'dados', title: 'Zona de dados', x: 590, y: 14, w: 250, h: 190, nodes: ['D'] },
  { key: 'entrega', title: 'Cadeia de entrega', x: 10, y: 244, w: 830, h: 130, nodes: ['Dev', 'P', 'G'] },
];

/** SVG estático, sem script, com texto escapado pelo chamador (esc). Cor nunca é o único sinal: o texto traz o número. */
function toSvg(arch, esc) {
  const has = (id) => arch.nodes.some((n) => n.id === id);
  const W = 850;
  const H = 390;
  const out = [`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Fluxo de dados e fronteiras de confiança" class="arch">`];
  out.push('<defs><marker id="seta" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="arch-seta"/></marker></defs>');
  for (const b of BOXES) {
    if (!b.nodes.some(has)) continue;
    out.push(`<rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="10" class="arch-zona"/>`);
    out.push(`<text x="${b.x + 12}" y="${b.y + 20}" class="arch-titulo">${esc(b.title)}</text>`);
  }
  const center = (id) => [POS[id][0] + 90, POS[id][1] + 25];
  const slot = new Map();
  for (const f of arch.flows) {
    const key = `${f.from}-${f.to}`;
    const n = slot.get(key) || 0;
    slot.set(key, n + 1);
    const [x1, y1] = center(f.from);
    const [x2, y2] = center(f.to);
    const dy = n * 26 - 6;
    const ax = x1 + (x2 > x1 ? 90 : x2 < x1 ? -90 : 0);
    const bx = x2 + (x2 > x1 ? -90 : x2 < x1 ? 90 : 0);
    const ay = y1 + (x2 === x1 ? (y2 > y1 ? 25 : -25) : dy);
    const by = y2 + (x2 === x1 ? (y2 > y1 ? -25 : 25) : dy);
    out.push(`<line x1="${ax}" y1="${ay}" x2="${bx}" y2="${by}" class="arch-fluxo ${f.exposed > 0 ? 'arch-exposto' : ''}" marker-end="url(#seta)"/>`);
    const mx = Math.round((ax + bx) / 2);
    const my = Math.round((ay + by) / 2) - 5;
    out.push(`<text x="${mx}" y="${my}" text-anchor="middle" class="arch-rotulo">${esc(`${f.id} ${f.label}`)}</text>`);
    out.push(`<text x="${mx}" y="${my + 13}" text-anchor="middle" class="arch-rotulo arch-sub">${esc(`${f.threats} ameaça(s), ${f.exposed} exposta(s)`)}</text>`);
  }
  for (const n of arch.nodes) {
    const [x, y] = POS[n.id];
    out.push(`<rect x="${x}" y="${y}" width="180" height="50" rx="8" class="arch-no"/>`);
    out.push(`<text x="${x + 90}" y="${y + 30}" text-anchor="middle" class="arch-notexto">${esc(n.label)}</text>`);
  }
  out.push('</svg>');
  return out.join('');
}

module.exports = { buildArchitecture, toMermaid, toSvg, NODE_LABEL };
