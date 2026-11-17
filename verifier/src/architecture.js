'use strict';

// Arquitetura segura desenhada a partir do modelo de ameaças: fluxo de dados com fronteiras de confiança, e, em
// cada fluxo, as ameaças e os controles que ele exige (com o estado de cada um).
//
// Dois modos:
//  - automático: um repositório, desenhado só pelo que o kit descobriu lendo o código e pelo perfil;
//  - declarado: o usuário descreve os componentes, os repositórios e os fluxos em .lastro/system.json (veja system.js).
//    O declarado manda no desenho. O que o kit descobriu nos repositórios e o usuário não declarou aparece marcado
//    como "descoberto", para revisão.
//
// O kit NÃO inventa a arquitetura: ele desenha o que descobriu e o que foi declarado, e mostra onde cada controle
// precisa estar. Decisões de desenho (onde colocar um proxy, como segmentar a rede) continuam sendo de uma pessoa.
// A saída é texto: Mermaid (para colar em documentação) e SVG estático sem script (para o relatório em HTML).

const ZONES = {
  internet: 'Internet e terceiros (não confiável)',
  app: 'Zona da aplicação',
  dados: 'Zona de dados',
  entrega: 'Cadeia de entrega',
};

const NODE_LABEL = {
  U: 'Usuário / navegador',
  A: 'Aplicação (web e API)',
  D: 'Armazenamento de dados',
  X: 'Serviços externos',
  Dev: 'Desenvolvedor',
  P: 'Repositório e CI',
  G: 'Agente de IA',
};
const NODE_ZONE = { U: 'internet', X: 'internet', A: 'app', D: 'dados', Dev: 'entrega', P: 'entrega', G: 'entrega' };
const ROLE_ZONE = { frontend: 'app', mobile: 'app', backend: 'app', gateway: 'app', worker: 'app', infra: 'app', queue: 'dados', database: 'dados', storage: 'dados', external: 'internet' };
const APP_ROLES = new Set(['frontend', 'mobile', 'backend', 'gateway', 'worker']);

const clean = (s) => String(s).replace(/["<>\[\]{}|`\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80);
const clip = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));

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

const statesOf = (controls) => new Map(controls.map((c) => [c.id, c.state]));

// ---------------------------------------------------------------------------------------------
// Modo automático
// ---------------------------------------------------------------------------------------------

function buildArchitecture({ model, profile, controls }) {
  const flags = profile.flags || {};
  const d = model.discovery;
  const states = statesOf(controls);
  const bySurface = (...names) => model.threats.filter((t) => names.includes(t.surface));
  const nodes = new Set();
  const flows = [];
  const add = (id, from, to, label, boundary, surfaces, note) => {
    const threats = bySurface(...surfaces);
    if (!threats.length) return;
    nodes.add(from);
    nodes.add(to);
    flows.push({ id, from, to, label, boundary, surfaces, note: note || '', source: 'descoberto', ...summarize(threats, states) });
  };

  if (flags.webApp || d.routes.total > 0) {
    const r = d.routes;
    add('F1', 'U', 'A', 'Requisições web e autenticação', 'Internet para aplicação', ['web', 'auth'],
      r.total ? `${r.total} rota(s); ${r.byAuth['nao-vista']} sem autenticação vista` : '');
  }
  if (flags.uploads || d.uploads.length) add('F2', 'U', 'A', 'Arquivos enviados', 'Internet para aplicação', ['uploads'], d.uploads.join(', '));
  if (flags.realtime || d.realtime.length) add('F3', 'U', 'A', 'Conexão de tempo real', 'Internet para aplicação', ['realtime'], d.realtime.join(', '));
  if (d.stores.length || flags.personalData) add('F4', 'A', 'D', 'Leitura e escrita de dados', 'Aplicação para dados', ['data'], d.stores.join(', '));
  if (d.externalHosts.length) {
    const t = bySurface('data');
    if (t.length) {
      nodes.add('A'); nodes.add('X');
      flows.push({ id: 'F5', from: 'A', to: 'X', label: 'Chamadas a serviços externos', boundary: 'Aplicação para terceiros', surfaces: ['data'], note: d.externalHosts.slice(0, 4).join(', '), source: 'descoberto', ...summarize(t, states) });
    }
  }
  add('F6', 'Dev', 'P', 'Código, revisão e CI', 'Entrega do software', ['pipeline'], `${d.workflows} workflow(s)`);
  if (nodes.has('P')) { nodes.add('A'); flows.push({ id: 'F7', from: 'P', to: 'A', label: 'Entrega (deploy)', boundary: 'Entrega do software', surfaces: ['pipeline'], note: '', source: 'descoberto', ...summarize(bySurface('pipeline'), states) }); }
  if (flags.aiCodingAgents) add('F8', 'G', 'P', 'Agente de IA escreve código', 'Entrega do software', ['agent'], '');

  const labels = { ...NODE_LABEL };
  if (d.stores.length) labels.D = `Armazenamento (${clean(d.stores.join(', '))})`.slice(0, 30);
  return {
    mode: 'automático',
    name: null,
    nodes: [...nodes].map((id) => ({ id, label: labels[id], zone: NODE_ZONE[id], source: 'automático', note: '' })),
    flows,
    warnings: [],
    repos: [],
  };
}

// ---------------------------------------------------------------------------------------------
// Modo declarado (sistema com mais de um componente ou repositório)
// ---------------------------------------------------------------------------------------------

const BOUNDARY = (fz, tz) => {
  if (fz === 'entrega' || tz === 'entrega') return 'Entrega do software';
  if (fz === 'internet' && tz === 'app') return 'Internet para aplicação';
  if (fz === 'app' && tz === 'internet') return 'Aplicação para terceiros';
  if (tz === 'dados') return 'Aplicação para dados';
  if (fz === 'app' && tz === 'app') return 'Entre componentes';
  return 'Entre zonas';
};

function defaultSurfaces(from, to, flow, comps) {
  if (flow.surfaces) return flow.surfaces;
  const f = comps.get(from);
  const t = comps.get(to);
  if (from === 'dev') return ['pipeline'];
  if (flow.protocol === 'wss') return ['realtime'];
  if (flow.protocol === 'file') return ['uploads'];
  if (t && ['database', 'storage', 'queue', 'external'].includes(t.role)) return ['data'];
  if (from === 'user') return ['web', 'auth'];
  if (f && f.role === 'external') return ['web'];
  return ['web'];
}

/**
 * `perRepo`: Map(chave do repositório -> { dir, status, disc, model, controls, flags, name }) dos repositórios lidos.
 * `primaryKey`: chave do repositório analisado quando o componente não declara `repo`.
 */
function buildSystemArchitecture({ system, repos, perRepo, primary }) {
  const comps = new Map(system.components.map((c) => [c.id, c]));
  const warnings = [];
  const nodes = [];
  const flows = [];
  const infoOf = (c) => (c && c.repo && perRepo.get(c.repo)) || null;
  const nodeById = new Map();
  const addNode = (n) => { if (!nodeById.has(n.id)) { nodeById.set(n.id, n); nodes.push(n); } return nodeById.get(n.id); };

  addNode({ id: 'user', label: 'Usuário / navegador', zone: 'internet', source: 'declarado', note: '' });
  for (const c of system.components) {
    const info = infoOf(c);
    const repo = c.repo ? repos.get(c.repo) : null;
    let note = c.note || '';
    if (c.repo && repo && repo.status !== 'ok') {
      note = repo.status === 'fora-do-repositorio' ? 'repositório fora do analisado: não lido (use --allow-external-repos)' : `repositório ${repo.status.replace('-', ' ')}`;
      warnings.push(`Componente "${c.name}": repositório "${c.repo}" não foi lido (${repo.status.replace(/-/g, ' ')}). O desenho usa só o que foi declarado.`);
    } else if (c.repo && repo) note = `repo: ${repo.same ? '.' : c.repo}`;
    addNode({ id: c.id, label: clip(c.name, 28), zone: ROLE_ZONE[c.role], source: 'declarado', note: clip(note, 40), role: c.role, exposure: c.exposure || null, dataClasses: c.dataClasses || [], hasRepo: !!info });
  }

  const summarizeFor = (comp, surfaces) => {
    const info = infoOf(comp) || primary;
    const threats = info.model.threats.filter((t) => surfaces.includes(t.surface));
    return { sum: summarize(threats, statesOf(info.controls)), usedPrimary: !infoOf(comp) };
  };

  let n = 0;
  const addFlow = (from, to, label, surfaces, source, note, protocol) => {
    const fc = comps.get(from);
    const tc = comps.get(to);
    const owner = (tc && infoOf(tc) ? tc : fc && infoOf(fc) ? fc : tc || fc) || null;
    const { sum, usedPrimary } = summarizeFor(owner, surfaces);
    if (!sum.threats) return;
    n += 1;
    const fz = (nodeById.get(from) || {}).zone;
    const tz = (nodeById.get(to) || {}).zone;
    flows.push({
      id: `F${n}`, from, to, label: clip(label, 60), boundary: BOUNDARY(fz, tz), surfaces, protocol: protocol || null, source,
      note: [note, usedPrimary && owner ? 'ameaças do repositório principal (o componente não tem repositório lido)' : ''].filter(Boolean).join('; '), ...sum,
    });
  };

  const declared = system.flows || [];
  if (declared.some((f) => f.from === 'dev' || f.to === 'dev')) addNode({ id: 'dev', label: NODE_LABEL.Dev, zone: 'entrega', source: 'declarado', note: '' });
  if (declared.length) {
    for (const f of declared) {
      if (f.to === 'user') continue;
      addFlow(f.from, f.to, f.label, defaultSurfaces(f.from, f.to, f, comps), 'declarado', f.note || '', f.protocol);
    }
  } else {
    // Sem fluxos declarados: o kit infere o básico a partir dos papéis e marca como inferido.
    const apps = system.components.filter((c) => APP_ROLES.has(c.role));
    for (const c of apps.filter((x) => x.exposure === 'internet' || (!x.exposure && (x.role === 'frontend' || x.role === 'gateway')))) addFlow('user', c.id, 'Acesso do usuário', ['web', 'auth'], 'inferido', '');
    const fronts = apps.filter((c) => c.role === 'frontend' || c.role === 'mobile');
    const backs = apps.filter((c) => c.role === 'backend' || c.role === 'gateway');
    for (const f of fronts) for (const b of backs) addFlow(f.id, b.id, 'Chamadas à API', ['web'], 'inferido', '');
    for (const b of apps.filter((c) => c.role !== 'frontend' && c.role !== 'mobile')) {
      for (const d of system.components.filter((c) => ['database', 'storage', 'queue'].includes(c.role))) addFlow(b.id, d.id, 'Leitura e escrita de dados', ['data'], 'inferido', '');
      for (const x of system.components.filter((c) => c.role === 'external')) addFlow(b.id, x.id, 'Chamada a serviço externo', ['data'], 'inferido', '');
    }
  }

  // Descoberto e não declarado, por repositório lido.
  const readRepos = [...new Set(system.components.filter((c) => infoOf(c)).map((c) => c.repo))];
  readRepos.forEach((key, i) => {
    const info = perRepo.get(key);
    const users = system.components.filter((c) => c.repo === key);
    const owner = users.find((c) => ['backend', 'gateway', 'worker'].includes(c.role)) || users[0];
    const declaredStore = declared.length
      ? declared.some((f) => f.from && users.some((u) => u.id === f.from) && comps.get(f.to) && ['database', 'storage', 'queue'].includes(comps.get(f.to).role))
      : system.components.some((c) => ['database', 'storage', 'queue'].includes(c.role));
    if (info.disc.stores.length && !declaredStore) {
      addNode({ id: `d-${i}`, label: clip(`Armazenamento (${info.disc.stores.join(', ')})`, 28), zone: 'dados', source: 'descoberto', note: 'não declarado' });
      addFlow(owner.id, `d-${i}`, 'Leitura e escrita de dados', ['data'], 'descoberto', info.disc.stores.join(', '));
      warnings.push(`O repositório de "${owner.name}" usa ${info.disc.stores.join(', ')}, mas nenhum armazenamento foi declarado para ele. Declare o componente ou confirme.`);
    }
    const declaredExt = declared.length
      ? declared.some((f) => users.some((u) => u.id === f.from) && comps.get(f.to) && comps.get(f.to).role === 'external')
      : system.components.some((c) => c.role === 'external');
    if (info.disc.externalHosts.length && !declaredExt) {
      addNode({ id: `x-${i}`, label: 'Serviços externos', zone: 'internet', source: 'descoberto', note: 'não declarado' });
      addFlow(owner.id, `x-${i}`, 'Chamadas a serviços externos', ['data'], 'descoberto', info.disc.externalHosts.slice(0, 4).join(', '));
    }
  });

  // Cadeia de entrega: um nó de repositório e CI por repositório lido, mais o desenvolvedor e o agente.
  if (readRepos.length) addNode({ id: 'dev', label: NODE_LABEL.Dev, zone: 'entrega', source: 'declarado', note: '' });
  readRepos.forEach((key, i) => {
    const info = perRepo.get(key);
    const users = system.components.filter((c) => c.repo === key);
    const ci = addNode({ id: `ci-${i}`, label: clip(`Repositório e CI (${info.name})`, 28), zone: 'entrega', source: 'descoberto', note: `${info.disc.workflows} workflow(s)` });
    const owner = users[0];
    const sumP = summarize(info.model.threats.filter((t) => t.surface === 'pipeline'), statesOf(info.controls));
    if (sumP.threats) {
      n += 1;
      flows.push({ id: `F${n}`, from: 'dev', to: ci.id, label: 'Código, revisão e CI', boundary: 'Entrega do software', surfaces: ['pipeline'], protocol: null, source: 'descoberto', note: info.name, ...sumP });
      for (const u of users) {
        n += 1;
        flows.push({ id: `F${n}`, from: ci.id, to: u.id, label: 'Entrega (deploy)', boundary: 'Entrega do software', surfaces: ['pipeline'], protocol: null, source: 'descoberto', note: '', ...sumP });
      }
    }
    if (info.flags && info.flags.aiCodingAgents && owner) {
      const sumA = summarize(info.model.threats.filter((t) => t.surface === 'agent'), statesOf(info.controls));
      if (sumA.threats) {
        const ag = addNode({ id: `ag-${i}`, label: clip(`Agente de IA (${info.name})`, 28), zone: 'entrega', source: 'declarado', note: '' });
        n += 1;
        flows.push({ id: `F${n}`, from: ag.id, to: ci.id, label: 'Agente de IA escreve código', boundary: 'Entrega do software', surfaces: ['agent'], protocol: null, source: 'descoberto', note: '', ...sumA });
      }
    }
  });

  // Fluxos de componente sem repositório lido e sem modelo próprio ficam marcados no próprio fluxo (nota).
  const used = new Set(flows.flatMap((f) => [f.from, f.to]));
  const finalNodes = nodes.filter((nd) => used.has(nd.id) || nd.source === 'declarado' && nd.id !== 'user' || (nd.id === 'user' && used.has('user')));
  for (const c of system.components) if (!used.has(c.id)) warnings.push(`O componente "${c.name}" não aparece em nenhum fluxo. Declare os fluxos dele em "flows".`);
  return {
    mode: 'declarado',
    name: system.name,
    nodes: finalNodes,
    flows,
    warnings,
    repos: [...repos.entries()].map(([key, r]) => ({ key, status: r.status, inside: r.inside })),
  };
}

// ---------------------------------------------------------------------------------------------
// Renderização
// ---------------------------------------------------------------------------------------------

const mid = (id) => String(id).replace(/[^A-Za-z0-9_]/g, '_');
const zoneOf = (n) => n.zone || NODE_ZONE[n.id] || 'app';
const flowText = (f) => `${f.id}: ${f.threats} ameaça(s), ${f.exposed} exposta(s)`;

function toMermaid(arch) {
  const out = ['flowchart LR'];
  for (const [zone, title] of Object.entries(ZONES)) {
    const list = arch.nodes.filter((n) => zoneOf(n) === zone);
    if (!list.length) continue;
    out.push(`  subgraph ${zone}["${clean(title)}"]`);
    for (const n of list) out.push(`    ${mid(n.id)}["${clean(n.label)}${n.source === 'descoberto' ? ' (descoberto)' : ''}"]`);
    out.push('  end');
  }
  for (const f of arch.flows) out.push(`  ${mid(f.from)} -->|"${clean(`${f.label} (${flowText(f)})`)}"| ${mid(f.to)}`);
  const bad = arch.flows.filter((f) => f.exposed > 0).map((f) => f.id);
  return { code: out.join('\n'), exposedFlows: bad };
}

const NODE_W = 180;
const NODE_H = 54;
const ROW = 76;
const COLS = { internet: 10, app: 300, dados: 590 };
const COL_W = 250;

function layout(arch) {
  const pos = new Map();
  const boxes = [];
  const byZone = (z) => arch.nodes.filter((n) => zoneOf(n) === z);
  const maxRows = Math.max(1, ...['internet', 'app', 'dados'].map((z) => byZone(z).length));
  const topH = 44 + maxRows * ROW;
  for (const z of ['internet', 'app', 'dados']) {
    const list = byZone(z);
    if (!list.length) continue;
    boxes.push({ zone: z, title: ZONES[z], x: COLS[z], y: 14, w: COL_W, h: topH });
    list.forEach((n, i) => pos.set(n.id, { x: COLS[z] + (COL_W - NODE_W) / 2, y: 14 + 40 + i * ROW }));
  }
  const ent = byZone('entrega');
  let height = 14 + topH + 14;
  if (ent.length) {
    const rows = Math.ceil(ent.length / 4);
    const y0 = 14 + topH + 28;
    boxes.push({ zone: 'entrega', title: ZONES.entrega, x: 10, y: y0, w: 830, h: 44 + rows * ROW });
    ent.forEach((n, i) => pos.set(n.id, { x: 30 + (i % 4) * 205, y: y0 + 40 + Math.floor(i / 4) * ROW }));
    height = y0 + 44 + rows * ROW + 14;
  }
  return { pos, boxes, width: 850, height };
}

function clipToBox(cx, cy, dx, dy) {
  const tx = dx === 0 ? Infinity : (NODE_W / 2) / Math.abs(dx);
  const ty = dy === 0 ? Infinity : (NODE_H / 2) / Math.abs(dy);
  const t = Math.min(tx, ty);
  return [cx + dx * t, cy + dy * t];
}

/** SVG estático, sem script, com texto escapado pelo chamador (esc). Cor nunca é o único sinal: o texto traz o número. */
function toSvg(arch, esc) {
  const { pos, boxes, width, height } = layout(arch);
  const out = [`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Fluxo de dados e fronteiras de confiança" class="arch">`];
  out.push('<defs><marker id="seta" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="arch-seta"/></marker></defs>');
  for (const b of boxes) {
    out.push(`<rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="10" class="arch-zona"/>`);
    out.push(`<text x="${b.x + 12}" y="${b.y + 20}" class="arch-titulo">${esc(b.title)}</text>`);
  }
  const pair = new Map();
  for (const f of arch.flows) {
    const a = pos.get(f.from);
    const b = pos.get(f.to);
    if (!a || !b) continue;
    const key = [f.from, f.to].sort().join('|');
    const k = pair.get(key) || 0;
    pair.set(key, k + 1);
    const c1 = [a.x + NODE_W / 2, a.y + NODE_H / 2];
    const c2 = [b.x + NODE_W / 2, b.y + NODE_H / 2];
    let dx = c2[0] - c1[0];
    let dy = c2[1] - c1[1];
    const len = Math.hypot(dx, dy) || 1;
    const off = (k - 0) * 22;
    const px = (-dy / len) * off;
    const py = (dx / len) * off;
    const [sx, sy] = clipToBox(c1[0], c1[1], dx, dy);
    const [ex, ey] = clipToBox(c2[0], c2[1], -dx, -dy);
    const x1 = Math.round(sx + px);
    const y1 = Math.round(sy + py);
    const x2 = Math.round(ex + px);
    const y2 = Math.round(ey + py);
    out.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="arch-fluxo${f.exposed > 0 ? ' arch-exposto' : ''}${f.source === 'declarado' || f.source === 'descoberto' ? '' : ' arch-inferido'}" marker-end="url(#seta)"/>`);
    const mx = Math.round((x1 + x2) / 2);
    const my = Math.round((y1 + y2) / 2) - 4;
    out.push(`<text x="${mx}" y="${my}" text-anchor="middle" class="arch-rotulo">${esc(`${f.id} ${clip(f.label, 30)}`)}</text>`);
    out.push(`<text x="${mx}" y="${my + 12}" text-anchor="middle" class="arch-rotulo arch-sub">${esc(`${f.threats} ameaça(s), ${f.exposed} exposta(s)`)}</text>`);
  }
  for (const n of arch.nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    out.push(`<rect x="${p.x}" y="${p.y}" width="${NODE_W}" height="${NODE_H}" rx="8" class="arch-no${n.source === 'descoberto' ? ' arch-desc' : ''}"/>`);
    out.push(`<text x="${p.x + NODE_W / 2}" y="${p.y + (n.note ? 22 : 31)}" text-anchor="middle" class="arch-notexto">${esc(clip(n.label, 28))}</text>`);
    if (n.note) out.push(`<text x="${p.x + NODE_W / 2}" y="${p.y + 40}" text-anchor="middle" class="arch-rotulo arch-sub">${esc(clip(n.note, 34))}</text>`);
  }
  out.push('</svg>');
  return out.join('');
}

module.exports = { buildArchitecture, buildSystemArchitecture, toMermaid, toSvg, NODE_LABEL, ZONES };
