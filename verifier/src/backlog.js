'use strict';

// Geração de backlog a partir do resultado de uma verificação (análise de lacunas).
// Cada controle falho ou não verificado vira um ticket, com prioridade P0 a P3.
// Não duplica: se já existe ticket aberto ou em andamento para o controle, nada é criado.

const fs = require('node:fs');
const path = require('node:path');
const U = require('./util');
const schema = require('./schema');
const { threatsToMitigate } = require('./threatmodel');

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Prioridade: parte da severidade (critical=P0 ... low=P3). Sobe um nível (menos urgente) se a aplicação
 * não é exposta à internet; e um nível se for só "verificar" de camada 2 ou 3 (a lacuna ainda não é um defeito).
 */
function priorityFor(control, type, profile, threatBoost = false) {
  let rank = SEV_RANK[control.severity];
  // Ameaça que alguém decidiu mitigar no modelo de ameaças sobe um nível de urgência.
  if (threatBoost) rank -= 1;
  if (profile && profile.flags && profile.flags.publicInternet === false) rank += 1;
  if (type === 'verify' && control.tier > 1) rank += 1;
  return `P${Math.min(3, Math.max(0, rank))}`;
}

function loadTickets(root) {
  const dir = path.join(root, '.lastro', 'backlog');
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((f) => /^T-\d{4}\.json$/.test(f)).sort();
  } catch (e) {
    return { tickets: [], errors: [] };
  }
  const tickets = [];
  const errors = [];
  for (const n of names) {
    const j = U.readJson(root, `.lastro/backlog/${n}`);
    if (!j.ok) { errors.push(`${n}: ${j.error}`); continue; }
    const errs = schema.validateTicket(j.value, n);
    if (errs.length) errors.push(...errs);
    else tickets.push(j.value);
  }
  return { tickets, errors };
}

function planBacklog(report, profile, existing, now = new Date()) {
  const mitigate = threatsToMitigate(report.threatModel);
  const open = new Set(existing.filter((t) => t.status === 'open' || t.status === 'in_progress').map((t) => t.control));
  const maxId = existing.reduce((m, t) => Math.max(m, Number(t.id.slice(2))), 0);
  const planned = [];
  let next = maxId;
  for (const c of report.controls) {
    if (c.state !== 'failed' && c.state !== 'unverified') continue;
    if (open.has(c.id) || c.controlRiskAccepted) continue;
    const pendingFindings = c.findings.filter((f) => !f.accepted);
    if (c.state === 'failed' && pendingFindings.length === 0) continue;
    const type = c.state === 'failed' ? 'fix' : 'verify';
    const threats = mitigate.get(c.id) || [];
    next += 1;
    planned.push({
      schemaVersion: 1,
      id: `T-${String(next).padStart(4, '0')}`,
      control: c.id,
      type,
      priority: priorityFor(c, type, profile, threats.length > 0),
      status: 'open',
      title: type === 'fix' ? `Corrigir ${c.id}: ${c.title}` : `Verificar ${c.id}: ${c.title}`,
      summary: `${threats.length ? `Mitiga ${threats.join(', ')} do modelo de ameaças. ` : ''}${pendingFindings.slice(0, 3).map((f) => f.message).join(' | ') || (c.notes[0] || '')}`.trim(),
      ...(threats.length ? { threat: threats[0] } : {}),
      acceptance: [
        type === 'fix'
          ? `"lastro check" mostra ${c.id} como verified, ou há risco aceito com dono e validade`
          : `${c.id} verificado por teste automático ou atestado com validade em .lastro/status.json`,
      ],
      owner: null,
      createdAt: now.toISOString(),
      source: 'lastro-backlog',
    });
  }
  planned.sort((a, b) => a.priority.localeCompare(b.priority) || a.control.localeCompare(b.control));
  // Renumera na ordem de prioridade para o T-0001 ser o mais urgente.
  planned.forEach((t, i) => { t.id = `T-${String(maxId + i + 1).padStart(4, '0')}`; });
  return planned;
}

function writeTickets(root, tickets) {
  const dir = path.join(root, '.lastro', 'backlog');
  fs.mkdirSync(dir, { recursive: true });
  for (const t of tickets) fs.writeFileSync(path.join(dir, `${t.id}.json`), `${JSON.stringify(t, null, 2)}\n`, { flag: 'wx' });
}

module.exports = { priorityFor, loadTickets, planBacklog, writeTickets };
