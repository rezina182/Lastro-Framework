'use strict';

// Escopo por assunto: mostra só os controles de um pacote (auth, web, pii, realtime, uploads, assets, agent, core),
// com o estado e o que fazer em cada um. Serve para quem vai mexer em um assunto e não precisa ler o catálogo todo.

const STATE_PT = { verified: 'verificado', failed: 'FALHANDO', unverified: 'sem prova', not_applicable: 'não se aplica' };
const SEV_PT = { critical: 'crítica', high: 'alta', medium: 'média', low: 'baixa' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const STATE_ORDER = { failed: 0, unverified: 1, verified: 2 };

const clip = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));

function scopeNames(catalog) {
  return Object.keys(catalog.packs);
}

/** Controles do pacote, no catálogo, na ordem do id. */
function scopeControlIds(catalog, name) {
  return catalog.controls.filter((c) => c.pack === name).map((c) => c.id);
}

/**
 * Texto do escopo. `report` é o resultado de runCheck com `only` do pacote; controles que não se aplicam ao perfil
 * não vêm no relatório, e o texto diz quais flags faltam.
 */
function formatScope(report, catalog, name, flags) {
  const pack = catalog.packs[name];
  const out = [`Escopo "${name}": ${pack.title}`, ''];
  const missing = (pack.requires || []).filter((f) => !(flags || {})[f]);
  if (missing.length) {
    out.push(`Nenhum controle deste escopo se aplica ao perfil: faltam as flags ${missing.join(', ')}. Se a aplicação tem isso, declare no .lastro/profile.json.`);
    return out.join('\n');
  }
  const list = [...report.controls].sort((a, b) => STATE_ORDER[a.state] - STATE_ORDER[b.state] || SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id));
  const count = { verified: 0, failed: 0, unverified: 0 };
  for (const c of list) count[c.state] = (count[c.state] || 0) + 1;
  out.push(`${list.length} controle(s) aplicáveis: ${count.verified} verificado(s), ${count.failed} falhando, ${count.unverified} sem prova.`, '');
  for (const c of list) {
    const def = catalog.byId.get(c.id);
    out.push(`[${STATE_PT[c.state]}] ${c.id} (gravidade ${SEV_PT[c.severity]}) ${c.title}`);
    if (c.state === 'verified') continue;
    for (const f of c.findings.slice(0, 3)) out.push(`    achado: ${clip(f.message, 160)}${f.location ? ` (${f.location})` : ''}`);
    if (c.findings.length > 3) out.push(`    ... e mais ${c.findings.length - 3} achado(s)`);
    if (c.state === 'failed') out.push(`    como corrigir: ${clip(def.remediation, 300)}`);
    else out.push(`    como provar: ${clip(def.check.type === 'manual' ? def.howToVerify : (c.notes[0] || def.summary), 300)}`);
    const asvs = def.refs.filter((r) => r.std === 'ASVS').map((r) => r.id).slice(0, 6);
    if (asvs.length) out.push(`    ASVS: ${asvs.join(', ')}`);
  }
  out.push('', 'Controle manual só passa com atestação de uma pessoa em .lastro/status.json (responsável e validade). O agente propõe o texto; quem atesta é o usuário.');
  return out.join('\n');
}

module.exports = { scopeNames, scopeControlIds, formatScope };
