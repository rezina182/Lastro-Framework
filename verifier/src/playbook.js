'use strict';

// Playbook de verificação e correção dos controles manuais: para cada controle sem prova, um roteiro com o que
// preparar, o passo a passo do teste, o que conferir, a evidência a guardar, o que fazer se falhar e como registrar a
// atestação. O texto vem do catálogo (howToVerify, rationale, remediation); o kit só o organiza em passos e acrescenta
// os cuidados de segurança do próprio teste (ambiente, dados de teste, quem pode atestar).

const R = require('./risk');
const L = require('./links');

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_PT = { critical: 'crítica', high: 'alta', medium: 'média', low: 'baixa' };
const KIND_ORDER = { security: 0, practice: 1, quality: 2 };
const DAY = 24 * 60 * 60 * 1000;
// Validade sugerida da atestação: controles altos e críticos são revistos com mais frequência. O motor aceita até 366.
const VALIDITY_DAYS = { critical: 180, high: 180, medium: 365, low: 365 };

const PREREQS = [
  { re: /(envie|chame|requisi|login|sess[aã]o|token|\bapi\b|rota|url|navegador|cookie|upload|cabe[cç]alho|formul[aá]rio)/i,
    text: 'Faça o teste em ambiente local ou de staging, com dados de teste. Nunca em produção: testes de abuso podem gerar carga, alarmes e apagar dados.' },
  { re: /\bconta/i, text: 'Contas de teste: pelo menos duas comuns e, se o passo pedir, uma de perfil superior. Não use contas de pessoas reais.' },
  { re: /(branch|push|\bPR\b|pull request|merge)/i, text: 'Um repositório ou uma branch descartável, para que a tentativa recusada não deixe resto.' },
  { re: /(plataforma|plano do reposit|configura[cç][aã]o d[oa] (reposit|plataforma)|painel|nuvem|provedor)/i, text: 'Acesso de leitura às configurações da plataforma (GitHub, nuvem ou hospedagem), para conferir a regra e tirar print.' },
  { re: /\blogs?\b|registro/i, text: 'Acesso de leitura aos logs do ambiente de teste.' },
  { re: /(agente|hook|steering|instru[cç][aã]o)/i, packs: ['agent'], text: 'Uma sessão de teste do agente de IA, numa pasta sem segredos reais.' },
  { re: /(segredo|cofre|chave|credencial|senha)/i, text: 'Nunca copie um segredo real para a evidência: registre só nomes, caminhos e o resultado.' },
];

const clean = (s) => String(s).replace(/\s+/g, ' ').trim();

/** Divide o texto de verificação do catálogo em passos e separa o pedido final de registro. */
function splitSteps(text) {
  let t = clean(text);
  const register = [];
  // O pedido de registro fica no fim do texto do catálogo; pode citar caminhos com ponto (.lastro/status.json).
  t = t.replace(/(?:^|(?<=[.;]\s))(Registre\b.*)$/u, (m, r) => { register.push(r.trim()); return ''; }).trim();
  let parts;
  // Marcador de passo é "(1)" depois de espaço e antes de uma palavra: alert(1) num exemplo de XSS não é passo.
  const MARK = /(?:^|\s)\(\d{1,2}\)\s+(?=\p{L})/u;
  if (MARK.test(t) && /(?:^|\s)\(2\)\s+\p{L}/u.test(t)) {
    const [head, ...rest] = t.split(/(?:^|\s)\(\d{1,2}\)\s+(?=\p{L})/u);
    parts = [...(head.trim() ? [head.trim().replace(/:$/, '.')] : []), ...rest];
  } else parts = t.split(/(?<=[.;])\s+(?=[A-ZÁÉÍÓÚÂÊÔÃÕÇ])/u);
  const cap = (s) => s.replace(/^./, (c) => c.toUpperCase());
  const steps = parts.map((p) => cap(clean(p).replace(/[;,]\s*$/, ''))).filter((p) => p.length > 2).map((p) => (/[.!?]$/.test(p) ? p : `${p}.`));
  // O que conferir: cada "confirme que ..." vira um item; se a frase ficar curta demais para entender sozinha
  // ("É recusado."), o item leva o passo inteiro. Passos que descrevem o resultado esperado ("recebe 403",
  // "é recusado", "não altera") também viram item.
  const checks = [];
  const EXPECT = /\b(recebe|recusa|é recusad|é bloquead|bloqueia|não alter|não executa|não aparece|não é|não são|falha|retorna|devolve|expira|encerra|exige)\b/iu;
  for (const s of steps) {
    let found = false;
    for (const m of s.matchAll(/confirme\s+(?:na prática\s+)?que\s+([^.;]+?)(?=(?:,\s*e\s+confirme|\s+e\s+confirme|[.;]|$))/giu)) {
      const clause = m[1].trim();
      checks.push(clause.length < 35 ? s : `${cap(clause)}.`);
      found = true;
    }
    if (!found && EXPECT.test(s) && !/^(Procure|Leia|Liste|Abra|Revise)\b/.test(s)) checks.push(s);
  }
  return { steps, checks: [...new Set(checks)], register };
}

function prereqsFor(control, text) {
  const out = [];
  for (const p of PREREQS) {
    const packHit = p.packs && p.packs.length === 1 && p.packs[0] === control.pack;
    if (p.re.test(text) || packHit) out.push(p.text);
  }
  return [...new Set(out)];
}

const isoDay = (d) => d.toISOString().slice(0, 10);

/** Monta os itens do playbook. `report` é o resultado de runCheck; `catalog` o catálogo carregado. */
function buildPlaybook(report, catalog, { now = new Date(), only = null, scope = null, all = false } = {}) {
  const riskMap = catalog.riskMap || {};
  const tm = report.threatModel;
  const items = [];
  for (const c of report.controls) {
    const def = catalog.byId.get(c.id);
    if (!def || def.check.type !== 'manual') continue;
    if (only && !only.includes(c.id)) continue;
    if (scope && c.pack !== scope) continue;
    if (!all && c.state === 'verified') continue;
    const e = riskMap[c.id] || { kind: 'practice', pillars: '', cwe: [] };
    const { steps, checks, register } = splitSteps(def.howToVerify);
    const threats = tm ? tm.threats.filter((t) => t.controls.includes(c.id)).map((t) => ({ id: t.id, name: t.strideName, state: t.state, decision: t.decision })) : [];
    const days = VALIDITY_DAYS[c.severity] || 365;
    const risk = report.risk ? report.risk.security.find((i) => i.id === c.id) : null;
    items.push({
      id: c.id, title: c.title, pack: c.pack, severity: c.severity, state: c.state, kind: e.kind,
      kindLabel: R.KINDS[e.kind] ? R.KINDS[e.kind].label : e.kind,
      pillars: (e.pillars || '').split('').filter(Boolean).map((p) => R.PILLARS[p]),
      cwe: e.cwe || [], lgpd: e.lgpd || null,
      asvs: def.refs.filter((r) => r.std === 'ASVS').map((r) => r.id),
      riskClass: risk ? risk.class : null,
      why: def.rationale, summary: def.summary,
      prereqs: prereqsFor(c, `${def.howToVerify} ${def.summary}`),
      steps, checks, registerHint: register[0] || null,
      fix: def.remediation,
      threats,
      attestation: {
        validityDays: days,
        highNeedsReviewer: c.severity === 'critical' || c.severity === 'high',
        json: {
          [c.id]: {
            state: 'verified',
            attestedBy: 'NOME DE QUEM TESTOU',
            collectedAt: isoDay(now),
            expiresAt: isoDay(new Date(now.getTime() + days * DAY)),
            evidenceRef: 'onde está a evidência (link do PR, print, ticket ou pasta)',
            note: 'resumo do resultado em uma frase',
          },
        },
      },
    });
  }
  items.sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || SEV_ORDER[a.severity] - SEV_ORDER[b.severity]
    || (b.threats.some((t) => t.decision === 'mitigate') ? 1 : 0) - (a.threats.some((t) => t.decision === 'mitigate') ? 1 : 0)
    || a.id.localeCompare(b.id));
  const byKind = { security: 0, practice: 0, quality: 0 };
  for (const i of items) byKind[i.kind] = (byKind[i.kind] || 0) + 1;
  return { project: report.profile.name, generatedAt: now.toISOString(), total: items.length, byKind, items };
}

// ---------------------------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------------------------

const md = (s) => String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
// "Registre com data." já está coberto pela evidência padrão; só vale citar o pedido do catálogo quando ele diz mais.
const extraHint = (i) => (i.registerHint && !/^Registre( a evidência)?( com data)?\.?$/i.test(i.registerHint.trim()) ? i.registerHint : null);

const GENERAL = [
  'Teste em ambiente local ou de staging, com dados e contas de teste. Nunca em produção.',
  'Quem escreveu o código não deve ser a única pessoa a atestar um controle de gravidade alta ou crítica: peça a outra pessoa para repetir o teste ou revisar a evidência.',
  'Guarde a evidência fora do repositório público (print, log, link do PR ou do ticket) e nunca inclua segredo, senha ou dado pessoal real.',
  'Se o teste falhar, não ateste: corrija (seção "Se falhar"), repita o teste e só então registre. Para virar tarefa, rode `lastro backlog --write`.',
  'A atestação é autodeclaração com prazo. Ao vencer, o controle volta a "sem prova" e o teste precisa ser repetido.',
];

function itemMd(i, n) {
  const out = [`### ${n}. ${i.id}: ${md(i.title)}`, ''];
  const meta = [`gravidade ${SEV_PT[i.severity]}`, i.kindLabel, `estado: ${i.state === 'failed' ? 'falhando' : i.state === 'verified' ? 'verificado' : 'sem prova'}`];
  if (i.riskClass) meta.push(`risco potencial ${R.CLASS_PT[i.riskClass].toLowerCase()}`);
  out.push(`- **Situação:** ${meta.join(' | ')}`);
  if (i.pillars.length) out.push(`- **Pilares:** ${i.pillars.join(', ')}`);
  if (i.cwe.length) out.push(`- **CWE:** ${i.cwe.map((x) => L.mdLink(`CWE-${x}`, L.cweUrl(x))).join(', ')}`);
  if (i.asvs.length) out.push(`- **ASVS:** ${i.asvs.slice(0, 8).join(', ')}`);
  if (i.lgpd) out.push(`- **LGPD:** ${md(i.lgpd)}`);
  if (i.threats.length) out.push(`- **Ameaças que este controle mitiga:** ${i.threats.map((t) => `${t.id} (${t.name})`).join(', ')}`);
  out.push('', `**Por que importa.** ${md(i.why)}`, '');
  if (i.prereqs.length) out.push('**Antes de começar**', '', ...i.prereqs.map((p) => `- ${p}`), '');
  out.push('**Passo a passo**', '', ...i.steps.map((s, k) => `${k + 1}. ${md(s)}`), '');
  out.push('**Resultado esperado (para passar)**', '');
  if (i.checks.length) out.push(...i.checks.map((c) => `- [ ] ${md(c)}`));
  else out.push('- [ ] Cada passo acima teve o resultado descrito, sem exceção.');
  out.push('- [ ] O resultado foi conferido por mais uma pessoa' + (i.attestation.highNeedsReviewer ? ' (obrigatório para gravidade alta ou crítica).' : ' (recomendado).'), '');
  out.push('**Evidência a guardar**', '', `- Data, ambiente (local ou staging), quem fez e o resultado de cada passo.${extraHint(i) ? ` O catálogo pede também: ${md(extraHint(i))}` : ''}`, '- Print, log ou link (PR, ticket, configuração). Sem segredo, senha ou dado pessoal real.', '');
  out.push('**Se falhar**', '', `${md(i.fix)}`, '', 'Depois de corrigir, repita o passo a passo inteiro. Para acompanhar a correção, `lastro backlog --write` cria o ticket.', '');
  out.push('**Como registrar**', '', `Acrescente em \`.lastro/status.json\`, dentro de \`"attestations"\` (validade sugerida: ${i.attestation.validityDays} dias):`, '', '```json', JSON.stringify(i.attestation.json, null, 2).slice(2, -2), '```', '');
  return out;
}

function formatPlaybookMarkdown(p) {
  const out = [`# Playbook de verificação: ${md(p.project)}`, ''];
  out.push(`Gerado em ${p.generatedAt.slice(0, 10)}. ${p.total} controle(s) manual(is) a testar: ${p.byKind.security || 0} de segurança, ${p.byKind.practice || 0} de boa prática e ${p.byKind.quality || 0} de qualidade. A ordem é por natureza (segurança primeiro) e gravidade.`, '');
  out.push('## Regras para todos os testes', '', ...GENERAL.map((g) => `- ${g}`), '');
  out.push('## Lista de verificação', '', '| # | Controle | Gravidade | Natureza | Feito |', '|---|---|---|---|---|');
  p.items.forEach((i, k) => out.push(`| ${k + 1} | ${i.id} ${md(i.title)} | ${SEV_PT[i.severity]} | ${i.kindLabel} | [ ] |`));
  out.push('', '## Roteiros', '');
  p.items.forEach((i, k) => out.push(...itemMd(i, k + 1)));
  out.push('## Depois de registrar', '', '1. Rode `lastro check`: o controle passa a "verificado" e mostra quem atestou e até quando.', '2. Rode `lastro report --out relatorio.html` para ver a maturidade e o risco atualizados.', '3. Marque na agenda a data de vencimento de cada atestação.', '');
  return `${out.join('\n')}\n`;
}

// ---------------------------------------------------------------------------------------------
// HTML (mesmo estilo dos relatórios, sem script)
// ---------------------------------------------------------------------------------------------

function formatPlaybookHtml(p, { theme = null } = {}) {
  const { ui } = require('./html');
  const { h, num, table, cweLinks, htmlShell } = ui;
  const s = [];
  s.push('<section id="regras" aria-labelledby="t-regras"><h2 id="t-regras">Regras para todos os testes</h2><ul>', ...GENERAL.map((g) => `<li>${h(g.replace(/`/g, ''))}</li>`), '</ul></section>');
  s.push('<section id="lista" aria-labelledby="t-lista"><h2 id="t-lista">Lista de verificação</h2>');
  s.push(table(`${num(p.total)} controle(s) a testar, em ordem de prioridade`, ['#', 'Controle', 'Gravidade', 'Natureza'],
    p.items.map((i, k) => [String(k + 1), `<a href="#pb-${h(i.id)}">${h(i.id)}</a> ${h(i.title)}`, h(SEV_PT[i.severity]), h(i.kindLabel)]), [0]));
  s.push('</section>', '<section id="roteiros" aria-labelledby="t-rot"><h2 id="t-rot">Roteiros</h2>');
  p.items.forEach((i, k) => {
    s.push(`<details id="pb-${h(i.id)}"${k < 3 ? ' open' : ''}><summary>${num(k + 1)}. ${h(i.id)}: ${h(i.title)} <span class="count">gravidade ${h(SEV_PT[i.severity])}, ${h(i.kindLabel)}</span></summary>`);
    const meta = [];
    if (i.pillars.length) meta.push(`<strong>Pilares:</strong> ${h(i.pillars.join(', '))}`);
    if (i.cwe.length) meta.push(`<strong>CWE:</strong> ${cweLinks(i.cwe)}`);
    if (i.asvs.length) meta.push(`<strong>ASVS:</strong> ${h(i.asvs.slice(0, 8).join(', '))}`);
    if (i.lgpd) meta.push(`<strong>LGPD:</strong> ${h(i.lgpd)}`);
    if (i.threats.length) meta.push(`<strong>Ameaças que mitiga:</strong> ${h(i.threats.map((t) => `${t.id} (${t.name})`).join(', '))}`);
    if (meta.length) s.push(`<p>${meta.join(' | ')}</p>`);
    s.push(`<p><strong>Por que importa.</strong> ${h(i.why)}</p>`);
    if (i.prereqs.length) s.push('<h3>Antes de começar</h3><ul>', ...i.prereqs.map((x) => `<li>${h(x)}</li>`), '</ul>');
    s.push('<h3>Passo a passo</h3><ol>', ...i.steps.map((x) => `<li>${h(x)}</li>`), '</ol>');
    s.push('<h3>Resultado esperado (para passar)</h3><ul>', ...(i.checks.length ? i.checks : ['Cada passo acima teve o resultado descrito, sem exceção.']).map((x) => `<li>${h(x)}</li>`),
      `<li>O resultado foi conferido por mais uma pessoa${i.attestation.highNeedsReviewer ? ' (obrigatório para gravidade alta ou crítica)' : ' (recomendado)'}.</li>`, '</ul>');
    s.push('<h3>Evidência a guardar</h3><ul>', `<li>Data, ambiente (local ou staging), quem fez e o resultado de cada passo.${extraHint(i) ? ` O catálogo pede também: ${h(extraHint(i))}` : ''}</li>`, '<li>Print, log ou link (PR, ticket, configuração). Sem segredo, senha ou dado pessoal real.</li>', '</ul>');
    s.push('<h3>Se falhar</h3>', `<p>${h(i.fix)}</p>`, '<p>Depois de corrigir, repita o passo a passo inteiro. Para acompanhar a correção, <code>lastro backlog --write</code> cria o ticket.</p>');
    s.push('<h3>Como registrar</h3>', `<p>Acrescente em <code>.lastro/status.json</code>, dentro de <code>"attestations"</code> (validade sugerida: ${num(i.attestation.validityDays)} dias):</p>`);
    s.push(`<pre><code>${h(JSON.stringify(i.attestation.json, null, 2).slice(2, -2))}</code></pre>`, '</details>');
  });
  s.push('</section>');
  return htmlShell({
    title: `Playbook de verificação: ${p.project}`, eyebrow: 'Playbook LASTRO',
    meta: [`Gerado em ${p.generatedAt.slice(0, 10)} | ${p.total} controle(s) manual(is): ${p.byKind.security || 0} de segurança, ${p.byKind.practice || 0} de boa prática, ${p.byKind.quality || 0} de qualidade`],
    nav: [['regras', 'Regras'], ['lista', 'Lista'], ['roteiros', 'Roteiros']], sections: s, theme,
  });
}

module.exports = { buildPlaybook, splitSteps, formatPlaybookMarkdown, formatPlaybookHtml, VALIDITY_DAYS };
