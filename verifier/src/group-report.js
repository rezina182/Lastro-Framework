'use strict';

// Relatório da aplicação com vários repositórios (Markdown e HTML autocontido).

const { mdui } = require('./report');
const { ui } = require('./html');
const R = require('./risk');
const { staticLegend } = require('./legend');

const { md, cweText, archSectionMd, legendMd } = mdui;
const { h, num, table, card, classBadge, cweLinks, archSectionHtml, legendHtml, htmlShell } = ui;

const VERDICT_PT = { pass: 'aprovado', fail: 'falha', incomplete: 'incompleto' };
const ROLE_PT = {
  frontend: 'Frontend', mobile: 'Aplicativo móvel', backend: 'Backend (API)', gateway: 'Gateway', worker: 'Worker (tarefas)', infra: 'Infraestrutura', library: 'Biblioteca',
};
const CONF_PT = { alta: 'alta', media: 'média', baixa: 'baixa', declarado: 'declarada por você' };

const confText = (c) => (c ? `${c.critical} crítico, ${c.high} alto, ${c.medium} médio, ${c.low} baixo` : '-');
const levelText = (r) => (r.level === null ? '-' : `${r.level}`);
const pct = (v) => (v === null || v === undefined ? '-' : `${String(v).replace('.', ',')}%`);

const NOTE_DERIVED = 'Perfil derivado é rascunho: o kit leu o código e ligou as flags que ele mostra (rotas, upload, tempo real, dados pessoais pelos nomes dos campos...). Dados de crianças e adolescentes, dados sensíveis e usuários anônimos o código não mostra e ficam desligados: declare no `.lastro/profile.json` de cada repositório.';
const NOTE_ROLES = 'Os papéis são heurísticas lidas do código, com motivo e confiança. Para corrigir, gere o rascunho com `--write-system ARQUIVO`, edite os papéis e as ligações e rode de novo com `--system ARQUIVO`.';
const LIMITS = [
  'Cada repositório foi verificado só pelo que o código e a configuração mostram. Nada foi executado nem acessado pela rede.',
  'As ligações entre repositórios (quem chama quem) são inferidas por menção no código e pelos papéis. Confirme no desenho.',
  'O risco confirmado é o que a verificação achou; o que ninguém provou fica de fora da lista e aparece como contagem de "potencial".',
  'A pontuação e as classes medem evidência e priorizam a investigação. Elas não certificam a aplicação.',
];

function formatGroupMarkdown(g) {
  const t = g.totals;
  const out = [`# Relatório da aplicação: ${md(g.name)}`, ''];
  out.push(`Gerado em ${g.generatedAt.slice(0, 10)} | LASTRO ${g.tool.version} | ${t.analyzed} de ${t.repos} repositório(s) analisado(s) | somente verificações estáticas, nenhuma requisição à aplicação.`, '');
  out.push('## Resumo', '');
  out.push(`- Riscos de segurança **confirmados** na aplicação: ${confText(t.confirmed)}.`);
  out.push(`- Riscos **potenciais** (sem prova, no máximo "alto"): ${t.potential.high} alto, ${t.potential.medium} médio, ${t.potential.low} baixo.`);
  out.push(`- Ameaças: ${t.threats} no total, ${t.threatsExposed} expostas (há controle falhando).`);
  out.push(`- Portão de CI: ${t.gateFail} de ${t.analyzed} repositório(s) falham.`);
  out.push(`- Perfis derivados pelo kit (rascunho): ${t.derivedProfiles}.`, '');
  out.push('## Repositórios identificados', '');
  out.push(NOTE_ROLES, '');
  out.push('| Repositório | Papel | Confiança | Por quê | Perfil | Portão | Nível | Automáticos | Risco confirmado | Ameaças expostas |', '|---|---|---|---|---|---|---|---|---|---|');
  for (const r of g.repos) {
    out.push(`| ${md(r.name)} | ${ROLE_PT[r.role] || r.role}${r.fullstack ? ' (full stack)' : ''} | ${CONF_PT[r.confidence] || r.confidence} | ${md((r.reasons || []).slice(0, 3).join('; ') || '-')} | ${r.profile} | ${r.error ? 'erro' : VERDICT_PT[r.verdict]} | ${levelText(r)} | ${r.automated && r.automated.passRatePct !== null ? pct(r.automated.passRatePct) : '-'} | ${md(confText(r.confirmed))} | ${r.threats ? r.threats.exposed : '-'} |`);
  }
  out.push('', `> ${NOTE_DERIVED}`, '');
  if (g.architecture && g.architecture.flows.length) out.push(...archSectionMd(g.architecture));

  out.push('## Riscos de segurança confirmados, de todos os repositórios', '');
  if (!g.risks.length) out.push('Nenhum.', '');
  else {
    out.push('Em ordem decrescente de risco (probabilidade x impacto). Cada risco vem do repositório indicado.', '');
    out.push('| Repositório | Classe | P x I | Controle | CWE | Pilares | Onde |', '|---|---|---|---|---|---|---|');
    for (const i of g.risks.slice(0, 40)) {
      out.push(`| ${md(i.repo)} | ${R.CLASS_PT[i.class]} | ${i.likelihood} x ${i.impact} = ${i.score} | ${i.id} ${md(i.title)} | ${cweText(i.cwe)} | ${i.pillars.map((p) => R.PILLARS[p]).join(', ')} | ${md((i.locations || []).join(', ') || '-')} |`);
    }
    if (g.risks.length > 40) out.push('', `... e mais ${g.risks.length - 40}.`);
    out.push('');
  }
  out.push('### Por repositório', '', '| Repositório | Confirmado | Potencial (alto) | Potencial (médio) | Ameaças | Expostas | Sem decisão |', '|---|---|---|---|---|---|---|');
  for (const r of g.repos.filter((x) => !x.error)) {
    out.push(`| ${md(r.name)} | ${r.confirmed.total} | ${r.potential.high} | ${r.potential.medium} | ${r.threats.threats} | ${r.threats.exposed} | ${r.threats.pending} |`);
  }
  out.push('');
  const withPersonal = g.repos.filter((r) => r.personalData);
  out.push('## Privacidade e dados pessoais', '');
  out.push(withPersonal.length
    ? `Os repositórios com indício de dado pessoal (pelo nome dos campos ou pelo perfil declarado) são: ${withPersonal.map((r) => md(r.name)).join(', ')}. Dados de crianças e adolescentes e dados sensíveis não podem ser inferidos do código: se a aplicação os trata, declare \`minorsData\` e \`context.sensitiveData\` no perfil, porque isso sobe o impacto dos riscos de confidencialidade.`
    : 'Nenhum repositório mostrou indício de dado pessoal. Se a aplicação trata dados pessoais, declare `personalData` no perfil.', '');
  if (g.warnings.length) out.push('## Avisos', '', ...g.warnings.map((w) => `- ${md(w)}`), '');
  out.push('## Limites', '', ...LIMITS.map((x) => `- ${x}`), '');
  if (g.legend) out.push(...legendMd({ legend: g.legend }));
  return `${out.join('\n')}\n`;
}

function formatGroupHtml(g, { theme = null } = {}) {
  const t = g.totals;
  const s = [];
  s.push('<section id="resumo" aria-labelledby="t-resumo"><h2 id="t-resumo">Resumo</h2><div class="cards">');
  s.push(card('Repositórios', `${num(t.analyzed)} de ${num(t.repos)}`, 'analisados, só leitura'));
  s.push(card('Risco confirmado', `<span class="bad">${num(t.confirmed.total)}</span>`, confText(t.confirmed)));
  s.push(card('Potenciais', String(num(t.potential.total)), `${num(t.potential.high)} alto, ${num(t.potential.medium)} médio (sem prova)`));
  s.push(card('Ameaças expostas', `<span class="bad">${num(t.threatsExposed)}</span>`, `de ${num(t.threats)} ameaça(s)`));
  s.push(card('Portão de CI', `${num(t.gateFail)} falham`, `de ${num(t.analyzed)} repositório(s)`));
  s.push(card('Perfis derivados', String(num(t.derivedProfiles)), 'rascunho do kit'));
  s.push('</div></section>');

  s.push('<section id="repos" aria-labelledby="t-repos"><h2 id="t-repos">Repositórios identificados</h2>');
  s.push(`<p>${h(NOTE_ROLES.replace(/`/g, ''))}</p>`);
  s.push(table('Papel identificado e situação de cada repositório', ['Repositório', 'Papel', 'Confiança', 'Por quê', 'Perfil', 'Portão', 'Nível', 'Automáticos', 'Risco confirmado', 'Expostas'],
    g.repos.map((r) => [`<strong>${h(r.name)}</strong>`, h(`${ROLE_PT[r.role] || r.role}${r.fullstack ? ' (full stack)' : ''}`), h(CONF_PT[r.confidence] || r.confidence), h((r.reasons || []).slice(0, 3).join('; ') || '-'), h(r.profile),
      h(r.error ? 'erro' : VERDICT_PT[r.verdict]), h(levelText(r)), h(r.automated && r.automated.passRatePct !== null ? pct(r.automated.passRatePct) : '-'), h(confText(r.confirmed)), r.threats ? String(num(r.threats.exposed)) : '-'])));
  s.push(`<div class="note"><p>${h(NOTE_DERIVED.replace(/`/g, ''))}</p></div></section>`);

  if (g.architecture && g.architecture.flows.length) s.push(`<section id="arquitetura" aria-labelledby="t-arq"><h2 id="t-arq">Arquitetura da aplicação</h2>${archSectionHtml(g.architecture).join('\n')}</section>`);

  s.push('<section id="riscos" aria-labelledby="t-riscos"><h2 id="t-riscos">Riscos de segurança confirmados</h2>');
  if (!g.risks.length) s.push('<p class="empty">Nenhum.</p>');
  else {
    s.push('<p>Em ordem decrescente de risco (probabilidade x impacto). Cada risco vem do repositório indicado.</p>');
    s.push(table('Riscos confirmados de todos os repositórios', ['Repositório', 'Classe', 'P x I', 'Controle', 'CWE', 'Pilares', 'Onde'],
      g.risks.slice(0, 40).map((i) => [h(i.repo), classBadge(i.class), `${num(i.likelihood)} x ${num(i.impact)} = ${num(i.score)}`, `<strong>${h(i.id)}</strong> ${h(i.title)}`, cweLinks(i.cwe), h(i.pillars.map((p) => R.PILLARS[p]).join(', ')), h((i.locations || []).join(', ') || '-')])));
    if (g.risks.length > 40) s.push(`<p class="empty">... e mais ${g.risks.length - 40}.</p>`);
  }
  s.push(table('Riscos e ameaças por repositório', ['Repositório', 'Confirmado', 'Potencial (alto)', 'Potencial (médio)', 'Ameaças', 'Expostas', 'Sem decisão'],
    g.repos.filter((x) => !x.error).map((r) => [h(r.name), String(num(r.confirmed.total)), String(num(r.potential.high)), String(num(r.potential.medium)), String(num(r.threats.threats)), String(num(r.threats.exposed)), String(num(r.threats.pending))]), [1, 2, 3, 4, 5, 6]));
  s.push('</section>');

  const withPersonal = g.repos.filter((r) => r.personalData);
  s.push('<section id="privacidade" aria-labelledby="t-priv"><h2 id="t-priv">Privacidade e dados pessoais</h2>');
  s.push(withPersonal.length
    ? `<p>Os repositórios com indício de dado pessoal (pelo nome dos campos ou pelo perfil declarado) são: ${h(withPersonal.map((r) => r.name).join(', '))}. Dados de crianças e adolescentes e dados sensíveis não podem ser inferidos do código: se a aplicação os trata, declare <code>minorsData</code> e <code>context.sensitiveData</code> no perfil, porque isso sobe o impacto dos riscos de confidencialidade.</p>`
    : '<p>Nenhum repositório mostrou indício de dado pessoal. Se a aplicação trata dados pessoais, declare <code>personalData</code> no perfil.</p>');
  s.push('</section>');
  if (g.warnings.length) s.push('<section id="avisos" aria-labelledby="t-avisos"><h2 id="t-avisos">Avisos</h2><ul>', ...g.warnings.map((w) => `<li>${h(w)}</li>`), '</ul></section>');
  s.push('<section id="limites" aria-labelledby="t-lim"><h2 id="t-lim">Limites</h2><ul>', ...LIMITS.map((x) => `<li>${h(x)}</li>`), '</ul></section>');
  if (g.legend) s.push(...legendHtml({ legend: g.legend }));

  const nav = [['resumo', 'Resumo'], ['repos', 'Repositórios'], ...(g.architecture ? [['arquitetura', 'Arquitetura']] : []), ['riscos', 'Riscos'], ['privacidade', 'Privacidade'], ['limites', 'Limites'], ...(g.legend ? [['legenda', 'Legenda']] : [])];
  return htmlShell({
    title: `Aplicação: ${g.name}`, eyebrow: 'Relatório LASTRO da aplicação',
    meta: [`Gerado em ${g.generatedAt.slice(0, 10)} | LASTRO ${g.tool.version}`, 'Somente verificações estáticas dos repositórios. Nenhuma requisição foi feita à aplicação.'],
    nav, sections: s, theme,
  });
}

module.exports = { formatGroupMarkdown, formatGroupHtml, staticLegend };
