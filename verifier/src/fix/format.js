'use strict';

// Saída do lastro fix: o plano no terminal e a descrição do PR para quem vai revisar (tech lead).

const STATE = { verified: 'verificado', failed: 'falhando', unverified: 'sem prova', not_applicable: 'não se aplica', ausente: 'ausente' };
const TESTS = {
  passed: (t) => `executados (\`${t.command}\`) e **verdes**`,
  failed: (t) => `\`${t.command}\` **falhou**: as correções foram desfeitas`,
  'not-run': () => '**não executados**. Rode a suíte do projeto nesta branch antes de pedir aprovação',
  'no-command': () => '**sem comando de teste** (o projeto não tem script "test" e nenhum --test-cmd foi informado)',
};

function formatPlan(r) {
  const L = [];
  const { edits, manual } = r.plan;
  L.push(edits.length ? `${edits.length} arquivo(s) seriam alterados:` : 'Nenhuma correção automática se aplica agora.');
  for (const e of edits) {
    L.push(`  ${e.kind === 'create' ? 'criar' : 'alterar'} ${e.file}  [${e.controls.join(', ')}]`);
    for (const s of e.summary) L.push(`    - [${s.control}] ${s.text}`);
  }
  if (manual.length) {
    L.push('', 'Fica para uma pessoa (sem correção determinística):');
    for (const m of manual) L.push(`  [${m.control}] ${m.file}: ${m.reason}`);
  }
  return L.join('\n');
}

function formatResult(r) {
  const L = [formatPlan(r)];
  if (r.rolledBack) L.push('', `Os testes falharam (${r.tests.command}). As correções foram desfeitas e a branch removida.`, r.tests.tail);
  else if (r.applied) {
    L.push('', `Branch criada: ${r.branch} (base: ${r.base}). Nada foi enviado ao GitHub.`);
    L.push(`Testes: ${TESTS[r.tests.status](r.tests)}.`);
    for (const id of Object.keys(r.statesAfter)) L.push(`  ${id}: ${STATE[r.statesBefore[id]]} → ${STATE[r.statesAfter[id]]}`);
    L.push(r.commit ? `Commit ${r.commit} na branch ${r.branch}.` : 'As mudanças estão na árvore de trabalho da branch, sem commit. Revise com "git diff".');
  } else if (r.plan.edits.length) L.push('', 'Plano apenas: nada foi alterado. Rode com --write para criar a branch e aplicar.');
  return L.join('\n');
}

/** Descrição de PR para o revisor. É um rascunho: quem abre o PR é uma pessoa. */
function formatPrBody(r, now = new Date()) {
  const L = ['# Correções de segurança propostas pelo LASTRO', ''];
  L.push(`Gerado em ${now.toISOString().slice(0, 10)}. Branch \`${r.branch || '(plano, sem branch)'}\`, base \`${r.base || '-'}\`.`, '');
  L.push('> Este PR foi preparado por uma ferramenta e **exige revisão humana**. O LASTRO não aprova, não faz merge e não envia nada sozinho.', '');
  L.push('## O que muda', '', '| Controle | Arquivo | Mudança |', '|---|---|---|');
  for (const e of r.plan.edits) for (const s of e.summary) L.push(`| ${s.control} | \`${e.file}\` | ${s.text.replace(/\|/g, '\\|')} |`);
  L.push('', '## Por que', '');
  const ids = [...new Set(r.plan.edits.flatMap((e) => e.controls))];
  for (const id of ids) {
    const c = r.before.controls.find((x) => x.id === id);
    if (c) L.push(`- **${id}** (${c.severity}): ${c.title}. ${c.remediation || ''}`.trim());
  }
  L.push('', '## Como foi validado', '');
  L.push(`- Testes do projeto: ${TESTS[r.tests.status](r.tests)}.`);
  for (const id of Object.keys(r.statesAfter)) L.push(`- Re-verificação do ${id}: ${STATE[r.statesBefore[id]]} → ${STATE[r.statesAfter[id]]}.`);
  L.push('- O teste do projeto **não exercita o CI**: as mudanças em workflows só se provam rodando o pipeline neste PR.', '');
  L.push('## Atenção do revisor', '');
  if (r.plan.edits.some((e) => e.controls.includes('CORE-006'))) L.push('- **SHA de Action:** o SHA é o que a tag apontava ao gerar o PR. Confira, no repositório da Action, que o commit é o esperado. Fixar por SHA protege de mudanças futuras da tag, não de uma tag já adulterada.');
  if (r.plan.edits.some((e) => e.controls.includes('CORE-010'))) L.push('- **permissions:** o padrão passa a ser somente leitura. Se algum job escreve (release, comentário em PR, publicação), declare a permissão nele. Veja o resultado do pipeline deste PR.');
  if (r.plan.edits.some((e) => e.controls.includes('CORE-011'))) L.push('- **SECURITY.md:** é um modelo. Preencha cada campo `LASTRO-PREENCHER` com o contato real. O LASTRO continua reprovando o CORE-011 enquanto o marcador existir.');
  L.push('', '## Fora do escopo (precisa de uma pessoa)', '');
  if (r.plan.manual.length) for (const m of r.plan.manual) L.push(`- [${m.control}] \`${m.file}\`: ${m.reason}`);
  else L.push('- Nenhuma pendência conhecida para os controles tratados.');
  L.push('', '## Checklist do revisor', '', '- [ ] Li o diff inteiro, inclusive o que parece mecânico', '- [ ] O pipeline deste PR passou', '- [ ] Os campos a preencher foram preenchidos', '- [ ] Quem aprova não é só quem gerou o PR', '');
  return L.join('\n');
}

module.exports = { formatPlan, formatResult, formatPrBody };
