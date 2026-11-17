---
name: lastro-corrigir
description: Aplica as correções previsíveis do LASTRO (Action por tag, workflow sem permissions, SECURITY.md ausente) numa branch nova, com teste verde. Use quando o pedido for corrigir, consertar ou "resolver o que der" dos achados do check.
---

# Correções previsíveis numa branch

## Passos

1. Rode `lastro fix` (só plano) e mostre ao usuário o que seria alterado e o que fica para uma pessoa.
2. Confirme três coisas antes de aplicar:
   - a árvore de trabalho está limpa (`git status`); se não, peça para commitar ou guardar antes;
   - pode consultar o github.com para achar o SHA das Actions (`--allow-network`);
   - pode rodar os testes do projeto (`--run-tests`), que executam o código do repositório.
3. Aplique: `lastro fix --write --allow-network --run-tests --pr-body <arquivo fora do repositório>`. Acrescente `--allow-network` e `--run-tests` só se o usuário aceitou.
4. Se os testes falharem, o kit desfaz tudo. Mostre o final da saída dos testes e ajude a entender.
5. Se passaram, mostre `git diff` e a mudança de estado de cada controle (antes e depois).
6. Para o commit e o PR, use a skill `lastro-pr`.

## Cuidados

- O SECURITY.md gerado é um modelo: o CORE-011 continua falhando até o usuário preencher os campos `LASTRO-PREENCHER`. Não preencha contato por conta própria.
- Uma Action que era fixada por BRANCH vira um SHA que fica velho: avise.
- Não "corrija" achado de outro controle editando à mão sem mostrar o diff ao usuário.
