---
name: lastro-pr
description: Prepara o pull request das correções e testes de segurança do LASTRO para um revisor (tech lead), e entrega ao usuário os comandos de commit, push e PR. Use quando o pedido for abrir PR, mandar para revisão ou publicar as correções.
---

# Preparar o PR (quem publica é o usuário)

O agente não faz commit, push nem abre PR: as permissões do agente LASTRO negam esses comandos e um hook os bloqueia. Isso é de propósito. Você prepara tudo; o usuário confere e publica.

## Passos

1. Confirme que está numa branch própria (`lastro/...` ou outra que não seja a principal) e que a suíte de testes está verde.
2. Rode `lastro check` e anote o antes e o depois dos controles tratados.
3. Gere a descrição do PR. Se veio do `lastro fix`, ela já existe (`--pr-body`). Se houve testes novos, acrescente uma seção com cada teste e o controle que ele prova.
4. Mostre ao usuário, nesta ordem: o resumo do `git diff`, a descrição do PR e a lista do que ficou para uma pessoa.
5. Entregue os comandos, para ele rodar:
   - `git add <arquivos>` e `git commit -m "..."`;
   - `git push -u origin <branch>`;
   - `gh pr create --base <principal> --title "..." --body-file <descrição> --reviewer <tech lead>` (ou abrir pelo site).
6. Lembre o checklist do revisor: ler o diff inteiro, ver o pipeline do PR passar, preencher os campos a preencher, e quem aprova não ser só quem gerou.

## Cuidados

- Nunca inclua segredo, senha de conta de teste ou caminho pessoal na descrição.
- Se a descrição for para um repositório público, confira que não cita nome de cliente ou produto interno.
