---
inclusion: auto
name: lastro-revisao-ameacas
description: Conduz a revisão do modelo de ameaças do LASTRO com o usuário, ameaça por ameaça, e registra as decisões em .lastro/threat-model.json. Use quando o pedido for revisar, criar, atualizar ou fechar o modelo de ameaças.
---

# Revisão do modelo de ameaças

O modelo de ameaças depende do que só o usuário sabe. Seu papel é organizar a conversa, não decidir por ele.

## Passos

1. Rode `lastro threat-model` e leia o resumo. Se não existir `.lastro/threat-model.json`, rode `lastro threat-model --write` para criar o rascunho (peça permissão antes de gravar).
2. Mostre ao usuário, em linguagem simples: os ativos, o que o kit descobriu no código e as pistas (rotas sem autenticação vista, indício de dado sensível). Lembre que "autenticação não vista" não quer dizer desprotegida.
3. Confirme os **ativos**: falta algum? Algum não existe? Há dado sensível ou de menores?
4. Percorra as ameaças **expostas primeiro** (há controle falhando), depois as sem prova. Para cada uma, faça a pergunta do STRIDE e ouça a resposta. Proponha uma decisão e peça confirmação:
   - `mitigate`: vamos corrigir. Opcional: `likelihood` de 1 a 4 (1 rara, 2 possível, 3 provável, 4 quase certa).
   - `accept`: aceitamos o risco. Exige `rationale` (pelo menos 20 caracteres), `owner` e `expires`.
   - `not_applicable`: a ameaça não existe aqui. Exige `rationale`.
5. Registre só o que o usuário confirmou, editando `.lastro/threat-model.json`. Nunca preencha `reviewedBy` e `reviewedAt` por ele: peça o nome de quem revisou e a data.
6. Rode `lastro check --only CORE-012` e relate o resultado. Depois `lastro backlog` mostra os tickets das ameaças marcadas para mitigar.

## Cuidados

- Não aceite risco em nome do usuário. Se ele hesitar, deixe a ameaça pendente.
- Não invente probabilidade. Sem resposta, não preencha `likelihood`.
- A revisão vence em 180 dias, ou quando a superfície mudar (nova rota pública, novo armazenamento, novo upload).
