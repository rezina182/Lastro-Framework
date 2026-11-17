---
name: lastro-triagem
description: Lê o resultado do lastro check e monta um plano em ordem de prioridade (o que bloqueia, o que é dívida, o que só falta provar). Use quando o pedido for verificar, auditar, avaliar a segurança ou "o que falta" num projeto existente.
---

# Triagem do resultado do check

## Passos

1. Rode `lastro check --json --out` para um arquivo fora do repositório e leia o resultado (ou `lastro check` se o usuário preferir o texto).
2. Separe em quatro grupos e mostre nesta ordem:
   - **Bloqueia o portão:** achado novo, alto ou crítico (`blocking: true`). Mostre a causa e a correção do catálogo.
   - **Tem correção previsível:** CORE-006, CORE-010 e CORE-011 falhando. Ofereça a skill `lastro-corrigir`.
   - **Falha que exige código:** outros controles `failed`. Indique o arquivo e a linha do achado.
   - **Sem prova:** controles manuais. Ofereça a skill `lastro-testes` para os que viram teste e `lastro playbook` para os demais.
3. Se o projeto já tem dívida e o usuário quer que o portão bloqueie só o novo, explique o `lastro baseline --write` e **peça confirmação** antes (é decisão de uma pessoa; um hook pede a confirmação).
4. Ofereça `lastro backlog --write` para virar tickets P0 a P3.

## Cuidados

- Achado em arquivo de teste tem gravidade limitada a baixa: não trate como urgente.
- Um achado heurístico (SQL por interpolação de fragmento, por exemplo) pode ser falso positivo. Leia o código antes de corrigir; se for legítimo, proponha `lastro-ignore` com justificativa, não uma "correção".
- Não diga que o projeto é seguro porque o check passou: o kit mede evidência.
