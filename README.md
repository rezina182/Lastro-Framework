# LASTRO

**L**ifecycle, **A**I, **S**ecurity, **T**hreat models, **R**ules, **O**perations.

Um framework neutro de ciclo de vida seguro para desenvolvimento assistido por IA. Ele junta três coisas:

1. Um **catálogo de controles** (80 na v0.1) com origem rastreável em lições reais e em padrões como OWASP ASVS, NIST SSDF e guias da OpenSSF.
2. Um **verificador sem dependências** (Node) que checa o repositório e, opcionalmente, a aplicação em execução, e dá um veredito.
3. Um **processo**: modelo de ameaças, adoção em aplicações existentes (análise de lacunas, backlog P0 a P3) e registro de risco aceito com dono e validade.

Status: v0.1.0, pré-lançamento. Documentação em português do Brasil por enquanto.

## Ideia central

O que obriga fica fora do modelo. Instruções em texto orientam o agente, mas quem garante é verificação determinística: hooks, CI e prova.

Por isso o verificador segue regras simples:

- **Desconhecido não é aprovado.** Sem prova, o controle fica `unverified`.
- **Falha fechado.** Erro dentro de uma verificação nunca vira "passou".
- **Autodeclaração não verifica controle automático.** Controles manuais exigem atestação com responsável e validade de até 366 dias.
- **O portão bloqueia só achados novos de severidade alta ou crítica.** A dívida antiga fica no baseline e vira ticket.
- **Risco aceito exige dono, aprovador, justificativa e validade.** Vencido, volta a ser achado.

## Uso rápido

Requer Node 22 ou superior. Nenhuma dependência para instalar.

```bash
# dentro do projeto que você quer verificar
node /caminho/para/lastro/verifier/bin/lastro.js init
# edite .lastro/profile.json para descrever a aplicação (flags)

node /caminho/para/lastro/verifier/bin/lastro.js check
node /caminho/para/lastro/verifier/bin/lastro.js check --url https://sua-app.exemplo   # inclui verificações HTTP passivas
node /caminho/para/lastro/verifier/bin/lastro.js backlog --write                        # gera tickets P0 a P3
node /caminho/para/lastro/verifier/bin/lastro.js asvs --level 2 --state                 # cobertura do ASVS 5.0 por capítulo
```

Códigos de saída: `0` aprovado, `1` falha, `2` incompleto, `3` erro de uso ou configuração.

Use `--url` e `--active` apenas em aplicações suas ou com autorização. As sondas ativas (TRACE, OPTIONS com Origin falsa, JSON malformado) ficam desligadas por padrão.

## O que está no repositório

| Pasta | Conteúdo |
|-------|----------|
| `catalog/` | Pacotes, lições e controles em JSON |
| `verifier/` | Verificador, CLI e testes |
| `docs/` | Princípios, adoção, perfil, modelo de ameaças, registro de pesquisa, roadmap |
| `.kiro/steering/` | Regras do próprio projeto para o Kiro |
| `.lastro/` | Perfil e estado do LASTRO aplicado a si mesmo |

Mais detalhes em [ARCHITECTURE.md](ARCHITECTURE.md), [docs/PRINCIPLES.md](docs/PRINCIPLES.md) e [docs/ADOPTION.md](docs/ADOPTION.md).

## Limites conhecidos

- As verificações de código são varreduras por padrão de texto (heurísticas). Elas encontram o comum e não substituem revisão nem análise estática completa.
- A v0.1 lê workflows do GitHub Actions. Outros CIs ficam como `unverified` até haver atestação.
- Referências a padrões citam apenas IDs e links. Conferência automática dos IDs contra as fontes oficiais está no [roadmap](docs/ROADMAP.md).
- Cobertura do ASVS (até L2, 253 requisitos): 128 (51%) são citados por algum controle, 102 (40%) estão classificados como cobertos por inteiro e 15 como parciais. Sete capítulos já foram classificados (V3, V5, V6, V7, V8, V13 e V16); nos demais, a referência existe mas ainda não foi avaliada. Quase tudo que é "inteiro" é controle manual: o kit entrega o roteiro de teste e o registro com validade, não uma sonda automática. A classificação foi feita pelo autor do kit e passou por uma revisão independente por agente (que achou exageros, corrigidos); falta ainda revisão humana. `lastro asvs` mostra o número atual por capítulo; ele mede o progresso do kit, não a conformidade de uma aplicação.
- Alinhado a padrões não é o mesmo que em conformidade com eles. O LASTRO não certifica nada.

## Testes

```bash
npm test
npm run catalog:validate
npm run check
```

## Licença

- Código: [Apache-2.0](LICENSE).
- Documentação: CC BY 4.0, conforme o arquivo [NOTICE](NOTICE).

Copyright 2026 Renato do Nascimento Junior.
