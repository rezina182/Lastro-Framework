# LASTRO

**L**ifecycle, **A**I, **S**ecurity, **T**hreat models, **R**ules, **O**perations.

Um framework neutro de ciclo de vida seguro para desenvolvimento assistido por IA. Ele junta três coisas:

1. Um **catálogo de controles** (154 na v0.1) com origem rastreável em lições reais e em padrões como OWASP ASVS, NIST SSDF e guias da OpenSSF.
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

## Estado e planos

O que o kit faz hoje, onde ele é e onde ainda não é efetivo (com base em aplicações reais), como usar no dia a dia e os próximos passos: [docs/ESTADO-E-PLANOS.md](docs/ESTADO-E-PLANOS.md).

## Efetividade medida

`lastro bench` roda o kit contra um banco de falhas plantadas, com gêmeas limpas, e mostra quantas ele detecta, quantas viram pergunta e quantas perde. Hoje ele detecta 29 de 29 falhas de código, configuração e HTTP. Nas falhas de lógica, ele detecta as 4 que testa em execução com as sondas autenticadas e transforma em pergunta as 4 que só existem no código. Veja [docs/BENCH.md](docs/BENCH.md).

## Sondas autenticadas

`lastro check --url STAGING --auth --confirm-non-production` entra com duas contas de teste e prova acesso por objeto entre contas, CSRF e logout, e analisa o cookie do login. Só em staging ou local. Veja [docs/SONDAS-AUTENTICADAS.md](docs/SONDAS-AUTENTICADAS.md).

## Playbook dos testes manuais

`lastro playbook --out playbook.html` gera o roteiro passo a passo de cada controle manual que ainda não tem prova: o que preparar, os passos, o que conferir, a evidência, o que fazer se falhar e o trecho pronto da atestação. Veja [docs/PLAYBOOK.md](docs/PLAYBOOK.md).

## Aplicação com vários repositórios

`lastro app --name "App X" --root PASTA --out relatorio.html` identifica sozinho o papel de cada repositório da aplicação (frontend, backend, worker, infraestrutura...), verifica todos (só leitura) e gera um relatório único com a arquitetura e os riscos. Veja [docs/APLICACAO.md](docs/APLICACAO.md).

## Legenda

Os relatórios trazem uma legenda no final (o que é `CORE`, `AUTH`, estados, classes de risco, pilares, STRIDE e siglas), e cada CWE, CVE e GHSA leva à fonte oficial. A mesma legenda está em [docs/GLOSSARIO.md](docs/GLOSSARIO.md).

## Uso com o Kiro e por assunto

`lastro scope auth` mostra só os controles de um assunto, e `lastro adapter kiro --write` leva as regras do kit para o steering do Kiro do projeto. Veja [docs/KIRO.md](docs/KIRO.md).

## Maturidade

Todo relatório traz um nível de 0 a 4 e a divisão entre o que foi provado por máquina, o que é autodeclarado, o que falha e o que está sem prova. A pontuação mede evidência, não segurança: veja [docs/SCORE.md](docs/SCORE.md).

## Risco

O relatório abre com a análise de risco: separa **risco de segurança**, **boa prática** e **qualidade**, e para o risco de segurança mostra probabilidade x impacto, classe, pilares da segurança da informação, CWE, requisitos do ASVS e o que toca privacidade e LGPD. O que ninguém provou aparece como "potencial" e nunca passa de "Alto". Veja [docs/RISCO.md](docs/RISCO.md).

## Modelo de ameaças

`lastro threat-model` gera um rascunho (STRIDE por superfície) a partir do perfil, do catálogo e da leitura do código, com pistas como rotas sem autenticação vista e indícios de dado sensível, e desenha o fluxo de dados com as fronteiras de confiança e os controles exigidos em cada fluxo. A pessoa decide cada ameaça e registra a revisão; só então o CORE-012 passa. Veja [docs/THREAT-MODEL-ASSISTIDO.md](docs/THREAT-MODEL-ASSISTIDO.md).

## Uso rápido

Requer Node 22 ou superior. Nenhuma dependência para instalar.

```bash
# dentro do projeto que você quer verificar
node /caminho/para/lastro/verifier/bin/lastro.js init
# edite .lastro/profile.json para descrever a aplicação (flags)

node /caminho/para/lastro/verifier/bin/lastro.js check
node /caminho/para/lastro/verifier/bin/lastro.js check --url https://sua-app.exemplo   # inclui verificações HTTP passivas
node /caminho/para/lastro/verifier/bin/lastro.js backlog --write                        # gera tickets P0 a P3
node /caminho/para/lastro/verifier/bin/lastro.js threat-model --write                    # rascunho do modelo de ameaças em .lastro/threat-model.json
node /caminho/para/lastro/verifier/bin/lastro.js asvs --level 2 --state                 # cobertura do ASVS 5.0 por capítulo
node /caminho/para/lastro/verifier/bin/lastro.js report --out relatorio.md              # relatório legível, com nível de maturidade
node /caminho/para/lastro/verifier/bin/lastro.js report --out relatorio.html            # o mesmo em HTML autocontido (sem scripts nem recursos externos)
node /caminho/para/lastro/verifier/bin/lastro.js report --out relatorio.html --theme meu-tema.css   # com a sua identidade visual
npm audit --json > audit.json   # você roda: envia a lista de pacotes ao registro do npm
node /caminho/para/lastro/verifier/bin/lastro.js report --out relatorio.html --audit-file audit.json   # inclui dependências vulneráveis (GHSA, CWE, CVSS)
```

Códigos de saída: `0` aprovado, `1` falha, `2` incompleto, `3` erro de uso ou configuração.

### Verificações que tocam a aplicação

O kit separa três tipos de verificação, do mais seguro ao mais arriscado:

| Tipo | O que faz | Quando roda |
|------|-----------|-------------|
| Estática | Lê o código e os arquivos do projeto | Sempre. Não toca na aplicação. |
| Passiva | Requisições GET comuns (cerca de 30), como um navegador | Só com `--url`. Intervalo mínimo de 150 ms e teto de 120 requisições. |
| Ativa | TRACE, OPTIONS com Origin falsa, JSON malformado | Só com `--active --confirm-non-production`. |

Regras de segurança do verificador:
- Prefira **staging ou homologação** para qualquer verificação HTTP. Antes de cada uma, o CLI imprime um aviso.
- As sondas ativas **nunca rodam sem confirmação** e são recusadas contra a URL de `urls.production` do perfil.
- Nada disso é automático: o CI do próprio kit só roda verificações estáticas.
- Passado o teto de requisições, as sondas viram "não verificado". O verificador não tenta mais, e nunca conta como aprovado.

## O que está no repositório

| Pasta | Conteúdo |
|-------|----------|
| `catalog/` | Pacotes, lições e controles em JSON |
| `fixtures/planted/` | Banco de falhas plantadas do `lastro bench` (código vulnerável de propósito, nunca use como modelo) |
| `verifier/` | Verificador, CLI e testes |
| `docs/` | Princípios, adoção, perfil, modelo de ameaças, registro de pesquisa, roadmap |
| `.kiro/steering/` | Regras do próprio projeto para o Kiro |
| `.lastro/` | Perfil e estado do LASTRO aplicado a si mesmo |

Mais detalhes em [ARCHITECTURE.md](ARCHITECTURE.md), [docs/PRINCIPLES.md](docs/PRINCIPLES.md) e [docs/ADOPTION.md](docs/ADOPTION.md).

## Limites conhecidos

- As verificações de código são varreduras por padrão de texto (heurísticas). Elas encontram o comum e não substituem revisão nem análise estática completa.
- A v0.1 lê workflows do GitHub Actions. Outros CIs ficam como `unverified` até haver atestação.
- Referências a padrões citam apenas IDs e links. Conferência automática dos IDs contra as fontes oficiais está no [roadmap](docs/ROADMAP.md).
- Cobertura do ASVS (até L2, 253 requisitos): todos (253, 100%) têm controle, 237 (94%) estão classificados como cobertos por inteiro e 16 como parciais. Os 17 capítulos estão classificados até L2; os 92 requisitos exclusivos do L3 ainda não são meta do kit. Quase tudo que é "inteiro" é controle manual: o kit entrega o roteiro de teste e o registro com validade, não uma sonda automática. A classificação foi feita pelo autor do kit e passou por uma revisão independente por agente (que achou exageros, corrigidos); falta ainda revisão humana. `lastro asvs` mostra o número atual por capítulo; ele mede o progresso do kit, não a conformidade de uma aplicação.
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
