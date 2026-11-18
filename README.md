# LASTRO

**Segurança com prova para quem desenvolve com IA.**

O LASTRO é um kit que acompanha a aplicação do primeiro requisito até a produção e responde, com evidência, a uma pergunta simples: **o que já está provado que é seguro, o que falha e o que ninguém conferiu?**

Ele não pede que você confie no código gerado pela IA, nem no próprio LASTRO. Tudo que ele afirma vem de uma prova: uma verificação da máquina que roda a cada execução, ou o teste de uma pessoa, registrado com nome e prazo de validade. O que não tem prova aparece como "sem prova", nunca como aprovado.

> Status: v0.1.0, pré-lançamento. Documentação em português do Brasil. A página de apresentação está em [docs/index.html](docs/index.html).

## Por que existe

Com IA, o código sai mais rápido do que a revisão consegue acompanhar. O agente escreve a rota, o login e a consulta ao banco, e os erros de sempre voltam: TLS desligado, SQL montado com texto, senha fixa no código, cookie sem proteção, ação do CI que qualquer um pode trocar. Instrução em texto ("não faça isso") ajuda, mas não garante nada.

O LASTRO parte de uma regra: **o que obriga fica fora do modelo**. A IA é orientada por regras e skills, e quem garante é verificação determinística: hooks no editor, o portão no CI e a prova registrada.

## O que ele faz

| Passo | O que acontece | Comando |
|---|---|---|
| 1. Entende a aplicação | Lê o código e monta o perfil: tem login? upload? dado pessoal? tempo real? Cada resposta decide quais controles valem | `lastro init` |
| 2. Mede | Roda as verificações no repositório e, se você quiser, na aplicação rodando em local ou staging | `lastro check` |
| 3. Explica | Dá uma nota de 0 a 10, diz por que ela está assim e qual é o próximo passo | `lastro gaps` |
| 4. Mostra | Gera um portal estático com os números, as decisões para agora e o detalhe de cada controle | `lastro site` |
| 5. Corrige e prova | Prepara a correção previsível numa branch, transforma testes manuais em roteiro e registra quem testou | `lastro fix`, `lastro playbook` |

## Em números

| | |
|---|---|
| Controles no catálogo | 162, em 8 escopos (base, web, autenticação, dados pessoais, tempo real, upload, ativos de mídia, agente de código) |
| Verificações automáticas | 41 |
| Lições de origem | 48, de três aplicações reais e de pesquisa: cada controle diz de onde veio |
| Requisitos do ASVS 5.0 | os 345 estão mapeados; os 253 até o nível 2 têm controle no catálogo |
| Falhas plantadas detectadas no banco de testes | 33 de 37, sem nenhum falso positivo nas aplicações limpas |
| Dependências para instalar | 0 (só Node 22 ou mais novo) |
| Peças para a IA | 1 agente, 5 skills, 7 arquivos de steering e 3 hooks |

## Começar em cinco minutos

Requer Node 22 ou mais novo. Nada para instalar.

```bash
# dentro do projeto que você quer verificar
node /caminho/para/lastro/verifier/bin/lastro.js init     # perfil derivado do código; revise e responda às perguntas
node /caminho/para/lastro/verifier/bin/lastro.js check    # o veredito e a nota de 0 a 10
node /caminho/para/lastro/verifier/bin/lastro.js gaps     # por que a nota está assim e como provar cada controle
node /caminho/para/lastro/verifier/bin/lastro.js site --out ../portal   # o portal, para abrir no navegador
```

Códigos de saída do `check`: `0` aprovado, `1` falha, `2` incompleto, `3` erro de uso ou configuração. No CI, o portão bloqueia só achado **novo** de gravidade alta ou crítica; a dívida antiga vira ticket.

## Com IA: agente, skills, steering e hooks

O LASTRO funciona com qualquer ferramenta. Para o [Kiro](https://kiro.dev), o adaptador instala tudo de uma vez:

```bash
node /caminho/para/lastro/verifier/bin/lastro.js adapter kiro            # mostra o que seria criado
node /caminho/para/lastro/verifier/bin/lastro.js adapter kiro --write    # cria em .kiro/ (nunca sobrescreve)
```

Depois, escolha o agente **lastro** no seletor de agentes do chat.

| Peça | Quantas | Para que serve |
|---|---|---|
| Agente `lastro` | 1 | Pergunta se a aplicação é nova ou existente. Na nova, entrega requisitos, ameaças e testes **antes** do código. Na existente, mede, corrige, prova e prepara o PR. Não pode fazer commit, push nem abrir PR |
| Skills | 5 | `lastro-requisitos` (antes de uma funcionalidade nova), `lastro-triagem` (ler o resultado e montar o plano), `lastro-corrigir` (correção numa branch), `lastro-testes` (teste manual vira teste automático), `lastro-pr` (descrição do PR para o revisor) |
| Steering | 7 | As regras que valem sempre (rodar o `check` antes de terminar, nunca atestar nem aceitar risco sozinho, não desligar TLS) e as de cada assunto, carregadas quando o arquivo aberto é de autenticação, dados, web, upload ou tempo real, mais a condução da revisão de ameaças |
| Hooks | 3 | `lastro-protect` pede confirmação antes de mexer nas decisões em `.lastro/`; `lastro-publish` **bloqueia** push, PR e publicação vindos do agente; `lastro-stop` roda o `check` quando o agente termina e pede para tratar achado novo grave |

O agente prepara; quem decide e publica é você. Detalhes em [docs/KIRO.md](docs/KIRO.md).

## O portal

`lastro site --out ../portal` gera oito páginas HTML, sem script e sem servidor:

- **Visão geral:** os números grandes (nota, portão, o que bloqueia, quanto está provado, quanto falta) e as **decisões para agora**, cada uma com quem decide e o link para o detalhe.
- **Análise completa:** sumário executivo, nota por escopo e por fase, evolução, os controles que exigem ação e por que importam.
- **Mapa da aplicação:** para quem é de produto ou de negócio. Quem usa a aplicação, por quais áreas entra, o que cada área faz e que dados toca, desenhado a partir do código. Mostra também, para cada dado, as áreas que o usam: é o que uma funcionalidade nova pode afetar.
- **Implementado por escopo, Decisões, Playbook, Relatório e Histórico.**

Para compartilhar fora do time, `--redact "Empresa,Produto"` troca os nomes por `[omitido]`. Veja [docs/PORTAL.md](docs/PORTAL.md).

## Como ele aprende

Cada aplicação que passa pelo LASTRO deixa lições. O que a aplicação errou, o que o kit errou e o que o ambiente impediu de testar viram lições no catálogo, ligadas aos controles que elas justificam, e, quando dá, viram verificação automática com teste. Foi assim que nasceram, por exemplo, a verificação de senha fixa nas contas criadas e a calibragem do CSRF pelo `SameSite` do cookie. O ciclo está em [CONTRIBUTING.md](CONTRIBUTING.md).

## Regras que não mudam

- **Sem prova não é aprovado.** Controle sem evidência fica "sem prova" e conta zero na nota.
- **Erro vira "sem prova", nunca "passou".**
- **Teste manual exige atestação** com responsável e validade de até 366 dias. Vencida, volta a ser "sem prova".
- **Risco aceito exige dono, aprovador, justificativa e validade.**
- **Decisão é de uma pessoa.** O agente propõe a atestação, o risco aceito ou a decisão de ameaça; uma pessoa confirma.
- **Sondas na aplicação só em local ou staging.** As ativas e as autenticadas pedem confirmação explícita (`--confirm-non-production`), e as duas são recusadas contra a URL de produção do perfil.

## Tudo que o kit faz

| Assunto | Comando | Documento |
|---|---|---|
| Nota de 0 a 10 e por que ela está assim | `lastro check`, `lastro gaps` | [SCORE.md](docs/SCORE.md) |
| Sondas HTTP passivas, ativas e autenticadas (duas contas de teste) | `lastro check --url ... [--active] [--auth]` | [SONDAS-AUTENTICADAS.md](docs/SONDAS-AUTENTICADAS.md) |
| Análise de risco (probabilidade x impacto, pilares, CWE, LGPD) | `lastro report` | [RISCO.md](docs/RISCO.md) |
| Modelo de ameaças assistido (STRIDE e fluxo de dados) | `lastro threat-model` | [THREAT-MODEL-ASSISTIDO.md](docs/THREAT-MODEL-ASSISTIDO.md) |
| Roteiro dos testes manuais | `lastro playbook` | [PLAYBOOK.md](docs/PLAYBOOK.md) |
| Correção previsível numa branch | `lastro fix` | [CORRIGIR.md](docs/CORRIGIR.md) |
| Portal e histórico | `lastro site`, `lastro history` | [PORTAL.md](docs/PORTAL.md) |
| Aplicação com vários repositórios | `lastro app` | [APLICACAO.md](docs/APLICACAO.md) |
| Cobertura do ASVS 5.0 | `lastro asvs` | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Controles de um assunto | `lastro scope auth` | [KIRO.md](docs/KIRO.md) |
| Tickets P0 a P3 e dívida conhecida | `lastro backlog`, `lastro baseline` | [ADOPTION.md](docs/ADOPTION.md) |
| Medir o próprio kit | `lastro bench` | [BENCH.md](docs/BENCH.md) |

O estado atual, o que os testes em aplicações reais mostraram e os próximos passos estão em [docs/ESTADO-E-PLANOS.md](docs/ESTADO-E-PLANOS.md). Siglas e estados estão no [glossário](docs/GLOSSARIO.md).

## Limites

- As verificações de código são varreduras por padrão de texto. Elas acham o comum e não substituem revisão nem análise estática completa.
- A v0.1 lê workflows do GitHub Actions. Outros CIs ficam "sem prova" até alguém atestar.
- A maior parte do catálogo ainda é teste manual: o kit entrega o roteiro, a prova parcial da máquina quando consegue e o registro com validade.
- Alinhado ao ASVS, ao NIST SSDF e aos guias da OpenSSF não é o mesmo que em conformidade com eles. O LASTRO não certifica nada. A nota mede evidência, não segurança.

## O que está no repositório

| Pasta | Conteúdo |
|---|---|
| `catalog/` | Escopos, lições, controles e os mapas de risco e do ASVS, em JSON |
| `verifier/` | O verificador, a linha de comando e os testes |
| `adapters/kiro/` | Agente, skills, steering e hooks que o `lastro adapter kiro` instala |
| `fixtures/planted/` | Falhas plantadas do `lastro bench` (código vulnerável de propósito; nunca use como modelo) |
| `docs/` | Documentação e a página de apresentação (`docs/index.html`) |
| `.lastro/` | O LASTRO aplicado a ele mesmo |

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
