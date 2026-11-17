# Modo corrigir (`lastro fix`)

O `lastro check` diz o que está errado. O `lastro fix` corrige o que tem correção **previsível** e entrega o resultado como uma branch pronta para virar PR, para um tech lead revisar. Quem decide abrir o PR, aprovar e fazer merge é sempre uma pessoa.

```bash
lastro fix                          # só mostra o plano; não muda nada
lastro fix --write --allow-network --run-tests --pr-body ../pr.md
```

## O que corrige hoje

| Controle | Correção | Observação |
|---|---|---|
| CORE-006 (Action por tag) | Troca `uses: dono/acao@v4` por `@<sha do commit> # v4` | Precisa de `--allow-network` (consulta o github.com com `git ls-remote`, só repositório público). Preserva aspas, comentário e fim de linha |
| CORE-010 (workflow sem `permissions`) | Acrescenta `permissions: contents: read` antes de `jobs:` | Não mexe em `write-all` nem em `pull_request_target`: isso vai para uma pessoa |
| CORE-011 (sem SECURITY.md) | Cria um modelo com campos `LASTRO-PREENCHER` | O CORE-011 **continua falhando** até alguém preencher o contato real. Modelo em branco não é canal de reporte |

Ainda não corrige, e diz isso no plano: imagem Docker sem digest, CODEOWNERS (precisa dos donos reais), dependência vulnerável, modelo de ameaças. Na dúvida, o kit não corrige e explica o motivo.

## O que ele nunca faz

- **Nunca mexe na branch atual.** Toda correção vai para uma branch nova `lastro/fix-AAAAMMDDHHMMSS` (ou o nome que você passar em `--branch`).
- **Nunca faz push e nunca abre PR.** O `--pr-body` só grava a descrição, e em um arquivo fora do repositório.
- **Nunca aplica sobre árvore suja.** O PR deve conter só as correções. Commite ou guarde o resto antes.
- **Nunca altera a configuração do git.** O autor do commit, se pedido, vai por `-c` só naquela chamada.
- **Nunca commita sem `--commit`**, que exige `--commit-name` e `--commit-email`. Sem ele, as mudanças ficam na árvore de trabalho da branch, para você ler com `git diff`.
- **Nunca troca rede por palpite.** Sem `--allow-network`, as Actions por tag ficam como pendência manual em vez de ganharem um SHA inventado.

## Teste verde antes do PR

`--run-tests` roda o `npm test` do projeto (ou o `--test-cmd` que você passar) **depois** de aplicar as correções:

- **Verde:** a branch fica, e o relatório registra "executados e verdes".
- **Vermelho:** as correções são desfeitas, a branch é apagada e o comando sai com código 1.
- **Sem `--run-tests`:** a branch é criada, mas o PR sai marcado como "testes não executados", para o revisor não confiar nisso.

Atenção: `--run-tests` **executa o código do repositório** (o script de teste dele). O resto do kit só lê. Use só em repositório em que você confia. O comando de teste nunca vem de dentro do repositório, só do `npm test` padrão ou da sua flag.

O teste do projeto **não exercita o CI**. Uma mudança em workflow só se prova rodando o pipeline do PR. A descrição do PR avisa isso ao revisor.

## O que o revisor recebe

A descrição gerada traz: o que mudou por controle e arquivo, por que (título, severidade e orientação do catálogo), como foi validado (testes e re-verificação antes e depois), o que pede atenção (o SHA é o da tag de hoje; jobs que escrevem precisam de permissão própria; campos a preencher), o que ficou para uma pessoa e um checklist, inclusive "quem aprova não é só quem gerou o PR".

## Fluxo de uso com o AppSec (planejado)

A ideia é que o time de segurança rode o kit num repositório e entregue ao time dono uma proposta pronta, em vez de uma lista de problemas:

1. O AppSec clona o repositório, roda `lastro check` e `lastro fix` (plano) para ver o que é corrigível.
2. Roda `lastro fix --write --allow-network --run-tests --commit ... --pr-body pr.md` numa cópia de trabalho.
3. Revisa o diff e a descrição, empurra a branch e abre o PR por conta própria, apontando o tech lead como revisor.
4. O tech lead revisa como qualquer PR. O pipeline do PR é o teste dos workflows.

O que ainda falta para esse fluxo ficar sem atrito: `lastro init` no mesmo comando para repositório sem perfil (hoje o `check` exige `.lastro/profile.json`), abrir o PR com a CLI do GitHub **depois** de uma confirmação sua, correções para mais controles e, no agente do Kiro (plano 5.4), a pergunta "posso abrir o PR?" antes de qualquer envio.

## Limites

- O SHA vem da tag **de hoje**. Se a tag já estava adulterada, o PR a congela. O revisor precisa conferir o commit.
- A correção é por texto, linha a linha. Workflows com `uses:` em formato incomum (por exemplo, em várias linhas) ficam como pendência.
- Só GitHub Actions e repositórios git.
