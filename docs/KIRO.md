# Uso com o Kiro

O LASTRO é independente de ferramenta. O adaptador do Kiro leva o kit para onde o agente trabalha: um **agente** dedicado, **skills** por tarefa, **steering** com as regras e **hooks** que garantem o que não pode depender do modelo obedecer.

```bash
lastro adapter kiro            # mostra o que seria criado
lastro adapter kiro --write    # cria em .kiro/ do projeto (nunca sobrescreve um arquivo existente)
```

Depois, escolha o agente **lastro** no seletor de agentes do chat (canto inferior da caixa de mensagem).

## O agente `lastro`

`.kiro/agents/lastro.md`. Começa perguntando se a aplicação é nova ou existente e conduz o ciclo:

| Aplicação nova | Aplicação existente |
|---|---|
| Para cada funcionalidade (login, upload, API...), a skill `lastro-requisitos` entrega requisitos, decisões de arquitetura, ameaças e os testes que provam cada requisito, **antes** do código | `lastro check` e triagem, correção previsível numa branch, testes automatizados a partir do playbook, revisão do modelo de ameaças e preparo do PR |

Ele carrega o steering e as skills do projeto (`resources`) e para nos pontos de decisão humana: gravar atestação, risco aceito, decisão de ameaça e baseline; rodar sondas HTTP; rodar testes de repositório de terceiros; e publicar. As permissões do agente **negam** `git commit`, `git push`, `gh pr create` e `gh pr merge`: ele prepara, você publica.

## Skills

Ficam em `.kiro/skills/<nome>/SKILL.md`. O Kiro carrega cada uma quando o pedido combina com a descrição, ou quando você digita `/nome`.

| Skill | Quando |
|---|---|
| `lastro-requisitos` | Antes de escrever uma funcionalidade nova: requisitos do escopo (`lastro scope`), decisões de arquitetura, ameaças e testes |
| `lastro-triagem` | Ler o `lastro check` e montar o plano: o que bloqueia, o que tem correção previsível, o que exige código, o que falta provar |
| `lastro-corrigir` | `lastro fix` numa branch nova, com confirmação de rede e de testes |
| `lastro-testes` | Transformar controles manuais (acesso por objeto, CSRF, logout, cookies) em testes no projeto, conferindo que o teste falha sem o controle |
| `lastro-pr` | Preparar a descrição do PR para o tech lead e entregar ao usuário os comandos de commit, push e PR |

## Steering

| Arquivo | Quando o Kiro o carrega | O que faz |
|---|---|---|
| `lastro-base.md` | sempre | Regras do agente: rodar `lastro check` antes de terminar, nunca atestar nem aceitar risco nem decidir ameaça por conta própria, não desligar TLS, não montar SQL por concatenação, não instalar dependência sem conferir, não commitar sem autorização |
| `lastro-escopo-auth.md` | ao ler arquivo com `auth` no caminho | Autenticação, sessão e autorização |
| `lastro-escopo-dados.md` | ao ler arquivo `.sql` | Consulta parametrizada, dado pessoal e sensível, hash de senha, migração com backup |
| `lastro-escopo-web.md`, `-upload.md`, `-tempo-real.md` | arquivos com `route`, `upload` ou `socket` no caminho | Os pontos de cada superfície |
| `lastro-revisao-ameacas.md` | quando o pedido combina com a descrição | Conduz a revisão do modelo de ameaças, ameaça por ameaça |

## Hooks

| Hook | Gatilho | O que faz |
|---|---|---|
| `lastro-protect` | antes de escrita e de terminal | Pede confirmação antes de mexer em `.lastro/status.json`, `.lastro/risks/`, `.lastro/threat-model.json`, `.lastro/baseline.json`, `.lastro/system.json` ou `lastro baseline --write` |
| `lastro-publish` | antes de comando de terminal | **Bloqueia** (saída 2) `git push`, `gh pr create/merge/review/ready`, `gh release create`, `gh api` de PR, merge ou release, e `npm publish` vindos do agente. `git stash push` e `gh pr view` passam |
| `lastro-stop` | quando o agente termina | Roda `lastro check` (só leitura, sem rede). Com achado novo alto ou crítico, pede ao agente para continuar e tratar o achado, **uma vez por sessão**, para não entrar em ciclo |

Os três usam só Node, sem rede. O `lastro-stop` acha o kit pela variável `LASTRO_CLI` (caminho do `verifier/bin/lastro.js`) ou pelo pacote instalado no projeto. O caminho nunca é gravado no repositório, para não expor a pasta pessoal de ninguém. Sem kit, sem perfil ou com erro, ele não faz nada.

## Limites do formato do Kiro (conferidos na documentação em 2026-11-17)

- **"Perguntar" por hook não é documentado no IDE.** A resposta `permissionDecision: "ask"` do `lastro-protect` está documentada só na CLI do Kiro (3.4 ou mais nova). No IDE, ela pode ser ignorada. Por isso a regra também está no steering e o CI é a trava de verdade. Já o `lastro-publish` usa a saída 2, que **bloqueia** no IDE e na CLI.
- **Agente com `hooks` é ignorado pelo IDE.** Os hooks ficam em `.kiro/hooks/`, fora do arquivo do agente.
- **Se um script de hook falhar, o Kiro segue.** A trava final de publicação é a proteção de branch do repositório.
- O nome do campo do comando no evento do terminal não está escrito na documentação. Os hooks procuram `tool_input.command` e, se não acharem, conferem o evento inteiro como texto.
- Os testes cobrem os scripts e o formato dos arquivos. A execução dentro do Kiro foi conferida só pela documentação.

## Escopo por assunto

```bash
lastro scope auth      # só os controles de autenticação, com estado, como provar ou corrigir, e ASVS
lastro scope core      # controles de base
```

Os escopos são os pacotes do catálogo: `core`, `web`, `auth`, `pii`, `realtime`, `uploads`, `assets` e `agent`. Um escopo que o perfil não ativa diz quais flags faltam.

## O que o adaptador não faz

- Não decide por você. O agente propõe o texto de uma atestação, de um risco aceito ou de uma decisão de ameaça; quem confirma é uma pessoa.
- Não publica. Commit, push e PR são seus.
- Não substitui o CI. Steering orienta, hook ajuda, e o portão é o `lastro check` no pipeline.
