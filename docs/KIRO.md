# Uso com o Kiro

O LASTRO é independente de ferramenta. Este adaptador só leva as regras do kit para onde o agente as lê: arquivos de steering do Kiro.

```bash
lastro adapter kiro            # mostra o que seria criado
lastro adapter kiro --write    # cria em .kiro/steering/ do projeto (nunca sobrescreve um arquivo existente)
```

| Arquivo | Quando o Kiro o carrega | O que faz |
|---|---|---|
| `lastro-base.md` | sempre | Regras do agente: rodar `lastro check` antes de terminar, nunca atestar nem aceitar risco nem decidir ameaça por conta própria, não desligar TLS, não montar SQL por concatenação, não instalar dependência sem conferir, não commitar sem autorização |
| `lastro-escopo-auth.md` | ao ler arquivo com `auth` no caminho | Os pontos de autenticação, sessão e autorização que mais custam caro, e a regra de escrever teste que falha quando o controle some |
| `lastro-escopo-dados.md` | ao ler arquivo `.sql` | Consulta parametrizada, dado pessoal e sensível, hash de senha, migração com backup |
| `lastro-revisao-ameacas.md` | quando o pedido combina com a descrição | Conduz a revisão do modelo de ameaças com o usuário, ameaça por ameaça, e registra só o que ele confirmou |

## Escopo por assunto

```bash
lastro scope auth      # só os controles de autenticação, com estado, como provar ou corrigir, e ASVS
lastro scope core      # controles de base
```

Os escopos são os pacotes do catálogo: `core`, `web`, `auth`, `pii`, `realtime`, `uploads`, `assets` e `agent`. Um escopo que o perfil não ativa diz quais flags faltam.

## O que o adaptador não faz

- Não decide por você. O agente propõe o texto de uma atestação, de um risco aceito ou de uma decisão de ameaça, e quem confirma é uma pessoa.
- Não impede nada sozinho: steering é orientação, não trava. A trava está no CI, onde `lastro check` bloqueia o que for novo e grave.
- Hooks de bloqueio do agente (por exemplo, impedir escrita em `.lastro/status.json`) ainda não vêm no adaptador: dependem do formato de hook de cada versão do Kiro e entram depois de testados.
