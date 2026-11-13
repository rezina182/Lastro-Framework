# Modelo de ameaças do LASTRO

Última revisão: 2026-11-12

Este documento descreve o que o próprio LASTRO precisa proteger. Um kit que verifica a segurança dos outros e não verifica a sua própria perde a razão de existir.

## Ativos

- Integridade do catálogo de controles: quem o altera muda o que "seguro" significa para todos os usuários.
- Integridade do verificador: um verificador adulterado pode declarar "passou" sem ter checado.
- Arquivos de instrução do agente (`.kiro/`): moldam o comportamento do agente que mantém o repositório.
- Credenciais de publicação e de CI.
- Máquina de quem executa o verificador.

## Fronteiras de confiança

- O repositório analisado é entrada não confiável. O verificador lê arquivos, mas nunca os executa.
- A URL analisada é entrada não confiável. As respostas HTTP são lidas com limite de tamanho e de tempo.
- Contribuições externas são não confiáveis até a revisão.

## Ameaças e tratamento

| # | Ameaça | Tratamento | Controle LASTRO |
|---|--------|-----------|-----------------|
| T1 | Arquivo do repositório analisado tenta fazer o verificador executar código | O verificador só lê texto, sem `eval`, sem `shell`, sem carregar módulos do alvo | CORE-008 |
| T2 | Resposta HTTP gigante ou lenta trava o verificador | Timeout de 10 s e teto de 512 KB por resposta | teste automatizado |
| T3 | Redirecionamento leva o verificador a outra origem | Só segue redirecionamento na mesma origem | teste automatizado |
| T4 | Verificação ativa (TRACE, OPTIONS, JSON malformado) usada sem consentimento ou contra produção | Desligada por padrão; exige `--active` e `--confirm-non-production`; recusada contra `urls.production` do perfil | teste automatizado |
| T16 | O verificador sobrecarrega ou derruba a aplicação alvo, ou dispara alarmes sem aviso | Aviso impresso antes de toda verificação HTTP; intervalo mínimo de 50 ms (padrão 150 ms) e teto de 120 requisições; passado o teto, nada mais é enviado | teste automatizado |
| T5 | "Não sei" tratado como "passou" | Estado `unverified` nunca conta como aprovado; veredito `incomplete` | princípio central |
| T6 | Atestação manual forjada ou eterna | Atestação tem responsável e validade de até 366 dias; controle automatizado ignora atestação | schema e engine |
| T7 | Risco aceito sem dono, sem prazo ou sem justificativa | Schema exige dono, aprovador, justificativa e validade; vencido volta a ser achado | CORE-013 |
| T8 | Instrução maliciosa ou texto invisível em arquivo do agente | Varredura de caracteres ocultos, CODEOWNERS e revisão | AG-002, AG-003 |
| T9 | Hook do agente exfiltra dados | Hooks não podem usar rede | AG-006 |
| T10 | Ação de CI trocada por versão maliciosa | Actions fixadas por SHA de commit | CORE-006 |
| T11 | Token de CI com permissão excessiva | `permissions: contents: read` | CORE-010 |
| T12 | Segredo commitado | Varredura no CI com binário de versão e checksum fixos | CORE-003 |
| T13 | Dependência nova comprometida | Zero dependências de execução; Dependabot nas Actions | CORE-002, CORE-005 |
| T14 | Entrada do usuário injetada no relatório (terminal ou Markdown) | Saída em texto simples; o relatório não interpreta conteúdo do alvo como comando | revisão |
| T15 | Catálogo contradiz a si mesmo (controle sem lição, check órfão) | `catalog validate` no CI bloqueia | teste automatizado |

## Riscos conhecidos e não tratados

- As verificações por texto (varredura de padrões) são heurísticas. Elas encontram o comum e não substituem revisão nem análise estática completa.
- A conferência do CI é por leitura do arquivo do workflow. Ela não prova que o workflow rodou nem que a proteção de branch está ativa; isso é atestação manual (CORE-014).
- A v0.1 analisa apenas GitHub Actions. Outros CIs ficam como `unverified`.

## Quando revisar

A cada nova versão menor, a cada nova classe de verificação e a cada incidente. O verificador acusa threat model sem revisão há mais de 180 dias.
