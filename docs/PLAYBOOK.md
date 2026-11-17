# Playbook de verificação dos controles manuais

Parte dos controles não tem como ser provada por máquina: proteção de branch, autorização por objeto, sandbox do agente, rotação de segredos. Eles só passam com uma **atestação**, a declaração de uma pessoa, com prazo, de que testou. O playbook é o roteiro desse teste.

```bash
lastro playbook --out playbook.html            # todos os controles manuais sem prova
lastro playbook --scope auth --out auth.md     # só um assunto (core, web, auth, pii, realtime, uploads, assets, agent)
lastro playbook --only CORE-014,AUTH-027       # só alguns controles
lastro playbook --all                          # inclui os que já estão atestados (para repetir o teste)
```

Aceita `--theme` (HTML) e `--redact`, como os relatórios.

## O que cada roteiro traz

| Parte | O que é |
|---|---|
| Situação | Gravidade, natureza (segurança, boa prática, qualidade), estado, pilares, CWE com link, requisitos do ASVS, base na LGPD e as ameaças do modelo que o controle mitiga |
| Por que importa | A razão do controle, em uma frase do catálogo |
| Antes de começar | O que preparar: ambiente local ou staging, contas de teste, branch descartável, acesso às configurações da plataforma, sessão de teste do agente. Montado a partir do que o teste pede |
| Passo a passo | Os passos numerados, tirados do texto de verificação do catálogo |
| Resultado esperado | Uma lista para marcar: cada "confirme que..." do catálogo vira um item, mais a conferência por outra pessoa |
| Evidência a guardar | Data, ambiente, quem fez, resultado de cada passo, print, log ou link. Sem segredo nem dado pessoal real |
| Se falhar | Como corrigir, e o lembrete de repetir o teste e de abrir o ticket com `lastro backlog --write` |
| Como registrar | O trecho pronto para colar em `.lastro/status.json`, com a data de hoje e a validade sugerida |

A ordem é por natureza (segurança primeiro) e por gravidade. No topo há uma lista de verificação com todos os controles.

## Regras que valem para todo teste

- **Ambiente:** local ou staging, com dados e contas de teste. Nunca em produção.
- **Quem atesta:** quem escreveu o código não deve ser a única pessoa a atestar um controle de gravidade alta ou crítica. Outra pessoa repete o teste ou revisa a evidência.
- **Evidência:** fora do repositório público, sem segredo, senha ou dado pessoal real.
- **Falhou:** não ateste. Corrija, repita e só então registre.
- **Validade sugerida:** 180 dias para gravidade alta e crítica, 365 para média e baixa. O kit recusa atestação com mais de 366 dias.

## Depois de registrar

1. `lastro check`: o controle vira "verificado", com quem atestou e até quando.
2. `lastro report --out relatorio.html`: maturidade e risco atualizados.
3. Agende o vencimento. Vencida, a atestação deixa de valer e o controle volta a "sem prova".

## Limites

- O passo a passo vem do texto do catálogo. O kit organiza e acrescenta os cuidados do próprio teste, mas não conhece a sua aplicação: adapte os nomes de rota, de conta e de ambiente.
- A atestação é autodeclaração. Ela vale como evidência de processo, não como prova técnica. Sempre que um teste puder virar teste automatizado no CI, prefira o teste automatizado.
- O agente de IA pode preparar o playbook e propor o texto da atestação, mas não deve registrá-la: o hook do Kiro pede a sua confirmação antes de qualquer escrita em `.lastro/status.json`.
