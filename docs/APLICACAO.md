# Aplicação com vários repositórios

Uma aplicação costuma ter vários repositórios numa organização: frontend, API, worker, infraestrutura. Você diz o **nome da aplicação** e a **pasta onde os repositórios estão**. O kit identifica sozinho o papel de cada um, verifica cada repositório e gera um relatório único.

```bash
# clone (ou deixe lado a lado) os repositórios da aplicação numa pasta, por exemplo ~/org/app-x
lastro app --name "App X" --root ~/org/app-x --match "app-x-*" --out relatorio-app-x.html
```

- `--root`: a pasta que contém os repositórios (cada um numa subpasta). Padrão: a pasta atual.
- `--match`: padrão dos nomes das subpastas (`*` e `?`). Sem ele, o kit considera toda subpasta que pareça repositório (tem `.git`, `package.json`, `requirements.txt`, `go.mod`, `main.tf` e semelhantes). Com mais de 12, restrinja com `--match` ou liste com `--repos a,b,c`.
- `--out`: relatório da aplicação em HTML ou Markdown. `--out-dir`: grava também um relatório completo por repositório.
- `--theme`, `--redact` e `--allow-external-repos` funcionam como nos outros relatórios.

O kit só **lê**. Nada é gravado nos repositórios, e nenhum precisa de `lastro init`.

## O que o kit identifica sozinho

| Papel | Sinais usados |
|---|---|
| Frontend | dependências de interface (React, Vue, Svelte, Angular, Vite...), `index.html` sem rota de servidor, nome do repositório |
| Backend | dependências de servidor (Express, Fastify, NestJS, Flask, Django, FastAPI...), rotas HTTP encontradas, nome |
| Gateway | como o backend, com nome de `gateway`, `bff` ou `proxy` |
| Worker | dependências de fila ou tarefa agendada (BullMQ, Celery, amqplib, node-cron...) sem rotas |
| Infraestrutura | Terraform, Docker Compose, Helm, Kubernetes, CloudFormation, com pouco ou nenhum código |
| Aplicativo móvel | React Native, Expo, Capacitor, Flutter, Android ou iOS |
| Biblioteca | `package.json` com `main` ou `exports`, sem servidor nem interface |

Cada papel vem com o **motivo** e a **confiança** (alta, média ou baixa). Sem nenhum sinal, o papel é assumido com confiança baixa e o relatório pede confirmação.

Também aparecem como componentes: os **bancos de dados** (pelas dependências, como `pg`, `mysql2`, `mongoose`) e os **serviços externos** (hosts chamados pelo código). Um host que contém o nome de um dos repositórios é a própria aplicação, não um serviço externo.

## Como as ligações são inferidas

- **Usuário para frontend ou aplicativo**; **usuário para API** (todo backend com rotas é alcançável diretamente).
- **Frontend para backend**: quando o código do frontend cita o nome do repositório ou do pacote do backend. Sem citação, liga a todos os backends e marca a suposição no rótulo do fluxo.
- **Backend e worker para banco** e **para serviço externo**: pelo que o código de cada repositório usa.
- **Cadeia de entrega**: um nó de repositório e CI por repositório, mais o desenvolvedor e, se houver, o agente de IA.

Tudo isso aparece no desenho com a origem **inferido** (borda tracejada). Um banco usado por mais de um repositório é tratado como o mesmo banco, e o desenho avisa que é suposição.

## Perfil de cada repositório

Repositório **com** `.lastro/profile.json` usa o perfil dele. Repositório **sem** perfil recebe um **perfil derivado**, um rascunho montado pelo que o código mostra: rotas (`webApp`), dependências de login ou token, upload, tempo real, nomes de campo de dado pessoal (`personalData`), mídia versionada, arquivos de agente de IA. O que o código **não mostra** fica desligado: dados de crianças e adolescentes (`minorsData`), dados sensíveis (`context.sensitiveData`) e usuários anônimos. O relatório avisa, e você declara no perfil de cada repositório. Isso importa: dados de menores e dados sensíveis sobem o impacto dos riscos de confidencialidade.

## Corrigindo o que o kit errou

```bash
lastro app --name "App X" --root ~/org/app-x --write-system sistema.json   # grava o rascunho (não sobrescreve)
# edite sistema.json: papéis, exposição, classes de dado, fluxos (veja THREAT-MODEL-ASSISTIDO.md)
lastro app --name "App X" --root ~/org/app-x --system sistema.json --out relatorio-app-x.html
```

O que você declarou passa a valer: o papel vira "declarado por você", e o componente deixa de aparecer como inferido. O formato é o do `.lastro/system.json`, descrito em [THREAT-MODEL-ASSISTIDO.md](THREAT-MODEL-ASSISTIDO.md).

## O que o relatório traz

- **Repositórios identificados:** papel, confiança, motivo, perfil (declarado ou derivado), portão de CI, nota de 0 a 10, taxa dos controles automáticos, risco confirmado e ameaças expostas.
- **Arquitetura da aplicação:** o fluxo de dados com as fronteiras de confiança, e em cada fluxo as ameaças e os controles exigidos. As ameaças de cada fluxo vêm do repositório certo.
- **Riscos de segurança confirmados**, de todos os repositórios, em ordem de criticidade, com CWE (link para a fonte oficial), pilares e local.
- **Privacidade e dados pessoais**, **avisos**, **limites** e a **legenda**.

## Limites

- A identificação de papéis e as ligações são heurísticas de texto. Frameworks incomuns, monorepos com vários serviços numa pasta e ligações por configuração (variável de ambiente, descoberta de serviço) podem passar despercebidos: corrija com o `system.json`.
- Só repositórios **dentro** da pasta `--root` são lidos. Fora dela, só com `--allow-external-repos`.
- O kit não baixa repositórios de uma organização: clone-os antes (o acesso à sua organização é seu). Um comando que clona por você, com o seu consentimento e uma credencial somente leitura, é um próximo passo possível.
- Nada foi executado, e nenhuma requisição foi feita às aplicações.
