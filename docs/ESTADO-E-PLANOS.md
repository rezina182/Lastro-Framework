# Estado do LASTRO e planos de evolução

Documento de passagem: o que o kit é hoje, como cada parte funciona, o que os testes reais mostraram, como usar no dia a dia e o que vem a seguir. Vale como ponto de partida para quem continua o trabalho.

## 1. O que o LASTRO é

Um kit, sem dependências de execução, que mede **quanta evidência** existe de que uma aplicação segue um ciclo de desenvolvimento seguro (SSDLC) e o ASVS 5.0, levando em conta o contexto da aplicação. Ele não certifica nada. Os princípios que valem em tudo:

- **Desconhecido não é aprovado.** Sem prova, o controle fica "sem prova" e conta zero.
- **Falha fechado.** Erro dentro de uma verificação nunca vira "passou".
- **Só leitura por padrão.** O kit lê o repositório e só grava em `.lastro/` quando recebe `--write`.
- **Dinâmico só com aviso e fora de produção.** Sondas HTTP com ritmo e teto; sondas ativas exigem `--confirm-non-production`.
- **Decisão é de uma pessoa.** Atestação, risco aceito e decisão de ameaça nunca são feitas pelo agente sozinho.

## 2. Como funciona, parte por parte

| Parte | Comando | O que faz | Documento |
|---|---|---|---|
| Catálogo | `lastro catalog validate` | 154 controles em 8 pacotes, 37 lições de origem, 32 verificações automáticas, mapa dos 345 requisitos do ASVS 5.0 | [ARCHITECTURE.md](../ARCHITECTURE.md), [GLOSSARIO.md](GLOSSARIO.md) |
| Perfil | `lastro init` | Flags que dizem o que a aplicação tem (web, login, upload, dados de menores...). Decidem o escopo e o contexto | [PROFILE.md](PROFILE.md) |
| Verificação | `lastro check` | Roda as verificações automáticas, lê as atestações e dá o portão de CI (bloqueia achado novo alto ou crítico) | [README](../README.md) |
| Sondas HTTP | `lastro check --url` | Cabeçalhos, CSP, HSTS, cookies, erros, arquivos sensíveis; `--active` para TRACE e CORS | [README](../README.md) |
| Maturidade | dentro do relatório | Nível 0 a 4, provado por máquina e autodeclarado, por pacote e por fase do SSDLC, mais a taxa dos controles automáticos | [SCORE.md](SCORE.md) |
| Risco | dentro do relatório | Separa risco de segurança, boa prática e qualidade; probabilidade x impacto, pilares, CWE, LGPD; dependências vulneráveis com `--audit-file` | [RISCO.md](RISCO.md) |
| Modelo de ameaças | `lastro threat-model` | Rascunho STRIDE por superfície a partir do código, com pistas (rotas sem autenticação vista, dado sensível), decisões gravadas e o desenho da arquitetura | [THREAT-MODEL-ASSISTIDO.md](THREAT-MODEL-ASSISTIDO.md) |
| Aplicação com vários repositórios | `lastro app` | Identifica o papel de cada repositório, verifica cada um e junta tudo num relatório com a arquitetura | [APLICACAO.md](APLICACAO.md) |
| Playbook | `lastro playbook` | Roteiro passo a passo de cada controle manual, com o trecho pronto da atestação | [PLAYBOOK.md](PLAYBOOK.md) |
| Backlog | `lastro backlog` | Lacunas viram tickets P0 a P3 | [README](../README.md) |
| Escopo | `lastro scope auth` | Só os controles de um assunto | [KIRO.md](KIRO.md) |
| Kiro | `lastro adapter kiro` | Steering (regras e escopos), hook que pede confirmação antes de mexer em decisões humanas, condução da revisão de ameaças | [KIRO.md](KIRO.md) |
| Relatório | `lastro report --out x.html` | HTML autocontido, sem script, com tema e redação, links só para fontes oficiais e legenda | [README](../README.md) |

### Como uma execução acontece por dentro

1. **Carga:** o catálogo é lido e validado nos dois sentidos (controle e lição, verificação e controle, referência ASVS e mapa); o perfil é validado; atestações, riscos aceitos, baseline e modelo de ameaças são lidos se existirem.
2. **Verificação:** cada controle aplicável ao perfil roda. Automático: a verificação do registro (repositório ou HTTP) devolve verificado, falhando, sem prova ou não se aplica, com achados. Manual: vale a atestação vigente, se houver.
3. **Achados:** cada achado ganha uma impressão digital estável; o baseline e os riscos aceitos dizem se ele bloqueia. Só achado novo, alto ou crítico, fora do baseline e sem risco aceito bloqueia o portão.
4. **Camadas de leitura:** a pontuação (maturidade e taxa dos automáticos), o contexto (risco inerente e meta), o modelo de ameaças (descoberta do código, STRIDE por superfície, decisões gravadas, desenho da arquitetura), a análise de risco (natureza, probabilidade x impacto, pilares, CWE, LGPD, dependências) e a legenda.
5. **Saída:** texto no terminal, JSON (`--out`), Markdown ou HTML (`lastro report`), playbook, backlog, modelo de ameaças.

### O que foi construído, em ordem

| Etapa | O que entrou | Por quê |
|---|---|---|
| Base | Catálogo, verificador, portão de CI, baseline, risco aceito com validade, atestação com prazo, backlog | Ter um "não sei" que nunca vira "passou" e um portão que só bloqueia o que é novo |
| ASVS | Mapa dos 345 requisitos e classificação dos 17 capítulos até L2 | Ligar cada controle ao padrão de mercado, com cobertura inteira ou parcial declarada |
| Testes dinâmicos | Sondas passivas, sondas ativas com trava, ritmo e teto de requisições | Ver o comportamento da aplicação sem derrubá-la nem tocar produção |
| Varreduras estáticas | SQL montado por texto, aleatoriedade e hash fracos, segredos literais, HTML cru | Pegar o comum em cada PR, sem tocar a aplicação |
| Maturidade e relatório | Nível 0 a 4, relatório em Markdown e HTML, tema e redação | Mostrar evidência sem parecer reprovação, e poder compartilhar sem expor nomes |
| Contexto | Risco inerente, meta, escopo, fases do SSDLC, fatos de engenharia, causas agrupadas | Nem toda aplicação precisa do mesmo rigor |
| Risco | Natureza, probabilidade x impacto, pilares, CWE, LGPD, `npm audit` | Saber o que é brecha, o que é processo e o que é qualidade |
| Modelo de ameaças | Rascunho STRIDE a partir do código, decisões gravadas, CORE-012 exigindo revisão, desenho da arquitetura | Tornar a probabilidade específica e achar riscos de desenho |
| Vários repositórios | `system.json`, `lastro app` com papéis identificados pelo código | Uma aplicação costuma ter vários repositórios |
| Kiro | Steering por escopo, hook de confirmação, `lastro scope`, `lastro adapter kiro` | Levar as regras para onde o agente as lê |
| Playbook | Roteiro de cada controle manual, com o trecho pronto da atestação | Tornar o teste manual repetível |
| Calibrações | Comentários e testes nas varreduras, ligação de rota a middleware, "saúde" e SSE, BOM do Windows, dependências | Cada aplicação real revelou falsos positivos; todos viraram teste |

## 3. O que os testes reais mostraram

O kit foi aplicado, sempre em cópia ou clone e só leitura, a duas aplicações reais (App A e App B) e a ele mesmo. O teste do App B foi de ponta a ponta: clone, perfil, auditoria de dependências, verificação estática, app rodando local com banco descartável, a suíte de testes do próprio app, sondas passivas e ativas, modelo de ameaças, relatório e playbook.

### Números do teste de ponta a ponta (App B)

| Momento | Peso provado | Controles automáticos | Riscos potenciais altos |
|---|---|---|---|
| Só estático | 9,8% | 13 ok, 9 falham, 10 não rodaram | 55 |
| Mais sondas passivas | 14,4% | 20 ok, 9 falham, 2 não rodaram | 49 |
| Mais sondas ativas | 14,9% | 21 ok, 9 falham, 1 não rodou | 48 |

Riscos confirmados: 0 crítico, 3 altos (Action por tag, SQL por interpolação para revisar, segredo literal num script de carga), 2 médios, 1 baixo (aviso de dependência só em desenvolvimento). Portão de CI: 6 bloqueantes em 3 causas. A suíte do próprio app passou (205 testes) contra banco real descartável.

### Como repetir o teste de ponta a ponta

1. Clone a aplicação a partir do repositório local numa pasta temporária (`git clone --no-hardlinks`). Nunca rode no repositório original.
2. Crie `.lastro/profile.json` no clone e rode `npm audit --json` lá (com consentimento: envia a lista de pacotes ao registro).
3. `lastro check --root CLONE --audit-file audit.json` e `lastro threat-model --root CLONE --write`.
4. Suba um banco descartável num container próprio (nome, porta e sem volume próprios; nunca o banco do desenvolvedor), crie um `.env` só no clone com segredos de teste gerados na hora, instale com `npm ci --ignore-scripts`, rode a suíte de testes e suba o app numa porta livre.
5. `lastro check --url http://127.0.0.1:PORTA`, depois com `--active --confirm-non-production`.
6. `lastro report` e `lastro playbook`; compare antes e depois. Pare o app, remova o container e confira que o repositório original não mudou.

### Onde ele é efetivo

- **Cadeia de suprimentos, CI e configuração:** acha com precisão Action sem SHA, workflow sem `permissions`, falta de CODEOWNERS, de SECURITY.md e de modelo de ameaças, TLS desligado, segredo literal e mídia sem origem. São achados reais e fáceis de corrigir.
- **Comportamento HTTP:** com o app rodando, prova de fora cabeçalhos, CSP, erros genéricos, arquivos sensíveis, TRACE e CORS. No App B, 21 de 22 controles automáticos aplicáveis passaram depois das sondas.
- **Organização do risco:** separa o que é brecha do que é processo; o "crítico exige evidência" evita alarme falso; dependência só de desenvolvimento não vira risco crítico.
- **Pergunta certa:** todas as 14 lições conhecidas do App B aparecem, seja como achado, seja como controle sem prova no playbook e no modelo de ameaças. Nenhuma ficou fora.

### Onde ele ainda não é efetivo

- **Falhas de lógica e de autorização:** só 1 das 14 lições do App B é pega automaticamente. As outras 13 viram pergunta, e a resposta depende de uma pessoa ou de um teste que ainda não existe.
- **Muito "sem prova":** cerca de 80% do peso fica sem prova até alguém executar o playbook. O nível de maturidade separa pouco duas aplicações nesse estado; a taxa dos controles automáticos separa melhor.
- **Sessão e cookies:** as sondas só fazem GET, e o cookie de sessão só aparece depois do login. O AUTH-003 fica sem prova.
- **Maturidade do próprio kit:** cada aplicação real revelou de 2 a 4 falsos positivos ou erros do kit (comentário tratado como código, "saúde" como dado sensível, BOM do Windows, aviso de dependência contado três vezes). Todos foram corrigidos com teste, mas isso mostra que as heurísticas ainda estão em calibração.
- **Ainda não houve prova contra o desconhecido:** as duas aplicações já tinham passado por trabalho de ASVS. O kit ainda não foi medido contra falhas que a equipe não conhecia.

### Conclusão honesta

Hoje o LASTRO é efetivo como **disciplina e higiene**: mostra a postura, organiza o risco, cobra o que falta e prova o que dá para provar de fora. Ele ainda não é efetivo como **detector de falha de lógica**. As evoluções abaixo atacam exatamente essa diferença.

## 4. Como usar na vida real

```
 desenvolvimento            pull request               periódico                  release
 ───────────────            ────────────               ─────────                  ───────
 agente com o steering      CI roda lastro check       relatório e playbook       relatório HTML com a
 do kit; lastro scope       (portão: só achado novo    semanais; atestações       arquitetura e o modelo
 ao mexer em auth;          alto/crítico bloqueia);    que vencem; revisão do     de ameaças como documento
 hook pede confirmação      relatório como artefato    modelo de ameaças a cada   da versão
 antes de decisões                                     180 dias ou ao mudar a
 humanas                                               superfície
```

1. **Adoção:** `lastro init`, revisar o perfil com outra pessoa, `lastro adapter kiro --write`, `lastro baseline --write` para registrar a dívida atual, e o passo `lastro check` no CI.
2. **No dia a dia:** o agente segue o steering e o escopo do assunto; o CI bloqueia só o que for novo e grave.
3. **Periodicamente:** `lastro report` e `lastro playbook`; uma pessoa executa os roteiros e atesta; `lastro threat-model` quando a superfície muda.
4. **Vários repositórios:** `lastro app` na pasta da organização, com `--write-system` para corrigir os papéis uma vez.

## 5. Planos de evolução

### 5.0 Visão: o LASTRO como base do ciclo de desenvolvimento com IA (AI-DLC)

A intenção é que qualquer pessoa que desenvolva com IA chame o LASTRO e ele conduza o ciclo inteiro, em dois cenários:

- **Aplicação nova:** o kit é o ponto de partida. Ao começar uma funcionalidade (por exemplo, uma tela de login), o dev pede os requisitos daquele assunto antes de escrever código: requisitos de segurança, decisões de arquitetura, ameaças do desenho, critérios de teste e controles que depois serão verificados. A arquitetura e o código nascem já alinhados ao que o kit cobra.
- **Aplicação existente:** o kit mede o que há, registra a dívida (baseline), prioriza (backlog P0 a P3), corrige o que é previsível e acompanha a evolução.

O mesmo catálogo serve aos dois: no desenho ele diz **o que deve ser feito**; depois do código ele **prova que foi feito**. A governança vem do registro: decisões, atestações, riscos aceitos e histórico, com uma visão para o dev (o que fazer agora) e outra para o time de segurança (risco, pendências e exceções que vencem). Quanto mais disso for automação (skills, steering, hooks, agente e pipeline), menos o dev precisa lembrar.

Hoje o kit é forte em verificar o que já existe. Faltam a fase de desenho para a aplicação nova (5.8), o ponto de entrada único do agente (5.4) e a pipeline como produto (5.10). A ordem de execução:

1. Banco de falhas plantadas (5.1): mede o recall, antes de mexer no resto.
2. Sondas autenticadas (5.2).
3. Modo corrigir (5.3).
4. Fase de desenho: requisitos por funcionalidade (5.8).
5. Agente, skills e hooks do Kiro, com os fluxos "nova" e "existente" (5.4).
6. Pipeline: Action reutilizável, SARIF e comentário no PR (5.10).
7. Histórico e portal estático, com visão por papel (5.5 e seção 6).
8. Revisão dos frameworks de mercado (5.9), em paralelo, a cada etapa que tocar o catálogo.

Os itens 5.1 a 5.7 abaixo continuam como estavam; 5.8 a 5.10 são novos.

### 5.1 Medir a efetividade de verdade (banco de falhas plantadas)

**Feito (primeira etapa):** `lastro bench` e `fixtures/planted/`, com 35 falhas plantadas e 23 gêmeas limpas. O banco roda dentro do `npm test`, então uma regressão quebra o CI. Veja [BENCH.md](BENCH.md).

| Primeira medição (2026-11-17) | Resultado |
|---|---|
| Código, configuração e HTTP | 29 de 29 detectadas |
| Lógica (acesso por objeto, atribuição em massa, CSRF, logout) | 0 de 6 detectadas; as 6 viram pergunta (depois das sondas autenticadas: 4 de 4 em execução detectadas; as 4 só no código seguem como pergunta) |
| Falsos positivos nas aplicações limpas | 0 de 23 |

A primeira execução achou uma falha do kit: o CORE-059 não pegava `"... name = '" + nome + "'"`. Foi corrigida, com teste. Próximos casos: variações das regras atuais, upload sem limite, redirecionamento aberto e SSRF. O 0 de 6 na lógica é a meta do 5.2.

### 5.2 Sondas autenticadas (staging ou local)

**Feito:** `lastro check --auth` ([SONDAS-AUTENTICADAS.md](SONDAS-AUTENTICADAS.md)) prova acesso por objeto entre duas contas e sem login (AUTH-027), CSRF (WEB-013), logout que encerra a sessão (AUTH-023) e passa o cookie do login pela análise de cookies (AUTH-003). No banco de falhas, as 4 falhas de lógica em execução passaram de pergunta a detectadas, com 0 falso positivo. **Falta:** acesso por campo e atribuição em massa (AUTH-028), expiração por inatividade (AUTH-024), login federado e descoberta das rotas a partir do código (hoje o perfil declara as rotas).

Plano original, mantido para referência:

Configuração opcional de **contas de teste** no perfil (nunca reais, só staging ou local, com a mesma trava das sondas ativas). Com elas o kit prova automaticamente:

- cookie de sessão com `Secure`, `HttpOnly`, `SameSite` e prefixo (AUTH-003);
- logout que encerra a sessão e expiração por inatividade (AUTH-023, AUTH-024);
- **acesso por objeto entre duas contas** (AUTH-027, AUTH-028): a conta A tenta ler e alterar o objeto da conta B nas rotas descobertas e precisa receber 403 ou 404;
- CSRF em rota que muda estado (WEB-013).

É o passo que mais aproxima o kit das falhas de lógica, porque transforma roteiros do playbook em prova de máquina.

### 5.3 Correção automática com permissão (modo "corrigir")

Para achados com correção determinística, o kit gera a mudança numa **branch própria**, roda os testes do projeto e só então pede ao desenvolvedor para abrir o PR:

| Achado | Correção gerada |
|---|---|
| Action por tag (CORE-006) | troca pelo SHA do commit da tag, com a versão em comentário |
| Workflow sem `permissions` (CORE-010) | `permissions: contents: read` no topo |
| Sem CODEOWNERS (AG-003) | arquivo com os caminhos de instrução e de CI, para o dono preencher |
| Sem SECURITY.md (CORE-011) | modelo com canal de contato a preencher |
| Dependência com correção publicada | atualização para a versão corrigida, com teste |
| Sem modelo de ameaças (CORE-012) | rascunho em `.lastro/threat-model.json` para revisão |

Regras: nunca na branch principal, nunca push sem autorização, sempre com teste verde, sempre com a mudança explicada no PR.

### 5.4 Agente, skills, steering e hooks para o ciclo automático

Um **agente do Kiro dedicado ao LASTRO** que conduz o ciclo inteiro e para nos pontos de decisão humana:

1. roda `lastro check` e `lastro threat-model`;
2. aplica as correções determinísticas (5.3) numa branch;
3. escreve os **testes automatizados** que o playbook descreve, a partir das rotas descobertas (por exemplo, o teste de acesso por objeto com duas contas), e roda a suíte;
4. prepara as decisões que só uma pessoa pode tomar (ameaças, atestações, riscos aceitos) e as apresenta;
5. **pede permissão antes do PR** e nunca faz push sozinho.

Peças: skills por tarefa (triagem, correção, testes do playbook, revisão de ameaças), steering por escopo (já existe), hooks que rodam o `lastro check` ao terminar uma tarefa e que pedem confirmação antes de decisões humanas (já existe o segundo).

### 5.5 Histórico e portal estático (a "interface")

Ver a seção 6.

### 5.6 Vários repositórios, segunda etapa

Clonar os repositórios de uma organização com credencial só de leitura e consentimento; ler as ligações a partir de Docker Compose, Terraform e Kubernetes; modelo de ameaças decidido uma vez por aplicação; ligação de rota a middleware em Fastify, NestJS, Flask e FastAPI.

### 5.7 Publicação

Revisar as lições de origem (descrevem aplicações reais), decidir sobre o e-mail nos commits, traduzir a documentação para inglês, atestar os 55 controles manuais do próprio kit pelo playbook e publicar a v0.1.0.

### 5.8 Fase de desenho: requisitos por funcionalidade (aplicação nova)

Hoje o modelo de ameaças nasce da leitura do código, então só ajuda depois que o código existe. Para a aplicação nova, o kit precisa agir **antes**:

- Um comando e uma skill que, dado o assunto ("login", "upload", "pagamento", "tempo real"), devolvem os requisitos de segurança daquele assunto: os controles do catálogo, o requisito do ASVS que cada um cobre, as decisões de arquitetura a tomar, as ameaças prováveis e os testes que provarão cada requisito. É o `lastro scope` levado para a fase de desenho.
- Decisões de arquitetura registradas (ADR curto, com dono e data), ligadas aos controles que elas atendem.
- Uma arquitetura-alvo por tipo de aplicação (web com login, API, tempo real, aplicação com agente de IA), como ponto de partida que a pessoa adapta. O kit propõe, a pessoa decide.
- Integração com a especificação do Kiro (requisitos, desenho e tarefas): os requisitos de segurança entram na spec e as tarefas incluem os testes.

Ainda não decidido: o formato do artefato (arquivo em `.lastro/` ou seção da spec) e quanto do texto o kit gera. Isso se define com um caso real (a tela de login).

### 5.9 Revisão dos frameworks de mercado

Hoje o kit cita ASVS 5.0, NIST SSDF, OpenSSF, CWE e LGPD. Para ser referência em desenvolvimento seguro com IA, vale avaliar acrescentar, uma a uma, com leitura da fonte oficial e mapeamento por ID (sem copiar texto):

| Candidato | Para que serviria | Situação |
|---|---|---|
| AI-DLC (AWS) | Estrutura de fases (ideação, inception, construction, operação) do ciclo com IA; o LASTRO pode mapear seus controles e portões por fase | A avaliar; o servidor MCP dele já roda no Kiro |
| OWASP SAMM | Medir a maturidade do **processo** de segurança da organização, que complementa a maturidade da aplicação | A avaliar |
| OWASP Top 10 for LLM Applications 2025 | Risco de aplicações que usam LLM (injeção de prompt, vazamento de prompt do sistema, agência excessiva) | A avaliar; hoje só o pacote `agent` toca o tema |
| OWASP Top 10 for Agentic Applications (2026) e MITRE ATLAS | Ameaças a agentes, para o pacote `agent` e o modelo de ameaças | A avaliar |
| NIST AI RMF e perfil de IA generativa; ISO/IEC 42001 | Governança de IA; o relatório poderia dizer onde a aplicação está | A avaliar |
| NIST SP 800-218A | Práticas de SSDF para IA generativa | Já lido parcialmente (PO.5.3) |
| SLSA e OpenSSF Scorecard | Cadeia de suprimentos e integridade de build | A avaliar; o CORE-006 e o CORE-010 já tocam parte |
| SBOM (CycloneDX ou SPDX) | Inventário de componentes por release | Já no roadmap ("Depois") |
| Lei de IA da UE | Obrigações por categoria de risco | A avaliar com cuidado: é jurídico e o kit não dá parecer |

Regra: cada framework entra com ID e link, registrado em `RESEARCH-REGISTER.md` com o quanto foi lido. "Alinhado a" nunca vira "em conformidade com". Nesta data, a lista acima veio de buscas na web e **ainda não foi conferida nas fontes oficiais**.

### 5.10 Pipeline como produto

O portão de CI existe (`lastro check`). Para uso em pipeline de verdade falta: uma GitHub Action reutilizável (com versão fixada por SHA), saída SARIF para o painel de segurança, comentário no PR com o que mudou desde o baseline, e o `lastro bench` (5.1) rodando no CI do próprio kit. Outros CIs (GitLab, Azure Pipelines) ficam depois.

## 6. Interface gráfica: vale a pena?

Vale a **visão**, em etapas. Não vale, por enquanto, um **painel com servidor**.

- **O que dá a visão completa sem aumentar a superfície de ataque:** gravar o resultado de cada execução em `.lastro/history/` e gerar um **portal estático** (`lastro site`): várias páginas HTML autocontidas, sem script e sem servidor, com a evolução no tempo (maturidade, risco, ameaças), a arquitetura e o modelo de ameaças atualizados, o backlog, as atestações que vencem e o playbook. Pode ser publicado como artefato do CI ou numa página interna. Os desenvolvedores continuam sem precisar fazer nada.
- **O que fica para depois, se houver demanda:** um painel interativo para decidir ameaças e registrar atestações. Ele exige servidor, login, proteção contra CSRF e controle de quem decide, ou seja, vira uma aplicação a ser protegida. Enquanto isso, a parte interativa fica com o agente no Kiro (5.4), que já conversa, propõe e pede confirmação.

## 7. Cuidados para quem continua

- Trabalhe com a pasta do LASTRO aberta como workspace. Se a pasta aberta for de uma aplicação analisada, nada deve ser escrito nela: as análises rodam em cópias ou clones.
- O repositório do kit é neutro: nada de nomes de empresas ou aplicações reais. Use "App A" e "App B".
- Rode `npm test` e `npm run catalog:validate` antes de dizer que terminou, e nunca faça commit nem push sem autorização explícita.
