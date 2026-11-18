# Modelo de ameaças assistido

`lastro threat-model` gera um **rascunho** de modelo de ameaças a partir do que o kit enxerga, e pergunta. Quem decide é uma pessoa. Isto não é o modelo de ameaças do próprio kit (esse é o [THREAT-MODEL.md](THREAT-MODEL.md)).

> Um modelo de ameaças depende do que só quem conhece o negócio sabe: quem ataca, o que vale mais, o que é aceitável perder. O kit organiza, descobre pistas e cobra a decisão. Ele não substitui a conversa.

## Como funciona

1. **Descoberta (só leitura).** O kit lê o repositório, sem executar nada e sem acessar a rede, e registra:
   - rotas HTTP (Express e Flask/FastAPI), com a autenticação **vista** ou **não vista**;
   - armazenamento, tempo real (WebSocket, SSE), bibliotecas de upload e chamadas a serviços externos;
   - variáveis de ambiente (**só os nomes**) e indícios de tipos de dado (categoria e arquivo, nunca valor), inclusive possível dado sensível (LGPD, art. 5º, II).
2. **Ativos.** Sai uma lista inicial a partir do perfil e da descoberta. Cada ativo diz se foi `declarado`, `descoberto` ou `revisado`.
3. **Ameaças.** Cada ameaça é uma categoria **STRIDE** numa **superfície**, com id estável (`TM-E-auth`, `TM-I-web`). As mitigações são os controles de segurança do catálogo daquela categoria e superfície, e o estado da ameaça vem deles:
   - `exposta`: algum controle está falhando;
   - `sem prova`: nenhum falha, mas nem todos estão provados;
   - `mitigada`: todos os controles estão verificados.
4. **Decisão.** Para cada ameaça, uma pessoa registra `mitigate`, `accept` (com justificativa, dono e validade) ou `not_applicable` (com justificativa), e pode informar a probabilidade de 1 a 4.
5. **Revisão.** Com todas as ameaças decididas, a pessoa preenche `reviewedBy` e `reviewedAt`. A partir daí o CORE-012 passa, até o prazo de revisão vencer (180 dias por padrão).

## Superfícies

| Superfície | De onde vêm os controles |
|---|---|
| Interface web e API | pacote `web`, e controles de base alcançáveis por requisição remota (injeção, validação) |
| Autenticação e sessão | pacote `auth` |
| Dados e comunicações | pacote `pii`, e controles de base que dependem de posição na rede ou de acesso interno (TLS, criptografia, logs) |
| Tempo real | pacote `realtime` |
| Upload de arquivos | pacote `uploads` |
| Desenvolvimento, CI e cadeia de suprimentos | pacote `assets` e controles de base de alcance `pipeline` |
| Agente de IA no desenvolvimento | pacote `agent` |

## STRIDE no catálogo

A categoria vem dos pilares e das CWE de cada controle (`catalog/risk-map.json`), sem lista nova para manter:

| STRIDE | Regra |
|---|---|
| S, falsificação de identidade | o controle protege **autenticidade** |
| T, adulteração | protege **integridade** |
| R, repúdio | protege **irretratabilidade** ou **auditabilidade** |
| I, divulgação de informação | protege **confidencialidade** ou **privacidade** |
| D, negação de serviço | protege **disponibilidade** |
| E, elevação de privilégio | a CWE é de controle de acesso (862, 863, 639, 284, 285, 269, 250, 653, 915, 732) |

Um controle pode contar em mais de uma categoria. Só controles de **segurança** entram como mitigação; boa prática e qualidade não.

## Arquitetura: fluxo de dados e fronteiras de confiança

O modelo também desenha o **fluxo de dados** da aplicação, com as fronteiras de confiança, e mostra em cada fluxo as ameaças e os controles que ele exige. É a parte "arquitetura segura" do modelo: onde cada controle precisa estar.

| Fluxo | Fronteira | Aparece quando |
|---|---|---|
| F1 Requisições web e autenticação | Internet para aplicação | há aplicação web ou rotas |
| F2 Arquivos enviados | Internet para aplicação | há upload |
| F3 Conexão de tempo real | Internet para aplicação | há WebSocket ou SSE |
| F4 Leitura e escrita de dados | Aplicação para dados | há armazenamento ou dado pessoal |
| F5 Chamadas a serviços externos | Aplicação para terceiros | o código chama hosts externos |
| F6 e F7 Código, revisão, CI e entrega | Entrega do software | sempre |
| F8 Agente de IA escreve código | Entrega do software | o perfil declara agentes de IA |

Para cada fluxo o relatório traz o número de ameaças e quantas estão expostas, quantos controles são exigidos (verificados, falhando, sem prova) e quais falham agora. A saída é o diagrama em **Mermaid** no Markdown, para colar na documentação, e um **SVG estático** (sem script) no HTML. No SVG, a linha vermelha marca o fluxo com ameaça exposta.

O kit desenha o que descobriu e o que o perfil declara. Ele **não inventa a arquitetura**: onde colocar um proxy reverso, como segmentar a rede, como separar ambientes e onde guardar segredos são decisões de uma pessoa, que o modelo de ameaças ajuda a justificar. A versão atual desenha só fluxos externos e entre zonas; o detalhe interno da aplicação (módulos, filas) não é descoberto.

## Aplicação com mais de um repositório ou componente

Ler um repositório já gera o modelo e o desenho. Quando a aplicação tem **vários repositórios** (frontend, API, worker, infraestrutura) ou componentes que o código não mostra (banco, fila, serviço de terceiros), descreva o sistema em `.lastro/system.json` no repositório principal. O que você declara manda no desenho; o kit combina com o que descobre lendo cada repositório.

```json
{
  "schemaVersion": 1,
  "name": "Plataforma de exemplo",
  "components": [
    { "id": "web", "name": "Frontend", "role": "frontend", "repo": "../app-web", "exposure": "internet" },
    { "id": "api", "name": "API", "role": "backend", "repo": ".", "exposure": "internet", "dataClasses": ["pessoal", "menores"] },
    { "id": "db", "name": "PostgreSQL", "role": "database", "exposure": "privada" },
    { "id": "pay", "name": "Gateway de pagamento", "role": "external" }
  ],
  "flows": [
    { "from": "user", "to": "web", "label": "Navegação", "protocol": "https" },
    { "from": "web", "to": "api", "label": "API REST", "protocol": "https" },
    { "from": "api", "to": "db", "label": "Consultas", "protocol": "sql" },
    { "from": "api", "to": "pay", "label": "Cobrança", "protocol": "https" }
  ]
}
```

- **Papéis** (`role`): `frontend`, `mobile`, `backend`, `gateway`, `worker`, `queue`, `database`, `storage`, `external`, `infra`. Só componente com código tem `repo`. **Exposição**: `internet`, `interna` ou `privada`. **Classes de dado** (`dataClasses`): `pessoal`, `menores`, `sensivel`, `credencial`, `financeiro`.
- **Atores** que podem aparecer nos fluxos: `user` (usuário na internet) e `dev` (desenvolvedor).
- **Fluxos**: `protocol` opcional (`https`, `wss`, `sql`...). O kit deduz a superfície de ameaças pelo papel e pelo protocolo; `surfaces` (`web`, `auth`, `data`, `realtime`, `uploads`, `pipeline`, `agent`) sobrescreve. **Sem `flows`**, o kit infere o básico pelos papéis e marca como `inferido`.
- **Cada repositório** que tem `.lastro/profile.json` é verificado por conta própria (só leitura), e os fluxos dele usam as ameaças e os controles dele. Repositório sem perfil é lido, mas usa as ameaças do principal, com aviso.
- **Origem de cada fluxo e componente**: `declarado` (você descreveu), `descoberto` (o kit viu no código e você não declarou, como um banco ou um host externo que faltou) e `inferido`. O descoberto aparece com borda tracejada, para você confirmar ou declarar.
- **Segurança da leitura**: o arquivo pode vir de um repositório de terceiros, então repositórios **fora da pasta analisada só são lidos com `--allow-external-repos`**, e o kit nunca grava neles. Dentro da pasta (monorepo), a leitura é sempre permitida.

Sem `system.json`, o desenho é o automático de um repositório.

## O que o desenho mostra de cada componente

O desenho automático não para nas caixas genéricas. Ele mostra o que o código revela, sempre como indício para a revisão e nunca como verificação de controle:

| Componente | O que aparece |
|---|---|
| Aplicação | **Módulos de rotas** pelo prefixo de montagem (`app.use('/api/quizzes', ...)` mais a rota), com quantas têm proteção vista, quantas são públicas esperadas e quantas não têm proteção vista (destacadas). Também tempo real, upload e as **defesas vistas no código**: cabeçalhos e CSP, CSRF, conferência de origem, limite de requisições, cookie `HttpOnly`, hash de senha forte, segundo fator, limite de corpo, reprocessamento de imagem, anti-robô e trilha de auditoria |
| Armazenamento | As **tabelas** criadas nas migrações SQL, com o tipo de dado que as colunas sugerem (credenciais, contato, identificação, financeiro, sensível) |
| Repositório e CI | Os workflows e os **jobs** |
| Serviços externos | Os hosts chamados pelo código |

Os fluxos são linhas com um número (F1, F2...). O detalhe de cada fluxo, com ameaças, controles exigidos e o que está falhando, fica na tabela logo abaixo do desenho. Assim nenhum texto fica cortado ou escondido atrás de uma caixa. Linha e número em vermelho indicam que o fluxo tem ameaça exposta. Abaixo do desenho, a seção "Componentes descobertos no código" lista os módulos, as defesas, as tabelas e os jobs em tabelas.

Limites: a montagem precisa estar numa linha só (`app.use('/x', ..., roteador)`). Uma montagem escrita em várias linhas aparece com o prefixo da própria rota. "Sem proteção vista" é pergunta, não veredito: rotas de recuperação de senha ou de convite costumam ser públicas por desenho.

## Modelo vivo: quando o código muda

A cada `lastro threat-model --write`, o kit grava no `.lastro/threat-model.json` uma **assinatura da superfície**: módulos e quantidade de rotas, tabelas, armazenamento, tempo real, upload e hosts externos. Ela não guarda caminho de arquivo, valor nem segredo. A cada `lastro check`, a assinatura gravada é comparada com a do código de hoje, e o CORE-012 avisa em dois casos:

- **A superfície mudou desde a última gravação.** O aviso diz o que mudou, por exemplo "módulo novo /api/pagamentos (4 rotas); tabela nova: cartoes". Rode `lastro threat-model --write`: as ameaças novas entram como pendentes e as decisões existentes ficam.
- **A revisão é anterior à última mudança.** O campo `surface.changedAt` só anda quando a superfície muda de fato. A primeira gravação da assinatura não conta como mudança. Se `reviewedAt` for mais antigo que a mudança, alguém precisa revisar de novo e atualizar `reviewedAt`.

A revisão humana (`reviewedBy`, `reviewedAt` e as decisões) nunca é apagada nem alterada pelo kit.

## Rotas e middleware de autenticação

A descoberta liga a **montagem do roteador** ao arquivo das rotas: em `app.use('/api', requireAuth, require('./rotas'))` ou `app.use('/api', requireAuth, rotas)` (com `const rotas = require('./rotas')` ou `import`), as rotas de `rotas.js`, e as dos roteadores que ele monta, contam como "autenticação na montagem do roteador". Também vale `router.use(auth)` dentro do arquivo e `app.use(auth)` antes das rotas. Fica de fora o que o texto não mostra: importação dinâmica, fábrica de roteador com lógica própria e montagem em várias linhas. Isso é pista, não prova.

## Comandos

```bash
lastro threat-model                      # rascunho no terminal, sem gravar nada
lastro threat-model --out ameacas.md     # a seção de ameaças em Markdown
lastro threat-model --write              # grava .lastro/threat-model.json (as decisões já existentes são preservadas)
lastro report --out relatorio.html       # o relatório traz a seção "Modelo de ameaças" (rascunho ou revisado)
```

`.lastro/threat-model.json` guarda só o que é humano ou estável (ativos, decisões, probabilidade, quem revisou). O resto é recalculado a cada execução. Reexecutar `--write` acrescenta ameaças novas como pendentes e nunca apaga uma decisão. Um arquivo inválido é recusado e nunca é sobrescrito.

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-11-12T12:00:00.000Z",
  "reviewedBy": "Nome de quem revisou",
  "reviewedAt": "2026-11-12",
  "assets": [{ "id": "A-01", "name": "Dados pessoais de usuários", "kind": "dado", "source": "declarado" }],
  "threats": [
    { "id": "TM-E-auth", "decision": "mitigate", "likelihood": 3 },
    { "id": "TM-D-realtime", "decision": "accept", "rationale": "Uso interno, com poucos usuários e sem dado sensível.", "owner": "Nome", "expires": "2027-05-01" },
    { "id": "TM-D-uploads", "decision": "not_applicable", "rationale": "A aplicação não aceita arquivos nesta versão." }
  ]
}
```

## O que o modelo muda no resto do kit

- **CORE-012:** com o arquivo estruturado, só um modelo revisado e com todas as ameaças decididas passa. Rascunho falha (severidade alta), pendência falha (média), revisão vencida falha.
- **Análise de risco:** a `likelihood` informada na ameaça substitui a estimativa genérica dos controles que ela cita (o maior valor vence), e o relatório mostra o motivo. O teto "crítico exige evidência" continua valendo: o controle segue sem prova.
- **Backlog:** controles citados por uma ameaça marcada como `mitigate` ganham um nível de urgência, e o ticket cita a ameaça (campo `threat`).
- **Relatório:** seção própria, com ativos, descoberta, pistas e ameaças por superfície.

## Limites

- A descoberta é heurística de texto. **"Autenticação não vista" não quer dizer desprotegida**: o kit não liga uma rota ao middleware aplicado na montagem do roteador e não entende todo framework. É uma lista de pistas para revisar autorização (ASVS V8), não um veredito.
- O rascunho pergunta; não encontra falhas de lógica. Quem as encontra é a pessoa que responde às perguntas com o conhecimento do negócio.
- A descoberta cobre JavaScript, TypeScript e Python. Outras linguagens aparecem só pelo perfil e pelo catálogo.
- O STRIDE aqui organiza a conversa. Ele não substitui uma modelagem por diagrama de fluxo de dados quando o sistema é grande.
