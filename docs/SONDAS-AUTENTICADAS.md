# Sondas autenticadas (`lastro check --auth`)

As sondas comuns só fazem GET sem login. Por isso falhas de lógica, como "a conta A lê o pedido da conta B", ficavam só como pergunta no playbook. As sondas autenticadas entram com **duas contas de teste** e provam, de fora, o que só aparece depois do login.

| Controle | O que a sonda faz | Achado |
|---|---|---|
| AUTH-027 (acesso por objeto) | A conta A lê o objeto da conta B, e o contrário. Depois, um anônimo lê o objeto | Crítico se uma conta lê o objeto da outra. Alto se o anônimo lê |
| WEB-013 (CSRF) | Envia a requisição legítima e depois a mesma requisição com `Origin` de outro site e sem token | Alto se a forjada for aceita |
| AUTH-023 (logout) | Faz logout e reenvia o cookie antigo | Alto se o cookie antigo ainda vale |
| AUTH-003 (cookie de sessão) | O cookie do login entra na análise de cookies que já existia | Os achados de `Secure`, `HttpOnly`, `SameSite` e prefixo |
| AUTH-022 (token de sessão) | Reenvia o cookie de sessão com um caractere trocado; depois do logout, entra de novo levando o cookie antigo | Crítico se o cookie adulterado vale. Alto se o login novo mantém o mesmo valor (fixação de sessão) |
| WEB-010 (cache) | Lê o `Cache-Control` da rota `protected` com a sessão aberta | Médio se não houver `no-store` nem `private` |
| CORE-056 (campos devolvidos) | Lê a rota `protected` e os objetos da conta a e procura campos que nunca deveriam sair (hash de senha, segredo do MFA, token de troca de senha, chave de API) | Alto se algum aparece |
| AUTH-028 e CORE-056 (atribuição em massa) | Para cada rota de `massAssignment`, manda a edição legítima com campos extras (`role`, `isAdmin`, `ownerId`, `status`...) e relê o registro | Alto se algum campo extra voltou gravado |

A atribuição em massa grava na conta de teste a: depois de um achado, a conta pode ter ficado com `role: "admin"`. Recrie a conta antes de outros testes. Exemplo de configuração:

```json
"massAssignment": [{ "path": "/api/conta", "method": "PATCH", "body": { "nome": "Teste" }, "read": "/api/conta" }]
```

## Prova assistida dos controles manuais

Além das sondas autenticadas, o `lastro check` faz sozinho a parte automatizável de outros controles manuais. A regra é a mesma: **achou a falha, o controle falha** (com prova de máquina, que vale mais que uma atestação). **Passou, fica a nota "Prova parcial da máquina"**, que o playbook mostra em "O que a máquina já testou" e usa para pré-preencher a atestação. Passar não verifica o controle, porque o roteiro do catálogo pede mais do que a máquina consegue ver.

| Controle | Quando roda | O que a máquina faz | Achado |
|---|---|---|---|
| CORE-015 (testes no CI com banco real) | sempre (lê o repositório) | Procura nos workflows o passo de testes e um banco real (serviço do CI ou contêiner) | Médio: CI sem testes; médio: testes sem banco numa aplicação que usa banco |
| AG-001 e AG-007 (agente de IA) | sempre, se o perfil declara agentes | Procura hook de bloqueio ou regra `deny` para segredos e para a configuração do agente | Médio (não bloqueia): só instrução, sem mecanismo |

### Pedaços que a máquina prova por inteiro (controles automáticos próprios)

Quando a máquina consegue provar um pedaço do controle manual sem depender de pessoa, esse pedaço vira um **controle automático próprio**, que pode ser verificado e vale o peso inteiro na nota. O controle manual de origem continua com o resto. Cada pedaço segue um requisito do ASVS (com cobertura `partial`) e vale para qualquer aplicação com o recurso: as rotas vêm do perfil, nunca do kit.

| Controle automático | Pedaço de | Quando roda | O que prova | Falha |
|---|---|---|---|---|
| WEB-022 | WEB-016 | `--url` | GET em `/docs`, `/swagger.json`, `/openapi.json`, `/metrics`, `/actuator`, `/uploads/` e outros: nada exposto | Médio: documentação, métricas, diagnóstico ou listagem sem login |
| WEB-023 | WEB-018 | `--url` | A página inicial e uma rota inexistente têm Content-Type, com charset nas de texto | Médio: sem Content-Type; baixo: texto sem charset |
| AUTH-041 | AUTH-011 | `--url --active --confirm-non-production` e `authProbes.login` | Nenhuma de 8 credenciais padrão comuns entra | Crítico: alguma entra. Se o limitador cortar o teste antes do fim, fica sem prova |
| AUTH-040 | AUTH-016 | idem | O login limita tentativas erradas seguidas do mesmo endereço antes de 25 | Alto: 25 tentativas sem limite |
| AUTH-042 | AUTH-002 | sempre (lê o código) | bcrypt com custo 10 ou mais, Argon2, ou scrypt com N de 16384 ou mais | Alto: custo abaixo do mínimo |
| AUTH-043 | AUTH-011 e AUTH-012 | sempre (lê o código) | Nenhuma conta criada, semeada ou redefinida com senha fixa: constante de senha padrão (`SENHA_PADRAO`, `DEFAULT_PASSWORD`...) ou texto literal passados para a função de hash | Alto: senha fixa, com arquivo e linhas (o valor nunca é mostrado) |

O WEB-022 testa, além dos caminhos comuns, as rotas GET de métrica, diagnóstico e documentação que a descoberta acha no próprio código (por exemplo, `/api/metrics/internal`), até dez, sem parâmetro.

Há dois tipos de achado. **Falha medida** (custo do bcrypt, login sem limite, credencial padrão aceita, documentação exposta, cookie adulterado aceito) vence qualquer atestação. **Ausência suspeita** (a máquina não viu o hook do agente, os testes no CI ou o banco no CI) só vira achado quando ninguém atestou o controle: o mecanismo pode estar fora do repositório. Se alguém atestou, a atestação vale e o relatório mostra "A máquina não confirmou o que foi atestado", para a pessoa conferir.

As tentativas de login do AUTH-011 e do AUTH-016 podem disparar o limitador e o alarme do ambiente, e o endereço de quem testa pode ficar bloqueado por um tempo: rode só em local ou staging. Com `--active` ou `--auth`, o teto padrão de requisições sobe de 120 para 250.

## Como usar

1. Crie **duas contas de teste** no staging ou no ambiente local (nunca contas reais) e coloque os dados em variáveis de ambiente:

```bash
export LASTRO_A_USER=conta-teste-a   LASTRO_A_PASS='...'
export LASTRO_B_USER=conta-teste-b   LASTRO_B_PASS='...'
```

2. Declare as rotas em `.lastro/profile.json`. O perfil guarda só os **nomes** das variáveis, nunca a senha:

```json
{
  "authProbes": {
    "login": { "path": "/login", "format": "json", "userField": "username", "passwordField": "password" },
    "accounts": {
      "a": { "userEnv": "LASTRO_A_USER", "passwordEnv": "LASTRO_A_PASS" },
      "b": { "userEnv": "LASTRO_B_USER", "passwordEnv": "LASTRO_B_PASS" }
    },
    "protected": "/api/me",
    "logout": { "path": "/logout", "method": "POST" },
    "objects": [{ "path": "/api/orders/{id}", "ids": { "a": "1", "b": "2" } }],
    "csrf": [{ "path": "/api/profile", "method": "POST", "body": { "nome": "teste" } }]
  }
}
```

- `csrfToken` (opcional): quando a aplicação usa token anti-CSRF por sessão, diga em que campo do JSON do login ele vem e em que cabeçalho as escritas o mandam, por exemplo `{ "field": "csrfToken", "header": "X-CSRF-Token" }`. A requisição legítima e o logout levam o token. A forjada, não, porque outro site não consegue lê-lo. Sem declarar o token, a sonda de CSRF fica inconclusiva numa aplicação que o exige.
- `protected`: uma rota que exige sessão (200 logado, 401, 403 ou redirecionamento sem login).
- `objects`: rotas de **objetos privados**. `{id}` é trocado pelo identificador de cada conta. `ids.a` é um objeto da conta A, e `ids.b` é um objeto da conta B.
- `csrf`: rotas que mudam estado, com um `body` que o servidor aceita. Em JSON, o corpo pode ter listas e objetos (até 4000 caracteres). Em formulário, só valores simples. A sonda muda dados de verdade no staging.
- `logout` e `csrf` são opcionais. Sem rotas declaradas, o controle correspondente não é testado.

3. Rode, só em staging ou local:

```bash
lastro check --url https://staging.exemplo --auth --confirm-non-production
```

## Regras de segurança

- **Mesma trava das sondas ativas.** `--auth` exige `--url` e `--confirm-non-production` e é recusada contra `urls.production` do perfil. O aviso impresso antes lista o que será feito.
- **Contas de teste, descartáveis.** O kit se recusa a rodar com as duas contas iguais. Faltando variável, ele diz só o **nome** da variável que falta, nunca um valor.
- **Segredo não vaza.** Senha e cookie não entram em relatório, aviso ou mensagem de achado. Os testes conferem isso.
- **Ritmo e teto.** Todas as requisições passam pelo mesmo freio das demais (intervalo mínimo de 50 ms e teto de 120 requisições no total).
- **Mudam estado.** Login, logout e as rotas de `csrf` escrevem no ambiente. Use dados de teste.

## O que um resultado significa

- **Achou a falha:** o controle fica `failed`, com prova de máquina. Isso **vale mais que uma atestação**: se alguém atestou o controle e a sonda achou a falha, o controle falha. Um achado crítico ou alto novo bloqueia o portão de CI.
- **Passou:** o controle **não** vira `verified`. A sonda testou só as rotas que o perfil declara, e a nota diz isso. O controle continua dependendo de atestação. Desconhecido não é aprovado.
- **Inconclusivo:** login recusado, rota `protected` aberta a anônimos, objeto que a conta não consegue ler ou requisição legítima recusada. Nenhum achado é gerado, e a nota diz o motivo. Falha de configuração da sonda nunca vira "passou" nem "falhou".

## O que ela não prova

- **Só testa as rotas do perfil.** Uma rota esquecida não é testada.
- **AUTH-028 (acesso por campo e atribuição em massa), AUTH-024 (expiração por inatividade) e o resto dos controles de lógica** seguem como pergunta. Não há sonda para eles ainda.
- A resposta 2xx com texto curto de negação (por exemplo, `{"error":"Forbidden"}`) é tratada como negada. Uma API que devolve 200 com outro formato de erro pode gerar falso positivo: ajuste a rota ou use `lastro-ignore` no código.
- O CSRF avalia o servidor. Se o cookie tem `SameSite=Strict`, o navegador já não envia o cookie em requisição entre sites. A sonda ainda cobra a recusa no servidor, que é a defesa que não depende do navegador.
- Só login por usuário e senha em formulário ou JSON. Login federado (OIDC, SAML) não é suportado.

## Testado numa aplicação real (App B, 2026-11-17)

Num clone do App B, com o app local e banco descartável, duas contas de professor de teste e um quiz de cada:

| Controle | Antes (só sondas sem login) | Com `--auth` |
|---|---|---|
| AUTH-003 | sem prova (o cookie só aparece no login) | **verificado**: `__Host-` com `HttpOnly`, `Secure` e `SameSite=Strict` |
| AUTH-027 | sem prova | passou em 3 testes (conta A e B não leem o quiz uma da outra; anônimo recebe 401) |
| WEB-013 | sem prova | passou: a escrita de origem estranha e sem token foi recusada |
| AUTH-023 | sem prova | passou: o cookie antigo deixou de valer depois do logout |

O teste real achou duas falhas do kit, corrigidas antes da medição: a sonda de CSRF não sabia mandar o token anti-CSRF (ficaria inconclusiva numa aplicação bem protegida), e um logout recusado por falta do token virava falso positivo de "sessão não encerrada". Hoje, logout recusado é inconclusivo.

## Prova assistida testada no App B (2026-11-18)

No mesmo clone, com `--url --active --auth --confirm-non-production`, em 73 requisições:

- **13 controles manuais ganharam prova parcial da máquina**, sem nenhum falso positivo:
  - o login limitou as tentativas erradas (HTTP 429) na sétima tentativa seguida;
  - as credenciais padrão foram recusadas;
  - o cookie adulterado foi recusado e o login novo trocou o valor da sessão;
  - a rota autenticada respondeu com `no-store`, sem campo secreto na resposta;
  - nenhuma documentação ou listagem estava exposta;
  - o CI roda os testes com banco real;
  - o hash de senha é scrypt;
  - o hook do agente estava instalado.
- **CORE-017 virou verificado.**
- O relatório não trouxe senha nem cookie.

O teste mostrou três ajustes, já feitos:

- A força bruta passou a somar as tentativas do teste de contas padrão, que usam o mesmo limitador.
- A sonda de atribuição em massa passou a testar primeiro a edição legítima. Assim, uma recusa da edição com campos extras (validação estrita) conta como o comportamento certo, em vez de inconclusiva.
- O texto do hash de senha deixou de citar o limite do bcrypt quando a aplicação usa scrypt.

O limitador de login do App B fica em memória. Depois do teste de força bruta, o app foi reiniciado antes das execuções seguintes, porque o próprio limitador bloquearia o login das sondas.

## Segunda aplicação: App A (2026-11-18)

O App A tem outra estrutura de código: um `server.js` único com 140 rotas, `schema.sql`, sessão no banco e MFA por TOTP. O teste rodou num clone, com banco descartável próprio, duas contas de operador de teste e duas rodadas, reiniciando o app entre elas porque o limitador de login aceita 10 tentativas a cada 15 minutos. A primeira rodada usou `--active` e a segunda, `--auth`, ambas com `--delay 350` para respeitar o limite de 200 requisições por minuto da API.

**Achados reais, sem falso positivo:**

- **AUTH-043:** administrador inicial e redefinição de senha com a mesma senha fixa no código, em cinco lugares. O valor não aparece no relatório.
- **WEB-007:** JSON malformado devolve o stack trace e o caminho interno do servidor.
- **WEB-001:** a CSP permite `'unsafe-inline'` em scripts.
- **WEB-010:** a rota autenticada sai sem `no-store`.
- **WEB-013:** a edição do perfil aceita origem estranha sem token.
- **AUTH-003:** o cookie de sessão está sem prefixo `__Host-`.

**Passaram:**

- **AUTH-040:** o login limitou na 11ª tentativa, o que bate com o `max: 10` do código.
- **AUTH-041:** nenhuma credencial padrão comum entrou.
- **AUTH-042:** bcrypt com custo 10.
- **WEB-022:** 22 caminhos sem exposição, incluindo as rotas de diagnóstico achadas no código.
- **WEB-023:** Content-Type correto.
- **Sondas autenticadas:** o cookie adulterado foi recusado e o login novo trocou o valor da sessão. O logout encerrou a sessão no servidor e nenhum campo secreto apareceu nas respostas. A edição com `perfil: "admin"` e outros campos extras não gravou nada.

**O teste mudou o kit em quatro pontos, todos genéricos:**

- O `lastro init` passou a derivar o perfil do código. O perfil em branco deixava 78 controles de fora.
- Entrou o AUTH-043.
- O WEB-022 passou a testar as rotas de diagnóstico declaradas no código.
- O CSRF aceito com cookie `SameSite=Strict` ou `Lax` passou a ser médio, como defesa em profundidade, porque os navegadores atuais já barram o envio. Sem `SameSite`, ou com `None`, continua alto.

## Medido no banco de falhas

No `lastro bench`, as quatro falhas de lógica em execução (pedido legível sem login, nota fiscal de outra conta, POST de origem estranha e logout que não encerra a sessão) passam a ser **detectadas**, e as três gêmeas limpas passam sem falso positivo. Veja [BENCH.md](BENCH.md).
