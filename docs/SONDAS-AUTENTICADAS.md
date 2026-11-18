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
| AUTH-002 (hash de senha) | sempre | Acha a biblioteca (bcrypt, Argon2, scrypt) e o custo no código | Alto: bcrypt com custo abaixo de 10, scrypt com N abaixo de 16384 |
| AG-001 e AG-007 (agente de IA) | sempre, se o perfil declara agentes | Procura hook de bloqueio ou regra `deny` para segredos e para a configuração do agente | Médio (não bloqueia): só instrução, sem mecanismo |
| WEB-016 (documentação e listagem expostas) | `--url` | GET em `/docs`, `/swagger.json`, `/openapi.json`, `/metrics`, `/actuator`, `/uploads/` e outros | Médio: documentação, métricas, diagnóstico ou listagem acessíveis sem login |
| WEB-018 (Content-Type) | `--url` | Lê a página inicial e uma rota inexistente | Médio: corpo sem Content-Type; baixo: texto sem charset |
| AUTH-011 (contas padrão) | `--url --active --confirm-non-production` e `authProbes.login` no perfil | Tenta 8 credenciais padrão comuns (admin/admin, root/root...) | Crítico: alguma entra |
| AUTH-016 (força bruta) | idem | 25 tentativas erradas seguidas numa conta inexistente | Alto: nenhum limite (nem 429, nem bloqueio, nem desafio) |

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

## Medido no banco de falhas

No `lastro bench`, as quatro falhas de lógica em execução (pedido legível sem login, nota fiscal de outra conta, POST de origem estranha e logout que não encerra a sessão) passam a ser **detectadas**, e as três gêmeas limpas passam sem falso positivo. Veja [BENCH.md](BENCH.md).
