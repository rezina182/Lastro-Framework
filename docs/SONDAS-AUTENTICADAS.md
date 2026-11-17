# Sondas autenticadas (`lastro check --auth`)

As sondas comuns só fazem GET sem login. Por isso falhas de lógica, como "a conta A lê o pedido da conta B", ficavam só como pergunta no playbook. As sondas autenticadas entram com **duas contas de teste** e provam, de fora, o que só aparece depois do login.

| Controle | O que a sonda faz | Achado |
|---|---|---|
| AUTH-027 (acesso por objeto) | A conta A lê o objeto da conta B, e o contrário. Depois, um anônimo lê o objeto | Crítico se uma conta lê o objeto da outra. Alto se o anônimo lê |
| WEB-013 (CSRF) | Envia a requisição legítima e depois a mesma requisição com `Origin` de outro site e sem token | Alto se a forjada for aceita |
| AUTH-023 (logout) | Faz logout e reenvia o cookie antigo | Alto se o cookie antigo ainda vale |
| AUTH-003 (cookie de sessão) | O cookie do login entra na análise de cookies que já existia | Os achados de `Secure`, `HttpOnly`, `SameSite` e prefixo |

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

- `protected`: uma rota que exige sessão (200 logado, 401, 403 ou redirecionamento sem login).
- `objects`: rotas de **objetos privados**. `{id}` é trocado pelo identificador de cada conta. `ids.a` é um objeto da conta A, e `ids.b` é um objeto da conta B.
- `csrf`: rotas que mudam estado, com um `body` que o servidor aceita. A sonda muda dados de verdade no staging.
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

## Medido no banco de falhas

No `lastro bench`, as quatro falhas de lógica em execução (pedido legível sem login, nota fiscal de outra conta, POST de origem estranha e logout que não encerra a sessão) passam a ser **detectadas**, e as três gêmeas limpas passam sem falso positivo. Veja [BENCH.md](BENCH.md).
