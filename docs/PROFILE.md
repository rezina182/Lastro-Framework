# Perfil (`.lastro/profile.json`)

Descreve a aplicação. Os flags decidem quais pacotes e controles se aplicam.

| Flag | Ativa | Marque `true` quando |
|------|-------|----------------------|
| `webApp` | pacote `web` | a aplicação serve páginas ou API por HTTP |
| `hasAuth` | pacote `auth` | há login ou sessão |
| `personalData` | pacote `pii` | a aplicação guarda dado pessoal |
| `realtime` | pacote `realtime` | usa WebSocket ou SSE |
| `uploads` | pacote `uploads` | aceita arquivos enviados por usuários |
| `thirdPartyAssets` | pacote `assets` | versiona mídia (áudio, imagem, fonte, vídeo) |
| `aiCodingAgents` | pacote `agent` | agentes de IA escrevem ou alteram código |
| `federatedLogin` | `AUTH-020` e `AUTH-021` | o login usa provedor de identidade externo (OIDC, SAML, SSO) |
| `tokenAuth` | `AUTH-030`, `AUTH-031`, `AUTH-034` | a aplicação emite ou valida tokens autocontidos (JWT e semelhantes) ou tokens de acesso OAuth |
| `oauthProvider` | `AUTH-035` a `AUTH-039` | a aplicação atua como servidor de autorização OAuth ou provedor OpenID |
| `anonymousUsers` | reservado | há usuários sem conta |
| `minorsData` | `PII-004` | há dados de crianças ou adolescentes |
| `publicInternet` | prioridade do backlog | a aplicação é acessível pela internet |

O pacote `core` sempre se aplica.

## Sondas autenticadas

O bloco opcional `authProbes` declara o login, os nomes das variáveis de ambiente com duas contas de teste e as rotas que as sondas autenticadas vão testar (`lastro check --auth`). Veja [SONDAS-AUTENTICADAS.md](SONDAS-AUTENTICADAS.md). O perfil nunca guarda senha, só o nome da variável.

## Campos opcionais

```json
{
  "urls": { "staging": "https://...", "production": "https://..." },
  "paths": { "health": "/health", "login": "/login", "api": "/api/status", "static": "/app.js" },
  "thresholds": { "hstsMinSeconds": 31536000, "threatModelMaxAgeDays": 180, "alwaysOnInstructionBytes": 8192 },
  "scan": { "excludePrefixes": ["fixtures/", "vendor-local/"] },
  "agent": { "instructionPaths": ["docs/agent/"] }
}
```

- `paths.api` e `paths.static` indicam uma rota de API e um arquivo estático reais. As sondas de cabeçalho (CSP, HSTS, nosniff, Referrer-Policy, frame-ancestors) também as consultam, além da página inicial, de um erro 404, da rota de saúde e do login. Sem elas, a amostra fica menor. A amostra reduz o ponto cego de cabeçalhos presentes só na home, mas não prova "todas as respostas".
- `context.criticality` (`low`, `medium` ou `high`) e `context.targetLevel` (0 a 4) sobrescrevem o risco inerente e a meta de maturidade que o relatório estima a partir dos flags. Veja [SCORE.md](SCORE.md).
- `context.sensitiveData` (`true` ou `false`) declara que a aplicação trata dado pessoal **sensível** (LGPD, art. 5º, II: saúde, biometria, origem racial, convicção religiosa e semelhantes). Junto com `personalData` e `minorsData`, sobe o impacto dos riscos de confidencialidade na [análise de risco](RISCO.md).
- `scan.safeFunctions` lista funções do projeto que escapam ou convertem a saída com segurança (por exemplo `brlFmt`). O CORE-009 já reconhece `escHtml`, `escapeHtml`, `esc`, `sanitize`, `DOMPurify.sanitize`, `encodeURIComponent`, `Number`, `parseInt` e `parseFloat`. Liste só funções que você revisou: uma função aqui deixa de ser acusada.
- `scan.excludePrefixes` tira pastas das varreduras de código e de mídia. Use só para fixtures de teste e código de terceiros. Cada exclusão é um ponto cego.
- `agent.instructionPaths` acrescenta pastas à lista de arquivos de instrução.
- Campo desconhecido é recusado, para evitar erro de digitação silencioso.
