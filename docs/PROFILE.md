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

## Campos opcionais

```json
{
  "urls": { "staging": "https://...", "production": "https://..." },
  "paths": { "health": "/health", "login": "/login" },
  "thresholds": { "hstsMinSeconds": 31536000, "threatModelMaxAgeDays": 180, "alwaysOnInstructionBytes": 8192 },
  "scan": { "excludePrefixes": ["fixtures/", "vendor-local/"] },
  "agent": { "instructionPaths": ["docs/agent/"] }
}
```

- `scan.excludePrefixes` tira pastas das varreduras de código e de mídia. Use só para fixtures de teste e código de terceiros. Cada exclusão é um ponto cego.
- `agent.instructionPaths` acrescenta pastas à lista de arquivos de instrução.
- Campo desconhecido é recusado, para evitar erro de digitação silencioso.
