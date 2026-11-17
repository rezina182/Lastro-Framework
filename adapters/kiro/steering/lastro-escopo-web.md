---
inclusion: fileMatch
fileMatchPattern: '**/*route*'
---

# LASTRO: escopo de rotas e aplicação web

Você está mexendo em rotas ou na camada HTTP. Rode `lastro scope web` e leia o que falha ou está sem prova.

- **Autorização em toda rota que lê ou altera dado de um usuário** (AUTH-027, AUTH-028): o servidor confere se aquele usuário pode acessar aquele objeto. Rota nova sem autenticação precisa de uma razão escrita (login, saúde, estáticos).
- **Validação de entrada no servidor, com lista de permissão** (CORE-041): tipo, tamanho e formato. Não confie no que o navegador já validou.
- **CSRF** (WEB-013) em rota que muda estado e usa cookie de sessão. **Erros genéricos** (WEB-007): nada de stack trace, caminho ou SQL na resposta.
- **Cabeçalhos e CORS** (WEB-001 a WEB-009): CSP sem `unsafe-inline`, CORS com lista de origens e sem curinga junto de credenciais.
- **Limite de requisições** (WEB-011) em rota cara ou sensível, com chave que o atacante não controla.

Escreva o teste que falha quando a proteção some. Ao terminar, rode `lastro scope web` de novo e relate o que mudou.
