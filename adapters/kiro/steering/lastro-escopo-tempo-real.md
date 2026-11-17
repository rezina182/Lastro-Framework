---
inclusion: fileMatch
fileMatchPattern: '**/*socket*'
---

# LASTRO: escopo de tempo real (WebSocket, SSE)

Você está mexendo em conexão de tempo real. Rode `lastro scope realtime`.

- **Origem verificada e sessão própria na conexão** (RT-004): confira o cabeçalho `Origin` e o token de sessão no handshake, sobre TLS.
- **Estado, tempo e segredos ficam no servidor** (RT-001): o cliente não decide pontuação, rodada nem resposta certa.
- **Limites de conexão** coerentes com a capacidade (RT-002) e **salas e sessões efêmeras** que expiram sozinhas (RT-003).
- **Mensagem malformada ou em excesso** não derruba o servidor: valide o formato e limite a taxa por conexão.

Teste com cliente que abre muitas conexões, manda mensagem inválida e tenta falar em sala de outro usuário.
