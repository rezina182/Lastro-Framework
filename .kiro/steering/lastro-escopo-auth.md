---
inclusion: fileMatch
fileMatchPattern: '**/*auth*'
---

# LASTRO: escopo de autenticação, sessão e autorização

Você está mexendo em código de autenticação. Antes de mudar, rode `lastro scope auth` e leia os controles que falham ou estão sem prova.

Pontos que mais custam caro, nesta ordem:

1. **Autorização no servidor, por função e por objeto** (AUTH-027, AUTH-028, AUTH-029). Esconder um botão na interface não é controle. Para cada rota que lê ou altera dado de um usuário, confirme que o servidor confere se aquele usuário pode acessar aquele objeto.
2. **Sessão** (AUTH-022 a AUTH-025): token aleatório e forte, encerramento efetivo no logout, validade documentada, cookies com `Secure`, `HttpOnly` e `SameSite`.
3. **Força bruta e recuperação de senha** (AUTH-013, AUTH-016, AUTH-017): limite de tentativas, recuperação que não contorna o segundo fator.
4. **Senhas** (AUTH-002, AUTH-008): hash lento com sal (Argon2id, scrypt ou bcrypt), sem regra de composição, sem limitar o tamanho abaixo de 64 caracteres.

Escreva um teste que **falha** quando o controle some (por exemplo, um usuário tentando ler o objeto de outro e recebendo 403 ou 404). Teste que só passa no caminho feliz não prova nada.

Ao terminar, rode `lastro scope auth` de novo e relate o que mudou de estado. Não ateste controle manual por conta própria.
