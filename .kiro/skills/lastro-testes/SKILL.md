---
name: lastro-testes
description: Transforma controles manuais do LASTRO (acesso por objeto, CSRF, logout, cookies de sessão, validação de entrada) em testes automatizados no projeto. Use quando o pedido for escrever testes de segurança, cobrir o playbook ou provar um controle sem atestação.
---

# Testes automatizados a partir do playbook

Atestação é autodeclaração. Um teste que roda no CI é prova. Sempre que um controle manual puder virar teste, prefira o teste.

## Passos

1. Rode `lastro playbook --scope <escopo>` e escolha, com o usuário, os controles a cobrir. Comece pelos críticos e altos.
2. Leia como o projeto já testa (framework, pasta, como sobe o app e o banco de teste). Siga o mesmo padrão; não traga um framework novo.
3. Para cada controle, escreva o teste a partir do "passo a passo" e do "resultado esperado" do playbook, com as rotas reais do projeto. Exemplos:
   - **AUTH-027:** duas contas; a conta A lê e altera o objeto da conta B e precisa receber 403 ou 404.
   - **WEB-013:** requisição que muda estado, com cookie de sessão, de outra origem e sem token: precisa ser recusada.
   - **AUTH-023:** depois do logout, o cookie antigo não pode mais acessar uma rota protegida.
   - **AUTH-003:** o `Set-Cookie` do login tem `HttpOnly`, `Secure`, `SameSite` e prefixo `__Host-`.
4. Confirme que o teste **falha** quando o controle é removido (comente a checagem, rode, veja falhar, volte). Mostre isso ao usuário.
5. Rode a suíte inteira. Só considere pronto com ela verde.
6. Diga ao usuário que, com o teste no CI, ele pode registrar a atestação apontando o teste como evidência (`evidenceRef`). Você **não** escreve a atestação: proponha o texto e peça que ele confirme.

## Cuidados

- Contas, senhas e dados de teste são falsos e ficam no setup do teste, nunca em segredo real.
- Teste de segurança contra banco real e descartável, nunca contra o banco de desenvolvimento de alguém.
- Se a rota declarada nas sondas (`authProbes` do perfil) também puder ser testada, sugira declarar: `lastro check --auth` passa a provar de fora.
