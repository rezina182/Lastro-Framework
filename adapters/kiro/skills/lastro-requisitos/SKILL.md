---
name: lastro-requisitos
description: Requisitos de segurança de uma funcionalidade ANTES de escrever o código (aplicação nova ou funcionalidade nova). Use quando o pedido for criar ou desenhar login, cadastro, sessão, upload, API, pagamento, tempo real, dados pessoais ou permissões.
---

# Requisitos de segurança de uma funcionalidade

## Passos

1. Identifique o assunto e o escopo do kit: login, sessão e permissões → `auth`; páginas e API → `web`; arquivos → `uploads`; WebSocket ou SSE → `realtime`; dados pessoais → `pii`. Uma funcionalidade pode tocar mais de um.
2. Rode `lastro scope <escopo>` para cada um. Se o escopo não se aplica ao perfil, mostre os flags que faltam e pergunte se o perfil está certo.
3. Monte, para o usuário, um documento curto com:
   - **Requisitos:** um por controle aplicável, em linguagem de quem programa, com o ID (por exemplo AUTH-027) e o requisito ASVS citado pelo kit.
   - **Decisões de arquitetura:** o que precisa ser escolhido antes do código (onde a sessão vive, como a autorização por objeto é aplicada, qual biblioteca de hash de senha). Para cada uma, proponha uma opção e diga o motivo; quem decide é o usuário.
   - **Ameaças:** as categorias STRIDE da superfície (rode `lastro threat-model` se o projeto já tiver código).
   - **Testes que provam:** para cada requisito, o teste automatizado que falha se o controle sumir (por exemplo, "a conta A recebe 403 ou 404 ao ler o pedido da conta B").
4. Se o projeto usa specs do Kiro, ofereça colocar os requisitos e os testes na spec da funcionalidade.
5. Ao escrever o código, escreva os testes junto. Depois rode `lastro check` e, com o app local, `lastro check --url ... --auth --confirm-non-production` se a funcionalidade tiver login.

## Cuidados

- Não invente requisito: use os controles do kit. Se faltar algo que você julga importante, diga que é sugestão sua, fora do catálogo.
- Cite padrões só por ID. Não copie texto do ASVS.
- Requisito sem teste vira atestação manual: diga isso ao usuário.
