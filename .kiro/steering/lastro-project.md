---
inclusion: always
---

# Regras do projeto LASTRO

- Documentação e mensagens em português do Brasil. Traduzir antes de publicar em inglês.
- Zero dependências de execução. Se precisar de uma, pergunte antes e fixe a versão exata.
- Neutralidade: nada de nomes de empresas ou apps reais. Use "App A" e "App B".
- "Desconhecido não é aprovado": um controle sem prova fica `unverified`, nunca `verified`.
- Falhar fechado: erro dentro de uma verificação não pode virar "passou".
- Todo controle novo precisa de lição de origem, referência com ID verificado e, se automatizado, teste com caso bom e ruim.
- Cite padrões (ASVS, SSDF, OWASP) só por ID e link. Escreva o texto com palavras próprias.
- Não coloque caracteres invisíveis em arquivos. Em testes, use escapes como `\u200b`.
- Rode `npm test` e `npm run catalog:validate` antes de dizer que terminou.
- Nunca faça commit nem push sem o usuário autorizar de forma explícita.
