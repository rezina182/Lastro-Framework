# Como contribuir

Antes de abrir um PR:

1. `npm test` e `npm run catalog:validate` passam.
2. Um controle novo tem: lição de origem (em `catalog/lessons.json`, nos dois sentidos), referência com ID conferido na fonte oficial, texto próprio em português e, se for automatizado, teste com caso bom e caso ruim.
3. Nenhuma dependência de execução nova. Se for indispensável, discuta antes e fixe a versão exata.
4. Texto de padrões (ASVS, SSDF, OWASP) não é copiado. Cite o ID e o link.
5. Nada de nomes de empresas ou apps reais nos exemplos. Use "App A" e "App B".
6. Sem caracteres invisíveis nos arquivos. Em testes, use escapes (`\u200b`).
7. Um PR não aprova a si mesmo: peça revisão de outra pessoa.

## Princípios de código

- Desconhecido nunca vira aprovado.
- Erro dentro de uma verificação vira `unverified`, não `verified`.
- O alvo analisado é entrada não confiável: leia, nunca execute.

Para vulnerabilidades, veja [SECURITY.md](SECURITY.md).
