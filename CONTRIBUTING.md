# Como contribuir

Antes de abrir um PR:

1. `npm test` e `npm run catalog:validate` passam.
2. Um controle novo tem: lição de origem (em `catalog/lessons.json`, nos dois sentidos), referência com ID conferido na fonte oficial, texto próprio em português e, se for automatizado, teste com caso bom e caso ruim.
3. Nenhuma dependência de execução nova. Se for indispensável, discuta antes e fixe a versão exata.
4. Texto de padrões (ASVS, SSDF, OWASP) não é copiado. Cite o ID e o link.
5. Nada de nomes de empresas ou apps reais nos exemplos. Use "App A" e "App B".
6. Sem caracteres invisíveis nos arquivos. Em testes, use escapes (`\u200b`).
7. Um PR não aprova a si mesmo: peça revisão de outra pessoa.

## A cada aplicação nova: enriquecer a base de conhecimento

Toda aplicação que passa pelo kit deixa lições. O ciclo é o mesmo para qualquer uma:

1. Rode o kit num clone (nunca no repositório original): `lastro init`, `lastro check` estático e, num ambiente local ou de staging, as rodadas com `--active` e com `--auth`.
2. Separe o que aconteceu em três grupos: o que a aplicação errou (achados confirmados), o que o kit errou (falso positivo, falso negativo, ruído, sonda que atrapalhou outra) e o que o ambiente impediu de testar.
3. Para cada item que ensina algo para outras aplicações, escreva uma lição em `catalog/lessons.json` com o id da fonte (`L-A..` para o App A, `L-B..` para o App B, uma letra nova para a próxima): o que aconteceu, por que importa e a lição, em texto próprio e sem nomes reais.
4. Ligue a lição aos controles que ela justifica, nos dois sentidos (`controls` na lição, `origin` no controle). Se a lição pede uma verificação que não existe, ela vira um controle novo ou uma sonda nova, com teste de caso bom e caso ruim.
5. Se o kit errou, a correção entra no mesmo PR, com um teste que reproduz o erro. O benchmark (`lastro bench`) não pode ganhar falso positivo.
6. Atualize `docs/ESTADO-E-PLANOS.md` com o resultado da rodada e o `CHANGELOG.md`.

## Princípios de código

- Desconhecido nunca vira aprovado.
- Erro dentro de uma verificação vira `unverified`, não `verified`.
- O alvo analisado é entrada não confiável: leia, nunca execute.

Para vulnerabilidades, veja [SECURITY.md](SECURITY.md).
