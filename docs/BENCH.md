# Banco de falhas plantadas (`lastro bench`)

O kit dizia onde era efetivo com base em duas aplicações reais. Isso não mede o que ele **deixa passar**. O banco de falhas plantadas mede: aplicações pequenas com falhas conhecidas, colocadas de propósito, e gêmeas limpas. A cada versão, o `lastro bench` diz quantas o kit pega.

```bash
lastro bench                       # roda o banco inteiro e compara com o esperado
lastro bench --only P-002,D-009    # só alguns casos
lastro bench --json --out b.json   # resultado em JSON
```

Sai com `1` se algum caso **piorou** em relação ao esperado, e com `0` nos demais casos. O `npm test` roda o banco inteiro, então uma regressão quebra o CI.

## O que é medido

| Resultado | Quando | Conta como |
|---|---|---|
| detectada | O controle esperado falhou e o achado aponta o ponto plantado (arquivo ou trecho da mensagem) | Recall |
| pergunta | O controle esperado ficou "sem prova" (controle manual): o kit cobra a verificação, mas não acha a falha | Cobertura, não recall |
| perdida | O controle passou, não se aplicou ou falhou em outro ponto | Lacuna |
| limpa | Na aplicação limpa, o controle ficou verificado | Precisão |
| falso positivo | Na aplicação limpa, o controle falhou | Erro do kit |
| não medida | Na aplicação limpa, o controle não rodou ou não se aplica | Erro do banco (piorou) |

- **Recall** = detectadas / plantadas. **Cobertura** = (detectadas + perguntas) / plantadas.
- Um controle que falhou **em outro ponto** não conta como detecção. Isso evita que um achado qualquer esconda a falha plantada.
- O resultado esperado de cada caso fica no manifesto (`expect`). Se o kit pegar algo que antes só virava pergunta, o bench avisa "melhorou" para você atualizar o esperado. Nunca rebaixe o esperado para fazer o bench passar: corrija o kit.

## O banco hoje

| Categoria | Casos | O que tem |
|---|---|---|
| Código | 11 | SQL por concatenação (com e sem aspas internas), template literal e f-string; `Math.random` para token; MD5 em senha; chave da AWS e senha literais; TLS desligado; `eval`; `innerHTML` |
| Configuração | 7 | Action por tag; workflow sem `permissions`; sem varredura de segredos; sem auditoria de dependências; sem SECURITY.md; sem modelo de ameaças; dependência com faixa e sem lockfile |
| HTTP | 11 | Cookie de sessão sem HttpOnly, SameSite e prefixo; sem CSP e sem diretivas complementares; sem nosniff; X-Powered-By; stack trace no erro; `.env` servido; CORS refletido com credenciais; `/health` com dados internos |
| Lógica | 6 | Acesso por objeto (estático e em execução); atribuição em massa; CSRF (estático e em execução); logout que não encerra a sessão |
| Limpas | 23 | Uma gêmea para cada controle acima |

Os servidores de teste (`vuln-web` e `clean-web`) usam só `node:http`. O bench os sobe em `127.0.0.1`, numa porta livre, com ambiente mínimo (sem herdar as variáveis do seu terminal), roda as sondas passivas e ativas contra eles e os encerra no fim. Nenhuma requisição sai da máquina.

## Primeira medição (v0.1.0, 2026-11-17)

| | Resultado |
|---|---|
| Recall geral | 29 de 35 (83%) |
| Código, configuração e HTTP | 29 de 29 (100%) |
| Lógica | 0 de 6 detectadas; as 6 viram pergunta; nenhuma perdida |
| Falsos positivos nas limpas | 0 de 23 |

A primeira execução achou uma falha do próprio kit: o CORE-059 não pegava a injeção clássica com aspas simples dentro do texto SQL (`"... name = '" + nome + "'"`). A regra foi corrigida e ganhou teste.

Leia o número com cuidado. As falhas de código e de configuração foram escritas por quem conhece as regras do kit, então 100% ali mostra que as regras funcionam nos casos óbvios, não que o kit pega variações. O número que importa é o da **lógica**: 0 de 6. É ele que as sondas autenticadas (plano 5.2) precisam subir.

## Como acrescentar um caso

1. Plante a falha num arquivo de `fixtures/planted/vuln-*`, com um comentário `FALHA PLANTADA (id)` e a CWE. Valores secretos sempre falsos.
2. Escreva a versão certa na gêmea limpa.
3. Acrescente as duas entradas em `fixtures/planted/manifest.json`: `id`, `app`, `kind`, `category`, `control`, `file` ou `messageIncludes`, `cwe`, `title` e `expect`.
4. Rode `lastro bench`. Se o kit não pegar, o caso entra com `expect: "missed"` ou `"question"` e vira item do roadmap. Não esconda a lacuna.

Falhas que valem plantar a seguir: variações das regras atuais (concatenação em várias linhas, ORM com SQL cru, segredo em YAML), upload sem limite, redirecionamento aberto, SSRF e as que vierem dos testes em aplicações reais.

## Limites

- O banco é pequeno e escrito por quem conhece o kit. Ele mede regressão e o tamanho da lacuna de lógica. Não prova a efetividade contra falhas desconhecidas.
- O resultado depende da versão do catálogo. Compare medições da mesma versão.
- A data de referência fica fixa no manifesto (`referenceDate`), para que prazos (revisão do modelo de ameaças) não mudem o resultado com o passar dos dias.
