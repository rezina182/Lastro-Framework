# Banco de falhas plantadas

Aplicações de exemplo, pequenas e neutras, com falhas **plantadas de propósito** e com gêmeas limpas. O comando `lastro bench` roda o kit contra elas e mede quantas falhas o kit pega, quantas viram pergunta (controle manual sem prova) e quantas ele perde, além dos falsos positivos nas aplicações limpas.

**Nada aqui é código para usar.** Os valores secretos são falsos. O repositório do kit exclui esta pasta do próprio `lastro check` (`scan.excludePrefixes`) e da varredura do gitleaks (allowlist em `.gitleaks.toml`).

| Pasta | O que é |
|---|---|
| `vuln-static/` | Código e CI com falhas de código, configuração e lógica. Só leitura estática. |
| `clean-static/` | Gêmea limpa: o mesmo tipo de código, escrito do jeito certo. Mede falso positivo. |
| `vuln-web/` | Servidor HTTP mínimo (só `node:http`) com falhas de cabeçalho, cookie, erro, CORS e lógica. |
| `clean-web/` | Gêmeo limpo do servidor. |
| `manifest.json` | Lista de falhas, o controle que deveria pegar cada uma e o resultado esperado hoje. |

Os servidores só sobem em `127.0.0.1`, numa porta livre sorteada, e são encerrados no fim. O resultado esperado (`expect`) de cada falha é a linha de base: se o kit piorar, o `bench` falha; se melhorar, ele avisa para você atualizar o manifesto.

Veja [docs/BENCH.md](../../docs/BENCH.md).
