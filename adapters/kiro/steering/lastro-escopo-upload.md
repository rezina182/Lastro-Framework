---
inclusion: fileMatch
fileMatchPattern: '**/*upload*'
---

# LASTRO: escopo de upload de arquivos

Você está mexendo em upload. Rode `lastro scope uploads`.

- **Tipo pelo conteúdo, não pela extensão nem pelo cabeçalho do cliente** (UP-001). Reprocesse imagens quando possível.
- **Limites** de tamanho, dimensão e memória (UP-002) e cota por usuário (UP-003).
- **Arquivo enviado nunca executa no servidor**, e o caminho de gravação vem de dado interno, nunca do nome enviado (UP-005). Gere o nome do arquivo no servidor.
- **Compactados** (UP-006): confira o tamanho descompactado e os caminhos internos antes de extrair.
- **Download** (UP-007): trate o nome do arquivo e entregue com tipo e cabeçalhos corretos, fora do domínio principal quando for conteúdo de usuário.

Teste com arquivo grande demais, tipo trocado e nome com `../`.
