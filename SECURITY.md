# Política de segurança

## Como reportar uma vulnerabilidade

Se você encontrou uma vulnerabilidade no LASTRO (no verificador, no catálogo ou nos arquivos de CI), não abra uma issue pública.

- Use o recurso "Report a vulnerability" na aba Security do repositório (aviso privado do GitHub), ou
- escreva para o responsável pelo repositório (@rezina182) por mensagem privada no GitHub.

Informe a versão afetada, os passos para reproduzir e o impacto que você enxerga.

## O que esperar

- Confirmação de recebimento em até 7 dias.
- Avaliação e plano de correção em até 30 dias, conforme a gravidade.
- Crédito no registro de mudanças, se você quiser.

## Escopo

O verificador roda localmente, sem dependências de execução, e só faz requisições HTTP à URL que você informa. Falhas que permitam executar código, ler arquivos fora da pasta analisada, ou enviar dados a terceiros estão no escopo.

Falsos negativos do catálogo (um controle que deveria acusar uma falha e não acusa) também são bem-vindos como relatos comuns, em issue pública.
