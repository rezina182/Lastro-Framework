# Histórico e portal (`lastro history` e `lastro site`)

O relatório mostra uma foto. O histórico guarda as fotos ao longo do tempo, e o portal junta tudo em poucas páginas para quem desenvolve e para o time de segurança, sem servidor e sem script.

```bash
lastro history                 # compara agora com o último registro, sem gravar
lastro history --write         # grava o registro em .lastro/history/
lastro site --out ../portal    # gera o portal (seis páginas, veja a tabela abaixo)
lastro site --out ../portal --theme meu-tema.css --redact "Empresa X,Produto Y"
```

## O histórico

Cada `lastro history --write` grava um arquivo pequeno em `.lastro/history/` com: data, versões do kit e do catálogo, portão de CI, nível de maturidade, nota de 0 a 10 (campo `grade`, opcional para registros antigos), percentuais (provado, máquina, atestado, falhando), taxa dos automáticos, contagem de risco confirmado e potencial, ameaças e o **estado de cada controle**.

- **Só números, IDs e estados.** Nada de caminho de arquivo, mensagem de achado, URL ou segredo. Por isso o histórico pode ser versionado e publicado como artefato do CI.
- **Nunca sobrescreve.** Dois registros no mesmo segundo ganham sufixo.
- **Registro inválido é ignorado com aviso**, nunca entra no gráfico.
- Onde gravar: a cada release, ou num job agendado do CI. Gravar a cada PR enche o histórico de ruído.

## O portal

| Página | Para quem | O que mostra |
|---|---|---|
| `index.html` | dev e segurança | **Agora:** uma frase-resumo, a nota de 0 a 10 (com a diferença desde o último registro), portão, maturidade, peso provado, automáticos, risco e ameaças. **A história desta versão:** quatro listas, [descritas abaixo](#a-história-dos-resultados). **Para quem desenvolve:** o que bloqueia, como corrigir e o próximo passo. **Para segurança:** atestações que vencem em 30 dias, vencidas, riscos aceitos, dívida no baseline, ameaças sem decisão e tickets abertos por prioridade. **Evolução:** gráfico de provado e falhando |
| `escopos.html` | dev, segurança e liderança | **O que já está implementado, por escopo** (base, web, autenticação, dados etc.): a nota de cada escopo e, para cada controle, a situação (implementado, falhando, falta provar), **como foi provado** (leitura do repositório, sonda HTTP, ou atestação com quem, quando e até quando) e o próximo passo |
| `decisoes.html` | segurança e liderança | **Registro de decisões:** atestações, riscos aceitos, a revisão do modelo de ameaças e a decisão de cada ameaça, com quem e até quando (avisa o que vence em 30 dias). **Decisões pendentes:** o que alguém ainda precisa decidir |
| `relatorio.html` | todos | O relatório completo de hoje (o mesmo do `lastro report`), que também abre com "Em resumo" |
| `playbook.html` | quem testa e atesta | Os roteiros dos controles manuais sem prova |
| `historico.html` | segurança e liderança | Todos os registros e o que mudou desde o anterior: controles que pioraram, melhoraram, entraram e saíram |

Regras de segurança do portal:

- **Sem script, sem servidor, sem recurso externo.** Cada página tem CSP `default-src 'none'`. O gráfico é SVG estático.
- **Links em lista fechada.** Entre páginas, só para as seis páginas do próprio portal. Para fora, só para as fontes oficiais que os relatórios já usam (CWE, CVE, GHSA, ASVS e LGPD).
- **Tudo que vem do projeto é escapado.** Os testes conferem com um nome de perfil que contém HTML.
- **Não apaga nada que não seja dele.** O comando só grava numa pasta nova, vazia ou que já seja um portal (tem o marcador `.lastro-site`) e só com os nomes das seis páginas.
- **Para compartilhar:** `--redact` troca os termos por `[omitido]` em todas as páginas, inclusive no histórico.

## A história dos resultados

O relatório (HTML e Markdown) e o portal abrem com a mesma narrativa, montada só com o que o relatório já tem:

| Parte | O que entra |
|---|---|
| **Já foi feito** | Controles provados pela máquina e por atestação; escopos com todos os controles provados; ameaças mitigadas; revisão do modelo de ameaças; o que melhorou e se a nota subiu desde o registro anterior (só no portal, que tem o histórico) |
| **Precisa de atenção** | O que piorou; controles falhando que não bloqueiam (gravidade menor, baseline ou risco aceito); atestações que vencem em 30 dias ou já venceram; mudança na superfície do código desde o modelo de ameaças; ameaças expostas; sondas HTTP que não rodaram; troca de versão do catálogo |
| **O que fazer agora** | Cada bloqueante com a correção; aviso quando `lastro fix` resolve; os controles altos e críticos sem prova (playbook); o próximo passo da maturidade |
| **O que alguém precisa decidir** | Revisar o modelo de ameaças; ameaças sem decisão; aceitações que vencem; dívida no baseline; aceitar ou corrigir bloqueantes; a meta de maturidade |

Cada lista mostra até oito itens e diz quantos ficaram de fora.

Comparar execuções de tipos diferentes engana. Se a anterior rodou as sondas HTTP (`--url`) e esta não, o que virou "sem prova" não piorou, só não foi medido agora. Esses controles aparecem num aviso próprio, e não em "Pioraram", e o card de diferença avisa a troca. Para acompanhar a evolução, grave o histórico sempre com o mesmo tipo de execução (por exemplo, o job agendado com `--url` em staging). Em "O que fazer agora", cada bloqueante traz o motivo concreto do achado (por exemplo, "o modelo de ameaças é um rascunho"); o texto genérico do catálogo só entra quando o achado não diz nada. A narrativa não cria prova nem muda estado: se um controle não tem evidência, ele aparece como "falta provar", mesmo que o código pareça certo.

## No CI

Um job agendado pode rodar `lastro history --write` e `lastro site --out portal`, e publicar a pasta como artefato ou numa página interna. O portal não precisa de login porque não tem formulário nem ação: só leitura. Ainda assim, ele descreve fraquezas da aplicação. Publique só onde o time de segurança e o time dono têm acesso.

## Limites

- O portal não decide nada. Atestar, aceitar risco e decidir ameaças continuam sendo feitos nos arquivos de `.lastro/`, por uma pessoa (ou pelo agente, com a confirmação dela).
- Números de versões diferentes do catálogo não são comparáveis: a página de histórico avisa quando o catálogo mudou entre dois registros.
- O gráfico mostra evidência, não segurança. Uma linha subindo quer dizer mais prova, não "mais seguro".
