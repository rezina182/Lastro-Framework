# Histórico e portal (`lastro history` e `lastro site`)

O relatório mostra uma foto. O histórico guarda as fotos ao longo do tempo, e o portal junta tudo em poucas páginas para quem desenvolve e para o time de segurança, sem servidor e sem script.

```bash
lastro history                 # compara agora com o último registro, sem gravar
lastro history --write         # grava o registro em .lastro/history/
lastro site --out ../portal    # gera o portal (index.html, relatorio.html, playbook.html, historico.html)
lastro site --out ../portal --theme meu-tema.css --redact "Empresa X,Produto Y"
```

## O histórico

Cada `lastro history --write` grava um arquivo pequeno em `.lastro/history/` com: data, versões do kit e do catálogo, portão de CI, nível de maturidade, percentuais (provado, máquina, atestado, falhando), taxa dos automáticos, contagem de risco confirmado e potencial, ameaças e o **estado de cada controle**.

- **Só números, IDs e estados.** Nada de caminho de arquivo, mensagem de achado, URL ou segredo. Por isso o histórico pode ser versionado e publicado como artefato do CI.
- **Nunca sobrescreve.** Dois registros no mesmo segundo ganham sufixo.
- **Registro inválido é ignorado com aviso**, nunca entra no gráfico.
- Onde gravar: a cada release, ou num job agendado do CI. Gravar a cada PR enche o histórico de ruído.

## O portal

| Página | Para quem | O que mostra |
|---|---|---|
| `index.html` | dev e segurança | **Agora:** portão, maturidade, peso provado (com a diferença desde o último registro), automáticos, risco e ameaças. **Para quem desenvolve:** o que bloqueia, como corrigir e o próximo passo. **Para segurança:** atestações que vencem em 30 dias, vencidas, riscos aceitos, dívida no baseline, ameaças sem decisão e tickets abertos por prioridade. **Evolução:** gráfico de provado e falhando |
| `relatorio.html` | todos | O relatório completo de hoje (o mesmo do `lastro report`) |
| `playbook.html` | quem testa e atesta | Os roteiros dos controles manuais sem prova |
| `historico.html` | segurança e liderança | Todos os registros e o que mudou desde o anterior: controles que pioraram, melhoraram, entraram e saíram |

Regras de segurança do portal:

- **Sem script, sem servidor, sem recurso externo.** Cada página tem CSP `default-src 'none'`. O gráfico é SVG estático.
- **Links em lista fechada.** Entre páginas, só para as quatro páginas do próprio portal. Para fora, só para as fontes oficiais que os relatórios já usam (CWE, CVE, GHSA, ASVS e LGPD).
- **Tudo que vem do projeto é escapado.** Os testes conferem com um nome de perfil que contém HTML.
- **Não apaga nada que não seja dele.** O comando só grava numa pasta nova, vazia ou que já seja um portal (tem o marcador `.lastro-site`) e só com os nomes das quatro páginas.
- **Para compartilhar:** `--redact` troca os termos por `[omitido]` em todas as páginas, inclusive no histórico.

## No CI

Um job agendado pode rodar `lastro history --write` e `lastro site --out portal`, e publicar a pasta como artefato ou numa página interna. O portal não precisa de login porque não tem formulário nem ação: só leitura. Ainda assim, ele descreve fraquezas da aplicação. Publique só onde o time de segurança e o time dono têm acesso.

## Limites

- O portal não decide nada. Atestar, aceitar risco e decidir ameaças continuam sendo feitos nos arquivos de `.lastro/`, por uma pessoa (ou pelo agente, com a confirmação dela).
- Números de versões diferentes do catálogo não são comparáveis: a página de histórico avisa quando o catálogo mudou entre dois registros.
- O gráfico mostra evidência, não segurança. Uma linha subindo quer dizer mais prova, não "mais seguro".
