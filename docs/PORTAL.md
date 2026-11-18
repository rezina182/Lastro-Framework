# Histórico e portal (`lastro history` e `lastro site`)

O relatório mostra uma foto. O histórico guarda as fotos ao longo do tempo, e o portal junta tudo em poucas páginas para quem desenvolve e para o time de segurança, sem servidor e sem script.

```bash
lastro history                 # compara agora com o último registro, sem gravar
lastro history --write         # grava o registro em .lastro/history/
lastro site --out ../portal    # gera o portal (oito páginas, veja a tabela abaixo)
lastro site --out ../portal --theme meu-tema.css --redact "Empresa X,Produto Y"
```

## O histórico

Cada `lastro history --write` grava um arquivo pequeno em `.lastro/history/` com: data, versões do kit e do catálogo, portão de CI, nota de 0 a 10 (campo `grade`, opcional para registros antigos), percentuais (provado, máquina, atestado, falhando), taxa dos automáticos, contagem de risco confirmado e potencial, ameaças, que sondas rodaram (`http`, `active`, `auth`) e o **estado de cada controle**.

- **Só números, IDs e estados.** Nada de caminho de arquivo, mensagem de achado, URL ou segredo. Por isso o histórico pode ser versionado e publicado como artefato do CI.
- **Nunca sobrescreve.** Dois registros no mesmo segundo ganham sufixo.
- **Registro inválido é ignorado com aviso**, nunca entra no gráfico.
- Onde gravar: a cada release, ou num job agendado do CI. Gravar a cada PR enche o histórico de ruído.

## O portal

| Página | Para quem | O que mostra |
|---|---|---|
| `index.html` | todos, para começar | **Visão geral, para ler em um minuto.** Os números grandes (nota de 0 a 10 com a meta, portão de CI, controles que bloqueiam, peso provado e controles sem prova), as **decisões para agora** (cada uma com quem decide, o que fazer, por quê e o link para o detalhe), a nota por escopo e os links para as outras páginas |
| `analise.html` | dev, segurança e liderança | **Análise completa**, no formato de relatório de maturidade (veja [a análise completa](#a-análise-completa)) |
| `mapa.html` | produto, negócio e quem não é técnico | **Mapa da aplicação** (veja [o mapa](#o-mapa-da-aplicação)): quem usa, as áreas, o que cada uma faz, que dados toca e o impacto de mudar cada dado. A visão geral traz o mesmo mapa no fim |
| `escopos.html` | dev, segurança e liderança | **O que já está implementado, por escopo** (base, web, autenticação, dados etc.): barras com a nota de cada escopo e, para cada escopo, quatro indicadores (nota, peso provado, falhando, falta provar) e cada controle com a situação (implementado, falhando, falta provar), **como foi provado** (leitura do repositório, sonda HTTP, ou atestação com quem, quando e até quando) e o próximo passo |
| `decisoes.html` | segurança e liderança | **Registro de decisões:** atestações, riscos aceitos, a revisão do modelo de ameaças e a decisão de cada ameaça, com quem e até quando (avisa o que vence em 30 dias). **Decisões pendentes:** o que alguém ainda precisa decidir |
| `relatorio.html` | todos | O relatório completo de hoje (o mesmo do `lastro report`), que também abre com "Em resumo" |
| `playbook.html` | quem testa e atesta | Os roteiros dos controles manuais sem prova |
| `historico.html` | segurança e liderança | Todos os registros e o que mudou desde o anterior: controles que pioraram, melhoraram, entraram e saíram |

Todas as páginas têm a mesma moldura: a faixa do topo com a navegação, o título e a **barra de filtros** (escopos aplicáveis, tipo de execução, data e hora em UTC, versão do catálogo).

### As decisões para agora (visão geral)

Até cinco cartões numerados, na ordem: corrigir o que bloqueia o portão (quem desenvolve); provar os controles altos e críticos sem prova (quem testa); confirmar o que provavelmente não se aplica (segurança); revisar o modelo de ameaças ou decidir as ameaças pendentes (segurança); confirmar a meta e o prazo (liderança). Cada cartão leva à página com o detalhe. Os cartões só organizam o que o relatório já tem: quem decide continua sendo uma pessoa.

### O mapa da aplicação

Um mapa conceitual desenhado a partir do código, para quem precisa entender a aplicação sem ler o código. As áreas ficam em **faixas por quem as usa** (visitante sem conta, pessoa logada, administração), e os dados à direita, na ordem que cruza menos linhas:

- **Quem usa:** uma faixa para cada tipo de pessoa. O visitante aparece sempre que alguma área tem ação sem autenticação vista, ligado a ela por uma linha tracejada vermelha: é por ali que qualquer pessoa entra.
- **Áreas da aplicação:** os grupos de rotas (`/api/contas`, `/api/admin`...), com a cor de quem pode usar (verde exige login, azul é pública, vermelho tem ação sem autenticação vista).
- **Dados guardados:** as tabelas das migrações SQL e os modelos do Prisma, em destaque quando guardam dado pessoal, com quantas áreas usam cada um, e os serviços externos que o código chama.

Sem script (a CSP do portal não permite), o mapa ainda responde ao leitor:

- **Passar o mouse** (ou o foco do teclado) numa área, num dado ou em quem usa apaga o resto e destaca só as ligações dele.
- **O balão** de cada área lista as rotas, com o método, o caminho e se exige login; o de cada dado lista as áreas que o usam.
- **Clicar numa área** leva ao cartão dela, logo abaixo, com a lista completa das rotas. Na visão geral, o clique abre a página do mapa já no cartão.

Abaixo do mapa, cada área em linguagem simples (o que dá para fazer: consultar, criar, alterar, apagar; quem usa; que dados toca) e a tabela **"Se eu mudar um dado, o que é afetado"**, com as áreas que usam cada dado. É a resposta para "onde uma funcionalidade nova pode ter impacto".

A ligação entre área e dado é um indício: o nome da tabela ou do modelo aparece no código das rotas da área (`prisma.conta`, `FROM contas`, `Conta.find`). O kit não segue importações, então uma área que passa por um serviço pode tocar dados que o mapa não mostra.

### A análise completa

Segue o formato de um relatório de maturidade em segurança:

| Seção | O que mostra |
|---|---|
| **Indicadores** | Quatro cartões: nota geral de 0 a 10 (faixa, meta, postura e cobertura), portão de CI, peso provado e o **maior gap** (o escopo com a menor nota). A diferença desde o último registro aparece em cada cartão; se a execução anterior foi de outro tipo (com e sem sondas HTTP), um aviso diz que a comparação mistura medidas diferentes |
| **Sumário executivo** | Um parágrafo com os números que importam: quantos controles e escopos, a nota, quanto tem prova (máquina, atestação, prova parcial), a meta, o que bloqueia, os três pontos mais frágeis e o escopo com o melhor e o pior resultado. Abaixo, **por que a nota está assim** (o mesmo do `lastro gaps`) |
| **Nota por escopo** e **Maturidade por fase do ciclo** | Barras lado a lado, de 0 a 10, coloridas pela faixa (verde a partir de 8, azul a partir de 6, âmbar a partir de 4, vermelho abaixo) |
| **Evolução** | Gráfico de provado e falhando ao longo do histórico |
| **Controles que exigem ação** | Até 12 controles em ordem de prioridade: bloqueantes, depois falhando, depois altos e críticos sem prova; com escopo, gravidade, situação e a primeira frase do próximo passo |
| **Controles prioritários: por que importam** | Até seis cartões com o **risco para o negócio** (o porquê do catálogo), **o que o kit encontrou** (o achado ou a situação da prova), o **impacto potencial** (os pilares afetados: confidencialidade, integridade, disponibilidade...) e **como corrigir** |
| **Em resumo** | A história em quatro listas ([descritas abaixo](#a-história-dos-resultados)) |
| **Para quem desenvolve** e **para o time de segurança** | Lado a lado. Dev: o que bloqueia, como corrigir e o próximo passo. Segurança: atestações que vencem em 30 dias e vencidas, riscos aceitos, dívida no baseline, risco confirmado e potencial, modelo de ameaças, verificações automáticas e tickets abertos por prioridade |

A paleta padrão do LASTRO é roxa com destaque âmbar, sobre fundo lavanda claro (com versão para o modo escuro). Para outra aparência, um arquivo de tema (`--theme`) redefine as variáveis de cor (`--brand` para a faixa do topo, `--highlight` para o sublinhado dos títulos, `--accent` para links e números, `--ok-fill`, `--warn-fill`, `--bad-fill` e `--info-fill` para as barras).

Regras de segurança do portal:

- **Sem script, sem servidor, sem recurso externo.** Cada página tem CSP `default-src 'none'`. O gráfico é SVG estático.
- **Links em lista fechada.** Entre páginas, só para as oito páginas do próprio portal (com ou sem âncora, como `analise.html#acao`). Para fora, só para as fontes oficiais que os relatórios já usam (CWE, CVE, GHSA, ASVS e LGPD).
- **Tudo que vem do projeto é escapado.** Os testes conferem com um nome de perfil que contém HTML.
- **Não apaga nada que não seja dele.** O comando só grava numa pasta nova, vazia ou que já seja um portal (tem o marcador `.lastro-site`) e só com os nomes das oito páginas.
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

Comparar execuções de tipos diferentes engana. Se a anterior rodou as sondas HTTP (`--url`), as ativas (`--active`) ou as autenticadas (`--auth`) e esta não, o que virou "sem prova" não piorou, só não foi medido agora. Esses controles aparecem num aviso próprio, e não em "Pioraram", e os indicadores avisam a troca. Para acompanhar a evolução, grave o histórico sempre com o mesmo tipo de execução (por exemplo, o job agendado com `--url` em staging). Em "O que fazer agora", cada bloqueante traz o motivo concreto do achado (por exemplo, "o modelo de ameaças é um rascunho"); o texto genérico do catálogo só entra quando o achado não diz nada. A narrativa não cria prova nem muda estado: se um controle não tem evidência, ele aparece como "falta provar", mesmo que o código pareça certo.

## No CI

Um job agendado pode rodar `lastro history --write` e `lastro site --out portal`, e publicar a pasta como artefato ou numa página interna. O portal não precisa de login porque não tem formulário nem ação: só leitura. Ainda assim, ele descreve fraquezas da aplicação. Publique só onde o time de segurança e o time dono têm acesso.

## Limites

- O portal não decide nada. Atestar, aceitar risco e decidir ameaças continuam sendo feitos nos arquivos de `.lastro/`, por uma pessoa (ou pelo agente, com a confirmação dela).
- Números de versões diferentes do catálogo não são comparáveis: a página de histórico avisa quando o catálogo mudou entre dois registros.
- O gráfico mostra evidência, não segurança. Uma linha subindo quer dizer mais prova, não "mais seguro".
