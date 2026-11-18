# Pontuação de maturidade

O relatório do LASTRO traz uma nota de 0 a 10 e percentuais. Esta página explica como eles são calculados, para que ninguém precise confiar em um número sem saber de onde ele vem.

## O que a pontuação mede

**Evidência verificável de que os controles aplicáveis estão atendidos.** Ela não mede a segurança da aplicação. Uma aplicação pode ter nota baixa e ser segura, só que ninguém provou, e uma nota alta pode esconder um risco que o catálogo ainda não cobre.

## Como é calculada

1. Entram só os controles **aplicáveis** ao perfil. O que não se aplica fica de fora.
2. Cada controle pesa pela gravidade: crítica 8, alta 5, média 3, baixa 1.
3. Só o estado **verificado** vale ponto. **Sem prova** e **falhando** valem zero: desconhecido não é aprovado.
4. O que está verificado se divide em:
   - **por máquina**: o verificador provou (varredura do repositório ou sonda HTTP);
   - **autodeclarado**: há atestação em `.lastro/status.json`, com responsável e validade de até 366 dias.
5. Os percentuais são fatias do peso total aplicável: provado (máquina mais autodeclarado), falhando e sem prova. Somam 100%.

O mesmo cálculo é feito por pacote (base, web, autenticação etc.), para mostrar onde está a lacuna.

## Nota de 0 a 10

O número do LASTRO é uma **nota de 0 a 10**. Ela usa os pesos e os estados acima.

| Nota | Como se calcula |
|---|---|
| **Postura** | Do peso que já tem resposta (verificado ou falhando), quanto passou: `10 × verificado / (verificado + falhando)`. Responde "quando olhamos, estava certo?". Sem nada decidido, fica `n/d`. |
| **Cobertura** | Quanto do peso aplicável tem prova (máquina ou atestação): `provado% / 10`. Responde "quanto já olhamos?". |
| **Nota geral** | Média das duas: `0,5 × postura + 0,5 × cobertura`. Sem postura, vale só a cobertura. |

**Prova parcial da máquina (método `v3`).** Quando a máquina testa parte de um controle manual e passa (prova assistida ou sonda autenticada, veja [SONDAS-AUTENTICADAS.md](SONDAS-AUTENTICADAS.md)), o controle continua "sem prova", mas ganha **metade do peso** na cobertura e na postura. Exemplo: a sonda provou que o login limita tentativas do mesmo endereço, mas não provou o limite por conta. O "peso provado" (`provenPct`) não muda: só conta o que foi provado por inteiro. O relatório mostra a fatia em `partialPct` e `partialControls`. O caminho para o crédito inteiro é separar o pedaço testável num controle automático próprio, que pode ser verificado de verdade.

A nota geral tem **teto** quando o portão falha, para que um número alto nunca esconda um bloqueio:

- algum achado **crítico** bloqueante: no máximo **4**;
- qualquer outro achado bloqueante: no máximo **6**.

O relatório diz quando o teto foi aplicado e por quê.

| Faixa | Nome |
|---|---|
| 0 a 3,9 | Inicial |
| 4 a 5,9 | Em evolução |
| 6 a 7,9 | Bom |
| 8 a 8,9 | Forte |
| 9 a 10 | Exemplar |

Cada escopo (pacote) e cada fase do SSDLC também têm nota, com a mesma média e **sem teto** (o teto é do portão, que é geral). Assim fica claro qual escopo puxa a nota para baixo.

No JSON: `score.grade`, `score.gradeBand` e `score.grades` (`overall`, `band`, `posture`, `coverage`, `cap`, `capReason`); `byPack[].grade` e `byPhase[].grade`. O histórico (`.lastro/history`) grava `grade` a partir desta versão; registros antigos, sem o campo, continuam válidos e aparecem como `n/d`.

Como no resto da pontuação, a nota mede **evidência**, não segurança. Uma nota 3 pode ser de uma aplicação segura que ninguém provou; uma nota 9 cobre só o que o catálogo cobre. Os pesos, as fórmulas e as faixas são convenção do kit, não padrão de mercado.

## Próximo passo

O relatório diz o que falta para a **próxima faixa** da nota. Exemplo: "Para chegar a 8,0 (Forte): provar mais controles (a cobertura está em 4,5 de 10; comece pelos 3 altos ou críticos sem prova ou falhando)". Com bloqueante, o próximo passo é sempre corrigir ou aceitar o bloqueante, porque enquanto ele existir a nota fica no teto.

O campo `score.method` do relatório JSON identifica a versão do cálculo:

- `v4`: só a nota de 0 a 10;
- `v3`: prova parcial com metade do peso;
- `v2`: primeira nota de 0 a 10;
- `v1`: níveis de 0 a 4, descontinuados.

O histórico ainda lê registros antigos que têm só o nível.

## Por que a nota está baixa (`lastro gaps`)

A causa mais comum de nota baixa não é código ruim: é falta de prova. A maior parte do catálogo (121 dos 159 controles) depende de um teste ou de uma decisão de uma pessoa, e sem atestação cada um conta zero. `lastro gaps` mostra a conta:

- quantos controles manuais estão sem atestação, e por qual caminho cada um pode ser provado: **sonda do kit**, **sonda com duas contas de teste**, **leitura do código** (com confirmação de uma pessoa), **configuração da plataforma** ou **pessoa** (processo ou documento);
- quais **provavelmente não se aplicam** à tecnologia da aplicação, para alguém confirmar e registrar "não se aplica" com justificativa (sai da conta até o prazo vencer);
- quais já têm **indício no código** (por exemplo, biblioteca de hash de senha, limitador de requisições, TOTP), o que encurta a atestação;
- quais controles automáticos não rodaram por falta de `--url`;
- quais falhas bloqueiam o portão, quais pedem só revisão e quais aparecem só em arquivos de teste.

Indício não é prova, e "provavelmente não se aplica" não é decisão: nada disso muda a nota até uma pessoa testar ou registrar a justificativa. O relatório e o portal mostram o mesmo resumo em "Por que a nota está assim".

## Como interpretar

- **Quase todo controle do catálogo é manual**, então no começo a nota é baixa para qualquer aplicação. Isso é esperado: ela sobe quando as atestações com evidência são registradas.
- **Autodeclarado vale menos que provado por máquina** no critério de confiança, mesmo contando igual no percentual. Por isso o relatório mostra as duas fatias separadas.
- **Quem escreveu o código não deve ser o único a atestar** controles de nível alto (lição L-B10). Uma nota inflada por autoatestação não prova nada.
- **A nota depende do perfil.** Marcar flags como `false` para fugir de controles melhora o número e piora a segurança. Revise o perfil com outra pessoa.
- **Compare com a mesma versão do catálogo.** Um catálogo novo pode trazer controles novos e derrubar a nota sem que nada mude na aplicação.

## Contexto: nem toda aplicação precisa do mesmo rigor

O relatório estima o **risco inerente** da aplicação a partir do que o perfil declara, e a partir dele sugere uma **meta de maturidade**. A meta não muda quais controles se aplicam (isso é papel dos flags do perfil). Ela diz quanto de evidência é razoável esperar.

| Fator declarado no perfil | Pontos |
|---|---|
| Exposição à internet, dados pessoais, dados de menores, servidor de autorização OAuth | 2 cada |
| Login, usuários anônimos, upload, tempo real, tokens, agentes de IA no desenvolvimento | 1 cada |

| Pontos | Risco inerente | Meta padrão |
|---|---|---|
| 0 a 3 | baixo | nota 6 (Bom) |
| 4 a 7 | moderado | nota 7 |
| 8 ou mais | alto | nota 8 (Forte) |

O perfil pode sobrescrever o risco e a meta quando quem conhece a aplicação discorda da estimativa:

```json
{ "context": { "criticality": "high", "targetGrade": 7.5 } }
```

`criticality` aceita `low`, `medium` ou `high`. `targetGrade` vai de 0 a 10. Perfis antigos com `targetLevel` (0 a 4) continuam valendo: o valor é convertido para a nota (0, 4, 6, 8 e 9). O relatório mostra de onde veio cada valor.

O escopo também depende do contexto: o relatório lista os pacotes que ficaram fora porque o perfil declara que a aplicação não tem aquele recurso. Um perfil que subdeclara a aplicação melhora o número e piora a segurança.

## Aderência por fase do ciclo de vida (SSDLC)

Cada controle declara as fases em que atua: projeto, desenvolvimento, teste, entrega, operação e resposta a incidentes. O relatório mostra, por fase, a fatia do peso provado, falhando e sem prova. Um controle conta em todas as fases em que atua, então as fases não somam o total.

"Aderência" aqui é evidência por fase, não conformidade certificada. O catálogo se alinha a práticas como o NIST SSDF e ao OWASP ASVS, mas o kit não certifica nada.

## Fatos de engenharia

Para a conversa sobre qualidade de desenvolvimento, o relatório lista fatos objetivos que **não entram na pontuação**: volume de código e de testes, arquivos muito grandes, se o CI executa os testes e o lint, ferramentas configuradas, lockfile e documentação. O kit não mede qualidade de código com uma nota: a leitura e o julgamento são das pessoas.

## O que não usar a pontuação para fazer

- Certificar, auditar ou declarar conformidade com ASVS, SSDF ou qualquer padrão.
- Comparar aplicações de perfis diferentes como se fossem equivalentes.
- Cobrar uma meta numérica sem olhar quais controles estão abertos: a lista de controles sem prova e o próximo passo importam mais que o percentual.

## Taxa de aprovação dos controles automáticos

A cobertura depende de muita prova manual e por isso separa pouco duas aplicações que ainda não têm atestações. O relatório mostra também, à parte, o que a **máquina rodou**: quantos controles automáticos passaram, quantos falharam e a taxa de aprovação entre os que rodaram. Os que não rodaram (por exemplo, as sondas HTTP sem `--url`) ficam fora da taxa e nunca contam como aprovados. Sem nenhum controle automático rodado, não há taxa (nem 0%, nem 100%).

Esta taxa não é nota de segurança: um controle automático cobre um ponto estreito, e passar em todos não prova que a aplicação é segura.
