# Análise de risco

O relatório do LASTRO separa três coisas que costumam aparecer misturadas e fazem tudo parecer igualmente urgente: **risco de segurança**, **boa prática** e **qualidade**. Só o risco de segurança recebe probabilidade, impacto e classe.

> A estimativa é transparente, não atuarial. Cada número traz o motivo no relatório. Sem modelo de ameaças, a probabilidade é uma suposição a partir do estado do controle e da exposição declarada no perfil.

## O que é cada coisa

| Natureza | Pergunta que responde | Exemplo | Se faltar |
|---|---|---|---|
| **Risco de segurança** | Alguém pode explorar isso, ou isso expõe dado, código ou cadeia de suprimentos? | SQL montado por concatenação (CORE-059), verificação de TLS desligada (CORE-007), Action fixada por tag (CORE-006) | Existe uma fraqueza concreta |
| **Boa prática** | Isso reduz a chance de falha futura ou ajuda a detectar e responder? | Modelo de ameaças (CORE-012), CODEOWNERS (AG-003), SECURITY.md (CORE-011) | Não é, sozinha, uma brecha, mas sem ela o risco cresce sem ninguém ver |
| **Qualidade** | Isso afeta manutenção, confiabilidade e clareza? | Teste para cada caso obrigatório (CORE-019), formato dos logs (CORE-024) | Vira risco só de forma indireta |

A classificação de cada controle está em `catalog/risk-map.json` (campo `kind`). É um julgamento do kit e pode ser revisto: a fronteira entre "segurança" e "boa prática" tem casos duvidosos, e o importante é que ela seja explícita e discutível.

## Probabilidade x impacto

Cada risco de segurança recebe probabilidade (1 a 4) e impacto (1 a 4). A classe sai do produto:

| Produto | Classe |
|---|---|
| 12 a 16 | Crítico |
| 8 a 11 | Alto |
| 4 a 7 | Médio |
| 1 a 3 | Baixo |

### Probabilidade

- **Confirmado** (o controle falhou): 3 se o achado é de gravidade alta ou crítica, 2 se média, 1 se baixa. Falha sem achado individual vale 3.
- **Potencial** (sem prova): 2, assumida. Não quer dizer que a falha exista: quer dizer que ninguém provou que não existe. O relatório marca esses itens como "potenciais" e os lista à parte.
- **Exposição** (campo `reach` de cada controle):
  - `internet`, fraqueza alcançável por requisição remota: soma 1 se o perfil declara `publicInternet` (só quando há evidência forte ou nenhuma prova; achado heurístico de gravidade média não sobe) e subtrai 1 se não declara;
  - `network`, exige posição privilegiada na rede (como interceptar o tráfego), e `internal`, depende de acesso interno ou de vazamento prévio: subtraem 1;
  - `pipeline`, ataca o desenvolvimento, o CI ou a cadeia de suprimentos: não muda com a exposição à internet.
- **Achado de varredura por heurística** (SQL, XSS, segredos) de gravidade média vale probabilidade 2: ele pede revisão humana, não é prova de exploração.
- **Crítico exige evidência**: um risco potencial (sem prova) nunca passa de "Alto" (produto máximo 11), por mais grave que seja o controle. Só um achado confirmado chega a "Crítico". Isso evita que cem controles não provados virem cem alarmes.

### Impacto

- Parte da gravidade do controle: crítica 4, alta 3, média 2, baixa 1.
- Soma 1 se o controle toca **confidencialidade ou privacidade** e o perfil declara `personalData`.
- Soma mais 1 se declara `minorsData` ou `context.sensitiveData` (dados de crianças e adolescentes, ou dados pessoais sensíveis).
- O teto é 4.

## Pilares da segurança da informação

Cada controle indica os pilares que a sua falta afeta. A literatura varia na lista; o kit adota estes oito e a lista pode ser ajustada em `verifier/src/risk.js`:

| Pilar | Significa |
|---|---|
| Confidencialidade | só quem deve ver, vê |
| Integridade | o dado e o código não mudam sem autorização |
| Disponibilidade | o serviço e os dados estão disponíveis quando precisam |
| Autenticidade | quem diz ser alguém, é |
| Irretratabilidade | quem fez uma ação não consegue negar depois |
| Privacidade | dados pessoais tratados com finalidade, minimização e direitos do titular |
| Conformidade | atende leis, contratos e licenças |
| Auditabilidade | dá para reconstruir o que aconteceu |

O relatório mostra, por pilar, quantos itens abertos o tocam e a pior classe de risco de segurança.

## Privacidade e LGPD

Se o perfil declara `personalData`, `minorsData` ou `context.sensitiveData`, o relatório ganha uma seção que lista os itens que tocam dado pessoal: os controles de privacidade e os de confidencialidade de natureza de segurança. Cada item indica a base na LGPD quando há uma:

- art. 6º, III (necessidade), art. 14 (crianças e adolescentes), art. 15 e 16 (término do tratamento), art. 18, VI (eliminação);
- art. 46 (medidas de segurança) para os controles técnicos de confidencialidade;
- art. 48 (comunicação de incidente à ANPD e ao titular) como nota geral.

Isto aponta onde olhar. Não é parecer jurídico nem substitui a avaliação do encarregado de dados.

## CWE, CVE e dependências vulneráveis

- **CWE**: cada controle de segurança aponta as CWE do tipo de fraqueza que a sua falta permite (por exemplo, CWE-89 para SQL, CWE-79 para XSS). Controles de processo não têm CWE, de propósito: forçar uma seria inventar.
- **ASVS**: cada item mostra os requisitos do ASVS que o controle cobre.
- **CVE**: CVE é identificador de uma vulnerabilidade **em um produto**, então só faz sentido para dependências. Use `--audit-file` com o resultado do `npm audit --json` (rodado por você, quando e onde decidir: o comando envia a lista de pacotes ao registro do npm). O kit lê GHSA, CWE e CVSS. O `npm audit` não informa o CVE; ele aparece quando já está no título do aviso, e do contrário está na página do aviso do GitHub. Cada pacote vulnerável entra na lista de riscos como risco confirmado.

O arquivo é tratado como dado não confiável: tamanho e quantidade são limitados, textos são limpos e só links de avisos do GitHub são mantidos como identificador.

## O que o modelo de ameaças muda

Sem modelo, a probabilidade é genérica. O modelo de ameaças assistido ([THREAT-MODEL-ASSISTIDO.md](THREAT-MODEL-ASSISTIDO.md)) é o que a torna específica: a `likelihood` que uma pessoa informa numa ameaça substitui a estimativa genérica dos controles que a mitigam. Em geral, o modelo:

- diz **quem** ataca e **por onde** (fronteiras de confiança, pontos de entrada), então a probabilidade deixa de depender só da exposição declarada;
- encontra riscos de **desenho** que nenhuma varredura vê: autorização, lógica de negócio, abuso de fluxo. Foram essas as falhas que mais custaram nos aplicativos reais que originaram o kit;
- liga cada ameaça (STRIDE) a pilares, a requisitos do ASVS e a CWE, e vira ticket com critério de aceite;
- transforma CORE-012, hoje boa prática pendente, em controle verificado.

## Limites

- A classe é uma ferramenta de **priorização**, não uma medida de dano.
- "Potencial" é suposição declarada, não achado.
- A classificação por natureza, pilar e CWE é um julgamento do kit, revisável em `catalog/risk-map.json`.
- Perfil que subdeclara a aplicação (sem `publicInternet`, sem `personalData`) reduz o risco no papel e não na realidade.
