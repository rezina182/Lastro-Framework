# Glossário e legenda

Para quem lê a documentação ou um relatório do LASTRO sem conhecer o kit. Os relatórios trazem esta mesma legenda no final.

## Pacotes e prefixos dos controles

Todo controle tem um id com o prefixo do pacote: `CORE-012` é o controle 12 do pacote Base. Um pacote só se aplica quando o perfil (`.lastro/profile.json`) declara que a aplicação tem aquilo.

| Prefixo | Pacote | O que cobre | Quando se aplica |
|---|---|---|---|
| `CORE` | Base | O que vale para qualquer projeto: segredos fora do código, dependências, CI, injeção de SQL e de comando, criptografia, logs, modelo de ameaças e desenvolvimento com agente de IA | sempre |
| `WEB` | Aplicação web | Cabeçalhos de segurança, CSP, HSTS, erros que não vazam detalhe, métodos HTTP, CORS, cache e CSRF | `webApp` |
| `AUTH` | Autenticação e sessão | Login, senha, segundo fator, recuperação de conta, sessão, OAuth e OpenID, e autorização por função e por objeto | `hasAuth` |
| `PII` | Dados pessoais | Coleta mínima, retenção e exclusão, aviso de privacidade (inclusive de menores) e dado pessoal fora dos logs | `personalData` |
| `RT` | Tempo real | WebSocket, SSE e WebRTC: origem verificada, limites de conexão e salas que expiram | `realtime` |
| `UP` | Upload de arquivos | Tipo conferido pelo conteúdo, limites de tamanho, arquivo que nunca executa no servidor e arquivo compactado | `uploads` |
| `AST` | Ativos de mídia | Origem e licença de imagem, áudio, fonte e vídeo versionados no repositório | `thirdPartyAssets` |
| `AG` | Agente de código | Arquivos de instrução do agente de IA, hooks sem rede, segredos fora do alcance dele e revisão humana | `aiCodingAgents` |

O comando `lastro scope <pacote>` mostra só os controles de um pacote (`core`, `web`, `auth`, `pii`, `realtime`, `uploads`, `assets`, `agent`).

## Estados de um controle

| Estado | Significa |
|---|---|
| verificado | há prova: uma verificação automática passou, ou há atestação vigente de uma pessoa |
| falhando | a verificação encontrou o problema |
| sem prova | ninguém provou ainda; conta como zero e nunca como aprovado |
| não se aplica | o perfil diz que a aplicação não tem aquilo (por exemplo, sem upload) |

## Natureza do item

| Natureza | Significa |
|---|---|
| Risco de segurança | a falta do controle abre uma fraqueza que alguém pode explorar, ou expõe dado, código ou cadeia de suprimentos |
| Boa prática | hábito de processo ou governança que reduz a chance de falha futura ou ajuda a detectar e responder; a falta dele não é, sozinha, uma brecha |
| Qualidade | afeta manutenção, confiabilidade e clareza; vira risco só de forma indireta |

## Risco

Probabilidade (1 a 4: rara, possível, provável, quase certa) vezes impacto (1 a 4: pequeno, moderado, grande, severo). Crítico: 12 a 16, só com evidência. Alto: 8 a 11 (o que ninguém provou fica, no máximo, aqui). Médio: 4 a 7. Baixo: 1 a 3. Detalhes em [RISCO.md](RISCO.md).

## Pilares da segurança da informação

Confidencialidade, integridade, disponibilidade, autenticidade, irretratabilidade, privacidade, conformidade e auditabilidade. O significado de cada um está em [RISCO.md](RISCO.md).

## STRIDE

Seis categorias de ameaça, usadas no modelo de ameaças: **S** falsificação de identidade, **T** adulteração, **R** repúdio, **I** divulgação de informação, **D** negação de serviço, **E** elevação de privilégio. Detalhes em [THREAT-MODEL-ASSISTIDO.md](THREAT-MODEL-ASSISTIDO.md).

## Siglas

| Sigla | O que é |
|---|---|
| [ASVS](https://owasp.org/www-project-application-security-verification-standard/) | Application Security Verification Standard, da OWASP: lista de requisitos de segurança para aplicações |
| [CWE](https://cwe.mitre.org/) | Common Weakness Enumeration: catálogo de tipos de fraqueza (CWE-89 é injeção de SQL). Cada número leva à página oficial |
| [CVE](https://nvd.nist.gov/) | Identificador de uma vulnerabilidade conhecida em um produto ou biblioteca. Só faz sentido para dependências |
| GHSA | Aviso de segurança do GitHub. É o identificador que o `npm audit` informa, e a página dele traz o CVE |
| CVSS | Nota de 0 a 10 da gravidade técnica de uma vulnerabilidade conhecida |
| SSDLC | Ciclo de vida de desenvolvimento seguro: projeto, desenvolvimento, teste, entrega, operação e resposta a incidentes |
| [LGPD](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm) | Lei Geral de Proteção de Dados (Lei 13.709/2018). Os artigos citados indicam onde olhar, não são parecer jurídico |
| Portão de CI | A verificação que bloqueia a publicação quando aparece um achado novo, alto ou crítico. Não é nota da aplicação |
| Baseline | Dívida conhecida registrada: o portão passa a bloquear só o que for novo |
| Atestação | Declaração de uma pessoa, com responsável e validade, de que um controle manual está em dia. É autodeclaração |
| Fronteira de confiança | Ponto em que o dado passa de uma zona para outra com mais ou menos confiança |

## Identificadores

| Formato | O que é |
|---|---|
| `CORE-012`, `AUTH-027` | Controle do catálogo: prefixo do pacote e número |
| `TM-E-auth`, `TM-I-web` | Ameaça do modelo de ameaças: TM, categoria STRIDE e superfície |
| `F1`, `F2` | Fluxo no desenho da arquitetura |
| `A-01` | Ativo do modelo de ameaças |
| `T-0001` | Ticket do backlog (P0 é o mais urgente, P3 o menos) |
| `RISK-0001` | Risco aceito, com dono, aprovador e validade |
| `L-A05`, `L-B07` | Lição de origem: problema real que motivou o controle |
| `VULN:pacote` | Dependência com vulnerabilidade conhecida |

## Links para as fontes oficiais

Nos relatórios, cada CWE leva a `cwe.mitre.org`, cada CVE ao NVD e cada GHSA ao aviso no GitHub. Só endereços montados pelo kit, a partir de identificadores validados, viram link: nada que venha do projeto analisado vira link. Os relatórios continuam sem script, fonte ou imagem externa.
