# Roadmap

> A visão consolidada (estado atual, o que os testes reais mostraram, uso no dia a dia e a ordem dos próximos passos) está em [ESTADO-E-PLANOS.md](ESTADO-E-PLANOS.md). Este arquivo guarda o histórico item a item.

## Prioridades depois dos testes reais

Visão: o LASTRO como base do ciclo de desenvolvimento com IA, para aplicação nova (requisitos e desenho antes do código) e existente (medir, corrigir, governar). Detalhes em [ESTADO-E-PLANOS.md](ESTADO-E-PLANOS.md), seção 5.

1. Banco de falhas plantadas para medir o recall do kit a cada versão. Feito: `lastro bench` (35 falhas, 23 limpas; veja [BENCH.md](BENCH.md)). Falta: mais variações e falhas de upload, redirecionamento e SSRF.
2. Sondas autenticadas com contas de teste (cookies de sessão, logout, expiração, acesso por objeto entre duas contas, CSRF), só em local ou staging. Feito: `--auth` com cookie, acesso por objeto, CSRF e logout ([SONDAS-AUTENTICADAS.md](SONDAS-AUTENTICADAS.md)). Falta: AUTH-028 (acesso por campo), AUTH-024 (expiração), login federado e descoberta das rotas a partir do código.
3. Modo "corrigir": correções determinísticas numa branch própria, com teste verde e permissão antes do PR. Feito: `lastro fix` para CORE-006, CORE-010 e CORE-011, com descrição de PR ([CORRIGIR.md](CORRIGIR.md)). Falta: CODEOWNERS, dependência vulnerável, rascunho do modelo de ameaças, imagem Docker por digest, perfil automático para repositório sem `.lastro/` e abrir o PR pela CLI do GitHub depois de confirmação (fluxo AppSec para tech lead).
4. Fase de desenho: requisitos, decisões de arquitetura e testes por funcionalidade, antes do código (aplicação nova).
5. Agente do Kiro que conduz o ciclo nos fluxos "nova" e "existente" (verificar, corrigir, escrever os testes do playbook, preparar as decisões humanas) e pede permissão antes do PR.
6. Pipeline como produto: Action reutilizável, SARIF e comentário no PR.
7. Histórico em `.lastro/history/` e portal estático (`lastro site`) com a evolução, a arquitetura e o modelo de ameaças, com visão por papel (dev e segurança).
8. Revisão dos frameworks de mercado (AI-DLC, SAMM, OWASP LLM e Agentic, NIST AI RMF, ISO 42001, SLSA, Scorecard, SBOM), cada um com leitura da fonte oficial.

## Próximo (v0.2)

- Adaptador Kiro: steering por tipo de arquivo, hooks que falham fechado (sem rede) e skills de threat model e de adoção.
- Ferramenta de conferência de IDs de referência contra as fontes oficiais (ASVS CSV, SSDF), executada no CI.
- Tradução da documentação para inglês.
- Classificação do ASVS por capítulo (meta: L2). Feito: os 17 capítulos até L2. Próximos: os 92 requisitos exclusivos do L3 e a promoção de controles `partial` a `full`. Cada requisito diz se o controle o cobre por inteiro ou em parte, com a prova.
- Revisão independente da classificação de V6 e V7 (contexto separado de quem escreveu) e, quando possível, trocar controles manuais por testes automatizados de comportamento.
- Escopos por assunto, steering e hook de confirmação do Kiro: feito (`lastro scope`, `lastro adapter kiro`). Falta: bloquear (e não só perguntar) por hook, o que depende do formato de cada versão do Kiro e de teste dentro do Kiro.
- Modelo de ameaças de sistemas com vários repositórios: feito (`.lastro/system.json` e `lastro app`, com papéis identificados pelo código). Falta: clonar os repositórios de uma organização com credencial somente leitura e consentimento (hoje a pessoa clona), ler fluxos de Docker Compose, Terraform e Kubernetes, modelo de ameaças gravado por aplicação (hoje a decisão é por repositório) e ligar rotas a middleware em outros frameworks.
- Threat model estruturado. Feito: rascunho assistido (`lastro threat-model`), decisões em `.lastro/threat-model.json`, CORE-012 exigindo revisão, probabilidade alimentando o risco e prioridade dos tickets. Falta: fluxo de dados e fronteiras de confiança por diagrama, ligação de rota ao middleware aplicado na montagem do roteador (por framework, começando pelo Express) e skill do Kiro que conduz a revisão com a pessoa.
- Autoaplicação completa: atestações e backlog do próprio repositório.

## Verificações automáticas (em andamento)

1. Feito: amostragem de várias respostas nas sondas de cabeçalho.
2. Feito: trava das verificações dinâmicas (aviso, staging confirmado, intervalo e teto de requisições).
3. Feito: varreduras estáticas de SQL por concatenação, aleatoriedade e hash fracos e segredos no código (V1, V11 e V13). Rodam em cada PR e não tocam a aplicação. Fica de fora a detecção de rotas sem checagem de autorização (V8): ela depende do framework e uma heurística de texto genérica daria falsa sensação de segurança. Entra como análise por framework (começando pelo Express), ou não entra.
4. Aplicar o kit em um app real e comparar com o que o ASVS já corrigiu nele.
5. Opcional: sonda de TLS e outras sondas dinâmicas, sempre atrás da mesma trava das ativas e nunca automáticas. Só se houver demanda real.

## Depois

- Exportar regras no formato do Project CodeGuard.
- Análise de outros CIs (GitLab, Azure Pipelines, CircleCI).
- Pacote de SBOM por release e verificação do artefato.
- Verificações de código mais precisas (análise sintática em vez de padrão de texto) para JavaScript.
- Pacote de containers e infraestrutura como código.
- Saída SARIF para integrar a painéis de segurança.

## Pendências de pesquisa

Veja as lacunas de leitura em [RESEARCH-REGISTER.md](RESEARCH-REGISTER.md).
