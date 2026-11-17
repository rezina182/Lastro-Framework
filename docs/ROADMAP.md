# Roadmap

## Próximo (v0.2)

- Adaptador Kiro: steering por tipo de arquivo, hooks que falham fechado (sem rede) e skills de threat model e de adoção.
- Ferramenta de conferência de IDs de referência contra as fontes oficiais (ASVS CSV, SSDF), executada no CI.
- Tradução da documentação para inglês.
- Classificação do ASVS por capítulo (meta: L2). Feito: os 17 capítulos até L2. Próximos: os 92 requisitos exclusivos do L3 e a promoção de controles `partial` a `full`. Cada requisito diz se o controle o cobre por inteiro ou em parte, com a prova.
- Revisão independente da classificação de V6 e V7 (contexto separado de quem escreveu) e, quando possível, trocar controles manuais por testes automatizados de comportamento.
- Escopos por assunto e steering do Kiro: feito (`lastro scope`, `lastro adapter kiro`). Falta: hooks de bloqueio do agente (formato depende da versão do Kiro, testar antes) e escopos para web, tempo real e upload.
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
