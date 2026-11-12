# Roadmap

## Próximo (v0.2)

- Adaptador Kiro: steering por tipo de arquivo, hooks que falham fechado (sem rede) e skills de threat model e de adoção.
- Ferramenta de conferência de IDs de referência contra as fontes oficiais (ASVS CSV, SSDF), executada no CI.
- Tradução da documentação para inglês.
- Classificação do ASVS por capítulo (meta: L2), começando por V6/V7, V3, V8, V5, V13 e V16. Cada requisito passa a dizer se o controle o cobre por inteiro ou em parte, com a prova (teste que roda ou check).
- Escopos por assunto (`lastro scope auth`) e skills/steering do Kiro que carregam só o escopo em uso.
- Threat model estruturado (ameaça com ID, ativo, ASVS e controles) gerando tickets com o que mudar, como, a prova e a origem.
- Autoaplicação completa: atestações e backlog do próprio repositório.

## Depois

- Exportar regras no formato do Project CodeGuard.
- Análise de outros CIs (GitLab, Azure Pipelines, CircleCI).
- Pacote de SBOM por release e verificação do artefato.
- Verificações de código mais precisas (análise sintática em vez de padrão de texto) para JavaScript.
- Pacote de containers e infraestrutura como código.
- Saída SARIF para integrar a painéis de segurança.

## Pendências de pesquisa

Veja as lacunas de leitura em [RESEARCH-REGISTER.md](RESEARCH-REGISTER.md).
