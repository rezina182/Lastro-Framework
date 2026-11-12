# Registro de pesquisa

Este registro diz de onde vieram as ideias, quanto de cada fonte foi lido e quais limites existem. Ele existe para o catálogo não virar folclore. Conteúdo das fontes foi reescrito com palavras próprias. Cada controle cita apenas IDs e links.

Data da pesquisa: novembro de 2026.

## Fontes e profundidade de leitura

| Fonte | Uso | Leitura | Licença |
|-------|-----|---------|---------|
| OWASP ASVS 5.0.0 (CSV oficial, tag v5.0.0, sha256 `98c8fe91...cdcf680`) | Mapa dos 345 IDs e níveis; IDs citados nos controles | IDs e níveis conferidos por ferramenta; o texto dos requisitos foi lido só para classificar, nunca copiado | CC BY-SA: só IDs, texto próprio |
| NIST SP 800-218 (SSDF 1.1) | Alinhamento de práticas (PO, PS, PW, RV) | PDF lido por extração de texto | Domínio público (EUA) |
| NIST SP 800-218A | Perfil para IA generativa; PO.5.3 | PDF lido | Domínio público (EUA) |
| NIST SP 800-218 r1 (rascunho inicial) | PO.6 e PS.4 novos | Lido; é rascunho | Domínio público (EUA) |
| Google, Secure AI Agents | Regra de Dois, defesa híbrida, páginas citadas como p34 e p73 | PDF lido | Verificar antes de redistribuir |
| OpenSSF, guia de instruções de IA | Enforcement fora do modelo, pacotes alucinados, personas | Lido por inteiro | CC BY 4.0 (conferir na publicação) |
| OWASP Agentic Skills Top 10 (AST10) | IDs AST01 a AST10 | Documento principal lido; cerca de 30 arquivos secundários não lidos | CC BY-SA |
| OWASP Secure AI Agents (SAA) | Hooks que falham fechado | Lido via agentes de apoio | CC BY-SA |
| OWASP GenAI Data Security | Dados em sistemas de IA | Parte 1 lida; partes 4 e 8 não lidas | CC BY-SA |
| AWS Security Reference Architecture para agentes | Threat modeling no desenho | Página lida por inteiro | Verificar |
| Project CodeGuard (CoSAI/OASIS) | Regras para assistentes de código; benchmark | Repositório e benchmark lidos | CC BY 4.0 |
| Pesquisas de ataque (AGENTS.md, steering do Kiro, Rules File Backdoor, CVE-2026-10591) | Lições L-R01 e L-R04 | Lidas por agentes de apoio, resumos conferidos | Citadas por link |

## Lacunas de leitura (declaradas)

- Páginas da CISA retornaram 403 e não foram lidas.
- Uma página da AWS sobre padrão com MCP no Kiro não pôde ser lida.
- Páginas oficiais OWASP "Top 10 agentic": só o resumo foi lido.
- OWASP GenAI Data Security: partes 4 e 8 não lidas.
- OWASP ASI, documento de ameaças e mitigações (T1 a T15): não lido.
- Orientação do NIST sobre atestação: não lida.
- O NIST 800-218A trata de produtores de modelos, não de uso de agentes de código. O LASTRO usa só a prática PO.5.3 como referência de registro de ações.

## O que a pesquisa mostrou

- O que obriga deve ficar fora do modelo (OpenSSF, Google, OWASP).
- "Desconhecido não é aprovado" e declaração de quem escreveu nunca verifica (padrão visto em projetos de governança de SDLC com IA).
- Gate por baseline e delta (bloquear o novo) aparece em um projeto de governança; a combinação com risco aceito (dono, aprovador, validade) e backlog P0 a P3 não apareceu em nenhum dos sete projetos lidos.
- Arquivos de instrução são vetor de ataque: injeção por AGENTS.md, vazamento por steering com imagem, Unicode invisível.
- Personas em prompts rendem pior segundo a OpenSSF.
- No benchmark do CodeGuard, um prompt simples de segurança superou o conjunto de regras nos modelos testados.
- Rule of Two e "tríade letal" como critério de desenho de fluxos de agente.
- O rascunho do SSDF 1.2 acrescenta PO.6 e PS.4.

## Projetos vizinhos

- Project CodeGuard já distribui regras de segurança para vários assistentes. O LASTRO não reconstrói adaptadores desse tipo. A diferença está na verificação, no modelo de ameaças, na adoção e no registro de risco aceito. Exportar regras no formato do CodeGuard é uma possibilidade do roadmap.
- Nomes rejeitados na escolha do nome e o motivo estão no histórico do projeto: colisão com produtos ou projetos existentes.

## Regra de manutenção

Quando uma lição nova surge (incidente, achado de revisão, pesquisa), ela entra em `catalog/lessons.json` com ID `L-Axx`, `L-Bxx` ou `L-Rxx`, e vira ou reforça um controle. Controle sem lição de origem não passa na validação.
