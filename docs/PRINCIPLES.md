# Princípios

1. **O que obriga fica fora do modelo.** Instrução em texto orienta; hook, sandbox, CI e proteção de branch garantem. Um portão que depende de o modelo obedecer não é portão.
2. **Desconhecido não é aprovado.** Sem prova, o estado é `unverified`. O veredito `incomplete` existe para isso.
3. **Falhar fechado.** Erro, tempo esgotado ou resposta inesperada nunca contam como "passou".
4. **Quem escreve não aprova.** Autodeclaração não verifica controle automático. Atestação manual tem responsável e prazo.
5. **Bloquear o novo, rastrear o antigo.** O portão barra achado novo alto ou crítico. A dívida existente entra no baseline e vira ticket com prioridade.
6. **Risco aceito tem dono e validade.** Sem dono, justificativa e data de vencimento, não é aceite, é esquecimento.
7. **Arquivos de instrução são código não confiável.** Procure caracteres ocultos, exija dono de revisão, proíba rede em hooks, confira a integridade do kit instalado.
8. **Curto no contexto, forte na verificação.** Mantenha as instruções sempre ativas pequenas e invista em checagens determinísticas. Um prompt curto de segurança já rende bem; o ganho está em provar.
9. **Cada controle conta de onde veio.** Toda regra tem lição de origem e referência. Regra sem origem vira folclore.
10. **Alinhado a, nunca "em conformidade com".** O kit ajuda a se aproximar de SSDF, ASVS e outros. Não certifica.
11. **Neutro e sem dependências.** Nada preso a uma marca, uma ferramenta de IA ou um gerenciador de pacotes.
12. **Evidência fresca.** Threat model, atestações e riscos têm prazo e perdem validade.
13. **Teste dinâmico só com aviso, só fora de produção e com freio.** Verificação estática é o padrão. Quem toca a aplicação avisa antes, usa intervalo e teto de requisições, e as sondas ativas exigem confirmação explícita e nunca rodam contra a URL de produção do perfil. Nada que gere carga roda de forma automática.
