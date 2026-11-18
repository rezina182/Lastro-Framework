---
inclusion: fileMatch
fileMatchPattern: '**/*.sql'
---

# LASTRO: escopo de dados e banco

Você está mexendo em esquema ou consulta SQL. Rode `lastro scope pii` se a aplicação trata dado pessoal, e `lastro scope core` para os controles de base.

- **Consultas parametrizadas sempre** (CORE-031, CORE-059). Nunca concatene nem interpole valor vindo do usuário, nem o nome de coluna ou de tabela sem lista de permissão.
- **Dado pessoal:** colete só o necessário (PII-001), defina retenção e exclusão (PII-002) e não grave dado pessoal nem segredo em log (PII-003). Se a coluna for dado de criança ou adolescente, ou dado sensível (saúde, biometria, religião, origem racial), avise o usuário: isso muda o impacto dos riscos e as obrigações da LGPD.
- **Senhas e tokens:** só o hash, nunca o valor (AUTH-002, AUTH-018).
- **Migração:** reversível quando possível, com backup antes de apagar ou alterar dado em produção.

Não rode migração contra produção sem o usuário confirmar o ambiente.
