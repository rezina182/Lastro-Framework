---
inclusion: always
---

# LASTRO neste projeto

Este projeto usa o LASTRO para desenvolver com segurança. Regras para o agente:

- Antes de dizer que terminou uma mudança, rode `lastro check` e leia o resultado. Um controle "sem prova" não é aprovado.
- Para trabalhar num assunto (por exemplo autenticação), rode `lastro scope auth` e siga só os controles daquele escopo.
- Nunca crie nem edite atestações em `.lastro/status.json`, riscos aceitos em `.lastro/risks/` nem decisões em `.lastro/threat-model.json` por conta própria. Quem atesta, aceita ou decide é uma pessoa; você pode propor o texto e pedir a confirmação.
- Quem escreveu o código não deve ser o único a atestar um controle de nível alto. Diga isso ao usuário quando pedirem a atestação.
- Não desligue verificação de certificado TLS, não use `eval` com entrada externa, não monte SQL por concatenação e não grave segredo no código, nem para teste.
- Não instale dependência nova sem conferir que o pacote existe e é o esperado. Nomes inventados por IA são uma via de ataque à cadeia de suprimentos.
- Nunca faça commit nem push sem o usuário autorizar de forma explícita.
- Verificações HTTP só em ambiente de staging ou local, nunca em produção, e sempre com aviso ao usuário antes.
