# Adoção em uma aplicação (nova ou existente)

## 1. Perfil honesto

```bash
node verifier/bin/lastro.js init --root /caminho/do/projeto
```

Edite `.lastro/profile.json` e marque só o que é verdade (veja [PROFILE.md](PROFILE.md)). Marcar `false` para fugir de controles é o jeito mais fácil de se enganar. Em caso de dúvida, marque `true`.

## 2. Primeira medição

```bash
node verifier/bin/lastro.js check --root /caminho/do/projeto
```

Em uma aplicação existente é normal o resultado ser `fail`. Isso é o retrato da dívida, não um castigo.

## 3. Threat model

Crie `docs/THREAT-MODEL.md` com a linha `Última revisão: AAAA-MM-DD`. Liste ativos, fronteiras de confiança, ameaças e o tratamento de cada uma. Use [THREAT-MODEL.md](THREAT-MODEL.md) deste repositório como exemplo. O verificador cobra revisão a cada 180 dias.

## 4. Baseline e backlog

```bash
node verifier/bin/lastro.js baseline --write   # registra a dívida atual
node verifier/bin/lastro.js backlog --write    # cria tickets P0..P3 em .lastro/backlog
```

- O baseline faz o portão bloquear só achados novos. Revise antes de gravar: cada item deve virar ticket ou risco aceito.
- A prioridade parte da severidade (crítica = P0). Sobe um nível de urgência se a aplicação não é pública e se o ticket é só "verificar" de camada 2 ou 3.
- Rodar `backlog` de novo não duplica tickets abertos.

## 5. Risco aceito

Quando não der para corrigir agora, crie `.lastro/risks/RISK-0001.json` com `control`, `fingerprints` do achado (aparecem no relatório), `owner`, `approvedBy`, `justification` (ao menos 20 caracteres), `createdAt` e `expires`. Vencido, o achado volta a bloquear.

## 6. Controles manuais

Para cada controle manual, execute o `howToVerify` do catálogo. Registre em `.lastro/status.json`:

```json
{
  "schemaVersion": 1,
  "attestations": {
    "CORE-014": {
      "state": "verified",
      "attestedBy": "Nome",
      "collectedAt": "2026-11-12",
      "expiresAt": "2027-05-12",
      "evidenceRef": "link ou caminho da evidência"
    }
  }
}
```

A validade máxima é de 366 dias. Quem escreveu o código não deve ser o único a atestar controles de nível alto.

Antes de atestar um por um, rode `lastro gaps`. Ele mostra por qual caminho cada controle manual pode ser provado (sonda do kit, sonda com duas contas, leitura do código, configuração da plataforma ou pessoa), os indícios que o código já mostra e os que **provavelmente não se aplicam** à tecnologia da aplicação (por exemplo, GraphQL sem nenhuma biblioteca de GraphQL). Para esses, depois de confirmar, registre "não se aplica" com a justificativa. O controle sai da conta até o prazo vencer:

```json
"WEB-020": {
  "state": "not_applicable",
  "attestedBy": "Nome",
  "collectedAt": "2026-11-18",
  "expiresAt": "2027-11-18",
  "note": "A aplicação não usa GraphQL em nenhum serviço."
}
```

`note` é obrigatório para "não se aplica" (ao menos 20 caracteres), para outra pessoa poder discordar. Ao vencer, o controle volta a contar como sem prova. O `lastro gaps` já imprime esse trecho pronto para os candidatos; troque o nome e revise o motivo antes de colar.

## 7. No CI

Rode `lastro check` a cada PR. `fail` (exit 1) bloqueia o merge. `incomplete` (exit 2) mostra o que falta provar; use `--allow-incomplete` enquanto as atestações não estiverem prontas.

## 8. Aplicação em execução

```bash
node verifier/bin/lastro.js check --url https://staging.exemplo
```

Verifique o ambiente de staging ou homologação, nunca a produção sem necessidade. Declare `urls.production` no perfil: assim o kit recusa sondas ativas contra ela. As sondas passivas usam só GET, com intervalo mínimo de 150 ms (`--delay`) e teto de 120 requisições.

Para as sondas ativas (TRACE, OPTIONS com Origin falsa, JSON malformado), use `--active --confirm-non-production`, e só em staging que você controla. Combine com a equipe: elas geram requisições incomuns que podem aparecer nos logs e nos alarmes. Não coloque isso em CI automático.
