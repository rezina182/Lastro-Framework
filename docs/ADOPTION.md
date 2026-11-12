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

## 7. No CI

Rode `lastro check` a cada PR. `fail` (exit 1) bloqueia o merge. `incomplete` (exit 2) mostra o que falta provar; use `--allow-incomplete` enquanto as atestações não estiverem prontas.

## 8. Aplicação em execução

```bash
node verifier/bin/lastro.js check --url https://staging.exemplo
```

Prefira verificar o ambiente de homologação. Use `--active` somente em ambientes seus.
