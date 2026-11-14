# Arquitetura

## Visão geral

```
catalog/                       verifier/
  risk-map.json (natureza, pilares, CWE; ver src/risk.js e src/audit.js)
  packs.json   ─┐                bin/lastro.js   (CLI)
  lessons.json ─┼─ loadCatalog ─ src/catalog.js  (carga e validação cruzada)
  controls/*.json┘              src/engine.js    (perfil, aplicabilidade, veredito)
                                src/checks/      (registro: repo.* e http.*)
.lastro/ (no projeto alvo)      src/backlog.js   (lacunas → tickets P0..P3)
  profile.json                  src/report.js    (texto e Markdown; HTML em src/html.js; nota em src/score.js)
  status.json  (atestações)     src/http.js      (cliente HTTP limitado)
  baseline.json                 src/schema.js    (validadores, sem dependências)
  risks/*.json
  backlog/T-*.json
  assets.json
```

## Catálogo

Cada controle tem id (`CORE-001`, `WEB-003`...), severidade, camada (`tier` 1 a 3), fase, texto próprio, referências por ID e ao menos uma lição de origem. A validação cruzada garante:

- toda verificação automática citada existe, e toda verificação do registro é usada por algum controle;
- lição e controle se referenciam nos dois sentidos;
- todo pacote tem controles.

Pacotes: `core`, `web`, `auth`, `pii`, `realtime`, `uploads`, `assets`, `agent`. Um pacote só se aplica quando os flags do perfil o ativam.

## Fluxo de uma verificação

1. Carrega e valida o catálogo. Catálogo inválido interrompe com erro de configuração.
2. Carrega o perfil (`.lastro/profile.json`), o baseline, as atestações e os riscos aceitos. Arquivo inválido interrompe: nunca é ignorado em silêncio.
3. Para cada controle aplicável:
   - automático: executa a verificação; atestação é ignorada e gera aviso;
   - manual: só vale com atestação vigente (validade máxima de 366 dias).
4. Cada achado recebe uma impressão digital estável (`sha256(controle|chave)`, 16 hexadecimais). Ela liga o achado ao baseline e ao risco aceito.
5. Veredito:
   - `fail` se houver achado novo, alto ou crítico, fora do baseline e sem risco vigente;
   - `incomplete` se algum controle alto ou crítico estiver sem prova;
   - `pass` nos demais casos.

## Mapa e cobertura do ASVS

`catalog/asvs-map.json` lista os 345 requisitos do ASVS 5.0.0 com o nível mínimo de cada um (só IDs e nível, sem o texto da norma). Ele é gerado a partir do CSV oficial por `lastro asvs sync` e conferido por `lastro asvs verify`, que o CI roda contra o CSV da tag `v5.0.0` com checksum fixo. O CSV não é versionado.

- Toda referência `ASVS` de um controle precisa existir no mapa (validação offline do catálogo).
- `lastro asvs` calcula a cobertura por capítulo até o nível pedido: requisitos citados por verificação automática, só por controle manual, sem controle e não aplicáveis.
- Com `--state`, o comando roda o `check` e mostra, por requisito, se os controles ligados estão verificados, com falha, sem prova ou fora do perfil.
- Cada referência ASVS de um controle pode declarar `covers`: `full` (o teste do `howToVerify` prova o requisito inteiro) ou `partial`. Sem o campo, a referência é "não classificada" e não conta como cobertura inteira.
- Com `--state`, um requisito só aparece como verificado se um controle com `covers: full` está verificado e nenhum controle ligado a ele falhou.
- Limite atual: os 17 capítulos estão classificados até L2. A classificação foi feita pelo autor do kit e revisada por um agente separado; falta revisão humana. Sondas automáticas que amostram só a página inicial ficam como `partial`.

## Estados de um controle

`verified`, `failed`, `unverified` e `not_applicable`. Erro interno em uma verificação vira `unverified`.

## Segurança do próprio verificador

O verificador trata o alvo como entrada não confiável: só lê arquivos (limite de 2 MB cada), nunca os executa. Respostas HTTP têm limite de 10 s e 512 KB, não seguem redirecionamento para outra origem e não enviam credenciais. Detalhes em [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Camadas do kit

| Camada | Serve a | Conteúdo |
|--------|---------|----------|
| Núcleo | Qualquer ferramenta | Catálogo, verificador, processo |
| Adaptadores | Ferramentas específicas | `.kiro/` (Kiro) hoje; outros no roadmap |

O núcleo nunca depende de um adaptador. Os adaptadores só chamam o núcleo.
