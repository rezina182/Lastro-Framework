# Registro de mudanças

Segue [SemVer](https://semver.org/lang/pt-BR/). O catálogo tem versão própria em `catalog/packs.json`.

## [0.1.0] - não publicado

### Adicionado
- Mapa dos 345 requisitos do ASVS 5.0.0 (`catalog/asvs-map.json`), comando `lastro asvs` (cobertura por capítulo e nível, `--state`), `asvs verify` e `asvs sync`, e conferência no CI contra o CSV oficial com checksum fixo.
- Validação do catálogo: toda referência ASVS de um controle precisa existir no mapa.
- Licença: Apache-2.0 para o código e CC BY 4.0 para a documentação.
- Catálogo com 150 controles em 8 pacotes e 37 lições de origem.
- Classificação do ASVS concluída para todos os 17 capítulos até L2 (253 requisitos): V9 a V12, V14, V15 e V17 com 29 controles novos (AUTH-030 a AUTH-039, CORE-043 a CORE-058, WEB-021, RT-005 e RT-006). Cobertura: 253 com controle, 237 inteiros e 16 parciais.
- Novas flags de perfil `tokenAuth` (emite ou valida tokens autocontidos) e `oauthProvider` (atua como servidor de autorização). Perfis antigos precisam acrescentá-las.
- Classificação do ASVS também em V1, V2 e V4 (48 requisitos até L2): 20 controles novos (CORE-029 a CORE-042, WEB-017 a WEB-020, RT-004), com revisão independente aplicada.
- Classificação do ASVS também em V3, V5, V8, V13 e V16 (64 requisitos até L2): 22 controles novos (WEB-012 a WEB-016, UP-004 a UP-007, AUTH-026 a AUTH-029, CORE-020 a CORE-028). As sondas automáticas existentes ficam como `partial`, porque amostram a página inicial e não todas as respostas.
- Classificação do ASVS nos capítulos V6 e V7 até L2 (53 requisitos): 18 controles novos de autenticação e sessão (AUTH-008 a AUTH-025), com o teste que prova cada requisito. Referências ASVS ganham o campo opcional `covers` (`full` ou `partial`); sem ele a referência fica "não classificada".
- Nova flag de perfil `federatedLogin` (provedor de identidade externo), que ativa AUTH-020 e AUTH-021. Perfis antigos precisam acrescentá-la.
- Verificador com 18 verificações de repositório e 10 HTTP, CLI (`init`, `catalog validate`, `check`, `baseline`, `backlog`).
- Veredito `pass`, `fail` ou `incomplete`; baseline; riscos aceitos com validade; atestações com prazo.
- Modelo de ameaças do próprio kit, CI com Actions fixadas por SHA e varredura de segredos.
- Testes com `node:test` (catálogo, verificações, motor, cliente HTTP, CLI e autoverificação).
