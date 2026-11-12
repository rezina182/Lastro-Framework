# Registro de mudanças

Segue [SemVer](https://semver.org/lang/pt-BR/). O catálogo tem versão própria em `catalog/packs.json`.

## [0.1.0] - não publicado

### Adicionado
- Mapa dos 345 requisitos do ASVS 5.0.0 (`catalog/asvs-map.json`), comando `lastro asvs` (cobertura por capítulo e nível, `--state`), `asvs verify` e `asvs sync`, e conferência no CI contra o CSV oficial com checksum fixo.
- Validação do catálogo: toda referência ASVS de um controle precisa existir no mapa.
- Licença: Apache-2.0 para o código e CC BY 4.0 para a documentação.
- Catálogo com 80 controles em 8 pacotes e 37 lições de origem.
- Classificação do ASVS nos capítulos V6 e V7 até L2 (53 requisitos): 18 controles novos de autenticação e sessão (AUTH-008 a AUTH-025), com o teste que prova cada requisito. Referências ASVS ganham o campo opcional `covers` (`full` ou `partial`); sem ele a referência fica "não classificada".
- Nova flag de perfil `federatedLogin` (provedor de identidade externo), que ativa AUTH-020 e AUTH-021. Perfis antigos precisam acrescentá-la.
- Verificador com 18 verificações de repositório e 10 HTTP, CLI (`init`, `catalog validate`, `check`, `baseline`, `backlog`).
- Veredito `pass`, `fail` ou `incomplete`; baseline; riscos aceitos com validade; atestações com prazo.
- Modelo de ameaças do próprio kit, CI com Actions fixadas por SHA e varredura de segredos.
- Testes com `node:test` (catálogo, verificações, motor, cliente HTTP, CLI e autoverificação).
