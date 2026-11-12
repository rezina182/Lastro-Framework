# Registro de mudanças

Segue [SemVer](https://semver.org/lang/pt-BR/). O catálogo tem versão própria em `catalog/packs.json`.

## [0.1.0] - não publicado

### Adicionado
- Licença: Apache-2.0 para o código e CC BY 4.0 para a documentação.
- Catálogo com 62 controles em 8 pacotes e 37 lições de origem.
- Verificador com 18 verificações de repositório e 10 HTTP, CLI (`init`, `catalog validate`, `check`, `baseline`, `backlog`).
- Veredito `pass`, `fail` ou `incomplete`; baseline; riscos aceitos com validade; atestações com prazo.
- Modelo de ameaças do próprio kit, CI com Actions fixadas por SHA e varredura de segredos.
- Testes com `node:test` (catálogo, verificações, motor, cliente HTTP, CLI e autoverificação).
