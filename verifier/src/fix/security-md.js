'use strict';

// Modelo de SECURITY.md do lastro fix. Os campos que só uma pessoa sabe vêm marcados com LASTRO-PREENCHER, e o
// CORE-011 recusa o arquivo enquanto o marcador existir: modelo em branco não é canal de reporte (falha fechado).

const MARKER = 'LASTRO-PREENCHER';

const SECURITY_TEMPLATE = `# Política de segurança

Este arquivo diz como reportar uma vulnerabilidade neste projeto. Ele foi gerado como modelo pelo LASTRO e **precisa ser preenchido por uma pessoa** antes de valer: troque cada trecho marcado com ${MARKER}.

## Como reportar

- Contato de segurança: [${MARKER}: e-mail, formulário ou aviso privado do repositório que o time monitora].
- Não abra uma issue pública com detalhes de uma vulnerabilidade.
- Informe a versão afetada, os passos para reproduzir e o impacto que você percebeu.

## O que esperar

- Confirmação de recebimento em até [${MARKER}: prazo, por exemplo 5 dias úteis].
- Um prazo combinado de correção e de divulgação, de acordo com a gravidade.

## Versões com suporte

[${MARKER}: liste as versões que recebem correção de segurança].
`;

module.exports = { MARKER, SECURITY_TEMPLATE };
