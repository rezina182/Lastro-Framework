#!/usr/bin/env node
'use strict';

// Hook do Kiro (PreToolUse): pede confirmação do usuário antes de o agente mexer no que só uma pessoa deve decidir:
// atestações, riscos aceitos, decisões do modelo de ameaças e o baseline do LASTRO.
//
// Lê o JSON do evento na entrada padrão. Se o texto do evento citar um desses caminhos (ou o comando "baseline --write"),
// responde com permissionDecision "ask": o Kiro mostra a pergunta ao usuário. Em qualquer outro caso, não faz nada.
// Sem dependências e sem rede. Se o script falhar, o Kiro segue sem bloquear (limite do formato de hook): por isso a
// regra principal também está no steering "lastro-base.md" e a trava de verdade fica no CI.

const PROTECTED = /\.lastro[\\/](status\.json|risks[\\/]|threat-model\.json|baseline\.json|system\.json)|lastro(\.js)?\s+baseline\s+--write/i;

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => { input += c; if (input.length > 1024 * 1024) process.exit(0); });
process.stdin.on('end', () => {
  let text = input;
  try { text = JSON.stringify(JSON.parse(input)); } catch (e) { /* usa o texto bruto */ }
  if (!PROTECTED.test(text.replace(/\\\\/g, '\\'))) process.exit(0);
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      permissionDecision: 'ask',
      permissionDecisionReason: 'LASTRO: atestações, riscos aceitos, decisões do modelo de ameaças e baseline são decisões de uma pessoa. Confirme que foi você quem decidiu e que o texto está correto.',
    },
  }));
  process.exit(0);
});
