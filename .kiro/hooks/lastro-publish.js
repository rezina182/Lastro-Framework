#!/usr/bin/env node
'use strict';

// Hook do Kiro (PreToolUse, ferramenta de terminal): bloqueia comandos que PUBLICAM vindos do agente: git push,
// abertura, merge ou aprovação de PR pela CLI do GitHub, e publicação de pacote. O agente prepara a branch e a
// descrição; quem publica é a pessoa, no próprio terminal.
//
// Saída 2 bloqueia o comando e o motivo vai para stderr (formato documentado do Kiro). Sem dependências e sem rede.
// Entrada que não é JSON ainda é conferida como texto. Se este script falhar, o Kiro segue: a trava de verdade é a
// proteção de branch do repositório, e a regra também está no steering e nas permissões do agente LASTRO.

const PUBLISH = [
  // "git push", inclusive com opções globais antes (git -c x=y push, git -C dir push); "git stash push" não publica.
  { re: /\bgit\s+(?:(?:-c|-C)\s+\S+\s+|--?[\w-]+(?:=\S+)?\s+)*push\b/i, what: 'git push' },
  { re: /\bgh\s+pr\s+(create|merge|review|ready)\b/i, what: 'gh pr' },
  { re: /\bgh\s+release\s+create\b/i, what: 'gh release create' },
  { re: /\bgh\s+api\b[^\n]*\b(pulls|merges|releases)\b/i, what: 'gh api (PR, merge ou release)' },
  { re: /\b(npm|pnpm|yarn)\s+publish\b/i, what: 'publicação de pacote' },
];

function commandOf(input) {
  try {
    const j = JSON.parse(input);
    const ti = j && j.tool_input;
    if (ti && typeof ti === 'object') return [ti.command, ti.cmd, ti.script].filter((v) => typeof v === 'string').join('\n') || JSON.stringify(ti);
    return JSON.stringify(j);
  } catch (e) {
    return input;
  }
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => { input += c; if (input.length > 1024 * 1024) process.exit(0); });
process.stdin.on('end', () => {
  const cmd = commandOf(input);
  const hit = PUBLISH.find((p) => p.re.test(cmd));
  if (!hit) process.exit(0);
  process.stderr.write(`LASTRO: o agente não publica (${hit.what}). Revise a branch e a descrição do PR, e rode o comando você mesmo no seu terminal. Veja a skill lastro-pr.\n`);
  process.exit(2);
});
