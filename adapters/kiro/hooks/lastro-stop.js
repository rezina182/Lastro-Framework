#!/usr/bin/env node
'use strict';

// Hook do Kiro (Stop): quando o agente termina, roda o lastro check (só leitura, sem rede). Se houver achado NOVO,
// alto ou crítico, devolve {"decision":"block"} para o agente continuar e tratar o achado, uma vez por sessão, para
// não entrar em ciclo. Fora isso, não faz nada.
//
// O CLI vem de LASTRO_CLI (caminho do verifier/bin/lastro.js do kit) ou do pacote instalado no projeto. Sem CLI,
// sem perfil (.lastro/profile.json) ou com qualquer erro, o hook sai sem bloquear: ele lembra, não é o portão.
// O portão de verdade é o lastro check no CI.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const MAX_LINES = 8;

function findCli(root, env) {
  if (env.LASTRO_CLI && fs.existsSync(env.LASTRO_CLI)) return env.LASTRO_CLI;
  try { return require.resolve('lastro-framework/verifier/bin/lastro.js', { paths: [root] }); } catch (e) { return null; }
}

function sessionMarker(sessionId, root) {
  const id = crypto.createHash('sha256').update(`${sessionId || 'sem-sessao'}|${root}`).digest('hex').slice(0, 16);
  return path.join(os.tmpdir(), `lastro-stop-${id}.flag`);
}

function decide(report) {
  const blocking = report.controls.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => `[${c.id}] ${f.severity}: ${f.message}${f.location ? ` (${f.location})` : ''}`));
  if (blocking.length === 0) return null;
  const list = blocking.slice(0, MAX_LINES).join('\n');
  const more = blocking.length > MAX_LINES ? `\n... e mais ${blocking.length - MAX_LINES}.` : '';
  return `lastro check encontrou ${blocking.length} achado(s) novo(s) de gravidade alta ou crítica:\n${list}${more}\nCorrija ou explique ao usuário por que não corrigiu. Não aceite risco nem grave baseline por conta própria.`;
}

function main(input, env = process.env, cwd = process.cwd()) {
  let event = {};
  try { event = JSON.parse(input || '{}'); } catch (e) { event = {}; }
  const root = typeof event.cwd === 'string' && event.cwd ? event.cwd : cwd;
  if (!fs.existsSync(path.join(root, '.lastro', 'profile.json'))) return null;
  const cli = findCli(root, env);
  if (!cli) return null;
  const marker = sessionMarker(event.session_id, root);
  if (fs.existsSync(marker)) return null;
  const r = spawnSync(process.execPath, [cli, 'check', '--root', root, '--json', '--allow-incomplete'], { encoding: 'utf8', timeout: 100000, maxBuffer: 64 * 1024 * 1024 });
  if (r.error || !r.stdout) return null;
  let report;
  try { report = JSON.parse(r.stdout); } catch (e) { return null; }
  const reason = decide(report);
  if (!reason) return null;
  try { fs.writeFileSync(marker, new Date().toISOString()); } catch (e) { /* sem marcador, pode lembrar de novo */ }
  return { decision: 'block', reason };
}

if (require.main === module) {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => { input += c; if (input.length > 1024 * 1024) process.exit(0); });
  process.stdin.on('end', () => {
    let out = null;
    try { out = main(input); } catch (e) { out = null; }
    if (out) process.stdout.write(JSON.stringify(out));
    process.exit(0);
  });
}

module.exports = { main, decide, findCli, sessionMarker };
