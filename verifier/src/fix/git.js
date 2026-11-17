'use strict';

// Operações de git do modo corrigir. Só locais: criar branch, voltar, apagar a própria branch e (opcional) commitar.
// Nunca há push, nem PR, nem alteração da configuração do git (autor vai por -c, só nesta chamada).

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

class FixError extends Error {}

const BRANCH = /^lastro\/[a-z0-9][a-z0-9._-]{0,60}$/;
const TEST_TIMEOUT_MS = 10 * 60 * 1000;

function git(root, args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

const real = (p) => { try { return fs.realpathSync(p); } catch (e) { return path.resolve(p); } };

/** O root precisa ser a raiz do repositório: as edições e a branch valem para o repositório todo. */
function assertRepoRoot(root) {
  let top;
  try {
    top = git(root, ['rev-parse', '--show-toplevel']).trim();
  } catch (e) {
    throw new FixError('A pasta não é um repositório git: o modo corrigir precisa de uma branch para propor a mudança.');
  }
  if (real(top).toLowerCase() !== real(root).toLowerCase()) throw new FixError(`Rode na raiz do repositório (${top}).`);
}

function currentBranch(root) {
  const b = git(root, ['rev-parse', '--abbrev-ref', 'HEAD']).trim();
  if (b === 'HEAD') throw new FixError('O repositório está com HEAD solto (detached): entre numa branch antes de corrigir.');
  return b;
}

function assertClean(root) {
  const status = git(root, ['status', '--porcelain']).trim();
  if (status) throw new FixError('A árvore de trabalho tem mudanças não commitadas ou arquivos novos. Commite ou guarde (stash) antes: o PR deve conter só as correções do LASTRO.');
}

function branchExists(root, name) {
  try { git(root, ['rev-parse', '--verify', '--quiet', `refs/heads/${name}`]); return true; } catch (e) { return false; }
}

function validBranchName(name) {
  return BRANCH.test(String(name));
}

function createBranch(root, name) {
  if (!validBranchName(name)) throw new FixError('Nome de branch inválido: use "lastro/" seguido de letras minúsculas, números, ponto, hífen ou sublinhado.');
  if (branchExists(root, name)) throw new FixError(`A branch ${name} já existe: escolha outro nome com --branch.`);
  git(root, ['switch', '-c', name]);
}

/** Volta para a branch original e apaga a branch criada (ela não tem commits, então -d basta). */
function dropBranch(root, original, name) {
  git(root, ['switch', original]);
  git(root, ['branch', '-d', name]);
}

function commit(root, files, { name, email, message }) {
  git(root, ['add', '--', ...files]);
  git(root, ['-c', `user.name=${name}`, '-c', `user.email=${email}`, 'commit', '-m', message]);
  return git(root, ['rev-parse', '--short', 'HEAD']).trim();
}

/**
 * Roda o comando de teste do projeto. ISSO EXECUTA O CÓDIGO DO REPOSITÓRIO: só com --run-tests, e o comando é o
 * `npm test` do projeto ou o que a pessoa passou em --test-cmd (nunca um comando vindo do repositório).
 */
function runTests(root, command) {
  // O comando é o "npm test" padrão ou o --test-cmd digitado por quem roda o kit, nunca texto vindo do repositório.
  // O shell é necessário para o npm no Windows (.cmd) e tem a mesma confiança do terminal da própria pessoa.
  const r = spawnSync(command, { cwd: root, shell: true, encoding: 'utf8', timeout: TEST_TIMEOUT_MS, maxBuffer: 32 * 1024 * 1024 }); // lastro-ignore dynamic-eval: comando de quem opera o kit (npm test ou --test-cmd), nunca do repositório analisado
  const tail = `${r.stdout || ''}${r.stderr || ''}`.split(/\r?\n/).filter(Boolean).slice(-15).join('\n');
  return { ok: r.status === 0 && !r.error, code: r.status, timedOut: !!(r.error && r.error.code === 'ETIMEDOUT'), tail };
}

module.exports = { FixError, assertRepoRoot, currentBranch, assertClean, createBranch, dropBranch, commit, runTests, validBranchName, branchExists };
