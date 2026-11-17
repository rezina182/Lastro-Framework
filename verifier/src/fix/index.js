'use strict';

// Modo corrigir (lastro fix). Gera correções determinísticas numa BRANCH própria e prepara a descrição do PR.
// Nunca faz push, nunca abre PR, nunca mexe na branch atual e nunca commita sem --commit. Veja docs/CORRIGIR.md.

const fs = require('node:fs');
const path = require('node:path');
const U = require('../util');
const { runCheck } = require('../engine');
const { planFixes } = require('./plan');
const G = require('./git');

const stamp = (d) => d.toISOString().replace(/[-:T]/g, '').slice(0, 14);
const stateOf = (report, id) => (report.controls.find((c) => c.id === id) || {}).state || 'ausente';

function defaultTestCommand(root) {
  const pkg = U.readJson(root, 'package.json');
  return pkg.ok && pkg.value && pkg.value.scripts && pkg.value.scripts.test ? 'npm test' : null;
}

function writeEdit(root, e) {
  const full = path.join(root, e.file);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, e.after, e.kind === 'create' ? { flag: 'wx' } : undefined);
}

function undoEdits(root, edits) {
  for (const e of edits) {
    const full = path.join(root, e.file);
    if (e.kind === 'create') fs.rmSync(full, { force: true });
    else fs.writeFileSync(full, e.before);
  }
}

/**
 * @param {object} o
 * @param {string} o.root pasta do repositório (a raiz)
 * @param {boolean} [o.write] aplica de verdade (sem isso, só planeja)
 * @param {string[]|null} [o.only] limita aos controles
 * @param {boolean} [o.allowNetwork] permite resolver tag para SHA (git ls-remote)
 * @param {Function|null} [o.resolve] resolvedor de tag para SHA
 * @param {boolean} [o.runTests] roda os testes do projeto (executa o código do repositório)
 * @param {string|null} [o.testCmd] comando de teste (padrão: npm test, se o projeto tiver)
 * @param {string|null} [o.branch] nome da branch (padrão: lastro/fix-AAAAMMDDHHMMSS)
 * @param {{name:string,email:string}|null} [o.commit] autor, para commitar na branch
 */
async function runFix(o) {
  const root = path.resolve(o.root);
  const now = o.now || new Date();
  const before = await runCheck({ root, now });
  const plan = await planFixes({ root, report: before, only: o.only || null, allowNetwork: !!o.allowNetwork, resolve: o.resolve || null });
  const result = { root, plan, before, after: null, applied: false, rolledBack: false, branch: null, base: null, commit: null, tests: { status: 'not-run', command: null, tail: '' }, statesBefore: {}, statesAfter: {} };
  if (!o.write || plan.edits.length === 0) return result;

  G.assertRepoRoot(root);
  G.assertClean(root);
  result.base = G.currentBranch(root);
  result.branch = o.branch || `lastro/fix-${stamp(now)}`;
  G.createBranch(root, result.branch);
  try {
    for (const e of plan.edits) writeEdit(root, e);
  } catch (err) {
    undoEdits(root, plan.edits);
    G.dropBranch(root, result.base, result.branch);
    throw new G.FixError(`Não foi possível gravar as correções (${err.message}). Nada foi mudado.`);
  }
  result.applied = true;

  if (o.runTests) {
    const cmd = o.testCmd || defaultTestCommand(root);
    if (!cmd) result.tests = { status: 'no-command', command: null, tail: 'O projeto não tem script "test" e nenhum --test-cmd foi informado.' };
    else {
      const t = G.runTests(root, cmd);
      result.tests = { status: t.ok ? 'passed' : 'failed', command: cmd, tail: t.tail, timedOut: t.timedOut };
      if (!t.ok) {
        undoEdits(root, plan.edits);
        G.dropBranch(root, result.base, result.branch);
        result.applied = false;
        result.rolledBack = true;
        return result;
      }
    }
  }

  result.after = await runCheck({ root, now });
  for (const e of plan.edits) for (const id of e.controls) { result.statesBefore[id] = stateOf(before, id); result.statesAfter[id] = stateOf(result.after, id); }

  if (o.commit) {
    const files = plan.edits.map((e) => e.file);
    result.commit = G.commit(root, files, { name: o.commit.name, email: o.commit.email, message: 'correcoes de seguranca propostas pelo LASTRO (revisao humana obrigatoria)' });
  }
  return result;
}

module.exports = { runFix, defaultTestCommand, FixError: G.FixError };
