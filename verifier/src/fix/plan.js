'use strict';

// Planejador do modo corrigir (lastro fix). Só lê: devolve as edições que SERIAM feitas e o que fica para uma pessoa.
// Corrige apenas o que tem correção determinística. Na dúvida, não corrige e explica.

const fs = require('node:fs');
const path = require('node:path');
const U = require('../util');
const { findUnpinned, pinActions, addPermissions } = require('./workflow');
const { SECURITY_TEMPLATE } = require('./security-md');

const FIXABLE = ['CORE-006', 'CORE-010', 'CORE-011'];
const WORKFLOW = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const SECURITY_FILES = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'];

/** Lê o arquivo só se for um arquivo comum (symlink nunca é seguido nem reescrito). */
function readPlain(root, rel) {
  try {
    const full = path.join(root, rel);
    if (fs.lstatSync(full).isSymbolicLink()) return null;
    return U.readText(root, rel);
  } catch (e) {
    return null;
  }
}

const stateOf = (report, id) => (report.controls.find((c) => c.id === id) || {}).state;

function dockerWithoutDigest(text) {
  return text.split(/\r?\n/).filter((l) => /^\s*-?\s*uses:\s*['"]?docker:\/\/(?!.*@sha256:[0-9a-f]{64})/.test(l)).length;
}

/**
 * @param {{root:string, report:object, only?:string[]|null, allowNetwork?:boolean, resolve?:Function}} o
 * @returns {Promise<{edits:object[], manual:object[]}>} edits: { file, kind, before, after, controls, summary }
 */
async function planFixes({ root, report, only = null, allowNetwork = false, resolve = null }) {
  const want = (id) => (!only || only.includes(id)) && stateOf(report, id) === 'failed';
  const files = U.listFiles(root);
  const edits = [];
  const manual = [];

  for (const file of files.filter((f) => WORKFLOW.test(f))) {
    const before = readPlain(root, file);
    if (before === null) continue;
    let cur = before;
    const controls = [];
    const summary = [];

    if (want('CORE-006')) {
      const docker = dockerWithoutDigest(cur);
      if (docker) manual.push({ control: 'CORE-006', file, reason: `${docker} imagem(ns) Docker sem digest: o kit não fixa imagem por digest. Fixe com "@sha256:..." depois de conferir a origem.` });
      if (findUnpinned(cur).length) {
        if (!allowNetwork || !resolve) {
          manual.push({ control: 'CORE-006', file, reason: 'Action(s) por tag ou branch: o SHA do commit só se descobre com rede. Rode de novo com --allow-network.' });
        } else {
          const r = await pinActions(cur, resolve);
          for (const s of r.skipped) manual.push({ control: 'CORE-006', file, reason: `linha ${s.line} (${s.from}): ${s.reason}.` });
          if (r.changes.length) {
            cur = r.text;
            controls.push('CORE-006');
            for (const c of r.changes) summary.push({ control: 'CORE-006', text: `linha ${c.line}: ${c.from} → ${c.to.split('@')[0]}@${c.sha.slice(0, 12)}… (# ${c.ref}${c.kind === 'branch' ? ', era uma BRANCH: o SHA muda a cada commit nela' : ''})` });
          }
        }
      }
    }

    if (want('CORE-010')) {
      const r = addPermissions(cur);
      if (r.manual) manual.push({ control: 'CORE-010', file, reason: r.manual });
      if (r.change) {
        cur = r.text;
        controls.push('CORE-010');
        summary.push({ control: 'CORE-010', text: `linha ${r.change.line}: acrescentado "${r.change.added}". Se algum job precisar de mais (release, comentário em PR), declare "permissions" nele.` });
      }
    }

    if (cur !== before) edits.push({ file, kind: 'modify', before, after: cur, controls, summary });
  }

  if (want('CORE-011')) {
    const existing = SECURITY_FILES.find((f) => files.includes(f));
    const hasTxt = files.some((f) => /(^|\/)security\.txt$/.test(f));
    if (existing) manual.push({ control: 'CORE-011', file: existing, reason: 'o arquivo existe, mas não descreve como reportar: preencha o contato.' });
    else if (!hasTxt) {
      edits.push({ file: 'SECURITY.md', kind: 'create', before: null, after: SECURITY_TEMPLATE, controls: ['CORE-011'], summary: [{ control: 'CORE-011', text: 'criado um modelo. O CORE-011 só passa depois que uma pessoa trocar os campos LASTRO-PREENCHER pelo contato real.' }] });
    }
  }

  return { edits, manual };
}

module.exports = { planFixes, FIXABLE, readPlain };
