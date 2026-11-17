'use strict';

// Adaptador do Kiro: copia o agente, as skills, o steering e os hooks do kit para o projeto analisado (.kiro/).
// Nunca sobrescreve um arquivo existente: se o projeto já tem um, ele fica como está.

const fs = require('node:fs');
const path = require('node:path');

const ADAPTERS_DIR = path.join(__dirname, '..', '..', 'adapters');
const NAMES = ['kiro'];
// [pasta, extensão]. Skills ficam em subpastas (skills/<nome>/SKILL.md).
const KINDS = [['agents', '.md'], ['skills', 'SKILL.md'], ['steering', '.md'], ['hooks', '.json'], ['hooks', '.js']];

function listFiles(adapter, kind = null) {
  const out = [];
  for (const [folder, ext] of KINDS) {
    if (kind && kind !== folder) continue;
    const dir = path.join(ADAPTERS_DIR, adapter, folder);
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { entries = []; }
    if (folder === 'skills') {
      for (const d of entries.filter((e) => e.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
        const file = path.join(dir, d.name, 'SKILL.md');
        if (fs.existsSync(file)) out.push({ name: `${d.name}/SKILL.md`, folder, file });
      }
      continue;
    }
    for (const e of entries.filter((x) => x.isFile() && x.name.endsWith(ext)).sort((a, b) => a.name.localeCompare(b.name))) {
      out.push({ name: e.name, folder, file: path.join(dir, e.name) });
    }
  }
  return out;
}

/** Plano: quais arquivos seriam criados e quais já existem. `write` grava só os que não existem. */
function installKiro(root, { write = false } = {}) {
  const result = { target: path.join(root, '.kiro'), created: [], skipped: [] };
  for (const f of listFiles('kiro')) {
    const dest = path.join(result.target, f.folder, ...f.name.split('/'));
    const shown = path.join(f.folder, ...f.name.split('/'));
    if (fs.existsSync(dest)) { result.skipped.push(shown); continue; }
    if (write) {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, fs.readFileSync(f.file, 'utf8'), { flag: 'wx' });
    }
    result.created.push(shown);
  }
  return result;
}

module.exports = { NAMES, installKiro, listFiles };
