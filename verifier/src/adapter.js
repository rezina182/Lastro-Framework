'use strict';

// Adaptador do Kiro: copia os arquivos de steering e de hook do kit para o projeto analisado (.kiro/steering e
// .kiro/hooks). Nunca sobrescreve um arquivo existente: se o projeto já tem um, ele fica como está.

const fs = require('node:fs');
const path = require('node:path');

const ADAPTERS_DIR = path.join(__dirname, '..', '..', 'adapters');
const NAMES = ['kiro'];
const KINDS = [['steering', '.md'], ['hooks', '.json'], ['hooks', '.js']];

function listFiles(adapter, kind = null) {
  const out = [];
  for (const [folder, ext] of KINDS) {
    if (kind && kind !== folder) continue;
    const dir = path.join(ADAPTERS_DIR, adapter, folder);
    let names = [];
    try { names = fs.readdirSync(dir); } catch (e) { names = []; }
    for (const f of names.filter((n) => n.endsWith(ext)).sort()) out.push({ name: f, folder, file: path.join(dir, f) });
  }
  return out;
}

/** Plano: quais arquivos seriam criados e quais já existem. `write` grava só os que não existem. */
function installKiro(root, { write = false } = {}) {
  const result = { target: path.join(root, '.kiro'), created: [], skipped: [] };
  for (const f of listFiles('kiro')) {
    const dest = path.join(result.target, f.folder, f.name);
    const shown = path.join(f.folder, f.name);
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
