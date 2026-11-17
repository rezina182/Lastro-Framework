'use strict';

// Adaptador do Kiro: copia os arquivos de steering do kit para o projeto analisado (.kiro/steering). Nunca
// sobrescreve um arquivo existente: se o projeto já tem um, ele fica como está e o relatório avisa.

const fs = require('node:fs');
const path = require('node:path');

const ADAPTERS_DIR = path.join(__dirname, '..', '..', 'adapters');
const NAMES = ['kiro'];

function listFiles(adapter) {
  const dir = path.join(ADAPTERS_DIR, adapter, 'steering');
  return fs.readdirSync(dir).filter((f) => f.endsWith('.md')).sort().map((f) => ({ name: f, file: path.join(dir, f) }));
}

/** Plano: quais arquivos seriam criados e quais já existem. `write` grava só os que não existem. */
function installKiro(root, { write = false } = {}) {
  const target = path.join(root, '.kiro', 'steering');
  const result = { target, created: [], skipped: [] };
  for (const f of listFiles('kiro')) {
    const dest = path.join(target, f.name);
    if (fs.existsSync(dest)) { result.skipped.push(f.name); continue; }
    if (write) {
      fs.mkdirSync(target, { recursive: true });
      fs.writeFileSync(dest, fs.readFileSync(f.file, 'utf8'), { flag: 'wx' });
    }
    result.created.push(f.name);
  }
  return result;
}

module.exports = { NAMES, installKiro, listFiles };
