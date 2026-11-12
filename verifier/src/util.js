'use strict';

// Utilitários do verificador. Sem dependências externas (somente módulos nativos do Node).

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.venv', 'venv', '__pycache__', 'vendor', '.cache',
]);
const MAX_READ_BYTES = 2 * 1024 * 1024;

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/** Impressão digital estável de um achado: controle + chave (arquivo, regra, caminho...). */
function fingerprint(controlId, key) {
  return sha256(`${controlId}|${key}`).slice(0, 16);
}

function toPosix(p) {
  return p.split(path.sep).join('/');
}

function walk(root, rel = '') {
  const out = [];
  let entries;
  try {
    entries = fs.readdirSync(path.join(root, rel), { withFileTypes: true });
  } catch (e) {
    return out;
  }
  for (const e of entries) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) {
      if (!IGNORED_DIRS.has(e.name)) out.push(...walk(root, r));
    } else if (e.isFile()) {
      out.push(r);
    }
  }
  return out;
}

/**
 * Arquivos do projeto (caminhos relativos, com "/"). Em repositório Git usa rastreados + novos não
 * ignorados, para que o que ainda vai ser commitado também seja verificado. Sem Git, varre a pasta.
 */
function listFiles(root) {
  if (fs.existsSync(path.join(root, '.git'))) {
    try {
      const raw = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
        cwd: root,
        maxBuffer: 256 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore'],
      }).toString('utf8');
      const set = new Set(raw.split('\0').filter(Boolean));
      return [...set]
        .filter((f) => fs.existsSync(path.join(root, f)))
        .filter((f) => !f.split('/').some((seg) => IGNORED_DIRS.has(seg)))
        .sort();
    } catch (e) {
      // sem git utilizável: cai para a varredura
    }
  }
  return walk(root).sort();
}

/** Lê texto UTF-8. Devolve null se não existir, for grande demais ou ilegível. */
function readText(root, rel, maxBytes = MAX_READ_BYTES) {
  try {
    const full = path.join(root, rel);
    const st = fs.statSync(full);
    if (!st.isFile() || st.size > maxBytes) return null;
    return fs.readFileSync(full, 'utf8');
  } catch (e) {
    return null;
  }
}

function readJson(root, rel) {
  const t = readText(root, rel);
  if (t === null) return { ok: false, error: 'arquivo ausente ou grande demais' };
  try {
    return { ok: true, value: JSON.parse(t) };
  } catch (e) {
    return { ok: false, error: `JSON inválido: ${e.message}` };
  }
}

function exists(root, rel) {
  return fs.existsSync(path.join(root, rel));
}

function parseDate(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?$/.test(v)) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
}

function nowIso(d = new Date()) {
  return d.toISOString();
}

function hasPrefix(rel, prefixes) {
  return (prefixes || []).some((p) => rel === p.replace(/\/$/, '') || rel.startsWith(p.endsWith('/') ? p : `${p}/`));
}

module.exports = {
  IGNORED_DIRS,
  sha256,
  fingerprint,
  toPosix,
  walk,
  listFiles,
  readText,
  readJson,
  exists,
  parseDate,
  nowIso,
  hasPrefix,
};
