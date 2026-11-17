'use strict';

// Correções determinísticas de workflows do GitHub Actions (lastro fix). Funções puras: recebem o texto e devolvem
// o novo texto. Preservam fim de linha (LF ou CRLF), BOM, aspas e comentários. O que não entendem, deixam como está.

const SHA40 = /^[0-9a-f]{40}$/;
const NAME_PART = /^(?!\.{1,2}$)[A-Za-z0-9_.-]+$/;
const REF = /^[A-Za-z0-9_./-]{1,100}$/;
// "uses: dono/repo[/caminho]@ref", com aspas e comentário final opcionais.
const USES_LINE = /^(\s*-?\s*uses:\s*)(['"]?)([^\s'"]+)\2(\s+#\s?(.*))?\s*$/;

function eolOf(text) {
  return text.includes('\r\n') ? '\r\n' : '\n';
}

/** Interpreta "dono/repo/caminho@ref". Devolve null se não for uma Action de repositório remoto. */
function parseUsesRef(value) {
  if (value.startsWith('./') || value.startsWith('docker://')) return null;
  const at = value.lastIndexOf('@');
  if (at < 0) return null;
  const target = value.slice(0, at);
  const ref = value.slice(at + 1);
  const parts = target.split('/');
  if (parts.length < 2 || !NAME_PART.test(parts[0]) || !NAME_PART.test(parts[1]) || !REF.test(ref)) return null;
  if (parts.slice(2).some((p) => !NAME_PART.test(p))) return null;
  return { ownerRepo: `${parts[0]}/${parts[1]}`, target, ref };
}

/** Lista as Actions que não estão fixadas por SHA (o que o CORE-006 cobra). */
function findUnpinned(text) {
  const out = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const m = USES_LINE.exec(line);
    if (!m) return;
    const p = parseUsesRef(m[3]);
    if (p && !SHA40.test(p.ref)) out.push({ line: i + 1, ...p });
  });
  return out;
}

/**
 * Troca `uses: dono/repo@ref` por `dono/repo@<sha> # ref`. `resolve(ownerRepo, ref)` devolve { sha, kind } ou null.
 * Devolve { text, changes, skipped }. Quem decide se o SHA é confiável é a revisão humana do PR.
 */
async function pinActions(text, resolve) {
  const eol = eolOf(text);
  const lines = text.split(/\r?\n/);
  const cache = new Map();
  const changes = [];
  const skipped = [];
  for (let i = 0; i < lines.length; i += 1) {
    const m = USES_LINE.exec(lines[i]);
    if (!m) continue;
    const p = parseUsesRef(m[3]);
    if (!p || SHA40.test(p.ref)) continue;
    const key = `${p.ownerRepo}@${p.ref}`;
    if (!cache.has(key)) cache.set(key, await resolve(p.ownerRepo, p.ref));
    const r = cache.get(key);
    if (!r || !SHA40.test(r.sha)) { skipped.push({ line: i + 1, from: m[3], reason: 'não foi possível resolver a referência para um SHA de commit' }); continue; }
    const note = m[5] ? ` ${m[5]}` : '';
    const to = `${p.target}@${r.sha}`;
    lines[i] = `${m[1]}${m[2]}${to}${m[2]} # ${p.ref}${note}`;
    changes.push({ line: i + 1, from: m[3], to, ref: p.ref, sha: r.sha, kind: r.kind || 'tag' });
  }
  return { text: lines.join(eol), changes, skipped };
}

/** Acrescenta `permissions: contents: read` no topo, antes de `jobs:`, quando o workflow não declara nenhuma. */
function addPermissions(text) {
  const eol = eolOf(text);
  // O que um bloco permissions não resolve vai para revisão humana, haja ou não bloco no topo.
  if (/permissions\s*:\s*write-all/.test(text)) return { text, change: null, manual: 'usa "permissions: write-all": escolha as permissões mínimas de cada job' };
  if (/\bpull_request_target\b/.test(text)) return { text, change: null, manual: 'usa "pull_request_target": exige revisão de desenho, não só um bloco permissions' };
  const hasTop = /^permissions\s*:/m.test(text);
  const jobsIdx = text.search(/^jobs\s*:/m);
  if (hasTop) return { text, change: null, manual: null };
  if (jobsIdx < 0) return { text, change: null, manual: 'o workflow não tem o bloco "jobs:"' };
  const jobsText = text.slice(jobsIdx);
  const jobCount = (jobsText.match(/^ {2}[A-Za-z0-9_-]+\s*:\s*$/gm) || []).length;
  const jobPerms = (jobsText.match(/^ {4}permissions\s*:/gm) || []).length;
  if (jobPerms >= jobCount && jobCount > 0) return { text, change: null, manual: null };
  const line = text.slice(0, jobsIdx).split(/\r?\n/).length;
  const next = `${text.slice(0, jobsIdx)}permissions:${eol}  contents: read${eol}${eol}${text.slice(jobsIdx)}`;
  return { text: next, change: { line, added: 'permissions: contents: read' }, manual: null };
}

module.exports = { findUnpinned, pinActions, addPermissions, parseUsesRef, SHA40 };
