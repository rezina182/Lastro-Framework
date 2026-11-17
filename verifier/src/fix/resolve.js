'use strict';

// Resolve a tag (ou branch) de uma Action do GitHub para o SHA do commit, com `git ls-remote` em repositório
// público. É a ÚNICA operação de rede do modo corrigir e só roda com --allow-network. Os nomes são validados antes
// de montar a URL (só github.com), e o git nunca pergunta senha (GIT_TERMINAL_PROMPT=0).

const { execFileSync } = require('node:child_process');

const PART = /^(?!\.{1,2}$)[A-Za-z0-9_.-]+$/;
const REF = /^[A-Za-z0-9_./-]{1,100}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const MAX_LOOKUPS = 30;

/** Escolhe o SHA do commit nas linhas do ls-remote: a tag anotada (^{}) aponta para o commit, e a leve já é o commit. */
function pickSha(output, fullRef) {
  const found = {};
  for (const line of String(output).split(/\r?\n/)) {
    const [sha, name] = line.split('\t');
    if (SHA40.test(sha || '') && name) found[name.trim()] = sha;
  }
  return found[`${fullRef}^{}`] || found[fullRef] || null;
}

function makeGitResolver({ run = execFileSync, maxLookups = MAX_LOOKUPS } = {}) {
  let lookups = 0;
  return async function resolve(ownerRepo, ref) {
    const [owner, repo, ...rest] = String(ownerRepo).split('/');
    if (rest.length || !PART.test(owner || '') || !PART.test(repo || '') || !REF.test(String(ref))) return null;
    if (lookups >= maxLookups) return null;
    const url = `https://github.com/${owner}/${repo}.git`;
    for (const kind of ['tag', 'branch']) {
      const full = kind === 'tag' ? `refs/tags/${ref}` : `refs/heads/${ref}`;
      lookups += 1;
      let out;
      try {
        out = run('git', ['ls-remote', url, full, `${full}^{}`], { encoding: 'utf8', timeout: 20000, stdio: ['ignore', 'pipe', 'ignore'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
      } catch (e) {
        continue;
      }
      const sha = pickSha(out, full);
      if (sha) return { sha, kind };
    }
    return null;
  };
}

module.exports = { makeGitResolver, pickSha, MAX_LOOKUPS };
