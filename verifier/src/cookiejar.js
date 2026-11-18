'use strict';

// Pote de cookies mínimo para as sondas autenticadas. Guarda só nome e valor (as sondas não precisam de domínio,
// caminho nem validade, porque falam com uma única origem). Os valores nunca vão para relatório nem para log.

function parseSetCookie(line) {
  const parts = String(line).split(';');
  const first = parts[0];
  const eq = first.indexOf('=');
  if (eq <= 0) return null;
  const name = first.slice(0, eq).trim();
  const value = first.slice(eq + 1).trim();
  const attrs = parts.slice(1).map((a) => a.trim().toLowerCase());
  // Valor vazio, Max-Age=0 ou data de 1970: o servidor está mandando apagar o cookie.
  const removed = value === '' || attrs.includes('max-age=0') || attrs.some((a) => /^expires\s*=\s*thu,\s*01 jan 1970/.test(a));
  return { name, value, removed };
}

function makeJar(initial = null) {
  const cookies = new Map(initial || []);
  return {
    /** Absorve as linhas Set-Cookie de uma resposta. */
    absorb(lines) {
      for (const line of lines || []) {
        const c = parseSetCookie(line);
        if (!c) continue;
        if (c.removed) cookies.delete(c.name);
        else cookies.set(c.name, c.value);
      }
    },
    /** Valor do cabeçalho Cookie, ou string vazia se o pote estiver vazio. */
    header: () => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; '),
    size: () => cookies.size,
    names: () => [...cookies.keys()],
    get: (name) => cookies.get(name),
    /** Cópia independente: o teste de fixação leva os cookies antigos para um login novo sem mexer no original. */
    clone: () => makeJar(cookies),
  };
}

module.exports = { makeJar, parseSetCookie };
