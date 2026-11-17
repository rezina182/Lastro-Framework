'use strict';

// Vulnerabilidades conhecidas em dependências, lidas de um arquivo gerado pelo `npm audit --json`.
// O kit NÃO consulta nenhuma base na internet: quem roda o npm audit decide quando e onde (o comando envia a
// lista de pacotes ao registro). O arquivo é tratado como dado não confiável: tamanho, quantidade e formato
// dos textos são limitados, e só links de avisos do GitHub são mantidos.
//
// O npm audit informa o aviso do GitHub (GHSA), a faixa afetada, a CWE e o CVSS. Ele não informa o CVE.
// O CVE só aparece aqui quando já está escrito no título do aviso; do contrário, o GHSA é o identificador,
// e o CVE correspondente está na página do aviso.

const fs = require('node:fs');
const { stripBom } = require('./util');

const MAX_BYTES = 5 * 1024 * 1024;
const MAX_PACKAGES = 500;
const MAX_ADVISORIES = 12;
const SEVERITY = { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low', info: 'low' };
const GHSA_URL = /^https:\/\/github\.com\/advisories\/(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})$/;
const CVE = /\bCVE-\d{4}-\d{4,7}\b/g;

const clip = (s, n) => String(s === undefined || s === null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n);

function advisoryOf(v) {
  const url = typeof v.url === 'string' ? v.url.trim() : '';
  const m = GHSA_URL.exec(url);
  const title = clip(v.title, 200);
  const cwe = (Array.isArray(v.cwe) ? v.cwe : [])
    .map((c) => /^CWE-(\d{1,4})$/.exec(String(c)))
    .filter(Boolean)
    .map((x) => Number(x[1]))
    .slice(0, 6);
  // CVSS 0 no npm audit quer dizer "não calculado", não "sem gravidade".
  const raw = v.cvss && Number.isFinite(Number(v.cvss.score)) ? Number(v.cvss.score) : null;
  const score = raw === null || raw === 0 ? null : Math.min(10, Math.max(0, raw));
  return {
    id: m ? m[1] : null,
    url: m ? url : null,
    title,
    severity: SEVERITY[String(v.severity).toLowerCase()] || 'medium',
    cwe,
    cvss: score,
    cve: [...new Set(title.match(CVE) || [])].slice(0, 4),
    range: clip(v.range, 80),
  };
}

/**
 * Lê o JSON do npm audit. `deps` (opcional): { prod: Set, dev: Set } com as dependências diretas do package.json,
 * para separar o que só existe em desenvolvimento (lint, teste, build) do que vai para produção.
 */
function parseAudit(text, deps = null) {
  let j;
  try {
    j = JSON.parse(text);
  } catch (e) {
    return { ok: false, error: `JSON inválido: ${e.message}` };
  }
  if (!j || typeof j !== 'object' || !j.vulnerabilities || typeof j.vulnerabilities !== 'object' || Array.isArray(j.vulnerabilities)) {
    return { ok: false, error: 'formato não reconhecido: esperado o resultado de "npm audit --json" (npm 7 ou superior, com o campo "vulnerabilities")' };
  }
  const names = Object.keys(j.vulnerabilities);
  if (names.length > MAX_PACKAGES) return { ok: false, error: `mais de ${MAX_PACKAGES} pacotes vulneráveis: arquivo recusado` };
  const items = [];
  for (const name of names) {
    const v = j.vulnerabilities[name];
    if (!v || typeof v !== 'object') continue;
    const via = Array.isArray(v.via) ? v.via : [];
    const advisories = via.filter((x) => x && typeof x === 'object').slice(0, MAX_ADVISORIES).map(advisoryOf);
    const viaPackages = via.filter((x) => typeof x === 'string').slice(0, 6).map((x) => clip(x, 80));
    const fix = v.fixAvailable;
    items.push({
      package: clip(name, 80),
      severity: SEVERITY[String(v.severity).toLowerCase()] || 'medium',
      direct: v.isDirect === true,
      fix: fix === true ? 'sim' : fix && typeof fix === 'object' ? (fix.isSemVerMajor ? 'sim, com troca de versão maior' : 'sim') : 'não há correção publicada',
      advisories,
      viaPackages,
      // Pacote que só herda o aviso de outro (via traz só nomes): não é uma vulnerabilidade a mais.
      inherited: advisories.length === 0,
      effects: (Array.isArray(v.effects) ? v.effects : []).filter((x) => typeof x === 'string').slice(0, 50).map((x) => clip(x, 80)),
      devOnly: null,
    });
  }
  // Dependência só de desenvolvimento: todas as dependências diretas que trazem o pacote estão em devDependencies.
  if (deps) {
    const byName = new Map(items.map((i) => [i.package, i]));
    const roots = (start) => {
      const seen = new Set();
      const out = new Set();
      const stack = [start];
      while (stack.length) {
        const n = stack.pop();
        if (seen.has(n)) continue;
        seen.add(n);
        const it = byName.get(n);
        if (deps.prod.has(n) || deps.dev.has(n)) out.add(n);
        if (it) for (const e of it.effects) stack.push(e);
      }
      return [...out];
    };
    for (const i of items) {
      const r = roots(i.package);
      i.devOnly = r.length > 0 && r.every((n) => deps.dev.has(n) && !deps.prod.has(n));
      i.via = r.slice(0, 6);
    }
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  items.sort((a, b) => order[a.severity] - order[b.severity] || a.package.localeCompare(b.package));
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const own = items.filter((i) => !i.inherited);
  for (const i of own) bySeverity[i.severity] += 1;
  const advisoryIds = new Set(own.flatMap((i) => i.advisories.map((a) => a.id || a.title)));
  return {
    ok: true,
    value: {
      source: 'npm audit', total: own.length, packagesAffected: items.length, advisories: advisoryIds.size,
      devOnly: own.filter((i) => i.devOnly === true).length, devKnown: !!deps, bySeverity, items,
    },
  };
}

/** Lê o arquivo do `npm audit --json`. Devolve { ok, value } ou { ok:false, error }. */
function loadAuditFile(file, deps = null) {
  let st;
  try {
    st = fs.statSync(file);
  } catch (e) {
    return { ok: false, error: `não foi possível ler ${file}: ${e.message}` };
  }
  if (!st.isFile()) return { ok: false, error: `${file} não é um arquivo` };
  if (st.size > MAX_BYTES) return { ok: false, error: `arquivo acima de ${MAX_BYTES / 1024 / 1024} MB` };
  // No Windows, "npm audit --json > arquivo" no PowerShell grava UTF-16 ou UTF-8 com BOM.
  const buf = fs.readFileSync(file);
  let text;
  if (buf[0] === 0xff && buf[1] === 0xfe) text = buf.slice(2).toString('utf16le');
  else text = stripBom(buf.toString('utf8'));
  return parseAudit(text, deps);
}

/** Dependências diretas do package.json do projeto, separadas em produção e desenvolvimento. */
function directDeps(pkgText) {
  try {
    const p = JSON.parse(stripBom(pkgText || 'null'));
    if (!p) return null;
    return { prod: new Set([...Object.keys(p.dependencies || {}), ...Object.keys(p.optionalDependencies || {})]), dev: new Set(Object.keys(p.devDependencies || {})) };
  } catch (e) {
    return null;
  }
}

module.exports = { parseAudit, loadAuditFile, directDeps, MAX_BYTES, MAX_PACKAGES };
