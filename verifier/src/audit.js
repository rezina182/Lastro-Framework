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
  const score = v.cvss && Number.isFinite(Number(v.cvss.score)) ? Math.min(10, Math.max(0, Number(v.cvss.score))) : null;
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

function parseAudit(text) {
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
    });
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  items.sort((a, b) => order[a.severity] - order[b.severity] || a.package.localeCompare(b.package));
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const i of items) bySeverity[i.severity] += 1;
  return { ok: true, value: { source: 'npm audit', total: items.length, bySeverity, items } };
}

/** Lê o arquivo do `npm audit --json`. Devolve { ok, value } ou { ok:false, error }. */
function loadAuditFile(file) {
  let st;
  try {
    st = fs.statSync(file);
  } catch (e) {
    return { ok: false, error: `não foi possível ler ${file}: ${e.message}` };
  }
  if (!st.isFile()) return { ok: false, error: `${file} não é um arquivo` };
  if (st.size > MAX_BYTES) return { ok: false, error: `arquivo acima de ${MAX_BYTES / 1024 / 1024} MB` };
  return parseAudit(fs.readFileSync(file, 'utf8'));
}

module.exports = { parseAudit, loadAuditFile, MAX_BYTES, MAX_PACKAGES };
