'use strict';

// Links para as fontes oficiais. Só endereços montados aqui, a partir de identificadores validados, entram nos
// relatórios: nada que venha do projeto analisado vira link. Os relatórios continuam sem script, fonte ou imagem
// externa; o link é só navegação, aberta pelo leitor.

const CWE_RE = /^\d{1,4}$/;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const GHSA_RE = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/;

const cweUrl = (n) => (CWE_RE.test(String(n)) ? `https://cwe.mitre.org/data/definitions/${n}.html` : null);
const cveUrl = (id) => (CVE_RE.test(String(id)) ? `https://nvd.nist.gov/vuln/detail/${id}` : null);
const ghsaUrl = (id) => (GHSA_RE.test(String(id)) ? `https://github.com/advisories/${id}` : null);

const LGPD_URL = 'https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm';
const ASVS_URL = 'https://owasp.org/www-project-application-security-verification-standard/';

/** Conjunto fechado de endereços que um relatório pode conter (usado nos testes e na validação do HTML). */
const ALLOWED_HREF = /^https:\/\/(cwe\.mitre\.org\/(data\/definitions\/\d{1,4}\.html)?|nvd\.nist\.gov\/(vuln\/detail\/CVE-\d{4}-\d{4,7})?|github\.com\/advisories\/GHSA(-[23456789cfghjmpqrvwx]{4}){3}|www\.planalto\.gov\.br\/ccivil_03\/_ato2015-2018\/2018\/lei\/l13709\.htm|owasp\.org\/www-project-application-security-verification-standard\/)$/;

/** Link em Markdown, ou só o texto se o identificador for inválido. */
const mdLink = (text, url) => (url ? `[${text}](${url})` : text);

module.exports = { cweUrl, cveUrl, ghsaUrl, mdLink, LGPD_URL, ASVS_URL, ALLOWED_HREF };
