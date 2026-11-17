'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { classOf, analyzeRisk, PILLARS } = require('../src/risk');
const { parseAudit, loadAuditFile } = require('../src/audit');
const { validateRiskMap, validateProfile } = require('../src/schema');
const { loadCatalog } = require('../src/catalog');
const { runCheck } = require('../src/engine');
const { formatMarkdown, formatReport, redactReport } = require('../src/report');
const { formatHtml } = require('../src/html');
const { ALL_FALSE, makeProject, profileJson, cleanup, badHrefs } = require('./helpers');

const cat = loadCatalog();
const ctl = (id, pack, severity, state, over = {}) => ({ id, title: `Controle ${id}`, pack, severity, state, notes: [], findings: [], evidence: null, remediation: 'corrigir', ...over });
const finding = (severity, location) => ({ severity, message: 'm', location, blocking: false, accepted: false, inBaseline: false });
const run = (controls, flags = {}, extra = {}, audit = null) => analyzeRisk({ controls }, { riskMap: cat.riskMap, catalog: cat, profile: { flags: { ...ALL_FALSE, ...flags }, ...extra }, audit });

test('mapa de risco: todo controle tem entrada válida, e controle de segurança tem CWE', () => {
  const ids = new Set(cat.controls.map((c) => c.id));
  assert.deepEqual(validateRiskMap({ schemaVersion: 1, entries: cat.riskMap }, ids), []);
  assert.equal(Object.keys(cat.riskMap).length, cat.controls.length);
  const kinds = new Set(Object.values(cat.riskMap).map((e) => e.kind));
  assert.deepEqual([...kinds].sort(), ['practice', 'quality', 'security']);
});

test('mapa de risco: o validador recusa entrada ausente, pilar inválido, CWE inválida e segurança sem CWE', () => {
  const ids = new Set(['CORE-001', 'CORE-002']);
  const ruim = {
    schemaVersion: 1,
    entries: {
      'CORE-001': { kind: 'security', pillars: 'X', cwe: [798] },
      'CORE-002': { kind: 'security', pillars: 'I', cwe: [] },
      'CORE-003': { kind: 'practice', pillars: 'I', cwe: [] },
    },
  };
  const errs = validateRiskMap(ruim, ids).join('\n');
  assert.match(errs, /pillars/);
  assert.match(errs, /ao menos um CWE/);
  assert.match(errs, /inexistente no catálogo/);
  assert.match(validateRiskMap({ schemaVersion: 1, entries: { 'CORE-001': { kind: 'security', pillars: 'C', cwe: [798] } } }, ids).join('\n'), /falta a entrada de CORE-002/);
  assert.match(validateRiskMap({ schemaVersion: 1, entries: { 'CORE-001': { kind: 'security', pillars: 'CC', cwe: [1.5] } } }, new Set(['CORE-001'])).join('\n'), /pillars|cwe/);
});

test('classe de risco: limiares da matriz 4x4', () => {
  assert.equal(classOf(16), 'critical');
  assert.equal(classOf(12), 'critical');
  assert.equal(classOf(11), 'high');
  assert.equal(classOf(8), 'high');
  assert.equal(classOf(7), 'medium');
  assert.equal(classOf(4), 'medium');
  assert.equal(classOf(3), 'low');
  assert.equal(classOf(1), 'low');
});

test('risco: falha confirmada, alcance de pipeline não sobe com a exposição, e traz CWE, pilar e ASVS', () => {
  const r = run([ctl('CORE-006', 'core', 'high', 'failed', { findings: [finding('high', '.github/workflows/ci.yml:3')] })], { publicInternet: true });
  const i = r.security[0];
  assert.equal(i.id, 'CORE-006');
  assert.equal(i.likelihood, 3);
  assert.equal(i.impact, 3);
  assert.equal(i.class, 'high');
  assert.equal(i.assumed, false);
  assert.deepEqual(i.pillars, ['I']);
  assert.ok(i.cwe.includes(829));
  assert.deepEqual(i.locations, ['.github/workflows/ci.yml:3']);
  assert.equal(r.summary.confirmed.high, 1);
});

test('risco: sem prova é potencial e assumido; a exposição à internet sobe a probabilidade, e a falta dela baixa', () => {
  const pub = run([ctl('CORE-031', 'core', 'critical', 'unverified')], { publicInternet: true, personalData: true }).security[0];
  assert.equal(pub.assumed, true);
  assert.equal(pub.likelihood, 3);
  assert.equal(pub.impact, 4);
  assert.equal(pub.score, 11, 'sem prova, o produto 12 é limitado a 11');
  assert.equal(pub.class, 'high', 'crítico exige evidência');
  assert.match(pub.reasons.likelihood.join(' '), /crítico exige evidência/);
  const priv = run([ctl('CORE-031', 'core', 'critical', 'unverified')], { publicInternet: false }).security[0];
  assert.equal(priv.likelihood, 1);
  assert.equal(priv.class, 'medium');
  const r = run([ctl('CORE-031', 'core', 'critical', 'unverified')], { publicInternet: true });
  assert.equal(r.summary.potential.critical, 0);
  assert.equal(r.summary.potential.high, 1);
  assert.equal(r.summary.confirmed.total, 0);
  const confirmedCritical = run([ctl('CORE-031', 'core', 'critical', 'failed', { findings: [finding('critical', 'q.js:1')] })], { publicInternet: true }).security[0];
  assert.equal(confirmedCritical.class, 'critical', 'com evidência, o crítico vale');
  assert.equal(confirmedCritical.score, 16);
});

test('risco: achado heurístico de gravidade média não sobe pela exposição, e acesso interno baixa a probabilidade', () => {
  const med = run([ctl('CORE-059', 'core', 'high', 'failed', { findings: [finding('medium', 's.js:1')] })], { publicInternet: true }).security[0];
  assert.equal(med.likelihood, 2);
  assert.match(med.reasons.likelihood.join(' '), /exige revisão humana/);
  const strong = run([ctl('CORE-059', 'core', 'high', 'failed', { findings: [finding('high', 's.js:1')] })], { publicInternet: true }).security[0];
  assert.equal(strong.likelihood, 4);
  const weakHash = run([ctl('CORE-061', 'core', 'medium', 'failed', { findings: [finding('high', 'h.js:1')] })], { publicInternet: true }).security[0];
  assert.equal(weakHash.likelihood, 2, 'reach internal: 3 - 1');
});

test('risco: dado pessoal, de menores ou sensível sobe o impacto só de controles que tocam confidencialidade', () => {
  const base = (flags, extra) => run([ctl('CORE-062', 'core', 'high', 'failed', { findings: [finding('high', 'a.js:1')] })], flags, extra).security[0].impact;
  assert.equal(base({}), 3);
  assert.equal(base({ personalData: true }), 4);
  assert.equal(base({ personalData: true, minorsData: true }), 4, 'o teto é 4');
  const semC = run([ctl('CORE-006', 'core', 'high', 'failed')], { personalData: true, minorsData: true }).security[0];
  assert.equal(semC.impact, 3, 'integridade da cadeia de suprimentos não é dado pessoal');
});

test('risco: boa prática e qualidade não entram na matriz nem têm probabilidade x impacto', () => {
  const r = run([ctl('CORE-012', 'core', 'high', 'failed'), ctl('CORE-019', 'core', 'medium', 'unverified'), ctl('CORE-001', 'core', 'critical', 'verified')]);
  assert.equal(r.security.length, 0);
  assert.equal(r.practices.length, 1);
  assert.equal(r.quality.length, 1);
  assert.equal(r.practices[0].score, undefined);
  assert.equal(r.summary.practicesOpen, 1);
  assert.equal(r.summary.qualityOpen, 1);
  assert.equal(r.summary.securityVerified, 1, 'controle de segurança verificado é contado à parte');
  assert.ok(r.matrix.every((m) => m.count === 0));
});

test('risco: ordem decrescente de risco, confirmado antes de potencial no empate', () => {
  const r = run([
    ctl('WEB-005', 'web', 'low', 'unverified'),
    ctl('AUTH-027', 'auth', 'critical', 'unverified'),
    ctl('CORE-059', 'core', 'high', 'failed', { findings: [finding('high', 's.js:1')] }),
  ], { publicInternet: true });
  const scores = r.security.map((i) => i.score);
  assert.deepEqual(scores, [...scores].sort((a, b) => b - a));
  assert.equal(r.security[0].id, 'CORE-059');
  assert.equal(r.security[0].score, 12);
  assert.equal(r.security[1].id, 'AUTH-027');
  assert.equal(r.security[1].score, 11, 'potencial limitado a 11');
  assert.equal(r.security.at(-1).id, 'WEB-005');
});

test('risco: pilares e a pior classe aberta', () => {
  const r = run([ctl('CORE-031', 'core', 'critical', 'failed', { findings: [finding('critical', 'q.js:1')] }), ctl('WEB-011', 'web', 'medium', 'unverified')], { publicInternet: true });
  const c = r.pillars.find((p) => p.code === 'C');
  const d = r.pillars.find((p) => p.code === 'D');
  assert.equal(c.confirmed, 1);
  assert.equal(c.worstClass, 'critical');
  assert.equal(d.potential, 1);
  assert.equal(r.pillars.length, Object.keys(PILLARS).length);
  assert.equal(r.pillars.find((p) => p.code === 'N').open, 0);
});

test('privacidade: só se aplica quando o perfil declara dado pessoal, e traz a base da LGPD', () => {
  const semDado = run([ctl('PII-001', 'pii', 'medium', 'unverified')]);
  assert.equal(semDado.privacy.applies, false);
  const r = run([ctl('PII-004', 'pii', 'medium', 'unverified'), ctl('PII-003', 'pii', 'medium', 'failed', { findings: [finding('medium', 'l.js:1')] }), ctl('CORE-031', 'core', 'critical', 'unverified')], { personalData: true, minorsData: true, publicInternet: true });
  assert.equal(r.privacy.applies, true);
  assert.equal(r.privacy.data.minors, true);
  const pii4 = r.privacy.items.find((i) => i.id === 'PII-004');
  assert.match(pii4.lgpd, /Art\. 14/);
  const pii3 = r.privacy.items.find((i) => i.id === 'PII-003');
  assert.match(pii3.lgpd, /Art\. 46/);
  assert.ok(r.privacy.items.some((i) => i.id === 'CORE-031'), 'injeção expõe dado pessoal: toca privacidade');
  assert.match(r.privacy.note, /art\. 48/);
  const sens = run([], {}, { context: { sensitiveData: true } });
  assert.equal(sens.privacy.applies, true);
  assert.equal(sens.privacy.data.sensitive, true);
});

test('perfil: context.sensitiveData é booleano', () => {
  const base = { schemaVersion: 1, name: 'x', flags: ALL_FALSE };
  assert.deepEqual(validateProfile({ ...base, context: { sensitiveData: true } }), []);
  assert.match(validateProfile({ ...base, context: { sensitiveData: 'sim' } }).join('\n'), /sensitiveData/);
});

const AUDIT = {
  auditReportVersion: 2,
  vulnerabilities: {
    lodash: { name: 'lodash', severity: 'high', isDirect: true, via: [{ source: 1, name: 'lodash', title: 'Prototype Pollution (CVE-2020-8203)', url: 'https://github.com/advisories/GHSA-p6mc-m468-83gw', severity: 'high', cwe: ['CWE-1321', 'CWE-20'], cvss: { score: 7.4 }, range: '<4.17.20' }], effects: [], range: '<4.17.20', fixAvailable: true },
    ruim: { name: 'ruim', severity: 'moderate', isDirect: false, via: ['lodash', { title: 'x\u0000y', url: 'https://evil.example/a', severity: 'moderate', cwe: ['abc', 'CWE-79'], cvss: { score: 99 } }], fixAvailable: { name: 'a', version: '2.0.0', isSemVerMajor: true } },
  },
};

test('auditoria de dependências: lê GHSA, CWE, CVSS e CVE do título, e ignora links e textos suspeitos', () => {
  const a = parseAudit(JSON.stringify(AUDIT));
  assert.equal(a.ok, true);
  assert.equal(a.value.total, 2);
  assert.equal(a.value.bySeverity.high, 1);
  assert.equal(a.value.bySeverity.medium, 1);
  const lodash = a.value.items.find((i) => i.package === 'lodash');
  assert.equal(lodash.advisories[0].id, 'GHSA-p6mc-m468-83gw');
  assert.deepEqual(lodash.advisories[0].cwe, [1321, 20]);
  assert.deepEqual(lodash.advisories[0].cve, ['CVE-2020-8203']);
  assert.equal(lodash.fix, 'sim');
  const ruim = a.value.items.find((i) => i.package === 'ruim');
  assert.equal(ruim.advisories[0].url, null, 'só links de avisos do GitHub são mantidos');
  assert.equal(ruim.advisories[0].id, null);
  assert.deepEqual(ruim.advisories[0].cwe, [79]);
  assert.equal(ruim.advisories[0].cvss, 10, 'CVSS fora da faixa é limitado');
  assert.ok(!ruim.advisories[0].title.includes('\u0000'));
  assert.deepEqual(ruim.viaPackages, ['lodash']);
  assert.match(ruim.fix, /versão maior/);
  assert.equal(a.value.items[0].severity, 'high', 'ordenado por gravidade');
});

test('auditoria de dependências: recusa JSON inválido, formato desconhecido, arquivo ausente e arquivo grande demais', () => {
  assert.equal(parseAudit('{nao json').ok, false);
  assert.match(parseAudit('{"a":1}').error, /formato não reconhecido/);
  assert.match(parseAudit('{"vulnerabilities":[]}').error, /formato não reconhecido/);
  assert.equal(loadAuditFile(path.join(os.tmpdir(), 'nao-existe-lastro.json')).ok, false);
  const many = { vulnerabilities: Object.fromEntries(Array.from({ length: 501 }, (_, i) => [`p${i}`, { severity: 'low', via: [] }])) };
  assert.match(parseAudit(JSON.stringify(many)).error, /mais de 500/);
});

test('risco: vulnerabilidade de dependência entra na lista como confirmada, com CWE e pilares', () => {
  const audit = parseAudit(JSON.stringify(AUDIT)).value;
  const r = run([], { publicInternet: true, personalData: true }, {}, audit);
  const v = r.security.find((i) => i.id === 'VULN:lodash');
  assert.equal(v.type, 'vuln');
  assert.equal(v.state, 'failed');
  assert.equal(v.likelihood, 3);
  assert.ok(v.cwe.includes(1321));
  assert.ok(v.pillars.includes('I'));
  assert.equal(r.dependencies.total, 2);
  assert.equal(r.summary.confirmed.total, 2);
  const semInternet = run([], { publicInternet: false }, {}, audit).security.find((i) => i.id === 'VULN:lodash');
  assert.equal(semInternet.likelihood, 2);
});

async function realReport(flags, extra = {}, opts = {}) {
  const root = makeProject({
    '.lastro/profile.json': profileJson(flags, extra),
    'package.json': JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { a: '^1.0.0' } }),
    'package-lock.json': '{}',
    'db.js': "const o = { ssl: { rejectUnauthorized: false } };\n",
  });
  try {
    const report = await runCheck({ root, now: new Date('2026-11-12T12:00:00Z'), ...opts });
    return report;
  } finally {
    cleanup(root);
  }
}

test('motor: o relatório traz a análise de risco, e a falha de TLS vira risco confirmado de alcance de rede', async () => {
  const rep = await realReport({ webApp: true, hasAuth: true, publicInternet: true, personalData: true });
  assert.ok(rep.risk);
  const tls = rep.risk.security.find((i) => i.id === 'CORE-007');
  assert.ok(tls, 'CORE-007 deve estar na lista de risco');
  assert.equal(tls.state, 'failed');
  assert.equal(tls.likelihood, 2, 'alcance de rede não ganha o acréscimo da exposição e perde 1 por exigir posição na rede');
  assert.match(tls.reasons.likelihood.join(' '), /posição privilegiada na rede/);
  assert.ok(tls.cwe.includes(295));
  assert.equal(rep.risk.privacy.applies, true);
  assert.equal(rep.dependencyVulns, null);
});

test('motor: --audit-file entra no relatório; arquivo inválido é erro de configuração', async () => {
  const file = path.join(os.tmpdir(), `lastro-audit-${process.pid}.json`);
  fs.writeFileSync(file, JSON.stringify(AUDIT));
  try {
    const rep = await realReport({ webApp: true, publicInternet: true }, {}, { auditFile: file });
    assert.equal(rep.dependencyVulns.total, 2);
    assert.ok(rep.risk.security.some((i) => i.id === 'VULN:lodash'));
    fs.writeFileSync(file, '{ruim');
    await assert.rejects(() => realReport({ webApp: true }, {}, { auditFile: file }), /--audit-file/);
  } finally {
    fs.rmSync(file, { force: true });
  }
});

test('relatórios: Markdown, texto e HTML mostram a análise de risco sem script nem link externo', async () => {
  const file = path.join(os.tmpdir(), `lastro-audit2-${process.pid}.json`);
  fs.writeFileSync(file, JSON.stringify(AUDIT));
  try {
    const rep = await realReport({ webApp: true, hasAuth: true, publicInternet: true, personalData: true, minorsData: true }, { context: { sensitiveData: true } }, { auditFile: file });
    const md = formatMarkdown(rep);
    for (const t of ['## Análise de risco', 'Risco de segurança', 'Boa prática', 'Matriz de risco', 'Pilares da segurança da informação', 'Privacidade e LGPD', 'CWE-295', 'GHSA-p6mc-m468-83gw', 'Boas práticas pendentes']) assert.ok(md.includes(t), `faltou no Markdown: ${t}`);
    assert.ok(md.indexOf('## Análise de risco') < md.indexOf('## Maturidade'), 'o risco vem antes da maturidade');
    assert.match(formatReport(rep), /Risco de segurança confirmado:/);
    const html = formatHtml(rep, { coverage: null });
    for (const t of ['id="risco"', 'Matriz de risco', 'heat-', 'Privacidade e LGPD', 'CWE-295', 'GHSA-p6mc-m468-83gw', 'Pilares da segurança da informação']) assert.ok(html.includes(t), `faltou no HTML: ${t}`);
    assert.ok(!/<script|<link|<iframe|<img/i.test(html));
    assert.deepEqual(badHrefs(html), [], 'só âncoras internas e fontes oficiais');
    assert.ok(!/\bsrc=/i.test(html));
    assert.ok(html.includes('href="https://cwe.mitre.org/data/definitions/295.html"'), 'CWE leva à página oficial');
    assert.ok(html.includes('href="https://github.com/advisories/GHSA-p6mc-m468-83gw"'), 'GHSA leva ao aviso');
    assert.ok(html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2020-8203"'), 'CVE leva ao NVD');
    assert.ok(md.includes('[CWE-295](https://cwe.mitre.org/data/definitions/295.html)'));
    assert.ok(md.includes('[GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw)'));
    assert.ok(md.includes('[CVE-2020-8203](https://nvd.nist.gov/vuln/detail/CVE-2020-8203)'));
    for (const s of ['## Legenda', 'Pacotes e prefixos dos controles', '| `AUTH` |', '| `CORE` |', 'Estados de um controle', 'Siglas']) assert.ok(md.includes(s), `faltou a legenda no Markdown: ${s}`);
    for (const s of ['id="legenda"', 'Pacotes do catálogo', 'Autenticação e sessão']) assert.ok(html.includes(s), `faltou a legenda no HTML: ${s}`);
    const red = redactReport(rep, ['lodash']);
    assert.ok(!formatMarkdown(red).includes('lodash'));
  } finally {
    fs.rmSync(file, { force: true });
  }
});

// Formato real do npm audit (npm 10): um aviso no minimatch, herdado por eslint e @eslint/config-array, só em devDependencies.
const REAL_AUDIT = {
  auditReportVersion: 2,
  vulnerabilities: {
    '@eslint/config-array': { name: '@eslint/config-array', severity: 'moderate', isDirect: false, via: ['minimatch'], effects: [], fixAvailable: true },
    eslint: { name: 'eslint', severity: 'moderate', isDirect: true, via: ['minimatch'], effects: [], fixAvailable: { name: 'eslint', version: '10.15.0', isSemVerMajor: false } },
    minimatch: { name: 'minimatch', severity: 'moderate', isDirect: false, via: [{ title: 'minimatch has potential denial of service via globparts amplification', url: 'https://github.com/advisories/GHSA-g3hv-75wg-m249', severity: 'moderate', cwe: ['CWE-405'], cvss: { score: 0, vectorString: null } }], effects: ['@eslint/config-array', 'eslint'], fixAvailable: true },
  },
};

test('dependências: aviso herdado não conta três vezes, devDependency não vira risco crítico, CVSS 0 é "não calculado"', () => {
  const deps = { prod: new Set(['express', 'pg']), dev: new Set(['eslint', 'jest']) };
  const a = parseAudit(JSON.stringify(REAL_AUDIT), deps).value;
  assert.equal(a.total, 1, 'um pacote com aviso próprio');
  assert.equal(a.packagesAffected, 3);
  assert.equal(a.advisories, 1);
  assert.equal(a.devOnly, 1);
  const mm = a.items.find((i) => i.package === 'minimatch');
  assert.equal(mm.devOnly, true);
  assert.deepEqual(mm.via, ['eslint']);
  assert.equal(mm.advisories[0].cvss, null);
  assert.ok(a.items.find((i) => i.package === 'eslint').inherited);
  const r = run([], { publicInternet: true, personalData: true, minorsData: true }, {}, a);
  const vulns = r.security.filter((i) => i.type === 'vuln');
  assert.equal(vulns.length, 1);
  assert.equal(vulns[0].likelihood, 1);
  assert.deepEqual(vulns[0].pillars, ['D'], 'CWE-405 é disponibilidade');
  assert.equal(vulns[0].impact, 2, 'disponibilidade não sobe com dado pessoal');
  assert.equal(vulns[0].class, 'low');
  assert.match(vulns[0].reasons.likelihood.join(' '), /desenvolvimento/);
  const prod = parseAudit(JSON.stringify(REAL_AUDIT), { prod: new Set(['eslint']), dev: new Set() }).value;
  assert.equal(prod.items.find((i) => i.package === 'minimatch').devOnly, false, 'em produção não é rebaixado');
  const desconhecida = JSON.parse(JSON.stringify(REAL_AUDIT));
  desconhecida.vulnerabilities.minimatch.via[0].cwe = ['CWE-9999'];
  const v2 = run([], { publicInternet: true, personalData: true, minorsData: true }, {}, parseAudit(JSON.stringify(desconhecida)).value).security[0];
  assert.deepEqual(v2.pillars, []);
  assert.equal(v2.impact, 2, 'CWE sem pilar não infla o impacto com dado pessoal');
});
