'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { packLegend, staticLegend, PACK_INFO } = require('../src/legend');
const { loadCatalog } = require('../src/catalog');
const { PACK_PREFIX } = require('../src/schema');
const { cweUrl, cveUrl, ghsaUrl, ALLOWED_HREF } = require('../src/links');
const { PILLARS } = require('../src/risk');
const { STRIDE } = require('../src/threatmodel');

const cat = loadCatalog();
const glossary = fs.readFileSync(path.join(__dirname, '..', '..', 'docs', 'GLOSSARIO.md'), 'utf8');

test('legenda: todo pacote do catálogo tem prefixo, descrição própria, condição e contagem de controles', () => {
  const packs = packLegend(cat);
  assert.equal(packs.length, Object.keys(cat.packs).length);
  for (const p of packs) {
    assert.ok(PACK_INFO[p.id], `faltou descrição para ${p.id}`);
    assert.equal(p.prefix, PACK_PREFIX[p.id]);
    assert.ok(p.what.length > 30);
    assert.ok(p.controls > 0);
  }
  assert.deepEqual(packs.find((p) => p.id === 'core').requires, []);
  assert.match(packs.find((p) => p.id === 'auth').requires[0], /hasAuth/);
});

test('o glossário da documentação cita todo prefixo, pilar e categoria STRIDE da legenda', () => {
  for (const p of packLegend(cat)) assert.ok(glossary.includes(`\`${p.prefix}\``), `glossário sem o prefixo ${p.prefix}`);
  for (const name of Object.values(PILLARS)) assert.ok(glossary.toLowerCase().includes(name.toLowerCase()), `glossário sem o pilar ${name}`);
  for (const k of Object.keys(STRIDE)) assert.ok(glossary.includes(STRIDE[k].name.toLowerCase()), `glossário sem ${STRIDE[k].name}`);
  for (const [sigla] of staticLegend().terms) assert.ok(glossary.includes(sigla), `glossário sem a sigla ${sigla}`);
});

test('links oficiais: só identificadores válidos viram endereço, e todos passam na lista permitida', () => {
  assert.equal(cweUrl(79), 'https://cwe.mitre.org/data/definitions/79.html');
  assert.equal(cweUrl('79/../x'), null);
  assert.equal(cweUrl('<script>'), null);
  assert.equal(cveUrl('CVE-2020-8203'), 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203');
  assert.equal(cveUrl('CVE-2020-8203"onmouseover="x'), null);
  assert.equal(ghsaUrl('GHSA-p6mc-m468-83gw'), 'https://github.com/advisories/GHSA-p6mc-m468-83gw');
  assert.equal(ghsaUrl('GHSA-xxxx'), null);
  for (const u of [cweUrl(295), cveUrl('CVE-2021-44228'), ghsaUrl('GHSA-p6mc-m468-83gw'), 'https://cwe.mitre.org/', 'https://nvd.nist.gov/']) assert.ok(ALLOWED_HREF.test(u), u);
  for (const u of ['http://cwe.mitre.org/data/definitions/79.html', 'https://evil.example/', 'https://cwe.mitre.org.evil.example/', 'javascript:alert(1)']) assert.ok(!ALLOWED_HREF.test(u), u);
});
