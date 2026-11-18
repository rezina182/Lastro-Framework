'use strict';

// A página de apresentação (docs/index.html) e o README citam números do kit. Este teste confere que eles batem com o
// catálogo e com o adaptador do Kiro, para a vitrine não ficar desatualizada, e que a página segue as mesmas regras
// do portal: sem script, CSP restritiva e links externos só para o repositório e o site do Kiro.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadCatalog } = require('../src/catalog');
const { registry } = require('../src/checks');

const ROOT = path.join(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const count = (dir, pred) => fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true }).filter(pred).length;

test('landing: números iguais aos do catálogo e do adaptador', () => {
  const html = read('docs/index.html');
  const cat = loadCatalog();
  const n = (key) => { const m = new RegExp(`data-n="${key}">(\\d+)<`).exec(html); return m ? Number(m[1]) : null; };
  assert.equal(n('controls'), cat.controls.length);
  assert.equal(n('checks'), registry.size);
  assert.equal(n('lessons'), cat.lessons.length);
  assert.equal(n('agents'), count('adapters/kiro/agents', (e) => e.isFile() && e.name.endsWith('.md')));
  assert.equal(n('skills'), count('adapters/kiro/skills', (e) => e.isDirectory()));
  assert.equal(n('steering'), count('adapters/kiro/steering', (e) => e.isFile() && e.name.endsWith('.md')));
  assert.equal(n('hooks'), count('adapters/kiro/hooks', (e) => e.isFile() && e.name.endsWith('.json')));
  const readme = read('README.md');
  for (const [text, value] of [['Controles no catálogo', cat.controls.length], ['Verificações automáticas', registry.size], ['Lições de origem', cat.lessons.length]]) {
    assert.match(readme, new RegExp(`\\| ${text} \\| ${value}\\b`), `README: ${text}`);
  }
});

test('landing: sem script, com CSP, e links externos só para o repositório e o Kiro', () => {
  const html = read('docs/index.html');
  assert.doesNotMatch(html, /<script|\son[a-z]+\s*=|javascript:/i);
  assert.match(html, /Content-Security-Policy" content="default-src 'none'/);
  const ext = [...html.matchAll(/href="(https?:[^"]+)"/g)].map((m) => m[1]);
  assert.ok(ext.length > 0);
  for (const u of ext) assert.match(u, /^https:\/\/(github\.com\/rezina182\/Lastro-Framework|kiro\.dev)(\/|$)/, u);
  for (const m of html.matchAll(/href="#([^"]+)"/g)) assert.ok(html.includes(`id="${m[1]}"`), `âncora sem destino: #${m[1]}`);
});
