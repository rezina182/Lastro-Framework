'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { deriveProfile, formatDerived } = require('../src/init');
const { validateProfile } = require('../src/schema');
const { makeProject, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');

const WEB_APP = {
  'package.json': JSON.stringify({ name: '@empresa/minha-api', version: '1.0.0', dependencies: { express: '4.19.2', 'express-session': '1.18.0', bcryptjs: '2.4.3', multer: '1.4.5', pg: '8.11.0' } }),
  'server.js': "const app = require('express')();\napp.post('/login', h);\napp.get('/api/clientes', auth, h);\napp.post('/api/upload', auth, h);\n",
  'schema.sql': 'create table clientes (id serial primary key, nome text, email text, senha_hash text);\n',
};

test('init: deriva o perfil do código, com o motivo de cada flag e as perguntas do que o código não mostra', () => {
  const root = makeProject(WEB_APP);
  try {
    const d = deriveProfile(root);
    assert.deepEqual(validateProfile(d.profile), [], 'o perfil derivado é válido');
    assert.equal(d.profile.name, 'minha-api');
    for (const f of ['webApp', 'hasAuth', 'uploads', 'personalData']) assert.equal(d.profile.flags[f], true, f);
    assert.equal(d.profile.flags.minorsData, false, 'o código não mostra dado de menor: fica desligado e vira pergunta');
    assert.match(d.reasons.hasAuth, /express-session|bcryptjs/);
    assert.ok(d.ask.some((a) => a.flag === 'minorsData'));
    const txt = formatDerived(d);
    assert.match(txt, /Perfil derivado do código \(rascunho\)/);
    assert.match(txt, /Revise estas, que o código não mostra/);
  } finally { cleanup(root); }
});

test('init (CLI): grava o perfil derivado; --blank grava tudo desligado; não sobrescreve sem --force', () => {
  const root = makeProject(WEB_APP);
  try {
    const r = spawnSync(process.execPath, [CLI, 'init', '--root', root], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const p = JSON.parse(fs.readFileSync(path.join(root, '.lastro', 'profile.json'), 'utf8'));
    assert.equal(p.flags.webApp, true);
    assert.equal(spawnSync(process.execPath, [CLI, 'init', '--root', root], { encoding: 'utf8' }).status, 3);
    assert.equal(spawnSync(process.execPath, [CLI, 'init', '--root', root, '--force', '--blank'], { encoding: 'utf8' }).status, 0);
    const b = JSON.parse(fs.readFileSync(path.join(root, '.lastro', 'profile.json'), 'utf8'));
    assert.equal(b.flags.webApp, false);
  } finally { cleanup(root); }
});
