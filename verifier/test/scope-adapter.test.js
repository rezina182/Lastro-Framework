'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { listFiles } = require('../src/adapter');
const { makeProject, profileJson, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const cli = (root, ...args) => spawnSync(process.execPath, [CLI, ...args, '--root', root], { encoding: 'utf8' });

test('scope: lista só os controles do pacote, com estado, como provar e ASVS', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ webApp: true, hasAuth: true }), 'a.js': 'const x = 1;\n' });
  try {
    const r = cli(root, 'scope', 'auth');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^Escopo "auth": /);
    assert.match(r.stdout, /AUTH-027 \(gravidade crítica\)/);
    assert.match(r.stdout, /como provar: /);
    assert.match(r.stdout, /ASVS: V/);
    assert.ok(!/CORE-0\d\d \(gravidade/.test(r.stdout), 'nenhum controle de outro pacote');
    assert.match(r.stdout, /Controle manual só passa com atestação/);
    const core = cli(root, 'scope', 'core');
    assert.match(core.stdout, /como corrigir: /, 'controle falhando mostra como corrigir');
    assert.ok(core.stdout.indexOf('[FALHANDO]') < core.stdout.indexOf('[sem prova]') || !core.stdout.includes('[sem prova]'), 'falhando vem antes de sem prova');
  } finally { cleanup(root); }
});

test('scope: pacote que o perfil não ativa diz quais flags faltam; nome inválido é erro de uso', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ webApp: true }), 'a.js': 'x\n' });
  try {
    const r = cli(root, 'scope', 'auth');
    assert.equal(r.status, 0);
    assert.match(r.stdout, /faltam as flags hasAuth/);
    const bad = cli(root, 'scope', 'banana');
    assert.equal(bad.status, 3);
    assert.match(bad.stderr, /Informe o escopo: lastro scope </);
    assert.equal(cli(root, 'scope').status, 3);
  } finally { cleanup(root); }
});

test('adaptador do Kiro: mostra o plano sem gravar, grava com --write e nunca sobrescreve', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({}), '.kiro/steering/lastro-base.md': 'meu texto\n' });
  try {
    let r = cli(root, 'adapter', 'kiro');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /seria criado: .*lastro-escopo-auth\.md/);
    assert.match(r.stdout, /já existe, mantido: .*lastro-base\.md/);
    assert.ok(!fs.existsSync(path.join(root, '.kiro', 'steering', 'lastro-escopo-auth.md')));

    r = cli(root, 'adapter', 'kiro', '--write');
    assert.equal(r.status, 0, r.stderr);
    for (const f of ['lastro-escopo-auth.md', 'lastro-escopo-dados.md', 'lastro-revisao-ameacas.md']) assert.ok(fs.existsSync(path.join(root, '.kiro', 'steering', f)), f);
    assert.equal(fs.readFileSync(path.join(root, '.kiro', 'steering', 'lastro-base.md'), 'utf8'), 'meu texto\n', 'arquivo existente fica como está');

    r = cli(root, 'adapter', 'kiro', '--write');
    assert.match(r.stdout, /já existe, mantido: .*lastro-revisao-ameacas\.md/);
    assert.equal(cli(root, 'adapter', 'outro').status, 3);
  } finally { cleanup(root); }
});

test('arquivos do adaptador: front matter correto, sem caractere oculto, o sempre ativo é pequeno e nada identifica empresa', () => {
  const files = listFiles('kiro');
  assert.equal(files.length, 4);
  for (const f of files) {
    const t = fs.readFileSync(f.file, 'utf8');
    assert.ok(t.startsWith('---\n'), `${f.name}: front matter`);
    const fm = t.slice(4, t.indexOf('\n---', 4));
    assert.match(fm, /inclusion: (always|fileMatch|auto)/, f.name);
    if (/inclusion: fileMatch/.test(fm)) assert.match(fm, /fileMatchPattern: '/, f.name);
    if (/inclusion: auto/.test(fm)) assert.ok(/name: /.test(fm) && /description: /.test(fm), `${f.name}: auto exige name e description`);
    assert.ok(!/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(t), `${f.name}: caractere oculto`);
    assert.ok(!/hardtech|lynx|quiz/i.test(t), `${f.name}: marca de empresa`);
  }
  const base = files.find((f) => f.name === 'lastro-base.md');
  assert.ok(fs.statSync(base.file).size < 4096, 'steering sempre ativo deve ser pequeno');
  assert.match(fs.readFileSync(base.file, 'utf8'), /Nunca faça commit nem push sem o usuário autorizar/);
});
