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
    assert.match(r.stdout, /seria criado: .*lastro-protect\.js/);
    assert.match(r.stdout, /já existe, mantido: .*lastro-base\.md/);
    assert.ok(!fs.existsSync(path.join(root, '.kiro', 'steering', 'lastro-escopo-auth.md')));

    r = cli(root, 'adapter', 'kiro', '--write');
    assert.equal(r.status, 0, r.stderr);
    for (const f of ['lastro-escopo-auth.md', 'lastro-escopo-dados.md', 'lastro-escopo-web.md', 'lastro-escopo-upload.md', 'lastro-escopo-tempo-real.md', 'lastro-revisao-ameacas.md']) assert.ok(fs.existsSync(path.join(root, '.kiro', 'steering', f)), f);
    for (const f of ['lastro-protect.json', 'lastro-protect.js']) assert.ok(fs.existsSync(path.join(root, '.kiro', 'hooks', f)), f);
    assert.equal(fs.readFileSync(path.join(root, '.kiro', 'steering', 'lastro-base.md'), 'utf8'), 'meu texto\n', 'arquivo existente fica como está');

    r = cli(root, 'adapter', 'kiro', '--write');
    assert.match(r.stdout, /já existe, mantido: .*lastro-revisao-ameacas\.md/);
    assert.equal(cli(root, 'adapter', 'outro').status, 3);
  } finally { cleanup(root); }
});

test('arquivos do adaptador: front matter correto, sem caractere oculto, o sempre ativo é pequeno e nada identifica empresa', () => {
  const files = listFiles('kiro', 'steering');
  assert.equal(files.length, 7);
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

test('hook do Kiro: pede confirmação ao citar atestação, risco aceito, decisão de ameaça ou baseline; ignora o resto e entrada inválida', () => {
  const hook = listFiles('kiro', 'hooks').find((f) => f.name === 'lastro-protect.js').file;
  const run = (input) => spawnSync(process.execPath, [hook], { input, encoding: 'utf8' });
  const ask = (payload) => {
    const r = run(JSON.stringify(payload));
    assert.equal(r.status, 0);
    return r.stdout ? JSON.parse(r.stdout).hookSpecificOutput : null;
  };
  for (const p of [
    { tool_name: 'fs_write', tool_input: { path: 'C:\\app\\.lastro\\status.json', text: '{}' } },
    { tool_name: 'str_replace', tool_input: { path: '/app/.lastro/threat-model.json' } },
    { tool_name: 'fs_write', tool_input: { path: '/app/.lastro/risks/RISK-0001.json' } },
    { tool_name: 'execute_pwsh', tool_input: { command: 'node lastro.js baseline --write' } },
  ]) {
    const out = ask(p);
    assert.equal(out && out.permissionDecision, 'ask', JSON.stringify(p));
    assert.match(out.permissionDecisionReason, /decisões de uma pessoa/);
  }
  for (const p of [
    { tool_name: 'fs_write', tool_input: { path: '/app/src/server.js', text: 'const a = 1;' } },
    { tool_name: 'execute_pwsh', tool_input: { command: 'npm test' } },
    { tool_name: 'fs_write', tool_input: { path: '/app/.lastro/profile.json' } },
  ]) assert.equal(ask(p), null, JSON.stringify(p));
  assert.equal(run('texto que não é json').stdout, '');
  assert.equal(run('texto .lastro/status.json solto').stdout.includes('"ask"'), true, 'entrada fora do formato ainda é conferida');
  assert.equal(run('').status, 0);
  const cfg = JSON.parse(fs.readFileSync(listFiles('kiro', 'hooks').find((f) => f.name === 'lastro-protect.json').file, 'utf8'));
  assert.equal(cfg.version, 'v1');
  assert.equal(cfg.hooks[0].trigger, 'PreToolUse');
  assert.match(cfg.hooks[0].action.command, /lastro-protect\.js/);
});
