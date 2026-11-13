'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { priorityFor, planBacklog, loadTickets } = require('../src/backlog');
const { runCheck } = require('../src/engine');
const { makeProject, profileJson, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const cli = (args, cwd) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });

test('prioridade parte da severidade e desce se o app não é público ou se é só verificação de camada 2', () => {
  const crit = { severity: 'critical', tier: 1 };
  assert.equal(priorityFor(crit, 'fix', { flags: { publicInternet: true } }), 'P0');
  assert.equal(priorityFor(crit, 'fix', { flags: { publicInternet: false } }), 'P1');
  assert.equal(priorityFor({ severity: 'high', tier: 2 }, 'verify', { flags: { publicInternet: true } }), 'P2');
  assert.equal(priorityFor({ severity: 'low', tier: 3 }, 'verify', { flags: { publicInternet: false } }), 'P3');
});

test('o backlog gera tickets ordenados, sem duplicar os que já estão abertos', async () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ aiCodingAgents: true, publicInternet: true }), '.gitignore': '.env\n' });
  try {
    const rep = await runCheck({ root, now: new Date('2026-11-12T12:00:00Z') });
    const profile = JSON.parse(fs.readFileSync(path.join(root, '.lastro', 'profile.json'), 'utf8'));
    const planned = planBacklog(rep, profile, []);
    assert.ok(planned.length > 5);
    assert.equal(planned[0].id, 'T-0001');
    assert.equal(planned[0].priority, 'P0');
    const prios = planned.map((t) => t.priority);
    assert.deepEqual([...prios].sort(), prios);
    const again = planBacklog(rep, profile, planned);
    assert.equal(again.length, 0);
    const done = planned.map((t, i) => (i === 0 ? { ...t, status: 'done' } : t));
    assert.equal(planBacklog(rep, profile, done).length, 1);
  } finally { cleanup(root); }
});

test('CLI: catalog validate dá 0; comando desconhecido dá 3; sem perfil dá 3', () => {
  assert.equal(cli(['catalog', 'validate']).status, 0);
  assert.equal(cli(['xyz']).status, 3);
  const root = makeProject({});
  try {
    assert.equal(cli(['check', '--root', root]).status, 3);
  } finally { cleanup(root); }
});

test('CLI: init cria o perfil e não sobrescreve sem --force', () => {
  const root = makeProject({});
  try {
    assert.equal(cli(['init', '--root', root]).status, 0);
    assert.ok(fs.existsSync(path.join(root, '.lastro', 'profile.json')));
    assert.equal(cli(['init', '--root', root]).status, 3);
    assert.equal(cli(['init', '--root', root, '--force']).status, 0);
  } finally { cleanup(root); }
});

test('CLI: check dá 1 numa falha, escreve JSON e o backlog --write cria arquivos válidos', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ aiCodingAgents: true }), '.gitignore': '.env\n' });
  try {
    const out = path.join(root, 'rel.json');
    const r = cli(['check', '--root', root, '--out', out]);
    assert.equal(r.status, 1);
    const rep = JSON.parse(fs.readFileSync(out, 'utf8'));
    assert.equal(rep.verdict, 'fail');
    assert.equal(cli(['backlog', '--root', root]).status, 0);
    assert.ok(!fs.existsSync(path.join(root, '.lastro', 'backlog')));
    assert.equal(cli(['backlog', '--root', root, '--write']).status, 0);
    const { tickets, errors } = loadTickets(root);
    assert.deepEqual(errors, []);
    assert.ok(tickets.length > 0);
    assert.equal(cli(['backlog', '--root', root, '--write']).stdout.includes('Nenhuma lacuna nova'), true);
    assert.equal(cli(['baseline', '--root', root, '--write']).status, 0);
    assert.equal(cli(['check', '--root', root, '--allow-incomplete']).status, 0);
  } finally { cleanup(root); }
});

test('CLI: --active sem confirmação, contra produção ou com --delay inválido é recusado antes de qualquer requisição', () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ aiCodingAgents: true }, { urls: { production: 'http://127.0.0.1:9' } }),
    '.gitignore': '.env\n',
  });
  try {
    const semConfirmar = cli(['check', '--root', root, '--url', 'http://127.0.0.1:8', '--active']);
    assert.equal(semConfirmar.status, 3);
    assert.ok(semConfirmar.stderr.includes('--confirm-non-production'));
    const emProducao = cli(['check', '--root', root, '--url', 'http://127.0.0.1:9', '--active', '--confirm-non-production']);
    assert.equal(emProducao.status, 3);
    assert.ok(emProducao.stderr.includes('nunca rodam em produção'));
    assert.equal(cli(['check', '--root', root, '--url', 'http://127.0.0.1:8', '--delay', '10']).status, 3);
    assert.equal(cli(['check', '--root', root, '--url', 'http://127.0.0.1:8', '--delay', 'abc']).status, 3);
  } finally { cleanup(root); }
});

test('CLI: toda verificação HTTP imprime o aviso, e o alvo de produção do perfil é destacado', () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ aiCodingAgents: true }, { urls: { production: 'http://127.0.0.1:9' } }),
    '.gitignore': '.env\n',
  });
  try {
    const staging = cli(['check', '--root', root, '--url', 'http://127.0.0.1:8']);
    assert.ok(staging.stderr.includes('AVISO: verificação HTTP em http://127.0.0.1:8'));
    assert.ok(staging.stderr.includes('staging'));
    assert.ok(!staging.stderr.includes('PRODUÇÃO'));
    const prod = cli(['check', '--root', root, '--url', 'http://127.0.0.1:9']);
    assert.ok(prod.stderr.includes('PRODUÇÃO'));
    assert.ok(prod.stderr.includes('ativas são recusadas'));
    const json = cli(['check', '--root', root, '--url', 'http://127.0.0.1:8', '--json']);
    assert.doesNotThrow(() => JSON.parse(json.stdout), 'o aviso vai para stderr e não suja a saída em JSON');
  } finally { cleanup(root); }
});
