'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { runFix, FixError } = require('../src/fix');
const { formatResult, formatPrBody } = require('../src/fix/format');
const { makeProject, profileJson, cleanup } = require('./helpers');

const SHA = 'c'.repeat(40);
const WORKFLOW = ['name: CI', 'on: [push]', 'jobs:', '  build:', '    runs-on: ubuntu-latest', '    steps:', '      - uses: actions/checkout@v4', '      - run: npm test', ''].join('\n');
const NOW = new Date('2026-11-17T12:00:00Z');
const resolve = async (repo, ref) => ({ sha: SHA, kind: 'tag', repo, ref });

const sh = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
const ID = ['-c', 'user.name=base', '-c', 'user.email=base@exemplo.invalid'];

/** Repositório git temporário com um commit inicial (árvore limpa). */
function repo(extra = {}) {
  const root = makeProject({ '.lastro/profile.json': profileJson({ webApp: false }), '.github/workflows/ci.yml': WORKFLOW, 'package.json': '{"name":"x","version":"1.0.0","scripts":{"test":"node -e \\"process.exit(0)\\""}}\n', ...extra });
  sh(root, ['init', '-q', '-b', 'main']);
  sh(root, ['add', '-A']);
  sh(root, [...ID, 'commit', '-q', '-m', 'base']);
  return root;
}

const run = (root, o = {}) => runFix({ root, now: NOW, allowNetwork: true, resolve, ...o });
const read = (root, rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const head = (root) => sh(root, ['rev-parse', 'main']);

test('fix: sem --write só planeja e não muda nada (nem a branch, nem os arquivos)', async () => {
  const root = repo();
  try {
    const r = await run(root);
    assert.equal(r.applied, false);
    assert.deepEqual(r.plan.edits.map((e) => e.file).sort(), ['.github/workflows/ci.yml', 'SECURITY.md']);
    assert.equal(read(root, '.github/workflows/ci.yml'), WORKFLOW);
    assert.equal(sh(root, ['status', '--porcelain']), '');
    assert.equal(sh(root, ['rev-parse', '--abbrev-ref', 'HEAD']), 'main');
    assert.match(formatResult(r), /Plano apenas: nada foi alterado/);
  } finally { cleanup(root); }
});

test('fix --write: cria branch nova, corrige CORE-006 e CORE-010, cria modelo de SECURITY.md e não toca a main', async () => {
  const root = repo();
  const mainBefore = head(root);
  try {
    const r = await run(root, { write: true });
    assert.equal(r.applied, true);
    assert.match(r.branch, /^lastro\/fix-\d{14}$/);
    assert.equal(sh(root, ['rev-parse', '--abbrev-ref', 'HEAD']), r.branch);
    assert.equal(head(root), mainBefore, 'a main continua no mesmo commit');
    const wf = read(root, '.github/workflows/ci.yml');
    assert.match(wf, new RegExp(`uses: actions/checkout@${SHA} # v4`));
    assert.match(wf, /\npermissions:\n {2}contents: read\n\njobs:/);
    assert.match(read(root, 'SECURITY.md'), /LASTRO-PREENCHER/);
    assert.deepEqual([r.statesBefore['CORE-006'], r.statesAfter['CORE-006']], ['failed', 'verified']);
    assert.deepEqual([r.statesBefore['CORE-010'], r.statesAfter['CORE-010']], ['failed', 'verified']);
    // Modelo em branco não é canal de reporte: o CORE-011 continua falhando até uma pessoa preencher.
    assert.deepEqual([r.statesBefore['CORE-011'], r.statesAfter['CORE-011']], ['failed', 'failed']);
    assert.match(r.after.controls.find((c) => c.id === 'CORE-011').findings[0].message, /campos a preencher/);
    assert.equal(r.commit, null);
    assert.match(sh(root, ['status', '--porcelain']), /ci\.yml/);
    assert.equal(r.tests.status, 'not-run');
  } finally { cleanup(root); }
});

test('fix: sem --allow-network não adivinha SHA e deixa a Action para uma pessoa', async () => {
  const root = repo();
  try {
    const r = await run(root, { allowNetwork: false, resolve: null });
    const wf = r.plan.edits.find((e) => e.file === '.github/workflows/ci.yml');
    assert.ok(!wf.controls.includes('CORE-006'));
    assert.ok(r.plan.manual.some((m) => m.control === 'CORE-006' && /--allow-network/.test(m.reason)));
  } finally { cleanup(root); }
});

test('fix: árvore suja, branch repetida e nome inválido são recusados sem mudar nada', async () => {
  const root = repo();
  try {
    fs.writeFileSync(path.join(root, 'sujo.txt'), 'x');
    await assert.rejects(() => run(root, { write: true }), (e) => e instanceof FixError && /não commitadas/.test(e.message));
    fs.rmSync(path.join(root, 'sujo.txt'));
    await assert.rejects(() => run(root, { write: true, branch: 'main' }), /Nome de branch inválido/);
    await assert.rejects(() => run(root, { write: true, branch: 'lastro/../x' }), /Nome de branch inválido/);
    sh(root, ['branch', 'lastro/ja-existe']);
    await assert.rejects(() => run(root, { write: true, branch: 'lastro/ja-existe' }), /já existe/);
    assert.equal(read(root, '.github/workflows/ci.yml'), WORKFLOW);
    assert.equal(sh(root, ['rev-parse', '--abbrev-ref', 'HEAD']), 'main');
  } finally { cleanup(root); }
});

test('fix --run-tests: testes verdes ficam registrados; testes vermelhos desfazem tudo e apagam a branch', async () => {
  const ok = repo();
  const ruim = repo({ 'package.json': '{"name":"x","version":"1.0.0","scripts":{"test":"node -e \\"process.exit(1)\\""}}\n' });
  try {
    const g = await run(ok, { write: true, runTests: true });
    assert.equal(g.tests.status, 'passed');
    assert.equal(g.tests.command, 'npm test');
    assert.equal(g.applied, true);
    const f = await run(ruim, { write: true, runTests: true });
    assert.equal(f.tests.status, 'failed');
    assert.equal(f.rolledBack, true);
    assert.equal(f.applied, false);
    assert.equal(read(ruim, '.github/workflows/ci.yml'), WORKFLOW);
    assert.ok(!fs.existsSync(path.join(ruim, 'SECURITY.md')));
    assert.equal(sh(ruim, ['rev-parse', '--abbrev-ref', 'HEAD']), 'main');
    assert.equal(sh(ruim, ['branch', '--list', 'lastro/*']), '');
    assert.equal(sh(ruim, ['status', '--porcelain']), '');
    assert.match(formatResult(f), /testes falharam/i);
  } finally { cleanup(ok); cleanup(ruim); }
});

test('fix --run-tests: --test-cmd próprio e projeto sem script de teste', async () => {
  const semScript = repo({ 'package.json': '{"name":"x","version":"1.0.0"}\n' });
  try {
    const a = await run(semScript, { write: true, runTests: true });
    assert.equal(a.tests.status, 'no-command');
    assert.equal(a.applied, true);
  } finally { cleanup(semScript); }
  const outro = repo();
  try {
    const b = await run(outro, { write: true, runTests: true, testCmd: 'node -e "process.exit(0)"' });
    assert.equal(b.tests.status, 'passed');
    assert.equal(b.tests.command, 'node -e "process.exit(0)"');
  } finally { cleanup(outro); }
});

test('fix --commit: commita só os arquivos corrigidos, com o autor informado, e a main segue intacta', async () => {
  const root = repo();
  const mainBefore = head(root);
  try {
    const r = await run(root, { write: true, commit: { name: 'Pessoa AppSec', email: 'appsec@exemplo.invalid' } });
    assert.ok(r.commit);
    assert.equal(sh(root, ['log', '-1', '--format=%an <%ae>']), 'Pessoa AppSec <appsec@exemplo.invalid>');
    assert.equal(sh(root, ['status', '--porcelain']), '');
    assert.equal(head(root), mainBefore);
    assert.equal(sh(root, ['rev-list', '--count', `main..${r.branch}`]), '1');
  } finally { cleanup(root); }
});

test('fix: a descrição do PR traz o que muda, a validação, as atenções e o checklist, e marca o que não foi testado', async () => {
  const root = repo();
  try {
    const r = await run(root, { write: true });
    const body = formatPrBody(r, NOW);
    for (const re of [/exige revisão humana/, /\| CORE-006 \|/, /\| CORE-010 \|/, /não executados/, /CORE-011: falhando → falhando/, /SHA de Action/, /permissions:\*\* o padrão/, /LASTRO-PREENCHER/, /não exercita o CI/, /Checklist do revisor/, /Quem aprova não é só quem gerou/]) assert.match(body, re);
    assert.ok(!/ghp_|senha|password/i.test(body));
  } finally { cleanup(root); }
});

test('fix (CLI): argumentos perigosos ou incoerentes são recusados antes de qualquer ação', async () => {
  const root = repo();
  const cli = path.join(__dirname, '..', 'bin', 'lastro.js');
  const go = (...args) => spawnSync(process.execPath, [cli, 'fix', '--root', root, ...args], { encoding: 'utf8' });
  try {
    assert.match(go('--only', 'AUTH-027').stderr, /Sem correção automática/);
    assert.match(go('--run-tests').stderr, /só valem com --write/);
    assert.match(go('--write', '--test-cmd', 'npm test').stderr, /exige --run-tests/);
    assert.match(go('--commit').stderr, /só vale com --write/);
    assert.match(go('--write', '--commit', '--commit-name', 'x').stderr, /--commit-name e --commit-email válidos/);
    assert.match(go('--pr-body', path.join(root, 'pr.md')).stderr, /fora do repositório/);
    for (const a of [['--only', 'AUTH-027'], ['--run-tests'], ['--commit'], ['--pr-body', path.join(root, 'pr.md')]]) assert.equal(go(...a).status, 3);
    assert.equal(sh(root, ['status', '--porcelain']), '');
  } finally { cleanup(root); }
});
