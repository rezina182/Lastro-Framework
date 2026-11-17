'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { findUnpinned, pinActions, addPermissions, parseUsesRef } = require('../src/fix/workflow');
const { ctxFor, makeProject, cleanup, runOne } = require('./helpers');

const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);
const WF = [
  'name: CI', 'on: [push]', 'jobs:', '  build:', '    runs-on: ubuntu-latest', '    steps:',
  '      - uses: actions/checkout@v4', '      - uses: "actions/setup-node@v4" # runtime', '      - uses: ./local-action', '      - uses: docker://alpine:3.20',
  `      - uses: actions/cache@${SHA_B} # v4`, '      - run: npm test', '',
].join('\n');

const resolver = (map) => async (repo, ref) => map[`${repo}@${ref}`] || null;

test('fix: parseUsesRef só entende Action de repositório remoto e rejeita nomes estranhos', () => {
  assert.deepEqual(parseUsesRef('actions/checkout@v4'), { ownerRepo: 'actions/checkout', target: 'actions/checkout', ref: 'v4' });
  assert.equal(parseUsesRef('github/codeql-action/analyze@v3').ownerRepo, 'github/codeql-action');
  for (const bad of ['./local', 'docker://x:1', 'semref', 'a/b@', 'a b/c@v1', 'a/b@v1;rm', '../x/y@v1', 'a/b/../c@v1']) assert.equal(parseUsesRef(bad), null, bad);
});

test('fix: findUnpinned lista só o que o CORE-006 cobra', () => {
  assert.deepEqual(findUnpinned(WF).map((u) => `${u.line}:${u.target}@${u.ref}`), ['7:actions/checkout@v4', '8:actions/setup-node@v4']);
});

test('fix: pinActions troca tag por SHA, guarda a tag no comentário e preserva aspas e comentário', async () => {
  const r = await pinActions(WF, resolver({ 'actions/checkout@v4': { sha: SHA_A, kind: 'tag' }, 'actions/setup-node@v4': { sha: SHA_B, kind: 'tag' } }));
  const lines = r.text.split('\n');
  assert.equal(lines[6], `      - uses: actions/checkout@${SHA_A} # v4`);
  assert.equal(lines[7], `      - uses: "actions/setup-node@${SHA_B}" # v4 runtime`);
  assert.equal(lines[8], '      - uses: ./local-action');
  assert.equal(lines[10], `      - uses: actions/cache@${SHA_B} # v4`);
  assert.equal(r.changes.length, 2);
  assert.deepEqual(findUnpinned(r.text), []);
});

test('fix: referência que não resolve fica como está e é listada, sem inventar SHA', async () => {
  const r = await pinActions(WF, resolver({ 'actions/checkout@v4': { sha: 'curto', kind: 'tag' } }));
  assert.equal(r.text, WF);
  assert.equal(r.changes.length, 0);
  assert.equal(r.skipped.length, 2);
});

test('fix: pinActions preserva CRLF e resolve cada referência uma vez só', async () => {
  const crlf = WF.replace(/\n/g, '\r\n');
  let calls = 0;
  const r = await pinActions(`${crlf}      - uses: actions/checkout@v4\r\n`, async () => { calls += 1; return { sha: SHA_A, kind: 'tag' }; });
  assert.ok(r.text.includes('\r\n') && !/[^\r]\n/.test(r.text), 'todo fim de linha continua CRLF');
  assert.equal(calls, 2, 'checkout@v4 duas vezes e setup-node@v4 uma: 2 resoluções distintas');
});

test('fix: o workflow corrigido passa no CORE-006 de verdade (imagem Docker sem digest segue como pendência)', async () => {
  const r = await pinActions(WF, resolver({ 'actions/checkout@v4': { sha: SHA_A }, 'actions/setup-node@v4': { sha: SHA_B } }));
  // O kit não fixa imagem Docker por digest: o CORE-006 continua falhando enquanto houver "docker://" sem digest.
  const docker = makeProject({ '.github/workflows/ci.yml': r.text });
  try {
    const d = await runOne('repo.ci.actions-pinned', ctxFor(docker));
    assert.equal(d.state, 'failed');
    assert.ok(d.findings.every((f) => /Imagem Docker sem digest/.test(f.message)), 'só a imagem Docker sobra');
  } finally { cleanup(docker); }
  const semDocker = WF.split('\n').filter((l) => !l.includes('docker://')).join('\n');
  const fixed = await pinActions(semDocker, resolver({ 'actions/checkout@v4': { sha: SHA_A }, 'actions/setup-node@v4': { sha: SHA_B } }));
  const before = makeProject({ '.github/workflows/ci.yml': semDocker });
  const after = makeProject({ '.github/workflows/ci.yml': fixed.text });
  try {
    assert.equal((await runOne('repo.ci.actions-pinned', ctxFor(before))).state, 'failed');
    assert.equal((await runOne('repo.ci.actions-pinned', ctxFor(after))).state, 'verified');
  } finally { cleanup(before); cleanup(after); }
});

test('fix: addPermissions põe contents: read antes de jobs e o CORE-010 passa', async () => {
  const r = addPermissions(WF);
  assert.match(r.text, /\npermissions:\n {2}contents: read\n\njobs:\n/);
  assert.equal(r.change.added, 'permissions: contents: read');
  const before = makeProject({ '.github/workflows/ci.yml': WF });
  const after = makeProject({ '.github/workflows/ci.yml': r.text });
  try {
    assert.equal((await runOne('repo.ci.permissions', ctxFor(before))).state, 'failed');
    assert.equal((await runOne('repo.ci.permissions', ctxFor(after))).state, 'verified');
  } finally { cleanup(before); cleanup(after); }
});

test('fix: addPermissions não mexe no que já tem permissions e manda para revisão o que é perigoso', () => {
  const has = 'on: [push]\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n';
  assert.equal(addPermissions(has).text, has);
  assert.equal(addPermissions(has).change, null);
  const wa = addPermissions('on: [push]\njobs:\n  a:\n    permissions: write-all\n    runs-on: x\n');
  assert.match(wa.manual, /write-all/);
  const prt = addPermissions('on: pull_request_target\njobs:\n  a:\n    runs-on: x\n');
  assert.match(prt.manual, /pull_request_target/);
  assert.match(addPermissions('on: [push]\n').manual, /jobs/);
  const crlf = addPermissions('on: [push]\r\njobs:\r\n  a:\r\n    runs-on: x\r\n');
  assert.ok(!/[^\r]\n/.test(crlf.text));
});
