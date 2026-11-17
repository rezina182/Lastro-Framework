'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeGitResolver, pickSha } = require('../src/fix/resolve');

const A = 'a'.repeat(40);
const B = 'b'.repeat(40);

test('resolve: tag anotada usa o commit apontado (^{}), e tag leve usa o próprio SHA', () => {
  assert.equal(pickSha(`${A}\trefs/tags/v4\n${B}\trefs/tags/v4^{}\n`, 'refs/tags/v4'), B);
  assert.equal(pickSha(`${A}\trefs/tags/v4\n`, 'refs/tags/v4'), A);
  assert.equal(pickSha('', 'refs/tags/v4'), null);
  assert.equal(pickSha('lixo\trefs/tags/v4\n', 'refs/tags/v4'), null);
});

test('resolve: tenta a tag primeiro e depois a branch, só em github.com e sem prompt de senha', async () => {
  const calls = [];
  const run = (cmd, args, opts) => {
    calls.push({ cmd, args, env: opts.env.GIT_TERMINAL_PROMPT });
    if (args[2] === 'refs/heads/main') return `${B}\trefs/heads/main\n`;
    return '';
  };
  const r = await makeGitResolver({ run })('actions/checkout', 'main');
  assert.deepEqual(r, { sha: B, kind: 'branch' });
  assert.equal(calls[0].cmd, 'git');
  assert.equal(calls[0].args[1], 'https://github.com/actions/checkout.git');
  assert.equal(calls[0].args[2], 'refs/tags/main');
  assert.ok(calls.every((c) => c.env === '0'));
});

test('resolve: nome ou referência suspeitos nunca chegam ao git', async () => {
  let called = 0;
  const resolve = makeGitResolver({ run: () => { called += 1; return `${A}\trefs/tags/v1\n`; } });
  for (const [repo, ref] of [['../x/y', 'v1'], ['a/b/c', 'v1'], ['a/b', 'v1;touch x'], ['a b/c', 'v1'], ['a/..', 'v1'], ['a/b', '']]) {
    assert.equal(await resolve(repo, ref), null, `${repo}@${ref}`);
  }
  assert.equal(called, 0);
});

test('resolve: erro do git (rede, repositório privado) vira null, e há teto de consultas', async () => {
  const falha = makeGitResolver({ run: () => { throw new Error('sem rede'); } });
  assert.equal(await falha('actions/checkout', 'v4'), null);
  const limitado = makeGitResolver({ run: () => `${A}\trefs/tags/v1\n`, maxLookups: 1 });
  assert.ok(await limitado('a/b', 'v1'));
  assert.equal(await limitado('a/c', 'v1'), null);
});
