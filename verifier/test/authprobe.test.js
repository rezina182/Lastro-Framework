'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { runAuthProbes, readAccounts, NOTE } = require('../src/authprobe');
const { ctxFor, makeProject, cleanup } = require('./helpers');
const { app, ACCOUNTS } = require('./authapp');

const CFG = {
  login: { path: '/login' },
  accounts: { a: { userEnv: 'T_A_USER', passwordEnv: 'T_A_PASS' }, b: { userEnv: 'T_B_USER', passwordEnv: 'T_B_PASS' } },
  protected: '/api/me',
  logout: { path: '/logout', method: 'POST' },
  objects: [{ path: '/api/orders/{id}', ids: { a: '1', b: '2' } }],
  csrf: [{ path: '/api/profile', method: 'POST', body: { nome: 'teste' } }],
};

async function probe(opt, cfg = CFG, accounts = ACCOUNTS) {
  const srv = await app(opt);
  const root = makeProject({});
  try {
    return await runAuthProbes(ctxFor(root, { url: srv.url }), cfg, accounts);
  } finally {
    await srv.close();
    cleanup(root);
  }
}

const keysOf = (r, id) => r.results[id].findings.map((f) => f.key);

test('authprobe: aplicação correta passa, mas passar só vira nota (não verifica o controle)', async () => {
  const r = await probe({});
  assert.equal(r.inconclusive, null);
  for (const id of ['AUTH-027', 'WEB-013', 'AUTH-023']) {
    assert.deepEqual(r.results[id].findings, [], id);
    assert.match(r.results[id].notes[0], new RegExp(`^${NOTE} passou em \\d+ teste`), id);
    assert.match(r.results[id].notes[0], /não verifica o controle/, id);
  }
  assert.equal(r.results['AUTH-027'].tested, 3);
});

test('authprobe: acesso por objeto quebrado entre contas é crítico, nos dois sentidos', async () => {
  const r = await probe({ bola: true });
  assert.deepEqual(keysOf(r, 'AUTH-027'), ['bola:a->b:/api/orders/{id}', 'bola:b->a:/api/orders/{id}']);
  assert.ok(r.results['AUTH-027'].findings.every((f) => f.severity === 'critical'));
  assert.match(r.results['AUTH-027'].findings[0].message, /a conta a leu o objeto da conta b/);
});

test('authprobe: objeto privado legível sem login é achado alto', async () => {
  const r = await probe({ anonRead: true });
  assert.ok(keysOf(r, 'AUTH-027').includes('anon:/api/orders/{id}'));
  assert.equal(r.results['AUTH-027'].findings.find((f) => f.key.startsWith('anon:')).severity, 'high');
});

test('authprobe: CSRF só é achado quando a requisição legítima passa e a forjada também', async () => {
  const r = await probe({ csrf: true });
  assert.deepEqual(keysOf(r, 'WEB-013'), ['csrf:POST:/api/profile']);
  const bad = await probe({}, { ...CFG, csrf: [{ path: '/api/inexistente', method: 'POST', body: {} }] });
  assert.deepEqual(bad.results['WEB-013'].findings, []);
  assert.match(bad.results['WEB-013'].notes.join(' '), /inconclusiva em POST \/api\/inexistente/);
});

test('authprobe: logout que só apaga o cookie é achado (replay do cookie antigo)', async () => {
  const r = await probe({ logoutBug: true });
  assert.deepEqual(keysOf(r, 'AUTH-023'), ['logout-replay']);
  assert.match(r.results['AUTH-023'].findings[0].message, /não é encerrada no servidor/);
});

test('authprobe: rota protegida aberta ou login recusado deixam tudo inconclusivo, sem achado', async () => {
  const open = await probe({ openProtected: true, bola: true });
  assert.match(open.inconclusive, /respondeu 2xx sem login/);
  for (const id of ['AUTH-027', 'WEB-013', 'AUTH-023']) {
    assert.deepEqual(open.results[id].findings, [], id);
    assert.match(open.results[id].notes[0], /inconclusiva/, id);
  }
  const wrong = await probe({}, CFG, { a: { user: 'alice', password: 'errada-123' }, b: ACCOUNTS.b });
  assert.match(wrong.inconclusive, /login da conta a recusado/);
  assert.doesNotMatch(JSON.stringify(wrong), /errada-123/);
});

test('authprobe: só testa o que o perfil declara', async () => {
  const r = await probe({}, { login: CFG.login, accounts: CFG.accounts, protected: CFG.protected });
  for (const id of ['AUTH-027', 'WEB-013', 'AUTH-023']) assert.match(r.results[id].notes[0], /nada a testar/, id);
});

test('authprobe: nenhum resultado carrega cookie, senha ou usuário', async () => {
  const r = await probe({ bola: true, csrf: true, logoutBug: true });
  assert.doesNotMatch(JSON.stringify(r), /sid=|"pa"|"pb"|alice|bob/);
});

test('authprobe: as contas vêm do ambiente e só os NOMES que faltam são apontados', () => {
  const env = { T_A_USER: 'u1', T_A_PASS: 'segredo-a', T_B_USER: 'u1' };
  const r = readAccounts(CFG, env);
  assert.deepEqual(r.missing, ['T_B_PASS']);
  assert.equal(r.sameUser, true);
  assert.doesNotMatch(JSON.stringify(r.missing), /segredo-a/);
  assert.deepEqual(readAccounts(CFG, { T_A_USER: 'a', T_A_PASS: 'x', T_B_USER: 'b', T_B_PASS: 'y' }).missing, []);
});
