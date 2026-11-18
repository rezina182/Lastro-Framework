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

test('authprobe: aplicação com token anti-CSRF no cabeçalho passa quando o perfil declara o token', async () => {
  const cfg = { ...CFG, csrfToken: { field: 'csrfToken', header: 'X-CSRF-Token' } };
  const r = await probe({ token: true }, cfg);
  assert.equal(r.inconclusive, null);
  for (const id of ['WEB-013', 'AUTH-023']) {
    assert.deepEqual(r.results[id].findings, [], id);
    assert.match(r.results[id].notes[0], /passou em/, id);
  }
  // Com token e o servidor aceitando origem estranha sem token, o CSRF é achado.
  const bad = await probe({ token: true, csrf: true }, cfg);
  assert.deepEqual(keysOf(bad, 'WEB-013'), ['csrf:POST:/api/profile']);
});

test('authprobe: sem declarar o token, a escrita legítima recusada fica inconclusiva e o logout recusado não vira falso positivo', async () => {
  const r = await probe({ token: true });
  assert.deepEqual(r.results['WEB-013'].findings, []);
  assert.match(r.results['WEB-013'].notes.join(' '), /declare "csrfToken"/);
  // O logout foi recusado (403), então a sessão continuar valendo é o esperado: nada de "logout-replay".
  assert.deepEqual(r.results['AUTH-023'].findings, []);
  assert.match(r.results['AUTH-023'].notes.join(' '), /inconclusiva no logout: \/logout recusou o pedido \(HTTP 403\)/);
});

test('authprobe: login que não devolve o token declarado é inconclusivo', async () => {
  const r = await probe({}, { ...CFG, csrfToken: { field: 'csrfToken', header: 'X-CSRF-Token' } });
  assert.match(r.inconclusive, /não devolveu o token anti-CSRF no campo "csrfToken"/);
});

test('authprobe: sessão sadia passa no cookie adulterado, na renovação no login e no Cache-Control', async () => {
  const r = await probe({});
  for (const id of ['AUTH-022', 'WEB-010']) {
    assert.deepEqual(r.results[id].findings, [], id);
    assert.match(r.results[id].notes[0], /passou em/, id);
  }
  assert.equal(r.results['AUTH-022'].tested, 2);
});

test('authprobe: cookie adulterado aceito é crítico; login que reaproveita o id é fixação de sessão', async () => {
  const t = await probe({ tamperBug: true });
  assert.ok(keysOf(t, 'AUTH-022').includes('session-tamper:sid'));
  assert.equal(t.results['AUTH-022'].findings[0].severity, 'critical');
  const f = await probe({ fixation: true });
  assert.deepEqual(keysOf(f, 'AUTH-022'), ['session-fixation:sid']);
  assert.match(f.results['AUTH-022'].findings[0].message, /não é renovado a cada autenticação/);
});

test('authprobe: rota autenticada sem Cache-Control: no-store é achado do WEB-010', async () => {
  const r = await probe({ cacheBug: true });
  assert.deepEqual(keysOf(r, 'WEB-010'), ['auth-cache:/api/me']);
});

test('authprobe: hash de senha na resposta autenticada é achado do CORE-056, sem configuração extra', async () => {
  const r = await probe({ leak: true });
  assert.deepEqual(keysOf(r, 'CORE-056'), ['field-leak:/api/me:senha_hash']);
  const ok = await probe({});
  assert.deepEqual(ok.results['CORE-056'].findings, []);
  assert.match(ok.results['CORE-056'].notes[0], /passou em/);
});

test('authprobe: atribuição em massa gravada reprova AUTH-028 e CORE-056; rota que filtra os campos passa', async () => {
  const cfg = { ...CFG, massAssignment: [{ path: '/api/conta', method: 'PATCH', body: { nome: 'Teste' }, read: '/api/conta' }] };
  const bad = await probe({ mass: true }, cfg);
  assert.equal(keysOf(bad, 'AUTH-028').length, 1);
  assert.match(bad.results['AUTH-028'].findings[0].message, /gravou campo\(s\) que o usuário não devia controlar: .*role/);
  assert.ok(keysOf(bad, 'CORE-056').some((k) => k.startsWith('mass-assign:')));
  const good = await probe({}, cfg);
  assert.deepEqual(good.results['AUTH-028'].findings, []);
  assert.match(good.results['AUTH-028'].notes[0], /passou em 1 teste/);
});

test('authschema: massAssignment valida método, caminho e corpo', () => {
  const { validateAuthProbes } = require('../src/authschema');
  const base = { login: CFG.login, accounts: CFG.accounts, protected: CFG.protected };
  assert.deepEqual(validateAuthProbes({ ...base, massAssignment: [{ path: '/api/conta', method: 'PATCH', body: { nome: 'x' } }] }), []);
  const errs = validateAuthProbes({ ...base, massAssignment: [{ path: 'api', method: 'GET', body: {} }] }).join(' ');
  for (const re of [/massAssignment\[0\]\.path/, /massAssignment\[0\]\.method/, /massAssignment\[0\]\.body/]) assert.match(errs, re);
});
