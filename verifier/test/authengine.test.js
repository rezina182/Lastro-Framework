'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { runCheck, ConfigError } = require('../src/engine');
const { makeProject, profileJson, cleanup, ALL_FALSE } = require('./helpers');
const { app } = require('./authapp');

const NOW = new Date('2026-11-12T12:00:00Z');
const ENV = { T_A_USER: 'alice', T_A_PASS: 'pa', T_B_USER: 'bob', T_B_PASS: 'pb' };
const AUTH = {
  login: { path: '/login' },
  accounts: { a: { userEnv: 'T_A_USER', passwordEnv: 'T_A_PASS' }, b: { userEnv: 'T_B_USER', passwordEnv: 'T_B_PASS' } },
  protected: '/api/me',
  logout: { path: '/logout' },
  objects: [{ path: '/api/orders/{id}', ids: { a: '1', b: '2' } }],
  csrf: [{ path: '/api/profile', method: 'POST', body: { nome: 'teste' } }],
};
const flags = { webApp: true, hasAuth: true };
const attest = (id) => ({ state: 'verified', attestedBy: 'Fulana', collectedAt: '2026-11-01', expiresAt: '2027-05-01', evidenceRef: 'ticket' });

function project(extra = {}, files = {}) {
  return makeProject({ '.lastro/profile.json': profileJson(flags, { authProbes: AUTH, ...extra }), ...files });
}

async function run(root, url, opts = {}) {
  return runCheck({ root, url, now: NOW, auth: true, confirmNonProduction: true, delayMs: 50, env: ENV, ...opts });
}

const control = (r, id) => r.controls.find((c) => c.id === id);

test('motor --auth: falha achada pela sonda vence a atestação e vira prova de máquina', async () => {
  const srv = await app({ bola: true, csrf: true, logoutBug: true });
  const root = project({}, { '.lastro/status.json': JSON.stringify({ schemaVersion: 1, attestations: { 'AUTH-027': attest(), 'WEB-013': attest(), 'AUTH-023': attest() } }) });
  try {
    const r = await run(root, srv.url);
    for (const id of ['AUTH-027', 'WEB-013', 'AUTH-023']) {
      const c = control(r, id);
      assert.equal(c.state, 'failed', id);
      assert.equal(c.evidence.source, 'verifier-http', id);
      assert.ok(c.findings.length > 0, id);
    }
    assert.ok(control(r, 'AUTH-027').findings.some((f) => f.blocking && f.severity === 'critical'));
    assert.equal(r.verdict, 'fail');
    assert.equal(r.target.authProbes, true);
  } finally { await srv.close(); cleanup(root); }
});

test('motor --auth: sonda que passa não verifica o controle, mas respeita a atestação existente', async () => {
  const srv = await app({});
  const withAtt = project({}, { '.lastro/status.json': JSON.stringify({ schemaVersion: 1, attestations: { 'AUTH-027': attest() } }) });
  const without = project();
  try {
    const a = control(await run(withAtt, srv.url), 'AUTH-027');
    assert.equal(a.state, 'verified');
    assert.equal(a.evidence.source, 'manual-attestation');
    assert.match(a.notes[0], /^Sonda autenticada: passou/);
    const b = control(await run(without, srv.url), 'AUTH-027');
    assert.equal(b.state, 'unverified');
    assert.match(b.notes[0], /não verifica o controle/);
  } finally { await srv.close(); cleanup(withAtt); cleanup(without); }
});

test('motor --auth: o cookie do login entra na análise de cookies (AUTH-003)', async () => {
  const srv = await app({});
  const root = project({ paths: { login: '/login' } });
  try {
    const c = control(await run(root, srv.url), 'AUTH-003');
    assert.equal(c.state, 'failed');
    assert.ok(c.findings.some((f) => /"sid"/.test(f.message)), 'o cookie "sid" do login deve aparecer');
  } finally { await srv.close(); cleanup(root); }
});

test('motor --auth: trava igual à das sondas ativas e sem vazar valores', async () => {
  const root = project();
  try {
    await assert.rejects(() => runCheck({ root, now: NOW, auth: true, confirmNonProduction: true, env: ENV }), /--auth exige --url/);
    await assert.rejects(() => runCheck({ root, now: NOW, auth: true, url: 'http://127.0.0.1:1', env: ENV }), /confirme com --confirm-non-production/);
    const sameUser = { ...ENV, T_B_USER: 'alice' };
    await assert.rejects(() => run(root, 'http://127.0.0.1:1', { env: sameUser }), /mesmo usuário/);
    await assert.rejects(() => run(root, 'http://127.0.0.1:1', { env: { T_A_USER: 'alice', T_A_PASS: 'segredo-que-nao-pode-aparecer' } }), (e) => e instanceof ConfigError && /T_B_USER, T_B_PASS/.test(e.message) && !/segredo-que-nao-pode-aparecer/.test(e.message));
  } finally { cleanup(root); }
  const prod = project({ urls: { production: 'http://127.0.0.1:9' } });
  const noBlock = makeProject({ '.lastro/profile.json': profileJson(flags) });
  try {
    await assert.rejects(() => run(prod, 'http://127.0.0.1:9'), /produção/);
    await assert.rejects(() => run(noBlock, 'http://127.0.0.1:1'), /exige o bloco "authProbes"/);
  } finally { cleanup(prod); cleanup(noBlock); }
});

test('motor sem --auth: nada muda (nenhuma requisição de login, nenhum campo novo preenchido)', async () => {
  const srv = await app({ bola: true });
  const root = project();
  try {
    const r = await runCheck({ root, url: srv.url, now: NOW, delayMs: 50 });
    assert.equal(r.authProbe, null);
    assert.equal(r.target.authProbes, false);
    assert.equal(control(r, 'AUTH-027').state, 'unverified');
    assert.ok(!control(r, 'AUTH-027').notes.some((n) => /Sonda autenticada/.test(n)));
  } finally { await srv.close(); cleanup(root); }
});

test('perfil: ALL_FALSE continua válido e o bloco authProbes é opcional', () => {
  assert.equal(Object.keys(ALL_FALSE).length, 13);
});
