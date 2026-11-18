'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { validateAuthProbes } = require('../src/authschema');
const { validateProfile } = require('../src/schema');
const { ALL_FALSE } = require('./helpers');

const valid = () => ({
  login: { path: '/login', format: 'json', userField: 'username', passwordField: 'password' },
  accounts: { a: { userEnv: 'LASTRO_A_USER', passwordEnv: 'LASTRO_A_PASS' }, b: { userEnv: 'LASTRO_B_USER', passwordEnv: 'LASTRO_B_PASS' } },
  protected: '/api/me',
  logout: { path: '/logout', method: 'POST' },
  objects: [{ path: '/api/orders/{id}', ids: { a: '1', b: '2' } }],
  csrf: [{ path: '/api/profile', method: 'POST', format: 'json', body: { nome: 'teste' } }],
});

test('authProbes: configuração completa e válida é aceita, e o perfil também', () => {
  assert.deepEqual(validateAuthProbes(valid()), []);
  const profile = { schemaVersion: 1, name: 'x', flags: ALL_FALSE, authProbes: valid() };
  assert.deepEqual(validateProfile(profile), []);
});

test('authProbes: só o mínimo (login, duas contas e rota protegida) basta', () => {
  const a = valid();
  delete a.logout; delete a.objects; delete a.csrf;
  assert.deepEqual(validateAuthProbes(a), []);
});

test('authProbes: a senha nunca entra no perfil (só o nome da variável de ambiente)', () => {
  const a = valid();
  a.accounts.a.passwordEnv = 'senha-de-verdade-123';
  assert.match(validateAuthProbes(a).join('\n'), /NOME de uma variável de ambiente/);
  const b = valid();
  b.accounts.a.password = 'x';
  assert.match(validateAuthProbes(b).join('\n'), /campo desconhecido "password"/);
});

test('authProbes: contas iguais, objetos iguais e caminhos inseguros são recusados', () => {
  const a = valid();
  a.accounts.b.userEnv = 'LASTRO_A_USER';
  a.objects[0].ids.b = '1';
  a.objects.push({ path: '/api/sem-id', ids: { a: '1', b: '2' } });
  a.login.path = '//evil.example/x';
  a.protected = 'api/me';
  a.csrf[0].method = 'GET';
  const errs = validateAuthProbes(a).join('\n');
  for (const re of [/usuários diferentes/, /objeto da conta a e o da conta b/, /use \{id\}/, /login\.path/, /protected/, /csrf\[0\]\.method/]) assert.match(errs, re);
});

test('authProbes: csrfToken com campo e cabeçalho válidos; cabeçalho reservado é recusado', () => {
  assert.deepEqual(validateAuthProbes({ ...valid(), csrfToken: { field: 'csrfToken', header: 'X-CSRF-Token' } }), []);
  assert.match(validateAuthProbes({ ...valid(), csrfToken: { field: 'csrfToken', header: 'Cookie' } }).join('\n'), /reservado/);
  assert.match(validateAuthProbes({ ...valid(), csrfToken: { field: 'x y', header: 'X-T' } }).join('\n'), /csrfToken\.field/);
  assert.match(validateAuthProbes({ ...valid(), csrfToken: { header: 'X-T' } }).join('\n'), /ausente "field"/);
});

test('authProbes: campos obrigatórios, desconhecidos e tipos errados', () => {
  assert.match(validateAuthProbes({}).join('\n'), /campo obrigatório ausente "login"/);
  assert.match(validateAuthProbes('x').join('\n'), /deve ser objeto/);
  const a = valid();
  a.extra = 1;
  a.objects = Array.from({ length: 21 }, () => ({ path: '/x/{id}', ids: { a: '1', b: '2' } }));
  a.csrf[0].format = 'form';
  a.csrf[0].body = { cookie: { dentro: 1 } };
  const errs = validateAuthProbes(a).join('\n');
  for (const re of [/campo desconhecido "extra"/, /lista de até 20/, /body\.cookie: em formulário/]) assert.match(errs, re);
  // Em JSON, corpo estruturado (listas, objetos) é aceito, com limite de tamanho.
  const j = valid();
  j.csrf[0].body = { titulo: 'x', perguntas: [{ tipo: 'vf', enunciado: 'a?', correta: 0 }] };
  assert.deepEqual(validateAuthProbes(j), []);
  j.csrf[0].body = { grande: 'x'.repeat(5000) };
  assert.match(validateAuthProbes(j).join('\n'), /até 4000 caracteres/);
});
