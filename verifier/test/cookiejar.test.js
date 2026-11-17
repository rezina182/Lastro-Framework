'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeJar, parseSetCookie } = require('../src/cookiejar');

test('cookiejar: guarda nome e valor, ignora atributos e linha malformada', () => {
  const jar = makeJar();
  jar.absorb(['sid=abc123; Path=/; HttpOnly; SameSite=Strict', 'tema=escuro', 'sem-igual', '=vazio']);
  assert.equal(jar.size(), 2);
  assert.equal(jar.header(), 'sid=abc123; tema=escuro');
  assert.deepEqual(jar.names(), ['sid', 'tema']);
});

test('cookiejar: o servidor apaga o cookie com valor vazio, Max-Age=0 ou data de 1970', () => {
  const jar = makeJar();
  jar.absorb(['a=1', 'b=2', 'c=3']);
  jar.absorb(['a=; Path=/', 'b=2; Max-Age=0', 'c=3; Expires=Thu, 01 Jan 1970 00:00:00 GMT']);
  assert.equal(jar.size(), 0);
  assert.equal(jar.header(), '');
});

test('cookiejar: o valor pode conter "=" e o último Set-Cookie vence', () => {
  const jar = makeJar();
  jar.absorb(['t=a=b==', 't=novo']);
  assert.equal(jar.header(), 't=novo');
  assert.deepEqual(parseSetCookie('x=y=z; Secure'), { name: 'x', value: 'y=z', removed: false });
  assert.equal(parseSetCookie('semigual'), null);
});
