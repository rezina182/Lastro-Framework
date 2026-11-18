'use strict';

// Cliente das sondas autenticadas. Todas as requisições passam pelo ctx.fetch do motor, então valem o ritmo
// mínimo e o teto de requisições. Cookies e senhas nunca são copiados para resultados, avisos ou mensagens.

const { makeJar } = require('./cookiejar');

function encodeBody(format, obj) {
  if (format === 'form') return new URLSearchParams(Object.entries(obj).map(([k, v]) => [k, String(v)])).toString();
  return JSON.stringify(obj);
}

const contentType = (format) => (format === 'form' ? 'application/x-www-form-urlencoded' : 'application/json');

const is2xx = (res) => res && res.ok === true && res.status >= 200 && res.status < 300;

// Resposta 2xx que é, na verdade, uma negação curta ("{"error":"forbidden"}"): não conta como acesso concedido.
const DENIAL = /not\s*found|forbidden|unauthori[sz]ed|access denied|permission|negad|proibid|n[aã]o encontrad|sem permiss/i;
const looksDenied = (res) => typeof res.body === 'string' && res.body.length < 300 && DENIAL.test(res.body);

/** Acesso concedido: 2xx que não parece uma negação disfarçada. */
const granted = (res) => is2xx(res) && !looksDenied(res);

// Contador do módulo: a chave de cache nunca se repete, nem entre clientes que compartilham o mesmo contexto.
let sequence = 0;

function makeClient(ctx) {
  /** Envia uma requisição. `jar` envia e absorve cookies; `cookie` força um cabeçalho Cookie (replay de sessão antiga). */
  async function send(method, path, { jar = null, cookie = null, headers = {}, body } = {}) {
    const h = { ...headers };
    const c = cookie !== null ? cookie : (jar && jar.size() ? jar.header() : '');
    if (c) h.cookie = c;
    sequence += 1;
    const res = await ctx.fetch(path, { method, headers: h, body, cacheKey: `auth:${sequence}` });
    if (jar && res.ok) jar.absorb(res.setCookie);
    return res;
  }
  return { send };
}

/** Entra com uma conta. Devolve { ok, jar } ou { ok: false, reason }. A razão nunca traz usuário, senha ou cookie. */
async function login(client, cfg, account, label, legit) {
  const l = cfg.login;
  const format = l.format || 'json';
  const body = encodeBody(format, { [l.userField || 'username']: account.user, [l.passwordField || 'password']: account.password });
  const jar = makeJar();
  const res = await client.send('POST', l.path, { jar, headers: { ...legit, 'content-type': contentType(format) }, body });
  if (!res.ok) return { ok: false, reason: `login da conta ${label} sem resposta (${res.error})` };
  if (res.status >= 400) return { ok: false, reason: `login da conta ${label} recusado (HTTP ${res.status})` };
  if (jar.size() === 0) return { ok: false, reason: `o login da conta ${label} não devolveu cookie de sessão` };
  let token = null;
  if (cfg.csrfToken) {
    try { token = JSON.parse(res.body)[cfg.csrfToken.field]; } catch (e) { token = null; }
    if (typeof token !== 'string' || token.length === 0 || token.length > 512) {
      return { ok: false, reason: `o login da conta ${label} não devolveu o token anti-CSRF no campo "${cfg.csrfToken.field}"` };
    }
  }
  const me = await client.send('GET', cfg.protected, { jar });
  if (!is2xx(me)) return { ok: false, reason: `a conta ${label} entrou, mas ${cfg.protected} não aceitou a sessão (HTTP ${me.status || 0})` };
  return { ok: true, jar, token };
}

/** Cabeçalho do token anti-CSRF da conta, para requisições legítimas. Vazio se o perfil não declara token. */
function tokenHeader(cfg, token) {
  return cfg.csrfToken && token ? { [cfg.csrfToken.header.toLowerCase()]: token } : {};
}

module.exports = { makeClient, login, tokenHeader, encodeBody, contentType, is2xx, granted, looksDenied };
