'use strict';

// Sondas autenticadas (lastro check --auth). Entram com duas contas de TESTE e provam o que só aparece depois do
// login: acesso por objeto entre contas (AUTH-027), CSRF (WEB-013) e logout que encerra a sessão (AUTH-023).
// O cookie de sessão (AUTH-003) é analisado pela sonda de cookies existente, que passa a ver o cookie do login.
//
// Regras (docs/SONDAS-AUTENTICADAS.md):
//  - só com --auth --confirm-non-production, nunca contra urls.production (a trava fica no motor);
//  - achar a falha vale como prova de máquina: o controle fica "falhou";
//  - passar NÃO verifica o controle: a sonda só testou as rotas declaradas no perfil. O controle segue
//    dependendo de atestação, com a nota do que foi provado. Desconhecido não é aprovado;
//  - qualquer dúvida (login recusado, rota protegida aberta, requisição legítima recusada) vira "inconclusivo".

const { makeClient, login, tokenHeader, encodeBody, contentType, is2xx, granted } = require('./authclient');

const EVIL_ORIGIN = 'https://lastro-probe.invalid';
const NOTE = 'Sonda autenticada:';
const CONTROLS = ['AUTH-027', 'WEB-013', 'AUTH-023'];

const fill = (tpl, id) => tpl.replace('{id}', encodeURIComponent(id));

function emptyResults() {
  return Object.fromEntries(CONTROLS.map((id) => [id, { findings: [], notes: [], tested: 0 }]));
}

function inconclusive(reason) {
  const results = emptyResults();
  for (const id of CONTROLS) results[id].notes.push(`${NOTE} inconclusiva: ${reason}.`);
  return { ran: true, inconclusive: reason, results };
}

async function probeObjects(client, cfg, jars, legit, out) {
  for (const o of cfg.objects || []) {
    const url = (acc) => fill(o.path, o.ids[acc]);
    const ownA = await client.send('GET', url('a'), { jar: jars.a });
    const ownB = await client.send('GET', url('b'), { jar: jars.b });
    if (!granted(ownA) || !granted(ownB)) {
      out.notes.push(`${NOTE} inconclusiva em ${o.path}: uma conta não conseguiu ler o próprio objeto (HTTP ${ownA.status || 0} e ${ownB.status || 0}). Confira os identificadores no perfil.`);
      continue;
    }
    for (const [from, to] of [['a', 'b'], ['b', 'a']]) {
      const r = await client.send('GET', url(to), { jar: jars[from] });
      out.tested += 1;
      if (granted(r)) out.findings.push({ severity: 'critical', key: `bola:${from}->${to}:${o.path}`, location: o.path, message: `Acesso por objeto quebrado: a conta ${from} leu o objeto da conta ${to} em ${o.path} (HTTP ${r.status}). Contas diferentes devem receber 403 ou 404.` });
    }
    const anon = await client.send('GET', url('a'), {});
    out.tested += 1;
    if (granted(anon)) out.findings.push({ severity: 'high', key: `anon:${o.path}`, location: o.path, message: `Objeto privado legível sem login em ${o.path} (HTTP ${anon.status}). Se o dado é público, tire a rota de "objects" no perfil.` });
  }
}

async function probeCsrf(client, cfg, jars, legit, out) {
  for (const c of cfg.csrf || []) {
    const format = c.format || 'json';
    const base = { 'content-type': contentType(format) };
    const body = encodeBody(format, c.body || {});
    // Primeiro a requisição legítima (com o token, se o perfil declara um): sem ela, recusar a forjada não prova nada.
    const ok = await client.send(c.method, c.path, { jar: jars.a, headers: { ...base, ...legit, ...tokenHeader(cfg, jars.tokens.a) }, body });
    if (!granted(ok)) {
      out.notes.push(`${NOTE} inconclusiva em ${c.method} ${c.path}: a requisição legítima não foi aceita (HTTP ${ok.status || 0}). Ajuste "body" no perfil${cfg.csrfToken ? '' : ' ou declare "csrfToken" se a aplicação usa token anti-CSRF'}.`);
      continue;
    }
    // A forjada imita outro site: origem estranha e sem o token (outro site não consegue lê-lo).
    const forged = await client.send(c.method, c.path, { jar: jars.a, headers: { ...base, origin: EVIL_ORIGIN, 'sec-fetch-site': 'cross-site' }, body });
    out.tested += 1;
    if (granted(forged)) out.findings.push({ severity: 'high', key: `csrf:${c.method}:${c.path}`, location: c.path, message: `${c.method} ${c.path} aceitou, com a sessão da conta a, uma requisição de origem estranha e sem token anti-CSRF (HTTP ${forged.status}). O navegador só envia o cookie conforme o SameSite, mas o servidor deve recusar por conta própria.` });
  }
}

async function probeLogout(client, cfg, jars, legit, out) {
  if (!cfg.logout) return;
  const old = jars.a.header();
  const before = await client.send('GET', cfg.protected, { cookie: old });
  if (!is2xx(before)) {
    out.notes.push(`${NOTE} inconclusiva no logout: a sessão da conta a já não era aceita em ${cfg.protected} (HTTP ${before.status || 0}).`);
    return;
  }
  const method = cfg.logout.method || 'POST';
  const extra = method === 'GET' ? {} : { 'content-type': 'application/json' };
  const lo = await client.send(method, cfg.logout.path, { jar: jars.a, headers: { ...legit, ...extra, ...tokenHeader(cfg, jars.tokens.a) }, body: method === 'GET' ? undefined : '{}' });
  if (!lo.ok) {
    out.notes.push(`${NOTE} inconclusiva no logout: ${cfg.logout.path} sem resposta (${lo.error}).`);
    return;
  }
  // Logout recusado (token, método, origem): a sessão seguir válida é o esperado, não um achado.
  if (!is2xx(lo) && !(lo.status >= 300 && lo.status < 400)) {
    out.notes.push(`${NOTE} inconclusiva no logout: ${cfg.logout.path} recusou o pedido (HTTP ${lo.status})${cfg.csrfToken ? '' : '; se a aplicação exige token anti-CSRF, declare "csrfToken" no perfil'}.`);
    return;
  }
  // Replay do cookie antigo: se ainda vale, o logout só apagou o cookie no navegador.
  const after = await client.send('GET', cfg.protected, { cookie: old });
  out.tested += 1;
  if (is2xx(after)) out.findings.push({ severity: 'high', key: 'logout-replay', location: cfg.logout.path, message: `Depois do logout em ${cfg.logout.path}, o cookie de sessão antigo ainda é aceito em ${cfg.protected} (HTTP ${after.status}): a sessão não é encerrada no servidor.` });
}

/**
 * Roda as sondas. `accounts` = { a: { user, password }, b: { user, password } } (lidas do ambiente pelo motor).
 * Devolve { ran, inconclusive, results: { 'AUTH-027': { findings, notes, tested }, ... } }.
 */
async function runAuthProbes(ctx, cfg, accounts) {
  const client = makeClient(ctx);
  const origin = new URL(ctx.url).origin;
  const legit = { origin, 'sec-fetch-site': 'same-origin' };

  const anon = await client.send('GET', cfg.protected, {});
  if (!anon.ok) return inconclusive(`${cfg.protected} sem resposta (${anon.error})`);
  if (is2xx(anon)) return inconclusive(`${cfg.protected} respondeu 2xx sem login: escolha, em "protected", uma rota que exija sessão`);

  const a = await login(client, cfg, accounts.a, 'a', legit);
  if (!a.ok) return inconclusive(a.reason);
  const b = await login(client, cfg, accounts.b, 'b', legit);
  if (!b.ok) return inconclusive(b.reason);
  const jars = { a: a.jar, b: b.jar, tokens: { a: a.token, b: b.token } };

  const results = emptyResults();
  await probeObjects(client, cfg, jars, legit, results['AUTH-027']);
  await probeCsrf(client, cfg, jars, legit, results['WEB-013']);
  await probeLogout(client, cfg, jars, legit, results['AUTH-023']);

  const what = { 'AUTH-027': 'leituras entre contas e sem login', 'WEB-013': 'requisições de origem estranha', 'AUTH-023': 'replay do cookie após o logout' };
  for (const id of CONTROLS) {
    const r = results[id];
    if (r.tested > 0 && r.findings.length === 0) {
      r.notes.unshift(`${NOTE} passou em ${r.tested} teste(s) (${what[id]}) nas rotas declaradas no perfil. Isso não verifica o controle: o que não está no perfil não foi testado.`);
    } else if (r.tested === 0 && r.notes.length === 0) {
      r.notes.push(`${NOTE} nada a testar: o perfil não declara rotas para este controle.`);
    }
  }
  return { ran: true, inconclusive: null, results };
}

/**
 * Lê as contas de teste das variáveis de ambiente que o perfil nomeia. Devolve só os NOMES que faltam, nunca valores.
 */
function readAccounts(cfg, env) {
  const accounts = {};
  const missing = [];
  for (const k of ['a', 'b']) {
    const acc = cfg.accounts[k];
    const user = env[acc.userEnv];
    const password = env[acc.passwordEnv];
    if (!user) missing.push(acc.userEnv);
    if (!password) missing.push(acc.passwordEnv);
    accounts[k] = { user, password };
  }
  return { accounts, missing, sameUser: !!accounts.a.user && accounts.a.user === accounts.b.user };
}

module.exports = { runAuthProbes, readAccounts, NOTE, CONTROLS, EVIL_ORIGIN };
