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
const { makeJar } = require('./cookiejar');

const EVIL_ORIGIN = 'https://lastro-probe.invalid';
const NOTE = 'Sonda autenticada:';
const CONTROLS = ['AUTH-027', 'WEB-013', 'AUTH-023', 'AUTH-022', 'WEB-010', 'CORE-056', 'AUTH-028'];

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

// Troca o último caractere por outro do mesmo alfabeto: o valor continua com cara de válido, mas não é o emitido.
function tamper(value) {
  const last = value.slice(-1);
  const pool = /[0-9]/.test(last) ? '0123456789' : /[a-f]/.test(last) ? 'abcdef' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  return value.slice(0, -1) + pool[(pool.indexOf(last) + 1) % pool.length];
}

/**
 * AUTH-022: o servidor só aceita o token que emitiu (o adulterado é recusado) e emite um token novo a cada login
 * (quem já tinha a sessão antiga não ganha a nova: proteção contra fixação de sessão).
 */
function sessionCookie(jar) {
  const names = jar.names();
  const name = names.find((n) => /sess|sid|auth|token|connect/i.test(n)) || names[0];
  return name ? { name, value: jar.get(name) } : null;
}

/** AUTH-022, parte 1 (com a sessão viva): o servidor só aceita o token que emitiu. */
async function probeTamper(client, cfg, jars, out) {
  const s = sessionCookie(jars.a);
  if (!s) { out.notes.push(`${NOTE} inconclusiva na sessão: o login não deixou cookie identificável.`); return null; }
  if (!s.value || s.value.length < 8) { out.notes.push(`${NOTE} inconclusiva na sessão: o cookie ${s.name} é curto demais para o teste.`); return null; }
  const forged = await client.send('GET', cfg.protected, { cookie: `${s.name}=${tamper(s.value)}` });
  out.tested += 1;
  if (is2xx(forged)) out.findings.push({ severity: 'critical', key: `session-tamper:${s.name}`, location: cfg.protected, message: `${cfg.protected} aceitou o cookie ${s.name} com um caractere alterado (HTTP ${forged.status}): o servidor não confere o token que emitiu.` });
  return s;
}

/**
 * AUTH-022, parte 2 (depois do logout): um login novo, levando o cookie antigo, recebe outro valor. Se o valor fica o
 * mesmo, quem plantou o cookie antes do login (fixação de sessão) ganha a sessão autenticada.
 */
async function probeRotation(client, cfg, accounts, jars, legit, before, out) {
  if (!before) return;
  // O logout pode ter apagado o cookie do pote: o login novo leva explicitamente o valor antigo.
  const again = await login(client, cfg, accounts.a, 'a', legit, makeJar([[before.name, before.value]]));
  if (!again.ok) { out.notes.push(`${NOTE} renovação no login inconclusiva: ${again.reason}.`); return; }
  out.tested += 1;
  if (again.jar.get(before.name) === before.value) out.findings.push({ severity: 'high', key: `session-fixation:${before.name}`, location: cfg.login.path, message: `Um novo login manteve o mesmo valor do cookie ${before.name}: o token de sessão não é renovado a cada autenticação (fixação de sessão).` });
}

// Campos que nunca deveriam sair numa resposta da API (CORE-056): segredo, hash de senha, segundo fator, token de troca.
const SECRET_FIELD = /^(password|passwd|senha|senha_?hash|password_?hash|hash_?senha|pass_?hash|salt|mfa_?secret|totp_?secret|otp_?secret|mfa_?segredo\w*|segredo_?mfa|reset_?token|token_?reset|refresh_?token|api_?key|secret|private_?key)$/i;

/** Nomes de campo sensíveis em qualquer nível de um JSON (até 4 níveis e 200 chaves, para não varrer resposta enorme). */
function secretFields(text) {
  let j;
  try { j = JSON.parse(text); } catch (e) { return []; }
  const found = new Set();
  let seen = 0;
  const walk = (v, depth) => {
    if (depth > 4 || seen > 200 || v === null || typeof v !== 'object') return;
    for (const [k, x] of Object.entries(v)) {
      seen += 1;
      if (SECRET_FIELD.test(k) && x !== null && x !== '' && typeof x !== 'boolean') found.add(k);
      walk(x, depth + 1);
    }
  };
  walk(j, 0);
  return [...found];
}

/** CORE-056, parte 1: a rota autenticada e os objetos da própria conta não devolvem campo secreto. */
async function probeLeaks(client, cfg, jars, out) {
  const paths = [cfg.protected, ...(cfg.objects || []).map((o) => fill(o.path, o.ids.a))];
  for (const p of paths.slice(0, 10)) {
    const res = await client.send('GET', p, { jar: jars.a });
    if (!is2xx(res)) continue;
    out.tested += 1;
    const leak = secretFields(res.body || '');
    if (leak.length) out.findings.push({ severity: 'high', key: `field-leak:${p}:${leak.sort().join(',')}`, location: p, message: `${p} devolve campo(s) que nunca deveriam sair da API: ${leak.join(', ')}. Monte a resposta com uma lista de campos permitidos.` });
  }
}

// Campos que um usuário comum tenta promover numa edição (AUTH-028). O valor é marcado para ser reconhecido na leitura.
const MASS_FIELDS = { role: 'admin', isAdmin: true, admin: true, papel: 'admin', perfil: 'admin', ownerId: 'lastro-probe', userId: 'lastro-probe', status: 'lastro-probe' };

/**
 * AUTH-028 e CORE-056, parte 2: atribuição em massa. Para cada rota de edição declarada no perfil (massAssignment),
 * manda a edição legítima com campos extras e relê o registro: se algum extra voltou gravado, a rota aceita campo
 * que o usuário não devia controlar. Só a conta a, só nos registros dela.
 */
async function probeMass(client, cfg, jars, legit, out) {
  for (const m of cfg.massAssignment || []) {
    const format = m.format || 'json';
    const headers = { 'content-type': contentType(format), ...legit, ...tokenHeader(cfg, jars.tokens.a) };
    const extra = Object.fromEntries(Object.entries(MASS_FIELDS).filter(([k]) => !(k in (m.body || {}))));
    // Primeiro a edição legítima sozinha: sem ela, uma recusa da edição com extras não prova nada.
    const plain = await client.send(m.method, m.path, { jar: jars.a, headers, body: encodeBody(format, m.body || {}) });
    if (!granted(plain)) { out.notes.push(`${NOTE} atribuição em massa inconclusiva em ${m.method} ${m.path}: a edição legítima foi recusada (HTTP ${plain.status || 0}); confira "body" no perfil.`); continue; }
    const res = await client.send(m.method, m.path, { jar: jars.a, headers, body: encodeBody(format, { ...(m.body || {}), ...extra }) });
    if (res.ok && res.status >= 400 && res.status < 500) {
      // A legítima passou e a com campos extras foi recusada: validação estrita, o comportamento esperado.
      out.tested += 1;
      out.notes.push(`${NOTE} ${m.method} ${m.path} recusou (HTTP ${res.status}) a edição com campos extras (${Object.keys(extra).slice(0, 4).join(', ')}...) e aceitou a legítima.`);
      continue;
    }
    if (!granted(res)) { out.notes.push(`${NOTE} atribuição em massa inconclusiva em ${m.method} ${m.path}: resposta inesperada à edição com campos extras (HTTP ${res.status || 0}).`); continue; }
    const back = await client.send('GET', m.read || m.path, { jar: jars.a });
    if (!is2xx(back)) { out.notes.push(`${NOTE} atribuição em massa inconclusiva: ${m.read || m.path} não pôde ser relido (HTTP ${back.status || 0}).`); continue; }
    out.tested += 1;
    let j = null;
    try { j = JSON.parse(back.body); } catch (e) { j = null; }
    const flat = j && typeof j === 'object' ? { ...j, ...(j.data && typeof j.data === 'object' ? j.data : {}), ...(j.user && typeof j.user === 'object' ? j.user : {}) } : {};
    const stuck = Object.keys(extra).filter((k) => k in flat && flat[k] === extra[k]);
    if (stuck.length) out.findings.push({ severity: 'high', key: `mass-assign:${m.method}:${m.path}:${stuck.sort().join(',')}`, location: m.path, message: `${m.method} ${m.path} gravou campo(s) que o usuário não devia controlar: ${stuck.join(', ')}. Aceite só uma lista fixa de campos editáveis.` });
  }
}

/** WEB-010: a resposta autenticada não pode ficar em cache compartilhado nem no disco do navegador. */
async function probeCache(client, cfg, jars, out) {
  const res = await client.send('GET', cfg.protected, { jar: jars.a });
  if (!is2xx(res)) return;
  out.tested += 1;
  const cc = String(res.headers['cache-control'] || '').toLowerCase();
  if (!/no-store/.test(cc) && !/private/.test(cc)) out.findings.push({ severity: 'medium', key: `auth-cache:${cfg.protected}`, location: cfg.protected, message: `A rota autenticada ${cfg.protected} responde sem Cache-Control: no-store${cc ? ` (veio "${cc.slice(0, 60)}")` : ''}: proxies e o navegador podem guardar dados da conta.` });
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
  await probeCache(client, cfg, jars, results['WEB-010']);
  await probeLeaks(client, cfg, jars, results['CORE-056']);
  await probeMass(client, cfg, jars, legit, results['AUTH-028']);
  // A mesma atribuição em massa também reprova o CORE-056 (bloquear atribuição em massa faz parte dele).
  for (const f of results['AUTH-028'].findings) results['CORE-056'].findings.push({ ...f, key: `${f.key}:core` });
  results['CORE-056'].tested += results['AUTH-028'].tested;
  const session = await probeTamper(client, cfg, jars, results['AUTH-022']);
  // O logout encerra a sessão da conta a; a renovação vem depois, com um login novo.
  await probeLogout(client, cfg, jars, legit, results['AUTH-023']);
  await probeRotation(client, cfg, accounts, jars, legit, session, results['AUTH-022']);

  const what = {
    'AUTH-027': 'leituras entre contas e sem login', 'WEB-013': 'requisições de origem estranha', 'AUTH-023': 'replay do cookie após o logout',
    'AUTH-022': 'cookie adulterado e renovação no login', 'WEB-010': 'Cache-Control da rota autenticada',
    'CORE-056': 'campos secretos nas respostas e atribuição em massa', 'AUTH-028': 'campos extras gravados numa edição',
  };
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
