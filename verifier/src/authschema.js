'use strict';

// Validação do bloco "authProbes" do perfil (sondas autenticadas). Sem dependências.
// As senhas NUNCA ficam no perfil: ele só guarda o nome das variáveis de ambiente que as contêm.

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const ID_VALUE = /^[A-Za-z0-9_-]{1,64}$/;
const FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const FORMATS = ['json', 'form'];
const CSRF_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];
const LOGOUT_METHODS = ['POST', 'GET', 'DELETE'];
const MAX_LIST = 20;

function keys(obj, required, optional, where, errs) {
  for (const k of required) if (!(k in obj)) errs.push(`${where}: campo obrigatório ausente "${k}"`);
  for (const k of Object.keys(obj)) if (!required.includes(k) && !optional.includes(k)) errs.push(`${where}: campo desconhecido "${k}"`);
}

const routePath = (v, where, errs) => {
  if (typeof v !== 'string' || !v.startsWith('/') || v.startsWith('//') || v.length > 200 || /[\s\u0000-\u001f]/.test(v)) errs.push(`${where}: caminho deve começar com uma só "/", sem espaços (máx. 200)`);
};

function oneOf(v, list, where, errs) {
  if (!list.includes(v)) errs.push(`${where}: valor inválido (esperado: ${list.join('|')})`);
}

function validateAuthProbes(a) {
  const errs = [];
  const w = 'profile.authProbes';
  if (!isObj(a)) return [`${w}: deve ser objeto`];
  keys(a, ['login', 'accounts', 'protected'], ['logout', 'objects', 'csrf', 'csrfToken', 'massAssignment'], w, errs);

  // Rotas de edição da própria conta a, para a sonda de atribuição em massa (AUTH-028): edição legítima + releitura.
  if (a.massAssignment !== undefined) {
    if (!Array.isArray(a.massAssignment) || a.massAssignment.length > MAX_LIST) errs.push(`${w}.massAssignment: lista de até ${MAX_LIST} itens`);
    else {
      a.massAssignment.forEach((m, i) => {
        const mw = `${w}.massAssignment[${i}]`;
        if (!isObj(m)) { errs.push(`${mw}: deve ser objeto`); return; }
        keys(m, ['path', 'method', 'body'], ['read', 'format'], mw, errs);
        routePath(m.path, `${mw}.path`, errs);
        oneOf(m.method, ['POST', 'PUT', 'PATCH'], `${mw}.method`, errs);
        if (m.read !== undefined) routePath(m.read, `${mw}.read`, errs);
        if (m.format !== undefined) oneOf(m.format, FORMATS, `${mw}.format`, errs);
        if (!isObj(m.body) || Object.keys(m.body).length === 0 || Object.keys(m.body).length > 20 || JSON.stringify(m.body).length > 4000) errs.push(`${mw}.body: objeto com a edição legítima (1 a 20 campos, até 4000 caracteres)`);
      });
    }
  }

  // Token anti-CSRF por sessão: o login devolve no JSON (field) e as escritas legítimas o mandam num cabeçalho (header).
  if (a.csrfToken !== undefined) {
    if (!isObj(a.csrfToken)) errs.push(`${w}.csrfToken: deve ser objeto`);
    else {
      keys(a.csrfToken, ['field', 'header'], [], `${w}.csrfToken`, errs);
      if ('field' in a.csrfToken && !FIELD_NAME.test(String(a.csrfToken.field))) errs.push(`${w}.csrfToken.field: nome de campo inválido`);
      if ('header' in a.csrfToken && !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(String(a.csrfToken.header))) errs.push(`${w}.csrfToken.header: nome de cabeçalho inválido`);
      if (/^(cookie|host|origin|content-length|authorization)$/i.test(String(a.csrfToken.header))) errs.push(`${w}.csrfToken.header: escolha o cabeçalho do token, não um cabeçalho reservado`);
    }
  }

  if (isObj(a.login)) {
    keys(a.login, ['path'], ['format', 'userField', 'passwordField'], `${w}.login`, errs);
    routePath(a.login.path, `${w}.login.path`, errs);
    if (a.login.format !== undefined) oneOf(a.login.format, FORMATS, `${w}.login.format`, errs);
    for (const f of ['userField', 'passwordField']) if (a.login[f] !== undefined && !FIELD_NAME.test(String(a.login[f]))) errs.push(`${w}.login.${f}: nome de campo inválido`);
  } else if ('login' in a) errs.push(`${w}.login: deve ser objeto`);

  if (isObj(a.accounts)) {
    keys(a.accounts, ['a', 'b'], [], `${w}.accounts`, errs);
    for (const k of ['a', 'b']) {
      const acc = a.accounts[k];
      if (!isObj(acc)) { if (k in a.accounts) errs.push(`${w}.accounts.${k}: deve ser objeto`); continue; }
      keys(acc, ['userEnv', 'passwordEnv'], [], `${w}.accounts.${k}`, errs);
      for (const f of ['userEnv', 'passwordEnv']) if (f in acc && !ENV_NAME.test(String(acc[f]))) errs.push(`${w}.accounts.${k}.${f}: use o NOME de uma variável de ambiente (MAIÚSCULAS e _), nunca o valor`);
    }
    if (isObj(a.accounts.a) && isObj(a.accounts.b) && a.accounts.a.userEnv === a.accounts.b.userEnv) errs.push(`${w}.accounts: as contas a e b precisam ser usuários diferentes`);
  } else if ('accounts' in a) errs.push(`${w}.accounts: deve ser objeto com as contas "a" e "b"`);

  if ('protected' in a) routePath(a.protected, `${w}.protected`, errs);

  if (a.logout !== undefined) {
    if (!isObj(a.logout)) errs.push(`${w}.logout: deve ser objeto`);
    else {
      keys(a.logout, ['path'], ['method'], `${w}.logout`, errs);
      routePath(a.logout.path, `${w}.logout.path`, errs);
      if (a.logout.method !== undefined) oneOf(a.logout.method, LOGOUT_METHODS, `${w}.logout.method`, errs);
    }
  }

  if (a.objects !== undefined) {
    if (!Array.isArray(a.objects) || a.objects.length > MAX_LIST) errs.push(`${w}.objects: lista de até ${MAX_LIST} itens`);
    else {
      a.objects.forEach((o, i) => {
        const ow = `${w}.objects[${i}]`;
        if (!isObj(o)) { errs.push(`${ow}: deve ser objeto`); return; }
        keys(o, ['path', 'ids'], [], ow, errs);
        routePath(o.path, `${ow}.path`, errs);
        if (typeof o.path === 'string' && !o.path.includes('{id}')) errs.push(`${ow}.path: use {id} no lugar do identificador do objeto`);
        if (isObj(o.ids)) {
          keys(o.ids, ['a', 'b'], [], `${ow}.ids`, errs);
          for (const k of ['a', 'b']) if (k in o.ids && !ID_VALUE.test(String(o.ids[k]))) errs.push(`${ow}.ids.${k}: identificador de 1 a 64 caracteres (letras, números, _ e -)`);
          if (o.ids.a !== undefined && String(o.ids.a) === String(o.ids.b)) errs.push(`${ow}.ids: o objeto da conta a e o da conta b precisam ser diferentes`);
        } else if ('ids' in o) errs.push(`${ow}.ids: deve ser objeto com o identificador do objeto de cada conta`);
      });
    }
  }

  if (a.csrf !== undefined) {
    if (!Array.isArray(a.csrf) || a.csrf.length > MAX_LIST) errs.push(`${w}.csrf: lista de até ${MAX_LIST} itens`);
    else {
      a.csrf.forEach((c, i) => {
        const cw = `${w}.csrf[${i}]`;
        if (!isObj(c)) { errs.push(`${cw}: deve ser objeto`); return; }
        keys(c, ['path', 'method'], ['format', 'body'], cw, errs);
        routePath(c.path, `${cw}.path`, errs);
        oneOf(c.method, CSRF_METHODS, `${cw}.method`, errs);
        if (c.format !== undefined) oneOf(c.format, FORMATS, `${cw}.format`, errs);
        if (c.body !== undefined) {
          if (!isObj(c.body) || Object.keys(c.body).length > 20) errs.push(`${cw}.body: objeto com até 20 campos`);
          else if ((c.format || 'json') === 'form') {
            for (const [k, v] of Object.entries(c.body)) if (!['string', 'number', 'boolean'].includes(typeof v) || String(v).length > 200) errs.push(`${cw}.body.${k}: em formulário, use texto, número ou booleano (máx. 200 caracteres)`);
          } else if (JSON.stringify(c.body).length > 4000) errs.push(`${cw}.body: JSON de até 4000 caracteres`);
        }
      });
    }
  }
  return errs;
}

module.exports = { validateAuthProbes, ENV_NAME };
