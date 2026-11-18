'use strict';

// Servidor de teste das sondas autenticadas. Cada opção liga uma falha:
//   bola: qualquer conta logada lê o objeto de outra; anonRead: objeto legível sem login; csrf: aceita origem estranha;
//   logoutBug: o logout só apaga o cookie; openProtected: a rota "protegida" responde a anônimos;
//   cacheBug: /api/me sem Cache-Control: no-store; fixation: o login reaproveita o id de sessão que o cliente mandou;
//   tamperBug: aceita um id de sessão com o último caractere trocado.
// Contas: alice/pa e bob/pb. Pedido 1 é de alice e pedido 2 é de bob.

const { serve } = require('./helpers');

const OWNER = { 1: 'alice', 2: 'bob' };
const ACCOUNTS = { a: { user: 'alice', password: 'pa' }, b: { user: 'bob', password: 'pb' } };

function app(opt = {}) {
  const sessions = new Map();
  const tokens = new Map();
  const profiles = new Map();
  let counter = 0;
  // opt.token: como muitas aplicações reais, exige o cabeçalho X-CSRF-Token (devolvido no login) em toda escrita.
  const tokenOk = (req, sid) => !opt.token || (sid && req.headers['x-csrf-token'] === tokens.get(sid));
  return serve((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const send = (status, obj) => { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(obj)); };
      const sid = (/sid=(\w+)/.exec(req.headers.cookie || '') || [])[1];
      // tamperBug: aceita qualquer valor que só difere no último caractere (não confere o token emitido).
      const loose = opt.tamperBug && sid ? [...sessions.keys()].find((k) => k.slice(0, -1) === sid.slice(0, -1)) : null;
      const user = sessions.get(sid) || (loose ? sessions.get(loose) : null) || null;
      const url = req.url;
      if (url === '/login' && req.method === 'POST') {
        const j = JSON.parse(raw || '{}');
        const ok = (j.username === 'alice' && j.password === 'pa') || (j.username === 'bob' && j.password === 'pb');
        if (!ok) return send(401, { error: 'credenciais' });
        counter += 1;
        // fixation: reaproveita o id que o cliente já mandava, em vez de emitir um novo.
        const t = opt.fixation && sid ? sid : `t${counter}x${String(counter * 7919).padStart(10, '0')}a`;
        sessions.set(t, j.username);
        tokens.set(t, `csrf${counter}`);
        if (!(opt.fixation && sid)) res.setHeader('Set-Cookie', `sid=${t}; Path=/; HttpOnly${opt.sameSite ? `; SameSite=${opt.sameSite}` : ''}`);
        return send(200, opt.token ? { ok: true, csrfToken: `csrf${counter}` } : { ok: true });
      }
      if (url === '/api/me') {
        // cacheBug: a rota autenticada sai sem Cache-Control: no-store.
        if (!opt.cacheBug) res.setHeader('Cache-Control', 'no-store');
        // leak: a resposta leva o hash da senha junto com os dados da conta.
        if (opt.openProtected || user) return send(200, opt.leak ? { user, senha_hash: '$2b$12$abcdefghijklmnopqrstuv' } : { user });
        return send(401, { error: 'login' });
      }
      // Edição do próprio perfil. mass: grava qualquer campo enviado; sem mass, só "nome".
      if (url === '/api/conta' && req.method === 'PATCH') {
        if (!user) return send(401, { error: 'login' });
        const j = JSON.parse(raw || '{}');
        // strict: recusa qualquer campo além de "nome" (validação por lista de permissão).
        if (opt.strict && Object.keys(j).some((k) => k !== 'nome')) return send(400, { error: 'campo desconhecido' });
        const cur = profiles.get(user) || { nome: user };
        profiles.set(user, opt.mass ? { ...cur, ...j } : { ...cur, nome: j.nome || cur.nome });
        return send(200, { ok: true });
      }
      if (url === '/api/conta' && req.method === 'GET') return user ? send(200, profiles.get(user) || { nome: user }) : send(401, { error: 'login' });
      const m = /^\/api\/orders\/(\d+)$/.exec(url);
      if (m) {
        if (!opt.anonRead && !user) return send(401, { error: 'login' });
        if (!opt.bola && !opt.anonRead && OWNER[m[1]] !== user) return send(403, { error: 'proibido' });
        return send(200, { id: Number(m[1]), owner: OWNER[m[1]], total: 99 });
      }
      if (url === '/api/profile' && req.method === 'POST') {
        if (!user) return send(401, { error: 'login' });
        const same = req.headers['sec-fetch-site'] === 'same-origin' && req.headers.origin === `http://${req.headers.host}`;
        if (!opt.csrf && (!same || !tokenOk(req, sid))) return send(403, { error: 'origem' });
        return send(200, { ok: true });
      }
      if (url === '/logout' && req.method === 'POST') {
        if (!tokenOk(req, sid)) return send(403, { error: 'token' });
        if (!opt.logoutBug) sessions.delete(sid);
        res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
        return send(200, { ok: true });
      }
      return send(404, { error: 'nao encontrado' });
    });
  });
}

module.exports = { app, ACCOUNTS };
