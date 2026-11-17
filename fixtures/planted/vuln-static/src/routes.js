'use strict';

// FALHAS DE LÓGICA PLANTADAS. O kit não tem como provar nenhuma por leitura de texto:
// o esperado é que elas virem pergunta (controle manual sem prova), e não "passou".
function mount(app, db, requireLogin) {
  // L-001: acesso por objeto. Qualquer usuário logado lê o pedido de outro (não confere o dono). CWE-639.
  app.get('/api/orders/:id', requireLogin, async (req, res) => {
    const rows = await db.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    res.json(rows[0]);
  });

  // L-002: acesso por campo. O corpo inteiro vira o usuário, inclusive o campo "role". CWE-915.
  app.put('/api/users/:id', requireLogin, async (req, res) => {
    const user = await db.findUser(req.params.id);
    Object.assign(user, req.body);
    await db.saveUser(user);
    res.json(user);
  });

  // L-003: rota que muda estado com sessão por cookie e sem token anti-CSRF. CWE-352.
  app.post('/api/profile', requireLogin, async (req, res) => {
    await db.saveProfile(req.session.userId, req.body);
    res.json({ ok: true });
  });

  // L-004: o logout só apaga o cookie; a sessão continua válida no servidor. CWE-613.
  app.post('/logout', (req, res) => {
    res.clearCookie('sid');
    res.redirect('/');
  });
}

module.exports = { mount };
