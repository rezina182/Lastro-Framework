'use strict';

// Gêmea limpa de P-001, P-002 e P-003: valores vão como parâmetros do driver.
function listOrders(db, req, res) {
  return db.query('SELECT * FROM orders WHERE owner_id = $1', [req.user.id]).then((rows) => res.json(rows));
}

function findUser(db, req, res) {
  return db.query('SELECT * FROM users WHERE name = $1', [req.query.name]).then((rows) => res.json(rows));
}

module.exports = { listOrders, findUser };
