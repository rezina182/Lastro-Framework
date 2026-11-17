'use strict';

// FALHA PLANTADA (P-002): a mesma injeção, com aspas simples dentro do texto SQL (o jeito clássico). CWE-89.
function findUser(db, req, res) {
  const sql = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  return db.query(sql).then((rows) => res.json(rows));
}

module.exports = { findUser };
