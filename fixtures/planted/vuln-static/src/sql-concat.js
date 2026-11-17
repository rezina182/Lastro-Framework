'use strict';

// FALHA PLANTADA (P-001): SQL montado por concatenação com dado da requisição. CWE-89.
function listOrders(db, req, res) {
  const sql = "SELECT * FROM orders WHERE owner_id = " + req.query.owner;
  return db.query(sql).then((rows) => res.json(rows));
}

module.exports = { listOrders };
