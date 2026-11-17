'use strict';

// FALHA PLANTADA (P-003): SQL com interpolação de template literal e dado da requisição. CWE-89.
function getUser(db, req, res) {
  return db.query(`SELECT * FROM users WHERE id = ${req.params.id}`).then((rows) => res.json(rows[0]));
}

module.exports = { getUser };
