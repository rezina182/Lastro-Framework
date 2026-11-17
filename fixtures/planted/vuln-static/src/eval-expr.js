'use strict';

// FALHA PLANTADA (P-010): eval sobre dado da requisição. CWE-95.
function calc(req, res) {
  res.json({ result: eval(req.body.expr) });
}

module.exports = { calc };
