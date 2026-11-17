'use strict';

// Gêmea limpa de P-010: converte os operandos e soma, sem executar texto.
function calc(req, res) {
  res.json({ result: Number(req.body.a) + Number(req.body.b) });
}

module.exports = { calc };
