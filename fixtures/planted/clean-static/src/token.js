'use strict';

const crypto = require('node:crypto');

// Gêmea limpa de P-005: token com gerador criptográfico.
function newResetToken() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  return resetToken;
}

module.exports = { newResetToken };
