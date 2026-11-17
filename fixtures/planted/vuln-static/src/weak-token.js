'use strict';

// FALHA PLANTADA (P-005): token de redefinição de senha gerado com Math.random. CWE-338.
function newResetToken() {
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}

module.exports = { newResetToken };
