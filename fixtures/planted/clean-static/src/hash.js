'use strict';

const crypto = require('node:crypto');

// Gêmea limpa de P-006: scrypt com sal aleatório, em vez de MD5.
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return `${salt.toString('hex')}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

function fingerprint(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

module.exports = { hashPassword, fingerprint };
