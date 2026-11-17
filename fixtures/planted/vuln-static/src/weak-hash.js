'use strict';

const crypto = require('node:crypto');

// FALHA PLANTADA (P-006): senha guardada com MD5, sem sal. CWE-328.
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = { hashPassword };
