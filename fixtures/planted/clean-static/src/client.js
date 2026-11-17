'use strict';

const https = require('node:https');

// Gêmea limpa de P-009: o certificado é verificado (comportamento padrão).
function call(host) {
  return https.request({ host, path: '/' });
}

module.exports = { call };
