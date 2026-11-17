'use strict';

const https = require('node:https');

// FALHA PLANTADA (P-009): verificação do certificado TLS desligada. CWE-295.
function call(host) {
  return https.request({ host, path: '/', rejectUnauthorized: false });
}

module.exports = { call };
