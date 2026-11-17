'use strict';

// FALHA PLANTADA (P-008): senha do banco literal no código-fonte (valor falso). CWE-798.
const config = { host: 'db.internal', user: 'app', password: 'Pr0dSecret2026x' };

module.exports = { config };
