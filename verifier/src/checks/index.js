'use strict';

// Registro de verificações automáticas. O id é o que o catálogo cita em check.id.

const repo = require('./repo');
const http = require('./http');
const assisted = require('./assisted');

const registry = new Map();
for (const [id, run] of Object.entries(repo.checks)) registry.set(id, { id, kind: 'repo', run });
for (const [id, run] of Object.entries(http.checks)) registry.set(id, { id, kind: 'http', run });
for (const [id, run] of Object.entries(assisted.checks)) registry.set(id, { id, kind: id.startsWith('repo.') ? 'repo' : 'http', run });

module.exports = { registry, ids: () => new Set(registry.keys()) };
