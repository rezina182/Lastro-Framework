'use strict';

// Utilitários de teste: projetos temporários, contexto de verificação e servidores HTTP locais.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { buildContext, DEFAULT_THRESHOLDS } = require('../src/engine');
const { loadCatalog } = require('../src/catalog');
const { registry } = require('../src/checks');

const ALL_FALSE = {
  webApp: false, hasAuth: false, anonymousUsers: false, realtime: false, uploads: false,
  personalData: false, minorsData: false, thirdPartyAssets: false, aiCodingAgents: false, publicInternet: false,
  federatedLogin: false, tokenAuth: false, oauthProvider: false,
};

function makeProject(files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lastro-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

function profileJson(flags = {}, extra = {}) {
  return JSON.stringify({ schemaVersion: 1, name: 'teste', flags: { ...ALL_FALSE, ...flags }, ...extra });
}

function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true });
}

function ctxFor(root, { profile, url = null, active = false, now = new Date('2026-11-12T12:00:00Z') } = {}) {
  const prof = profile || { schemaVersion: 1, name: 'teste', flags: ALL_FALSE };
  return buildContext({ root, profile: prof, catalog: loadCatalog(), url, active, now });
}

async function runOne(id, ctx) {
  return registry.get(id).run(ctx);
}

/** Sobe um servidor HTTP local. handler(req, res). Devolve { url, close }. */
function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
      });
    });
  });
}

/** Hrefs de um HTML que não são âncora interna nem fonte oficial permitida (deve ser sempre vazio). */
function badHrefs(html) {
  const { ALLOWED_HREF } = require('../src/links');
  return [...html.matchAll(/\bhref="([^"]*)"/g)].map((m) => m[1].replace(/&amp;/g, '&')).filter((u) => !u.startsWith('#') && !ALLOWED_HREF.test(u));
}

module.exports = { badHrefs, ALL_FALSE, makeProject, profileJson, cleanup, ctxFor, runOne, serve, DEFAULT_THRESHOLDS };
