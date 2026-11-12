'use strict';

// Cliente HTTP mínimo do verificador. Somente http/https, com limite de tempo e de tamanho,
// sem seguir redirecionamentos para outra origem e sem enviar cookies ou credenciais.

const http = require('node:http');
const https = require('node:https');

const USER_AGENT = 'lastro-verifier/0.1 (verificacao-autorizada)';

function request(urlString, opts = {}) {
  const { method = 'GET', headers = {}, body, timeoutMs = 10000, maxBytes = 512 * 1024, maxRedirects = 0 } = opts;
  return follow(urlString, { method, headers, body, timeoutMs, maxBytes }, maxRedirects, []);
}

async function follow(urlString, o, redirectsLeft, trail) {
  const res = await once(urlString, o);
  const isRedirect = [301, 302, 303, 307, 308].includes(res.status) && res.headers.location;
  if (!isRedirect || o.method !== 'GET') return { ...res, redirects: trail };
  let next;
  try {
    next = new URL(res.headers.location, urlString);
  } catch (e) {
    return { ...res, redirects: trail };
  }
  const origem = new URL(urlString).origin;
  trail = [...trail, { from: urlString, status: res.status, to: next.toString() }];
  if (redirectsLeft <= 0 || next.origin !== origem) return { ...res, redirects: trail, redirectStopped: true };
  return follow(next.toString(), o, redirectsLeft - 1, trail);
}

function once(urlString, { method, headers, body, timeoutMs, maxBytes }) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(urlString);
    } catch (e) {
      return resolve(failure(urlString, 'URL inválida'));
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return resolve(failure(urlString, 'protocolo não suportado'));
    if (u.username || u.password) return resolve(failure(urlString, 'URL com credenciais não é aceita'));
    const lib = u.protocol === 'https:' ? https : http;
    const h = { 'user-agent': USER_AGENT, accept: '*/*', connection: 'close', ...headers };
    if (body !== undefined) h['content-length'] = Buffer.byteLength(body);
    let finished = false;
    const done = (r) => {
      if (finished) return;
      finished = true;
      resolve(r);
    };
    const req = lib.request(
      { protocol: u.protocol, hostname: u.hostname, port: u.port || undefined, path: `${u.pathname}${u.search}`, method, headers: h, agent: false, timeout: timeoutMs },
      (res) => {
        const chunks = [];
        let size = 0;
        let truncated = false;
        res.on('data', (c) => {
          size += c.length;
          if (size > maxBytes) {
            truncated = true;
            res.destroy();
            return;
          }
          chunks.push(c);
        });
        const fim = () => {
          const headersLower = {};
          for (const [k, v] of Object.entries(res.headers)) headersLower[k.toLowerCase()] = v;
          const setCookie = Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [];
          done({
            ok: true,
            url: urlString,
            status: res.statusCode,
            headers: headersLower,
            setCookie,
            body: Buffer.concat(chunks).toString('utf8'),
            truncated,
          });
        };
        res.on('end', fim);
        res.on('close', fim);
        res.on('error', () => fim());
      }
    );
    req.on('timeout', () => {
      req.destroy();
      done(failure(urlString, 'tempo esgotado'));
    });
    req.on('error', (e) => done(failure(urlString, e.code || e.message)));
    if (body !== undefined) req.write(body);
    req.end();
    return undefined;
  });
}

function failure(url, error) {
  return { ok: false, url, status: 0, headers: {}, setCookie: [], body: '', truncated: false, error, redirects: [] };
}

module.exports = { request };
