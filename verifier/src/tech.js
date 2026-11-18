'use strict';

// Tecnologias que a aplicação usa, lidas das dependências e do código. Serve para dizer quais controles
// provavelmente não se aplicam (por exemplo, GraphQL sem nenhuma biblioteca de GraphQL). É indício, nunca decisão:
// quem decide "não se aplica" é uma pessoa, registrando a justificativa (.lastro/status.json).

const TECH = [
  { id: 'graphql', label: 'GraphQL', deps: ['graphql', '@apollo/server', 'apollo-server', 'apollo-server-express', 'graphql-yoga', 'mercurius', 'express-graphql', 'graphene', 'strawberry-graphql', 'ariadne'] },
  { id: 'oauthClient', label: 'login por provedor externo (OAuth/OIDC)', deps: ['openid-client', 'passport-oauth2', 'passport-google-oauth20', 'passport-github2', 'passport-azure-ad', 'next-auth', '@auth/core', 'simple-oauth2', 'authlib', 'oauthlib', 'requests-oauthlib', 'social-auth-app-django', 'django-allauth', 'msal', '@azure/msal-node'], code: /authorization_code|response_type=code|\/oauth\/authorize|openid-configuration/i },
  { id: 'oauthServer', label: 'servidor de autorização OAuth', deps: ['oidc-provider', 'oauth2-server', '@node-oauth/oauth2-server', 'node-oauth2-server', 'django-oauth-toolkit', 'flask-oauthlib'] },
  { id: 'jwt', label: 'tokens JWT', deps: ['jsonwebtoken', 'jose', 'pyjwt', 'python-jose', 'express-jwt', 'passport-jwt', '@fastify/jwt'] },
  { id: 'sms', label: 'envio de SMS ou voz', deps: ['twilio', '@vonage/server-sdk', 'nexmo', 'zenvia', '@aws-sdk/client-sns', 'messagebird'], code: /\bsendSms\b|\benviarSms\b/i },
  { id: 'ldap', label: 'LDAP ou XPath', deps: ['ldapjs', 'ldap3', 'python-ldap', 'xpath', 'xmldom', '@xmldom/xmldom'] },
  { id: 'xml', label: 'leitura de XML', deps: ['xml2js', 'fast-xml-parser', 'libxmljs', 'libxmljs2', 'sax', 'lxml', 'defusedxml', 'xmldom', '@xmldom/xmldom'] },
  { id: 'webrtc', label: 'WebRTC', deps: ['simple-peer', 'mediasoup', 'livekit-server-sdk', 'peerjs', 'wrtc', '@roamhq/wrtc', 'aiortc'], code: /RTCPeerConnection/ },
  { id: 'websocket', label: 'WebSocket', deps: ['ws', 'socket.io', 'websocket', 'sockjs', 'uWebSockets.js', 'websockets', 'channels'] },
  { id: 'archives', label: 'leitura de arquivos compactados', deps: ['adm-zip', 'unzipper', 'yauzl', 'jszip', 'tar', 'decompress', 'extract-zip', 'node-stream-zip'] },
  { id: 'nativeCode', label: 'código nativo (C, C++, Rust, Go)', files: /\.(c|cc|cpp|h|hpp|rs|go)$|(^|\/)binding\.gyp$/i },
  { id: 'memcache', label: 'memcache', deps: ['memjs', 'memcached', 'pymemcache', 'python-memcached'] },
  { id: 'latex', label: 'LaTeX', deps: ['node-latex', 'latex', 'pylatex'] },
  { id: 'templates', label: 'motor de template no servidor', deps: ['ejs', 'pug', 'handlebars', 'express-handlebars', 'nunjucks', 'mustache', 'jinja2', 'mako', 'eta', 'hbs'] },
  { id: 'outboundUrl', label: 'busca de URL informada pelo usuário', code: /fetch\(\s*(req\.|request\.|body\.|params\.|query\.)|axios\.(get|post)\(\s*(req\.|body\.|params\.|query\.)|requests\.get\(\s*request\./ },
];

const MAX_SCAN = 400;

/** { id: { present: bool, evidence } } para cada tecnologia da lista. */
function detectTech(ctx, files, deps) {
  const out = {};
  const scan = files.slice(0, MAX_SCAN);
  for (const t of TECH) {
    const dep = (t.deps || []).find((d) => deps.has(d));
    if (dep) { out[t.id] = { present: true, label: t.label, evidence: `dependência ${dep}` }; continue; }
    if (t.files) {
      const hit = ctx.files.find((f) => t.files.test(f) && !/(^|\/)node_modules\//.test(f));
      out[t.id] = hit ? { present: true, label: t.label, evidence: hit } : { present: false, label: t.label, evidence: null };
      continue;
    }
    const hit = t.code ? scan.find((f) => t.code.test(ctx.read(f) || '')) : null;
    out[t.id] = hit ? { present: true, label: t.label, evidence: hit } : { present: false, label: t.label, evidence: null };
  }
  return out;
}

module.exports = { detectTech, TECH };
