'use strict';

// Perfil inicial (lastro init) derivado do código, em vez de um modelo com tudo desligado. Usa a mesma
// classificação do "lastro app" (classify.js). É RASCUNHO: o kit diz o motivo de cada flag ligada e quais flags o
// código não mostra (dados de menores, usuários anônimos, servidor OAuth), para uma pessoa revisar. Um perfil que
// subdeclara a aplicação deixa controles de fora e infla a nota; um que sobredeclara só pede mais prova.

const path = require('node:path');
const { buildContext } = require('./engine');
const { loadCatalog } = require('./catalog');
const { discover } = require('./discover');
const { classifyRepo } = require('./classify');
const { FLAGS } = require('./schema');

// O que o código não consegue mostrar: precisa de alguém que conhece a aplicação.
const ASK = {
  minorsData: 'a aplicação trata dados de crianças ou adolescentes?',
  anonymousUsers: 'há usuários que usam a aplicação sem conta (participantes, visitantes)?',
  oauthProvider: 'a aplicação emite tokens para outros sistemas (servidor de autorização OAuth)?',
  publicInternet: 'a aplicação fica exposta à internet (e não só numa rede interna)?',
  personalData: 'a aplicação guarda dados pessoais (nome, e-mail, documento, telefone)?',
};

function reasonsFor(flags, disc, deps) {
  const r = {};
  if (flags.webApp) r.webApp = `${disc.routes.total} rota(s) HTTP no código`;
  if (flags.hasAuth) {
    const auth = ['express-session', 'passport', 'bcrypt', 'bcryptjs', 'argon2', 'jsonwebtoken', 'jose', 'otpauth', 'next-auth', 'flask-login', 'django'].filter((d) => deps.has(d));
    r.hasAuth = auth.length ? `dependências de login: ${auth.slice(0, 4).join(', ')}` : 'campos de credencial nas tabelas ou no código';
  }
  if (flags.realtime) r.realtime = disc.realtime.join(', ');
  if (flags.uploads) r.uploads = disc.uploads.join(', ');
  if (flags.personalData) r.personalData = `indícios de dado pessoal: ${[...new Set(disc.dataHints.map((h) => h.name || h.category))].slice(0, 3).join(', ')}`;
  if (flags.tokenAuth) r.tokenAuth = 'biblioteca de tokens (JWT) nas dependências';
  if (flags.federatedLogin) r.federatedLogin = 'biblioteca de login externo (OAuth/OIDC) nas dependências';
  if (flags.thirdPartyAssets) r.thirdPartyAssets = 'cinco ou mais arquivos de mídia no repositório';
  if (flags.aiCodingAgents) r.aiCodingAgents = 'arquivos de agente de IA (.kiro, .cursor, CLAUDE.md, AGENTS.md...)';
  if (flags.publicInternet) r.publicInternet = 'é aplicação web ou móvel (confirme se fica exposta à internet)';
  return r;
}

/** Deriva o perfil da pasta. Devolve { profile, role, confidence, reasons, ask }. */
function deriveProfile(root) {
  const catalog = loadCatalog();
  const base = path.basename(root);
  const tmp = { schemaVersion: 1, name: base, flags: Object.fromEntries(FLAGS.map((f) => [f, false])) };
  const ctx = buildContext({ root, profile: tmp, catalog, url: null, active: false, now: new Date() });
  const disc = discover(ctx);
  const cls = classifyRepo(ctx, disc, base);
  let name = base;
  try { name = String(JSON.parse(ctx.read('package.json') || '{}').name || base).replace(/^@[^/]+\//, '').slice(0, 80) || base; } catch (e) { name = base; }
  const deps = new Set();
  try { const p = JSON.parse(ctx.read('package.json') || '{}'); for (const k of ['dependencies', 'devDependencies']) for (const d of Object.keys(p[k] || {})) deps.add(d); } catch (e) { /* sem package.json */ }
  const flags = Object.fromEntries(FLAGS.map((f) => [f, !!cls.flags[f]]));
  const profile = { schemaVersion: 1, name, flags, paths: { health: '/health' } };
  return { profile, role: cls.role, confidence: cls.confidence, roleReasons: cls.reasons, reasons: reasonsFor(flags, disc, deps), ask: Object.entries(ASK).filter(([f]) => !flags[f]).map(([f, q]) => ({ flag: f, question: q })) };
}

function formatDerived(d) {
  const on = Object.entries(d.profile.flags).filter(([, v]) => v);
  const out = [`Perfil derivado do código (rascunho): papel ${d.role}, confiança ${d.confidence === 'media' ? 'média' : d.confidence}.`];
  out.push(on.length ? 'Flags ligadas:' : 'Nenhuma flag ligada pelo código.');
  for (const [f] of on) out.push(`  ${f}: ${d.reasons[f] || 'derivado do código'}`);
  if (d.ask.length) {
    out.push('Revise estas, que o código não mostra (ficaram desligadas):');
    for (const a of d.ask) out.push(`  ${a.flag}: ${a.question}`);
  }
  out.push('Um perfil que subdeclara a aplicação deixa controles de fora e melhora a nota sem melhorar a segurança. Revise com outra pessoa.');
  return out.join('\n');
}

module.exports = { deriveProfile, formatDerived, ASK };
