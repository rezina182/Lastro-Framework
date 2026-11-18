'use strict';

// Identifica o papel de um repositório (frontend, backend, worker, infraestrutura, mobile, biblioteca) só pela leitura
// do código, das dependências e dos arquivos de configuração, e deriva um perfil provisório (flags) para que o kit
// possa verificá-lo sem que ninguém precise rodar "lastro init" nele.
//
// É heurística: cada decisão vem com o motivo e o grau de confiança, e o usuário corrige com um system.json.
// O perfil derivado é rascunho. Algumas flags o código não mostra (dados de menores, dados sensíveis, usuários anônimos):
// ficam desligadas e o relatório avisa.

const path = require('node:path');
const { depNames } = require('./discover');
const { FLAGS } = require('./schema');

const FRONT_DEPS = ['react', 'react-dom', 'vue', 'svelte', '@angular/core', 'next', 'nuxt', 'vite', 'solid-js', 'preact', 'astro', 'gatsby', 'webpack', 'parcel', '@sveltejs/kit'];
const BACK_DEPS = ['express', 'fastify', 'koa', '@nestjs/core', '@hapi/hapi', 'restify', 'flask', 'django', 'fastapi', 'starlette', 'aiohttp', 'sanic', 'tornado', 'bottle', 'gunicorn', 'uvicorn', 'spring-boot'];
const WORKER_DEPS = ['bull', 'bullmq', 'bee-queue', 'agenda', 'amqplib', 'kafkajs', 'celery', 'rq', 'dramatiq', 'node-cron', 'node-schedule', 'apscheduler', 'pika'];
const MOBILE_DEPS = ['react-native', 'expo', '@capacitor/core', 'cordova', 'nativescript'];
const AUTH_DEPS = ['passport', 'jsonwebtoken', 'bcrypt', 'bcryptjs', 'argon2', 'express-session', 'next-auth', 'openid-client', 'oauth2-server', 'flask-login', 'flask-jwt-extended', 'pyjwt', 'passlib', 'django-allauth', 'authlib', 'jose', '@auth/core', 'lucia'];
const FEDERATED_DEPS = ['openid-client', 'next-auth', 'passport-google-oauth20', 'passport-saml', 'authlib', 'django-allauth', '@auth/core', 'passport-azure-ad'];
const TOKEN_DEPS = ['jsonwebtoken', 'jose', 'pyjwt', 'flask-jwt-extended', 'passport-jwt', 'djangorestframework-simplejwt'];
const AGENT_FILES = [/^\.kiro\//, /^\.cursor\//, /^AGENTS\.md$/, /^CLAUDE\.md$/, /^\.github\/copilot-instructions\.md$/, /^\.windsurf\//];
const INFRA_FILE = /(^|\/)(docker-compose[\w.-]*\.ya?ml|Chart\.yaml|serverless\.ya?ml|template\.ya?ml|main\.tf|[\w-]+\.tf|Pulumi\.ya?ml|playbook[\w.-]*\.ya?ml|kustomization\.ya?ml)$/;
const MEDIA = /\.(png|jpe?g|gif|webp|svg|mp3|wav|ogg|mp4|webm|woff2?|ttf|otf)$/i;

const NAME_HINTS = [
  ['frontend', /(^|[-_.])(front|frontend|web|ui|client|site|portal|spa|painel)([-_.]|$)/i],
  ['backend', /(^|[-_.])(api|back|backend|server|service|svc|core)([-_.]|$)/i],
  ['gateway', /(^|[-_.])(gateway|bff|proxy|edge)([-_.]|$)/i],
  ['worker', /(^|[-_.])(worker|job|jobs|queue|consumer|cron|scheduler)([-_.]|$)/i],
  ['infra', /(^|[-_.])(infra|iac|terraform|deploy|devops|k8s|helm|ops)([-_.]|$)/i],
  ['mobile', /(^|[-_.])(mobile|android|ios|app-mobile)([-_.]|$)/i],
  ['library', /(^|[-_.])(lib|sdk|shared|common|utils|commons)([-_.]|$)/i],
];

const has = (deps, list) => list.filter((d) => deps.has(d));

/**
 * Papel provável do repositório. `disc` é o resultado de discover(ctx); `ctx` é o contexto de leitura.
 * Devolve { role, confidence, reasons, fullstack, flags }.
 */
function classifyRepo(ctx, disc, name) {
  const deps = depNames(ctx);
  const files = ctx.files;
  const reasons = [];
  const front = has(deps, FRONT_DEPS);
  const back = has(deps, BACK_DEPS);
  const worker = has(deps, WORKER_DEPS);
  const mobile = has(deps, MOBILE_DEPS);
  const infraFiles = files.filter((f) => INFRA_FILE.test(f));
  const html = files.some((f) => /(^|\/)(index\.html)$/.test(f) && !/node_modules/.test(f));
  const pubspec = files.includes('pubspec.yaml') || files.some((f) => /(^|\/)(AndroidManifest\.xml|Info\.plist)$/.test(f));
  const routes = disc.routes.total;
  const codeFiles = disc.sourceFilesRead;
  const nameHit = NAME_HINTS.filter(([, re]) => re.test(name)).map(([r]) => r);

  const score = { frontend: 0, backend: 0, gateway: 0, worker: 0, infra: 0, mobile: 0, library: 0 };
  if (front.length) { score.frontend += 3; reasons.push(`dependências de interface: ${front.slice(0, 3).join(', ')}`); }
  if (html && routes === 0) { score.frontend += 2; reasons.push('tem index.html e nenhuma rota de servidor'); }
  if (back.length) { score.backend += 3; reasons.push(`dependências de servidor: ${back.slice(0, 3).join(', ')}`); }
  if (routes > 0) { score.backend += routes >= 5 ? 3 : 2; reasons.push(`${routes} rota(s) HTTP encontrada(s)`); }
  if (worker.length) { score.worker += routes === 0 ? 4 : 1; reasons.push(`dependências de fila ou tarefa agendada: ${worker.slice(0, 3).join(', ')}`); }
  if (mobile.length || pubspec) { score.mobile += 4; reasons.push(mobile.length ? `dependências móveis: ${mobile.slice(0, 2).join(', ')}` : 'arquivos de aplicativo móvel (Flutter, Android ou iOS)'); }
  if (infraFiles.length) { score.infra += codeFiles <= 3 ? 4 : 1; reasons.push(`${infraFiles.length} arquivo(s) de infraestrutura (${infraFiles.slice(0, 2).map((f) => path.posix.basename(f)).join(', ')})`); }
  if (codeFiles === 0 && !html && !infraFiles.length) score.library += 1;
  for (const r of nameHit) { score[r] += 2; reasons.push(`o nome do repositório sugere ${r}`); }

  let pkg = null;
  try { pkg = JSON.parse(ctx.read('package.json') || 'null'); } catch (e) { pkg = null; }
  if (pkg && (pkg.main || pkg.exports || pkg.module) && !front.length && !back.length && routes === 0 && !worker.length) { score.library += 2; reasons.push('package.json de biblioteca (main ou exports) sem servidor nem interface'); }

  const ordered = Object.entries(score).sort((a, b) => b[1] - a[1]);
  let [role, top] = ordered[0];
  const second = ordered[1][1];
  let fullstack = false;
  if (top === 0) {
    role = codeFiles > 0 ? 'backend' : 'infra';
    reasons.push('nenhum sinal claro: papel assumido, confirme');
  }
  // Next.js, Nuxt e afins servem as páginas (app/**/page.tsx, pages/*.vue) e a API do mesmo repositório.
  const frameworkPages = files.some((f) => /^(?:src\/)?(?:app\/(?:.*\/)?page|pages\/(?!api\/)[^/]+)\.(?:tsx|jsx|js|ts|vue)$/.test(f));
  const servesUi = routes > 0 && (html || frameworkPages || files.some((f) => /(^|\/)public\/[^/]+\.html$/.test(f)));
  if (servesUi && !fullstack && score.backend >= score.frontend) {
    role = 'backend';
    fullstack = true;
    reasons.push('serve páginas HTML junto com a API (full stack)');
  }
  if (!fullstack && score.frontend > 0 && score.backend > 0 && Math.abs(score.frontend - score.backend) <= 2 && routes > 0) {
    role = 'backend';
    fullstack = true;
    reasons.push('serve interface e API no mesmo repositório (full stack)');
  }
  if (role === 'backend' && score.gateway >= score.backend) role = 'gateway';
  const confidence = top === 0 ? 'baixa' : top - second >= 3 ? 'alta' : top - second >= 1 ? 'media' : 'baixa';

  const authDeps = has(deps, AUTH_DEPS);
  const flags = Object.fromEntries(FLAGS.map((f) => [f, false]));
  const webLike = ['frontend', 'backend', 'gateway'].includes(role) || routes > 0;
  flags.webApp = webLike;
  flags.hasAuth = authDeps.length > 0 || disc.dataHints.some((h) => h.category === 'credencial');
  flags.realtime = disc.realtime.length > 0;
  flags.uploads = disc.uploads.length > 0;
  flags.personalData = disc.dataHints.some((h) => ['identificacao', 'contato', 'nascimento', 'financeiro', 'sensivel'].includes(h.category));
  flags.thirdPartyAssets = files.filter((f) => MEDIA.test(f)).length >= 5;
  flags.aiCodingAgents = files.some((f) => AGENT_FILES.some((re) => re.test(f)));
  flags.publicInternet = webLike || role === 'mobile';
  flags.federatedLogin = has(deps, FEDERATED_DEPS).length > 0;
  flags.tokenAuth = has(deps, TOKEN_DEPS).length > 0;
  return { role, confidence, reasons: reasons.slice(0, 6), fullstack, flags };
}

module.exports = { classifyRepo };
