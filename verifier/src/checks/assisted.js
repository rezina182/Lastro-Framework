'use strict';

// Verificações automáticas que nasceram da prova assistida (assist.js): o pedaço de um controle manual que a máquina
// prova por inteiro virou controle automático próprio (WEB-022, WEB-023, AUTH-040, AUTH-041, AUTH-042). O controle
// manual de origem continua com a parte que só uma pessoa confirma. Cada pedaço segue um requisito do ASVS e vale
// para qualquer aplicação com o recurso; as rotas vêm do perfil, nunca do kit.

const A = require('../assist');
const { discover } = require('../discover');

const unverified = (note) => ({ state: 'unverified', findings: [], notes: [note] });
const clean = (s) => s.replace(/^Prova parcial da máquina:\s*/, '').replace(/\s*Falta [^.]*\.\s*$/, '');

/** Resultado da prova assistida no formato de uma verificação: achou falha, falhou; testou e passou, verificado. */
function asCheck(r, nothing) {
  if (r.findings.length) return { state: 'failed', findings: r.findings.map(({ soft, ...f }) => f), notes: r.notes.map(clean) };
  if (r.tested > 0 && !r.notes.some((n) => /inconclusiva|começou a limitar/.test(n))) return { state: 'verified', findings: [], notes: r.notes.map(clean) };
  return { state: 'unverified', findings: [], notes: r.notes.length ? r.notes.map(clean) : [nothing] };
}

// As duas sondas de login usam o mesmo limitador da aplicação: rodam uma vez, nesta ordem, e o resultado é reaproveitado.
function loginProbes(ctx) {
  if (!ctx.loginProbesRun) {
    const login = ctx.profile.authProbes && ctx.profile.authProbes.login;
    ctx.loginProbesRun = (async () => {
      const dc = await A.defaultCreds(ctx, login);
      const bf = await A.bruteForce(ctx, login, { prior: dc.tested, priorLimited: dc.notes.some((n) => /começou a limitar/.test(n)) });
      return { dc, bf };
    })();
  }
  return ctx.loginProbesRun;
}

const NEED_URL = 'Informe --url para executar esta verificação.';
const NEED_ACTIVE = 'Sonda ativa (tentativas de login erradas): rode com --url, --active e --confirm-non-production, só em local ou staging.';
const NEED_LOGIN = 'O perfil não declara a rota de login (authProbes.login): sem ela não há o que testar.';

const checks = {
  // Além dos caminhos comuns, as rotas GET de métrica, diagnóstico e documentação que a descoberta acha no próprio código.
  'http.paths.exposed': async (ctx) => (ctx.url ? asCheck(await A.exposedPaths(ctx, { extra: discover(ctx).routes.diag || [] }), 'Nenhum caminho respondeu.') : unverified(NEED_URL)),
  'http.content-type': async (ctx) => (ctx.url ? asCheck(await A.contentTypes(ctx), 'Nenhuma resposta com corpo para conferir.') : unverified(NEED_URL)),
  'http.login.default-creds': async (ctx) => {
    if (!ctx.url || !ctx.active) return unverified(NEED_ACTIVE);
    if (!(ctx.profile.authProbes && ctx.profile.authProbes.login)) return unverified(NEED_LOGIN);
    const { dc } = await loginProbes(ctx);
    // Se o limitador cortou o teste antes do fim, nem todas as credenciais foram tentadas: não dá para afirmar.
    if (!dc.findings.length && dc.notes.some((n) => /começou a limitar/.test(n))) return unverified(`${clean(dc.notes[0])} Nem todas as credenciais foram tentadas.`);
    return asCheck(dc, 'O login não respondeu.');
  },
  'http.login.bruteforce': async (ctx) => {
    if (!ctx.url || !ctx.active) return unverified(NEED_ACTIVE);
    if (!(ctx.profile.authProbes && ctx.profile.authProbes.login)) return unverified(NEED_LOGIN);
    const { bf } = await loginProbes(ctx);
    if (!bf.findings.length && bf.notes.some((n) => /passou a limitar/.test(n))) return { state: 'verified', findings: [], notes: bf.notes.map(clean) };
    return asCheck(bf, 'O login não respondeu.');
  },
  'repo.code.default-password': (ctx) => {
    const r = A.defaultPasswords(ctx);
    if (!r.tested) return unverified('Nenhuma chamada a função de hash de senha no código: nada a conferir.');
    return asCheck(r, '');
  },
  'repo.code.unauth-write-routes': (ctx) => {
    const r = A.unauthWriteRoutes(discover(ctx));
    if (!r.tested) return unverified('Nenhuma rota HTTP encontrada no código (Express, Flask, FastAPI, Next.js): confira como as rotas são declaradas.');
    return asCheck(r, '');
  },
  'repo.code.mass-assignment': (ctx) => {
    const r = A.massAssignment(ctx);
    if (!r.tested) return unverified('Nenhuma gravação no banco por ORM encontrada no código: nada a conferir.');
    return asCheck(r, '');
  },
  'repo.code.password-hash': (ctx) => {
    const r = A.passwordHash(ctx);
    if (!r.tested) return unverified('Nenhuma biblioteca de hash de senha (bcrypt, Argon2, scrypt, passlib) encontrada no código: confira como as senhas são guardadas.');
    return asCheck(r, '');
  },
};

module.exports = { checks };
