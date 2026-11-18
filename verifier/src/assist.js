'use strict';

// Prova assistida para controles MANUAIS: a máquina faz a parte do teste que dá para automatizar.
//  - achou a falha: o controle fica "falhou", com prova de máquina (vence a atestação, como nas sondas autenticadas);
//  - passou: vira nota "Prova parcial da máquina", que o playbook e a atestação reaproveitam. NÃO verifica o
//    controle: o roteiro do catálogo pede mais do que a máquina consegue ver;
//  - não deu para testar: fica sem nota, ou com a razão.
// Três famílias, cada uma com a sua trava:
//  - código (sempre roda): só lê o repositório;
//  - HTTP passivo (--url): GET em caminhos conhecidos, como as sondas HTTP de hoje;
//  - HTTP ativo (--url --active --confirm-non-production): tentativas de login erradas, nunca com conta real.

const crypto = require('node:crypto');
const { encodeBody, contentType } = require('./authclient');

const NOTE = 'Prova parcial da máquina:';
const TEST_FILE = /(^|\/)(test|tests|__tests__|spec)\/|\.(test|spec)\.[cm]?[jt]s$/;
const result = () => ({ findings: [], notes: [], tested: 0 });

const workflows = (ctx) => ctx.files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f));
const codeFiles = (ctx) => ctx.files.filter((f) => /\.([cm]?[jt]s|py)$/.test(f) && !TEST_FILE.test(f) && !/(^|\/)node_modules\//.test(f)).slice(0, 500);

// --- Código ------------------------------------------------------------------------------------------------

const TEST_CMD = /\b(npm|yarn|pnpm)\s+(run\s+)?test\b|\bnpm\s+t\b|\bmake\s+test\b|\bnode\s+--test\b|\bpytest\b|\bjest\b|\bvitest\b|\bmocha\b|\bgo\s+test\b|\bpython\s+-m\s+unittest\b/;
const DB_SERVICE = /^\s{4,}(postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|db|database)\s*:|image:\s*['"]?(postgres|mysql|mariadb|mongo|redis)/im;
const DB_DOCKER = /docker\s+(run|compose\s+up)[^\n]*(postgres|mysql|mariadb|mongo)/i;

/** CORE-015: o CI roda os testes contra um banco real e descartável. */
function ciTestsWithDb(ctx, disc) {
  const r = result();
  const wf = workflows(ctx);
  if (!wf.length) return r;
  const tests = wf.filter((f) => TEST_CMD.test(ctx.read(f) || ''));
  r.tested += 1;
  if (!tests.length) {
    r.findings.push({ soft: true, severity: 'medium', key: 'ci-no-tests', message: 'Nenhum workflow do CI roda a suíte de testes (npm test, node --test, pytest, jest...).' });
    return r;
  }
  const withDb = tests.find((f) => DB_SERVICE.test(ctx.read(f) || '') || DB_DOCKER.test(ctx.read(f) || ''));
  const usesDb = disc && (disc.stores || []).some((s) => /PostgreSQL|MySQL|MongoDB|SQLite|ORM/.test(s));
  if (!withDb && usesDb) {
    r.findings.push({ soft: true, severity: 'medium', key: 'ci-no-db', location: tests[0], message: `${tests[0]} roda os testes, mas nenhum workflow sobe um banco real (serviço do CI ou contêiner): consultas e regras de autorização ficam testadas só contra mock ou não ficam.` });
    return r;
  }
  r.notes.push(`${NOTE} ${withDb || tests[0]} roda os testes${withDb ? ' com um banco real no CI' : ''}. Falta confirmar que o deploy só acontece depois do CI verde.`);
  return r;
}

const PW_LIB = /\b(bcrypt|bcryptjs|argon2|@node-rs\/argon2|@node-rs\/bcrypt|scrypt|passlib|argon2-cffi)\b/;
const BCRYPT_COST = /\b(?:bcrypt\w*)\.(?:hash|hashSync|genSalt|genSaltSync)\s*\(\s*(?:[^,()]+,\s*)?(\d{1,2})\s*\)/g;
// Só nomes inequívocos: "CUSTO" ou "ROUNDS" soltos pegariam outras constantes do arquivo.
const ROUNDS_CONST = /\b(?:SALT_?ROUNDS|BCRYPT_?(?:ROUNDS|COST)|CUSTO_?BCRYPT)\s*=\s*(\d{1,2})\b/gi;
const SCRYPT_N = /\bN\s*:\s*(\d+)/;

/** AUTH-002: algoritmo de hash de senha e custo, lidos do código. */
function passwordHash(ctx) {
  const r = result();
  const files = codeFiles(ctx).filter((f) => PW_LIB.test(ctx.read(f) || '') || /\bscrypt(Sync)?\s*\(/.test(ctx.read(f) || ''));
  // Nome do pacote importado (require/import), não o nome da variável: "const bcrypt = require('bcryptjs')".
  const libOf = (text) => {
    const m = /(?:require\(\s*|from\s+)['"]([^'"]*(?:bcrypt|argon2|scrypt|passlib)[^'"]*)['"]/.exec(text) || /^\s*(?:import|from)\s+(bcrypt|argon2|passlib)\b/m.exec(text);
    return m ? m[1] : /scrypt/.test(text) ? 'scrypt (node:crypto)' : null;
  };
  if (!files.length) return r;
  r.tested += 1;
  const seen = [];
  for (const f of files) {
    const text = ctx.read(f) || '';
    for (const re of [BCRYPT_COST, ROUNDS_CONST]) {
      for (const m of text.matchAll(re)) {
        const cost = Number(m[1]);
        seen.push(`custo ${cost} em ${f}`);
        if (cost < 10) r.findings.push({ severity: 'high', key: `bcrypt-cost:${f}:${cost}`, location: f, message: `Custo do bcrypt ${cost} em ${f}: abaixo de 10, o hash sai rápido demais para resistir a força bruta offline. Use 12 ou mais (ou Argon2id).` });
      }
    }
    const n = SCRYPT_N.exec(text);
    if (n && /scrypt/.test(text)) {
      seen.push(`scrypt N=${n[1]} em ${f}`);
      if (Number(n[1]) < 16384) r.findings.push({ severity: 'high', key: `scrypt-n:${f}`, location: f, message: `scrypt com N=${n[1]} em ${f}: abaixo de 2^14 (16384) o custo é baixo. Use N de 2^15 ou mais.` });
    }
  }
  if (!r.findings.length) {
    const lib = files.map((f) => libOf(ctx.read(f) || '')).find(Boolean);
    const isBcrypt = /bcrypt/i.test(lib || '');
    const scryptDefault = /scrypt/i.test(lib || '') && !seen.length ? ' (sem N explícito: o padrão do Node é 16384)' : '';
    r.notes.push(`${NOTE} hash de senha com ${lib || 'biblioteca reconhecida'} em ${files.slice(0, 2).join(', ')}${seen.length ? ` (${[...new Set(seen)].slice(0, 3).join('; ')})` : scryptDefault}. Falta conferir ${isBcrypt ? 'como o limite de 72 bytes do bcrypt é tratado' : 'se há truncamento da senha'} e que a senha é verificada exatamente como recebida.`);
  }
  return r;
}

// Senha fixa no código usada para criar ou redefinir conta (AUTH-043): uma constante com nome de senha padrão, ou um
// texto literal, passada para a função de hash de senha. O valor NUNCA é copiado para o achado.
const PW_CONST = /\b(?:const|let|var)\s+([A-Z_]*(?:SENHA|PASSWORD|PASSWD|PASS|PWD)[A-Z_]*(?:PADRAO|DEFAULT|INICIAL|INITIAL|TEMP|PROVISORIA)[A-Z_]*|DEFAULT_?(?:PASSWORD|PASS|PWD|SENHA)|SENHA_?(?:PADRAO|INICIAL))\s*=\s*(['"`])[^'"`]{1,200}\2/g;
const HASH_CALL = /\b(?:bcrypt\w*\.(?:hash|hashSync)|argon2\.hash|hashPassword|hashSenha|gerarHash|scrypt(?:Sync)?)\s*\(\s*([^,)]+)/g;

function defaultPasswords(ctx) {
  const r = result();
  for (const f of codeFiles(ctx)) {
    const text = ctx.read(f) || '';
    // Regex com /g guarda a posição (lastIndex): o teste usa uma cópia sem /g para não estragar a busca por linha.
    if (!new RegExp(HASH_CALL.source).test(text)) continue;
    r.tested += 1;
    const consts = new Set([...text.matchAll(PW_CONST)].map((m) => m[1]));
    const lines = text.split(/\r?\n/);
    const uses = [];
    lines.forEach((line, i) => {
      for (const m of line.matchAll(HASH_CALL)) {
        const arg = m[1].trim();
        // senha || SENHA_PADRAO também conta: sem senha informada, a conta nasce com a fixa.
        const hit = [...consts].find((c) => new RegExp(`\\b${c}\\b`).test(arg)) || (/^(['"`])[^'"`]{4,}\1$/.test(arg) ? 'texto literal' : null);
        if (hit) uses.push({ line: i + 1, what: hit });
      }
    });
    if (uses.length) {
      r.findings.push({ severity: 'high', key: `default-password:${f}:${uses[0].what}`, location: `${f}:${uses[0].line}`, message: `Conta criada ou redefinida com senha fixa no código (${uses[0].what === 'texto literal' ? 'texto literal' : uses[0].what}, ${uses.length} uso(s) em ${f}, linhas ${uses.slice(0, 5).map((u) => u.line).join(', ')}): quem conhece o código ou a documentação entra como esse usuário até a senha ser trocada. Gere uma senha aleatória por conta, entregue por canal seguro, com troca obrigatória e prazo.` });
    }
  }
  if (r.tested && !r.findings.length) r.notes.push(`${NOTE} nenhuma senha fixa passada para a função de hash em ${r.tested} arquivo(s).`);
  return r;
}

/** AG-001 e AG-007: existe um mecanismo (hook ou permissão), não só uma instrução, que barra o agente. */
function agentGuard(ctx, profile) {
  const out = { 'AG-001': result(), 'AG-007': result() };
  if (!profile.flags || !profile.flags.aiCodingAgents) return out;
  const hookFiles = ctx.files.filter((f) => /^\.kiro\/hooks\/[^/]+\.(json|js|kiro\.hook)$/.test(f));
  const hookText = hookFiles.map((f) => ctx.read(f) || '').join('\n');
  const claude = ['.claude/settings.json', '.claude/settings.local.json'].filter((f) => ctx.has(f)).map((f) => ctx.read(f) || '').join('\n');
  const env = /\.env|segredo|secret/i;
  const conf = /\.kiro|settings\.json|mcp\.json|steering|hooks/i;
  const blocks = /PreToolUse|"deny"|permissionDecision|exit\(2\)|process\.exit\(\s*2\s*\)/;
  for (const [id, re, what] of [['AG-001', env, 'a leitura de arquivos de segredo'], ['AG-007', conf, 'a escrita na configuração do próprio agente']]) {
    const r = out[id];
    r.tested += 1;
    const viaHook = hookFiles.length && blocks.test(hookText) && re.test(hookText);
    const viaClaude = /"deny"/.test(claude) && re.test(claude);
    if (viaHook || viaClaude) r.notes.push(`${NOTE} há mecanismo que barra ${what} (${viaHook ? `hook em ${hookFiles.slice(0, 2).join(', ')}` : '.claude/settings.json com deny'}). Falta provar numa sessão de teste que o bloqueio acontece.`);
    // Média, não alta: o mecanismo pode estar fora do repositório (sandbox, política da empresa). Pede revisão, não bloqueia.
    else r.findings.push({ soft: true, severity: 'medium', key: `${id.toLowerCase()}-no-mechanism`, message: `O perfil declara agentes de IA, mas nenhum hook ou regra de permissão barra ${what}: uma instrução no prompt não é mecanismo. Instale o adaptador (lastro adapter kiro --write) ou configure deny.` });
  }
  return out;
}

// --- HTTP passivo ------------------------------------------------------------------------------------------

const DOC_PATHS = ['/docs', '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json', '/api-docs', '/openapi.json', '/v3/api-docs', '/redoc', '/metrics', '/actuator', '/server-status', '/debug', '/phpinfo.php'];
const LIST_PATHS = ['/uploads/', '/static/', '/public/', '/assets/', '/files/', '/backup/'];
const DOC_BODY = /swagger|openapi|redoc|"paths"\s*:/i;
const METRICS_BODY = /^# (HELP|TYPE) /m;
const LIST_BODY = /<title>\s*(Index of|Directory listing)|<h1>\s*Index of \//i;
const DEBUG_BODY = /phpinfo\(\)|Server Status for|Apache Server Status|actuator|"_links"\s*:/i;

/** WEB-016: listagem de diretório, documentação interna e monitoramento expostos. */
async function exposedPaths(ctx, { extra = [] } = {}) {
  const r = result();
  for (const p of [...new Set([...DOC_PATHS, ...LIST_PATHS, ...extra])]) {
    const res = await ctx.fetch(p);
    if (!res.ok) continue;
    r.tested += 1;
    if (res.status < 200 || res.status >= 300) continue;
    const body = res.body || '';
    const kind = LIST_BODY.test(body) ? 'listagem de diretório' : METRICS_BODY.test(body) ? 'métricas de monitoramento' : DOC_BODY.test(body) ? 'documentação da API' : DEBUG_BODY.test(body) ? 'página de diagnóstico' : null;
    if (kind) r.findings.push({ severity: 'medium', key: `exposed:${p}`, location: p, message: `${p} responde ${res.status} com ${kind}, acessível sem login. Tire de produção ou proteja com autenticação.` });
  }
  if (r.tested && !r.findings.length) r.notes.push(`${NOTE} ${r.tested} caminho(s) comuns de documentação, monitoramento e listagem sem exposição. Falta conferir os caminhos próprios da aplicação.`);
  return r;
}

/** WEB-018: Content-Type presente, e charset nas respostas de texto. */
async function contentTypes(ctx) {
  const r = result();
  const samples = [['/', 'página inicial'], [`/lastro-probe-${crypto.randomBytes(4).toString('hex')}`, 'rota inexistente']];
  for (const [p, label] of samples) {
    const res = await ctx.fetch(p);
    if (!res.ok || !(res.body || '').length) continue;
    r.tested += 1;
    const ct = String(res.headers['content-type'] || '');
    if (!ct) r.findings.push({ severity: 'medium', key: `ct-missing:${label}`, location: p, message: `A ${label} (${p}) responde com corpo e sem Content-Type: o navegador adivinha o tipo (MIME sniffing).` });
    else if (/^text\//i.test(ct) && !/charset=/i.test(ct)) r.findings.push({ severity: 'low', key: `ct-charset:${label}`, location: p, message: `A ${label} responde ${ct} sem charset. Declare charset=utf-8.` });
  }
  if (r.tested && !r.findings.length) r.notes.push(`${NOTE} Content-Type correto em ${r.tested} resposta(s) de amostra. Falta conferir rotas de API, de erro e os cabeçalhos do proxy.`);
  return r;
}

// --- HTTP ativo (login com credenciais erradas) -----------------------------------------------------------

const DEFAULT_CREDS = [['admin', 'admin'], ['admin', 'password'], ['admin', '123456'], ['root', 'root'], ['test', 'test'], ['admin@admin.com', 'admin'], ['admin@example.com', 'admin123'], ['user', 'user']];
const LIMITED = (res) => res.status === 429 || res.status === 423 || /too many|muitas tentativas|tente (novamente )?mais tarde|bloquead|limite de tentativas|rate limit/i.test(res.body || '');

async function tryLogin(ctx, login, user, password) {
  const format = login.format || 'json';
  const body = encodeBody(format, { [login.userField || 'username']: user, [login.passwordField || 'password']: password });
  const origin = new URL(ctx.url).origin;
  return ctx.fetch(login.path, { method: 'POST', headers: { 'content-type': contentType(format), origin, 'sec-fetch-site': 'same-origin' }, body, cacheKey: `assist-login:${crypto.randomBytes(6).toString('hex')}` });
}

/** AUTH-011: nenhuma das credenciais padrão mais comuns entra. Roda antes da força bruta, para o limite não esconder nada. */
async function defaultCreds(ctx, login) {
  const r = result();
  for (const [u, p] of DEFAULT_CREDS) {
    const res = await tryLogin(ctx, login, u, p);
    if (!res.ok) continue;
    r.tested += 1;
    if (LIMITED(res)) { r.notes.push(`${NOTE} o login começou a limitar durante o teste de contas padrão; ${r.tested} tentativa(s) recusadas.`); break; }
    if (res.status >= 200 && res.status < 300 && (res.setCookie || []).length) {
      r.findings.push({ severity: 'critical', key: `default-cred:${u}`, location: login.path, message: `O login em ${login.path} aceitou a credencial padrão "${u}" (HTTP ${res.status}, com cookie de sessão). Desative contas padrão e de exemplo.` });
    }
  }
  if (r.tested && !r.findings.length && !r.notes.length) r.notes.push(`${NOTE} ${r.tested} credenciais padrão comuns recusadas em ${login.path}. Falta conferir contas de seed, de documentação e dicas de senha.`);
  return r;
}

const BRUTE_ATTEMPTS = 25;

/** AUTH-016: tentativas erradas em sequência, numa conta inexistente, são limitadas. */
async function bruteForce(ctx, login, { prior = 0, priorLimited = false } = {}) {
  const r = result();
  const user = `lastro-probe-${crypto.randomBytes(4).toString('hex')}@invalid.test`;
  for (let i = 1; i <= BRUTE_ATTEMPTS; i += 1) {
    const res = await tryLogin(ctx, login, user, `errada-${i}-${crypto.randomBytes(3).toString('hex')}`);
    if (!res.ok) { r.notes.push(`${NOTE} força bruta inconclusiva: ${login.path} parou de responder (${res.error}).`); return r; }
    r.tested = i;
    if (LIMITED(res)) {
      // As tentativas do teste de contas padrão contam no mesmo limitador. Se ele já limitava na primeira daqui, o
      // limite veio na última tentativa daquele teste (que já está em "prior"): não soma de novo.
      const carried = priorLimited && i === 1;
      const at = carried ? prior : prior + i;
      const how = !prior ? '' : carried ? ' (o limite já vinha do teste de contas padrão)' : ` (${prior} do teste de contas padrão e ${i} deste)`;
      r.notes.push(`${NOTE} o login em ${login.path} passou a limitar depois de ${at} tentativa(s) erradas seguidas do mesmo endereço${how} (HTTP ${res.status}). Falta conferir o limite por conta (de IPs diferentes) e a documentação.`);
      return r;
    }
    if (res.status >= 200 && res.status < 300 && (res.setCookie || []).length) { r.notes.push(`${NOTE} força bruta inconclusiva: ${login.path} respondeu 2xx com cookie para uma senha errada; confira o formato do login no perfil.`); return r; }
  }
  r.findings.push({ severity: 'high', key: `no-bruteforce-limit:${login.path}`, location: login.path, message: `${BRUTE_ATTEMPTS} tentativas de login erradas seguidas em ${login.path}, do mesmo endereço, sem nenhum limite (nem 429, nem bloqueio, nem desafio).` });
  return r;
}

/**
 * Roda as provas assistidas que as travas permitem. Devolve { 'CTRL-ID': { findings, notes, tested } }.
 * `disc` é a descoberta (discover) já feita pelo motor.
 */
async function runAssists(ctx, profile, { active = false, disc = null, want = () => true } = {}) {
  const out = {};
  const put = (id, r, source) => { if (r && (r.tested || r.notes.length || r.findings.length)) out[id] = { ...r, source }; };
  // WEB-016, WEB-018, AUTH-011, AUTH-016 e AUTH-002 tinham prova parcial aqui; o pedaço que a máquina prova por
  // inteiro virou controle automático próprio (WEB-022, WEB-023, AUTH-041, AUTH-040 e AUTH-042, checks/assisted.js),
  // para a mesma falha não contar duas vezes. Ficam aqui só as provas que continuam parciais.
  void active;
  if (want('CORE-015')) put('CORE-015', ciTestsWithDb(ctx, disc), 'verifier-repo');
  if (want('AG-001') || want('AG-007')) {
    const ag = agentGuard(ctx, profile);
    if (want('AG-001')) put('AG-001', ag['AG-001'], 'verifier-repo');
    if (want('AG-007')) put('AG-007', ag['AG-007'], 'verifier-repo');
  }
  return out;
}

// --- Rotas de escrita sem autenticação vista (AUTH-044) -----------------------------------------------------
// Usa a descoberta de rotas (Express, Flask/FastAPI, Next.js). Rota administrativa sem autenticação é alta; as demais
// também, a não ser que haja montagem de roteador com autenticação que o kit não conseguiu ligar às rotas: aí a rota
// pode estar protegida, e o achado vira médio (revisar), sem bloquear.
const ADMIN_PATH = /(^|\/)(admin|administra\w*|gestao|manage|internal|interno|backoffice|sistema)(\/|$)/i;

function unauthWriteRoutes(disc) {
  const r = result();
  const routes = disc && disc.routes;
  if (!routes || !routes.total) return r;
  r.tested += 1;
  const unsure = routes.authMounts > 0;
  const list = routes.unauthWrites || [];
  const admin = list.filter((x) => ADMIN_PATH.test(x.path));
  const rest = list.filter((x) => !ADMIN_PATH.test(x.path));
  const fmt = (xs) => xs.slice(0, 8).map((x) => `${x.method} ${x.path} (${x.location})`).join('; ');
  const tail = unsure ? ' Há montagem de roteador com autenticação que o kit não ligou a estas rotas: confira se ela as cobre.' : '';
  if (admin.length) {
    r.findings.push({ severity: unsure ? 'medium' : 'high', key: `unauth-admin:${admin.map((x) => `${x.method} ${x.path}`).join(',')}`, location: admin[0].location, message: `${admin.length} rota(s) administrativa(s) de escrita sem autenticação vista no código: ${fmt(admin)}${admin.length > 8 ? ' ...' : ''}. Qualquer pessoa que alcance a aplicação pode executá-las.${tail}` });
  }
  if (rest.length) {
    r.findings.push({ severity: unsure ? 'medium' : 'high', key: `unauth-write:${rest.map((x) => `${x.method} ${x.path}`).join(',')}`, location: rest[0].location, message: `${rest.length} rota(s) de escrita sem autenticação vista no código: ${fmt(rest)}${rest.length > 8 ? ' ...' : ''}. Se alguma é pública de propósito, justifique com 'lastro-ignore unauth-write: motivo' na linha da rota.${tail}` });
  }
  if (!r.findings.length) r.notes.push(`${NOTE} nenhuma rota de escrita sem autenticação vista, entre as ${routes.total} rota(s) lidas no código.`);
  return r;
}

// --- Corpo da requisição gravado direto no banco (AUTH-045) -------------------------------------------------
// Prisma: data: body | data: await req.json() | data: { ...body }. Sequelize/Mongoose/TypeORM: Model.create(req.body),
// .update(req.body), findByIdAndUpdate(id, req.body), Object.assign(x, req.body). Variável que passa por um esquema
// (parse, safeParse, validate, pick) no mesmo arquivo não conta.
const ORM_WRITE = /\.(create|createMany|update|updateMany|upsert|insert|save|findByIdAndUpdate|findOneAndUpdate|updateOne|replaceOne)\s*\(/;
const RAW_BODY_DEF = /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+\w+\.json\(\)|req(?:uest)?\.body)\s*;?\s*$/;
const VALIDATED = (name) => new RegExp(`\\.(?:parse|safeParse|parseAsync|validate|validateSync|pick|strict)\\s*\\(\\s*(?:await\\s+)?${name}\\b|\\b${name}\\s*=\\s*\\w+\\.(?:parse|safeParse|parseAsync)\\s*\\(`);

function massAssignment(ctx) {
  const r = result();
  for (const f of codeFiles(ctx)) {
    const text = ctx.read(f) || '';
    if (!ORM_WRITE.test(text)) continue;
    r.tested += 1;
    const lines = text.split(/\r?\n/);
    const raw = new Set();
    for (const line of lines) { const m = RAW_BODY_DEF.exec(line); if (m && !VALIDATED(m[1]).test(text)) raw.add(m[1]); }
    const hits = [];
    lines.forEach((line, i) => {
      if (/lastro-ignore\s+mass-assignment/.test(line) || /^\s*(\/\/|\*|#)/.test(line)) return;
      const names = [...raw].map((n) => n.replace(/\$/g, '\\$')).join('|');
      const viaVar = names && new RegExp(`\\bdata\\s*:\\s*(?:\\{\\s*\\.\\.\\.\\s*)?(?:${names})\\b(?!\\s*\\.)`).test(line);
      const direct = /\bdata\s*:\s*(?:\{\s*\.\.\.\s*)?(?:await\s+\w+\.json\(\)|req(?:uest)?\.body\b(?!\s*\.))/.test(line)
        || (ORM_WRITE.test(line) && /\(\s*(?:[\w.]+\s*,\s*)?req\.body\s*[,)]/.test(line))
        || /Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)/.test(line);
      if (viaVar || direct) hits.push(i + 1);
    });
    if (hits.length) r.findings.push({ severity: 'high', key: `mass-assignment:${f}`, location: `${f}:${hits[0]}`, message: `Corpo da requisição gravado direto no banco, sem esquema nem lista de campos, em ${f} (linha(s) ${hits.slice(0, 5).join(', ')}): o cliente pode mudar qualquer campo do registro, inclusive dono, saldo ou papel. Valide com um esquema e grave só os campos permitidos.` });
  }
  if (r.tested && !r.findings.length) r.notes.push(`${NOTE} nenhuma gravação do corpo cru da requisição em ${r.tested} arquivo(s) com escrita no banco.`);
  return r;
}

const COVERS = ['CORE-015', 'AG-001', 'AG-007'];

module.exports = { runAssists, NOTE, COVERS, ciTestsWithDb, passwordHash, defaultPasswords, unauthWriteRoutes, massAssignment, agentGuard, exposedPaths, contentTypes, defaultCreds, bruteForce, BRUTE_ATTEMPTS };
