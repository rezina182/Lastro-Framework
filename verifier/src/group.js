'use strict';

// Aplicação com vários repositórios (por exemplo, os repositórios de uma organização que formam uma só aplicação).
// O usuário diz o nome da aplicação e a pasta onde os repositórios estão; o kit identifica sozinho o papel de cada um
// (frontend, backend, worker, infraestrutura...), verifica cada repositório (só leitura), monta o desenho da aplicação
// e junta os riscos num relatório único.
//
// Tudo é heurística lida do código, com motivo e confiança. O usuário corrige com um system.json (--write-system
// gera o rascunho; --system usa o corrigido). Nada é gravado dentro dos repositórios analisados.

const fs = require('node:fs');
const path = require('node:path');
const schema = require('./schema');
const { stripBom } = require('./util');
const { buildContext, runCheck, ConfigError } = require('./engine');
const { loadCatalog } = require('./catalog');
const { discover } = require('./discover');
const { classifyRepo } = require('./classify');
const { buildSystemArchitecture } = require('./architecture');
const { validateSystem, resolveRepos } = require('./system');

const MARKERS = ['.git', 'package.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'pom.xml', 'build.gradle', 'Cargo.toml', 'composer.json', 'Gemfile', 'pubspec.yaml', 'main.tf', 'docker-compose.yml', 'Chart.yaml'];
const MAX_REPOS = 12;
const MAX_HOSTS = 8;
const CODE_RE = /\.(js|mjs|cjs|ts|tsx|jsx|py|html|vue|svelte)$/i;

const globToRe = (g) => new RegExp(`^${String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');
const posix = (p) => p.split(path.sep).join('/');

function slug(s, used) {
  let id = String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 20) || 'repo';
  if (!/^[a-z]/.test(id)) id = `r-${id}`;
  let out = id;
  for (let n = 2; used.has(out); n += 1) out = `${id}-${n}`.slice(0, 24);
  used.add(out);
  return out;
}

function isRepoDir(d) {
  return MARKERS.some((m) => fs.existsSync(path.join(d, m)));
}

/** Repositórios do grupo: os informados, ou as subpastas diretas que parecem repositório (e casam com --match). */
function findRepoDirs(dir, { repos = null, match = null } = {}) {
  if (repos && repos.length) {
    return repos.map((r) => {
      const d = path.resolve(dir, r);
      if (!fs.existsSync(d) || !fs.statSync(d).isDirectory()) throw new ConfigError(`Repositório não encontrado: ${r}`);
      return d;
    });
  }
  const re = match ? globToRe(match) : null;
  const found = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!e.isDirectory() || e.isSymbolicLink() || e.name.startsWith('.') || e.name === 'node_modules') continue;
    if (re && !re.test(e.name)) continue;
    const d = path.join(dir, e.name);
    if (isRepoDir(d)) found.push(d);
  }
  found.sort();
  if (found.length === 0) throw new ConfigError(`Nenhum repositório encontrado em ${dir}${match ? ` com o padrão "${match}"` : ''}.`);
  if (found.length > MAX_REPOS) throw new ConfigError(`${found.length} repositórios encontrados (máximo ${MAX_REPOS}). Restrinja com --match ou liste com --repos.`);
  return found;
}

function loadDeclaredProfile(dir) {
  const file = path.join(dir, '.lastro', 'profile.json');
  try {
    const p = JSON.parse(stripBom(fs.readFileSync(file, 'utf8')));
    return schema.validateProfile(p).length ? null : p;
  } catch (e) {
    return null;
  }
}

function mentions(ctx, token) {
  if (!token || token.length < 4) return false;
  const t = token.toLowerCase();
  for (const f of ctx.files.filter((x) => CODE_RE.test(x)).slice(0, 300)) {
    const text = ctx.read(f);
    if (text && text.toLowerCase().includes(t)) return true;
  }
  return false;
}

const DB_TECH = /^(PostgreSQL|MySQL|SQLite|MongoDB|Redis)$/;

/** Rascunho de system.json a partir dos repositórios identificados. */
function generateSystem(name, entries) {
  const used = new Set(['user', 'dev']);
  const components = [];
  const flows = [];
  for (const e of entries) {
    e.id = slug(e.base, used);
    components.push({
      id: e.id, name: e.base.slice(0, 60), role: e.cls.role, repo: e.rel,
      exposure: ['frontend', 'backend', 'gateway', 'mobile'].includes(e.cls.role) ? 'internet' : 'interna',
      ...(e.cls.flags.personalData ? { dataClasses: ['pessoal'] } : {}), inferred: true,
      note: `papel identificado pelo kit, confiança ${e.cls.confidence === 'media' ? 'média' : e.cls.confidence}${e.cls.fullstack ? '; serve interface e API' : ''}`.slice(0, 200),
    });
  }
  const techs = [...new Set(entries.flatMap((e) => e.disc.stores.filter((s) => DB_TECH.test(s))))];
  const dbId = new Map();
  for (const t of techs) {
    const id = slug(`db-${t}`, used);
    dbId.set(t, id);
    components.push({ id, name: t, role: 'database', exposure: 'privada', inferred: true, note: techs.length && entries.filter((e) => e.disc.stores.includes(t)).length > 1 ? 'compartilhado entre repositórios (suposição: confirme)' : '' });
    if (!components[components.length - 1].note) delete components[components.length - 1].note;
  }
  // Host que contém o nome de um dos repositórios é a própria aplicação, não um serviço externo.
  const internalHost = (h) => entries.some((x) => x.base.length >= 4 && h.toLowerCase().includes(x.base.toLowerCase()));
  const hosts = [...new Set(entries.flatMap((e) => e.disc.externalHosts))].filter((h) => !internalHost(h)).slice(0, MAX_HOSTS);
  const hostId = new Map();
  for (const h of hosts) {
    const id = slug(`ext-${h}`, used);
    hostId.set(h, id);
    components.push({ id, name: h.slice(0, 60), role: 'external', inferred: true });
  }
  const fronts = entries.filter((e) => ['frontend', 'mobile'].includes(e.cls.role));
  const backs = entries.filter((e) => ['backend', 'gateway'].includes(e.cls.role));
  const flow = (from, to, label, protocol) => flows.push({ from, to, label, ...(protocol ? { protocol } : {}), inferred: true });
  for (const f of fronts) flow('user', f.id, f.cls.role === 'mobile' ? 'Uso do aplicativo' : 'Navegação do usuário', 'https');
  for (const b of backs.filter((x) => x.disc.routes.total > 0)) flow('user', b.id, 'Acesso direto à API', 'https');
  for (const f of fronts) {
    const linked = backs.filter((b) => mentions(f.ctx, b.base) || mentions(f.ctx, b.pkgName));
    for (const b of (linked.length ? linked : backs)) flow(f.id, b.id, linked.length ? 'Chamadas à API' : 'Chamadas à API (suposição: o código não cita o backend)', 'https');
  }
  for (const g of backs.filter((x) => x.cls.role === 'gateway')) for (const b of backs.filter((x) => x.cls.role === 'backend')) flow(g.id, b.id, 'Encaminha requisições', 'https');
  for (const e of entries.filter((x) => ['backend', 'gateway', 'worker'].includes(x.cls.role))) {
    for (const s of e.disc.stores.filter((x) => dbId.has(x))) flow(e.id, dbId.get(s), 'Leitura e escrita de dados', 'sql');
    for (const h of e.disc.externalHosts.filter((x) => hostId.has(x))) flow(e.id, hostId.get(h), 'Chamada a serviço externo', 'https');
  }
  return { schemaVersion: 1, name: name.slice(0, 80), components, flows };
}

const gradeOf = (r) => (r && r.score ? r.score.grade : null);

/**
 * Analisa a aplicação. `dir`: pasta com os repositórios. `repos`: nomes ou caminhos (opcional). `match`: padrão dos nomes.
 * `system`: system.json corrigido pelo usuário (opcional). Devolve { group, reports }.
 */
async function analyzeGroup({ dir, name, repos = null, match = null, system = null, allowExternal = false, now = new Date(), catalogDir } = {}) {
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new ConfigError(`Pasta não encontrada: ${dir}`);
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 80) throw new ConfigError('Informe o nome da aplicação (--name, de 2 a 80 caracteres).');
  const catalog = loadCatalog(catalogDir);
  const warnings = [];

  let dirs;
  if (system) {
    const bad = validateSystem(system);
    if (bad.length) throw new ConfigError(`system inválido:\n- ${bad.slice(0, 5).join('\n- ')}`);
    dirs = [...new Set(system.components.filter((c) => c.repo).map((c) => path.resolve(root, c.repo)))];
  } else dirs = findRepoDirs(root, { repos, match });

  const entries = [];
  for (const d of dirs) {
    const base = path.basename(d);
    const rel = posix(path.relative(root, d)) || '.';
    const inside = !rel.startsWith('..') && !path.isAbsolute(rel);
    if (!inside && !allowExternal) { warnings.push(`Repositório "${rel}" fora da pasta analisada: não lido (use --allow-external-repos).`); continue; }
    const tmp = { schemaVersion: 1, name: base, flags: Object.fromEntries(schema.FLAGS.map((f) => [f, false])) };
    const ctx = buildContext({ root: d, profile: tmp, catalog, url: null, active: false, now });
    const disc = discover(ctx);
    const cls = classifyRepo(ctx, disc, base);
    let pkgName = '';
    try { pkgName = String((JSON.parse(ctx.read('package.json') || '{}')).name || '').replace(/^@[^/]+\//, ''); } catch (e) { pkgName = ''; }
    const declared = loadDeclaredProfile(d);
    entries.push({ dir: d, base, rel, ctx, disc, cls, pkgName, declared, profile: declared || { schemaVersion: 1, name: base, flags: cls.flags } });
  }
  if (!entries.length) throw new ConfigError('Nenhum repositório pôde ser lido.');

  let sys = system;
  if (!sys) sys = generateSystem(name, entries);
  else {
    // O usuário corrigiu os papéis: usa os dele, mantendo o que o kit leu.
    for (const c of sys.components) {
      const e = entries.find((x) => c.repo && path.resolve(root, c.repo) === x.dir);
      if (e) { e.id = c.id; e.cls = { ...e.cls, role: c.role, confidence: 'declarado', reasons: ['papel declarado no system.json'] }; }
    }
  }

  const reports = [];
  const perRepo = new Map();
  const repoMap = new Map();
  for (const e of entries) {
    const key = sys.components.find((c) => c.repo && path.resolve(root, c.repo) === e.dir);
    const repoKey = key ? key.repo : e.rel;
    let report = null;
    let error = null;
    try {
      report = await runCheck({ root: e.dir, now, noSystem: true, catalogDir, ...(e.declared ? {} : { profile: e.profile }) });
    } catch (err) {
      error = String(err.message).split('\n')[0].slice(0, 160);
      warnings.push(`Repositório "${e.base}": a verificação falhou (${error}).`);
    }
    e.report = report;
    e.error = error;
    repoMap.set(repoKey, { dir: e.dir, inside: true, same: false, status: report ? 'ok' : 'erro' });
    if (report) {
      perRepo.set(repoKey, { model: report.threatModel, controls: report.controls, disc: report.threatModel.discovery, flags: e.profile.flags, name: e.base, dir: e.dir });
      reports.push({ name: e.base, report });
    }
    if (!e.declared) warnings.push(`Repositório "${e.base}": sem .lastro/profile.json. O kit derivou um perfil provisório do código (rascunho). O que o código não mostra (dados de menores, dados sensíveis, usuários anônimos) ficou desligado: revise.`);
    if (e.cls.confidence === 'baixa') warnings.push(`Repositório "${e.base}": papel "${e.cls.role}" identificado com confiança baixa. Confirme.`);
  }

  let architecture = null;
  const first = [...perRepo.values()].find((p) => p) || null;
  if (first) {
    const primary = [...perRepo.values()].find((p) => sys.components.some((c) => c.repo && path.resolve(root, c.repo) === p.dir && ['backend', 'gateway'].includes(c.role))) || first;
    architecture = buildSystemArchitecture({ system: sys, repos: repoMap, perRepo, primary });
    architecture.mode = 'aplicação';
    architecture.name = name;
  }

  const repoRows = entries.map((e) => {
    const r = e.report;
    const rs = r && r.risk ? r.risk.summary : null;
    return {
      name: e.base, path: e.rel, role: e.cls.role, confidence: e.cls.confidence, reasons: e.cls.reasons, fullstack: !!e.cls.fullstack,
      profile: e.declared ? 'declarado' : 'derivado', error: e.error,
      verdict: r ? r.verdict : null, blocking: r ? r.summary.blocking : null, grade: gradeOf(r), provenPct: r ? r.score.provenPct : null,
      automated: r ? r.score.automated : null,
      confirmed: rs ? rs.confirmed : null, potential: rs ? rs.potential : null,
      threats: r ? r.threatModel.counts : null,
      personalData: !!e.profile.flags.personalData, flags: Object.entries(e.profile.flags).filter(([, v]) => v).map(([k]) => k),
    };
  });

  const risks = reports.flatMap(({ name: repo, report }) => report.risk.security
    .filter((i) => i.state === 'failed')
    .map((i) => ({ repo, id: i.id, title: i.title, kind: i.kind, class: i.class, likelihood: i.likelihood, impact: i.impact, score: i.score, cwe: i.cwe, pillars: i.pillars, locations: i.locations, asvs: i.asvs, privacy: i.privacy, type: i.type })))
    .sort((a, b) => b.score - a.score || a.repo.localeCompare(b.repo) || a.id.localeCompare(b.id));
  const tally = (pick) => {
    const t = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    for (const r of reports) { const s = r.report.risk.summary[pick]; for (const k of Object.keys(t)) t[k] += s[k]; }
    return t;
  };
  const totals = {
    repos: entries.length, analyzed: reports.length,
    confirmed: tally('confirmed'), potential: tally('potential'),
    gateFail: reports.filter((r) => r.report.verdict === 'fail').length,
    threatsExposed: reports.reduce((s, r) => s + r.report.threatModel.counts.exposed, 0),
    threats: reports.reduce((s, r) => s + r.report.threatModel.counts.threats, 0),
    derivedProfiles: entries.filter((e) => !e.declared).length,
  };

  const group = {
    name, dir: path.basename(root), generatedAt: now.toISOString(), repos: repoRows, system: sys, architecture, risks, totals, warnings,
    legend: reports.length ? reports[0].report.legend : null,
    tool: reports.length ? reports[0].report.tool : { name: 'lastro', version: '0.0.0' },
  };
  return { group, reports };
}

module.exports = { analyzeGroup, generateSystem, findRepoDirs, globToRe, MAX_REPOS };
