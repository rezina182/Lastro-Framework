'use strict';

// Motor do LASTRO: carrega o catálogo e o perfil, executa as verificações e calcula o veredito.
//
// Regras de projeto (ver docs/PRINCIPLES.md):
//  - "não sei" nunca vira "passou": sem prova o estado é unverified;
//  - afirmação de quem escreveu o código (atestação) nunca verifica um controle automático;
//  - o portão só bloqueia achados NOVOS de severidade alta/crítica (fora do baseline e sem risco aceito vigente);
//  - risco aceito exige dono, aprovador e validade; vencido, volta a contar como achado;
//  - atestação manual tem validade (no máximo 366 dias).

const fs = require('node:fs');
const path = require('node:path');
const U = require('./util');
const schema = require('./schema');
const { loadCatalog, validateCatalog } = require('./catalog');
const { registry } = require('./checks');
const { request } = require('./http');

class ConfigError extends Error {}

const DEFAULT_THRESHOLDS = { hstsMinSeconds: 31536000, threatModelMaxAgeDays: 180, alwaysOnInstructionBytes: 8192 };
const BLOCKING_SEVERITIES = new Set(['critical', 'high']);
const STATES = new Set(['verified', 'failed', 'unverified', 'not_applicable']);
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_ATTESTATION_DAYS = 366;

function kitVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;
  } catch (e) {
    return '0.0.0';
  }
}

function loadProfile(root) {
  const j = U.readJson(root, '.lastro/profile.json');
  if (!j.ok) throw new ConfigError(`.lastro/profile.json ausente ou inválido (${j.error}). Rode "lastro init".`);
  const errs = schema.validateProfile(j.value);
  if (errs.length) throw new ConfigError(`.lastro/profile.json inválido:\n- ${errs.join('\n- ')}`);
  return j.value;
}

function loadOptional(root, rel, validator, empty) {
  if (!U.exists(root, rel)) return empty;
  const j = U.readJson(root, rel);
  if (!j.ok) throw new ConfigError(`${rel} inválido (${j.error}).`);
  const errs = validator(j.value);
  if (errs.length) throw new ConfigError(`${rel} inválido:\n- ${errs.join('\n- ')}`);
  return j.value;
}

function loadRisks(root) {
  const dir = path.join(root, '.lastro', 'risks');
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  } catch (e) {
    return [];
  }
  const out = [];
  for (const n of names) {
    const j = U.readJson(root, `.lastro/risks/${n}`);
    // Risco inválido não vale como aceitação; o check repo.risks.valid o reporta.
    if (j.ok && schema.validateRisk(j.value, n).length === 0) out.push({ ...j.value, scope: j.value.scope || 'findings' });
  }
  return out;
}

function isApplicable(control, packs, flags) {
  const req = (packs[control.pack] && packs[control.pack].requires) || [];
  return req.every((f) => flags[f]) && (control.appliesIf || []).every((f) => flags[f]);
}

function buildContext({ root, profile, catalog, url, active, now }) {
  const files = U.listFiles(root);
  const fileSet = new Set(files);
  const readCache = new Map();
  const httpCache = new Map();
  let base = null;
  if (url) {
    const u = new URL(url);
    base = `${u.origin}${u.pathname.replace(/\/$/, '')}`;
  }
  return {
    root,
    now,
    profile,
    catalog,
    url,
    active: !!active,
    files,
    thresholds: { ...DEFAULT_THRESHOLDS, ...(profile.thresholds || {}) },
    excludePrefixes: (profile.scan && profile.scan.excludePrefixes) || [],
    isGit: fs.existsSync(path.join(root, '.git')),
    has: (rel) => fileSet.has(rel),
    read(rel) {
      if (!readCache.has(rel)) readCache.set(rel, U.readText(root, rel));
      return readCache.get(rel);
    },
    async fetch(p, o = {}) {
      const key = o.cacheKey || `${o.method || 'GET'} ${p} ${o.maxRedirects || 0}`;
      if (httpCache.has(key)) return httpCache.get(key);
      const res = await request(`${base}${p}`, { method: o.method || 'GET', headers: o.headers, body: o.body, maxRedirects: o.maxRedirects || 0 });
      httpCache.set(key, res);
      return res;
    },
    allSetCookies: () => [...httpCache.values()].flatMap((r) => r.setCookie || []),
  };
}

function evaluateManual(control, status, now) {
  const a = status.attestations[control.id];
  if (!a) return { state: 'unverified', findings: [], notes: ['Sem atestação registrada em .lastro/status.json.'], evidence: null };
  const col = U.parseDate(a.collectedAt);
  const exp = U.parseDate(a.expiresAt);
  if (exp === null || col === null || exp <= now.getTime()) return { state: 'unverified', findings: [], notes: ['Atestação expirada.'], evidence: null };
  if (col > now.getTime() + DAY_MS) return { state: 'unverified', findings: [], notes: ['Atestação com data de coleta no futuro.'], evidence: null };
  if ((exp - col) / DAY_MS > MAX_ATTESTATION_DAYS) return { state: 'unverified', findings: [], notes: [`Atestação com validade acima de ${MAX_ATTESTATION_DAYS} dias não é aceita.`], evidence: null };
  return {
    state: 'verified',
    findings: [],
    notes: [`Atestado por ${a.attestedBy} (autodeclaração com prazo, até ${a.expiresAt.slice(0, 10)}).`],
    evidence: { source: 'manual-attestation', attestedBy: a.attestedBy, collectedAt: a.collectedAt, expiresAt: a.expiresAt, ref: a.evidenceRef || null },
  };
}

async function runCheck(opts = {}) {
  const root = path.resolve(opts.root || process.cwd());
  const now = opts.now || new Date();
  const catalog = loadCatalog(opts.catalogDir);
  const catErrors = validateCatalog(catalog, new Set(registry.keys()));
  if (catErrors.length) throw new ConfigError(`Catálogo inválido:\n- ${catErrors.slice(0, 15).join('\n- ')}`);
  const profile = loadProfile(root);
  const baselineFile = loadOptional(root, '.lastro/baseline.json', schema.validateBaseline, null);
  const baseline = new Set(baselineFile ? baselineFile.fingerprints : []);
  const status = loadOptional(root, '.lastro/status.json', schema.validateStatus, { schemaVersion: 1, attestations: {} });
  const risks = loadRisks(root);
  if (opts.url && !/^https?:\/\//.test(opts.url)) throw new ConfigError('--url deve começar com http:// ou https://');

  const ctx = buildContext({ root, profile, catalog, url: opts.url || null, active: opts.active, now });
  const only = opts.only ? new Set(opts.only) : null;
  const warnings = [];
  const validRisk = (rk) => U.parseDate(rk.expires) > now.getTime();

  const controls = [];
  let notApplicable = 0;
  for (const c of catalog.controls) {
    if (only && !only.has(c.id)) continue;
    if (!isApplicable(c, catalog.packs, profile.flags)) {
      notApplicable += 1;
      continue;
    }
    let r;
    if (c.check.type === 'automated') {
      if (status.attestations[c.id]) warnings.push(`${c.id}: atestação ignorada (controle automático não aceita autodeclaração).`);
      const chk = registry.get(c.check.id);
      try {
        r = await chk.run(ctx);
      } catch (e) {
        r = { state: 'unverified', findings: [], notes: [`Erro interno na verificação: ${e.message}`] };
      }
      if (!r || !STATES.has(r.state)) r = { state: 'unverified', findings: [], notes: ['A verificação devolveu um resultado inválido.'] };
      r.evidence = { source: chk.kind === 'http' ? 'verifier-http' : 'verifier-repo', collectedAt: now.toISOString() };
    } else {
      r = evaluateManual(c, status, now);
    }

    const controlRisk = risks.find((rk) => rk.control === c.id && rk.scope === 'control' && validRisk(rk)) || null;
    const findings = (r.findings || []).map((f) => {
      const fp = U.fingerprint(c.id, f.key || f.message);
      const severity = f.severity || c.severity;
      const risk = risks.find((rk) => rk.control === c.id && rk.scope === 'findings' && rk.fingerprints.includes(fp) && validRisk(rk)) || null;
      const accepted = !!risk || !!controlRisk;
      const inBaseline = baseline.has(fp);
      const blocking = r.state === 'failed' && BLOCKING_SEVERITIES.has(severity) && !accepted && !inBaseline;
      return {
        fingerprint: fp, severity, message: f.message, location: f.location || null,
        accepted, riskId: risk ? risk.id : controlRisk ? controlRisk.id : null, inBaseline, blocking,
      };
    });
    controls.push({
      id: c.id, title: c.title, pack: c.pack, tier: c.tier, severity: c.severity, enforcement: c.enforcement,
      state: r.state, notes: r.notes || [], evidence: r.evidence || null, findings,
      controlRiskAccepted: r.state === 'unverified' && !!controlRisk ? controlRisk.id : null,
    });
  }

  const count = (s) => controls.filter((x) => x.state === s).length;
  const allFindings = controls.flatMap((x) => x.findings);
  const blocking = allFindings.filter((f) => f.blocking).length;
  const summary = {
    applicable: controls.length,
    verified: count('verified'),
    failed: count('failed'),
    unverified: count('unverified'),
    notApplicable: notApplicable + count('not_applicable'),
    blocking,
    debt: allFindings.filter((f) => f.inBaseline && !f.accepted).length,
    accepted: allFindings.filter((f) => f.accepted).length,
  };
  const incomplete = controls.some((x) => x.state === 'unverified' && BLOCKING_SEVERITIES.has(x.severity) && !x.controlRiskAccepted);
  const verdict = blocking > 0 ? 'fail' : incomplete ? 'incomplete' : 'pass';

  return {
    tool: { name: 'lastro', version: kitVersion() },
    catalogVersion: catalog.version,
    generatedAt: now.toISOString(),
    target: { root: path.basename(root), url: opts.url || null, active: !!opts.active },
    profile: { name: profile.name, flags: profile.flags },
    verdict,
    summary,
    controls,
    warnings,
  };
}

module.exports = { runCheck, buildContext, loadProfile, loadRisks, isApplicable, ConfigError, DEFAULT_THRESHOLDS, MAX_ATTESTATION_DAYS };
