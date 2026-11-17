'use strict';

// Banco de falhas plantadas (lastro bench): roda o kit contra aplicações de exemplo com falhas conhecidas e
// com gêmeas limpas, e mede o recall. Ver docs/BENCH.md.
//
// Resultado de cada falha plantada, do melhor para o pior:
//  - detected: o controle esperado falhou e apontou o ponto plantado;
//  - question: o controle esperado ficou "sem prova" (manual): o kit fez a pergunta, mas não achou a falha;
//  - missed: o controle passou, não se aplicou ou falhou em outro ponto: o kit perdeu a falha.
// Em aplicação limpa, o controle deve ficar verificado. Falhar ali é falso positivo.
//
// O resultado esperado de cada caso (expect) é a linha de base: piorar reprova; melhorar avisa para atualizar.
// Os servidores de teste são código do próprio kit e só sobem em 127.0.0.1, numa porta livre, com ambiente mínimo.

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { runCheck } = require('./engine');
const { stripBom } = require('./util');

const PLANTED_OUTCOMES = ['detected', 'question', 'missed'];
const RANK = { missed: 0, question: 1, detected: 2 };
const CATEGORIES = ['code', 'config', 'http', 'logic'];
const KINDS = ['planted', 'clean'];
const ID_CASE = /^[A-Z]{1,3}-\d{3}$/;
const ID_CONTROL = /^[A-Z]+-\d{3}$/;
const SERVER_START_TIMEOUT_MS = 5000;
const DEFAULT_MANIFEST = path.join(__dirname, '..', '..', 'fixtures', 'planted', 'manifest.json');

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isRelativeInside = (rel) => typeof rel === 'string' && rel.length > 0 && !path.isAbsolute(rel) && !rel.split(/[\\/]/).includes('..');

function loadManifest(file) {
  let text;
  try {
    text = stripBom(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return { ok: false, error: `manifesto ilegível: ${e.message}` };
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    return { ok: false, error: `manifesto com JSON inválido: ${e.message}` };
  }
  const errors = validateManifest(value);
  return errors.length ? { ok: false, error: `manifesto inválido:\n- ${errors.join('\n- ')}` } : { ok: true, value };
}

function validateManifest(m) {
  const errs = [];
  if (!isObj(m)) return ['o manifesto deve ser um objeto'];
  if (m.schemaVersion !== 1) errs.push('schemaVersion: use 1');
  if (typeof m.referenceDate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(m.referenceDate) || Number.isNaN(Date.parse(m.referenceDate))) {
    errs.push('referenceDate: use AAAA-MM-DD (data fixa que mantém o resultado reproduzível)');
  }
  if (!isObj(m.apps) || Object.keys(m.apps).length === 0) errs.push('apps: deve ser um objeto com ao menos uma aplicação');
  else {
    for (const [name, a] of Object.entries(m.apps)) {
      if (!isObj(a) || !isRelativeInside(a.dir)) errs.push(`apps.${name}.dir: caminho relativo, sem ".."`);
      if (isObj(a) && a.server !== undefined && !isRelativeInside(a.server)) errs.push(`apps.${name}.server: caminho relativo, sem ".."`);
      if (isObj(a) && a.auth !== undefined && typeof a.auth !== 'boolean') errs.push(`apps.${name}.auth: use true ou false`);
      if (isObj(a) && a.auth === true && !a.server) errs.push(`apps.${name}.auth: as sondas autenticadas precisam de um servidor de teste (server)`);
      if (isObj(a) && a.env !== undefined) {
        if (!isObj(a.env)) errs.push(`apps.${name}.env: deve ser objeto (contas de teste FALSAS)`);
        else for (const [k, v] of Object.entries(a.env)) if (!/^BENCH_[A-Z0-9_]{1,40}$/.test(k) || typeof v !== 'string' || v.length > 64) errs.push(`apps.${name}.env.${k}: use nomes BENCH_* e texto de até 64 caracteres`);
      }
    }
  }
  if (!Array.isArray(m.cases) || m.cases.length === 0) {
    errs.push('cases: deve ser uma lista com ao menos um caso');
    return errs;
  }
  const seen = new Set();
  m.cases.forEach((c, i) => {
    const where = `cases[${i}]`;
    if (!isObj(c)) { errs.push(`${where}: deve ser objeto`); return; }
    if (typeof c.id !== 'string' || !ID_CASE.test(c.id)) errs.push(`${where}.id: use o formato P-001`);
    else if (seen.has(c.id)) errs.push(`${where}.id: repetido (${c.id})`);
    else seen.add(c.id);
    if (!isObj(m.apps) || !(c.app in m.apps)) errs.push(`${where}.app: aplicação desconhecida (${c.app})`);
    if (!KINDS.includes(c.kind)) errs.push(`${where}.kind: use ${KINDS.join(' ou ')}`);
    if (typeof c.control !== 'string' || !ID_CONTROL.test(c.control)) errs.push(`${where}.control: use um id de controle (CORE-059)`);
    if (typeof c.title !== 'string' || c.title.trim().length === 0 || c.title.length > 160) errs.push(`${where}.title: texto de 1 a 160 caracteres`);
    if (c.file !== undefined && !isRelativeInside(c.file)) errs.push(`${where}.file: caminho relativo, sem ".."`);
    if (c.messageIncludes !== undefined && (typeof c.messageIncludes !== 'string' || c.messageIncludes.length === 0)) errs.push(`${where}.messageIncludes: texto não vazio`);
    if (c.cwe !== undefined && !/^CWE-\d+$/.test(String(c.cwe))) errs.push(`${where}.cwe: use CWE-89`);
    if (c.probe !== undefined && (typeof c.probe !== 'boolean' || c.kind !== 'clean')) errs.push(`${where}.probe: só em caso limpo, com true ou false`);
    if (c.kind === 'planted') {
      if (!PLANTED_OUTCOMES.includes(c.expect)) errs.push(`${where}.expect: use ${PLANTED_OUTCOMES.join(', ')}`);
      if (!CATEGORIES.includes(c.category)) errs.push(`${where}.category: use ${CATEGORIES.join(', ')}`);
    } else if (c.kind === 'clean') {
      if (c.expect !== 'clean') errs.push(`${where}.expect: em caso limpo, use "clean"`);
    }
  });
  return errs;
}

/** Classifica um caso a partir do relatório da aplicação. Devolve { outcome, detail }. */
function evaluateCase(c, report) {
  const ctl = report.controls.find((x) => x.id === c.control);
  if (c.kind === 'clean') {
    if (!ctl) return { outcome: 'unmeasured', detail: 'o controle não se aplica ao perfil' };
    if (ctl.state === 'failed') {
      const f = ctl.findings[0];
      return { outcome: 'false-positive', detail: f ? `${f.location || '-'}: ${f.message}` : 'controle falhou sem achado' };
    }
    if (ctl.state === 'verified') return { outcome: 'clean', detail: 'verificado' };
    // Controle manual provado por sonda: a sonda passar não o verifica (fica sem prova), mas mostra que ela rodou e não achou nada.
    if (c.probe && ctl.state === 'unverified' && (ctl.notes || []).some((n) => n.startsWith('Sonda autenticada: passou'))) {
      return { outcome: 'clean', detail: 'a sonda autenticada rodou e passou' };
    }
    return { outcome: 'unmeasured', detail: `estado ${ctl.state}: o controle não foi medido` };
  }
  if (!ctl) return { outcome: 'missed', detail: 'o controle não se aplica ao perfil' };
  if (ctl.state === 'unverified') return { outcome: 'question', detail: 'sem prova: o kit só faz a pergunta' };
  if (ctl.state !== 'failed') return { outcome: 'missed', detail: `o controle ficou ${ctl.state}` };
  const hits = ctl.findings.filter((f) => {
    if (c.file) {
      const loc = f.location || '';
      if (loc !== c.file && !loc.startsWith(`${c.file}:`)) return false;
    }
    return !c.messageIncludes || String(f.message).includes(c.messageIncludes);
  });
  if (hits.length === 0) return { outcome: 'missed', detail: 'o controle falhou, mas não no ponto plantado' };
  return { outcome: 'detected', detail: `${hits[0].location || '-'}: ${hits[0].message}` };
}

/** Compara o resultado atual com o esperado: ok, improved ou regressed. */
function compare(c, outcome) {
  if (c.kind === 'clean') return outcome === 'clean' ? 'ok' : 'regressed';
  if (outcome === c.expect) return 'ok';
  return RANK[outcome] > RANK[c.expect] ? 'improved' : 'regressed';
}

const ratio = (n, d) => (d === 0 ? null : Math.round((n / d) * 1000) / 1000);

function summarize(results) {
  const planted = results.filter((r) => r.kind === 'planted');
  const clean = results.filter((r) => r.kind === 'clean');
  const count = (list, o) => list.filter((r) => r.outcome === o).length;
  const bucket = (list) => ({
    total: list.length,
    detected: count(list, 'detected'),
    question: count(list, 'question'),
    missed: count(list, 'missed'),
    recall: ratio(count(list, 'detected'), list.length),
  });
  const byCategory = {};
  for (const cat of CATEGORIES) {
    const sub = planted.filter((r) => r.category === cat);
    if (sub.length) byCategory[cat] = bucket(sub);
  }
  return {
    planted: { ...bucket(planted), coverage: ratio(count(planted, 'detected') + count(planted, 'question'), planted.length), byCategory },
    clean: { total: clean.length, clean: count(clean, 'clean'), falsePositives: count(clean, 'false-positive'), unmeasured: count(clean, 'unmeasured') },
    regressed: results.filter((r) => r.status === 'regressed').length,
    improved: results.filter((r) => r.status === 'improved').length,
  };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function waitListening(port, child) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let exited = false;
    child.once('exit', () => { exited = true; });
    const attempt = () => {
      if (exited) { reject(new Error('o servidor de teste terminou antes de abrir a porta')); return; }
      const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(); });
      s.on('error', () => {
        s.destroy();
        if (Date.now() - started > SERVER_START_TIMEOUT_MS) reject(new Error('o servidor de teste não abriu a porta a tempo'));
        else setTimeout(attempt, 50);
      });
    };
    attempt();
  });
}

function stopServer(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) { resolve(); return; }
    const timer = setTimeout(resolve, 2000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    child.kill();
  });
}

/** Sobe o servidor de teste da aplicação em 127.0.0.1, numa porta livre, com ambiente mínimo (sem herdar segredos). */
async function startServer(dir, script) {
  const port = await freePort();
  const env = { PORT: String(port) };
  for (const k of ['PATH', 'Path', 'SystemRoot', 'TEMP', 'TMP']) if (process.env[k]) env[k] = process.env[k];
  const child = spawn(process.execPath, [script], { cwd: dir, env, stdio: 'ignore', windowsHide: true });
  try {
    await waitListening(port, child);
  } catch (e) {
    await stopServer(child);
    throw e;
  }
  return { url: `http://127.0.0.1:${port}`, stop: () => stopServer(child) };
}

async function runApp(baseDir, app, now) {
  const dir = path.join(baseDir, app.dir);
  if (!app.server) return runCheck({ root: dir, now });
  const srv = await startServer(dir, app.server);
  try {
    return await runCheck({ root: dir, now, url: srv.url, active: true, auth: !!app.auth, env: app.env || {}, confirmNonProduction: true, delayMs: 50 });
  } finally {
    await srv.stop();
  }
}

/** Roda o banco inteiro (ou só os casos de `only`). Lança Error se o manifesto for inválido. */
async function runBench({ manifestFile = DEFAULT_MANIFEST, only = null } = {}) {
  const loaded = loadManifest(manifestFile);
  if (!loaded.ok) throw new Error(loaded.error);
  const manifest = loaded.value;
  const baseDir = path.dirname(path.resolve(manifestFile));
  const now = new Date(`${manifest.referenceDate}T12:00:00Z`);
  const wanted = only ? new Set(only) : null;
  if (wanted) {
    const unknown = [...wanted].filter((id) => !manifest.cases.some((c) => c.id === id));
    if (unknown.length) throw new Error(`caso(s) desconhecido(s): ${unknown.join(', ')}`);
  }
  const cases = manifest.cases.filter((c) => !wanted || wanted.has(c.id));
  const reports = new Map();
  for (const name of new Set(cases.map((c) => c.app))) reports.set(name, await runApp(baseDir, manifest.apps[name], now));

  const results = cases.map((c) => {
    const { outcome, detail } = evaluateCase(c, reports.get(c.app));
    return {
      id: c.id, app: c.app, kind: c.kind, category: c.category || null, control: c.control, title: c.title, cwe: c.cwe || null,
      expect: c.expect, outcome, status: compare(c, outcome), detail,
    };
  });
  const [first] = reports.values();
  return { catalogVersion: first ? first.catalogVersion : null, referenceDate: manifest.referenceDate, results, summary: summarize(results) };
}

const pct = (v) => (v === null ? 'n/d' : `${Math.round(v * 100)}%`);
const LABEL = { detected: 'detectada', question: 'pergunta', missed: 'perdida', clean: 'limpa', 'false-positive': 'FALSO POSITIVO', unmeasured: 'não medida' };
const EXPECT_LABEL = { ...LABEL, clean: 'limpa' };
const STATUS_LABEL = { ok: '', improved: ' (melhorou: atualize o esperado)', regressed: ' (PIOROU)' };

function formatBench(res) {
  const s = res.summary;
  const L = [];
  L.push(`Banco de falhas plantadas (catálogo ${res.catalogVersion}, data de referência ${res.referenceDate})`, '');
  L.push(`Falhas plantadas: ${s.planted.total}`);
  L.push(`  detectadas ...... ${s.planted.detected} (${pct(s.planted.recall)}), é o recall do kit`);
  L.push(`  viram pergunta .. ${s.planted.question} (controle manual sem prova: o kit pergunta, mas não acha)`);
  L.push(`  perdidas ........ ${s.planted.missed}`);
  for (const [cat, b] of Object.entries(s.planted.byCategory)) L.push(`  - ${cat}: ${b.detected} de ${b.total} detectadas (${pct(b.recall)}), ${b.question} pergunta(s), ${b.missed} perdida(s)`);
  L.push(`Aplicações limpas: ${s.clean.total} controle(s), ${s.clean.falsePositives} falso(s) positivo(s), ${s.clean.unmeasured} não medido(s)`);
  L.push(`Contra o esperado: ${s.regressed} piorou, ${s.improved} melhorou`, '');
  for (const r of res.results) {
    const tag = r.kind === 'clean' ? 'limpa' : `${r.category}`;
    L.push(`${r.id} ${r.control.padEnd(9)} ${LABEL[r.outcome].padEnd(14)} [${tag}] ${r.title}${STATUS_LABEL[r.status]}`);
    if (r.status !== 'ok' || r.outcome === 'false-positive' || r.outcome === 'unmeasured') L.push(`        esperado: ${EXPECT_LABEL[r.expect]}; ${r.detail}`);
  }
  return L.join('\n');
}

module.exports = { DEFAULT_MANIFEST, loadManifest, validateManifest, evaluateCase, compare, summarize, runBench, formatBench };
