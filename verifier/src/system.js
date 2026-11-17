'use strict';

// Descrição do sistema pelo usuário (.lastro/system.json): componentes, repositórios e fluxos. Serve quando a aplicação
// tem mais de um repositório (frontend, API, worker, infraestrutura) ou quando o desenho automático não basta.
// O que o usuário declara é combinado com o que o kit descobre lendo cada repositório: o declarado manda no desenho, e o
// que foi descoberto e não declarado aparece marcado, para revisão.
//
// O arquivo é entrada não confiável (pode vir de um repositório de terceiros). Por isso o kit só lê pastas fora do
// repositório analisado com --allow-external-repos, e nunca grava nelas.

const fs = require('node:fs');
const path = require('node:path');
const U = require('./util');

const FILE = '.lastro/system.json';
const ROLES = ['frontend', 'mobile', 'backend', 'gateway', 'worker', 'queue', 'database', 'storage', 'external', 'infra'];
const EXPOSURE = ['internet', 'interna', 'privada'];
const DATA_CLASSES = ['pessoal', 'menores', 'sensivel', 'credencial', 'financeiro'];
const PROTOCOLS = ['https', 'http', 'wss', 'tls', 'sql', 'amqp', 'grpc', 'file', 'outro'];
const SURFACE_IDS = ['web', 'auth', 'data', 'realtime', 'uploads', 'pipeline', 'agent'];
const ACTORS = ['user', 'dev'];
const CODE_ROLES = new Set(['frontend', 'mobile', 'backend', 'gateway', 'worker', 'infra']);
const MAX_COMPONENTS = 20;
const MAX_FLOWS = 60;
const MAX_REPOS = 8;
const ID_RE = /^[a-z][a-z0-9-]{0,23}$/;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const text = (v, min, max) => typeof v === 'string' && v.trim().length >= min && v.length <= max;

function validateSystem(s) {
  const errs = [];
  if (!isObj(s)) return ['system.json: deve ser objeto'];
  for (const k of Object.keys(s)) if (!['schemaVersion', 'name', 'components', 'flows', 'notes'].includes(k)) errs.push(`system: campo desconhecido "${k}"`);
  if (s.schemaVersion !== 1) errs.push('system.schemaVersion: use 1');
  if (!text(s.name, 2, 80)) errs.push('system.name: texto de 2 a 80 caracteres');
  if (s.notes !== undefined && !text(s.notes, 0, 600)) errs.push('system.notes: até 600 caracteres');
  const ids = new Set(ACTORS);
  if (!Array.isArray(s.components) || s.components.length === 0 || s.components.length > MAX_COMPONENTS) errs.push(`system.components: lista de 1 a ${MAX_COMPONENTS} itens`);
  else {
    const repos = new Set();
    s.components.forEach((c, i) => {
      const w = `system.components[${i}]`;
      if (!isObj(c)) { errs.push(`${w}: deve ser objeto`); return; }
      for (const k of Object.keys(c)) if (!['id', 'name', 'role', 'repo', 'exposure', 'dataClasses', 'note'].includes(k)) errs.push(`${w}: campo desconhecido "${k}"`);
      if (typeof c.id !== 'string' || !ID_RE.test(c.id)) errs.push(`${w}.id: minúsculas, números e hífen (até 24, começando por letra)`);
      else if (ids.has(c.id)) errs.push(`${w}.id: repetido ou reservado (${c.id}; "user" e "dev" são reservados)`);
      else ids.add(c.id);
      if (!text(c.name, 2, 60)) errs.push(`${w}.name: texto de 2 a 60 caracteres`);
      if (!ROLES.includes(c.role)) errs.push(`${w}.role: ${ROLES.join('|')}`);
      if (c.exposure !== undefined && !EXPOSURE.includes(c.exposure)) errs.push(`${w}.exposure: ${EXPOSURE.join('|')}`);
      if (c.repo !== undefined) {
        if (!text(c.repo, 1, 300) || /[\u0000-\u001f]/.test(c.repo)) errs.push(`${w}.repo: caminho de 1 a 300 caracteres`);
        else if (!CODE_ROLES.has(c.role)) errs.push(`${w}.repo: só componente com código (${[...CODE_ROLES].join(', ')}) tem repositório`);
        else repos.add(c.repo);
      }
      if (c.dataClasses !== undefined && (!Array.isArray(c.dataClasses) || !c.dataClasses.every((d) => DATA_CLASSES.includes(d)))) errs.push(`${w}.dataClasses: ${DATA_CLASSES.join('|')}`);
      if (c.note !== undefined && !text(c.note, 0, 200)) errs.push(`${w}.note: até 200 caracteres`);
    });
    if (repos.size > MAX_REPOS) errs.push(`system.components: no máximo ${MAX_REPOS} repositórios`);
  }
  if (s.flows !== undefined) {
    if (!Array.isArray(s.flows) || s.flows.length > MAX_FLOWS) errs.push(`system.flows: lista de até ${MAX_FLOWS} itens`);
    else {
      s.flows.forEach((f, i) => {
        const w = `system.flows[${i}]`;
        if (!isObj(f)) { errs.push(`${w}: deve ser objeto`); return; }
        for (const k of Object.keys(f)) if (!['from', 'to', 'label', 'protocol', 'surfaces', 'note'].includes(k)) errs.push(`${w}: campo desconhecido "${k}"`);
        for (const k of ['from', 'to']) if (typeof f[k] !== 'string' || !ids.has(f[k])) errs.push(`${w}.${k}: componente ou ator desconhecido (${String(f[k]).slice(0, 30)})`);
        if (!text(f.label, 2, 80)) errs.push(`${w}.label: texto de 2 a 80 caracteres`);
        if (f.protocol !== undefined && !PROTOCOLS.includes(f.protocol)) errs.push(`${w}.protocol: ${PROTOCOLS.join('|')}`);
        if (f.surfaces !== undefined && (!Array.isArray(f.surfaces) || f.surfaces.length === 0 || !f.surfaces.every((x) => SURFACE_IDS.includes(x)))) errs.push(`${w}.surfaces: ${SURFACE_IDS.join('|')}`);
        if (f.note !== undefined && !text(f.note, 0, 200)) errs.push(`${w}.note: até 200 caracteres`);
      });
    }
  }
  return errs;
}

function loadSystem(root) {
  if (!U.exists(root, FILE)) return null;
  const j = U.readJson(root, FILE);
  if (!j.ok) return { ok: false, error: j.error };
  const errs = validateSystem(j.value);
  if (errs.length) return { ok: false, error: errs.slice(0, 5).join('; ') };
  return { ok: true, value: j.value };
}

/**
 * Resolve os repositórios dos componentes. Repositório dentro do analisado é sempre permitido; fora dele só com
 * `allowExternal`. Devolve { repos: Map(caminho informado -> { dir, inside, status }) }.
 */
function resolveRepos(root, system, { allowExternal = false } = {}) {
  const rootAbs = path.resolve(root);
  const repos = new Map();
  for (const c of system.components) {
    if (!c.repo || repos.has(c.repo)) continue;
    const dir = path.resolve(rootAbs, c.repo);
    const rel = path.relative(rootAbs, dir);
    const inside = rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    let status = 'ok';
    if (!inside && !allowExternal) status = 'fora-do-repositorio';
    else {
      try {
        if (!fs.statSync(dir).isDirectory()) status = 'nao-e-pasta';
      } catch (e) {
        status = 'nao-encontrado';
      }
    }
    repos.set(c.repo, { dir, inside, same: rel === '', status });
  }
  return repos;
}

module.exports = { FILE, ROLES, EXPOSURE, DATA_CLASSES, PROTOCOLS, SURFACE_IDS, ACTORS, CODE_ROLES, validateSystem, loadSystem, resolveRepos };
