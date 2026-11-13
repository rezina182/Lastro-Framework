#!/usr/bin/env node
'use strict';

// CLI do LASTRO. Sem dependências externas.
// Códigos de saída: 0 aprovado | 1 falha (achado novo alto/crítico) | 2 incompleto | 3 erro de uso ou de configuração.

const fs = require('node:fs');
const path = require('node:path');
const { runCheck, ConfigError } = require('../src/engine');
const { loadCatalog, validateCatalog, DEFAULT_CATALOG_DIR } = require('../src/catalog');
const { registry } = require('../src/checks');
const { formatReport } = require('../src/report');
const { loadProfile } = require('../src/engine');
const { loadTickets, planBacklog, writeTickets } = require('../src/backlog');
const { FLAGS } = require('../src/schema');
const { nowIso } = require('../src/util');

const asvsLib = require('../src/asvs');

const VALUE_FLAGS = new Set(['root', 'url', 'out', 'only', 'csv', 'level', 'delay']);

function parseArgs(argv) {
  const pos = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const k = eq >= 0 ? a.slice(2, eq) : a.slice(2);
      if (VALUE_FLAGS.has(k)) flags[k] = eq >= 0 ? a.slice(eq + 1) : argv[++i];
      else flags[k] = true;
    } else pos.push(a);
  }
  return { pos, flags };
}

const HELP = `LASTRO - SDLC seguro para desenvolvimento assistido por IA

Uso:
  lastro init [--root DIR] [--force]         cria .lastro/profile.json para você preencher
  lastro catalog validate                    valida o catálogo de controles do kit
  lastro check [opções]                      verifica o projeto e dá o veredito
  lastro baseline [--write] [opções]         registra os achados atuais como dívida conhecida
  lastro backlog [--write] [opções]          gera tickets P0-P3 a partir das lacunas
  lastro asvs [--level 1|2|3] [--state]      cobertura do ASVS 5.0 por capítulo (--state mostra o estado no projeto)
  lastro asvs verify --csv ARQUIVO           confere o mapa do kit contra o CSV oficial do ASVS
  lastro asvs sync --csv ARQUIVO [--write]   regenera catalog/asvs-map.json a partir do CSV oficial

Opções de check, baseline e backlog:
  --root DIR           pasta do projeto (padrão: a pasta atual)
  --url URL            também verifica a aplicação em execução (somente GET, ritmo controlado, teto de 120 requisições).
                       Prefira staging ou homologação.
  --delay MS           intervalo mínimo entre requisições à aplicação (padrão 150, mínimo 50)
  --active             liga sondas ativas (TRACE, OPTIONS com Origin falsa, JSON malformado).
                       Exige --url e --confirm-non-production, e é recusada contra a URL de produção do perfil.
  --confirm-non-production   confirma que o alvo é staging ou homologação sob seu controle
  --only ID,ID         limita a alguns controles
  --json               saída em JSON
  --out ARQUIVO        grava o relatório JSON
  --allow-incomplete   exit 0 quando o veredito for "incompleto"

Saída: 0 aprovado | 1 falha | 2 incompleto | 3 erro de uso ou configuração.`;

/** Opções de segurança das verificações HTTP, repassadas ao motor. */
function httpOptions(flags) {
  const opts = { url: flags.url, active: !!flags.active, confirmNonProduction: !!flags['confirm-non-production'] };
  if (flags.delay !== undefined) opts.delayMs = Number(flags.delay);
  return opts;
}

/** Aviso antes de qualquer requisição à aplicação. Vai para stderr para não sujar a saída em JSON. */
function printHttpNotice(root, flags) {
  if (!flags.url || flags.url === true) return;
  let origin = String(flags.url);
  try { origin = new URL(flags.url).origin; } catch (e) { /* o motor recusa URL inválida */ }
  let prod = null;
  try { prod = (loadProfile(root).urls || {}).production || null; } catch (e) { /* o motor reporta o perfil inválido */ }
  const lines = [`AVISO: verificação HTTP em ${origin}`];
  if (prod && new URL(prod).origin === origin) {
    lines.push('- O alvo é a URL de PRODUÇÃO do perfil. Só rodam sondas passivas (GET); as ativas são recusadas. Prefira o staging.');
  } else {
    lines.push('- Prefira o ambiente de staging ou de homologação. Evite apontar para produção sem necessidade.');
  }
  lines.push('- Modo passivo: requisições GET (cerca de 30), 1 a cada 150 ms por padrão, com teto de 120 no total.');
  if (flags.active) lines.push('- SONDAS ATIVAS LIGADAS (TRACE, OPTIONS com Origin falsa, JSON malformado). Use só em staging que você controla.');
  console.error(lines.join('\n'));
}

function profileTemplate(name) {
  const flags = {};
  for (const f of FLAGS) flags[f] = false;
  flags.aiCodingAgents = true;
  return { schemaVersion: 1, name, flags, paths: { health: '/health' } };
}

async function main(argv) {
  const { pos, flags } = parseArgs(argv);
  const cmd = pos[0];
  const root = path.resolve(flags.root || process.cwd());

  if (!cmd || cmd === 'help' || flags.help) {
    console.log(HELP);
    return 0;
  }

  if (cmd === 'catalog' && pos[1] === 'validate') {
    const cat = loadCatalog();
    const errors = validateCatalog(cat, new Set(registry.keys()));
    if (errors.length) {
      console.error(`Catálogo inválido (${errors.length} erro(s)):\n- ${errors.join('\n- ')}`);
      return 3;
    }
    console.log(`Catálogo ${cat.version} válido: ${cat.controls.length} controles, ${cat.lessons.length} lições, ${registry.size} verificações automáticas.`);
    return 0;
  }

  if (cmd === 'asvs') {
    const sub = pos[1];
    if (sub === 'sync' || sub === 'verify') {
      if (!flags.csv || flags.csv === true) {
        console.error(`Informe --csv ARQUIVO (CSV oficial do ASVS ${asvsLib.ASVS_VERSION}). O CSV não é versionado neste repositório.`);
        return 3;
      }
      let reqs;
      try {
        reqs = asvsLib.requirementsFromCsv(fs.readFileSync(path.resolve(flags.csv), 'utf8'));
      } catch (e) {
        console.error(`CSV inválido: ${e.message}`);
        return 3;
      }
      const loaded = asvsLib.loadAsvsMap(DEFAULT_CATALOG_DIR);
      if (sub === 'verify') {
        if (!loaded.ok) { console.error(loaded.error); return 3; }
        const errs = asvsLib.verifyMap(loaded.value, reqs);
        if (errs.length) {
          console.error(`Mapa diverge do CSV oficial (${errs.length}):\n- ${errs.slice(0, 30).join('\n- ')}`);
          return 3;
        }
        console.log(`Mapa confere com o CSV oficial: ${Object.keys(reqs).length} requisitos, níveis iguais.`);
        return 0;
      }
      const next = asvsLib.buildMap(reqs, loaded.ok ? loaded.value : null);
      const text = `${JSON.stringify(next, null, 2)}\n`;
      if (!flags.write) {
        console.log(`Mapa gerado com ${Object.keys(next.requirements).length} requisitos. Rode com --write para gravar catalog/asvs-map.json.`);
        return 0;
      }
      fs.writeFileSync(loaded.file, text);
      console.log(`Gravado ${loaded.file} (${Object.keys(next.requirements).length} requisitos).`);
      return 0;
    }
    if (sub !== undefined) {
      console.error(`Subcomando desconhecido: asvs ${sub}`);
      return 3;
    }
    const level = flags.level === undefined ? 2 : Number(flags.level);
    if (![1, 2, 3].includes(level)) {
      console.error('--level deve ser 1, 2 ou 3.');
      return 3;
    }
    const cat = loadCatalog();
    const errors = validateCatalog(cat, new Set(registry.keys()));
    if (errors.length) {
      console.error(`Catálogo inválido:\n- ${errors.slice(0, 15).join('\n- ')}`);
      return 3;
    }
    let states = null;
    if (flags.state) {
      printHttpNotice(root, flags);
      const rep = await runCheck({ root, ...httpOptions(flags) });
      states = new Map(rep.controls.map((c) => [c.id, c.state]));
    }
    const cov = asvsLib.coverage(cat.controls, cat.asvsMap, { level, states });
    if (flags.out) fs.writeFileSync(path.resolve(flags.out), `${JSON.stringify(cov, null, 2)}\n`);
    console.log(flags.json ? JSON.stringify(cov, null, 2) : asvsLib.formatCoverage(cov));
    return 0;
  }

  if (cmd === 'init') {
    const dir = path.join(root, '.lastro');
    const file = path.join(dir, 'profile.json');
    if (fs.existsSync(file) && !flags.force) {
      console.error('.lastro/profile.json já existe (use --force para sobrescrever).');
      return 3;
    }
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, `${JSON.stringify(profileTemplate(path.basename(root)), null, 2)}\n`);
    console.log('Criado .lastro/profile.json. Edite os "flags" para descrever a aplicação (ex.: webApp, hasAuth, uploads).');
    console.log('Controles só se aplicam quando o perfil os ativa; um perfil honesto é a base de tudo.');
    return 0;
  }

  if (['check', 'baseline', 'backlog'].includes(cmd)) {
    const only = flags.only ? String(flags.only).split(',').map((s) => s.trim()).filter(Boolean) : null;
    printHttpNotice(root, flags);
    const report = await runCheck({ root, ...httpOptions(flags), only });

    if (cmd === 'check') {
      if (flags.out) fs.writeFileSync(path.resolve(flags.out), `${JSON.stringify(report, null, 2)}\n`);
      console.log(flags.json ? JSON.stringify(report, null, 2) : formatReport(report));
      if (report.verdict === 'fail') return 1;
      if (report.verdict === 'incomplete') return flags['allow-incomplete'] ? 0 : 2;
      return 0;
    }

    if (cmd === 'baseline') {
      const fps = [...new Set(report.controls.filter((c) => c.state === 'failed').flatMap((c) => c.findings.filter((f) => !f.accepted).map((f) => f.fingerprint)))];
      if (!flags.write) {
        console.log(`${fps.length} achado(s) entrariam no baseline. Rode com --write para gravar .lastro/baseline.json.`);
        console.log('O baseline registra dívida conhecida: o portão passa a bloquear só achados NOVOS. Revise antes de gravar.');
        return 0;
      }
      const dir = path.join(root, '.lastro');
      fs.mkdirSync(dir, { recursive: true });
      const body = { schemaVersion: 1, generatedAt: nowIso(), fingerprints: fps.sort(), note: 'Dívida conhecida. Cada item deve virar ticket em .lastro/backlog ou risco aceito com validade.' };
      fs.writeFileSync(path.join(dir, 'baseline.json'), `${JSON.stringify(body, null, 2)}\n`);
      console.log(`Baseline gravado com ${fps.length} achado(s).`);
      return 0;
    }

    // backlog
    const profile = loadProfile(root);
    const { tickets, errors } = loadTickets(root);
    if (errors.length) {
      console.error(`Tickets inválidos em .lastro/backlog:\n- ${errors.join('\n- ')}`);
      return 3;
    }
    const planned = planBacklog(report, profile, tickets);
    if (planned.length === 0) {
      console.log('Nenhuma lacuna nova: todo controle falho ou não verificado já tem ticket aberto, ou não há lacunas.');
      return 0;
    }
    for (const t of planned) console.log(`${t.id} ${t.priority} [${t.control}] ${t.type === 'fix' ? 'corrigir' : 'verificar'}: ${t.title.replace(/^[^:]+: /, '')}`);
    if (!flags.write) {
      console.log(`\n${planned.length} ticket(s) planejado(s). Rode com --write para criar os arquivos em .lastro/backlog.`);
      return 0;
    }
    writeTickets(root, planned);
    console.log(`\n${planned.length} ticket(s) criado(s) em .lastro/backlog.`);
    return 0;
  }

  console.error(`Comando desconhecido: ${cmd}\n`);
  console.error(HELP);
  return 3;
}

main(process.argv.slice(2))
  .then((code) => { process.exitCode = code; })
  .catch((e) => {
    if (e instanceof ConfigError) console.error(`Erro de configuração: ${e.message}`);
    else console.error(`Erro inesperado: ${e && e.message ? e.message : e}`);
    process.exitCode = 3;
  });
