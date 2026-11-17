#!/usr/bin/env node
'use strict';

// CLI do LASTRO. Sem dependências externas.
// Códigos de saída: 0 aprovado | 1 falha (achado novo alto/crítico) | 2 incompleto | 3 erro de uso ou de configuração.

const fs = require('node:fs');
const path = require('node:path');
const { runCheck, ConfigError } = require('../src/engine');
const { loadCatalog, validateCatalog, DEFAULT_CATALOG_DIR } = require('../src/catalog');
const { registry } = require('../src/checks');
const { formatReport, formatMarkdown, redactReport, validateRedactTerms, threatMarkdown } = require('../src/report');
const TM = require('../src/threatmodel');
const BENCH = require('../src/bench');
const { analyzeGroup } = require('../src/group');
const { buildPlaybook, formatPlaybookMarkdown, formatPlaybookHtml } = require('../src/playbook');
const { formatGroupMarkdown, formatGroupHtml } = require('../src/group-report');
const { scopeNames, scopeControlIds, formatScope } = require('../src/scope');
const { installKiro, NAMES: ADAPTER_NAMES } = require('../src/adapter');
const { formatHtml, validateTheme } = require('../src/html');
const { loadProfile } = require('../src/engine');
const { loadTickets, planBacklog, writeTickets } = require('../src/backlog');
const { FLAGS } = require('../src/schema');
const { nowIso } = require('../src/util');

const asvsLib = require('../src/asvs');

const VALUE_FLAGS = new Set(['test-cmd', 'branch', 'commit-name', 'commit-email', 'pr-body', 'manifest', 'root', 'url', 'out', 'only', 'csv', 'level', 'delay', 'format', 'theme', 'redact', 'audit-file', 'name', 'repos', 'match', 'system', 'write-system', 'out-dir', 'scope']);

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
  lastro app --name "App X" [--root PASTA] [--repos a,b] [--match 'app-x-*'] [--out ARQ.html|.md]
                                             aplicação com vários repositórios: o kit identifica sozinho o papel de
                                             cada um (frontend, backend, worker, infraestrutura...), verifica cada
                                             repositório (só leitura) e gera um relatório único com a arquitetura e os
                                             riscos. --root é a pasta onde os repositórios estão.
                                             --write-system ARQ grava o rascunho de system.json para você corrigir;
                                             --system ARQ usa o corrigido. --out-dir DIR grava também um relatório
                                             por repositório. Aceita --theme, --redact e --allow-external-repos.
  lastro playbook [--scope auth] [--only ID,ID] [--all] [--out ARQ.md|.html]
                                             roteiro passo a passo para testar cada controle manual sem prova:
                                             o que preparar, passos, o que conferir, evidência, o que fazer se
                                             falhar e o trecho pronto para registrar a atestação. Aceita --theme
                                             e --redact.
  lastro fix [--root DIR] [--only CORE-006,CORE-010,CORE-011] [--write] [--allow-network] [--run-tests]
             [--test-cmd "npm test"] [--branch lastro/nome] [--commit --commit-name N --commit-email E] [--pr-body ARQ.md]
                                             correções determinísticas numa BRANCH nova, para um PR que uma pessoa revisa.
                                             Sem --write só mostra o plano. Corrige: Actions por tag (CORE-006, com
                                             --allow-network), workflow sem permissions (CORE-010) e SECURITY.md ausente
                                             (CORE-011, modelo a preencher). Nunca faz push, nunca abre PR e nunca
                                             mexe na branch atual. --run-tests executa o código do repositório (npm test);
                                             se falhar, tudo é desfeito. --pr-body grava a descrição do PR (fora do repo).
  lastro bench [--manifest ARQ.json] [--only P-001,D-004] [--json] [--out ARQ.json]
                                             mede o recall do kit contra o banco de falhas plantadas
                                             (fixtures/planted): quantas falhas ele pega, quantas viram pergunta e
                                             quantas perde, e os falsos positivos nas aplicações limpas. Sobe os
                                             servidores de teste só em 127.0.0.1. Sai com 1 se algo piorar.
  lastro scope <auth|web|pii|realtime|uploads|assets|agent|core>
                                             só os controles de um assunto, com estado e o que fazer em cada um
  lastro adapter kiro [--write]              copia os arquivos de steering do Kiro para .kiro/steering do projeto
                                             (nunca sobrescreve um arquivo existente)
  lastro threat-model [--write] [--out ARQ.md]
                                             rascunho de modelo de ameaças (STRIDE por superfície) a partir do
                                             perfil, do catálogo e da leitura do código. Só lê o repositório.
                                             --write grava .lastro/threat-model.json (decisões preservadas).
  lastro baseline [--write] [opções]         registra os achados atuais como dívida conhecida
  lastro backlog [--write] [opções]          gera tickets P0-P3 a partir das lacunas
  lastro report [--out ARQUIVO] [--format md|html] [--theme ARQUIVO.css]
                                             relatório legível: maturidade, achados, falta de prova e ASVS.
                                             Termina em .html? Gera HTML autocontido, sem scripts nem recursos
                                             externos. --theme aplica um CSS seu (só variáveis e estilos).
                                             --redact termo1,termo2 troca esses termos por [omitido] em todo o
                                             relatório, para compartilhá-lo sem nomes de empresa ou produto.
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
  --auth               liga as sondas autenticadas (cookie de sessão, acesso por objeto entre duas contas, CSRF, logout).
                       Exige --url, --confirm-non-production e o bloco authProbes no perfil. As contas de teste vêm de
                       variáveis de ambiente; o perfil só guarda os nomes delas. Recusada contra a URL de produção.
  --confirm-non-production   confirma que o alvo é staging ou homologação sob seu controle
  --audit-file ARQ     resultado de "npm audit --json" gerado por você (o kit não consulta a internet). Traz as
                       vulnerabilidades conhecidas das dependências (GHSA, CWE, CVSS) para a análise de risco.
  --allow-external-repos
                       permite ler, só leitura, os repositórios de .lastro/system.json que ficam FORA da pasta
                       analisada. Sem a opção, só repositórios dentro da pasta são lidos.
  --only ID,ID         limita a alguns controles
  --json               saída em JSON
  --out ARQUIVO        grava o relatório JSON
  --allow-incomplete   exit 0 quando o veredito for "incompleto"

Saída: 0 aprovado | 1 falha | 2 incompleto | 3 erro de uso ou configuração.`;

/** Opções de segurança das verificações HTTP, repassadas ao motor. */
function httpOptions(flags) {
  const opts = { url: flags.url, active: !!flags.active, auth: !!flags.auth, confirmNonProduction: !!flags['confirm-non-production'] };
  if (flags.delay !== undefined) opts.delayMs = Number(flags.delay);
  if (flags['audit-file'] && flags['audit-file'] !== true) opts.auditFile = flags['audit-file'];
  if (flags['allow-external-repos']) opts.allowExternalRepos = true;
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
  if (flags.auth) lines.push('- SONDAS AUTENTICADAS LIGADAS: entram com duas contas de TESTE (variáveis de ambiente nomeadas em authProbes), fazem login, logout e requisições de escrita nas rotas declaradas no perfil. Use só em staging ou local, com contas descartáveis.');
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

  if (cmd === 'report') {
    // Formato e tema são validados antes de qualquer requisição à aplicação.
    const outFile = flags.out && flags.out !== true ? flags.out : null;
    const format = flags.format && flags.format !== true ? String(flags.format) : (outFile && /\.html?$/i.test(outFile) ? 'html' : 'md');
    if (!['md', 'html'].includes(format)) {
      console.error('--format deve ser md ou html.');
      return 3;
    }
    let theme = null;
    if (flags.theme) {
      if (format !== 'html') {
        console.error('--theme só vale com --format html (ou com --out terminando em .html).');
        return 3;
      }
      let css;
      try {
        css = fs.readFileSync(path.resolve(String(flags.theme)), 'utf8');
      } catch (e) {
        console.error(`Não foi possível ler o tema: ${e.message}`);
        return 3;
      }
      const themeErrors = validateTheme(css);
      if (themeErrors.length) {
        console.error(`Tema recusado:\n- ${themeErrors.join('\n- ')}`);
        return 3;
      }
      theme = css;
    }
    let redact = null;
    if ('redact' in flags) {
      redact = typeof flags.redact === 'string' ? flags.redact.split(',').map((t) => t.trim()).filter(Boolean) : [];
      const redactErrors = validateRedactTerms(redact);
      if (redactErrors.length) {
        console.error(`--redact recusado:\n- ${redactErrors.join('\n- ')}`);
        return 3;
      }
    }
    printHttpNotice(root, flags);
    const rawReport = await runCheck({ root, ...httpOptions(flags) });
    const report = redact ? redactReport(rawReport, redact) : rawReport;
    const cat = loadCatalog();
    const states = new Map(report.controls.map((c) => [c.id, c.state]));
    const coverage = asvsLib.coverage(cat.controls, cat.asvsMap, { level: 2, states });
    const text = format === 'html' ? formatHtml(report, { coverage, theme }) : `${formatMarkdown(report, { coverage })}\n`;
    if (flags.out && flags.out !== true) {
      const file = path.resolve(flags.out);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, text);
      console.log(`Relatório gravado em ${file}`);
    } else {
      console.log(text);
    }
    return 0;
  }

  if (cmd === 'app') {
    const name = flags.name && flags.name !== true ? String(flags.name) : null;
    if (!name) {
      console.error('Informe o nome da aplicação: lastro app --name "App X" [--root PASTA_DOS_REPOSITORIOS]');
      return 3;
    }
    const outFile = flags.out && flags.out !== true ? path.resolve(String(flags.out)) : null;
    const format = outFile && /\.html?$/i.test(outFile) ? 'html' : 'md';
    let theme = null;
    if (flags.theme) {
      if (format !== 'html' && !flags['out-dir']) { console.error('--theme só vale com saída em HTML.'); return 3; }
      try { theme = fs.readFileSync(path.resolve(String(flags.theme)), 'utf8'); } catch (e) { console.error(`Não foi possível ler o tema: ${e.message}`); return 3; }
      const te = validateTheme(theme);
      if (te.length) { console.error(`Tema recusado:\n- ${te.join('\n- ')}`); return 3; }
    }
    let redact = null;
    if ('redact' in flags) {
      redact = typeof flags.redact === 'string' ? flags.redact.split(',').map((t) => t.trim()).filter(Boolean) : [];
      const re = validateRedactTerms(redact);
      if (re.length) { console.error(`--redact recusado:\n- ${re.join('\n- ')}`); return 3; }
    }
    let system = null;
    if (flags.system && flags.system !== true) {
      try { system = JSON.parse(require('../src/util').stripBom(fs.readFileSync(path.resolve(String(flags.system)), 'utf8'))); } catch (e) { console.error(`system ilegível: ${e.message}`); return 3; }
    }
    const repos = flags.repos && flags.repos !== true ? String(flags.repos).split(',').map((s) => s.trim()).filter(Boolean) : null;
    const { group, reports } = await analyzeGroup({ dir: root, name, repos, match: flags.match && flags.match !== true ? String(flags.match) : null, system, allowExternal: !!flags['allow-external-repos'] });

    console.log(`Aplicação "${name}": ${group.totals.analyzed} repositório(s) analisado(s) em ${root}`);
    for (const r of group.repos) {
      console.log(`  ${r.name}: ${r.role}${r.fullstack ? ' (full stack)' : ''}, confiança ${r.confidence} | perfil ${r.profile} | ${r.error ? `ERRO ${r.error}` : `portão ${r.verdict}, risco confirmado ${r.confirmed.critical} crítico, ${r.confirmed.high} alto, ${r.confirmed.medium} médio`}`);
    }
    console.log(`Risco confirmado na aplicação: ${group.totals.confirmed.critical} crítico, ${group.totals.confirmed.high} alto, ${group.totals.confirmed.medium} médio, ${group.totals.confirmed.low} baixo | ameaças expostas: ${group.totals.threatsExposed} de ${group.totals.threats}`);
    for (const w of group.warnings.slice(0, 8)) console.log(`AVISO: ${w}`);
    if (group.warnings.length > 8) console.log(`... e mais ${group.warnings.length - 8} aviso(s) no relatório.`);

    if (flags['write-system'] && flags['write-system'] !== true) {
      const file = path.resolve(String(flags['write-system']));
      if (fs.existsSync(file)) { console.error(`${file} já existe: não sobrescrevo.`); return 3; }
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, `${JSON.stringify(group.system, null, 2)}\n`);
      console.log(`Rascunho do system.json gravado em ${file}. Corrija os papéis e as ligações e rode de novo com --system.`);
    }
    const shown = redact ? redactReport(group, redact) : group;
    if (outFile) {
      fs.mkdirSync(path.dirname(outFile), { recursive: true });
      fs.writeFileSync(outFile, format === 'html' ? formatGroupHtml(shown, { theme }) : formatGroupMarkdown(shown));
      console.log(`Relatório da aplicação gravado em ${outFile}`);
    } else if (!flags['out-dir']) {
      console.log('Use --out relatorio.html (ou .md) para gravar o relatório da aplicação.');
    }
    if (flags['out-dir'] && flags['out-dir'] !== true) {
      const dir = path.resolve(String(flags['out-dir']));
      fs.mkdirSync(dir, { recursive: true });
      for (const { name: repo, report } of reports) {
        const rep = redact ? redactReport(report, redact) : report;
        const states = new Map(rep.controls.map((c) => [c.id, c.state]));
        const cov = asvsLib.coverage(loadCatalog().controls, loadCatalog().asvsMap, { level: 2, states });
        const base = String(repo).replace(/[^A-Za-z0-9._-]+/g, '_');
        fs.writeFileSync(path.join(dir, `${base}.html`), formatHtml(rep, { coverage: cov, theme }));
      }
      console.log(`Relatórios por repositório gravados em ${dir}`);
    }
    return 0;
  }

  if (cmd === 'playbook') {
    const cat = loadCatalog();
    const scope = flags.scope && flags.scope !== true ? String(flags.scope) : null;
    if (scope && !scopeNames(cat).includes(scope)) { console.error(`Escopo desconhecido: ${scope}. Use ${scopeNames(cat).join('|')}.`); return 3; }
    const only = flags.only && flags.only !== true ? String(flags.only).split(',').map((s) => s.trim()).filter(Boolean) : null;
    const outFile = flags.out && flags.out !== true ? path.resolve(String(flags.out)) : null;
    const isHtml = outFile && /\.html?$/i.test(outFile);
    let theme = null;
    if (flags.theme) {
      if (!isHtml) { console.error('--theme só vale com --out terminando em .html.'); return 3; }
      try { theme = fs.readFileSync(path.resolve(String(flags.theme)), 'utf8'); } catch (e) { console.error(`Não foi possível ler o tema: ${e.message}`); return 3; }
      const te = validateTheme(theme);
      if (te.length) { console.error(`Tema recusado:\n- ${te.join('\n- ')}`); return 3; }
    }
    let redact = null;
    if ('redact' in flags) {
      redact = typeof flags.redact === 'string' ? flags.redact.split(',').map((t) => t.trim()).filter(Boolean) : [];
      const re = validateRedactTerms(redact);
      if (re.length) { console.error(`--redact recusado:\n- ${re.join('\n- ')}`); return 3; }
    }
    const raw = await runCheck({ root });
    const report = redact ? redactReport(raw, redact) : raw;
    const pb = buildPlaybook(report, cat, { only, scope, all: !!flags.all });
    console.log(`Playbook de "${report.profile.name}": ${pb.total} controle(s) manual(is) a testar (${pb.byKind.security || 0} de segurança, ${pb.byKind.practice || 0} de boa prática, ${pb.byKind.quality || 0} de qualidade).`);
    const text = isHtml ? formatPlaybookHtml(pb, { theme }) : formatPlaybookMarkdown(pb);
    if (outFile) {
      fs.mkdirSync(path.dirname(outFile), { recursive: true });
      fs.writeFileSync(outFile, text);
      console.log(`Playbook gravado em ${outFile}`);
    } else console.log(text);
    return 0;
  }

  if (cmd === 'fix') {
    const { runFix, FixError } = require('../src/fix');
    const { FIXABLE } = require('../src/fix/plan');
    const { formatResult, formatPrBody } = require('../src/fix/format');
    const { makeGitResolver } = require('../src/fix/resolve');
    const str = (k) => (flags[k] && flags[k] !== true ? String(flags[k]) : null);
    const only = str('only') ? str('only').split(',').map((s) => s.trim()).filter(Boolean) : null;
    const unknown = (only || []).filter((id) => !FIXABLE.includes(id));
    if (unknown.length) { console.error(`Sem correção automática para: ${unknown.join(', ')}. Corrigíveis: ${FIXABLE.join(', ')}.`); return 3; }
    if ((flags['run-tests'] || str('test-cmd')) && !flags.write) { console.error('--run-tests e --test-cmd só valem com --write.'); return 3; }
    if (str('test-cmd') && !flags['run-tests']) { console.error('--test-cmd exige --run-tests.'); return 3; }
    let commit = null;
    if (flags.commit) {
      if (!flags.write) { console.error('--commit só vale com --write.'); return 3; }
      if (!str('commit-name') || !/^[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+$/.test(str('commit-email') || '')) { console.error('--commit exige --commit-name e --commit-email válidos (o git do repositório não é alterado).'); return 3; }
      commit = { name: str('commit-name'), email: str('commit-email') };
    }
    let prFile = null;
    if (str('pr-body')) {
      prFile = path.resolve(str('pr-body'));
      const rel = path.relative(root, prFile);
      if (!rel.startsWith('..') && !path.isAbsolute(rel)) { console.error('--pr-body deve apontar para fora do repositório: a descrição do PR não deve ir para dentro dele.'); return 3; }
    }
    if (flags['allow-network']) console.error('AVISO: --allow-network consulta o github.com (git ls-remote, repositórios públicos) para achar o SHA de cada tag de Action.');
    if (flags['run-tests']) console.error('AVISO: --run-tests EXECUTA o código deste repositório (o script de teste dele). Use só em repositório em que você confia.');
    let res;
    try {
      res = await runFix({ root, write: !!flags.write, only, allowNetwork: !!flags['allow-network'], resolve: flags['allow-network'] ? makeGitResolver() : null, runTests: !!flags['run-tests'], testCmd: str('test-cmd'), branch: str('branch'), commit });
    } catch (e) {
      if (e instanceof FixError || e instanceof ConfigError) { console.error(e.message); return 3; }
      throw e;
    }
    console.log(formatResult(res));
    if (prFile) {
      fs.mkdirSync(path.dirname(prFile), { recursive: true });
      fs.writeFileSync(prFile, formatPrBody(res));
      console.log(`Descrição do PR gravada em ${prFile}. Abrir o PR é uma decisão sua: o LASTRO não faz push nem abre PR.`);
    }
    return res.rolledBack ? 1 : 0;
  }

  if (cmd === 'bench') {
    // Só roda código do próprio kit (fixtures/planted ou um manifesto que você aponta). Nada vai à rede além de 127.0.0.1.
    const only = flags.only && flags.only !== true ? String(flags.only).split(',').map((s) => s.trim()).filter(Boolean) : null;
    const manifestFile = flags.manifest && flags.manifest !== true ? path.resolve(String(flags.manifest)) : BENCH.DEFAULT_MANIFEST;
    let res;
    try {
      res = await BENCH.runBench({ manifestFile, only });
    } catch (e) {
      console.error(`bench: ${e.message}`);
      return 3;
    }
    if (flags.out && flags.out !== true) {
      const file = path.resolve(String(flags.out));
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, `${JSON.stringify(res, null, 2)}\n`);
    }
    console.log(flags.json ? JSON.stringify(res, null, 2) : BENCH.formatBench(res));
    return res.summary.regressed > 0 ? 1 : 0;
  }

  if (cmd === 'scope') {
    const cat = loadCatalog();
    const names = scopeNames(cat);
    const name = pos[1];
    if (!name || !names.includes(name)) {
      console.error(`Informe o escopo: lastro scope <${names.join('|')}>`);
      return 3;
    }
    const profile = loadProfile(root);
    const report = await runCheck({ root, only: scopeControlIds(cat, name) });
    console.log(formatScope(report, cat, name, profile.flags));
    return 0;
  }

  if (cmd === 'adapter') {
    if (pos[1] !== 'kiro') {
      console.error(`Informe o adaptador: lastro adapter <${ADAPTER_NAMES.join('|')}> [--write]`);
      return 3;
    }
    const r = installKiro(root, { write: !!flags.write });
    for (const n of r.created) console.log(`${flags.write ? 'criado' : 'seria criado'}: ${path.join(r.target, n)}`);
    for (const n of r.skipped) console.log(`já existe, mantido: ${path.join(r.target, n)}`);
    if (!flags.write && r.created.length) console.log('Rode com --write para criar os arquivos. Nenhum arquivo existente é sobrescrito.');
    return 0;
  }

  if (cmd === 'threat-model') {
    // Só leitura do repositório: nada é executado nem acessado pela rede. Grava apenas com --write.
    const raw = TM.loadFile(root);
    let persisted = null;
    if (raw) {
      if (!raw.ok) { console.error(`${TM.FILE} ilegível (${raw.error}). Corrija ou remova antes de continuar.`); return 3; }
      const errs = TM.validateModel(raw.value);
      if (errs.length) { console.error(`${TM.FILE} inválido:\n- ${errs.slice(0, 10).join('\n- ')}`); return 3; }
      persisted = raw.value;
    }
    const report = await runCheck({ root, allowExternalRepos: !!flags['allow-external-repos'] });
    const t = report.threatModel;
    console.log(`Modelo de ameaças de "${report.profile.name}": ${t.counts.threats} ameaça(s) (${t.counts.exposed} exposta(s), ${t.counts.unproven} sem prova, ${t.counts.mitigated} mitigada(s)), ${t.counts.pending} sem decisão.`);
    console.log(`Descoberta: ${t.discovery.routes.total} rota(s), ${t.discovery.routes.byAuth['nao-vista']} sem autenticação vista; armazenamento: ${t.discovery.stores.join(', ') || 'nenhum encontrado'}; tempo real: ${t.discovery.realtime.join(', ') || 'não'}; uploads: ${t.discovery.uploads.join(', ') || 'não'}.`);
    for (const h of t.discovery.dataHints.filter((x) => x.sensitive)) console.log(`ATENÇÃO: indício de ${h.name} em ${h.files.slice(0, 2).join(', ')}. Confirme e, se for o caso, declare context.sensitiveData no perfil.`);
    if (flags.out && flags.out !== true) {
      const file = path.resolve(flags.out);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, `${threatMarkdown(report).join('\n')}\n`);
      console.log(`Modelo de ameaças em Markdown gravado em ${file}`);
    }
    if (!flags.write) {
      console.log(t.persisted ? `Modelo em ${TM.FILE}. Rode com --write para acrescentar ameaças novas (as decisões são preservadas).` : `Rascunho não gravado. Rode com --write para criar ${TM.FILE}; depois decida cada ameaça (mitigate, accept ou not_applicable) e registre reviewedBy e reviewedAt.`);
      return 0;
    }
    const content = TM.serialize(t, persisted, new Date());
    const bad = TM.validateModel(content);
    if (bad.length) { console.error(`Erro interno ao montar o modelo:\n- ${bad.slice(0, 5).join('\n- ')}`); return 3; }
    TM.writeModel(root, content);
    console.log(`Gravado ${TM.FILE} com ${content.threats.length} ameaça(s). As decisões já existentes foram preservadas.`);
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
