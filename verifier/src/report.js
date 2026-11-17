'use strict';

// Relatório legível em texto puro (sem cores, para funcionar igual em terminal, CI e arquivo).

const VERDICT = { pass: 'APROVADO', fail: 'FALHA', incomplete: 'INCOMPLETO' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function formatReport(r) {
  const s = r.summary;
  const out = [];
  out.push(`LASTRO ${r.tool.version} | catálogo ${r.catalogVersion} | perfil "${r.profile.name}" | veredito: ${VERDICT[r.verdict]}`);
  out.push(`Controles aplicáveis: ${s.applicable} | verificados: ${s.verified} | com falha: ${s.failed} | não verificados: ${s.unverified} | não se aplicam: ${s.notApplicable}`);
  out.push(`Achados bloqueantes (novos, alta/crítica): ${s.blocking} | dívida em baseline: ${s.debt} | riscos aceitos: ${s.accepted}`);
  if (r.score) {
    const k = r.score;
    out.push(`Maturidade: nível ${k.level} (${k.levelName}) | provado ${k.provenPct}% (máquina ${k.machinePct}%, autodeclarado ${k.attestedPct}%) | falhando ${k.failedPct}% | sem prova ${k.unverifiedPct}%`);
    if (k.automated && k.automated.controls) out.push(`  Automáticos: ${k.automated.verified} passaram, ${k.automated.failed} falharam${k.automated.passRatePct === null ? '' : ` (taxa ${k.automated.passRatePct}%)`}, ${k.automated.notRun} não rodaram`);
    out.push(`  ${k.nextStep}`);
    out.push(`  ${k.disclaimer}`);
  }
  if (r.context && r.score) {
    const c = r.context;
    out.push(`Contexto: risco ${c.risk} (${c.points} pontos) | meta de maturidade: nível ${c.targetLevel} | hoje: nível ${r.score.level}${c.meetsTarget ? ' (meta atingida)' : ` (faltam ${c.gap})`}`);
  }
  if (r.risk) {
    const c = r.risk.summary.confirmed;
    const p = r.risk.summary.potential;
    out.push(`Risco de segurança confirmado: ${c.critical} crítico(s), ${c.high} alto(s), ${c.medium} médio(s), ${c.low} baixo(s) | potencial (sem prova): ${p.critical} crítico(s), ${p.high} alto(s) | boas práticas abertas: ${r.risk.summary.practicesOpen} | qualidade aberta: ${r.risk.summary.qualityOpen}`);
  }
  if (r.threatModel) {
    const tc = r.threatModel.counts;
    out.push(`Modelo de ameaças: ${r.threatModel.reviewed ? 'revisado' : r.threatModel.persisted ? 'gravado, incompleto' : 'rascunho'} | ${tc.threats} ameaça(s): ${tc.exposed} exposta(s), ${tc.unproven} sem prova, ${tc.mitigated} mitigada(s) | ${tc.pending} sem decisão`);
  }
  if (r.baselineView) out.push(`Portão: ${r.baselineView.findings} achado(s) bloqueante(s) em ${r.baselineView.causes} causa(s). Registrada como baseline, essa dívida deixaria o portão ${r.baselineView.verdictIfAdopted === 'pass' ? 'aprovado' : 'incompleto'}: só achado novo bloquearia.`);
  if (r.target.url) out.push(`Alvo HTTP: ${r.target.url}${r.target.active ? ' (sondas ativas ligadas)' : ' (somente sondas passivas)'} | ${r.target.requestsSent} requisições, intervalo mínimo de ${r.target.delayMs} ms`);

  const blocking = r.controls.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => ({ c, f })));
  if (blocking.length) {
    out.push('', 'BLOQUEIAM A PUBLICAÇÃO:');
    for (const { c, f } of blocking.sort((a, b) => SEV_ORDER[a.f.severity] - SEV_ORDER[b.f.severity])) {
      out.push(`  [${c.id}] ${f.severity.toUpperCase()} ${f.message}${f.location ? ` (${f.location})` : ''}  #${f.fingerprint}`);
    }
  }

  const others = r.controls.flatMap((c) => c.findings.filter((f) => !f.blocking).map((f) => ({ c, f })));
  if (others.length) {
    out.push('', 'OUTROS ACHADOS (não bloqueiam):');
    for (const { c, f } of others.sort((a, b) => SEV_ORDER[a.f.severity] - SEV_ORDER[b.f.severity]).slice(0, 40)) {
      const tag = f.accepted ? 'aceito' : f.inBaseline ? 'baseline' : f.severity;
      out.push(`  [${c.id}] ${tag}: ${f.message}${f.location ? ` (${f.location})` : ''}  #${f.fingerprint}`);
    }
    if (others.length > 40) out.push(`  ... e mais ${others.length - 40}.`);
  }

  const unverified = r.controls.filter((c) => c.state === 'unverified');
  if (unverified.length) {
    out.push('', 'NÃO VERIFICADOS (sem prova, não contam como aprovados):');
    for (const c of unverified.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])) {
      out.push(`  [${c.id}] ${c.severity}: ${c.title}${c.notes[0] ? ` - ${c.notes[0]}` : ''}`);
    }
  }
  if (r.warnings.length) {
    out.push('', 'AVISOS:');
    for (const w of r.warnings) out.push(`  ${w}`);
  }
  return out.join('\n');
}

const { groupCauses } = require('./causes');
const { FLAG_LABELS } = require('./context');
const R = require('./risk');

const cweText = (list) => (list.length ? list.map((n) => `CWE-${n}`).join(', ') : '-');
const pillarText = (codes) => codes.map((c) => R.PILLARS[c]).join(', ');
const stateWord = (i) => (i.state === 'failed' ? (i.type === 'vuln' ? 'vulnerável' : 'confirmado') : 'sem prova');

const TMX = require('./threatmodel');
const { toMermaid } = require('./architecture');
const TM_STATE = { exposed: 'exposta (controle falhando)', unproven: 'sem prova', mitigated: 'mitigada (controles verificados)' };
const tmDecision = (t) => (t.pending ? (t.decision === 'accept' ? 'aceitação vencida' : 'pendente') : TMX.DECISION_PT[t.decision]);

function tmStatusLine(t) {
  if (t.reviewed) return `Modelo revisado por ${t.reviewedBy} em ${String(t.reviewedAt).slice(0, 10)}, com todas as ameaças decididas.`;
  if (t.persisted) return `Modelo gravado em .lastro/threat-model.json, ainda incompleto: ${t.counts.pending} ameaça(s) sem decisão ou com aceitação vencida${t.reviewedBy ? '' : ', e sem revisão registrada'}.`;
  return 'Rascunho gerado nesta execução e não gravado. Rode `lastro threat-model --write` para gravar `.lastro/threat-model.json`, decidir cada ameaça e registrar a revisão.';
}

function threatMd(r) {
  const t = r.threatModel;
  const d = t.discovery;
  const out = ['## Modelo de ameaças', ''];
  out.push(tmStatusLine(t), '');
  out.push('> O kit gera o rascunho a partir do perfil, do catálogo e da leitura do código. Rascunho não é prova: o CORE-012 só passa quando uma pessoa decide cada ameaça e registra a revisão. A descoberta é heurística de texto e nunca guarda valores, só nomes e caminhos.', '');
  out.push('### Ativos', '', '| Id | Ativo | Tipo | Origem |', '|---|---|---|---|');
  for (const a of t.assets) out.push(`| ${a.id} | ${md(a.name)}${a.note ? ` (${md(a.note)})` : ''} | ${a.kind} | ${a.source} |`);
  out.push('', '### O que o kit encontrou no código', '');
  out.push(`- Rotas HTTP: ${d.routes.total}${d.routes.total ? ` (autenticação visível ${d.routes.byAuth.visivel}, middleware global ${d.routes.byAuth.global}, públicas esperadas ${d.routes.byAuth['publica-esperada']}, **não vista ${d.routes.byAuth['nao-vista']}**)` : ''}.`);
  if (d.stores.length) out.push(`- Armazenamento: ${d.stores.join(', ')}.`);
  if (d.realtime.length) out.push(`- Tempo real: ${d.realtime.join(', ')}.`);
  if (d.uploads.length) out.push(`- Upload de arquivos: ${d.uploads.join(', ')}.`);
  if (d.externalHosts.length) out.push(`- Chamadas a serviços externos: ${d.externalHosts.slice(0, 10).join(', ')}.`);
  out.push(`- Variáveis de ambiente lidas: ${d.env.total}${d.env.credentials.length ? `, ${d.env.credentials.length} com nome de segredo (só os nomes)` : ''}.`);
  for (const h of d.dataHints) out.push(`- Indício de dado: ${h.name}${h.sensitive ? ' (**confirme se há dado sensível e declare `context.sensitiveData`**)' : ''} em ${h.files.slice(0, 3).map((f) => `\`${md(f)}\``).join(', ')}.`);
  if (d.routes.examples.length) {
    out.push('', '**Rotas sem autenticação vista** (pistas para revisar a autorização, não um veredito; "não vista" não quer dizer desprotegida):', '');
    if (d.routes.authMounts) out.push(`- Atenção: ${d.routes.authMounts} montagem(ns) de roteador com middleware de autenticação foram encontradas. As rotas desses roteadores podem estar protegidas por elas, e o kit não faz essa ligação.`);
    for (const x of d.routes.examples) out.push(`- \`${md(x.method)} ${md(x.path)}\` (${md(x.location)})`);
    if (d.routes.byAuth['nao-vista'] > d.routes.examples.length) out.push(`- ... e mais ${d.routes.byAuth['nao-vista'] - d.routes.examples.length}.`);
  }
  out.push('', '### Ameaças (STRIDE por superfície)', '');
  out.push(`${t.counts.threats} ameaça(s): ${t.counts.exposed} exposta(s), ${t.counts.unproven} sem prova, ${t.counts.mitigated} mitigada(s); ${t.counts.pending} sem decisão.`, '');
  out.push('| Ameaça | Superfície | Estado | Controles | Decisão |', '|---|---|---|---|---|');
  const order = { exposed: 0, unproven: 1, mitigated: 2 };
  for (const x of [...t.threats].sort((a, b) => order[a.state] - order[b.state] || a.id.localeCompare(b.id))) {
    out.push(`| ${x.id} ${md(x.strideName)} | ${md(x.surfaceName)} | ${TM_STATE[x.state]} | ${x.controls.length} | ${tmDecision(x)} |`);
  }
  if (t.architecture && t.architecture.flows.length) {
    const m = toMermaid(t.architecture);
    out.push('', '### Arquitetura: fluxo de dados e fronteiras de confiança', '');
    out.push('O kit desenha o que descobriu no código e o que o perfil declara, e mostra, em cada fluxo, as ameaças e os controles que ele exige. Ele não inventa a arquitetura: onde colocar um proxy, como segmentar a rede e como separar ambientes são decisões de uma pessoa. Cole o diagrama em qualquer visualizador de Mermaid.', '');
    out.push('```mermaid', m.code, '```', '');
    out.push('| Fluxo | Fronteira | Ameaças | Controles exigidos | Falhando agora | Observação |', '|---|---|---|---|---|---|');
    for (const f of t.architecture.flows) {
      out.push(`| ${f.id} ${md(f.label)} | ${md(f.boundary)} | ${f.threats} (${f.exposed} exposta(s), ${f.pending} sem decisão) | ${f.controls}: ${f.verified} verificado(s), ${f.failed} falhando, ${f.unverified} sem prova | ${f.failing.length ? f.failing.join(', ') : '-'} | ${md(f.note || '-')} |`);
    }
    out.push('');
  }
  out.push('', 'Perguntas para a revisão:', '');
  for (const k of Object.keys(TMX.STRIDE)) out.push(`- **${k} (${TMX.STRIDE[k].name}):** ${TMX.STRIDE[k].ask}`);
  if (t.orphans.length) out.push('', `Decisões de ameaças que não existem mais (a superfície sumiu do perfil ou do código): ${t.orphans.join(', ')}.`);
  out.push('');
  return out;
}

function riskMd(r) {
  const k = r.risk;
  const out = ['## Análise de risco', ''];
  out.push('Três coisas diferentes aparecem em um relatório de segurança, e misturá-las faz tudo parecer igualmente urgente:', '');
  for (const key of ['security', 'practice', 'quality']) out.push(`- **${R.KINDS[key].label}:** ${R.KINDS[key].help}.`);
  out.push('', 'A estimativa de risco (probabilidade x impacto, de 1 a 4 cada, classe pelo produto) vale só para **riscos de segurança**. Boa prática e qualidade aparecem em listas próprias, ordenadas pela gravidade do controle.', '');
  const c = k.summary.confirmed;
  const p = k.summary.potential;
  out.push('### Riscos de segurança por criticidade', '');
  out.push('| Classe | Confirmados (achado ou falha) | Potenciais (sem prova) |', '|---|---|---|');
  for (const cls of R.CLASSES) out.push(`| ${R.CLASS_PT[cls]} | ${c[cls]} | ${p[cls]} |`);
  out.push(`| **Total** | **${c.total}** | **${p.total}** |`, '');
  out.push(`"Confirmado" é o que a verificação encontrou. "Potencial" é o que ninguém provou: a probabilidade é uma suposição média ajustada pela exposição, e não quer dizer que a falha exista. ${k.summary.securityVerified} controle(s) de segurança estão verificados e não entram na conta.`, '');

  out.push('### Matriz de risco (riscos confirmados)', '');
  out.push('Só os riscos confirmados entram na matriz. Os potenciais (sem prova) ficam limitados a "Alto": crítico exige evidência.', '');
  out.push('| Impacto \\ Probabilidade | 1 rara | 2 possível | 3 provável | 4 quase certa |', '|---|---|---|---|---|');
  for (let imp = 4; imp >= 1; imp -= 1) {
    const cells = k.matrix.filter((m) => m.impact === imp).sort((a, b) => a.likelihood - b.likelihood);
    out.push(`| ${imp} ${R.IMPACT_PT[imp]} | ${cells.map((m) => (m.count ? `${m.count} (${R.CLASS_PT[m.class]})` : '·')).join(' | ')} |`);
  }
  out.push('');

  const rows = k.security;
  if (rows.length) {
    out.push('### Lista de riscos de segurança', '');
    const conf = rows.filter((i) => i.state === 'failed');
    const pot = rows.filter((i) => i.state === 'unverified');
    const render = (list, title, limit) => {
      if (!list.length) return;
      out.push(`#### ${title}`, '');
      out.push('| Classe | P x I | Controle | Pilares | CWE | ASVS | Onde / por quê |', '|---|---|---|---|---|---|---|');
      for (const i of list.slice(0, limit)) {
        const where = i.type === 'vuln'
          ? `${i.advisories.map((a) => a.id || a.title).join(', ').slice(0, 90)} (${i.direct ? 'direta' : 'indireta'}; correção: ${i.fix})`
          : (i.locations.length ? i.locations.join(', ') : i.reasons.likelihood[0]);
        out.push(`| ${R.CLASS_PT[i.class]}${i.accepted ? ' (aceito)' : ''} | ${i.likelihood} x ${i.impact} = ${i.score} | ${i.id} ${md(i.title)} | ${pillarText(i.pillars)} | ${cweText(i.cwe)} | ${i.asvs.slice(0, 3).join(', ') || '-'} | ${md(where)} |`);
      }
      if (list.length > limit) out.push('', `... e mais ${list.length - limit}, em ordem decrescente de risco.`);
      out.push('');
    };
    render(conf, 'Confirmados', 60);
    render(pot, 'Potenciais (sem prova): onde olhar primeiro', 25);
  }

  out.push('### Pilares da segurança da informação', '');
  out.push('Quais pilares os riscos abertos (de qualquer natureza) tocam. "Pior classe" considera só riscos de segurança.', '');
  out.push('| Pilar | Significa | Itens abertos | Confirmados | Potenciais | Pior classe |', '|---|---|---|---|---|---|');
  for (const pl of k.pillars) out.push(`| ${pl.name} | ${pl.help} | ${pl.open} | ${pl.confirmed} | ${pl.potential} | ${pl.worstClass ? R.CLASS_PT[pl.worstClass] : '-'} |`);
  out.push('');

  const pv = k.privacy;
  out.push('### Privacidade e LGPD', '');
  if (!pv.applies) out.push('O perfil declara que a aplicação não trata dados pessoais. Se isso mudar, declare `personalData` (e `minorsData` ou `context.sensitiveData`, se for o caso) para que o impacto dos riscos de confidencialidade suba.', '');
  else {
    const classes = [pv.data.personal && 'dados pessoais', pv.data.minors && 'dados de crianças ou adolescentes', pv.data.sensitive && 'dados pessoais sensíveis'].filter(Boolean).join(', ');
    out.push(`A aplicação trata ${classes}. ${pv.confirmed} risco(s) confirmado(s) e ${pv.potential} potencial(is) tocam privacidade ou confidencialidade de dado pessoal.`, '');
    out.push(`> ${pv.note}`, '');
    if (pv.items.length) {
      out.push('| Classe | Controle | Natureza | Estado | Base na LGPD |', '|---|---|---|---|---|');
      for (const i of pv.items.slice(0, 25)) out.push(`| ${i.class ? R.CLASS_PT[i.class] : '-'} | ${i.id} ${md(i.title)} | ${R.KINDS[i.kind].label} | ${stateWord(i)} | ${md(i.lgpd || '-')} |`);
      if (pv.items.length > 25) out.push('', `... e mais ${pv.items.length - 25}.`);
      out.push('');
    }
  }

  if (r.dependencyVulns) {
    const v = r.dependencyVulns;
    out.push('### Vulnerabilidades conhecidas em dependências', '');
    out.push(`Fonte: ${v.source}. ${v.total} pacote(s): ${v.bySeverity.critical} crítico(s), ${v.bySeverity.high} alto(s), ${v.bySeverity.medium} médio(s), ${v.bySeverity.low} baixo(s). O npm audit informa o aviso do GitHub (GHSA), a CWE e o CVSS, mas não o CVE: o CVE está na página do aviso.`, '');
    if (v.items.length) {
      out.push('| Pacote | Gravidade | Aviso (GHSA) | CWE | CVSS | CVE | Correção |', '|---|---|---|---|---|---|---|');
      for (const i of v.items.slice(0, 40)) {
        const a = i.advisories[0];
        out.push(`| ${md(i.package)}${i.direct ? '' : ' (indireta)'} | ${SEV_PT[i.severity]} | ${md(a && (a.id || a.title) ? (a.id || a.title) : '-')} | ${a ? cweText(a.cwe) : '-'} | ${a && a.cvss !== null ? a.cvss : '-'} | ${a && a.cve.length ? a.cve.join(', ') : 'ver o aviso'} | ${md(i.fix)} |`);
      }
      out.push('');
    }
  }

  const listKind = (title, help, list) => {
    out.push(`### ${title}`, '', help, '');
    if (!list.length) { out.push('Nenhum item aberto.', ''); return; }
    out.push('| Gravidade | Controle | Estado | Pilares |', '|---|---|---|---|');
    for (const i of list.slice(0, 40)) out.push(`| ${SEV_PT[i.severity]} | ${i.id} ${md(i.title)} | ${stateWord(i)} | ${pillarText(i.pillars)} |`);
    if (list.length > 40) out.push('', `... e mais ${list.length - 40}.`);
    out.push('');
  };
  listKind('Boas práticas pendentes', `${R.KINDS.practice.help}. Cobrar com prazo, mas sem tratar como brecha.`, k.practices);
  listKind('Qualidade pendente', `${R.KINDS.quality.help}.`, k.quality);

  out.push('> A probabilidade é uma estimativa a partir do estado do controle e da exposição declarada no perfil. Um modelo de ameaças (docs/THREAT-MODEL.md) a torna específica: quem ataca, por onde e o que já existe. Sem ele, use a classe para priorizar a investigação, não como medida do dano.', '');
  return out;
}

/** Texto sobre o que acontece se a dívida atual virar baseline (usado no Markdown, no HTML e no texto). */
function baselineLines(v) {
  const view = v.verdictIfAdopted === 'pass' ? 'aprovado' : 'incompleto (ainda há controles altos ou críticos sem prova)';
  return [
    `Se esta dívida (${v.findings} achado(s), ${v.causes} causa(s)) fosse registrada como baseline com \`lastro baseline --write\`, o portão ficaria ${view}: só achado novo passaria a bloquear. A dívida continua visível no relatório e deve virar ticket ou risco aceito com dono e validade.`,
  ];
}

const flagList = (flags) => flags.map((f) => FLAG_LABELS[f] || f).join(', ');

function contextMd(r) {
  const c = r.context;
  const out = ['## Contexto e meta', ''];
  out.push(`- **Risco inerente: ${c.risk}** (${c.points} pontos, ${c.riskSource}). A aplicação ${c.factors.length ? c.factors.join('; ') : 'não declara fatores de exposição no perfil'}.`);
  out.push(`- **Meta de maturidade para este contexto: nível ${c.targetLevel}** (${c.targetSource}). Hoje: nível ${r.score.level}. ${c.meetsTarget ? 'Meta atingida.' : `Faltam ${c.gap} nível(is).`}`);
  if (r.scope) {
    out.push(`- Pacotes no escopo: ${r.scope.on.map((p) => p.title.split(':')[0]).join('; ')}.`);
    if (r.scope.off.length) out.push(`- Fora do escopo, porque o perfil declara que a aplicação não tem: ${r.scope.off.map((p) => `${p.title.split(':')[0]} (${flagList(p.missing)})`).join('; ')}.`);
  }
  out.push('', '> Nem toda aplicação precisa do mesmo rigor. A meta acompanha o risco inerente, e o escopo depende do perfil: um perfil que subdeclara a aplicação melhora o número e piora a segurança. Revise o perfil com outra pessoa.', '');
  return out;
}

function phasesMd(r) {
  const out = ['## Aderência por fase do ciclo de vida (SSDLC)', ''];
  out.push('Cada controle conta em todas as fases em que atua, então as fases não somam o total. "Aderência" é a fatia do peso dos controles da fase que está provada, não uma certificação.', '');
  out.push('| Fase | Controles | Provado | Falhando | Sem prova |', '|---|---|---|---|---|');
  for (const p of r.score.byPhase) out.push(`| ${p.name} | ${p.controls} | ${p.provenPct}% | ${p.failedPct}% | ${p.unverifiedPct}% |`);
  out.push('');
  return out;
}

function engineeringMd(e) {
  const yes = (b) => (b ? 'sim' : 'não');
  const out = ['## Fatos de engenharia (não entram na pontuação)', ''];
  out.push('O kit não dá nota à qualidade do código. Estes são indícios objetivos para a conversa sobre manutenção e revisão.', '');
  out.push(`- Código-fonte: ${e.sourceFiles} arquivo(s), ${e.sourceLines} linha(s).${e.largest.length ? ` Maiores: ${e.largest.map((x) => `${md(x.file)} (${x.lines})`).join(', ')}.` : ''}`);
  out.push(`- Testes: ${e.testFiles} arquivo(s), ${e.testLines} linha(s) (${e.testToSourcePct}% do código-fonte).`);
  out.push(`- CI: ${e.ci.workflows} workflow(s); executa testes: ${yes(e.ci.runsTests)}; executa lint: ${yes(e.ci.runsLint)}.`);
  out.push(`- Ferramentas: script de teste ${yes(e.tooling.testScript)}; lint configurado ${yes(e.tooling.lintConfig || e.tooling.lintScript)}; tipagem ${yes(e.tooling.typeConfig)}; lockfile ${yes(e.tooling.lockfile)}.`);
  out.push(`- Documentação: README ${yes(e.docs.readme)}; arquitetura ${yes(e.docs.architecture)}; registro de mudanças ${yes(e.docs.changelog)}; licença ${yes(e.docs.license)}.`);
  if (e.dependencies.prod !== null) out.push(`- Dependências: ${e.dependencies.prod} de produção e ${e.dependencies.dev} de desenvolvimento.`);
  if (e.observations.length) out.push('', 'Observações:', ...e.observations.map((x) => `- ${md(x)}`));
  out.push('');
  return out;
}

const md = (s) => String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const STATE_PT = { verified: 'verificado', failed: 'falhando', unverified: 'sem prova', not_applicable: 'não se aplica' };
const SEV_PT = { critical: 'crítica', high: 'alta', medium: 'média', low: 'baixa' };

/**
 * Relatório em Markdown para leitura humana (adoção, revisão, conversa com a equipe).
 * `coverage` (opcional) é o resultado de asvs.coverage(..., { states }) para incluir a cobertura do ASVS.
 */
function formatMarkdown(r, { coverage = null } = {}) {
  const k = r.score;
  const s = r.summary;
  const out = [];
  out.push(`# Relatório LASTRO: ${md(r.profile.name)}`, '');
  out.push(`Gerado em ${r.generatedAt.slice(0, 10)} | LASTRO ${r.tool.version} | catálogo ${r.catalogVersion} | portão de CI: **${VERDICT[r.verdict]}**`);
  out.push(r.target.url
    ? `Alvo HTTP: ${md(r.target.url)} (${r.target.active ? 'sondas ativas ligadas' : 'somente sondas passivas'}, ${r.target.requestsSent} requisições).`
    : 'Escopo: somente verificações estáticas do repositório. Nenhuma requisição foi feita à aplicação, então cabeçalhos, cookies, CSP e HSTS ficaram sem verificação.');
  out.push('');
  if (r.risk) out.push(...riskMd(r));
  if (r.threatModel) out.push(...threatMd(r));
  if (k) {
    out.push('## Maturidade', '');
    out.push(`**Nível ${k.level}: ${k.levelName}.** Regra do nível: ${k.levelRule}.`, '');
    out.push('| Provado | Por máquina | Autodeclarado | Falhando | Sem prova |', '|---|---|---|---|---|');
    out.push(`| ${k.provenPct}% | ${k.machinePct}% | ${k.attestedPct}% | ${k.failedPct}% | ${k.unverifiedPct}% |`, '');
    out.push(`Próximo passo: ${k.nextStep}`, '');
    if (k.automated && k.automated.controls) {
      const a = k.automated;
      out.push(`**Controles automáticos** (o que a máquina rodou): ${a.verified} passaram, ${a.failed} falharam${a.passRatePct === null ? '' : `, taxa de aprovação ${String(a.passRatePct).replace('.', ',')}%`}; ${a.notRun} não rodaram (por exemplo, as sondas HTTP sem \`--url\`) e ficam fora da taxa, sem virar aprovação. Esta taxa separa melhor duas aplicações do que o nível, que depende de muita prova manual.`, '');
    }
    out.push(`> ${k.disclaimer}`, '');
    out.push('### Por pacote', '', '| Pacote | Controles | Provado | Falhando | Sem prova |', '|---|---|---|---|---|');
    for (const p of k.byPack) out.push(`| ${md(p.title.split(':')[0])} | ${p.controls} | ${p.provenPct}% | ${p.failedPct}% | ${p.unverifiedPct}% |`);
    out.push('');
  }
  if (r.context && k) out.push(...contextMd(r));
  if (k && k.byPhase && k.byPhase.length) out.push(...phasesMd(r));
  out.push('## Resumo', '');
  out.push(`- Controles aplicáveis: ${s.applicable} (verificados ${s.verified}, falhando ${s.failed}, sem prova ${s.unverified}); não se aplicam: ${s.notApplicable}.`);
  out.push(`- Achados bloqueantes: ${s.blocking}. Dívida em baseline: ${s.debt}. Riscos aceitos: ${s.accepted}.`, '');

  const blocking = r.controls.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => ({ c, f })));
  out.push('## Causas dos bloqueios', '');
  const causes = groupCauses(r);
  if (!blocking.length) out.push('Nenhum achado bloqueante.', '');
  else {
    out.push(`${blocking.length} achado(s) em ${causes.length} causa(s). Cada causa tem uma correção só.`, '');
    out.push('| Controle | Gravidade | Ocorrências | Onde | Como corrigir |', '|---|---|---|---|---|');
    for (const c of causes) {
      const where = `${md(c.locations.slice(0, 3).join(', ') || '-')}${c.locations.length > 3 ? ` e mais ${c.locations.length - 3}` : ''}`;
      out.push(`| ${c.id} ${md(c.title)} | ${SEV_PT[c.severity]} | ${c.count} | ${where} | ${md(c.remediation.slice(0, 260))} |`);
    }
    out.push('');
    if (r.baselineView) out.push(...baselineLines(r.baselineView), '');
    out.push('### Todas as ocorrências', '');
    out.push('| Controle | Gravidade | Onde | O que |', '|---|---|---|---|');
    for (const { c, f } of blocking.sort((a, b) => SEV_ORDER[a.f.severity] - SEV_ORDER[b.f.severity])) {
      out.push(`| ${c.id} | ${SEV_PT[f.severity]} | ${md(f.location || '-')} | ${md(f.message)} |`);
    }
    out.push('');
  }

  const failing = r.controls.filter((c) => c.findings.some((f) => !f.blocking));
  out.push('## Outros achados (não bloqueiam)', '');
  if (!failing.length) out.push('Nenhum.', '');
  else {
    out.push('Agrupados por controle. Cada um pede uma decisão: corrigir, justificar ou aceitar o risco com dono e validade.', '');
    out.push('| Controle | Título | Achados | Maior gravidade | Exemplo |', '|---|---|---|---|---|');
    for (const c of failing.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id))) {
      const fs = c.findings.filter((f) => !f.blocking);
      const worst = fs.map((f) => f.severity).sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b])[0];
      out.push(`| ${c.id} | ${md(c.title)} | ${fs.length} | ${SEV_PT[worst]} | ${md(fs[0].message.slice(0, 140))}${fs[0].location ? ` (${md(fs[0].location)})` : ''} |`);
    }
    out.push('');
  }

  const open = r.controls.filter((c) => c.state === 'unverified').sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id));
  out.push('## Controles sem prova', '');
  out.push(`${open.length} controle(s) sem prova não contam como aprovados. A maioria é manual: a prova é uma atestação com responsável e validade em \`.lastro/status.json\`, ou uma verificação HTTP que exige \`--url\`.`, '');
  if (open.length) {
    out.push('| Controle | Gravidade | Título | Por quê |', '|---|---|---|---|');
    for (const c of open) out.push(`| ${c.id} | ${SEV_PT[c.severity]} | ${md(c.title)} | ${md((c.notes[0] || '').slice(0, 90))} |`);
    out.push('');
  }

  if (coverage) {
    const t = coverage.totals;
    out.push(`## Cobertura do ASVS ${coverage.version} (até L${coverage.level})`, '');
    out.push(`${t.total} requisitos. Verificados: ${t.verified}. Falhando: ${t.failed}. Sem prova: ${t.unverified}. Fora do perfil: ${t.outOfProfile}. Sem controle: ${t.none}.`, '');
    out.push('Um requisito só conta como verificado quando um controle que o cobre por inteiro está verificado.', '');
    out.push('| Capítulo | Total | Verificados | Falhando | Sem prova | Fora do perfil |', '|---|---|---|---|---|---|');
    for (const ch of Object.keys(coverage.byChapter).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)))) {
      const b = coverage.byChapter[ch];
      out.push(`| ${ch} ${md(b.name)} | ${b.total} | ${b.verified} | ${b.failed} | ${b.unverified} | ${b.outOfProfile} |`);
    }
    out.push('');
  }

  if (r.warnings.length) out.push('## Avisos', '', ...r.warnings.map((w) => `- ${md(w)}`), '');
  if (r.engineering) out.push(...engineeringMd(r.engineering));
  out.push('## Limites', '');
  out.push('- As varreduras de código são heurísticas por texto, linha a linha: erram para os dois lados e não substituem revisão.');
  out.push('- A pontuação e a cobertura medem evidência e progresso do kit. Elas não certificam a aplicação nem provam conformidade com o ASVS.');
  out.push('- Atestação é autodeclaração com prazo. Quem escreveu o código não deve ser o único a atestar controles de nível alto.', '');
  return out.join('\n');
}

const REDACT_MAX_TERMS = 20;

/** Valida a lista de termos de --redact. Devolve a lista de erros (vazia = válida). */
function validateRedactTerms(terms) {
  const errs = [];
  if (!Array.isArray(terms) || terms.length === 0) return ['informe ao menos um termo'];
  if (terms.length > REDACT_MAX_TERMS) errs.push(`no máximo ${REDACT_MAX_TERMS} termos`);
  for (const t of terms) {
    if (typeof t !== 'string' || t.length < 3 || t.length > 60) errs.push(`termo inválido "${String(t).slice(0, 20)}": use de 3 a 60 caracteres`);
    else if (!/^[\p{L}\p{N}][\p{L}\p{N} ._-]*$/u.test(t)) errs.push(`termo inválido "${t}": use só letras, números, espaço, ponto, _ e -`);
  }
  return errs;
}

/**
 * Devolve uma cópia do relatório com os termos trocados por "[omitido]" em todos os textos, sem diferenciar
 * maiúsculas de minúsculas. Serve para compartilhar um relatório sem nomes de empresa, produto ou cliente.
 * A troca é feita nos dados, antes de formatar, então o Markdown e o HTML continuam íntegros.
 */
function redactReport(report, terms) {
  const errs = validateRedactTerms(terms);
  if (errs.length) throw new Error(`--redact inválido: ${errs.join('; ')}`);
  const re = new RegExp(terms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'giu');
  const walk = (v) => {
    if (typeof v === 'string') return v.replace(re, '[omitido]');
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(report);
}

/** Só a seção de modelo de ameaças, em Markdown (para `lastro threat-model --out`). */
function threatMarkdown(r) {
  return [`# Modelo de ameaças: ${md(r.profile.name)}`, '', ...threatMd(r)];
}

module.exports = { formatReport, formatMarkdown, redactReport, validateRedactTerms, threatMarkdown };
