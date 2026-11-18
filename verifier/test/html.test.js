'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { formatHtml, validateTheme, MAX_FINDINGS_PER_CONTROL } = require('../src/html');
const { computeScore } = require('../src/score');
const { loadCatalog } = require('../src/catalog');
const asvs = require('../src/asvs');
const { makeProject, profileJson, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const ctl = (id, pack, severity, state, over = {}) => ({ id, title: `Controle ${id}`, pack, severity, state, notes: [], findings: [], evidence: null, ...over });
const finding = (severity, message, location, blocking = false) => ({ fingerprint: 'a'.repeat(16), severity, message, location, blocking, accepted: false, inBaseline: false });

function fakeReport(over = {}) {
  const controls = [
    ctl('CORE-007', 'core', 'high', 'failed', { findings: [finding('high', 'TLS desligado', 'db.js:13', true)] }),
    ctl('CORE-009', 'core', 'medium', 'failed', { findings: [finding('medium', 'HTML por template', 'app.js:9'), finding('low', 'variável solta', 'app.js:20')] }),
    ctl('AUTH-001', 'auth', 'high', 'unverified', { notes: ['Sem atestação registrada em .lastro/status.json.'] }),
    ctl('CORE-001', 'core', 'critical', 'verified', { evidence: { source: 'verifier-repo' } }),
  ];
  const summary = { applicable: 4, verified: 1, failed: 2, unverified: 1, notApplicable: 0, blocking: 1, debt: 0, accepted: 0 };
  return {
    tool: { version: '0.1.0' }, catalogVersion: '0.1.0', generatedAt: '2026-11-12T12:00:00.000Z',
    target: { root: 'x', url: null, active: false, requestsSent: 0, delayMs: 150 },
    profile: { name: 'App de teste', flags: {} }, verdict: 'fail', summary, controls, warnings: [],
    score: computeScore({ controls, summary }, { packTitles: { core: 'Base: cadeia de suprimentos', auth: 'Autenticação e sessão' } }),
    ...over,
  };
}

test('HTML: estrutura, idioma, seções, âncoras internas e aviso de que a nota mede evidência', () => {
  const html = formatHtml(fakeReport());
  assert.ok(html.startsWith('<!doctype html>'));
  for (const trecho of ['<html lang="pt-BR">', '<title>Relatório LASTRO: App de teste</title>', 'id="resumo"', 'id="pacotes"', 'id="bloqueantes"', 'id="achados"', 'id="sem-prova"', 'id="limites"', 'Nota geral', 'não a segurança da aplicação']) {
    assert.ok(html.includes(trecho), `faltou: ${trecho}`);
  }
  assert.ok(html.includes('role="img" aria-label="Provado por máquina'), 'a barra tem texto alternativo');
  assert.ok(html.includes('<caption>'), 'as tabelas têm legenda');
  assert.ok(html.includes('scope="col"'));
  assert.ok(html.includes('<details>') && html.includes('<summary>CORE-009'));
  assert.ok(html.includes('FALHA'));
  assert.ok(!html.includes('## '), 'não vaza Markdown');
});

test('HTML: tudo que vem do projeto analisado é escapado (nome, mensagem, local, URL, aviso, nota)', () => {
  const ruim = '<script>alert(1)</script>';
  const r = fakeReport({
    profile: { name: '<img src=x onerror=alert(1)>', flags: {} },
    target: { root: 'x', url: 'https://x.test/"><b>', active: false, requestsSent: 2, delayMs: 150 },
    warnings: [ruim],
  });
  r.controls[0].findings[0].message = ruim;
  r.controls[0].findings[0].location = '"><svg onload=alert(1)>';
  r.controls[1].findings[0].message = `${ruim} & "aspas" 'simples'`;
  r.controls[2].notes = [ruim];
  r.controls[2].title = ruim;
  const html = formatHtml(r);
  assert.ok(!html.includes('<script'), 'nenhuma tag script no documento');
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('<svg'));
  assert.ok(!html.includes('"><b>'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(html.includes('&amp; &quot;aspas&quot; &#39;simples&#39;'));
});

test('HTML: autocontido, sem script, sem recurso externo e com política de conteúdo restritiva', () => {
  const html = formatHtml(fakeReport());
  assert.ok(!/<script|<link|<iframe|<object|<embed|<img/i.test(html));
  assert.ok(!/(?:src|href)=["'](?!#)/i.test(html), 'só âncoras internas');
  assert.ok(!/@import|url\(/i.test(html));
  assert.ok(html.includes(`default-src 'none'`));
  assert.ok(html.includes('Content-Security-Policy'));
  assert.ok(!/\son[a-z]+\s*=/i.test(html.replace(/aria-label="[^"]*"/g, '')), 'sem atributos de evento');
});

test('HTML: o gerador do kit é neutro, sem marca de empresa', () => {
  const html = formatHtml(fakeReport());
  assert.ok(!/hardtech|lynx|quiz/i.test(html));
  assert.ok(html.includes('--brand:#5219a1') && html.includes('--highlight:#ffad01'), 'paleta padrão do LASTRO');
  assert.ok(html.includes('prefers-color-scheme:dark'), 'suporta modo escuro');
});

test('HTML: percentuais com vírgula e barras com larguras limitadas entre 0 e 100', () => {
  const r = fakeReport();
  r.score.machinePct = 250;
  r.score.failedPct = -5;
  const html = formatHtml(r);
  assert.ok(/\d,\d%/.test(html), 'vírgula decimal');
  assert.ok(!/width:-/.test(html));
  assert.ok(html.includes('width:100%'));
  assert.ok(html.includes('width:0%'));
});

test('HTML: um achado por linha, com truncamento nos grupos muito grandes', () => {
  const r = fakeReport();
  r.controls[1].findings = Array.from({ length: MAX_FINDINGS_PER_CONTROL + 40 }, (_, i) => finding('low', `achado ${i}`, `a.js:${i + 1}`));
  const html = formatHtml(r);
  assert.ok(html.includes('... e mais 40 achado(s) do mesmo controle.'));
  assert.ok(html.includes('achado 0'));
  assert.ok(!html.includes(`achado ${MAX_FINDINGS_PER_CONTROL + 10}<`));
});

test('HTML: sem bloqueantes, sem outros achados e com a cobertura do ASVS', () => {
  const controls = [ctl('CORE-001', 'core', 'critical', 'verified', { evidence: { source: 'verifier-repo' } })];
  const summary = { applicable: 1, verified: 1, failed: 0, unverified: 0, notApplicable: 0, blocking: 0, debt: 0, accepted: 0 };
  const cat = loadCatalog();
  const coverage = asvs.coverage(cat.controls, cat.asvsMap, { level: 2, states: new Map([['CORE-001', 'verified']]) });
  const html = formatHtml(fakeReport({ controls, summary, verdict: 'pass', score: computeScore({ controls, summary }) }), { coverage });
  assert.ok(html.includes('APROVADO'));
  assert.equal((html.match(/<p class="empty">Nenhum\.<\/p>/g) || []).length, 2, 'bloqueantes e outros achados vazios');
  assert.ok(html.includes('id="asvs"'));
  assert.ok(html.includes('Cobertura do ASVS 5.0.0 (até L2)'));
  assert.ok(html.includes('V6 Autenticação'));
});

test('tema: aceita CSS inofensivo e recusa o que quebra o documento ou chama recursos externos', () => {
  assert.deepEqual(validateTheme(':root{--bg:#05050b;--accent:#7c3aed} body{font-family:Inter,"Segoe UI",sans-serif}'), []);
  assert.deepEqual(validateTheme('.hero{background:url(data:image/png;base64,AAAA)}'), []);
  const ruins = {
    vazio: '   ',
    'fecha o style': 'body{} </style><script>alert(1)</script>',
    importa: '@import url("https://x.test/a.css");',
    'recurso externo': '.a{background:url(https://x.test/i.png)}',
    'recurso externo sem aspas': ".a{background:url(//x.test/i.png)}",
    escape: '.a{content:"\\75rl(x)"}',
    expressao: '.a{width:expression(alert(1))}',
    'javascript': '.a{background:url(javascript:alert(1))}',
    grande: `.a{}${'x'.repeat(70000)}`,
  };
  for (const [nome, css] of Object.entries(ruins)) assert.ok(validateTheme(css).length > 0, `deveria recusar: ${nome}`);
});

test('tema: o CSS do usuário entra depois do padrão, para poder sobrescrevê-lo', () => {
  const tema = ':root{--bg:#05050b;--accent:#7c3aed}';
  const html = formatHtml(fakeReport(), { theme: tema });
  assert.ok(html.includes(tema));
  assert.ok(html.indexOf(tema) > html.indexOf('--accent:#1d4ed8'));
  assert.ok(html.indexOf(tema) < html.indexOf('</style>'));
});

test('CLI report: .html gera HTML, aplica o tema e recusa tema perigoso ou usado fora do HTML', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({ aiCodingAgents: true }), '.gitignore': '.env\n' });
  try {
    const tema = path.join(root, 'tema.css');
    fs.writeFileSync(tema, ':root{--accent:#7c3aed}\n');
    const out = path.join(root, 'saida', 'r.html');
    const r = spawnSync(process.execPath, [CLI, 'report', '--root', root, '--out', out, '--theme', tema], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const html = fs.readFileSync(out, 'utf8');
    assert.ok(html.startsWith('<!doctype html>'));
    assert.ok(html.includes('--accent:#7c3aed'));
    assert.ok(html.includes('Cobertura do ASVS 5.0.0'));
    assert.ok(!/<script/i.test(html));

    const md = spawnSync(process.execPath, [CLI, 'report', '--root', root, '--out', path.join(root, 'r.md'), '--format', 'md', '--theme', tema], { encoding: 'utf8' });
    assert.equal(md.status, 3);
    assert.ok(md.stderr.includes('--theme só vale com'));

    const ruim = path.join(root, 'ruim.css');
    fs.writeFileSync(ruim, '@import url(https://x.test/a.css);');
    const recusa = spawnSync(process.execPath, [CLI, 'report', '--root', root, '--out', path.join(root, 'r2.html'), '--theme', ruim], { encoding: 'utf8' });
    assert.equal(recusa.status, 3);
    assert.ok(recusa.stderr.includes('Tema recusado'));
    assert.ok(!fs.existsSync(path.join(root, 'r2.html')), 'nada é gravado quando o tema é recusado');

    assert.equal(spawnSync(process.execPath, [CLI, 'report', '--root', root, '--format', 'pdf'], { encoding: 'utf8' }).status, 3);
    assert.equal(spawnSync(process.execPath, [CLI, 'report', '--root', root, '--theme', path.join(root, 'nao-existe.css'), '--format', 'html'], { encoding: 'utf8' }).status, 3);
  } finally { cleanup(root); }
});

test('redact: troca os termos em todo o relatório, sem diferenciar maiúsculas, e deixa números e estrutura intactos', () => {
  const { redactReport, validateRedactTerms } = require('../src/report');
  const r = fakeReport({ profile: { name: 'Meu AcmeCorp App', flags: {} }, warnings: ['aviso sobre acmecorp'] });
  r.controls[0].findings[0].location = 'public/img/logo_ACMECORP.png';
  r.controls[1].findings[0].message = 'usa o domínio acme-interno.exemplo e Segredo';
  const red = redactReport(r, ['acmecorp', 'acme-interno']);
  assert.equal(red.profile.name, 'Meu [omitido] App');
  assert.equal(red.warnings[0], 'aviso sobre [omitido]');
  assert.equal(red.controls[0].findings[0].location, 'public/img/logo_[omitido].png');
  assert.equal(red.controls[1].findings[0].message, 'usa o domínio [omitido].exemplo e Segredo');
  assert.equal(red.score.grade, r.score.grade);
  assert.equal(red.summary.blocking, 1);
  assert.equal(r.profile.name, 'Meu AcmeCorp App', 'o original não é alterado');
  assert.ok(!JSON.stringify(red).match(/acmecorp|acme-interno/i));
  assert.ok(validateRedactTerms(['ab']).length > 0, 'termo curto demais');
  assert.ok(validateRedactTerms(['a<b>c']).length > 0, 'caracteres de marcação são recusados');
  assert.ok(validateRedactTerms([]).length > 0);
  assert.ok(validateRedactTerms(Array.from({ length: 21 }, (_, i) => `termo${i}`)).length > 0);
  assert.deepEqual(validateRedactTerms(['Empresa X', 'produto_y', 'a.b.c']), []);
});

test('redact: uma expressão especial não vira regex, e o HTML continua íntegro', () => {
  const { redactReport } = require('../src/report');
  const r = fakeReport();
  r.controls[0].findings[0].message = 'valor a.b e axb';
  const red = redactReport(r, ['a.b']);
  assert.equal(red.controls[0].findings[0].message, 'valor [omitido] e axb', 'o ponto é literal');
  const html = formatHtml(redactReport(fakeReport({ profile: { name: 'Div Section Table', flags: {} } }), ['table', 'section']));
  assert.ok(html.includes('<h1>Div [omitido] [omitido]</h1>'));
  assert.ok(html.includes('<section id="resumo"'), 'as tags não são tocadas');
});

test('CLI report --redact: grava sem os termos e recusa termos inválidos antes de qualquer análise', () => {
  const root = makeProject({
    '.lastro/profile.json': profileJson({ thirdPartyAssets: true, aiCodingAgents: true }),
    '.gitignore': '.env\n',
    'public/logo_acmecorp.png': 'x',
  });
  try {
    const out = path.join(root, 'r.html');
    const r = spawnSync(process.execPath, [CLI, 'report', '--root', root, '--out', out, '--redact', 'acmecorp'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const html = fs.readFileSync(out, 'utf8');
    assert.ok(!/acmecorp/i.test(html), 'o termo não aparece em lugar nenhum');
    assert.ok(html.includes('logo_[omitido].png'));
    const md = path.join(root, 'r.md');
    assert.equal(spawnSync(process.execPath, [CLI, 'report', '--root', root, '--out', md, '--redact', 'acmecorp'], { encoding: 'utf8' }).status, 0);
    assert.ok(!/acmecorp/i.test(fs.readFileSync(md, 'utf8')));
    const ruim = spawnSync(process.execPath, [CLI, 'report', '--root', root, '--out', path.join(root, 'r2.html'), '--redact', 'ab,<x>'], { encoding: 'utf8' });
    assert.equal(ruim.status, 3);
    assert.ok(ruim.stderr.includes('--redact recusado'));
    assert.ok(!fs.existsSync(path.join(root, 'r2.html')));
    assert.equal(spawnSync(process.execPath, [CLI, 'report', '--root', root, '--redact'], { encoding: 'utf8' }).status, 3);
  } finally { cleanup(root); }
});
