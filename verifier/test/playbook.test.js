'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { buildPlaybook, splitSteps, formatPlaybookMarkdown, formatPlaybookHtml, VALIDITY_DAYS } = require('../src/playbook');
const { loadCatalog } = require('../src/catalog');
const { runCheck } = require('../src/engine');
const { validateStatus } = require('../src/schema');
const { makeProject, profileJson, cleanup, badHrefs } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const NOW = new Date('2026-11-12T12:00:00Z');
const cat = loadCatalog();
const project = () => makeProject({ '.lastro/profile.json': profileJson({ webApp: true, hasAuth: true, publicInternet: true, personalData: true }), 'a.js': 'const a = 1;\n' });

test('passos: lista numerada vira passos, "confirme que" vira checagem e o "Registre" final sai dos passos', () => {
  const r = splitSteps('Com duas contas: (1) a conta comum chama a função e recebe 403; (2) a conta A tenta ler o objeto da conta B e recebe 404; (3) confirme que a regra vale sem a interface. Registre com data.');
  assert.equal(r.steps.length, 4);
  assert.match(r.steps[0], /^Com duas contas\.$/);
  assert.equal(r.steps[1], 'A conta comum chama a função e recebe 403.', 'passo começa com maiúscula');
  assert.ok(!r.steps.some((s) => /Registre/.test(s)));
  assert.deepEqual(r.register, ['Registre com data.']);
  assert.deepEqual(r.checks, [
    'A conta comum chama a função e recebe 403.',
    'A conta A tenta ler o objeto da conta B e recebe 404.',
    'Confirme que a regra vale sem a interface.',
  ], 'resultado esperado inclui os "recebe 403/404", e a checagem curta leva o passo inteiro');
  const s = splitSteps('Tente um push direto e confirme que a plataforma recusa. Confirme que o plano aplica a regra de revisão obrigatória e de checks verdes. Registre o resultado e a data em .lastro/status.json, com validade de até 12 meses.');
  assert.equal(s.steps.length, 2);
  assert.deepEqual(s.checks, ['Tente um push direto e confirme que a plataforma recusa.', 'O plano aplica a regra de revisão obrigatória e de checks verdes.']);
  assert.match(s.register[0], /^Registre o resultado/);
  const xss = splitSteps('Envie em cada campo os valores <script>alert(1)</script> e <img src=x onerror=alert(1)>. Confirme que aparecem como texto e não executam.');
  assert.equal(xss.steps.length, 2, 'alert(1) não é marcador de passo');
  assert.ok(xss.steps[0].includes('<script>alert(1)</script>'));
  assert.equal(splitSteps('Procure no código consultas que retornam dados e confirme que usam parâmetros em todas as rotas de busca.').checks.length, 1, 'passo de leitura só vira item pelo "confirme que"');
});

test('todo controle manual do catálogo vira pelo menos um passo, e nenhum passo fica vazio', () => {
  for (const c of cat.controls.filter((x) => x.check.type === 'manual')) {
    const r = splitSteps(c.howToVerify);
    assert.ok(r.steps.length >= 1, `${c.id} sem passos`);
    assert.ok(r.steps.every((x) => x.length > 3 && /[.!?]$/.test(x)), `${c.id}: passo malformado ${JSON.stringify(r.steps)}`);
  }
});

test('playbook: só manuais sem prova, segurança primeiro, com pré-requisitos, CWE, ASVS e atestação válida no formato do kit', async () => {
  const root = project();
  try {
    const rep = await runCheck({ root, now: NOW });
    const pb = buildPlaybook(rep, cat, { now: NOW });
    assert.ok(pb.total > 20);
    assert.ok(pb.items.every((i) => cat.byId.get(i.id).check.type === 'manual' && i.state !== 'verified'));
    const kinds = pb.items.map((i) => i.kind);
    assert.ok(kinds.indexOf('practice') === -1 || kinds.lastIndexOf('security') < kinds.indexOf('practice'), 'segurança vem antes de boa prática');
    const authz = pb.items.find((i) => i.id === 'AUTH-027');
    assert.ok(authz.steps.length >= 3);
    assert.ok(authz.prereqs.some((p) => /staging/.test(p)), 'teste de API pede staging');
    assert.ok(authz.prereqs.some((p) => /Contas de teste/.test(p)));
    assert.ok(authz.cwe.includes(862));
    assert.ok(authz.asvs.length > 0);
    assert.equal(authz.attestation.validityDays, VALIDITY_DAYS.critical);
    assert.equal(authz.attestation.highNeedsReviewer, true);
    const status = { schemaVersion: 1, attestations: { ...authz.attestation.json } };
    assert.deepEqual(validateStatus(status), [], 'o trecho de atestação passa no validador do kit');
    assert.equal(authz.attestation.json['AUTH-027'].collectedAt, '2026-11-12');
    assert.equal(authz.attestation.json['AUTH-027'].expiresAt, '2027-05-11');
    const segredo = pb.items.find((i) => i.id === 'CORE-022');
    assert.ok(segredo.prereqs.some((p) => /Nunca copie um segredo real/.test(p)));
    assert.equal(buildPlaybook(rep, cat, { now: NOW, scope: 'auth' }).items.every((i) => i.pack === 'auth'), true);
    assert.deepEqual(buildPlaybook(rep, cat, { now: NOW, only: ['CORE-014'] }).items.map((i) => i.id), ['CORE-014']);
  } finally { cleanup(root); }
});

test('playbook: atestação vigente tira o controle da lista, e --all o traz de volta', async () => {
  const root = project();
  try {
    fs.writeFileSync(path.join(root, '.lastro', 'status.json'), JSON.stringify({ schemaVersion: 1, attestations: { 'CORE-014': { state: 'verified', attestedBy: 'Fulano', collectedAt: '2026-11-01', expiresAt: '2027-05-01' } } }));
    const rep = await runCheck({ root, now: NOW });
    assert.ok(!buildPlaybook(rep, cat, { now: NOW }).items.some((i) => i.id === 'CORE-014'));
    assert.ok(buildPlaybook(rep, cat, { now: NOW, all: true }).items.some((i) => i.id === 'CORE-014' && i.state === 'verified'));
  } finally { cleanup(root); }
});

test('playbook: Markdown e HTML com regras, lista, roteiros, checagens, evidência, correção e registro; HTML sem script nem link externo', async () => {
  const root = project();
  try {
    const rep = await runCheck({ root, now: NOW });
    const pb = buildPlaybook(rep, cat, { now: NOW, scope: 'auth' });
    const md = formatPlaybookMarkdown(pb);
    for (const s of ['# Playbook de verificação', '## Regras para todos os testes', 'Nunca em produção', '## Lista de verificação', '## Roteiros', '**Antes de começar**', '**Passo a passo**', '**Resultado esperado (para passar)**', '- [ ] ', '**Evidência a guardar**', '**Se falhar**', '**Como registrar**', '"AUTH-027": {', '[CWE-862](https://cwe.mitre.org/data/definitions/862.html)']) assert.ok(md.includes(s), `faltou no Markdown: ${s}`);
    const html = formatPlaybookHtml(pb);
    for (const s of ['<title>Playbook de verificação:', 'id="pb-AUTH-027"', '<ol>', '<pre><code>', 'Como registrar']) assert.ok(html.includes(s), `faltou no HTML: ${s}`);
    assert.ok(!/<script|<link|<iframe|<img/i.test(html));
    assert.deepEqual(badHrefs(html), []);
  } finally { cleanup(root); }
});

test('CLI playbook: grava Markdown e HTML, recusa escopo desconhecido e tema fora do HTML, e aplica a redação', () => {
  const root = project();
  try {
    let r = spawnSync(process.execPath, [CLI, 'playbook', '--root', root, '--scope', 'auth', '--out', path.join(root, 'pb.md')], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Playbook de "teste": \d+ controle/);
    assert.ok(fs.readFileSync(path.join(root, 'pb.md'), 'utf8').startsWith('# Playbook de verificação: teste'));
    r = spawnSync(process.execPath, [CLI, 'playbook', '--root', root, '--out', path.join(root, 'pb.html'), '--redact', 'teste'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!/Playbook de verificação: teste/.test(fs.readFileSync(path.join(root, 'pb.html'), 'utf8')));
    assert.equal(spawnSync(process.execPath, [CLI, 'playbook', '--root', root, '--scope', 'banana'], { encoding: 'utf8' }).status, 3);
    assert.equal(spawnSync(process.execPath, [CLI, 'playbook', '--root', root, '--theme', 'x.css'], { encoding: 'utf8' }).status, 3);
  } finally { cleanup(root); }
});
