'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { listFiles, installKiro } = require('../src/adapter');
const { makeProject, profileJson, cleanup } = require('./helpers');

const CLI = path.join(__dirname, '..', 'bin', 'lastro.js');
const hookFile = (name) => listFiles('kiro', 'hooks').find((f) => f.name === name).file;
const frontMatter = (t) => (t.startsWith('---\n') ? t.slice(4, t.indexOf('\n---', 4)) : null);
const field = (fm, k) => { const m = new RegExp(`^${k}:\\s*(.+)$`, 'm').exec(fm); return m ? m[1].trim() : null; };
// A neutralidade (nenhum nome de empresa) de todos os arquivos do adaptador é conferida em scope-adapter.test.js.
const clean = (t, name) => {
  assert.ok(!/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/.test(t), `${name}: caractere oculto`);
  assert.ok(!/[A-Za-z]:\\Users\\|\/home\/[a-z]/i.test(t), `${name}: caminho pessoal`);
};

test('agente LASTRO: front matter válido para o IDE (sem "hooks"), recursos de steering e skills, e publicação negada', () => {
  const [agent] = listFiles('kiro', 'agents');
  assert.equal(agent.name, 'lastro.md');
  const t = fs.readFileSync(agent.file, 'utf8');
  clean(t, agent.name);
  const fm = frontMatter(t);
  assert.ok(fm, 'front matter no início');
  assert.equal(field(fm, 'name'), 'lastro');
  assert.ok(field(fm, 'description').length > 40);
  assert.ok(!/^hooks:/m.test(fm), 'o IDE ignora agente com o campo hooks');
  for (const r of ['file://.kiro/steering/**/*.md', 'skill://.kiro/skills/**/SKILL.md']) assert.ok(fm.includes(r), r);
  assert.match(fm, /effect: deny/);
  for (const c of ['git push*', 'gh pr create*', 'gh pr merge*']) assert.ok(fm.includes(`"${c}"`), c);
  for (const s of ['lastro-requisitos', 'lastro-triagem', 'lastro-corrigir', 'lastro-testes', 'lastro-pr', 'lastro-revisao-ameacas']) assert.ok(t.includes(s), `o agente cita ${s}`);
});

test('skills: nome igual à pasta, minúsculas, descrição dentro do limite e sem caractere oculto', () => {
  const skills = listFiles('kiro', 'skills');
  assert.deepEqual(skills.map((s) => s.name.split('/')[0]), ['lastro-corrigir', 'lastro-pr', 'lastro-requisitos', 'lastro-testes', 'lastro-triagem']);
  for (const s of skills) {
    const t = fs.readFileSync(s.file, 'utf8');
    clean(t, s.name);
    const fm = frontMatter(t);
    assert.ok(fm, `${s.name}: front matter`);
    const name = field(fm, 'name');
    assert.equal(name, s.name.split('/')[0], `${s.name}: name igual à pasta`);
    assert.match(name, /^[a-z0-9-]{1,64}$/);
    const desc = field(fm, 'description');
    assert.ok(desc && desc.length >= 40 && desc.length <= 1024, `${s.name}: descrição de 40 a 1024 caracteres`);
    assert.match(desc, /Use quando/, `${s.name}: a descrição diz quando usar (o Kiro ativa pela descrição)`);
  }
});

test('adaptador: instala agente, skills e hooks novos sem sobrescrever nada', () => {
  const root = makeProject({ '.lastro/profile.json': profileJson({}), '.kiro/skills/lastro-pr/SKILL.md': 'minha skill\n' });
  try {
    const plan = installKiro(root);
    assert.ok(plan.created.includes(path.join('agents', 'lastro.md')));
    assert.ok(plan.created.includes(path.join('skills', 'lastro-requisitos', 'SKILL.md')));
    assert.ok(plan.skipped.includes(path.join('skills', 'lastro-pr', 'SKILL.md')));
    assert.ok(!fs.existsSync(path.join(root, '.kiro', 'agents')));
    installKiro(root, { write: true });
    for (const f of ['agents/lastro.md', 'skills/lastro-testes/SKILL.md', 'hooks/lastro-publish.json', 'hooks/lastro-publish.js', 'hooks/lastro-stop.json', 'hooks/lastro-stop.js']) assert.ok(fs.existsSync(path.join(root, '.kiro', f)), f);
    assert.equal(fs.readFileSync(path.join(root, '.kiro', 'skills', 'lastro-pr', 'SKILL.md'), 'utf8'), 'minha skill\n');
  } finally { cleanup(root); }
});

test('hooks: formato v1, gatilhos certos e nenhum acesso a rede (o próprio AG-006 confere)', async () => {
  for (const name of ['lastro-publish.json', 'lastro-stop.json']) {
    const cfg = JSON.parse(fs.readFileSync(hookFile(name), 'utf8'));
    assert.equal(cfg.version, 'v1', name);
    assert.ok(cfg.hooks[0].name && cfg.hooks[0].action.type === 'command', name);
  }
  assert.equal(JSON.parse(fs.readFileSync(hookFile('lastro-publish.json'), 'utf8')).hooks[0].trigger, 'PreToolUse');
  assert.equal(JSON.parse(fs.readFileSync(hookFile('lastro-publish.json'), 'utf8')).hooks[0].matcher, 'shell');
  assert.equal(JSON.parse(fs.readFileSync(hookFile('lastro-stop.json'), 'utf8')).hooks[0].trigger, 'Stop');
  const root = makeProject({ '.lastro/profile.json': profileJson({ aiCodingAgents: true }) });
  try {
    installKiro(root, { write: true });
    const r = spawnSync(process.execPath, [CLI, 'check', '--root', root, '--only', 'AG-006', '--json', '--allow-incomplete'], { encoding: 'utf8' });
    const ag = JSON.parse(r.stdout).controls.find((c) => c.id === 'AG-006');
    assert.equal(ag.state, 'verified', JSON.stringify(ag.findings));
  } finally { cleanup(root); }
});

test('hook de publicação: bloqueia push, PR, merge, release e publish do agente; deixa o resto passar', () => {
  const run = (payload) => spawnSync(process.execPath, [hookFile('lastro-publish.js')], { input: typeof payload === 'string' ? payload : JSON.stringify(payload), encoding: 'utf8' });
  const shell = (command) => ({ hook_event_name: 'PreToolUse', tool_name: 'execute_pwsh', tool_input: { command } });
  for (const cmd of ['git push origin main', 'git push -u origin lastro/fix-1', 'git -c user.name=x push', 'git add . && git commit -m x && git push', 'gh pr create --title x', 'gh pr merge 12', 'gh release create v1', 'npm publish', 'gh api repos/o/r/pulls -f title=x']) {
    const r = run(shell(cmd));
    assert.equal(r.status, 2, cmd);
    assert.match(r.stderr, /o agente não publica/, cmd);
  }
  for (const cmd of ['git status', 'git stash push -m wip', 'git diff', 'npm test', 'node verifier/bin/lastro.js fix --write', 'gh pr view 12', 'git log --oneline']) {
    const r = run(shell(cmd));
    assert.equal(r.status, 0, cmd);
    assert.equal(r.stderr, '', cmd);
  }
  assert.equal(run('texto solto com git push origin').status, 2, 'entrada fora do formato ainda é conferida');
  assert.equal(run('').status, 0);
});

test('hook de fim (Stop): lembra uma vez por sessão quando há achado bloqueante e fica quieto no resto', () => {
  const { main, sessionMarker } = require(hookFile('lastro-stop.js'));
  const env = { LASTRO_CLI: CLI };
  const ruim = makeProject({ '.lastro/profile.json': profileJson({}), 'src/a.js': 'const o = { rejectUnauthorized: false };\n' });
  const bom = makeProject({ '.lastro/profile.json': profileJson({}), 'src/a.js': 'const x = 1;\n' });
  const semPerfil = makeProject({ 'src/a.js': 'const o = { rejectUnauthorized: false };\n' });
  const sid = `teste-${process.pid}-${Date.now()}`;
  // Projeto "bom": a dívida que já existe (sem CI, sem modelo de ameaças) está no baseline, então não há achado NOVO.
  const base = spawnSync(process.execPath, [CLI, 'baseline', '--write', '--root', bom], { encoding: 'utf8' });
  assert.equal(base.status, 0, base.stderr);
  try {
    const first = main(JSON.stringify({ hook_event_name: 'Stop', session_id: sid, cwd: ruim }), env);
    assert.equal(first.decision, 'block');
    assert.match(first.reason, /\[CORE-007\] high/);
    assert.match(first.reason, /Não aceite risco nem grave baseline/);
    assert.equal(main(JSON.stringify({ session_id: sid, cwd: ruim }), env), null, 'segunda vez na mesma sessão: não bloqueia de novo');
    assert.equal(main(JSON.stringify({ session_id: `${sid}-b`, cwd: bom }), env), null, 'sem achado bloqueante');
    assert.equal(main(JSON.stringify({ session_id: `${sid}-c`, cwd: semPerfil }), env), null, 'sem perfil');
    assert.equal(main(JSON.stringify({ session_id: `${sid}-d`, cwd: ruim }), {}), null, 'sem CLI encontrado');
    assert.equal(main('não é json', env, bom), null);
  } finally {
    for (const s of [sid, `${sid}-b`, `${sid}-c`, `${sid}-d`]) for (const r of [ruim, bom, semPerfil]) fs.rmSync(sessionMarker(s, r), { force: true });
    cleanup(ruim); cleanup(bom); cleanup(semPerfil);
  }
  assert.ok(os.tmpdir());
});
