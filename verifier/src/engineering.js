'use strict';

// Fatos de engenharia observáveis no repositório. Não entram na pontuação: o kit não mede "qualidade de código"
// com uma nota. Ele mostra indícios objetivos (testes, CI, ferramentas, tamanho dos arquivos, documentação)
// para a conversa sobre manutenção e revisão, e deixa o julgamento para as pessoas.

const path = require('node:path');

const SOURCE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.rb', '.php', '.go', '.java', '.cs']);
const TEST_PATH = /(^|\/)(tests?|__tests__|specs?|e2e)\/|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$|Test\.java$/;
const LINT_CONFIG = /(^|\/)(\.eslintrc(\.[\w]+)?|eslint\.config\.[cm]?js|biome\.jsonc?|\.prettierrc[\w.]*|ruff\.toml|\.flake8|\.pylintrc|\.golangci\.ya?ml|\.editorconfig)$/;
const TYPE_CONFIG = /(^|\/)(tsconfig[\w.]*\.json|mypy\.ini|pyrightconfig\.json|jsconfig\.json)$/;
const RUNS_TESTS = /\b(npm (run )?test|yarn test|pnpm test|jest|vitest|mocha|node --test|pytest|go test|cargo test|mvn( -\w+)* test|gradle test|dotnet test|rspec|phpunit)\b/i;
const RUNS_LINT = /\b(npm run lint|yarn lint|pnpm lint|eslint|biome (check|lint)|ruff|flake8|pylint|golangci-lint)\b/i;
const BIG_FILE_LINES = 2000;
const LOW_TEST_RATIO = 15;
const hasFile = (files, re) => files.some((f) => re.test(f));

function countLines(text) {
  if (text === null || text === '') return 0;
  let n = 1;
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) n += 1;
  return text.endsWith('\n') ? n - 1 : n;
}

function engineeringFacts(ctx) {
  const files = ctx.files;
  const isSource = (f) => SOURCE_EXT.has(path.extname(f).toLowerCase()) && !/\.min\./.test(f);
  const testFiles = files.filter((f) => isSource(f) && TEST_PATH.test(f));
  const sourceFiles = files.filter((f) => isSource(f) && !TEST_PATH.test(f));

  const sized = (list) => list.map((f) => ({ file: f, lines: countLines(ctx.read(f)) }));
  const sourceSized = sized(sourceFiles);
  const testSized = sized(testFiles);
  const sourceLines = sourceSized.reduce((s, x) => s + x.lines, 0);
  const testLines = testSized.reduce((s, x) => s + x.lines, 0);
  const largest = [...sourceSized].sort((a, b) => b.lines - a.lines).slice(0, 3).filter((x) => x.lines > 0);
  const testToSourcePct = sourceLines === 0 ? 0 : Math.round((testLines / sourceLines) * 1000) / 10;

  const workflows = files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f));
  const workflowText = workflows.map((f) => ctx.read(f) || '').join('\n');

  let pkg = null;
  try { pkg = JSON.parse(ctx.read('package.json') || 'null'); } catch (e) { pkg = null; }
  const scripts = (pkg && pkg.scripts) || {};

  const facts = {
    sourceFiles: sourceFiles.length,
    sourceLines,
    largest,
    testFiles: testFiles.length,
    testLines,
    testToSourcePct,
    ci: { workflows: workflows.length, runsTests: RUNS_TESTS.test(workflowText), runsLint: RUNS_LINT.test(workflowText) },
    tooling: {
      testScript: !!scripts.test,
      lintScript: !!scripts.lint,
      lintConfig: hasFile(files, LINT_CONFIG),
      typeConfig: hasFile(files, TYPE_CONFIG),
      lockfile: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'uv.lock', 'go.sum', 'Cargo.lock'].some((f) => ctx.has(f)),
    },
    docs: {
      readme: files.some((f) => /^README(\.\w+)?$/i.test(f)),
      architecture: files.some((f) => /(^|\/)ARCHITECTURE(\.\w+)?$/i.test(f)),
      changelog: files.some((f) => /^CHANGELOG(\.\w+)?$/i.test(f)),
      license: files.some((f) => /^LICENSE(\.\w+)?$/i.test(f)),
      docsFolder: files.some((f) => f.startsWith('docs/')),
    },
    dependencies: { prod: pkg ? Object.keys(pkg.dependencies || {}).length : null, dev: pkg ? Object.keys(pkg.devDependencies || {}).length : null },
    observations: [],
  };

  const o = facts.observations;
  if (sourceFiles.length === 0) o.push('Nenhum arquivo de código-fonte reconhecido (JavaScript, TypeScript, Python, Go, Java, C#, PHP, Ruby).');
  for (const big of largest.filter((x) => x.lines > BIG_FILE_LINES)) {
    o.push(`${big.file} tem ${big.lines} linhas: arquivos muito grandes são difíceis de revisar e de testar por partes.`);
  }
  if (sourceFiles.length > 0 && testFiles.length === 0) o.push('Nenhum arquivo de teste encontrado.');
  else if (testFiles.length > 0 && testToSourcePct < LOW_TEST_RATIO) o.push(`O código de teste equivale a ${String(testToSourcePct).replace('.', ',')}% do código-fonte: volume pequeno, o que costuma indicar áreas sem cobertura.`);
  if (testFiles.length > 0 && workflows.length > 0 && !facts.ci.runsTests) o.push('Há testes e CI, mas nenhum workflow parece executar os testes.');
  if (workflows.length === 0) o.push('Nenhum workflow de CI do GitHub Actions encontrado (outros CIs não são analisados).');
  if (sourceFiles.length > 0 && !facts.tooling.lintConfig && !facts.tooling.lintScript) o.push('Nenhuma configuração de lint ou formatação encontrada.');
  if (!facts.tooling.lockfile && pkg) o.push('Há package.json sem lockfile.');
  if (!facts.docs.readme) o.push('Sem README.');
  return facts;
}

const isTestPath = (file) => TEST_PATH.test(file);

module.exports = { engineeringFacts, isTestPath, BIG_FILE_LINES, LOW_TEST_RATIO };
