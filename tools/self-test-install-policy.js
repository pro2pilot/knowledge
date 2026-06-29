#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { spawnSync } = require('child_process');

const sourceRoot = path.resolve(__dirname, '..');
const cyrillic = '\u043a\u0438\u0440\u0438\u043b\u043b\u0438\u0446\u0430';
const childTimeoutMs = Number(process.env.KNOWLEDGE_SELF_TEST_CHILD_TIMEOUT_MS || 120000);
const gitTimeoutMs = Number(process.env.KNOWLEDGE_SELF_TEST_GIT_TIMEOUT_MS || 30000);

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function rmDir(dirPath) {
  fs.rmSync(dirPath, { recursive: true, force: true });
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function runNode(args, cwd, env = {}) {
  const res = spawnSync(process.execPath, args, {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: Number.isFinite(childTimeoutMs) ? childTimeoutMs : 120000,
    windowsHide: true
  });
  return {
    command: `node ${args.join(' ')}`,
    cwd,
    exit: res.status,
    signal: res.signal || null,
    error: res.error ? { code: res.error.code, message: res.error.message } : null,
    timed_out: res.error?.code === 'ETIMEDOUT',
    stdout: (res.stdout || '').trim(),
    stderr: (res.stderr || '').trim()
  };
}

function runGit(args, cwd) {
  const res = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    timeout: Number.isFinite(gitTimeoutMs) ? gitTimeoutMs : 30000,
    windowsHide: true
  });
  return {
    command: `git ${args.join(' ')}`,
    cwd,
    exit: res.status,
    signal: res.signal || null,
    error: res.error ? { code: res.error.code, message: res.error.message } : null,
    timed_out: res.error?.code === 'ETIMEDOUT',
    stdout: (res.stdout || '').trim(),
    stderr: (res.stderr || '').trim()
  };
}

function initGitRepo(repo) {
  const res = runGit(['init'], repo);
  assert(res.exit === 0, 'git init failed in self-test repo.', res);
}

function parseJsonResult(result) {
  try { return JSON.parse(result.stdout || '{}'); }
  catch (error) {
    throw new Error(`${result.command} did not return JSON: ${error.message}\n${result.stdout}\n${result.stderr}`);
  }
}

function assert(condition, message, details = {}) {
  if (!condition) {
    const error = new Error(message);
    error.details = details;
    throw error;
  }
}

function findEndOfCentralDirectory(buffer) {
  for (let i = buffer.length - 22; i >= 0; i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) return i;
  }
  throw new Error('ZIP end of central directory not found.');
}

function safeOutputPath(dest, entryName) {
  const target = path.resolve(dest, ...normalizeRel(entryName).split('/'));
  const root = path.resolve(dest);
  if (target !== root && !target.startsWith(root + path.sep)) throw new Error(`Unsafe zip entry path: ${entryName}`);
  return target;
}

function extractZip(zipPath, dest) {
  ensureDir(dest);
  const buffer = fs.readFileSync(zipPath);
  const eocd = findEndOfCentralDirectory(buffer);
  const entries = buffer.readUInt16LE(eocd + 10);
  let ptr = buffer.readUInt32LE(eocd + 16);
  const names = [];
  for (let i = 0; i < entries; i += 1) {
    assert(buffer.readUInt32LE(ptr) === 0x02014b50, 'Invalid central directory header.', { ptr });
    const method = buffer.readUInt16LE(ptr + 10);
    const compressedSize = buffer.readUInt32LE(ptr + 20);
    const nameLength = buffer.readUInt16LE(ptr + 28);
    const extraLength = buffer.readUInt16LE(ptr + 30);
    const commentLength = buffer.readUInt16LE(ptr + 32);
    const localOffset = buffer.readUInt32LE(ptr + 42);
    const name = buffer.slice(ptr + 46, ptr + 46 + nameLength).toString('utf8');
    names.push(name);

    assert(buffer.readUInt32LE(localOffset) === 0x04034b50, 'Invalid local file header.', { name });
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.slice(dataStart, dataStart + compressedSize);
    const data = method === 0 ? compressed : zlib.inflateRawSync(compressed);
    const outPath = safeOutputPath(dest, name);
    if (name.endsWith('/')) ensureDir(outPath);
    else {
      ensureDir(path.dirname(outPath));
      fs.writeFileSync(outPath, data);
    }
    ptr += 46 + nameLength + extraLength + commentLength;
  }
  return names;
}

function tempRoot() {
  const base = path.join(sourceRoot, '.self-test-tmp');
  ensureDir(base);
  return fs.mkdtempSync(path.join(base, `knowledge install policy ${cyrillic} `));
}

function record(results, name, fn) {
  try {
    const details = fn();
    results.push({ name, status: 'pass', details });
  } catch (error) {
    results.push({ name, status: 'fail', message: error.message, details: error.details || null });
  }
}

function stagedFiles(repo) {
  const staged = runGit(['diff', '--cached', '--name-only'], repo);
  assert(staged.exit === 0, 'git diff --cached failed.', staged);
  return staged.stdout ? staged.stdout.split(/\r?\n/).filter(Boolean).map(normalizeRel) : [];
}

function generatedOrRuntime(file) {
  return (
    file === '.knowledge/project_index.json' ||
    file === '.knowledge/freshness.json' ||
    file.startsWith('.knowledge/maintenance/flow-logs/') ||
    file.startsWith('.knowledge/maintenance/events/') ||
    file.startsWith('.knowledge/maintenance/install-backups/') ||
    file === '.knowledge/maintenance/install_check_report.json' ||
    file === '.knowledge/maintenance/update_system_files_report.json' ||
    file === '.knowledge/maintenance/update_status.json' ||
    file === '.knowledge/maintenance/routing_bundle.json' ||
    file === '.knowledge/maintenance/trust_report.json' ||
    file === '.knowledge/maintenance/quality_report.json' ||
    file === '.knowledge/maintenance/wiki_lint_report.json' ||
    file === '.knowledge/maintenance/external_memory_status.json' ||
    file === '.knowledge/maintenance/secret_scan_report.json' ||
    file === '.knowledge/maintenance/pr_summary.md' ||
    file === '.knowledge/maintenance/sync_log.json' ||
    file === '.knowledge/maintenance/stale_items.json' ||
    file === '.knowledge/maintenance/repair_queue.json' ||
    file === '.knowledge/maintenance/automation_status.json' ||
    file === '.knowledge/maintenance/handoff_summary.json' ||
    file.startsWith('.knowledge/maintenance/graphs/') ||
    file === '.knowledge/search/index.json' ||
    file.startsWith('.knowledge/inspector/') ||
    file.startsWith('.knowledge/metrics/') ||
    file === '.knowledge/maps/wiki_graph.json' ||
    file === '.knowledge/maps/file_criticality.json' ||
    file === '.knowledge/maps/dependency_map.json' ||
    file === '.knowledge/maps/directory_map.json' ||
    file === '.knowledge/maps/entrypoints.json' ||
    file.startsWith('.knowledge/evaluation/results/') ||
    file.includes('.tmp-') ||
    file.includes('.bak-') ||
    file.startsWith('.knowledge/.lock/') ||
    file.startsWith('.knowledge/.runtime/')
  );
}

function countManagedBlocks(text) {
  const legacyMarker = ['KNOWLEDGE', 'KIT'].join('-');
  return (text.match(new RegExp(`<!-- BEGIN (?:DOT-KNOWLEDGE|${legacyMarker}) MANAGED BLOCK -->`, 'g')) || []).length;
}

function removeKnowledgePaths(repo, relPaths) {
  for (const relPath of relPaths) rmDir(path.join(repo, '.knowledge', relPath));
}

const runtimeExpectations = {
  codex: ['AGENTS.md', '.agents/skills/kb-metrics/SKILL.md'],
  claude: ['CLAUDE.md', '.claude/skills/kb-metrics/SKILL.md'],
  opencode: ['.opencode/commands/kb-metrics.md'],
  gemini: ['GEMINI.md'],
  copilot: ['.github/copilot-instructions.md'],
  devin: ['.devin/rules/knowledge.md'],
  windsurf: ['.devin/rules/knowledge.md'],
  continue: ['.continue/rules/knowledge.md'],
  roo: ['.roo/rules/knowledge.md'],
  aider: ['CONVENTIONS.md', '.aider.conf.yml']
};

const allIntegrationPaths = Array.from(new Set(Object.values(runtimeExpectations).flat()));

function existsRel(repo, relPath) {
  return fs.existsSync(path.join(repo, relPath));
}

function gitattributesText(repo) {
  return fs.existsSync(path.join(repo, '.gitattributes')) ? fs.readFileSync(path.join(repo, '.gitattributes'), 'utf8') : '';
}

function attrPattern(relPath) {
  if (relPath.startsWith('.agents/skills/')) return '.agents/skills/**';
  if (relPath.startsWith('.claude/skills/')) return '.claude/skills/**';
  if (relPath.startsWith('.opencode/commands/')) return '.opencode/commands/**';
  return relPath;
}

function assertRuntimeOnly(repo, runtime) {
  const expected = runtimeExpectations[runtime];
  const missing = expected.filter((relPath) => !existsRel(repo, relPath));
  assert(missing.length === 0, `${runtime} integration did not create expected files.`, { missing, expected });
  const unexpected = allIntegrationPaths.filter((relPath) => !expected.includes(relPath) && existsRel(repo, relPath));
  assert(unexpected.length === 0, `${runtime} integration created unrelated agent files.`, { unexpected, expected });
  const attrs = gitattributesText(repo);
  const attrMissing = expected.filter((relPath) => !attrs.includes(attrPattern(relPath)));
  assert(attrMissing.length === 0, `${runtime} .gitattributes is missing expected paths.`, { attrMissing, attrs });
  const attrUnexpected = allIntegrationPaths.filter((relPath) => {
    if (expected.includes(relPath)) return false;
    return attrs.includes(attrPattern(relPath));
  });
  assert(attrUnexpected.length === 0, `${runtime} .gitattributes contains unrelated runtime paths.`, { attrUnexpected, attrs });
  return { expected };
}

function assertInstalledSystemComplete(repo) {
  const manifest = readJson(path.join(sourceRoot, 'install-manifest.json'));
  const missingTopLevel = manifest.system_paths.filter((relPath) => !fs.existsSync(path.join(repo, '.knowledge', relPath)));
  const keyFiles = [
    'install-manifest.json',
    'memory-providers/mem0/manifest.json',
    'memory-providers/pinecone/manifest.json',
    'benchmarks/run-benchmarks.js',
    '.release-notes/v3.2.1.md',
    '.gitignore',
    '.gitattributes',
    'inspector.js',
    'open-inspector.vbs',
    'assets/knowledge-trust-gate-light-readme.svg',
    'agent-integrations/codex/skills/kb-repair-trust/SKILL.md',
    'agent-integrations/claude/skills/kb-repair-trust/SKILL.md',
    'CHANGELOG.md',
    'RELEASE_NOTES.md',
    'SECURITY.md',
    'SBOM.memory.json',
    'THIRD_PARTY_NOTICES.md',
    'tools/lib/python-discovery.js'
  ];
  const missingKeyFiles = keyFiles.filter((relPath) => !fs.existsSync(path.join(repo, '.knowledge', relPath)));
  assert(missingTopLevel.length === 0 && missingKeyFiles.length === 0, 'Installed system paths are incomplete.', { missingTopLevel, missingKeyFiles });
  return { system_paths_checked: manifest.system_paths.length, key_files_checked: keyFiles.length };
}

function main(argv = process.argv.slice(2)) {
  const keep = argv.includes('--keep');
  const results = [];
  const root = tempRoot();
  let packageSummary = null;

  try {
    record(results, 'package artifact has .knowledge root and no source metadata', () => {
      const packaged = runNode(['tools/package-release.js', '--json'], sourceRoot);
      assert(packaged.exit === 0, 'package-release failed.', packaged);
      packageSummary = parseJsonResult(packaged);
      const entries = extractZip(packageSummary.output_path, path.join(root, 'artifact-inspect'));
      assert(Number.isInteger(packageSummary.excluded_entries_count), 'package-release summary is missing excluded_entries_count.', packageSummary);
      assert(Number.isInteger(packageSummary.excluded_files_count), 'package-release summary is missing excluded_files_count.', packageSummary);
      assert(entries.every((entry) => entry.startsWith('.knowledge/')), 'Artifact contains entries outside .knowledge/.', { entries: entries.slice(0, 20) });
      assert(entries.includes('.knowledge/.gitignore'), 'Artifact does not contain installed .knowledge/.gitignore.', {});
      assert(entries.includes('.knowledge/install-manifest.json'), 'Artifact does not contain install-manifest.json.', {});
      assert(entries.includes('.knowledge/memory-providers/mem0/manifest.json'), 'Artifact does not contain Mem0 provider manifest.', {});
      assert(entries.includes('.knowledge/memory-providers/pinecone/manifest.json'), 'Artifact does not contain Pinecone provider manifest.', {});
      assert(entries.includes('.knowledge/benchmarks/run-benchmarks.js'), 'Artifact does not contain benchmark runner.', {});
      assert(!entries.some((entry) => /(^|\/)\.git(\/|$)/.test(entry)), 'Artifact contains Git metadata.', {});
      assert(!entries.some((entry) => entry.startsWith('.knowledge/.github/')), 'Artifact contains source .github metadata.', {});
      return { output_path: packageSummary.output_path, entries: entries.length };
    });

    record(results, 'package artifact normalizes text files to LF', () => {
      const repo = path.join(root, 'lf artifact repo');
      ensureDir(repo);
      extractZip(packageSummary.output_path, repo);
      const textFiles = [
        '.knowledge/.gitignore',
        '.knowledge/README.md',
        '.knowledge/Quick-Start.md',
        '.knowledge/tools/package-release.js',
        '.knowledge/tools/install-check.js',
        '.knowledge/templates/git-policy/.knowledge.gitignore'
      ];
      const withCrLf = textFiles.filter((file) => fs.readFileSync(path.join(repo, file), 'utf8').includes('\r'));
      assert(withCrLf.length === 0, 'Packaged text files contain CR or CRLF line endings.', { withCrLf });
      return { checked: textFiles.length };
    });

    record(results, 'source and installed gitignore policies are separated', () => {
      const sourceIgnore = fs.readFileSync(path.join(sourceRoot, '.gitignore'), 'utf8');
      const templateIgnore = fs.readFileSync(path.join(sourceRoot, 'templates', 'git-policy', '.knowledge.gitignore'), 'utf8');
      assert(!/(^|\r?\n)\.github\/(\r?\n|$)/.test(sourceIgnore), 'Source .gitignore must not ignore .github/.', {});
      assert(/(^|\r?\n)\.github\/(\r?\n|$)/.test(templateIgnore), 'Installed .knowledge.gitignore should protect against accidental .knowledge/.github.', {});
      return { source_allows_github: true, installed_ignores_github: true };
    });

    record(results, 'fresh install passes install-check and uses template .gitignore', () => {
      const repo = path.join(root, 'fresh repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'fresh-repo', private: true });
      const installedIgnore = fs.readFileSync(path.join(repo, '.knowledge', '.gitignore'), 'utf8');
      const templateIgnore = fs.readFileSync(path.join(sourceRoot, 'templates', 'git-policy', '.knowledge.gitignore'), 'utf8');
      assert(installedIgnore === templateIgnore, 'Installed .knowledge/.gitignore does not match template.', {});
      const check = runNode(['.knowledge/tools/install-check.js', '--json'], repo);
      const parsed = parseJsonResult(check);
      assert(check.exit === 0, 'install-check failed on fresh install.', { check, parsed });
      assert(parsed.status === 'ok' && parsed.mode === 'fresh', 'Fresh install should be ok/fresh.', parsed);
      return { status: parsed.status, mode: parsed.mode };
    });

    record(results, 'nested .knowledge/.git is detected and fixed with consistent report', () => {
      const repo = path.join(root, 'bad nested git repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'bad-repo', private: true });
      writeJson(path.join(repo, '.knowledge', 'decisions.json'), { custom: 'preserve-me' });
      ensureDir(path.join(repo, '.knowledge', '.git'));
      fs.writeFileSync(path.join(repo, '.knowledge', '.git', 'HEAD'), 'ref: refs/heads/main\n', 'utf8');
      const bad = runNode(['.knowledge/tools/install-check.js', '--json'], repo);
      const badJson = parseJsonResult(bad);
      assert(bad.exit !== 0 && badJson.status === 'failed', 'Nested .git should fail install-check.', badJson);
      const fixed = runNode(['.knowledge/tools/install-check.js', '--fix', '--yes'], repo);
      const fixedJson = parseJsonResult(fixed);
      const reportJson = readJson(path.join(repo, '.knowledge', 'maintenance', 'install_check_report.json'));
      assert(!fs.existsSync(path.join(repo, '.knowledge', '.git')), 'Nested .git still exists after fix.', fixedJson);
      assert(fixedJson.status === 'ok' && fixedJson.post_fix?.status === 'ok', 'Console fix output does not show post-fix ok status.', fixedJson);
      assert(reportJson.status === 'ok' && reportJson.post_fix?.status === 'ok', 'Install-check report does not show post-fix ok status.', reportJson);
      assert(reportJson.pre_fix?.status === 'failed', 'Install-check report is missing failed pre_fix.', reportJson);
      assert(JSON.stringify(reportJson.fixes_applied) === JSON.stringify(fixedJson.fixes_applied), 'Console output and report fixes_applied differ.', { console: fixedJson.fixes_applied, report: reportJson.fixes_applied });
      assert(readJson(path.join(repo, '.knowledge', 'decisions.json')).custom === 'preserve-me', 'Project knowledge was modified by install-check fix.', {});
      return { before: badJson.status, after: fixedJson.status, report_post_fix: reportJson.post_fix.status, fixes_applied: fixedJson.fixes_applied };
    });

    record(results, '.knowledge/.github is diagnosed as copied source repo', () => {
      const repo = path.join(root, 'bad github diagnostic repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'bad-github-repo', private: true });
      ensureDir(path.join(repo, '.knowledge', '.github', 'workflows'));
      fs.writeFileSync(path.join(repo, '.knowledge', '.github', 'workflows', 'bad.yml'), 'name: bad\n', 'utf8');
      const check = runNode(['.knowledge/tools/install-check.js', '--json'], repo);
      const parsed = parseJsonResult(check);
      const codes = parsed.issues.map((item) => item.code);
      assert(check.exit !== 0 && parsed.status === 'failed', '.knowledge/.github should fail install-check.', parsed);
      assert(codes.includes('source_repo_copied_into_knowledge'), '.knowledge/.github diagnostic code missing.', parsed);
      return { status: parsed.status, issue_codes: codes };
    });

    record(results, 'install-agent-integrations creates only selected runtime files', () => {
      const checked = [];
      for (const runtime of Object.keys(runtimeExpectations)) {
        const repo = path.join(root, `runtime ${runtime} repo`);
        ensureDir(repo);
        initGitRepo(repo);
        extractZip(packageSummary.output_path, repo);
        writeJson(path.join(repo, 'package.json'), { name: `runtime-${runtime}-repo`, private: true });
        const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--runtime', runtime, '--no-package-scripts'], repo);
        const parsed = parseJsonResult(integrations);
        assert(integrations.exit === 0 && parsed.status === 'ok', `${runtime} install-agent-integrations failed.`, { integrations, parsed });
        assert(parsed.mode === 'runtime' && parsed.runtimes?.includes(runtime), `${runtime} install result did not report runtime mode.`, parsed);
        checked.push({ runtime, ...assertRuntimeOnly(repo, runtime) });
        const rerun = runNode(['.knowledge/tools/install-agent-integrations.js', '--runtime', runtime, '--no-package-scripts'], repo);
        const rerunParsed = parseJsonResult(rerun);
        assert(rerun.exit === 0 && rerunParsed.status === 'ok', `${runtime} rerun failed.`, { rerun, rerunParsed });
        for (const relPath of runtimeExpectations[runtime].filter((item) => item.endsWith('.md') && !item.startsWith('.agents/skills/') && !item.startsWith('.claude/skills/') && !item.startsWith('.opencode/commands/'))) {
          const text = fs.readFileSync(path.join(repo, relPath), 'utf8');
          assert(countManagedBlocks(text) === 1, `${runtime} rerun duplicated managed block in ${relPath}.`, { relPath, text });
        }
      }
      return { runtimes_checked: checked.map((item) => item.runtime) };
    });

    record(results, 'install-agent-integrations rejects unknown runtime without creating agent files', () => {
      const repo = path.join(root, 'unknown runtime repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'unknown-runtime-repo', private: true });
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--runtime', 'mystery', '--no-package-scripts'], repo);
      const parsed = parseJsonResult(integrations);
      assert(integrations.exit === 0 && parsed.status === 'runtime_required', 'Unknown runtime should return runtime_required.', parsed);
      const created = allIntegrationPaths.filter((relPath) => existsRel(repo, relPath));
      assert(created.length === 0, 'Unknown runtime created integration files.', { created, parsed });
      assert(!existsRel(repo, '.gitattributes'), 'Unknown runtime created .gitattributes.', { parsed });
      return { status: parsed.status, commands: parsed.commands.length };
    });

    record(results, 'install-agent-integrations --all creates the full integration set', () => {
      const repo = path.join(root, 'all runtimes repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'all-runtimes-repo', private: true });
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--all', '--no-package-scripts'], repo);
      const parsed = parseJsonResult(integrations);
      assert(integrations.exit === 0 && parsed.status === 'ok' && parsed.mode === 'all', '--all install failed.', { integrations, parsed });
      const missing = allIntegrationPaths.filter((relPath) => !existsRel(repo, relPath));
      assert(missing.length === 0, '--all did not create the full integration set.', { missing });
      const attrs = gitattributesText(repo);
      const attrMissing = allIntegrationPaths.map(attrPattern).filter((pattern, index, list) => list.indexOf(pattern) === index && !attrs.includes(pattern));
      assert(attrMissing.length === 0, '--all .gitattributes is missing integration paths.', { attrMissing, attrs });
      return { runtimes: parsed.runtimes, files_checked: allIntegrationPaths.length };
    });

    record(results, 'Quick-Start lists every supported runtime command', () => {
      const quickStart = fs.readFileSync(path.join(sourceRoot, 'Quick-Start.md'), 'utf8');
      const missing = Object.keys(runtimeExpectations)
        .map((runtime) => `node .knowledge/tools/install-agent-integrations.js --runtime ${runtime}`)
        .filter((command) => !quickStart.includes(command));
      assert(missing.length === 0, 'Quick-Start is missing runtime install commands.', { missing });
      assert(quickStart.includes('OpenClaw') && quickStart.includes('Hermes') && quickStart.includes('Pi'), 'Quick-Start is missing generic compatibility notes.', {});
      return { commands_checked: Object.keys(runtimeExpectations).length };
    });

    record(results, 'install-agent-integrations propagates final-report contract in --all mode', () => {
      const repo = path.join(root, 'integration contract repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'integration-contract-repo', private: true });
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--all'], repo);
      assert(integrations.exit === 0, 'install-agent-integrations failed for integration contract test.', integrations);
      const agentsMd = fs.readFileSync(path.join(repo, 'AGENTS.md'), 'utf8');
      const claudeMd = fs.readFileSync(path.join(repo, 'CLAUDE.md'), 'utf8');
      const codexMetrics = fs.readFileSync(path.join(repo, '.agents', 'skills', 'kb-metrics', 'SKILL.md'), 'utf8');
      const claudeMetrics = fs.readFileSync(path.join(repo, '.claude', 'skills', 'kb-metrics', 'SKILL.md'), 'utf8');
      const opencodeMetrics = fs.readFileSync(path.join(repo, '.opencode', 'commands', 'kb-metrics.md'), 'utf8');
      const opencodePrSummary = fs.readFileSync(path.join(repo, '.opencode', 'commands', 'kb-pr-summary.md'), 'utf8');
      assert(agentsMd.includes('## Final report after meaningful work'), 'AGENTS.md is missing the final-report contract.', {});
      assert(agentsMd.includes('estimated tokens saved and percent saved'), 'AGENTS.md is missing token-savings guidance.', {});
      assert(claudeMd.includes('## Final report after meaningful work'), 'CLAUDE.md is missing the final-report contract.', {});
      assert(claudeMd.includes('silently skipping token-savings reporting'), 'CLAUDE.md is missing explicit metrics-missing guidance.', {});
      assert(codexMetrics.includes('estimated tokens saved plus estimated percent saved'), 'Installed Codex metrics skill is missing token-savings guidance.', {});
      assert(claudeMetrics.includes('estimated tokens saved plus estimated percent saved'), 'Installed Claude metrics skill is missing token-savings guidance.', {});
      assert(opencodeMetrics.includes('estimated percent saved'), 'Installed OpenCode metrics command is missing token-savings guidance.', {});
      assert(opencodePrSummary.includes('metrics or token-savings status'), 'Installed OpenCode PR summary command is missing final-report guidance.', {});
      return {
        agents_contract: true,
        claude_contract: true,
        codex_metrics_contract: true,
        claude_metrics_contract: true,
        opencode_contract: true
      };
    });

    record(results, 'install-agent-integrations migrates legacy managed marker without duplicate', () => {
      const repo = path.join(root, 'legacy marker repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'legacy-marker-repo', private: true });
      const legacyMarker = ['KNOWLEDGE', 'KIT'].join('-');
      fs.writeFileSync(path.join(repo, 'AGENTS.md'), [
        '# Project agents',
        '',
        `<!-- BEGIN ${legacyMarker} MANAGED BLOCK -->`,
        'old managed body',
        `<!-- END ${legacyMarker} MANAGED BLOCK -->`,
        ''
      ].join('\n'), 'utf8');
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--runtime', 'codex'], repo);
      assert(integrations.exit === 0, 'install-agent-integrations failed for legacy marker test.', integrations);
      const agentsMd = fs.readFileSync(path.join(repo, 'AGENTS.md'), 'utf8');
      assert(countManagedBlocks(agentsMd) === 1, 'AGENTS.md has duplicate managed blocks after legacy marker migration.', { agentsMd });
      assert(agentsMd.includes('<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->'), 'AGENTS.md did not migrate to canonical marker.', {});
      assert(!agentsMd.includes(`<!-- BEGIN ${legacyMarker} MANAGED BLOCK -->`), 'AGENTS.md still contains legacy begin marker.', {});
      assert(agentsMd.includes('## Final report after meaningful work'), 'Migrated AGENTS.md is missing final-report contract.', {});
      return { managed_blocks: countManagedBlocks(agentsMd), migrated_to_dot_knowledge: true };
    });

    record(results, 'fresh install flow release and git add ignore generated runtime', () => {
      const repo = path.join(root, 'fresh flow release repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'fresh-flow-repo', private: true });
      const check = runNode(['.knowledge/tools/install-check.js', '--json'], repo);
      const checkJson = parseJsonResult(check);
      assert(check.exit === 0 && checkJson.status === 'ok', 'install-check failed before fresh flow release.', checkJson);
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--runtime', 'codex'], repo);
      assert(integrations.exit === 0, 'install-agent-integrations failed.', integrations);
      const importResult = runNode(['.knowledge/tools/flow.js', 'import', '--no-color'], repo);
      assert(importResult.exit === 0, 'flow import failed in fresh flow release test.', importResult);
      const releaseResult = runNode(['.knowledge/tools/flow.js', 'release', '--no-color'], repo);
      assert(releaseResult.exit === 0, 'flow release failed in fresh flow release test.', releaseResult);
      const add = runGit(['add', '.'], repo);
      assert(add.exit === 0, 'git add . failed in fresh flow release test.', add);
      const staged = stagedFiles(repo);
      const forbidden = staged.filter(generatedOrRuntime);
      assert(forbidden.length === 0, 'Generated/runtime artifacts were staged by git add .', { forbidden, staged_sample: staged.slice(0, 40) });
      return { staged_files: staged.length, forbidden_staged: forbidden.length };
    });

    record(results, 'existing update preserves project knowledge', () => {
      const repo = path.join(root, 'existing update repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'existing-repo', private: true });
      const importResult = runNode(['.knowledge/tools/flow.js', 'import', '--no-color'], repo);
      assert(importResult.exit === 0, 'flow import failed before update test.', importResult);
      fs.writeFileSync(path.join(repo, '.knowledge', 'wiki', 'custom.md'), '# Custom Wiki\n\nPreserve this.\n', 'utf8');
      writeJson(path.join(repo, '.knowledge', 'modules', 'custom_module.json'), { module_id: 'custom', note: 'preserve this' });
      writeJson(path.join(repo, '.knowledge', 'evidence', 'custom_evidence.json'), { facts: [{ id: 'custom', text: 'preserve this' }] });
      writeJson(path.join(repo, '.knowledge', 'decisions.json'), { decisions: [{ id: 'D-custom', text: 'preserve this' }] });
      rmDir(path.join(repo, '.knowledge', 'inspector.js'));
      const missingVerify = runNode(['.knowledge/tools/update-system-files.js', '--verify-upgrade', '--json'], repo);
      const missingVerifyJson = parseJsonResult(missingVerify);
      assert(missingVerify.exit !== 0 && missingVerifyJson.status === 'failed', 'verify-upgrade should fail when Inspector launcher is missing.', missingVerifyJson);
      assert(missingVerifyJson.verify?.checks?.some((check) => check.check === 'system_completeness' && check.missing_system_paths?.includes('inspector.js')), 'verify-upgrade should report missing Inspector launcher.', missingVerifyJson.verify);
      const dryRun = runNode(['.knowledge/tools/update-system-files.js', '--from', sourceRoot, '--dry-run'], repo);
      const dryJson = parseJsonResult(dryRun);
      assert(dryRun.exit === 0 && dryJson.status === 'ok', 'update-system-files dry-run failed.', dryJson);
      assert(dryJson.actions?.some((action) => action.action === 'create' && action.path === 'inspector.js'), 'dry-run should plan missing Inspector launcher creation.', dryJson.actions);
      const apply = runNode(['.knowledge/tools/update-system-files.js', '--from', sourceRoot, '--apply', '--yes'], repo);
      const applyJson = parseJsonResult(apply);
      assert(apply.exit === 0 && applyJson.status === 'ok', 'update-system-files apply failed.', applyJson);
      assert(applyJson.summary.curated_changed_files === 0, 'Updater changed curated project knowledge.', applyJson.summary);
      assert(applyJson.system_completeness?.status === 'ok', 'Updater left missing system paths.', applyJson.system_completeness);
      assertInstalledSystemComplete(repo);
      assert(fs.existsSync(path.join(repo, '.knowledge', 'inspector.js')), 'Updater did not install .knowledge/inspector.js.', {});
      assert(fs.readFileSync(path.join(repo, '.knowledge', 'wiki', 'custom.md'), 'utf8').includes('Preserve this'), 'Custom wiki was not preserved.', {});
      assert(readJson(path.join(repo, '.knowledge', 'modules', 'custom_module.json')).note === 'preserve this', 'Custom module was not preserved.', {});
      assert(readJson(path.join(repo, '.knowledge', 'evidence', 'custom_evidence.json')).facts[0].id === 'custom', 'Custom evidence was not preserved.', {});
      assert(readJson(path.join(repo, '.knowledge', 'decisions.json')).decisions[0].id === 'D-custom', 'decisions.json was not preserved.', {});
      const verify = runNode(['.knowledge/tools/update-system-files.js', '--verify-upgrade', '--from', sourceRoot, '--json'], repo);
      const verifyJson = parseJsonResult(verify);
      assert(verify.exit === 0 && verifyJson.status === 'ok', 'verify-upgrade failed after existing update.', verifyJson);
      return { dry_run: dryJson.summary, apply: applyJson.summary, verify: verifyJson.status };
    });

    record(results, 'bootstrap update from 3.1.8-like install without updater', () => {
      const repo = path.join(root, 'bootstrap old update repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'bootstrap-old-repo', private: true });
      const importResult = runNode(['.knowledge/tools/flow.js', 'import', '--no-color'], repo);
      assert(importResult.exit === 0, 'flow import failed before bootstrap update test.', importResult);
      fs.writeFileSync(path.join(repo, '.knowledge', 'wiki', 'custom.md'), '# Custom Wiki\n\nPreserve this.\n', 'utf8');
      writeJson(path.join(repo, '.knowledge', 'modules', 'custom_module.json'), { module_id: 'custom', note: 'preserve this' });
      writeJson(path.join(repo, '.knowledge', 'evidence', 'custom_evidence.json'), { facts: [{ id: 'custom', text: 'preserve this' }] });
      writeJson(path.join(repo, '.knowledge', 'decisions.json'), { decisions: [{ id: 'D-custom', text: 'preserve this' }] });
      writeJson(path.join(repo, '.knowledge', 'maintenance', 'external_memory_status.json'), { status: 'legacy-shape', providers: { mem0: { status: 'unknown' } } });
      removeKnowledgePaths(repo, [
        'tools/update-system-files.js',
        'install-manifest.json',
        'memory-providers',
        'benchmarks',
        'inspector.js',
        '.release-notes',
        '.gitignore',
        '.gitattributes',
        'CHANGELOG.md',
        'RELEASE_NOTES.md',
        'SECURITY.md',
        'SBOM.memory.json',
        'THIRD_PARTY_NOTICES.md',
        'external_memory/registry.json',
        'external_memory/retrieval_policy.json'
      ]);
      assert(!fs.existsSync(path.join(repo, '.knowledge', 'tools', 'update-system-files.js')), 'Old install simulation still has updater.', {});
      const apply = runNode([
        path.join(sourceRoot, 'tools', 'update-system-files.js'),
        '--from', sourceRoot,
        '--target-knowledge-root', path.join(repo, '.knowledge'),
        '--apply',
        '--yes',
        '--json'
      ], repo);
      const applyJson = parseJsonResult(apply);
      assert(apply.exit === 0 && applyJson.status === 'ok', 'bootstrap update-system-files apply failed.', applyJson);
      assert(applyJson.summary.curated_changed_files === 0, 'Bootstrap updater changed curated project knowledge.', applyJson.summary);
      assert(applyJson.summary.migration_defaults_created === 2, 'Bootstrap updater did not create missing project defaults.', applyJson.summary);
      assert(fs.existsSync(path.join(repo, '.knowledge', 'external_memory', 'registry.json')), 'Missing migrated external_memory/registry.json.', {});
      assert(fs.existsSync(path.join(repo, '.knowledge', 'external_memory', 'retrieval_policy.json')), 'Missing migrated external_memory/retrieval_policy.json.', {});
      assert(applyJson.system_completeness?.status === 'ok', 'Bootstrap updater left missing system paths.', applyJson.system_completeness);
      assertInstalledSystemComplete(repo);
      assert(fs.existsSync(path.join(repo, '.knowledge', 'inspector.js')), 'Bootstrap updater did not install .knowledge/inspector.js.', {});
      assert(fs.existsSync(path.join(repo, '.knowledge', 'tools', 'update-system-files.js')), 'Bootstrap updater did not install updater into target.', {});
      assert(fs.readFileSync(path.join(repo, '.knowledge', 'wiki', 'custom.md'), 'utf8').includes('Preserve this'), 'Custom wiki was not preserved by bootstrap update.', {});
      assert(readJson(path.join(repo, '.knowledge', 'modules', 'custom_module.json')).note === 'preserve this', 'Custom module was not preserved by bootstrap update.', {});
      assert(readJson(path.join(repo, '.knowledge', 'evidence', 'custom_evidence.json')).facts[0].id === 'custom', 'Custom evidence was not preserved by bootstrap update.', {});
      assert(readJson(path.join(repo, '.knowledge', 'decisions.json')).decisions[0].id === 'D-custom', 'decisions.json was not preserved by bootstrap update.', {});
      const doctor = readJson(path.join(repo, '.knowledge', 'maintenance', 'quality_report.json'));
      assert(doctor.status !== 'broken', 'Doctor is broken after bootstrap update.', doctor);
      const verify = runNode(['.knowledge/tools/update-system-files.js', '--verify-upgrade', '--from', sourceRoot, '--json'], repo);
      const verifyJson = parseJsonResult(verify);
      assert(verify.exit === 0 && verifyJson.status === 'ok', 'verify-upgrade failed after bootstrap update.', verifyJson);
      return { apply: applyJson.summary, doctor_status: doctor.status, verify: verifyJson.status };
    });

    record(results, 'update preflight stops before report/backup permission failures', () => {
      const repo = path.join(root, 'update preflight invalid maintenance repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'preflight-invalid-maintenance', private: true });
      rmDir(path.join(repo, '.knowledge', 'maintenance'));
      fs.writeFileSync(path.join(repo, '.knowledge', 'maintenance'), 'not a directory\n', 'utf8');
      const preflight = runNode([
        path.join(sourceRoot, 'tools', 'update-system-files.js'),
        '--from', sourceRoot,
        '--target-knowledge-root', path.join(repo, '.knowledge'),
        '--preflight',
        '--json'
      ], repo);
      const preflightJson = parseJsonResult(preflight);
      assert(preflight.exit !== 0 && preflightJson.status === 'failed', 'preflight should fail for unwritable maintenance report path.', preflightJson);
      assert(preflightJson.permission_preflight?.status === 'failed', 'preflight report did not expose permission_preflight failure.', preflightJson);
      const apply = runNode([
        path.join(sourceRoot, 'tools', 'update-system-files.js'),
        '--from', sourceRoot,
        '--target-knowledge-root', path.join(repo, '.knowledge'),
        '--apply',
        '--yes',
        '--json'
      ], repo);
      const applyJson = parseJsonResult(apply);
      assert(apply.exit !== 0 && applyJson.status === 'failed', 'apply should fail before backup/copy when preflight fails.', applyJson);
      assert(!applyJson.backup_path, 'apply created backup despite failing preflight.', applyJson);
      return { preflight_status: preflightJson.permission_preflight.status, apply_status: applyJson.status };
    });

    record(results, 'runtime files are covered by installed .knowledge/.gitignore', () => {
      const gitignore = fs.readFileSync(path.join(sourceRoot, 'templates', 'git-policy', '.knowledge.gitignore'), 'utf8');
      const requiredPatterns = [
        'project_index.json',
        'freshness.json',
        '.lock/',
        '.runtime/',
        'maintenance/flow-logs/',
        'maintenance/events/',
        'maintenance/sync_log.json',
        'search/index.json',
        'inspector/',
        'metrics/baseline.json',
        'metrics/external_memory.json',
        'maps/wiki_graph.json',
        '*.tmp-*',
        '*.bak-*'
      ];
      const missing = requiredPatterns.filter((pattern) => !gitignore.includes(pattern));
      assert(missing.length === 0, 'Missing runtime ignore patterns.', { missing });
      return { patterns_checked: requiredPatterns.length };
    });

    record(results, 'paths with spaces and Cyrillic pass install-check', () => {
      const repo = path.join(root, `repo with spaces ${cyrillic}`);
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'unicode-path-repo', private: true });
      const check = runNode(['.knowledge/tools/install-check.js', '--json'], repo);
      const parsed = parseJsonResult(check);
      assert(check.exit === 0 && parsed.status === 'ok', 'install-check failed in path with spaces/Cyrillic.', parsed);
      return { repo, status: parsed.status };
    });
  } finally {
    if (!keep) rmDir(root);
  }

  const failed = results.filter((result) => result.status !== 'pass');
  const output = {
    status: failed.length ? 'failed' : 'ok',
    temp_root: keep ? root : null,
    tests_total: results.length,
    tests_passed: results.length - failed.length,
    tests_failed: failed.length,
    results
  };
  console.log(JSON.stringify(output, null, 2));
  if (failed.length) process.exit(2);
}

if (require.main === module) main();
