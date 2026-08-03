#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { createZip } = require('./package-release');

const sourceRoot = path.resolve(__dirname, '..');
const cyrillic = '\u043a\u0438\u0440\u0438\u043b\u043b\u0438\u0446\u0430';
const childTimeoutMs = Number(process.env.KNOWLEDGE_SELF_TEST_CHILD_TIMEOUT_MS || 300000);
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

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function requiredEntriesForProfile(policy, profile = 'public_runtime') {
  if (policy.required_entry_profiles && Array.isArray(policy.required_entry_profiles[profile])) {
    return policy.required_entry_profiles[profile];
  }
  return Array.isArray(policy.required_entries) ? policy.required_entries : [];
}

function isolatedChildEnv(overrides = {}) {
  const env = { ...process.env };
  const controlledKeys = new Set([
    'KNOWLEDGE_MODE',
    'KNOWLEDGE_SYSTEM_ROOT',
    'KNOWLEDGE_TARGET_ROOT',
    'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT',
    'KNOWLEDGE_STATE_ROOT',
    'KNOWLEDGE_AGENT_ID',
    'KNOWLEDGE_DISABLE_GIT_DISCOVERY',
    'KNOWLEDGE_FLOW_NO_OPEN',
    'KNOWLEDGE_INSPECTOR_NO_OPEN',
    'KNOWLEDGE_TEAM_ROOT',
    'KNOWLEDGE_WORKSPACE_ID',
    'KNOWLEDGE_REPO_ID',
    'KNOWLEDGE_SPARK_BATTLE_REPORT',
    'KNOWLEDGE_MEMORY_BATTLE_REPORT',
    'KNOWLEDGE_MEMORY_BATTLE_MAX_AGE_HOURS'
  ]);
  for (const key of Object.keys(env)) {
    if (controlledKeys.has(key.toUpperCase())) delete env[key];
  }
  return {
    ...env,
    KNOWLEDGE_FLOW_NO_OPEN: '1',
    KNOWLEDGE_INSPECTOR_NO_OPEN: '1',
    ...overrides
  };
}

function runNode(args, cwd, env = {}) {
  const res = spawnSync(process.execPath, args, {
    cwd,
    env: isolatedChildEnv(env),
    encoding: 'utf8',
    timeout: Number.isFinite(childTimeoutMs) ? childTimeoutMs : 120000,
    windowsHide: true
  });
  const stdout = res.stdout || '';
  const stderr = res.stderr || '';
  return {
    command: `node ${args.join(' ')}`,
    cwd,
    pid: Number.isInteger(res.pid) ? res.pid : null,
    exit: res.status,
    signal: res.signal || null,
    error: res.error ? { code: res.error.code, message: res.error.message } : null,
    timed_out: res.error?.code === 'ETIMEDOUT',
    stdout_bytes: Buffer.byteLength(stdout, 'utf8'),
    stderr_bytes: Buffer.byteLength(stderr, 'utf8'),
    stdout: stdout.trim(),
    stderr: stderr.trim()
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

function copySourceFixture(dest) {
  const excludedTopLevel = new Set(['.git', '.qa-tmp', '.self-test-tmp', 'dist']);
  fs.cpSync(sourceRoot, dest, {
    recursive: true,
    filter(sourcePath) {
      const relative = normalizeRel(path.relative(sourceRoot, sourcePath));
      return !relative || !excludedTopLevel.has(relative.split('/')[0]);
    }
  });
}

function zipEntriesFromTree(root) {
  const entries = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) {
        const name = normalizeRel(path.relative(root, abs));
        entries.push({ abs, rel: name, name });
      }
    }
  }
  walk(root);
  return entries.sort((left, right) => left.name.localeCompare(right.name));
}

function tempRoot() {
  const base = path.resolve(process.env.KNOWLEDGE_SELF_TEST_TMP_ROOT || os.tmpdir());
  ensureDir(base);
  return fs.mkdtempSync(path.join(base, 'kk-install-'));
}

const ALWAYS_RUN_TESTS = new Set([
  'package artifact has .knowledge root and no source metadata'
]);
let activeTestFilter = null;
let activeTestFilterMatches = 0;

function record(results, name, fn) {
  const matchesFilter = !activeTestFilter || name.toLowerCase().includes(activeTestFilter);
  if (activeTestFilter && matchesFilter) activeTestFilterMatches += 1;
  if (!matchesFilter && !ALWAYS_RUN_TESTS.has(name)) return;
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
    file.startsWith('.knowledge/maintenance/dedicated_verification_receipts/') ||
    file.startsWith('.knowledge/maintenance/repair_sessions/') ||
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
    /^\.knowledge\/external_memory\/(mem0|legacy|claude|claude_mem|claude-auto-memory)(\/|$)/i.test(file) ||
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
  openclaw: ['AGENTS.md', '.agents/skills/kb-metrics/SKILL.md'],
  hermes: ['AGENTS.md'],
  gemini: ['GEMINI.md'],
  copilot: ['.github/copilot-instructions.md'],
  devin: ['AGENTS.md', '.devin/rules/knowledge.rules'],
  windsurf: ['.windsurf/rules/knowledge.md'],
  continue: ['.continue/rules/knowledge.md'],
  roo: ['.roo/rules/knowledge.md'],
  aider: ['CONVENTIONS.md', '.aider.conf.yml']
};

const allIntegrationPaths = Array.from(new Set(Object.values(runtimeExpectations).flat()));

function existsRel(repo, relPath) {
  return fs.existsSync(path.join(repo, relPath));
}

function createKnowledgeSourceCheckout(repo, dirName = 'knowledge-src') {
  const checkout = path.join(repo, dirName);
  ensureDir(path.join(checkout, '.git'));
  ensureDir(path.join(checkout, 'tools'));
  fs.writeFileSync(path.join(checkout, '.git', 'HEAD'), 'ref: refs/heads/main\n', 'utf8');
  writeJson(path.join(checkout, 'package.json'), { name: 'dot-knowledge', version: '0.0.0-source' });
  writeJson(path.join(checkout, 'install-manifest.json'), { schema_version: 'source-fixture', system_paths: [] });
  fs.writeFileSync(path.join(checkout, 'Quick-Start.md'), '# Source checkout fixture\n', 'utf8');
  fs.writeFileSync(path.join(checkout, 'tools', 'package-release.js'), "'use strict';\n", 'utf8');
  return checkout;
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
    'INSTALL.md',
    'install-policy.json',
    'install-manifest.json',
    'memory-providers/mem0/manifest.json',
    'memory-providers/pinecone/manifest.json',
    '.release-notes/v3.3.0.md',
    '.gitignore',
    '.gitattributes',
    'inspector.js',
    'open-inspector.vbs',
    'assets/knowledge-trust-gate-light-readme.svg',
    'agent-integrations/codex/skills/kb-repair-trust/SKILL.md',
    'agent-integrations/claude/skills/kb-repair-trust/SKILL.md',
    'RELEASE_NOTES.md',
    'SECURITY.md',
    'SBOM.memory.json',
    'THIRD_PARTY_NOTICES.md',
    'tools/lib/python-discovery.js',
    ...(manifest.required_system_files || [])
  ];
  const missingKeyFiles = keyFiles.filter((relPath) => !fs.existsSync(path.join(repo, '.knowledge', relPath)));
  assert(missingTopLevel.length === 0 && missingKeyFiles.length === 0, 'Installed system paths are incomplete.', { missingTopLevel, missingKeyFiles });
  return { system_paths_checked: manifest.system_paths.length, key_files_checked: keyFiles.length };
}

function main(argv = process.argv.slice(2)) {
  const keep = argv.includes('--keep');
  const filterIndex = argv.indexOf('--filter');
  if (filterIndex !== -1) {
    const filterValue = String(argv[filterIndex + 1] || '').trim().toLowerCase();
    if (!filterValue || filterValue.startsWith('--')) {
      console.log(JSON.stringify({
        status: 'failed',
        tests_total: 0,
        tests_passed: 0,
        tests_failed: 1,
        errors: ['--filter requires a test-name substring.']
      }, null, 2));
      process.exit(2);
    }
    activeTestFilter = filterValue;
    activeTestFilterMatches = 0;
  }
  const results = [];
  const root = tempRoot();
  let packageSummary = null;

  try {
    record(results, 'package artifact has .knowledge root and no source metadata', () => {
      // Never write the default dist/knowledge-vX.Y.Z.zip here: that path may
      // be an immutable release candidate under audit.
      const packaged = runNode([
        'tools/package-release.js',
        '--out',
        path.join(root, 'knowledge-v3.3.0.zip'),
        '--json'
      ], sourceRoot);
      assert(packaged.exit === 0, 'package-release failed.', packaged);
      packageSummary = parseJsonResult(packaged);
      const entries = extractZip(packageSummary.output_path, path.join(root, 'artifact-inspect'));
      assert(Number.isInteger(packageSummary.excluded_entries_count), 'package-release summary is missing excluded_entries_count.', packageSummary);
      assert(Number.isInteger(packageSummary.excluded_files_count), 'package-release summary is missing excluded_files_count.', packageSummary);
      assert(entries.every((entry) => entry.startsWith('.knowledge/')), 'Artifact contains entries outside .knowledge/.', { entries: entries.slice(0, 20) });
      assert(entries.includes('.knowledge/INSTALL.md'), 'Artifact does not contain INSTALL.md.', {});
      assert(entries.includes('.knowledge/install-policy.json'), 'Artifact does not contain install-policy.json.', {});
      assert(entries.includes('.knowledge/.gitignore'), 'Artifact does not contain installed .knowledge/.gitignore.', {});
      assert(entries.includes('.knowledge/install-manifest.json'), 'Artifact does not contain install-manifest.json.', {});
      assert(entries.includes('.knowledge/.release-notes/v3.3.0.md'), 'Artifact does not contain the current release note.', {});
      assert(!entries.includes('.knowledge/.release-notes/v3.2.12.md'), 'Artifact contains the unpublished internal 3.2.12 release note.', {});
      assert(!entries.includes('.knowledge/.release-notes/v3.3.1.md'), 'Artifact contains a release note newer than the artifact version.', {});
      assert(entries.includes('.knowledge/memory-providers/mem0/manifest.json'), 'Artifact does not contain Mem0 provider manifest.', {});
      assert(entries.includes('.knowledge/docs/mem0-install.md'), 'Artifact does not contain Mem0 install docs.', {});
      assert(entries.includes('.knowledge/docs/memory-providers.md'), 'Artifact does not contain memory provider docs.', {});
      assert(entries.includes('.knowledge/docs/field-report.md'), 'Artifact does not contain Field Report docs.', {});
      assert(entries.includes('.knowledge/tools/field-report.js'), 'Artifact does not contain Field Report CLI.', {});
      assert(entries.includes('.knowledge/tools/recertify.js'), 'Artifact does not contain recertify CLI.', {});
      assert(entries.includes('.knowledge/schemas/field-report.schema.json'), 'Artifact does not contain Field Report schema.', {});
      const repairRuntimeEntries = [
        '.knowledge/tools/repair-on-touch.js',
        '.knowledge/tools/lib/repair-on-touch.js',
        '.knowledge/tools/lib/dedicated-verification.js',
        '.knowledge/tools/self-test-repair-on-touch.js',
        '.knowledge/tools/self-test-dedicated-verification.js',
        '.knowledge/tools/self-test-repair-session-isolation.js',
        '.knowledge/schemas/repair-opportunities.schema.json',
        '.knowledge/schemas/verification-execution.schema.json',
        '.knowledge/schemas/verification-receipt.schema.json',
        '.knowledge/schemas/dedicated-verification-receipt.schema.json',
        '.knowledge/docs/repair-on-touch.md'
      ];
      const missingRepairRuntime = repairRuntimeEntries.filter((entry) => !entries.includes(entry));
      assert(missingRepairRuntime.length === 0, 'Artifact is missing Repair-on-touch runtime files.', { missingRepairRuntime });
      const installManifest = readJson(path.join(sourceRoot, 'install-manifest.json'));
      const requiredRepairFiles = [
        'tools/lib/dedicated-verification.js',
        'tools/self-test-dedicated-verification.js',
        'tools/self-test-repair-session-isolation.js',
        'schemas/dedicated-verification-receipt.schema.json'
      ];
      const missingManifestRequired = requiredRepairFiles.filter((entry) =>
        !(installManifest.required_system_files || []).includes(entry));
      assert(
        missingManifestRequired.length === 0 &&
        (installManifest.immutable_runtime_evidence_paths || []).includes(
          'maintenance/dedicated_verification_receipts'
        ) &&
        (installManifest.runtime_preserve_paths || []).includes(
          'maintenance/repair_sessions'
        ) &&
        (installManifest.system_exclude_paths || []).includes(
          'maintenance/dedicated_verification_receipts'
        ) &&
        (installManifest.system_exclude_paths || []).includes(
          'maintenance/repair_sessions'
        ),
        'Install manifest is missing mandatory Dedicated/session boundaries.',
        { missingManifestRequired, installManifest }
      );
      assert(entries.includes('.knowledge/tools/memory-mem0.js'), 'Artifact does not contain Mem0 provider code.', {});
      assert(entries.includes('.knowledge/tools/memory-provider.js'), 'Artifact does not contain memory provider CLI.', {});
      assert(!entries.some((entry) => /^\.knowledge\/external_memory\/mem0(\/|$)/.test(entry)), 'Artifact contains Mem0 user runtime state.', {});
      assert(entries.includes('.knowledge/memory-providers/pinecone/manifest.json'), 'Artifact does not contain Pinecone provider manifest.', {});
      assert(!entries.some((entry) => entry.startsWith('.knowledge/benchmarks/')), 'Artifact contains source-only benchmark material.', {});
      assert(
        !['benchmarks', 'tools/run-benchmarks.js', 'agent-integrations/codex/skills/release-preparation-workflow.md', 'agent-integrations/devin/rules/knowledge.md']
          .some((relPath) => (installManifest.system_remove_paths || []).includes(relPath)) &&
        JSON.stringify(installManifest.legacy_compatible_remove_paths || []) === JSON.stringify([
          'benchmarks',
          'tools/run-benchmarks.js',
          'agent-integrations/codex/skills/release-preparation-workflow.md',
          'agent-integrations/devin/rules/knowledge.md'
        ]),
        'Install manifest does not isolate the 3.2.11-compatible source-only cleanup from normal removals.',
        { installManifest }
      );
      assert(!entries.includes('.knowledge/tools/run-benchmarks.js'), 'Artifact contains the source-only benchmark runner.', {});
      assert(!entries.includes('.knowledge/agent-integrations/codex/skills/release-preparation-workflow.md'), 'Artifact contains the source-only release-preparation workflow.', {});
      assert(!entries.some((entry) => /(^|\/)\.git(\/|$)/.test(entry)), 'Artifact contains Git metadata.', {});
      assert(!entries.some((entry) => entry.startsWith('.knowledge/.github/')), 'Artifact contains source .github metadata.', {});
      assert(!entries.includes('.knowledge/docs/release-gates.md'), 'Artifact contains release gate runbook.', {});
      const cleanValidation = runNode([
        path.join(sourceRoot, 'tools', 'validate-release-artifact.js'),
        packageSummary.output_path,
        '--profile', 'public_runtime',
        '--json'
      ], root);
      const cleanValidationJson = parseJsonResult(cleanValidation);
      assert(
        cleanValidation.exit === 0 &&
        cleanValidationJson.status === 'ok',
        'Clean packaged artifact failed release validation.',
        cleanValidationJson
      );
      const maintainerOnlyEntries = [
        '.knowledge/release-policy.json',
        '.knowledge/tools/release-gate.js',
        '.knowledge/tools/check-public-consistency.js',
        '.knowledge/tools/package-release.js',
        '.knowledge/tools/validate-release-artifact.js',
        '.knowledge/tools/post-release-live-asset.js',
        '.knowledge/tools/conformance-install-smoke.js',
        '.knowledge/tools/classify-release-impact.js',
        '.knowledge/tools/generate-conformance-report.js',
        '.knowledge/tools/validate-sbom.js',
        '.knowledge/tools/validate-third-party-notices.js',
        '.knowledge/tools/validate-source-deliverable.js'
      ];
      const leakedMaintainerOnly = maintainerOnlyEntries.filter((entry) => entries.includes(entry));
      assert(leakedMaintainerOnly.length === 0, 'Artifact contains maintainer-only release tooling.', { leakedMaintainerOnly });
      const releaseContract = installManifest.release_contract;
      const missingContractRequired = (releaseContract.required_public_paths || [])
        .map((entry) => `.knowledge/${entry}`)
        .filter((entry) => !entries.includes(entry));
      assert(missingContractRequired.length === 0, 'Artifact is missing required public contract entries.', { missingContractRequired });
      const packagedRepairTest = runNode(['.knowledge/tools/self-test-repair-on-touch.js'], path.join(root, 'artifact-inspect'));
      assert(packagedRepairTest.exit === 0, 'Packaged Repair-on-touch self-test failed.', packagedRepairTest);
      const packagedDedicatedTest = runNode(
        ['.knowledge/tools/self-test-dedicated-verification.js'],
        path.join(root, 'artifact-inspect')
      );
      assert(
        packagedDedicatedTest.exit === 0,
        'Packaged Dedicated verification self-test failed.',
        packagedDedicatedTest
      );
      const packagedSessionTest = runNode(
        ['.knowledge/tools/self-test-repair-session-isolation.js'],
        path.join(root, 'artifact-inspect')
      );
      assert(
        packagedSessionTest.exit === 0,
        'Packaged Repair session-isolation self-test failed.',
        packagedSessionTest
      );
      return {
        output_path: packageSummary.output_path,
        entries: entries.length,
        repair_runtime_entries: repairRuntimeEntries.length,
        clean_artifact_validation: cleanValidationJson.status,
        packaged_repair_self_test: 'pass',
        packaged_dedicated_self_test: 'pass',
        packaged_session_isolation_self_test: 'pass'
      };
    });

    record(results, 'Repair runtime state is excluded and injected state is rejected', () => {
      const fixtureSource = path.join(root, 'repair-runtime-package-source');
      copySourceFixture(fixtureSource);
      const canaries = [
        'maintenance/routing_decision.json',
        'maintenance/restore-trust-report.md',
        'maintenance/repair_opportunities.json',
        'maintenance/repair_on_touch_telemetry.json',
        'maintenance/verification_receipts/pending.json',
        'maintenance/verification_executions/referenced.json',
        'maintenance/dedicated_verification_receipts/reviewed.json',
        'maintenance/repair_sessions/task-fixture/session-fixture/plan.json',
        'maintenance/transactions/tx-fixture/manifest.json',
        'maintenance/repair_queue.json',
        'maintenance/recertifications.json',
        'maintenance/events/repair.ndjson'
      ];
      for (const relative of canaries) {
        const target = path.join(fixtureSource, relative);
        ensureDir(path.dirname(target));
        fs.writeFileSync(target, relative.endsWith('.ndjson') ? '{"event":"fixture"}\n' : '{"fixture":true}\n', 'utf8');
      }
      const packaged = runNode(['tools/package-release.js', '--json'], fixtureSource);
      assert(packaged.exit === 0, 'Canary package-release failed.', packaged);
      const summary = parseJsonResult(packaged);
      const extracted = path.join(root, 'repair-runtime-package-inspect');
      const entries = extractZip(summary.output_path, extracted);
      const leaked = canaries
        .map((relative) => `.knowledge/${relative}`)
        .filter((entry) => entries.includes(entry));
      assert(leaked.length === 0, 'Repair runtime state leaked into the package.', { leaked });

      const maliciousTree = path.join(root, 'repair-runtime-malicious-tree');
      extractZip(summary.output_path, maliciousTree);
      for (const relative of canaries) {
        const target = path.join(maliciousTree, '.knowledge', relative);
        ensureDir(path.dirname(target));
        fs.writeFileSync(target, relative.endsWith('.ndjson') ? '{"event":"fixture"}\n' : '{"fixture":true}\n', 'utf8');
      }
      const maliciousZip = path.join(root, 'knowledge-v3.3.0-repair-runtime-injected.zip');
      createZip(zipEntriesFromTree(maliciousTree), maliciousZip);
      const validation = runNode([
        path.join(sourceRoot, 'tools', 'validate-release-artifact.js'),
        maliciousZip,
        '--profile', 'public_runtime',
        '--json'
      ], root);
      const validationJson = parseJsonResult(validation);
      assert(validation.exit !== 0 && validationJson.status !== 'ok', 'Validator accepted injected Repair runtime state.', validationJson);
      const rejectedEntries = new Set((validationJson.violations || []).map((item) => item.entry));
      const missingRejections = canaries
        .map((relative) => `.knowledge/${relative}`)
        .filter((entry) => !rejectedEntries.has(entry));
      assert(missingRejections.length === 0, 'Validator did not reject every injected Repair runtime canary.', {
        missingRejections,
        violations: validationJson.violations
      });
      return {
        canaries: canaries.length,
        package_leaks: leaked.length,
        validator_rejections: canaries.length
      };
    });

    record(results, 'package artifact normalizes text files to LF', () => {
      const repo = path.join(root, 'lf artifact repo');
      ensureDir(repo);
      extractZip(packageSummary.output_path, repo);
      const textFiles = [
        '.knowledge/.gitignore',
        '.knowledge/README.md',
        '.knowledge/Quick-Start.md',
        '.knowledge/tools/install-check.js',
        '.knowledge/templates/git-policy/.knowledge.gitignore'
      ];
      const withCrLf = textFiles.filter((file) => fs.readFileSync(path.join(repo, file), 'utf8').includes('\r'));
      assert(withCrLf.length === 0, 'Packaged text files contain CR or CRLF line endings.', { withCrLf });
      return { checked: textFiles.length };
    });

    record(results, 'marketing proof packs and public-consistency maintainer tooling are omitted and rejected', () => {
      const isolatedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-marketing-policy-'));
      try {
        const isolatedSource = path.join(isolatedRoot, 'source');
        const cleanExtract = path.join(isolatedRoot, 'clean-artifact');
        const canaryEntry = '.knowledge/marketing-proof-packs/field-test-canary.txt';
        const maintainerEntry = '.knowledge/tools/check-public-consistency.js';
        copySourceFixture(isolatedSource);
        const sourceCanary = path.join(isolatedSource, 'marketing-proof-packs', 'field-test-canary.txt');
        ensureDir(path.dirname(sourceCanary));
        fs.writeFileSync(sourceCanary, 'release-boundary-canary\n', 'utf8');

        const packaged = runNode(['tools/package-release.js', '--json'], isolatedSource);
        const packagedJson = parseJsonResult(packaged);
        assert(packaged.exit === 0 && packagedJson.status === 'ok', 'Isolated package-release failed.', { packaged, packagedJson });
        const cleanEntries = extractZip(packagedJson.output_path, cleanExtract);
        assert(!cleanEntries.includes(canaryEntry), 'Package artifact leaked marketing proof pack canary.', { canaryEntry });
        assert(!cleanEntries.includes(maintainerEntry), 'Package artifact leaked the maintainer-only public consistency checker.', { maintainerEntry });

        const injectedCanary = path.join(cleanExtract, ...canaryEntry.split('/'));
        ensureDir(path.dirname(injectedCanary));
        fs.writeFileSync(injectedCanary, 'release-boundary-canary\n', 'utf8');
        const injectedMaintainerTool = path.join(cleanExtract, ...maintainerEntry.split('/'));
        fs.writeFileSync(injectedMaintainerTool, 'maintainer-only-canary\n', 'utf8');
        const maliciousArtifact = path.join(isolatedRoot, 'knowledge-v3.3.0.zip');
        createZip(zipEntriesFromTree(cleanExtract), maliciousArtifact);

        const validation = runNode([
          path.join(sourceRoot, 'tools', 'validate-release-artifact.js'),
          maliciousArtifact,
          '--profile',
          'public_runtime',
          '--json'
        ], sourceRoot);
        const validationJson = parseJsonResult(validation);
        const canaryViolation = (validationJson.violations || []).find((violation) => violation.entry === canaryEntry);
        const maintainerViolation = (validationJson.violations || []).find((violation) => violation.entry === maintainerEntry);
        assert(validation.exit !== 0 && validationJson.status === 'failed',
          'Validator accepted an artifact with an injected marketing proof pack.', { validation, validationJson });
        assert(Boolean(canaryViolation), 'Validator failed without reporting the marketing proof pack contract violation.', validationJson);
        assert(Boolean(maintainerViolation), 'Validator failed without reporting the maintainer-only consistency checker contract violation.', validationJson);
        return {
          package_omitted: canaryEntry,
          maintainer_tool_omitted: maintainerEntry,
          validator_exit: validation.exit,
          validator_rules: [canaryViolation.rule, maintainerViolation.rule]
        };
      } finally {
        rmDir(isolatedRoot);
      }
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
      const fieldReport = runNode(['.knowledge/tools/field-report.js', 'start', '--new', '--json'], repo);
      const fieldReportJson = parseJsonResult(fieldReport);
      assert(fieldReport.exit === 0 && fieldReportJson.status === 'needs_user_input', 'Field Report did not start from the physical package artifact.', { fieldReport, fieldReportJson });
      assert(fs.existsSync(path.join(repo, '.knowledge', 'reports', 'field-reports', fieldReportJson.report_id, 'manifest.json')), 'Field Report did not persist physical-install state.', { report_id: fieldReportJson.report_id });
      return { status: parsed.status, mode: parsed.mode, field_report_status: fieldReportJson.status };
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

    record(results, 'sibling knowledge source checkout is blocked before import', () => {
      const repo = path.join(root, 'bad sibling source checkout repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'bad-sibling-source-repo', private: true });
      createKnowledgeSourceCheckout(repo, 'knowledge-src');
      const check = runNode(['.knowledge/tools/install-check.js', '--json'], repo);
      const parsed = parseJsonResult(check);
      const codes = parsed.issues.map((item) => item.code);
      assert(check.exit !== 0 && parsed.status === 'failed', 'Sibling source checkout should fail install-check.', parsed);
      assert(codes.includes('source_checkout_in_target_root'), 'Sibling source checkout diagnostic code missing.', parsed);
      const importResult = runNode(['.knowledge/tools/flow.js', 'import', '--no-color'], repo);
      assert(importResult.exit !== 0, 'flow import should stop before ingest when a source checkout is present.', importResult);
      assert(!fs.existsSync(path.join(repo, '.knowledge', 'modules', 'knowledge_src.json')), 'flow import created a knowledge_src module despite failed install-check.', {});
      return { status: parsed.status, issue_codes: codes, import_exit: importResult.exit };
    });

    record(results, 'direct ingest and sync ignore sibling knowledge source checkout', () => {
      const repo = path.join(root, 'direct ingest source checkout repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'direct-ingest-source-repo', private: true });
      createKnowledgeSourceCheckout(repo, 'knowledge-src');
      const ingest = runNode(['.knowledge/tools/ingest-existing-project.js', '--merge', '--no-sync'], repo);
      const ingestJson = parseJsonResult(ingest);
      assert(ingest.exit === 0, 'direct ingest should complete while ignoring source checkout.', { ingest, ingestJson });
      assert((ingestJson.ignored_source_checkouts || []).includes('knowledge-src/'), 'ingest did not report ignored source checkout.', ingestJson);
      assert(!(ingestJson.ignored_source_checkouts || []).includes('.knowledge/'), 'ingest should not report installed .knowledge as an ignored source checkout.', ingestJson);
      const registry = readJson(path.join(repo, '.knowledge', 'modules', 'module_registry.json'));
      const moduleIds = (registry.modules || []).map((module) => module.module_id);
      assert(!moduleIds.includes('knowledge_src'), 'ingest registered knowledge-src as a project module.', { moduleIds });
      const sync = runNode(['.knowledge/tools/sync-tracked.js', '--scan', '--discover'], repo);
      const syncJson = parseJsonResult(sync);
      assert(sync.exit === 0, 'sync should complete while ignoring source checkout.', { sync, syncJson });
      const badNewFiles = (syncJson.new_files || []).filter((file) => String(file.path || '').startsWith('knowledge-src/'));
      assert(badNewFiles.length === 0, 'sync discovered files from ignored source checkout.', { badNewFiles, syncJson });
      return { ignored_source_checkouts: ingestJson.ignored_source_checkouts, modules: moduleIds, sync_new_files: (syncJson.new_files || []).length };
    });

    record(results, 'direct ingest CLI rejects unsafe legacy lock with diagnostics', () => {
      const repo = path.join(root, 'direct ingest diagnostics repo');
      ensureDir(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'direct-ingest-diagnostics-repo', private: true });
      fs.writeFileSync(path.join(repo, '.knowledge', '.lock'), 'UNTRUSTED_LEGACY_LOCK_PAYLOAD\n', 'utf8');
      const ingest = runNode(
        ['.knowledge/tools/ingest-existing-project.js', '--merge', '--no-sync'],
        repo,
        { KNOWLEDGE_LOCK_TIMEOUT_MS: '1' }
      );
      assert(ingest.exit !== 0, 'ingest should reject unsafe legacy lock storage.', ingest);
      assert(!ingest.timed_out, 'ingest failure diagnostic case timed out instead of exiting.', ingest);
      assert(ingest.signal === null, 'ingest failure diagnostic case terminated by signal.', ingest);
      assert(ingest.stderr_bytes > 0, 'ingest failure did not preserve stderr diagnostics.', ingest);
      assert(
        /Legacy lock storage is unsafe/.test(ingest.stderr) &&
          !ingest.stderr.includes('UNTRUSTED_LEGACY_LOCK_PAYLOAD'),
        'ingest failure stderr did not identify unsafe legacy storage safely.',
        ingest
      );
      assert(ingest.stdout_bytes === 0, 'failed ingest unexpectedly emitted success output.', ingest);
      return {
        exit: ingest.exit,
        signal: ingest.signal,
        timed_out: ingest.timed_out,
        stdout_bytes: ingest.stdout_bytes,
        stderr_bytes: ingest.stderr_bytes,
        diagnostic: 'unsafe_legacy_lock'
      };
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

    record(results, 'install-agent-integrations without runtime does not create agent files', () => {
      const repo = path.join(root, 'no runtime repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'no-runtime-repo', private: true });
      const cleared = {
        KNOWLEDGE_AGENT_RUNTIME: '',
        KNOWLEDGE_RUNTIME: '',
        CODEX_HOME: '',
        CODEX_SANDBOX: '',
        CODEX_CLI_SANDBOX: '',
        CODEX_ENV_PWD: '',
        CLAUDECODE: '',
        CLAUDE_CODE: '',
        ANTHROPIC_CLAUDE_CODE: '',
        OPENCODE: '',
        OPENCODE_APP: ''
      };
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--no-package-scripts'], repo, cleared);
      const parsed = parseJsonResult(integrations);
      assert(integrations.exit === 0 && parsed.status === 'runtime_required', 'No-runtime install should require a runtime.', { integrations, parsed });
      const created = allIntegrationPaths.filter((relPath) => existsRel(repo, relPath));
      assert(created.length === 0, 'No-runtime install created integration files.', { created, parsed });
      assert(!existsRel(repo, '.gitattributes'), 'No-runtime install created .gitattributes.', { parsed });
      return { status: parsed.status, created };
    });

    record(results, 'install-agent-integrations detects explicit runtime from env only', () => {
      const repo = path.join(root, 'env runtime codex repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'env-runtime-codex-repo', private: true });
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--no-package-scripts'], repo, { KNOWLEDGE_AGENT_RUNTIME: 'codex' });
      const parsed = parseJsonResult(integrations);
      assert(integrations.exit === 0 && parsed.status === 'ok' && parsed.source === 'env:KNOWLEDGE_AGENT_RUNTIME', 'Env runtime should install only the explicit runtime.', { integrations, parsed });
      return assertRuntimeOnly(repo, 'codex');
    });

    record(results, 'install-agent-integrations requires confirmation for --all', () => {
      const repo = path.join(root, 'all runtimes unconfirmed repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'all-runtimes-unconfirmed-repo', private: true });
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--all', '--no-package-scripts'], repo);
      const parsed = parseJsonResult(integrations);
      assert(integrations.exit === 0 && parsed.status === 'all_requires_confirmation', '--all should require explicit confirmation.', { integrations, parsed });
      const created = allIntegrationPaths.filter((relPath) => existsRel(repo, relPath));
      assert(created.length === 0, 'Unconfirmed --all created integration files.', { created, parsed });
      assert(String(parsed.all_command || '').includes('--confirm-all'), 'Confirmed --all command should include --confirm-all.', parsed);
      return { status: parsed.status, created };
    });

    record(results, 'install-agent-integrations --all creates the full integration set', () => {
      const repo = path.join(root, 'all runtimes repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'all-runtimes-repo', private: true });
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--all', '--confirm-all', '--no-package-scripts'], repo);
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
      assert(quickStart.includes('--runtime openclaw') && quickStart.includes('--runtime hermes') && quickStart.includes('Pi'), 'Quick-Start is missing OpenClaw, Hermes, or generic Pi compatibility notes.', {});
      assert(quickStart.includes('--all --confirm-all'), 'Quick-Start should require --confirm-all for every-integration setup.', {});
      return { commands_checked: Object.keys(runtimeExpectations).length };
    });

    record(results, 'install-agent-integrations propagates final-report contract in --all mode', () => {
      const repo = path.join(root, 'integration contract repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'integration-contract-repo', private: true });
      const integrations = runNode(['.knowledge/tools/install-agent-integrations.js', '--all', '--confirm-all'], repo);
      assert(integrations.exit === 0, 'install-agent-integrations failed for integration contract test.', integrations);
      const agentsMd = fs.readFileSync(path.join(repo, 'AGENTS.md'), 'utf8');
      const claudeMd = fs.readFileSync(path.join(repo, 'CLAUDE.md'), 'utf8');
      const codexMetrics = fs.readFileSync(path.join(repo, '.agents', 'skills', 'kb-metrics', 'SKILL.md'), 'utf8');
      const claudeMetrics = fs.readFileSync(path.join(repo, '.claude', 'skills', 'kb-metrics', 'SKILL.md'), 'utf8');
      const opencodeMetrics = fs.readFileSync(path.join(repo, '.opencode', 'commands', 'kb-metrics.md'), 'utf8');
      const opencodePrSummary = fs.readFileSync(path.join(repo, '.opencode', 'commands', 'kb-pr-summary.md'), 'utf8');
      assert(agentsMd.includes('## Final report after meaningful work'), 'AGENTS.md is missing the final-report contract.', {});
      assert(agentsMd.includes('exactly one routing-context estimate state'), 'AGENTS.md is missing four-state routing-estimate guidance.', {});
      assert(claudeMd.includes('## Final report after meaningful work'), 'CLAUDE.md is missing the final-report contract.', {});
      assert(claudeMd.includes('silently skipping routing-context estimate reporting'), 'CLAUDE.md is missing explicit metrics-missing guidance.', {});
      assert(codexMetrics.includes('workspace-to-task narrowing') && codexMetrics.includes('deterministic local context estimate'), 'Installed Codex metrics skill is missing four-state estimate guidance.', {});
      assert(claudeMetrics.includes('workspace-to-task narrowing') && claudeMetrics.includes('deterministic local context estimate'), 'Installed Claude metrics skill is missing four-state estimate guidance.', {});
      assert(opencodeMetrics.includes('workspace-to-task narrowing') && opencodeMetrics.includes('deterministic local context estimate'), 'Installed OpenCode metrics command is missing four-state estimate guidance.', {});
      assert(opencodePrSummary.includes('routing-context estimate state or its unavailable/not-comparable reason'), 'Installed OpenCode PR summary command is missing final-report guidance.', {});
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

    record(results, 'flow rejects semantic doctor failure even when doctor exits zero', () => {
      const repo = path.join(root, 'semantic doctor failure repo');
      ensureDir(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'semantic-doctor-failure-repo', private: true });
      const flow = runNode(['.knowledge/tools/flow.js', 'doctor', '--json'], repo);
      const flowJson = parseJsonResult(flow);
      assert(flow.exit !== 0 && flowJson.status === 'failed', 'Flow accepted a broken doctor report because its process exit was zero.', flowJson);
      const doctorStep = (flowJson.steps || []).find((step) => step.step === 'doctor');
      assert(
        doctorStep?.success === false &&
        doctorStep.status === 'fail' &&
        Array.isArray(doctorStep.semantic_errors) &&
        doctorStep.semantic_errors.length > 0,
        'Flow did not preserve the doctor semantic failure evidence.',
        doctorStep
      );
      return { flow_status: flowJson.status, doctor_semantic_errors: doctorStep.semantic_errors };
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
      const releaseResult = runNode(['.knowledge/tools/flow.js', 'release', '--no-color', '--json'], repo);
      const releaseJson = parseJsonResult(releaseResult);
      assert(
        releaseResult.exit === 0 &&
        releaseJson.status === 'ok' &&
        releaseJson.flow_log_status === 'written',
        'flow release did not finalize a verified evidence log.',
        { command: releaseResult, output: releaseJson }
      );
      const releaseLogPath = path.isAbsolute(releaseJson.flow_log)
        ? path.resolve(releaseJson.flow_log)
        : path.resolve(repo, ...String(releaseJson.flow_log || '').split('/'));
      const releaseStateRoot = path.resolve(releaseJson.state_root);
      const expectedLogRoot = path.join(releaseStateRoot, 'maintenance', 'flow-logs');
      const logRelative = path.relative(expectedLogRoot, releaseLogPath);
      assert(
        logRelative && !logRelative.startsWith('..') && !path.isAbsolute(logRelative),
        'flow release log escaped the expected stateRoot flow-logs directory.',
        { releaseLogPath, expectedLogRoot, flow_log: releaseJson.flow_log }
      );
      const releaseLog = readJson(releaseLogPath);
      assert(releaseLog.flow === releaseJson.flow, 'flow log/readback flow mismatch.', { releaseLog, releaseJson });
      assert(releaseLog.started_at === releaseJson.started_at, 'flow log/readback started_at mismatch.', { releaseLog, releaseJson });
      assert(releaseLog.steps_total === releaseJson.steps_total, 'flow log/readback steps_total mismatch.', { releaseLog, releaseJson });
      assert(releaseLog.steps_total === releaseLog.steps.length, 'flow log persisted an inconsistent steps array.', releaseLog);
      assert(releaseLog.steps_ok === releaseJson.steps_ok, 'flow log/readback steps_ok mismatch.', { releaseLog, releaseJson });
      assert(releaseLog.overall_status === releaseJson.overall_status, 'flow log/readback status mismatch.', { releaseLog, releaseJson });
      const add = runGit(['add', '.'], repo);
      assert(add.exit === 0, 'git add . failed in fresh flow release test.', add);
      const staged = stagedFiles(repo);
      const forbidden = staged.filter(generatedOrRuntime);
      assert(forbidden.length === 0, 'Generated/runtime artifacts were staged by git add .', { forbidden, staged_sample: staged.slice(0, 40) });
      return {
        staged_files: staged.length,
        forbidden_staged: forbidden.length,
        flow_log_status: releaseJson.flow_log_status,
        flow_log_correlated: true
      };
    });

    record(results, 'existing update preserves project knowledge', () => {
      const repo = path.join(root, 'existing update repo');
      ensureDir(repo);
      initGitRepo(repo);
      extractZip(packageSummary.output_path, repo);
      writeJson(path.join(repo, 'package.json'), { name: 'existing-repo', private: true });
      const generatedWorkspaceDirs = ['.knowledge_backup_legacy', 'qa_runs', '_baseline_dev'];
      for (const dir of generatedWorkspaceDirs) {
        ensureDir(path.join(repo, dir));
        fs.writeFileSync(path.join(repo, dir, 'should-not-be-discovered.py'), 'print("generated")\n', 'utf8');
      }
      const importResult = runNode(['.knowledge/tools/flow.js', 'import', '--no-color'], repo);
      assert(importResult.exit === 0, 'flow import failed before update test.', importResult);
      const generatedNames = generatedWorkspaceDirs.map((value) => value.replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').toLowerCase());
      const importedRegistry = readJson(path.join(repo, '.knowledge', 'modules', 'module_registry.json'));
      assert(!(importedRegistry.modules || []).some((item) => generatedNames.includes(item.module_id)), 'Generated backup/QA/baseline directories became modules.', importedRegistry);
      const importedFacts = JSON.stringify(readJson(path.join(repo, '.knowledge', 'evidence', 'file_facts.json')));
      assert(!generatedWorkspaceDirs.some((dir) => importedFacts.includes(dir)), 'Generated backup/QA/baseline files entered evidence.', { generatedWorkspaceDirs });
      const doctorAfterImport = readJson(path.join(repo, '.knowledge', 'maintenance', 'quality_report.json'));
      assert(doctorAfterImport.issues?.some((item) => item.code === 'legacy_project_root_knowledge_backup'), 'Doctor did not surface the legacy project-root backup.', doctorAfterImport);
      const pollutedRegistryPath = path.join(repo, '.knowledge', 'modules', 'module_registry.json');
      const pollutedRegistry = readJson(pollutedRegistryPath);
      pollutedRegistry.modules.push({ module_id: 'qa_runs', path: 'qa_runs/', card: '.knowledge/modules/qa_runs.json', key_files: ['qa_runs/should-not-be-discovered.py'], evidence_files: [] });
      writeJson(pollutedRegistryPath, pollutedRegistry);
      writeJson(path.join(repo, '.knowledge', 'modules', 'qa_runs.json'), { module_id: 'qa_runs', boundaries: { owns: ['qa_runs/'] }, confidence: 'low' });
      const pollutedFreshnessPath = path.join(repo, '.knowledge', 'freshness.json');
      const pollutedFreshness = readJson(pollutedFreshnessPath);
      pollutedFreshness.tracked_files.push({ path: 'qa_runs/should-not-be-discovered.py', sha256: 'stale', status: 'needs_recheck' });
      writeJson(pollutedFreshnessPath, pollutedFreshness);
      const pollutionCleanup = runNode(['.knowledge/tools/sync-tracked.js', '--scan', '--discover'], repo);
      const pollutionCleanupJson = parseJsonResult(pollutionCleanup);
      assert(pollutionCleanup.exit === 0 && pollutionCleanupJson.status === 'ok', 'Sync failed while cleaning generated workspace pollution.', pollutionCleanupJson);
      assert(pollutionCleanupJson.ignored_modules_removed?.includes('qa_runs'), 'Sync did not remove the generated QA module.', pollutionCleanupJson);
      assert(pollutionCleanupJson.ignored_tracked_paths_removed?.includes('qa_runs/should-not-be-discovered.py'), 'Sync did not remove the generated QA tracked file.', pollutionCleanupJson);
      assert(!fs.existsSync(path.join(repo, '.knowledge', 'modules', 'qa_runs.json')), 'Sync left the generated QA module card behind.', {});
      fs.writeFileSync(path.join(repo, '.knowledge', 'wiki', 'custom.md'), '# Custom Wiki\n\nPreserve this.\n', 'utf8');
      writeJson(path.join(repo, '.knowledge', 'modules', 'custom_module.json'), { module_id: 'custom', note: 'preserve this' });
      writeJson(path.join(repo, '.knowledge', 'evidence', 'custom_evidence.json'), { facts: [{ id: 'custom', text: 'preserve this' }] });
      writeJson(path.join(repo, '.knowledge', 'decisions.json'), { decisions: [{ id: 'D-custom', text: 'preserve this' }] });
      const runtimePreserveFiles = [
        'maintenance/repair_opportunities.json',
        'maintenance/repair_on_touch_telemetry.json',
        'maintenance/verification_receipts/applied.json',
        'maintenance/verification_receipts/pending.json',
        'maintenance/verification_executions/referenced.json',
        'maintenance/verification_executions/orphan.json',
        'maintenance/dedicated_verification_receipts/reviewed.json',
        'maintenance/repair_sessions/task-update/session-update/canary.json',
        'maintenance/transactions/tx-fixture/manifest.json',
        'maintenance/transactions/tx-fixture/backups/0.json',
        'maintenance/recertifications.json',
        'settings/operator-profile.json'
      ];
      for (const relative of runtimePreserveFiles) {
        const target = path.join(repo, '.knowledge', relative);
        let fixture;
        if (relative === 'settings/operator-profile.json') {
          fixture = {
            ...(fs.existsSync(target) ? readJson(target) : {}),
            selected_agent_id: 'update-preservation-fixture',
            preservation_fixture: true
          };
        } else if (relative === 'maintenance/repair_on_touch_telemetry.json') {
          fixture = {
            schema_version: 'knowledge-repair-on-touch-telemetry.v1',
            repair_on_touch_enabled: true,
            repair_mode: 'scoped',
            repair_findings_considered: 1,
            repair_findings_selected: 0,
            repair_findings_closed: 0,
            repair_findings_deferred: 1,
            repair_lifecycle_ids_considered: ['LC-0123456789abcdef'],
            repair_lifecycle_ids_closed: [],
            repair_extra_wall_time_ms: 0,
            repair_extra_input_tokens: 0,
            repair_extra_output_tokens: 0,
            doctor_before: 90,
            doctor_after: 90,
            task_readiness_before: 90,
            task_readiness_after: 90,
            token_values: 'actual_only'
          };
        } else {
          fixture = {
            fixture: relative,
            state: relative.includes('pending') ? 'pending' : 'applied',
            preserved: true
          };
        }
        writeJson(target, fixture);
      }
      const runtimeHashesBefore = Object.fromEntries(runtimePreserveFiles.map((relative) => [
        relative,
        sha256File(path.join(repo, '.knowledge', relative))
      ]));
      fs.writeFileSync(path.join(repo, '.knowledge', '.release-notes', 'v3.3.1.md'), '# Obsolete staged note\n', 'utf8');
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
      assert(applyJson.curated_apply_preservation_proof?.changed_files_count === 0, 'System-file apply changed protected curated knowledge.', applyJson.curated_apply_preservation_proof);
      assert(applyJson.curated_preservation_proof?.changed_files_count === 0, 'Post-checks changed protected curated knowledge.', applyJson.curated_preservation_proof);
      assert(applyJson.runtime_apply_preservation_proof?.status === 'preserved', 'System-file apply changed Repair runtime evidence.', applyJson.runtime_apply_preservation_proof);
      assert(applyJson.runtime_preservation_proof?.status === 'preserved' &&
        applyJson.runtime_preservation_proof?.hash_set_unchanged === true, 'Post-checks changed Repair runtime evidence.', applyJson.runtime_preservation_proof);
      assert(applyJson.runtime_regeneration?.bootstrap_required === false, 'Initialized update unexpectedly selected flow import.', applyJson.runtime_regeneration);
      assert(applyJson.system_completeness?.status === 'ok', 'Updater left missing system paths.', applyJson.system_completeness);
      assert(applyJson.system_completeness?.mismatched_system_paths?.length === 0, 'Updater left system hash mismatches.', applyJson.system_completeness);
      assert(applyJson.backup_verification?.safe_to_remove === true, 'Updater did not produce a verified backup disposition.', applyJson.backup_verification);
      assert(fs.existsSync(path.join(applyJson.backup_path, 'backup-verification.json')), 'Updater did not persist the backup verification receipt.', applyJson.backup_verification);
      assert(!fs.existsSync(path.join(repo, '.knowledge', '.release-notes', 'v3.3.1.md')), 'Updater did not remove the obsolete staged release note.', {});
      assert(!fs.existsSync(path.join(repo, '.knowledge', '.release-notes', 'v3.2.12.md')), 'Updater retained the unpublished internal 3.2.12 release note.', {});
      assertInstalledSystemComplete(repo);
      assert(fs.existsSync(path.join(repo, '.knowledge', 'inspector.js')), 'Updater did not install .knowledge/inspector.js.', {});
      assert(fs.readFileSync(path.join(repo, '.knowledge', 'wiki', 'custom.md'), 'utf8').includes('Preserve this'), 'Custom wiki was not preserved.', {});
      assert(readJson(path.join(repo, '.knowledge', 'modules', 'custom_module.json')).note === 'preserve this', 'Custom module was not preserved.', {});
      assert(readJson(path.join(repo, '.knowledge', 'evidence', 'custom_evidence.json')).facts[0].id === 'custom', 'Custom evidence was not preserved.', {});
      assert(readJson(path.join(repo, '.knowledge', 'decisions.json')).decisions[0].id === 'D-custom', 'decisions.json was not preserved.', {});
      const runtimeHashMismatches = runtimePreserveFiles.filter((relative) => (
        runtimeHashesBefore[relative] !== sha256File(path.join(repo, '.knowledge', relative))
      ));
      assert(runtimeHashMismatches.length === 0, 'Updater changed protected Repair runtime evidence or operator settings.', {
        runtimeHashMismatches
      });
      const verify = runNode(['.knowledge/tools/update-system-files.js', '--verify-upgrade', '--from', sourceRoot, '--json'], repo);
      const verifyJson = parseJsonResult(verify);
      assert(verify.exit === 0 && verifyJson.status === 'ok', 'verify-upgrade failed after existing update.', verifyJson);
      const legacyApplyReport = JSON.parse(JSON.stringify(applyJson));
      legacyApplyReport.schema_version = '3.2.11';
      legacyApplyReport.phase = 'apply';
      legacyApplyReport.mode = 'apply';
      legacyApplyReport.status = 'ok';
      legacyApplyReport.installed_version = '3.3.0';
      legacyApplyReport.source_version = '3.3.0';
      delete legacyApplyReport.runtime_apply_preservation_proof;
      delete legacyApplyReport.runtime_preservation_proof;
      const legacyReportPath = path.join(
        repo,
        '.knowledge',
        'maintenance',
        'update_system_files_report.json'
      );
      writeJson(legacyReportPath, legacyApplyReport);
      const legacyReportShaBefore = sha256File(legacyReportPath);
      const legacyVerify = runNode([
        '.knowledge/tools/update-system-files.js',
        '--verify-upgrade',
        '--from',
        sourceRoot,
        '--json'
      ], repo);
      const legacyVerifyJson = parseJsonResult(legacyVerify);
      assert(
        legacyVerify.exit === 0 && legacyVerifyJson.status === 'ok',
        '3.2.11 apply report could not reconstruct runtime preservation proof.',
        legacyVerifyJson
      );
      assert(
        legacyVerifyJson.runtime_preservation_proof?.status === 'preserved' &&
        legacyVerifyJson.runtime_preservation_proof?.proof_source ===
          'reconstructed_legacy_backup',
        'legacy runtime proof was not reconstructed from the retained backup.',
        legacyVerifyJson.runtime_preservation_proof
      );
      assert(
        legacyVerifyJson.verify?.legacy_recovery?.status === 'reconstructed',
        'verify output did not disclose legacy proof reconstruction.',
        legacyVerifyJson.verify
      );
      const persistedLegacyVerify = readJson(
        legacyReportPath
      );
      assert(
        persistedLegacyVerify.runtime_preservation_proof?.proof_source ===
          'reconstructed_legacy_backup',
        'reconstructed proof was not persisted atomically.',
        persistedLegacyVerify
      );
      assert(
        persistedLegacyVerify.schema_version === '3.2.11' &&
        persistedLegacyVerify.phase === 'apply' &&
        persistedLegacyVerify.mode === 'apply' &&
        persistedLegacyVerify.backup_path === legacyApplyReport.backup_path &&
        JSON.stringify(persistedLegacyVerify.actions || []) ===
          JSON.stringify(legacyApplyReport.actions || []),
        'legacy apply provenance was overwritten while enriching runtime proof.',
        persistedLegacyVerify
      );
      assert(
        persistedLegacyVerify.runtime_proof_provenance?.source ===
          'reconstructed_legacy_backup' &&
        persistedLegacyVerify.runtime_proof_provenance
          ?.apply_report_sha256_before_enrichment === legacyReportShaBefore,
        'legacy proof provenance does not bind the pre-enrichment apply report.',
        persistedLegacyVerify.runtime_proof_provenance
      );
      const persistedLegacySha = sha256File(legacyReportPath);
      const repeatLegacyVerify = runNode([
        '.knowledge/tools/update-system-files.js',
        '--verify-upgrade',
        '--from',
        sourceRoot,
        '--json'
      ], repo);
      const repeatLegacyVerifyJson = parseJsonResult(repeatLegacyVerify);
      assert(
        repeatLegacyVerify.exit === 0 &&
        repeatLegacyVerifyJson.status === 'ok' &&
        !repeatLegacyVerifyJson.verify?.legacy_recovery &&
        repeatLegacyVerifyJson.verify?.runtime_proof_source ===
          'previous_update_report_revalidated',
        'repeat verification reconstructed legacy proof again instead of revalidating it.',
        repeatLegacyVerifyJson
      );
      assert(
        sha256File(legacyReportPath) === persistedLegacySha,
        'repeat verification unexpectedly rewrote the enriched apply report.',
        { before: persistedLegacySha, after: sha256File(legacyReportPath) }
      );
      const tamperedLegacyReport = readJson(legacyReportPath);
      tamperedLegacyReport.runtime_preservation_proof.required_paths =
        tamperedLegacyReport.runtime_preservation_proof.required_paths.slice(1);
      writeJson(legacyReportPath, tamperedLegacyReport);
      const tamperedLegacyVerify = runNode([
        '.knowledge/tools/update-system-files.js',
        '--verify-upgrade',
        '--from',
        sourceRoot,
        '--json'
      ], repo);
      const tamperedLegacyVerifyJson = parseJsonResult(tamperedLegacyVerify);
      assert(
        tamperedLegacyVerify.exit !== 0 &&
        tamperedLegacyVerifyJson.status === 'failed' &&
        tamperedLegacyVerifyJson.verify?.runtime_proof_validation?.errors
          ?.includes('runtime_proof_declared_path_coverage_mismatch'),
        'verify-upgrade accepted a runtime proof with incomplete mandatory path coverage.',
        tamperedLegacyVerifyJson
      );
      writeJson(legacyReportPath, persistedLegacyVerify);
      const emptyManifestFixture = path.join(root, 'empty-runtime-manifest');
      writeJson(path.join(emptyManifestFixture, 'install-manifest.json'), {
        schema_version: '3.3.0',
        system_paths: [],
        required_system_files: [],
        immutable_runtime_evidence_paths: [],
        runtime_preserve_paths: [],
        system_exclude_paths: [],
        forbidden_paths: []
      });
      const loadedEmptyRuntimeManifest =
        require('./update-system-files').loadInstallManifest(emptyManifestFixture);
      assert(
        loadedEmptyRuntimeManifest.immutable_runtime_evidence_paths.includes(
          'maintenance/verification_receipts'
        ) &&
        loadedEmptyRuntimeManifest.immutable_runtime_evidence_paths.includes(
          'maintenance/dedicated_verification_receipts'
        ) &&
        loadedEmptyRuntimeManifest.runtime_preserve_paths.includes(
          'settings/operator-profile.json'
        ) &&
        loadedEmptyRuntimeManifest.runtime_preserve_paths.includes(
          'maintenance/repair_sessions'
        ) &&
        loadedEmptyRuntimeManifest.system_paths.includes(
          'tools'
        ) &&
        loadedEmptyRuntimeManifest.required_system_files.includes(
          'tools/lib/json-transaction.js'
        ) &&
        loadedEmptyRuntimeManifest.system_exclude_paths.includes(
          'maintenance/repair_sessions'
        ) &&
        loadedEmptyRuntimeManifest.forbidden_paths.includes(
          '.git'
        ),
        'explicit empty manifest arrays removed mandatory update boundaries.',
        loadedEmptyRuntimeManifest
      );
      const legacyPruneFixture = path.join(
        repo,
        '.knowledge',
        'maintenance',
        'install-backups',
        'system-files-legacy-prune-fixture'
      );
      ensureDir(legacyPruneFixture);
      fs.writeFileSync(
        path.join(legacyPruneFixture, 'legacy-state.txt'),
        'must remain until runtime proof exists\n',
        'utf8'
      );
      writeJson(path.join(legacyPruneFixture, 'backup-verification.json'), {
        schema_version: 'knowledge-update-backup-verification.v1',
        status: 'verified',
        safe_to_remove: true,
        checks: {
          curated_preservation: 'pass',
          system_sha256_parity: 'pass',
          semantic_post_checks: 'pass'
        }
      });
      const pruneWithoutConfirmation = runNode(['.knowledge/tools/update-system-files.js', '--prune-verified-backups', '--json'], repo);
      const pruneWithoutConfirmationJson = parseJsonResult(pruneWithoutConfirmation);
      assert(pruneWithoutConfirmation.exit !== 0 && pruneWithoutConfirmationJson.status === 'failed', 'Backup prune should require --yes.', pruneWithoutConfirmationJson);
      const prune = runNode(['.knowledge/tools/update-system-files.js', '--prune-verified-backups', '--yes', '--json'], repo);
      const pruneJson = parseJsonResult(prune);
      assert(prune.exit === 0 && pruneJson.status === 'ok' && pruneJson.removed_count >= 1, 'Verified backup prune did not remove a verified backup.', pruneJson);
      assert(!fs.existsSync(applyJson.backup_path), 'Verified backup still exists after confirmed prune.', { backup_path: applyJson.backup_path });
      assert(
        fs.existsSync(legacyPruneFixture) &&
        pruneJson.retained?.some((item) => (
          item.path === legacyPruneFixture &&
          item.reason === 'legacy_runtime_proof_required'
        )),
        'legacy receipt without runtime proof was pruned.',
        pruneJson
      );
      const installedDoctor = path.join(repo, '.knowledge', 'tools', 'doctor.js');
      fs.appendFileSync(installedDoctor, '\n// hash drift probe\n', 'utf8');
      const driftVerify = runNode(['.knowledge/tools/update-system-files.js', '--verify-upgrade', '--from', sourceRoot, '--json'], repo);
      const driftVerifyJson = parseJsonResult(driftVerify);
      assert(driftVerify.exit !== 0 && driftVerifyJson.status === 'failed', 'verify-upgrade accepted a modified system file.', driftVerifyJson);
      assert(driftVerifyJson.verify?.checks?.some((check) => check.check === 'system_completeness' && check.mismatched_system_paths?.includes('tools/doctor.js')), 'verify-upgrade did not report the modified system file SHA-256 mismatch.', driftVerifyJson.verify);
      fs.copyFileSync(path.join(sourceRoot, 'tools', 'doctor.js'), installedDoctor);
      return {
        dry_run: dryJson.summary,
        apply: applyJson.summary,
        verify: verifyJson.status,
        legacy_verify: legacyVerifyJson.status,
        legacy_runtime_proof: legacyVerifyJson.runtime_preservation_proof?.proof_source,
        backup_pruned: pruneJson.removed_count,
        hash_drift_rejected: true,
        runtime_preserved_files: runtimePreserveFiles.length,
        generated_workspace_dirs_ignored: generatedWorkspaceDirs
      };
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
      assert(applyJson.curated_preservation_proof?.changed_files_count === 0, 'Bootstrap post-checks changed protected curated knowledge.', applyJson.curated_preservation_proof);
      assert(applyJson.runtime_regeneration?.bootstrap_required === false, 'Initialized legacy fixture unexpectedly selected flow import.', applyJson.runtime_regeneration);
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
      const sourceRuntimeIgnore = fs.readFileSync(
        path.join(sourceRoot, '.gitignore'),
        'utf8'
      );
      const requiredPatterns = [
        'project_index.json',
        'freshness.json',
        '.lock/',
        '.runtime/',
        'maintenance/flow-logs/',
        'maintenance/events/',
        'maintenance/sync_log.json',
        'maintenance/routing_decision.json',
        'maintenance/routing_decisions.ndjson',
        'maintenance/restore-trust-report.md',
        'maintenance/recertifications.json',
        'maintenance/repair_opportunities.json',
        'maintenance/repair_on_touch_telemetry.json',
        'maintenance/verification_receipts/',
        'maintenance/verification_executions/',
        'maintenance/dedicated_verification_receipts/',
        'maintenance/repair_sessions/',
        'maintenance/transactions/',
        'search/index.json',
        'reports/field-reports/',
        'inspector/',
        'metrics/baseline.json',
        'metrics/external_memory.json',
        'external_memory/mem0/',
        'external_memory/legacy/',
        'external_memory/claude/',
        'external_memory/claude_mem/',
        'external_memory/claude-auto-memory/',
        'maps/wiki_graph.json',
        '*.tmp-*',
        '*.bak-*'
      ];
      const missing = requiredPatterns.filter((pattern) => !gitignore.includes(pattern));
      const missingSourceRuntime = [
        'maintenance/dedicated_verification_receipts/',
        'maintenance/repair_sessions/'
      ].filter((pattern) => !sourceRuntimeIgnore.includes(pattern));
      assert(
        missing.length === 0 && missingSourceRuntime.length === 0,
        'Missing runtime ignore patterns.',
        { missing, missingSourceRuntime }
      );
      return {
        patterns_checked: requiredPatterns.length,
        source_runtime_patterns_checked: 2
      };
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

  if (activeTestFilter && activeTestFilterMatches === 0) {
    results.push({
      name: `filter: ${activeTestFilter}`,
      status: 'fail',
      message: 'No install-policy test matched the requested filter.',
      details: null
    });
  }

  const failed = results.filter((result) => result.status !== 'pass');
  const output = {
    status: failed.length ? 'failed' : 'ok',
    filter: activeTestFilter,
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
