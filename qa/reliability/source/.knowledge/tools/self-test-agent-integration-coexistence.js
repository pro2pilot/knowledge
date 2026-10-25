#!/usr/bin/env node
'use strict';

// Source-only physical regression suite for the public agent-integration CLI.
// Its expectations are intentionally independent of install-agent-integrations'
// RUNTIME_SPECS/INTEGRATIONS tables so that an unsafe shared implementation
// cannot make its own verifier pass.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildPackageEntries } = require('./package-release');
const { readZipEntries } = require('./validate-release-artifact');
const { withTempFixture } = require('./lib/strict-temp-cleanup');

const systemRoot = path.resolve(__dirname, '..');
const managedStart = '<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->';
const managedEnd = '<!-- END DOT-KNOWLEDGE MANAGED BLOCK -->';
const agentsRuntimes = ['codex', 'openclaw', 'hermes', 'devin'];
const expectedAgentAttributes = [
  'AGENTS.md text eol=lf',
  '.agents/skills/** text eol=lf',
  '.devin/rules/knowledge.rules text eol=lf'
];

function parseArgs(argv) {
  const outIndex = argv.indexOf('--out');
  const artifactIndex = argv.indexOf('--artifact');
  return {
    out: outIndex >= 0 ? argv[outIndex + 1] : null,
    artifact: artifactIndex >= 0 ? argv[artifactIndex + 1] : null
  };
}

function sha(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hashFile(filePath) {
  return fs.existsSync(filePath) && !fs.lstatSync(filePath).isSymbolicLink()
    ? sha(fs.readFileSync(filePath))
    : null;
}

function materializePublicRuntime(targetRoot, artifact = null) {
  const entries = artifact
    ? readZipEntries(artifact).entries.map((entry) => ({
      rel: String(entry.name || '').replace(/^\.knowledge\//, ''),
      body: entry.body
    }))
    : buildPackageEntries(systemRoot).entries.map((entry) => ({ rel: entry.rel, body: fs.readFileSync(entry.abs) }));
  for (const entry of entries) {
    if (!entry.rel || entry.rel.includes('..') || entry.rel.endsWith('/')) throw new Error(`Unsafe runtime entry: ${entry.rel}`);
    const output = path.join(targetRoot, '.knowledge', ...entry.rel.split('/'));
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, entry.body);
  }
}

function fixtureEnv(repoRoot) {
  const env = { ...process.env };
  for (const key of [
    'KNOWLEDGE_MODE', 'KNOWLEDGE_SYSTEM_ROOT', 'KNOWLEDGE_TARGET_ROOT',
    'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT', 'KNOWLEDGE_STATE_ROOT',
    'KNOWLEDGE_AGENT_ID', 'KNOWLEDGE_DISABLE_GIT_DISCOVERY'
  ]) delete env[key];
  return {
    ...env,
    KNOWLEDGE_MODE: 'repo',
    KNOWLEDGE_SYSTEM_ROOT: path.join(repoRoot, '.knowledge'),
    KNOWLEDGE_TARGET_ROOT: repoRoot,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(repoRoot, '.knowledge'),
    KNOWLEDGE_STATE_ROOT: path.join(repoRoot, '.knowledge'),
    KNOWLEDGE_AGENT_ID: 'agent-integration-coexistence-self-test',
    KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1',
    NO_COLOR: '1',
    TERM: 'dumb'
  };
}

function parseJsonOutput(stdout, stderr) {
  for (const value of [stdout, stderr]) {
    if (!String(value || '').trim()) continue;
    try { return JSON.parse(value); } catch { /* Try a JSON diagnostic after a prefix. */ }
    const text = String(value || '');
    for (let start = text.indexOf('{'); start >= 0; start = text.indexOf('{', start + 1)) {
      try {
        const parsed = JSON.parse(text.slice(start));
        if (parsed && typeof parsed === 'object') return parsed;
      } catch { /* A diagnostic prefix or nested object; keep scanning. */ }
    }
  }
  return null;
}

function install(repoRoot, runtime, extra = []) {
  const result = spawnSync(
    process.execPath,
    ['.knowledge/tools/install-agent-integrations.js', '--runtime', runtime, '--no-install-check', ...extra],
    { cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 120000, env: fixtureEnv(repoRoot) }
  );
  const stdout = result.stdout || '';
  const stderr = result.stderr || '';
  return { exit: result.status, stdout, stderr, report: parseJsonOutput(stdout, stderr) };
}

function installAll(repoRoot) {
  const result = spawnSync(
    process.execPath,
    ['.knowledge/tools/install-agent-integrations.js', '--all', '--confirm-all', '--no-install-check'],
    { cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 180000, env: fixtureEnv(repoRoot) }
  );
  const stdout = result.stdout || '';
  const stderr = result.stderr || '';
  return { exit: result.status, stdout, stderr, report: parseJsonOutput(stdout, stderr) };
}

function installCheck(repoRoot) {
  const result = spawnSync(process.execPath, ['.knowledge/tools/install-check.js', '--json'], {
    cwd: repoRoot, encoding: 'utf8', windowsHide: true, timeout: 120000, env: fixtureEnv(repoRoot)
  });
  const stdout = result.stdout || '';
  const stderr = result.stderr || '';
  return { exit: result.status, stdout, stderr, report: parseJsonOutput(stdout, stderr) };
}

function read(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

function managedBlock(text) {
  const start = text.indexOf(managedStart);
  const end = text.indexOf(managedEnd);
  if (start < 0 || end < start || text.indexOf(managedStart, start + managedStart.length) >= 0 || text.indexOf(managedEnd, end + managedEnd.length) >= 0) return null;
  return text.slice(start + managedStart.length, end).trim();
}

function codes(report) {
  return (report?.issues || []).map((item) => item.code);
}

function treeState(root) {
  const state = {};
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (directory === root && entry.name === '.knowledge') continue;
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).replace(/\\/g, '/');
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        state[relative] = { type: 'symlink', target: fs.readlinkSync(absolute) };
      } else if (stat.isDirectory()) {
        state[relative] = { type: 'dir' };
        visit(absolute);
      } else if (stat.isFile()) {
        state[relative] = { type: 'file', sha256: sha(fs.readFileSync(absolute)) };
      }
    }
  };
  visit(root);
  return state;
}

function createDirectoryLink(target, link) {
  fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir');
}

function createFileLink(target, link) {
  try {
    fs.symlinkSync(target, link, 'file');
    return { ok: true };
  } catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'UNKNOWN'].includes(error.code)) {
      return { ok: false, code: error.code, message: error.message };
    }
    throw error;
  }
}

function rejected(result, before, after, sentinelPath = null) {
  const structured = Boolean(
    result.report && (
      result.report.code ||
      (Array.isArray(result.report.violations) && result.report.violations.length) ||
      String(result.report.status || '') === 'failed'
    )
  );
  const sentinelUntouched = !sentinelPath || read(sentinelPath) === 'EXTERNAL-SENTINEL\n';
  const noSentinelLeak = !`${result.stdout}\n${result.stderr}`.includes('EXTERNAL-SENTINEL');
  const unchanged = JSON.stringify(before) === JSON.stringify(after);
  result.rejection_evidence = { structured, sentinel_untouched: sentinelUntouched, no_sentinel_leak: noSentinelLeak, unchanged };
  return result.exit !== 0 && structured && sentinelUntouched && noSentinelLeak && unchanged;
}

function permutations(values) {
  if (values.length <= 1) return [values];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)]).map((rest) => [value, ...rest]));
}

function run(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const checks = [];
  const check = (id, pass, detail = null, blocked = null) => checks.push({ id, status: blocked ? 'blocked' : (pass ? 'pass' : 'fail'), detail, blocked_reason: blocked });
  const fixture = (id, callback) => withTempFixture({ prefix: `knowledge-agent-integration-${id}-` }, (root) => {
    materializePublicRuntime(root, args.artifact ? path.resolve(args.artifact) : null);
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n', 'utf8');
    return callback(root);
  });
  const external = (id, callback) => withTempFixture({ prefix: `knowledge-agent-integration-external-${id}-` }, callback);

  const singleHashes = {};
  for (const runtime of agentsRuntimes) {
    fixture(`single-${runtime}`, (repoRoot) => {
      fs.writeFileSync(path.join(repoRoot, 'AGENTS.md'), 'USER TOP\n\nUSER BOTTOM\n', 'utf8');
      const result = install(repoRoot, runtime);
      const agents = read(path.join(repoRoot, 'AGENTS.md'));
      const block = managedBlock(agents);
      const devinRule = path.join(repoRoot, '.devin', 'rules', 'knowledge.rules');
      const ok = result.exit === 0 && Boolean(block) && agents.includes('USER TOP') && agents.includes('USER BOTTOM') &&
        block.includes('Shared .knowledge bridge') && (runtime !== 'devin' || (fs.existsSync(devinRule) && !fs.existsSync(path.join(repoRoot, '.devin', 'rules', 'knowledge.md'))));
      check(`agents-single-${runtime}`, ok, { exit: result.exit, block: Boolean(block), devin_rule: fs.existsSync(devinRule) });
      if (block) singleHashes[runtime] = sha(block);
    });
  }
  check('agents-single-shared-hash', new Set(Object.values(singleHashes)).size === 1, singleHashes);

  const permutationHashes = {};
  for (const order of permutations(agentsRuntimes)) {
    const key = order.join('-');
    fixture(`permutation-${key}`, (repoRoot) => {
      fs.writeFileSync(path.join(repoRoot, 'AGENTS.md'), 'USER PRE\n\nUSER POST\n', 'utf8');
      const exits = order.map((runtime) => install(repoRoot, runtime).exit);
      const agentsPath = path.join(repoRoot, 'AGENTS.md');
      const agents = read(agentsPath);
      const block = managedBlock(agents);
      const attributesPath = path.join(repoRoot, '.gitattributes');
      const attrsBefore = read(attributesPath);
      const before = hashFile(agentsPath);
      for (const runtime of [...order].reverse()) install(repoRoot, runtime);
      const after = hashFile(agentsPath);
      const attrsAfter = read(attributesPath);
      const attributesOk = expectedAgentAttributes.every((item) => attrsAfter.includes(item)) && sha(attrsBefore) === sha(attrsAfter);
      check(`agents-perm-${key}`, exits.every((exit) => exit === 0) && Boolean(block) && agents.includes('USER PRE') && agents.includes('USER POST') && before === after && attributesOk && fs.existsSync(path.join(repoRoot, '.devin', 'rules', 'knowledge.rules')), { exits, before, after, attributes_ok: attributesOk });
      if (block) permutationHashes[key] = sha(block);
    });
  }
  check('agents-all-permutations-same-managed-block', new Set(Object.values(permutationHashes)).size === 1, { unique: new Set(Object.values(permutationHashes)).size });

  fixture('windsurf-does-not-change-agents', (repoRoot) => {
    install(repoRoot, 'devin');
    const before = hashFile(path.join(repoRoot, 'AGENTS.md'));
    const result = install(repoRoot, 'windsurf');
    const after = hashFile(path.join(repoRoot, 'AGENTS.md'));
    check('windsurf-does-not-change-agents', result.exit === 0 && before === after, { before, after });
  });

  for (const order of [['devin', 'windsurf'], ['windsurf', 'devin']]) {
    const key = order.join('-');
    fixture(`vendor-${key}`, (repoRoot) => {
      const exits = order.map((runtime) => install(repoRoot, runtime).exit);
      const devinPath = path.join(repoRoot, '.devin', 'rules', 'knowledge.rules');
      const windsurfPath = path.join(repoRoot, '.windsurf', 'rules', 'knowledge.md');
      const agentsPath = path.join(repoRoot, 'AGENTS.md');
      const before = [hashFile(devinPath), hashFile(windsurfPath), hashFile(agentsPath)];
      for (const runtime of order) install(repoRoot, runtime);
      const after = [hashFile(devinPath), hashFile(windsurfPath), hashFile(agentsPath)];
      const devin = read(devinPath);
      const windsurf = read(windsurfPath);
      check(`vendor-order-${key}`, exits.every((exit) => exit === 0) && before.join(':') === after.join(':') && devin.includes('# Devin .knowledge bridge') && !devin.includes('## Source-of-truth order') && windsurf.startsWith('---\ntrigger: always_on\n---\n') && !windsurf.includes('# Devin .knowledge bridge') && path.resolve(devinPath) !== path.resolve(windsurfPath), { before, after });
    });
  }

  const devinLegacy = `${managedStart}\n# Devin .knowledge rules\nlegacy devin\n${managedEnd}\n`;
  const windsurfLegacy = `${managedStart}\n# Windsurf Cascade .knowledge rules\nlegacy windsurf\n${managedEnd}\n`;
  fixture('legacy-mixed', (repoRoot) => {
    const legacyPath = path.join(repoRoot, '.devin', 'rules', 'knowledge.md');
    fs.mkdirSync(path.dirname(legacyPath), { recursive: true });
    fs.writeFileSync(legacyPath, `USER TOP\n${devinLegacy}MIDDLE\n${windsurfLegacy}USER BOTTOM\n`, 'utf8');
    const windsurf = install(repoRoot, 'windsurf');
    const middle = read(legacyPath);
    check('legacy-windsurf-removes-own-block-only', windsurf.exit === 0 && !middle.includes('legacy windsurf') && middle.includes('legacy devin') && middle.includes('USER TOP') && middle.includes('USER BOTTOM') && fs.existsSync(path.join(repoRoot, '.windsurf', 'rules', 'knowledge.md')), { exit: windsurf.exit });
    const devin = install(repoRoot, 'devin');
    const final = read(legacyPath);
    check('legacy-devin-removes-own-block-only', devin.exit === 0 && !final.includes('legacy devin') && final.includes('USER TOP') && final.includes('USER BOTTOM') && fs.existsSync(path.join(repoRoot, '.devin', 'rules', 'knowledge.rules')) && fs.existsSync(path.join(repoRoot, 'AGENTS.md')), { exit: devin.exit });
  });

  for (const runtime of ['devin', 'windsurf']) {
    fixture(`legacy-user-${runtime}`, (repoRoot) => {
      const legacyPath = path.join(repoRoot, '.devin', 'rules', 'knowledge.md');
      fs.mkdirSync(path.dirname(legacyPath), { recursive: true });
      fs.writeFileSync(legacyPath, 'USER CUSTOM ONLY\n', 'utf8');
      const before = hashFile(legacyPath);
      const result = install(repoRoot, runtime);
      check(`legacy-user-preserved-${runtime}`, result.exit === 0 && before === hashFile(legacyPath), { before, after: hashFile(legacyPath) });
    });
  }

  fixture('all', (repoRoot) => {
    fs.writeFileSync(path.join(repoRoot, 'AGENTS.md'), 'USER\n', 'utf8');
    const result = installAll(repoRoot);
    const agents = read(path.join(repoRoot, 'AGENTS.md'));
    const attributes = read(path.join(repoRoot, '.gitattributes'));
    const valid = result.exit === 0 && agents.includes('USER') && agents.split(managedStart).length - 1 === 1 && fs.existsSync(path.join(repoRoot, '.devin', 'rules', 'knowledge.rules')) && fs.existsSync(path.join(repoRoot, '.windsurf', 'rules', 'knowledge.md')) && !fs.existsSync(path.join(repoRoot, '.devin', 'rules', 'knowledge.md')) && expectedAgentAttributes.every((item) => attributes.includes(item));
    check('all-integrations-normal', valid, { exit: result.exit, status: result.report?.status });
    check('all-integrations-transaction-committed', result.report?.transaction?.status === 'committed' && result.report?.runtimes?.length === 12, {
      transaction_status: result.report?.transaction?.status || null,
      runtimes: result.report?.runtimes?.length || 0
    });
    const verify = installCheck(repoRoot);
    const bad = (verify.report?.issues || []).filter((item) => item.severity === 'error' && /(integration|devin|windsurf|agents)/i.test(item.code));
    check('all-integrations-install-check', verify.exit === 0 && bad.length === 0, bad);
  });

  fixture('malformed-package', (repoRoot) => {
    fs.writeFileSync(path.join(repoRoot, 'package.json'), '{MALFORMED-PACKAGE', 'utf8');
    const before = treeState(repoRoot);
    const result = installAll(repoRoot);
    const violations = result.report?.violations || [];
    check('malformed-package-zero-write', rejected(result, before, treeState(repoRoot)) &&
      violations.some((item) => item.code === 'integration_package_invalid'), {
      exit: result.exit, violations, rejection_evidence: result.rejection_evidence
    });
  });

  fixture('invalid-package-schema', (repoRoot) => {
    fs.writeFileSync(path.join(repoRoot, 'package.json'), '{"name":"fixture","scripts":[]}\n', 'utf8');
    const before = treeState(repoRoot);
    const result = installAll(repoRoot);
    const violations = result.report?.violations || [];
    check('invalid-package-schema-zero-write', rejected(result, before, treeState(repoRoot)) &&
      violations.some((item) => item.code === 'integration_package_invalid'), {
      exit: result.exit, violations, rejection_evidence: result.rejection_evidence
    });
  });

  fixture('hardlink-agents', (repoRoot) => external('hardlink-agents', (outside) => {
    const sentinel = path.join(outside, 'AGENTS.md');
    fs.writeFileSync(sentinel, 'EXTERNAL-SENTINEL\n', 'utf8');
    fs.linkSync(sentinel, path.join(repoRoot, 'AGENTS.md'));
    const before = treeState(repoRoot);
    const result = install(repoRoot, 'codex');
    const violations = result.report?.violations || [];
    check('hardlink-agents-zero-write', rejected(result, before, treeState(repoRoot), sentinel) &&
      violations.some((item) => item.code === 'integration_target_hardlinked'), {
      exit: result.exit, violations, rejection_evidence: result.rejection_evidence
    });
  }));

  fixture('hardlink-package', (repoRoot) => external('hardlink-package', (outside) => {
    fs.rmSync(path.join(repoRoot, 'package.json'), { force: true });
    const sentinel = path.join(outside, 'package.json');
    fs.writeFileSync(sentinel, 'EXTERNAL-SENTINEL\n', 'utf8');
    fs.linkSync(sentinel, path.join(repoRoot, 'package.json'));
    const before = treeState(repoRoot);
    const result = install(repoRoot, 'hermes');
    const violations = result.report?.violations || [];
    check('hardlink-package-zero-write', rejected(result, before, treeState(repoRoot), sentinel) &&
      violations.some((item) => item.code === 'integration_target_hardlinked'), {
      exit: result.exit, violations, rejection_evidence: result.rejection_evidence
    });
  }));

  const parentCases = [
    ['codex', '.agents', 'skills/kb-audit/SKILL.md'], ['claude', '.claude', 'skills/kb-audit/SKILL.md'],
    ['opencode', '.opencode', 'commands/kb-audit.md'], ['openclaw', '.agents', 'skills/kb-audit/SKILL.md'],
    ['copilot', '.github', 'copilot-instructions.md'], ['devin', '.devin', 'rules/knowledge.rules'],
    ['windsurf', '.windsurf', 'rules/knowledge.md'], ['continue', '.continue', 'rules/knowledge.md'], ['roo', '.roo', 'rules/knowledge.md']
  ];
  for (const [runtime, parent, relPath] of parentCases) {
    fixture(`containment-parent-${runtime}`, (repoRoot) => external(`parent-${runtime}`, (outside) => {
      createDirectoryLink(outside, path.join(repoRoot, parent));
      const before = treeState(repoRoot);
      const result = install(repoRoot, runtime);
      const after = treeState(repoRoot);
      check(`containment-parent-${runtime}`, rejected(result, before, after) && !fs.existsSync(path.join(outside, relPath)), { exit: result.exit, violations: result.report?.violations || null, rejection_evidence: result.rejection_evidence });
    }));
  }

  const nestedCases = [['codex', '.agents/skills'], ['claude', '.claude/skills'], ['opencode', '.opencode/commands'], ['devin', '.devin/rules'], ['windsurf', '.windsurf/rules'], ['continue', '.continue/rules'], ['roo', '.roo/rules']];
  for (const [runtime, nestedParent] of nestedCases) {
    fixture(`containment-nested-${runtime}`, (repoRoot) => external(`nested-${runtime}`, (outside) => {
      const target = path.join(repoRoot, ...nestedParent.split('/'));
      fs.mkdirSync(path.dirname(target), { recursive: true });
      createDirectoryLink(outside, target);
      const before = treeState(repoRoot);
      const externalBefore = treeState(outside);
      const result = install(repoRoot, runtime);
      const externalAfter = treeState(outside);
      check(`containment-nested-${runtime}`, rejected(result, before, treeState(repoRoot)) && JSON.stringify(externalBefore) === JSON.stringify(externalAfter), { exit: result.exit, violations: result.report?.violations || null, rejection_evidence: result.rejection_evidence, external_unchanged: JSON.stringify(externalBefore) === JSON.stringify(externalAfter) });
    }));
  }

  const rootFileCases = [['codex', 'AGENTS.md'], ['openclaw', 'AGENTS.md'], ['hermes', 'AGENTS.md'], ['devin', 'AGENTS.md'], ['claude', 'CLAUDE.md'], ['gemini', 'GEMINI.md'], ['aider', 'CONVENTIONS.md']];
  for (const [runtime, targetRel] of rootFileCases) {
    fixture(`containment-root-${runtime}`, (repoRoot) => external(`root-${runtime}`, (outside) => {
      const sentinel = path.join(outside, 'target');
      fs.writeFileSync(sentinel, 'EXTERNAL-SENTINEL\n', 'utf8');
      const linked = createFileLink(sentinel, path.join(repoRoot, targetRel));
      if (!linked.ok) return check(`containment-root-file-${runtime}`, true, null, linked);
      const before = treeState(repoRoot);
      const result = install(repoRoot, runtime);
      check(`containment-root-file-${runtime}`, rejected(result, before, treeState(repoRoot), sentinel), { exit: result.exit, violations: result.report?.violations || null });
    }));
  }

  const exactFileCases = [['copilot', '.github/copilot-instructions.md'], ['devin', '.devin/rules/knowledge.rules'], ['windsurf', '.windsurf/rules/knowledge.md'], ['continue', '.continue/rules/knowledge.md'], ['roo', '.roo/rules/knowledge.md'], ['aider', '.aider.conf.yml']];
  for (const [runtime, targetRel] of exactFileCases) {
    fixture(`containment-exact-${runtime}`, (repoRoot) => external(`exact-${runtime}`, (outside) => {
      const sentinel = path.join(outside, 'target');
      fs.writeFileSync(sentinel, 'EXTERNAL-SENTINEL\n', 'utf8');
      const target = path.join(repoRoot, ...targetRel.split('/'));
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const linked = createFileLink(sentinel, target);
      if (!linked.ok) return check(`containment-exact-file-${runtime}`, true, null, linked);
      const before = treeState(repoRoot);
      const result = install(repoRoot, runtime);
      check(`containment-exact-file-${runtime}`, rejected(result, before, treeState(repoRoot), sentinel), { exit: result.exit, violations: result.report?.violations || null });
    }));
  }

  for (const targetRel of ['package.json', '.gitattributes']) {
    fixture(`containment-system-${targetRel.replace(/[^a-z]/gi, '-')}`, (repoRoot) => external(`system-${targetRel}`, (outside) => {
      const target = path.join(repoRoot, targetRel);
      if (fs.existsSync(target)) fs.rmSync(target, { force: true });
      const sentinel = path.join(outside, 'target');
      fs.writeFileSync(sentinel, 'EXTERNAL-SENTINEL\n', 'utf8');
      const linked = createFileLink(sentinel, target);
      if (!linked.ok) return check(`containment-system-file-${targetRel}`, true, null, linked);
      const before = treeState(repoRoot);
      const result = install(repoRoot, 'hermes');
      check(`containment-system-file-${targetRel}`, rejected(result, before, treeState(repoRoot), sentinel), { exit: result.exit, violations: result.report?.violations || null });
    }));
  }

  fixture('all-unsafe', (repoRoot) => external('all-unsafe', (outside) => {
    createDirectoryLink(outside, path.join(repoRoot, '.windsurf'));
    const before = treeState(repoRoot);
    const externalBefore = treeState(outside);
    const result = installAll(repoRoot);
    const externalAfter = treeState(outside);
    check('all-preflight-transactional', rejected(result, before, treeState(repoRoot)) && JSON.stringify(externalBefore) === JSON.stringify(externalAfter), { exit: result.exit, violations: result.report?.violations || null, rejection_evidence: result.rejection_evidence, external_unchanged: JSON.stringify(externalBefore) === JSON.stringify(externalAfter) });
  }));

  fixture('install-check-unsafe', (repoRoot) => external('install-check-unsafe', (outside) => {
    createDirectoryLink(outside, path.join(repoRoot, '.windsurf'));
    const result = installCheck(repoRoot);
    const found = codes(result.report);
    check('install-check-detects-unsafe', result.exit !== 0 && (found.includes('integration_target_symlink') || found.includes('unsafe_integration_parent')), { exit: result.exit, codes: found });
  }));

  fixture('source-template-unsafe', (repoRoot) => external('source-template-unsafe', (outside) => {
    const source = path.join(repoRoot, '.knowledge', 'agent-integrations', 'gemini', 'GEMINI.md');
    const sentinel = path.join(outside, 'template');
    fs.writeFileSync(sentinel, 'EXTERNAL-SENTINEL\n', 'utf8');
    fs.rmSync(source, { force: true });
    const linked = createFileLink(sentinel, source);
    if (!linked.ok) return check('containment-source-template', true, null, linked);
    const before = treeState(repoRoot);
    const result = install(repoRoot, 'gemini');
    check('containment-source-template', rejected(result, before, treeState(repoRoot), sentinel) && !fs.existsSync(path.join(repoRoot, 'GEMINI.md')), { exit: result.exit, violations: result.report?.violations || null });
  }));

  fixture('source-directory-unsafe', (repoRoot) => external('source-directory-unsafe', (outside) => {
    const source = path.join(repoRoot, '.knowledge', 'agent-integrations', 'codex', 'skills');
    fs.rmSync(source, { recursive: true, force: true });
    createDirectoryLink(outside, source);
    const before = treeState(repoRoot);
    const externalBefore = treeState(outside);
    const result = install(repoRoot, 'codex');
    const externalAfter = treeState(outside);
    check('containment-source-copy-directory', rejected(result, before, treeState(repoRoot)) && !fs.existsSync(path.join(repoRoot, 'AGENTS.md')) && JSON.stringify(externalBefore) === JSON.stringify(externalAfter), { exit: result.exit, violations: result.report?.violations || null, rejection_evidence: result.rejection_evidence, external_unchanged: JSON.stringify(externalBefore) === JSON.stringify(externalAfter) });
  }));

  fixture('install-check-exact-copy', (repoRoot) => external('install-check-exact-copy', (outside) => {
    const sentinel = path.join(outside, 'skill');
    fs.writeFileSync(sentinel, 'EXTERNAL-SENTINEL\n', 'utf8');
    const target = path.join(repoRoot, '.agents', 'skills', 'kb-audit', 'SKILL.md');
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const linked = createFileLink(sentinel, target);
    if (!linked.ok) return check('install-check-detects-exact-copy-target', true, null, linked);
    const result = installCheck(repoRoot);
    const found = codes(result.report);
    check('install-check-detects-exact-copy-target', result.exit !== 0 && (found.includes('integration_target_symlink') || found.includes('unsafe_integration_parent')), { exit: result.exit, codes: found });
  }));

  fixture('parallel-agents', (repoRoot) => {
    fs.writeFileSync(path.join(repoRoot, 'AGENTS.md'), 'USER PARALLEL PRE\n\nUSER PARALLEL POST\n', 'utf8');
    const concurrentRunner = [
      "const { spawn } = require('child_process');",
      `const runtimes = ${JSON.stringify(agentsRuntimes)};`,
      "Promise.all(runtimes.map((runtime) => new Promise((resolve) => {",
      "  const child = spawn(process.execPath, ['.knowledge/tools/install-agent-integrations.js', '--runtime', runtime, '--no-package-scripts', '--no-install-check'], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, KNOWLEDGE_LOCK_TIMEOUT_MS: '1' } });",
      "  let stdout = ''; let stderr = '';",
      "  child.stdout.on('data', (chunk) => { stdout += chunk; });",
      "  child.stderr.on('data', (chunk) => { stderr += chunk; });",
      "  child.on('error', (error) => resolve([runtime, { exit_code: null, error: error.code || error.message, stdout, stderr }]));",
      "  child.on('exit', (code) => resolve([runtime, { exit_code: code, stdout, stderr }]));",
      "}))).then((pairs) => process.stdout.write(JSON.stringify(Object.fromEntries(pairs))));"
    ].join('\n');
    const parallel = spawnSync(process.execPath, ['-e', concurrentRunner], {
      cwd: repoRoot,
      encoding: 'utf8',
      windowsHide: true,
      timeout: 180000,
      env: fixtureEnv(repoRoot)
    });
    let exits = {};
    try { exits = JSON.parse(parallel.stdout || '{}'); } catch { exits = {}; }
    const agents = read(path.join(repoRoot, 'AGENTS.md'));
    const attributes = read(path.join(repoRoot, '.gitattributes'));
    check('parallel-agents-compatible-install', Object.keys(exits).length === agentsRuntimes.length && Object.values(exits).every((result) => result?.exit_code === 0) && agents.split(managedStart).length - 1 === 1 && agents.includes('USER PARALLEL PRE') && agents.includes('USER PARALLEL POST') && expectedAgentAttributes.every((item) => attributes.includes(item)) && fs.existsSync(path.join(repoRoot, '.devin', 'rules', 'knowledge.rules')), { exits, launcher_exit: parallel.status });
  });

  const report = {
    schema_version: 'agent-integration-coexistence-self-test.v2',
    generated_at: new Date().toISOString(),
    artifact: args.artifact ? path.resolve(args.artifact) : null,
    checks_total: checks.length,
    checks_passed: checks.filter((item) => item.status === 'pass').length,
    checks_blocked: checks.filter((item) => item.status === 'blocked').length,
    checks,
    status: checks.every((item) => item.status !== 'fail') ? 'pass' : 'fail'
  };
  if (args.out) {
    const out = path.resolve(args.out);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  }
  console.log(JSON.stringify(report, null, 2));
  if (report.checks_total !== 81 || report.status !== 'pass') process.exitCode = 2;
  return report;
}

if (require.main === module) run();
module.exports = { run };
