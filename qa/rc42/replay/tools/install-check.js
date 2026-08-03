#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  ensureDir,
  writeJsonAtomic,
  assertSafeContainmentRoot,
  assertSafeContainedPath
} = require('./lib/json-store');
const { inspectContextLockSafety } = require('./lib/contained-lock-manager');
const { resolveKnowledgeContext } = require('./lib/path-context');
const {
  allPotentialIntegrationTargetRelPaths,
  buildIntegrationWritePlan,
  supportedRuntimeIds
} = require('./install-agent-integrations');
const {
  loadInstallManifest
} = require('./update-system-files');

const knowledgeRoot = path.resolve(__dirname, '..');
const repoRoot = path.basename(knowledgeRoot).toLowerCase() === '.knowledge' ? path.dirname(knowledgeRoot) : process.cwd();
const knowledgeContext = resolveKnowledgeContext();
const stateRoot = knowledgeContext.stateRoot;
const legacyManagedMarker = ['KNOWLEDGE', 'KIT'].join('-');

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function rel(abs, base = repoRoot) {
  return normalizeRel(path.relative(base, abs));
}

function parseArgs(argv) {
  return {
    json: argv.includes('--json'),
    fix: argv.includes('--fix'),
    yes: argv.includes('--yes')
  };
}

function issue(issues, severity, code, message, artifact = null) {
  issues.push({ severity, code, message, artifact });
}

function compareNodeVersion(version) {
  const major = Number(String(version).replace(/^v/, '').split('.')[0]);
  return Number.isFinite(major) && major >= 18;
}

function commandExists(command, args, cwd) {
  const res = spawnSync(command, args, { cwd, encoding: 'utf8', windowsHide: true });
  return res.status === 0 ? (res.stdout || '').trim() : null;
}

function detectGitRoot() {
  return commandExists('git', ['rev-parse', '--show-toplevel'], repoRoot);
}

function isDirectory(filePath) {
  try { return fs.statSync(filePath).isDirectory(); } catch { return false; }
}

function isFile(filePath) {
  try { return fs.statSync(filePath).isFile(); } catch { return false; }
}

function safeReadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '')); }
  catch { return null; }
}

function safeReadText(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch { return null; }
}

const INTEGRATION_DIRECTORY_TARGETS = new Set([
  '.agents', '.agents/skills',
  '.claude', '.claude/skills',
  '.opencode', '.opencode/commands',
  '.github',
  '.devin', '.devin/rules',
  '.windsurf', '.windsurf/rules',
  '.continue', '.continue/rules',
  '.roo', '.roo/rules'
]);

function classifyIntegrationSafetyError(repoRoot, relPath, targetPath, error) {
  let code = 'unsafe_integration_target';
  let message = `Integration target is unsafe: ${relPath}. ${error.message}`;
  let leafStat = null;
  try { leafStat = fs.lstatSync(targetPath); } catch {}
  if (leafStat?.isSymbolicLink()) {
    code = 'integration_target_symlink';
    message = `Integration target is a symlink or junction: ${relPath}.`;
  } else if (error.code === 'integration_target_hardlinked') {
    code = 'integration_target_hardlinked';
    message = `Integration target is hardlinked and cannot be read safely: ${relPath}.`;
  } else if (/escapes containment root|outside/i.test(String(error.message))) {
    code = 'integration_target_outside_repo';
  } else if (/symlink|junction|reparse|parent is not a directory/i.test(String(error.message))) {
    code = 'unsafe_integration_parent';
  }
  return {
    severity: 'error',
    code,
    message,
    artifact: relPath,
    details: {
      target: targetPath,
      repo_root: repoRoot,
      os_code: error.code || null
    }
  };
}

function inspectIntegrationTargetSafety() {
  const findings = [];
  const unsafe = new Set();
  try {
    assertSafeContainmentRoot(repoRoot);
  } catch (error) {
    findings.push({
      severity: 'error',
      code: 'integration_target_outside_repo',
      message: `Repository root is not a safe physical containment root: ${error.message}`,
      artifact: '.',
      details: { repo_root: repoRoot, os_code: error.code || null }
    });
    return { findings, unsafe };
  }
  const relPaths = new Set(allPotentialIntegrationTargetRelPaths());
  try {
    const plan = buildIntegrationWritePlan(
      { targetRoot: repoRoot, systemRoot: knowledgeRoot },
      supportedRuntimeIds(),
      { updatePackageScripts: true }
    );
    for (const target of plan.targets || []) relPaths.add(normalizeRel(target.rel_path));
  } catch (error) {
    findings.push({
      severity: 'error',
      code: 'unsafe_integration_source',
      message: `Unable to build the integration safety plan: ${error.message}`,
      artifact: '.knowledge/agent-integrations',
      details: { os_code: error.code || null }
    });
  }
  for (const relPath of relPaths) {
    const normalized = normalizeRel(relPath);
    const target = path.join(repoRoot, ...normalized.split('/'));
    try {
      assertSafeContainedPath(repoRoot, target, { allowMissing: true });
      if (fs.existsSync(target)) {
        const stat = fs.lstatSync(target);
        if (INTEGRATION_DIRECTORY_TARGETS.has(normalized)) {
          if (!stat.isDirectory() || stat.isSymbolicLink()) {
            const error = new Error('Expected a physical integration directory.');
            error.code = 'contained_path_unsafe';
            throw error;
          }
        } else if (!stat.isFile() || stat.isSymbolicLink()) {
          const error = new Error('Expected a physical integration file.');
          error.code = 'contained_path_unsafe';
          throw error;
        } else if (Number(stat.nlink) !== 1) {
          const error = new Error('Integration target has more than one physical link.');
          error.code = 'integration_target_hardlinked';
          throw error;
        }
      }
    } catch (error) {
      unsafe.add(normalized);
      findings.push(classifyIntegrationSafetyError(repoRoot, normalized, target, error));
    }
  }
  return { findings, unsafe };
}

function countManagedKnowledgeBlocks(text) {
  const expression = new RegExp(`<!-- BEGIN (?:DOT-KNOWLEDGE|${legacyManagedMarker}) MANAGED BLOCK -->`, 'g');
  return (String(text || '').match(expression) || []).length;
}

function hasWindsurfAlwaysOnFrontmatter(text) {
  const normalized = String(text || '').replace(/\r\n/g, '\n');
  if (!normalized.startsWith('---\n')) return false;
  const end = normalized.indexOf('\n---\n', 4);
  if (end === -1) return false;
  return /^\s*trigger\s*:\s*always_on\s*$/m.test(normalized.slice(4, end));
}

function walkMarkdownFiles(rootDir) {
  const out = [];
  if (!isDirectory(rootDir)) return out;
  const stack = [rootDir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(abs);
      else if (entry.isFile() && /\.md$/i.test(entry.name)) out.push(abs);
    }
  }
  return out;
}

function packageScriptTargets(packageJson) {
  const out = [];
  for (const [name, command] of Object.entries(packageJson?.scripts || {})) {
    const match = String(command).match(/(?:^|\s)node\s+([^\s"']+\.js)(?:\s|$)/);
    if (!match) continue;
    out.push({ name, command, target: normalizeRel(match[1]) });
  }
  return out;
}

function documentedInstalledCommandTargets() {
  const out = [];
  const pattern = /node\s+\.knowledge\/([A-Za-z0-9_.\/-]+\.js)(?=\s|`|$)/g;
  const publicRoots = [
    knowledgeRoot,
    path.join(knowledgeRoot, 'docs'),
    path.join(knowledgeRoot, 'agent-integrations'),
    path.join(knowledgeRoot, 'commands'),
    path.join(knowledgeRoot, 'flows'),
    path.join(knowledgeRoot, 'skills')
  ];
  const files = [];
  for (const rootDir of publicRoots) {
    if (path.resolve(rootDir) === path.resolve(knowledgeRoot)) {
      for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
        if (entry.isFile() && /\.md$/i.test(entry.name)) files.push(path.join(rootDir, entry.name));
      }
    } else {
      files.push(...walkMarkdownFiles(rootDir));
    }
  }
  for (const filePath of Array.from(new Set(files))) {
    let text = '';
    try { text = fs.readFileSync(filePath, 'utf8'); } catch { continue; }
    let match;
    while ((match = pattern.exec(text)) !== null) {
      out.push({ document: rel(filePath, knowledgeRoot), target: normalizeRel(match[1]) });
    }
  }
  return out;
}

function legacyMetricsInstructions() {
  const roots = [
    path.join(knowledgeRoot, 'agent-integrations'),
    path.join(knowledgeRoot, 'tools', 'install-agent-integrations.js')
  ];
  const findings = [];
  const pattern = /estimated\s+tokens\s+saved\s+(?:and|plus)\s+(?:estimated\s+)?percent\s+saved/i;
  for (const candidate of roots) {
    const files = isDirectory(candidate)
      ? walkFilesForText(candidate)
      : (isFile(candidate) ? [candidate] : []);
    for (const filePath of files) {
      let text = '';
      try { text = fs.readFileSync(filePath, 'utf8'); } catch { continue; }
      if (pattern.test(text)) findings.push(rel(filePath, knowledgeRoot));
    }
  }
  return findings.sort();
}

function walkFilesForText(rootDir) {
  const out = [];
  if (!isDirectory(rootDir)) return out;
  const stack = [rootDir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(abs);
      else if (entry.isFile()) out.push(abs);
    }
  }
  return out;
}

function isKnowledgeSourceCheckout(dirPath, name = path.basename(dirPath)) {
  const lower = String(name || '').toLowerCase();
  const pkg = safeReadJson(path.join(dirPath, 'package.json')) || {};
  const hasKnowledgePackage = pkg.name === 'dot-knowledge' || pkg.name === 'knowledge' || /knowledge/.test(String(pkg.name || ''));
  const hasReleaseTool = isFile(path.join(dirPath, 'tools', 'package-release.js'));
  const hasInstallManifest = isFile(path.join(dirPath, 'install-manifest.json'));
  const hasQuickStart = isFile(path.join(dirPath, 'Quick-Start.md'));
  const hasSourceGit = isDirectory(path.join(dirPath, '.git'));
  return (
    lower === 'knowledge-src' ||
    lower.startsWith('knowledge-src') ||
    (hasKnowledgePackage && hasReleaseTool && hasInstallManifest) ||
    (hasSourceGit && hasReleaseTool && hasQuickStart)
  );
}

function detectSiblingSourceCheckouts() {
  const out = [];
  let entries = [];
  try { entries = fs.readdirSync(repoRoot, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (['.knowledge', '.agents', '.claude', '.opencode', 'node_modules', '.git'].includes(entry.name)) continue;
    const full = path.join(repoRoot, entry.name);
    if (isKnowledgeSourceCheckout(full, entry.name)) out.push(rel(full));
  }
  return out.sort();
}

function moveDirectory(src, dst) {
  ensureDir(path.dirname(dst));
  try {
    fs.renameSync(src, dst);
    return;
  } catch (error) {
    if (error.code !== 'EXDEV') throw error;
  }
  copyDirectory(src, dst);
  fs.rmSync(src, { recursive: true, force: true });
}

function copyDirectory(src, dst) {
  ensureDir(dst);
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const from = path.join(src, entry.name);
    const to = path.join(dst, entry.name);
    if (entry.isDirectory()) copyDirectory(from, to);
    else if (entry.isFile()) {
      ensureDir(path.dirname(to));
      fs.copyFileSync(from, to);
    }
  }
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function analyze(options = {}) {
  const issues = [];
  const fixesAvailable = [];
  const fixesApplied = [];
  const nextCommands = [];
  const integrationSafety = inspectIntegrationTargetSafety();
  issues.push(...integrationSafety.findings);
  const unsafeIntegrationTargets = integrationSafety.unsafe;
  const lockSafety = inspectContextLockSafety(knowledgeContext);
  for (const finding of lockSafety.findings) {
    issue(
      issues,
      'error',
      finding.code,
      `Lock safety validation failed (${finding.reason || 'unsafe_lock'}).`,
      '.knowledge/locks'
    );
  }

  const installManifest = loadInstallManifest(knowledgeRoot);
  const rawInstallManifest = safeReadJson(path.join(knowledgeRoot, 'install-manifest.json')) || {};
  const requiredSystemFiles = Array.from(new Set([
    'Quick-Start.md',
    'README.md',
    'tools/flow.js',
    ...(installManifest.required_system_files || [])
  ]));

  if (!compareNodeVersion(process.version)) {
    issue(issues, 'error', 'node_version_unsupported', `Node.js ${process.version} is unsupported. Use Node.js >=18.`, null);
  }

  if (path.basename(knowledgeRoot).toLowerCase() !== '.knowledge') {
    issue(issues, 'warning', 'non_repo_local_layout', `This tool is running from ${knowledgeRoot}; installed repo-local mode expects a .knowledge directory.`, rel(knowledgeRoot));
  }

  const gitRoot = detectGitRoot();
  if (gitRoot && path.resolve(gitRoot) !== path.resolve(repoRoot)) {
    issue(issues, 'warning', 'git_root_mismatch', `Git root is ${gitRoot}, expected ${repoRoot}.`, null);
  }

  const nestedGit = path.join(knowledgeRoot, '.git');
  if (isDirectory(nestedGit)) {
    issue(issues, 'error', 'nested_knowledge_git', 'Nested .knowledge/.git detected. Install from the release artifact, not by copying the source checkout.', '.knowledge/.git');
    fixesAvailable.push({ code: 'move_nested_git', command: 'node .knowledge/tools/install-check.js --fix --yes' });
  }

  const nestedGithub = path.join(knowledgeRoot, '.github');
  if (isDirectory(nestedGithub)) {
    issue(issues, 'error', 'source_repo_copied_into_knowledge', 'A source .github directory exists inside .knowledge. This usually means the whole source repo was copied instead of the release artifact.', '.knowledge/.github');
  }

  const siblingSourceCheckouts = detectSiblingSourceCheckouts();
  for (const sourceCheckout of siblingSourceCheckouts) {
    issue(
      issues,
      'error',
      'source_checkout_in_target_root',
      `Knowledge source checkout detected at ${sourceCheckout}. Install from the release asset only, and keep source checkouts outside the target project.`,
      sourceCheckout
    );
  }
  if (siblingSourceCheckouts.length) {
    fixesAvailable.push({
      code: 'move_source_checkout_outside_target',
      command: 'Move the source checkout folder outside this repository, then rerun node .knowledge/tools/install-check.js --json.'
    });
  }

  for (const required of requiredSystemFiles) {
    if (!isFile(path.join(knowledgeRoot, required))) {
      issue(issues, 'error', 'missing_system_file', `Missing required system file: ${required}`, `.knowledge/${required}`);
    }
  }

  const packageJson = safeReadJson(path.join(knowledgeRoot, 'package.json')) || {};
  for (const script of packageScriptTargets(packageJson)) {
    if (!isFile(path.join(knowledgeRoot, script.target))) {
      issue(
        issues,
        'error',
        'public_package_script_target_missing',
        `Package script ${script.name} points to missing target ${script.target}.`,
        `.knowledge/package.json`
      );
    }
  }

  const publicSelfTests = [...(rawInstallManifest.release_contract?.public_self_test_paths || [])]
    .map((item) => String(item).replace(/\\/g, '/'))
    .sort();
  const sourceOnlySelfTests = new Set((rawInstallManifest.release_contract?.source_only_test_paths || [])
    .map((item) => String(item).replace(/\\/g, '/')));
  const physicalSelfTests = isDirectory(path.join(knowledgeRoot, 'tools'))
    ? fs.readdirSync(path.join(knowledgeRoot, 'tools'), { withFileTypes: true })
      .filter((entry) => entry.isFile() && /^self-test-.*\.js$/i.test(entry.name))
      .map((entry) => `tools/${entry.name}`)
      .filter((item) => !sourceOnlySelfTests.has(item))
      .sort()
    : [];
  if (JSON.stringify(publicSelfTests) !== JSON.stringify(physicalSelfTests)) {
    issue(
      issues,
      'error',
      'public_self_test_allowlist_mismatch',
      'release_contract.public_self_test_paths does not exactly match the installed public self-test set.',
      '.knowledge/install-manifest.json'
    );
  }

  for (const command of documentedInstalledCommandTargets()) {
    if (!isFile(path.join(knowledgeRoot, command.target))) {
      issue(
        issues,
        'error',
        'documented_installed_command_target_missing',
        `${command.document} points to missing installed target ${command.target}.`,
        `.knowledge/${command.document}`
      );
    }
  }

  for (const obsolete of installManifest.system_remove_paths || []) {
    if (fs.existsSync(path.join(knowledgeRoot, obsolete))) {
      issue(
        issues,
        'error',
        'obsolete_system_path_present',
        `Obsolete or source-only system path is present: ${obsolete}.`,
        `.knowledge/${obsolete}`
      );
    }
  }

  const staleMetrics = legacyMetricsInstructions();
  for (const artifact of staleMetrics) {
    issue(
      issues,
      'error',
      'legacy_metrics_reporting_instruction',
      'Agent integration still requires the obsolete saved-token reporting contract.',
      `.knowledge/${artifact}`
    );
  }

  const agentsText = unsafeIntegrationTargets.has('AGENTS.md') ? null : safeReadText(path.join(repoRoot, 'AGENTS.md'));
  if (agentsText !== null) {
    const managedBlocks = countManagedKnowledgeBlocks(agentsText);
    if (managedBlocks > 1) {
      issue(issues, 'error', 'duplicate_agents_managed_blocks', 'AGENTS.md contains more than one .knowledge managed block.', 'AGENTS.md');
    } else if (managedBlocks === 1 && !agentsText.includes('# Shared .knowledge bridge for AGENTS.md-compatible agents')) {
      issue(issues, 'warning', 'legacy_runtime_specific_agents_bridge', 'AGENTS.md still contains a runtime-specific .knowledge bridge. Reinstall an AGENTS.md-compatible runtime to migrate to the shared block.', 'AGENTS.md');
      nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime codex');
    }
  }

  const legacyDevinRulePath = path.join(repoRoot, '.devin', 'rules', 'knowledge.md');
  const legacyDevinRule = unsafeIntegrationTargets.has('.devin/rules/knowledge.md') ? null : safeReadText(legacyDevinRulePath);
  if (legacyDevinRule && (legacyDevinRule.includes('# Windsurf Cascade .knowledge rules') || legacyDevinRule.includes('# Windsurf Cascade .knowledge bridge'))) {
    issue(issues, 'warning', 'legacy_windsurf_rule_in_devin_path', 'A legacy generated Windsurf rule is still stored under .devin. Reinstall Windsurf to migrate only that managed block to .windsurf/rules/knowledge.md.', '.devin/rules/knowledge.md');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime windsurf');
  }
  if (legacyDevinRule && (legacyDevinRule.includes('# Devin .knowledge rules') || legacyDevinRule.includes('# Devin .knowledge bridge'))) {
    issue(issues, 'warning', 'legacy_devin_markdown_rule', 'A legacy generated Devin Markdown rule is still present. Reinstall Devin to migrate its managed block to .devin/rules/knowledge.rules and the shared AGENTS.md bridge.', '.devin/rules/knowledge.md');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime devin');
  }

  const devinRulePath = path.join(repoRoot, '.devin', 'rules', 'knowledge.rules');
  const devinRule = unsafeIntegrationTargets.has('.devin/rules/knowledge.rules') ? null : safeReadText(devinRulePath);
  if (devinRule !== null) {
    if (!devinRule.includes('# Devin .knowledge bridge')) {
      issue(issues, 'warning', 'unrecognized_devin_rule', 'The Devin vendor rule is not recognized as the current managed bridge.', '.devin/rules/knowledge.rules');
    }
    if (!agentsText || !agentsText.includes('# Shared .knowledge bridge for AGENTS.md-compatible agents')) {
      issue(issues, 'error', 'devin_primary_agents_bridge_missing', 'Devin requires the documented repository-root AGENTS.md bridge in addition to the separate vendor rule.', 'AGENTS.md');
      nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime devin');
    }
  }

  const windsurfRulePath = path.join(repoRoot, '.windsurf', 'rules', 'knowledge.md');
  const windsurfRule = unsafeIntegrationTargets.has('.windsurf/rules/knowledge.md') ? null : safeReadText(windsurfRulePath);
  if (windsurfRule !== null) {
    if (!windsurfRule.includes('# Windsurf Cascade .knowledge bridge')) {
      issue(issues, 'warning', 'unrecognized_windsurf_rule', 'The Windsurf .knowledge rule is not recognized as the current managed bridge.', '.windsurf/rules/knowledge.md');
    }
    if (!hasWindsurfAlwaysOnFrontmatter(windsurfRule)) {
      issue(issues, 'error', 'windsurf_rule_frontmatter_invalid', 'The Windsurf workspace rule must declare `trigger: always_on` in top-level frontmatter.', '.windsurf/rules/knowledge.md');
    }
  }

  if (devinRule !== null && windsurfRule !== null && path.resolve(devinRulePath) === path.resolve(windsurfRulePath)) {
    issue(issues, 'error', 'devin_windsurf_path_collision', 'Devin and Windsurf rules must use separate files.', '.devin/rules/knowledge.rules');
  }

  if (!fs.existsSync(path.join(knowledgeRoot, 'maintenance', 'routing_bundle.json'))) {
    issue(issues, 'info', 'fresh_runtime_missing', 'maintenance/routing_bundle.json is absent. This is normal before first flow import.', '.knowledge/maintenance/routing_bundle.json');
  }

  if (!fs.existsSync(path.join(knowledgeRoot, '.gitignore'))) {
    issue(issues, 'warning', 'knowledge_gitignore_missing', 'Missing .knowledge/.gitignore. Runtime artifacts may appear in git status.', '.knowledge/.gitignore');
  }

  if (!fs.existsSync(path.join(repoRoot, '.gitattributes'))) {
    issue(issues, 'info', 'root_gitattributes_optional', 'Root .gitattributes is optional. See .knowledge/templates/git-policy/gitattributes.snippet for recommendations.', '.gitattributes');
  }

  const hasErrors = issues.some((item) => item.severity === 'error');
  const hasWarnings = issues.some((item) => item.severity === 'warning');
  const routingExists = fs.existsSync(path.join(knowledgeRoot, 'maintenance', 'routing_bundle.json'));
  const systemFilesOk = requiredSystemFiles.every((file) =>
    isFile(path.join(knowledgeRoot, file)));
  const mode = hasErrors ? 'broken' : (!systemFilesOk ? 'broken' : (routingExists ? 'configured' : 'fresh'));
  const status = hasErrors ? 'failed' : (hasWarnings ? 'warning' : 'ok');

  if (mode === 'fresh') {
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime codex');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime claude');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime opencode');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime gemini');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime copilot');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime devin');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime windsurf');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime continue');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime roo');
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js --runtime aider');
    nextCommands.push('node .knowledge/tools/flow.js import');
  } else if (mode === 'configured') {
    nextCommands.push('node .knowledge/tools/flow.js release --no-color');
  }
  if (fixesAvailable.length && !fixesApplied.length) nextCommands.unshift('node .knowledge/tools/install-check.js --fix --yes');

  return {
    status,
    mode,
    repo_root: repoRoot,
    knowledge_root: knowledgeRoot,
    state_root: stateRoot,
    lock_safety: lockSafety,
    issues,
    fixes_available: fixesAvailable,
    fixes_applied: fixesApplied,
    next_commands: nextCommands
  };
}

function applyFixes() {
  const fixesApplied = [];
  const nestedGit = path.join(knowledgeRoot, '.git');
  if (isDirectory(nestedGit)) {
    const backupDir = path.join(knowledgeRoot, 'maintenance', 'install-backups', `nested-git-${timestamp()}`);
    moveDirectory(nestedGit, backupDir);
    fixesApplied.push({ code: 'move_nested_git', from: '.knowledge/.git', to: `.knowledge/${rel(backupDir, knowledgeRoot)}` });
  }
  return fixesApplied;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  let result = analyze();
  if (options.fix && !options.yes) {
    result = {
      ...result,
      status: 'failed',
      mode: 'broken',
      issues: [
        ...result.issues,
        { severity: 'error', code: 'fix_requires_yes', message: 'Refusing to apply fixes without --yes.', artifact: null }
      ]
    };
  } else if (options.fix && options.yes) {
    const preFix = analyze();
    const fixesApplied = applyFixes();
    const postFix = analyze();
    const reportPath = path.join(knowledgeRoot, 'maintenance', 'install_check_report.json');
    result = {
      ...postFix,
      fixes_applied: fixesApplied,
      pre_fix: preFix,
      post_fix: postFix,
      report: '.knowledge/maintenance/install_check_report.json',
      generated_at: new Date().toISOString()
    };
    ensureDir(path.dirname(reportPath));
    writeJsonAtomic(reportPath, result);
  }
  console.log(JSON.stringify(result, null, 2));
  if (result.status === 'failed') process.exit(2);
}

if (require.main === module) main();

module.exports = { analyze };
