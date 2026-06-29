#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { ensureDir, readJson, writeJsonAtomic } = require('./lib/json-store');

const defaultKnowledgeRoot = path.resolve(__dirname, '..');
const defaultRepoRoot = path.basename(defaultKnowledgeRoot).toLowerCase() === '.knowledge' ? path.dirname(defaultKnowledgeRoot) : process.cwd();
let activeKnowledgeRoot = defaultKnowledgeRoot;
let activeRepoRoot = defaultRepoRoot;

const DEFAULT_MANIFEST = {
  schema_version: '3.2.2',
  system_paths: [
    '.gitattributes',
    '.gitignore',
    '.release-notes',
    'README.md',
    'Quick-Start.md',
    'Portal.md',
    'CHANGELOG.md',
    'RELEASE_NOTES.md',
    'SECURITY.md',
    'SBOM.memory.json',
    'THIRD_PARTY_NOTICES.md',
    'LICENSE',
    'NOTICE',
    'package.json',
    'config.yaml',
    'inspector.js',
    'open-inspector.vbs',
    'assets',
    'agent-integrations',
    'benchmarks',
    'commands',
    'docs',
    'flows',
    'github-action-templates',
    'memory-providers',
    'models',
    'skills',
    'templates',
    'tools',
    'install-manifest.json'
  ],
  project_preserve_paths: [
    'project_index.json',
    'freshness.json',
    'decisions.json',
    'contradictions.json',
    'glossary.json',
    'evidence',
    'external_memory',
    'invariants',
    'maintenance',
    'maps',
    'metrics',
    'modules',
    'search',
    'sessions',
    'wiki',
    'inspector'
  ],
  curated_preserve_paths: [
    'wiki',
    'modules',
    'evidence',
    'decisions.json',
    'glossary.json',
    'contradictions.json',
    'project_index.json'
  ],
  runtime_regenerate_paths: [
    'freshness.json',
    'external_memory',
    'maintenance',
    'maps',
    'metrics',
    'search',
    'inspector'
  ],
  repair_default_paths: [
    'external_memory/registry.json',
    'external_memory/retrieval_policy.json'
  ],
  system_exclude_paths: [
    'benchmarks/results',
    'benchmark-runs',
    'dist',
    '.git',
    '.github',
    '.self-test-tmp',
    '.qa-tmp',
    'node_modules',
    'maintenance/install-backups',
    'maintenance/flow-logs',
    'maintenance/events',
    'maintenance/dev-notes',
    'evaluation/results',
    'search',
    '.lock',
    '.runtime'
  ],
  forbidden_paths: [
    '.git',
    '.github',
    'node_modules',
    'dist',
    '.env',
    '.env.local'
  ]
};

const SYSTEM_PATHS = DEFAULT_MANIFEST.system_paths;
const PROJECT_PATHS = DEFAULT_MANIFEST.project_preserve_paths;

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/g, '');
}

function uniqueNormalized(values) {
  return Array.from(new Set((values || []).map(normalizeRel).filter(Boolean)));
}

function parseArgs(argv) {
  const args = {
    from: null,
    targetKnowledgeRoot: null,
    dryRun: false,
    apply: false,
    yes: false,
    json: false,
    verifyUpgrade: false,
    preflight: false,
    repairDefaults: true,
    postUpgradeTrustRefresh: 'repair_queue'
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--from') args.from = argv[++i];
    else if (arg.startsWith('--from=')) args.from = arg.slice('--from='.length);
    else if (arg === '--target-knowledge-root' || arg === '--target') args.targetKnowledgeRoot = argv[++i];
    else if (arg.startsWith('--target-knowledge-root=')) args.targetKnowledgeRoot = arg.slice('--target-knowledge-root='.length);
    else if (arg.startsWith('--target=')) args.targetKnowledgeRoot = arg.slice('--target='.length);
    else if (arg === '--dry-run') args.dryRun = true;
    else if (arg === '--apply') args.apply = true;
    else if (arg === '--yes') args.yes = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--verify-upgrade') args.verifyUpgrade = true;
    else if (arg === '--preflight') args.preflight = true;
    else if (arg === '--no-repair-defaults') args.repairDefaults = false;
    else if (arg === '--repair-defaults') args.repairDefaults = true;
    else if (arg.startsWith('--repair-defaults=')) args.repairDefaults = !['false', '0', 'no', 'off'].includes(arg.slice('--repair-defaults='.length).toLowerCase());
    else if (arg === '--post-upgrade-trust-refresh') args.postUpgradeTrustRefresh = argv[++i];
    else if (arg.startsWith('--post-upgrade-trust-refresh=')) args.postUpgradeTrustRefresh = arg.slice('--post-upgrade-trust-refresh='.length);
  }
  if (!args.verifyUpgrade && !args.preflight && !args.dryRun && !args.apply) args.dryRun = true;
  return args;
}

function configureTarget(targetArg) {
  if (!targetArg) return;
  const resolved = path.resolve(process.cwd(), targetArg);
  if (path.basename(resolved).toLowerCase() === '.knowledge') {
    activeKnowledgeRoot = resolved;
    activeRepoRoot = path.dirname(resolved);
    return;
  }
  const nested = path.join(resolved, '.knowledge');
  if (fs.existsSync(nested) || !fs.existsSync(resolved)) {
    activeKnowledgeRoot = nested;
    activeRepoRoot = resolved;
    return;
  }
  activeKnowledgeRoot = resolved;
  activeRepoRoot = path.dirname(resolved);
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function isDirectory(filePath) {
  try { return fs.statSync(filePath).isDirectory(); } catch { return false; }
}

function isFile(filePath) {
  try { return fs.statSync(filePath).isFile(); } catch { return false; }
}

function walkFiles(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      const rel = normalizeRel(path.relative(root, abs));
      const parts = rel.split('/');
      if (parts.includes('.git') || parts.includes('node_modules')) continue;
      if (rel.includes('.tmp-') || rel.includes('.bak-')) continue;
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) out.push({ abs, rel });
    }
  }
  walk(root);
  out.sort((a, b) => a.rel.localeCompare(b.rel));
  return out;
}

function loadInstallManifest(root = activeKnowledgeRoot) {
  const manifestPath = path.join(root, 'install-manifest.json');
  const raw = fs.existsSync(manifestPath) ? readJson(manifestPath, {}) : {};
  return {
    schema_version: raw.schema_version || DEFAULT_MANIFEST.schema_version,
    system_paths: uniqueNormalized(raw.system_paths || DEFAULT_MANIFEST.system_paths),
    project_preserve_paths: uniqueNormalized(raw.project_preserve_paths || DEFAULT_MANIFEST.project_preserve_paths),
    curated_preserve_paths: uniqueNormalized(raw.curated_preserve_paths || DEFAULT_MANIFEST.curated_preserve_paths),
    runtime_regenerate_paths: uniqueNormalized(raw.runtime_regenerate_paths || DEFAULT_MANIFEST.runtime_regenerate_paths),
    repair_default_paths: uniqueNormalized(raw.repair_default_paths || raw.project_default_paths || DEFAULT_MANIFEST.repair_default_paths),
    system_exclude_paths: uniqueNormalized(raw.system_exclude_paths || DEFAULT_MANIFEST.system_exclude_paths),
    forbidden_paths: uniqueNormalized(raw.forbidden_paths || DEFAULT_MANIFEST.forbidden_paths),
    manifest_path: fs.existsSync(manifestPath) ? manifestPath : null,
    used_default: !fs.existsSync(manifestPath)
  };
}

function sourcePathFor(sourceRoot, relPath) {
  const rel = normalizeRel(relPath);
  if (rel === '.gitignore') {
    const installedTemplate = path.join(sourceRoot, 'templates', 'git-policy', '.knowledge.gitignore');
    if (fs.existsSync(installedTemplate)) return installedTemplate;
  }
  return path.join(sourceRoot, rel);
}

function isExcludedByManifest(relPath, manifest) {
  const rel = normalizeRel(relPath);
  return (manifest.system_exclude_paths || []).some((excluded) => rel === excluded || rel.startsWith(`${excluded}/`));
}

function resolveSourceRoot(fromArg) {
  if (!fromArg) throw new Error('Missing --from <new-knowledge-root>.');
  const candidate = path.resolve(process.cwd(), fromArg);
  const direct = path.join(candidate, 'tools', 'flow.js');
  const nested = path.join(candidate, '.knowledge', 'tools', 'flow.js');
  if (fs.existsSync(direct)) return candidate;
  if (fs.existsSync(nested)) return path.join(candidate, '.knowledge');
  throw new Error(`Cannot find a .knowledge root at ${candidate}. Expected tools/flow.js or .knowledge/tools/flow.js.`);
}

function sourceMissingSystemPaths(sourceRoot, manifest) {
  return manifest.system_paths.filter((relPath) => !fs.existsSync(sourcePathFor(sourceRoot, relPath)));
}

function planActions(sourceRoot, options = {}) {
  const targetRoot = options.targetKnowledgeRoot || activeKnowledgeRoot;
  const manifest = options.manifest || loadInstallManifest(sourceRoot);
  const actions = [];
  for (const relPath of manifest.system_paths) {
    const src = sourcePathFor(sourceRoot, relPath);
    const dst = path.join(targetRoot, relPath);
    if (!fs.existsSync(src)) {
      actions.push({ action: 'skip', path: relPath, reason: 'source_missing' });
      continue;
    }
    if (isDirectory(src)) {
      const files = walkFiles(src)
        .filter((file) => !isExcludedByManifest(path.posix.join(relPath, file.rel), manifest));
      if (!fs.existsSync(dst)) actions.push({ action: 'create', path: relPath, kind: 'directory' });
      for (const file of files) {
        const dstFile = path.join(dst, file.rel);
        const relFile = normalizeRel(path.posix.join(relPath, file.rel));
        if (!fs.existsSync(dstFile)) actions.push({ action: 'create', path: relFile, kind: 'file' });
        else if (!isFile(dstFile)) actions.push({ action: 'update', path: relFile, reason: 'replace_non_file', kind: 'file' });
        else if (sha256(file.abs) !== sha256(dstFile)) actions.push({ action: 'update', path: relFile, kind: 'file' });
        else actions.push({ action: 'skip', path: relFile, reason: 'unchanged' });
      }
      continue;
    }
    if (isFile(src)) {
      if (!fs.existsSync(dst)) actions.push({ action: 'create', path: relPath, kind: 'file' });
      else if (!isFile(dst)) actions.push({ action: 'update', path: relPath, reason: 'replace_non_file', kind: 'file' });
      else if (sha256(src) !== sha256(dst)) actions.push({ action: 'update', path: relPath, kind: 'file' });
      else actions.push({ action: 'skip', path: relPath, reason: 'unchanged' });
    }
  }

  for (const relPath of manifest.project_preserve_paths) {
    if (fs.existsSync(path.join(targetRoot, relPath))) actions.push({ action: 'preserve', path: relPath, reason: 'project_specific' });
  }
  return actions;
}

function planRepairDefaults(sourceRoot, manifest, options = {}) {
  if (options.repairDefaults === false) return [];
  const targetRoot = options.targetKnowledgeRoot || activeKnowledgeRoot;
  const actions = [];
  for (const relPath of manifest.repair_default_paths || []) {
    const src = sourcePathFor(sourceRoot, relPath);
    const dst = path.join(targetRoot, relPath);
    if (!fs.existsSync(src)) {
      actions.push({ action: 'skip', path: relPath, reason: 'source_missing', kind: 'repair_default' });
      continue;
    }
    if (fs.existsSync(dst)) {
      actions.push({ action: 'skip', path: relPath, reason: 'target_exists', kind: 'repair_default' });
      continue;
    }
    actions.push({ action: 'repair_default', path: relPath, reason: 'missing_project_default', kind: 'file' });
  }
  return actions;
}

function copyFile(src, dst) {
  ensureDir(path.dirname(dst));
  fs.copyFileSync(src, dst);
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function copyKnowledgeBackup() {
  const backupRoot = path.join(activeKnowledgeRoot, 'maintenance', 'install-backups', `system-files-${timestamp()}`);
  function copyDir(src, dst) {
    ensureDir(dst);
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
      const from = path.join(src, entry.name);
      const rel = normalizeRel(path.relative(activeKnowledgeRoot, from));
      if (rel.startsWith('.lock/') || rel.startsWith('.runtime/')) continue;
      if (rel.startsWith('maintenance/install-backups/')) continue;
      const to = path.join(dst, entry.name);
      if (entry.isDirectory()) copyDir(from, to);
      else if (entry.isFile()) copyFile(from, to);
    }
  }
  copyDir(activeKnowledgeRoot, backupRoot);
  return backupRoot;
}

function contextEnv(extra = {}) {
  return {
    ...process.env,
    ...extra,
    KNOWLEDGE_SYSTEM_ROOT: activeKnowledgeRoot,
    KNOWLEDGE_TARGET_ROOT: activeRepoRoot,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: activeKnowledgeRoot,
    KNOWLEDGE_STATE_ROOT: activeKnowledgeRoot
  };
}

function runNode(script, args, label = null) {
  const res = spawnSync(process.execPath, [path.join(activeKnowledgeRoot, 'tools', script), ...args], {
    cwd: activeRepoRoot,
    env: contextEnv(),
    encoding: 'utf8',
    windowsHide: true
  });
  return {
    label: label || script.replace(/\.js$/, ''),
    command: `node .knowledge/tools/${script}${args.length ? ' ' + args.join(' ') : ''}`,
    exit: res.status,
    stdout: (res.stdout || '').trim().slice(0, 12000),
    stderr: (res.stderr || '').trim().slice(0, 4000)
  };
}

function assertSystemWriteAllowed(actionPath, manifest) {
  const rel = normalizeRel(actionPath);
  const allowed = manifest.system_paths.some((systemPath) => rel === systemPath || rel.startsWith(`${systemPath}/`));
  if (!allowed) throw new Error(`Refusing to write non-system path: ${actionPath}`);
  if (isExcludedByManifest(rel, manifest)) throw new Error(`Refusing to write excluded system path: ${actionPath}`);
}

function assertRepairDefaultWriteAllowed(actionPath, manifest) {
  const rel = normalizeRel(actionPath);
  const allowed = (manifest.repair_default_paths || []).some((defaultPath) => rel === defaultPath);
  if (!allowed) throw new Error(`Refusing to write non-repair-default path: ${actionPath}`);
  if (isExcludedByManifest(rel, manifest)) throw new Error(`Refusing to write excluded repair default path: ${actionPath}`);
}

function applyActions(sourceRoot, actions, manifest) {
  for (const action of actions) {
    if (!['create', 'update'].includes(action.action)) continue;
    assertSystemWriteAllowed(action.path, manifest);
    const dst = path.join(activeKnowledgeRoot, action.path);
    if (action.kind === 'directory') {
      ensureDir(dst);
      continue;
    }
    copyFile(sourcePathFor(sourceRoot, action.path), dst);
  }
}

function applyRepairDefaults(sourceRoot, actions, manifest) {
  for (const action of actions) {
    if (action.action !== 'repair_default') continue;
    assertRepairDefaultWriteAllowed(action.path, manifest);
    const dst = path.join(activeKnowledgeRoot, action.path);
    if (fs.existsSync(dst)) continue;
    copyFile(sourcePathFor(sourceRoot, action.path), dst);
  }
}

function snapshotPath(root, relPath) {
  const abs = path.join(root, relPath);
  if (!fs.existsSync(abs)) return { exists: false, files: new Map() };
  if (isFile(abs)) return { exists: true, files: new Map([[normalizeRel(relPath), sha256(abs)]]) };
  const files = new Map();
  for (const file of walkFiles(abs)) files.set(normalizeRel(path.posix.join(relPath, file.rel)), sha256(file.abs));
  return { exists: true, files };
}

function curatedPreservationProof(backupRoot, manifest) {
  if (!backupRoot) return null;
  const paths = [];
  const changedFiles = [];
  for (const relPath of manifest.curated_preserve_paths) {
    const before = snapshotPath(backupRoot, relPath);
    const after = snapshotPath(activeKnowledgeRoot, relPath);
    const keys = Array.from(new Set([...before.files.keys(), ...after.files.keys()])).sort();
    const changed = keys.filter((key) => before.files.get(key) !== after.files.get(key));
    changedFiles.push(...changed);
    paths.push({
      path: relPath,
      backup_exists: before.exists,
      current_exists: after.exists,
      compared_files: keys.length,
      changed_files: changed
    });
  }
  return {
    status: changedFiles.length ? 'changed' : 'preserved',
    paths,
    changed_files: changedFiles,
    changed_files_count: changedFiles.length
  };
}

function verifySystemCompleteness(sourceRoot, manifest) {
  const missingSystemPaths = [];
  const sourceMissing = [];
  for (const relPath of manifest.system_paths) {
    const src = sourcePathFor(sourceRoot, relPath);
    if (!fs.existsSync(src)) {
      sourceMissing.push(relPath);
      continue;
    }
    const dst = path.join(activeKnowledgeRoot, relPath);
    if (!fs.existsSync(dst)) missingSystemPaths.push(relPath);
    if (isDirectory(src)) {
      for (const file of walkFiles(src)) {
        const relFile = normalizeRel(path.posix.join(relPath, file.rel));
        if (isExcludedByManifest(relFile, manifest)) continue;
        if (!fs.existsSync(path.join(activeKnowledgeRoot, relFile))) missingSystemPaths.push(relFile);
      }
    }
  }
  return {
    status: sourceMissing.length || missingSystemPaths.length ? 'failed' : 'ok',
    source_missing_system_paths: sourceMissing,
    missing_system_paths: missingSystemPaths
  };
}

function verifyInstalledSystemPaths(manifest) {
  const missingSystemPaths = manifest.system_paths.filter((relPath) => !fs.existsSync(path.join(activeKnowledgeRoot, relPath)));
  return {
    status: missingSystemPaths.length ? 'failed' : 'ok',
    source_missing_system_paths: [],
    missing_system_paths: missingSystemPaths
  };
}

function markerCounts(filePath) {
  if (!fs.existsSync(filePath)) return { exists: false, blocks: 0, dotKnowledge: 0, knowledgeKit: 0 };
  const text = fs.readFileSync(filePath, 'utf8');
  const legacyMarker = ['KNOWLEDGE', 'KIT'].join('-');
  const anyMarkerPattern = new RegExp(`<!-- BEGIN (?:DOT-KNOWLEDGE|${legacyMarker}) MANAGED BLOCK -->`, 'g');
  const legacyMarkerPattern = new RegExp(`<!-- BEGIN ${legacyMarker} MANAGED BLOCK -->`, 'g');
  return {
    exists: true,
    blocks: (text.match(anyMarkerPattern) || []).length,
    dotKnowledge: (text.match(/<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->/g) || []).length,
    knowledgeKit: (text.match(legacyMarkerPattern) || []).length
  };
}

function readVersionFromConfig(root) {
  const configPath = path.join(root, 'config.yaml');
  if (!fs.existsSync(configPath)) return null;
  const match = fs.readFileSync(configPath, 'utf8').match(/^version:\s*['"]?([^'"\r\n]+)['"]?/m);
  return match ? match[1].trim() : null;
}

function readPackageVersion(root) {
  const packagePath = path.join(root, 'package.json');
  const pkg = fs.existsSync(packagePath) ? readJson(packagePath, {}) : {};
  return String(pkg.version || readVersionFromConfig(root) || 'unknown');
}

function detectTargetCapabilities(root = activeKnowledgeRoot) {
  return {
    version: readPackageVersion(root),
    has_update_system_files: fs.existsSync(path.join(root, 'tools', 'update-system-files.js')),
    has_install_manifest: fs.existsSync(path.join(root, 'install-manifest.json')),
    has_external_memory_registry: fs.existsSync(path.join(root, 'external_memory', 'registry.json')),
    has_external_memory_retrieval_policy: fs.existsSync(path.join(root, 'external_memory', 'retrieval_policy.json')),
    has_memory_providers: fs.existsSync(path.join(root, 'memory-providers')),
    agent_integration_markers: markerCounts(path.join(path.dirname(root), 'AGENTS.md'))
  };
}

function permissionError(error, check, targetPath) {
  return {
    check,
    status: 'fail',
    path: targetPath,
    code: error.code || 'ERROR',
    message: error.message,
    remediation: `Run the update from a process that can write ${targetPath}, or fix filesystem permissions before retrying.`
  };
}

function cleanupPath(targetPath) {
  try { fs.rmSync(targetPath, { recursive: true, force: true }); } catch {}
}

function probeAtomicWrite(dirPath, check) {
  if (!fs.existsSync(dirPath)) {
    return { check, status: 'warn', path: dirPath, message: 'directory_missing; parent write check must cover creation during apply' };
  }
  const base = path.join(dirPath, `.update-preflight-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  const tmpPath = `${base}.tmp`;
  const finalPath = `${base}.json`;
  try {
    fs.writeFileSync(tmpPath, '{}\n', 'utf8');
    fs.renameSync(tmpPath, finalPath);
    fs.rmSync(finalPath, { force: true });
    return { check, status: 'pass', path: dirPath };
  } catch (error) {
    cleanupPath(tmpPath);
    cleanupPath(finalPath);
    return permissionError(error, check, dirPath);
  }
}

function probeDirectoryCreate(parentPath, check) {
  if (!fs.existsSync(parentPath)) {
    return { check, status: 'warn', path: parentPath, message: 'parent_missing; root write check must cover creation during apply' };
  }
  const target = path.join(parentPath, `.update-preflight-dir-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  try {
    fs.mkdirSync(target);
    fs.rmSync(target, { recursive: true, force: true });
    return { check, status: 'pass', path: parentPath };
  } catch (error) {
    cleanupPath(target);
    return permissionError(error, check, parentPath);
  }
}

function permissionPreflight(sourceRoot, manifest) {
  const checks = [];
  const reportDir = path.join(activeKnowledgeRoot, 'maintenance');
  const backupParent = path.join(reportDir, 'install-backups');
  checks.push(fs.existsSync(activeKnowledgeRoot)
    ? { check: 'knowledge_root_exists', status: 'pass', path: activeKnowledgeRoot }
    : { check: 'knowledge_root_exists', status: 'fail', path: activeKnowledgeRoot, message: 'target .knowledge root does not exist' });
  checks.push(probeAtomicWrite(activeKnowledgeRoot, 'knowledge_root_atomic_write'));
  checks.push(probeAtomicWrite(reportDir, 'maintenance_report_atomic_write'));
  checks.push(probeDirectoryCreate(reportDir, 'backup_directory_create'));
  checks.push(probeDirectoryCreate(activeKnowledgeRoot, 'lock_directory_create'));
  if (sourceRoot) {
    const missing = sourceMissingSystemPaths(sourceRoot, manifest);
    checks.push({
      check: 'source_system_completeness',
      status: missing.length ? 'fail' : 'pass',
      path: sourceRoot,
      missing_system_paths: missing
    });
  }
  const failed = checks.filter((check) => check.status === 'fail');
  return {
    status: failed.length ? 'failed' : 'ok',
    checked_at: new Date().toISOString(),
    checks,
    errors: failed.map((check) => `${check.check}: ${check.message || check.code || 'failed'}`),
    manual_action_required: failed.map((check) => check.remediation || `Fix ${check.path} before retrying.`),
    report_path: path.join(reportDir, 'update_system_files_report.json'),
    backup_parent: backupParent
  };
}

function collectPostUpgradeHealth(mode) {
  const quality = readJson(path.join(activeKnowledgeRoot, 'maintenance', 'quality_report.json'), {});
  const stale = readJson(path.join(activeKnowledgeRoot, 'maintenance', 'stale_items.json'), { items: [], stale_items: [] });
  const repair = readJson(path.join(activeKnowledgeRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
  const trust = readJson(path.join(activeKnowledgeRoot, 'maintenance', 'trust_report.json'), { modules: {}, module_statuses: [] });
  const staleItems = stale.items || stale.stale_items || [];
  const repairItems = repair.queue || [];
  const suspectModules = new Set([
    ...((trust.modules || {}).suspect || []),
    ...(trust.module_statuses || []).filter((item) => item.trust_status === 'suspect').map((item) => item.module_id)
  ].filter(Boolean));
  return {
    mode,
    quality_status: quality.status || 'unknown',
    quality_score: quality.quality_score ?? quality.score ?? null,
    stale_items_count: staleItems.length,
    repair_queue_count: repairItems.length,
    suspect_modules_count: suspectModules.size,
    generated_at: new Date().toISOString()
  };
}

function reportManualActions(errors, postUpgradeHealth) {
  const actions = [...errors];
  if (postUpgradeHealth?.stale_items_count > 0) actions.push(`Review ${postUpgradeHealth.stale_items_count} stale item(s) in .knowledge/maintenance/stale_items.json.`);
  if (postUpgradeHealth?.repair_queue_count > 0) actions.push(`Review ${postUpgradeHealth.repair_queue_count} repair queue item(s) in .knowledge/maintenance/repair_queue.json.`);
  if (postUpgradeHealth?.suspect_modules_count > 0) actions.push(`Re-check ${postUpgradeHealth.suspect_modules_count} suspect module(s) against current code/tests before trusting them.`);
  return Array.from(new Set(actions));
}

function verifyUpgrade(sourceRoot, manifest) {
  const checks = [];
  const errors = [];
  const manifestExists = fs.existsSync(path.join(activeKnowledgeRoot, 'install-manifest.json'));
  checks.push({ check: 'install_manifest', status: manifestExists ? 'pass' : 'fail', artifact: '.knowledge/install-manifest.json' });
  if (!manifestExists) errors.push('install-manifest.json is missing.');

  const completeness = sourceRoot ? verifySystemCompleteness(sourceRoot, manifest) : verifyInstalledSystemPaths(manifest);
  checks.push({ check: 'system_completeness', ...completeness });
  if (completeness.source_missing_system_paths.length) errors.push(`Source is missing system artifacts: ${completeness.source_missing_system_paths.join(', ')}`);
  if (completeness.missing_system_paths.length) errors.push(`Installed .knowledge is missing system artifacts: ${completeness.missing_system_paths.slice(0, 20).join(', ')}`);

  const agentsMarkers = markerCounts(path.join(activeRepoRoot, 'AGENTS.md'));
  checks.push({ check: 'agent_integration_markers', status: agentsMarkers.blocks <= 1 ? 'pass' : 'fail', agents_md: agentsMarkers });
  if (agentsMarkers.blocks > 1) errors.push('AGENTS.md contains more than one managed .knowledge block.');

  const missingRepairDefaults = (manifest.repair_default_paths || []).filter((relPath) => !fs.existsSync(path.join(activeKnowledgeRoot, relPath)));
  checks.push({ check: 'repair_defaults', status: missingRepairDefaults.length ? 'fail' : 'pass', missing_paths: missingRepairDefaults });
  if (missingRepairDefaults.length) errors.push(`Installed .knowledge is missing repair default artifacts: ${missingRepairDefaults.join(', ')}`);

  const previousReportPath = path.join(activeKnowledgeRoot, 'maintenance', 'update_system_files_report.json');
  if (fs.existsSync(previousReportPath)) {
    const previousReport = readJson(previousReportPath, {});
    const changed = previousReport.curated_preservation_proof?.changed_files_count || 0;
    checks.push({ check: 'curated_preservation_proof', status: changed === 0 ? 'pass' : 'fail', changed_files: changed });
    if (changed > 0) errors.push(`Curated preservation proof reports ${changed} changed file(s).`);
  } else {
    checks.push({ check: 'curated_preservation_proof', status: 'warn', note: 'No previous update report found.' });
  }

  const postChecks = [
    runNode('install-check.js', ['--json'], 'install_check'),
    runNode('doctor.js', [], 'doctor')
  ];
  for (const check of postChecks) {
    checks.push({ check: check.label, status: check.exit === 0 ? 'pass' : 'fail', command: check.command, exit: check.exit });
    if (check.exit !== 0) errors.push(`${check.command} failed with exit ${check.exit}.`);
  }
  return { checks, post_checks: postChecks, errors };
}

function runPostChecks(mode) {
  if (mode === 'none') {
    return [
      runNode('install-check.js', ['--json'], 'install_check'),
      runNode('doctor.js', [], 'doctor')
    ];
  }
  return [
    runNode('install-check.js', ['--json'], 'install_check'),
    runNode('flow.js', ['release', '--no-color'], 'runtime_regeneration'),
    runNode('doctor.js', [], 'doctor'),
    runNode('flow.js', ['release', '--no-color'], 'final_release')
  ];
}

function summarize(actions, postChecks, curatedProof, completeness, errors, migrationDefaults = []) {
  const runtimeRegenerated = postChecks
    .filter((check) => check.label === 'runtime_regeneration' || check.label === 'final_release')
    .map((check) => ({ command: check.command, exit: check.exit, status: check.exit === 0 ? 'ok' : 'failed' }));
  const migrationCreated = migrationDefaults.filter((a) => a.action === 'repair_default');
  return {
    create: actions.filter((a) => a.action === 'create').length,
    update: actions.filter((a) => a.action === 'update').length,
    skip: actions.filter((a) => a.action === 'skip').length,
    preserve: actions.filter((a) => a.action === 'preserve').length,
    system_created: actions.filter((a) => a.action === 'create').length,
    system_updated: actions.filter((a) => a.action === 'update').length,
    system_skipped: actions.filter((a) => a.action === 'skip').length,
    project_preserved: actions.filter((a) => a.action === 'preserve').length,
    migration_defaults_created: migrationCreated.length,
    migration_default_paths: migrationCreated.map((action) => action.path),
    runtime_regenerated: runtimeRegenerated,
    missing_system_paths: completeness ? completeness.missing_system_paths : [],
    source_missing_system_paths: completeness ? completeness.source_missing_system_paths : [],
    curated_changed_files: curatedProof ? curatedProof.changed_files_count : null,
    manual_action_required: errors.length ? errors : []
  };
}

function safeWriteUpdateReport(report) {
  const reportPath = path.join(activeKnowledgeRoot, 'maintenance', 'update_system_files_report.json');
  try {
    writeJsonAtomic(reportPath, { ...report, generated_at: new Date().toISOString() });
    return { status: 'ok', path: '.knowledge/maintenance/update_system_files_report.json' };
  } catch (error) {
    return {
      status: 'failed',
      path: reportPath,
      code: error.code || 'ERROR',
      message: error.message,
      remediation: `Fix write permissions for ${path.dirname(reportPath)} and rerun --verify-upgrade --json.`
    };
  }
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  configureTarget(args.targetKnowledgeRoot);
  const warnings = [];
  const errors = [];
  let sourceRoot = null;
  let manifest = loadInstallManifest(activeKnowledgeRoot);
  let actions = [];
  let migrationDefaults = [];
  let backupPath = null;
  let postChecks = [];
  let curatedProof = null;
  let systemCompleteness = null;
  let verify = null;
  let permission = null;
  let postUpgradeHealth = null;
  let reportWrite = null;

  try {
    if (!['repair_queue', 'report_only', 'none'].includes(args.postUpgradeTrustRefresh)) {
      errors.push(`Invalid --post-upgrade-trust-refresh value: ${args.postUpgradeTrustRefresh}. Use repair_queue, report_only, or none.`);
    }
    if (args.verifyUpgrade) {
      if (args.from) sourceRoot = resolveSourceRoot(args.from);
      manifest = sourceRoot ? loadInstallManifest(sourceRoot) : loadInstallManifest(activeKnowledgeRoot);
      verify = verifyUpgrade(sourceRoot, manifest);
      errors.push(...verify.errors);
    } else if (args.preflight) {
      if (args.from) sourceRoot = resolveSourceRoot(args.from);
      manifest = sourceRoot ? loadInstallManifest(sourceRoot) : loadInstallManifest(activeKnowledgeRoot);
      permission = permissionPreflight(sourceRoot, manifest);
      errors.push(...permission.errors);
    } else {
      sourceRoot = resolveSourceRoot(args.from);
      manifest = loadInstallManifest(sourceRoot);
      const sourceMissing = sourceMissingSystemPaths(sourceRoot, manifest);
      if (sourceMissing.length) errors.push(`Source is missing system artifacts: ${sourceMissing.join(', ')}`);
      actions = planActions(sourceRoot, { manifest });
      migrationDefaults = planRepairDefaults(sourceRoot, manifest, { repairDefaults: args.repairDefaults });
      const missingDefaultSources = migrationDefaults.filter((action) => action.kind === 'repair_default' && action.reason === 'source_missing');
      if (missingDefaultSources.length) errors.push(`Source is missing repair default artifacts: ${missingDefaultSources.map((action) => action.path).join(', ')}`);
      if (args.apply && !args.yes) errors.push('Refusing --apply without --yes.');
      if (args.apply && args.yes && errors.length === 0) {
        permission = permissionPreflight(sourceRoot, manifest);
        errors.push(...permission.errors);
      }
      if (args.apply && args.yes && errors.length === 0) {
        backupPath = copyKnowledgeBackup();
        applyActions(sourceRoot, actions, manifest);
        applyRepairDefaults(sourceRoot, migrationDefaults, manifest);
        curatedProof = curatedPreservationProof(backupPath, manifest);
        systemCompleteness = verifySystemCompleteness(sourceRoot, manifest);
        if (systemCompleteness.source_missing_system_paths.length) errors.push(`Source is missing system artifacts: ${systemCompleteness.source_missing_system_paths.join(', ')}`);
        if (systemCompleteness.missing_system_paths.length) errors.push(`Installed .knowledge is missing system artifacts: ${systemCompleteness.missing_system_paths.slice(0, 20).join(', ')}`);
        if (curatedProof && curatedProof.changed_files_count > 0) errors.push(`Curated preservation proof reports ${curatedProof.changed_files_count} changed file(s).`);
        if (errors.length === 0) {
          postChecks = runPostChecks(args.postUpgradeTrustRefresh);
          for (const check of postChecks) {
            if (check.exit !== 0) errors.push(`${check.command} failed with exit ${check.exit}.`);
          }
          postUpgradeHealth = collectPostUpgradeHealth(args.postUpgradeTrustRefresh);
        }
      }
    }
  } catch (error) {
    errors.push(error.message);
  }

  const report = {
    schema_version: '3.2.2',
    status: errors.length ? 'failed' : 'ok',
    phase: args.verifyUpgrade ? 'verify_upgrade' : (args.preflight ? 'preflight' : (args.apply ? 'apply' : 'dry_run')),
    mode: args.verifyUpgrade ? 'verify_upgrade' : (args.preflight ? 'preflight' : (args.apply ? 'apply' : 'dry_run')),
    installed_version: readPackageVersion(activeKnowledgeRoot),
    source_version: sourceRoot ? readPackageVersion(sourceRoot) : null,
    source_root: sourceRoot,
    knowledge_root: activeKnowledgeRoot,
    repo_root: activeRepoRoot,
    backup_path: backupPath,
    installed_capabilities: detectTargetCapabilities(activeKnowledgeRoot),
    manifest: {
      schema_version: manifest.schema_version,
      path: manifest.manifest_path,
      used_default: manifest.used_default,
      system_paths: manifest.system_paths.length,
      project_preserve_paths: manifest.project_preserve_paths.length,
      curated_preserve_paths: manifest.curated_preserve_paths.length,
      runtime_regenerate_paths: manifest.runtime_regenerate_paths.length,
      repair_default_paths: (manifest.repair_default_paths || []).length
    },
    options: {
      repair_defaults: args.repairDefaults,
      post_upgrade_trust_refresh: args.postUpgradeTrustRefresh
    },
    permission_preflight: permission,
    actions,
    migration_defaults: {
      status: migrationDefaults.some((action) => action.action === 'repair_default') ? 'planned_or_applied' : 'none_required',
      actions: migrationDefaults,
      created_paths: migrationDefaults.filter((action) => action.action === 'repair_default').map((action) => action.path)
    },
    summary: summarize(actions, postChecks, curatedProof, systemCompleteness, errors, migrationDefaults),
    system_completeness: systemCompleteness,
    curated_preservation_proof: curatedProof,
    post_upgrade_health: postUpgradeHealth,
    verify,
    warnings,
    errors,
    manual_action_required: reportManualActions(errors, postUpgradeHealth),
    post_checks: postChecks
  };

  if (args.apply && args.yes) {
    reportWrite = safeWriteUpdateReport(report);
    report.report_write = reportWrite;
    if (reportWrite.status === 'ok') report.report = reportWrite.path;
    else {
      report.status = 'failed';
      report.errors.push(`Failed to write update report: ${reportWrite.message}`);
      report.manual_action_required = reportManualActions(report.errors, postUpgradeHealth);
    }
  }

  console.log(JSON.stringify(report, null, 2));
  if (errors.length) process.exit(2);
}

if (require.main === module) main();

module.exports = {
  SYSTEM_PATHS,
  PROJECT_PATHS,
  DEFAULT_MANIFEST,
  loadInstallManifest,
  planActions,
  planRepairDefaults,
  permissionPreflight,
  resolveSourceRoot,
  verifySystemCompleteness
};
