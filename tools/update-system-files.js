#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const {
  ensureDir,
  readJson,
  writeJsonAtomic,
  normalizeSystemAlias
} = require('./lib/json-store');
const { inspectSemanticJson, parseJsonOutput } = require('./lib/semantic-json');
const { systemVersion } = require('./lib/system-version');

const defaultKnowledgeRoot = path.resolve(__dirname, '..');
const defaultRepoRoot = path.basename(defaultKnowledgeRoot).toLowerCase() === '.knowledge' ? path.dirname(defaultKnowledgeRoot) : process.cwd();
let activeKnowledgeRoot = defaultKnowledgeRoot;
let activeRepoRoot = defaultRepoRoot;

const DEFAULT_MANIFEST = {
  schema_version: systemVersion(),
  system_paths: [
    '.gitattributes',
    '.gitignore',
    '.release-notes',
    'INSTALL.md',
    'README.md',
    'Quick-Start.md',
    'Portal.md',
    'RELEASE_NOTES.md',
    'SECURITY.md',
    'SBOM.memory.json',
    'THIRD_PARTY_NOTICES.md',
    'LICENSE',
    'NOTICE',
    'package.json',
    'install-policy.json',
    'config.yaml',
    'inspector.js',
    'open-inspector.vbs',
    'assets',
    'agent-integrations',
    'commands',
    'docs',
    'flows',
    'external_memory',
    'maintenance/concurrency_policy.json',
    'maps/critical_paths.json',
    'github-action-templates',
    'memory-providers',
    'models',
    'schemas',
    'skills',
    'templates',
    'tools',
    'install-manifest.json'
  ],
  required_system_files: [
    'tools/repair-on-touch.js',
    'tools/lib/repair-on-touch.js',
    'tools/lib/dedicated-verification.js',
    'tools/self-test-repair-on-touch.js',
    'tools/self-test-dedicated-verification.js',
    'tools/self-test-repair-session-isolation.js',
    'tools/doctor.js',
    'tools/recertify.js',
    'tools/build-visual-inspector.js',
    'tools/serve-inspector.js',
    'tools/install-agent-integrations.js',
    'tools/lib/queue-lifecycle.js',
    'tools/lib/json-transaction.js',
    'tools/lib/contained-artifact.js',
    'tools/lib/workspace-baseline.js',
    'tools/lib/task-routing.js',
    'schemas/repair-opportunities.schema.json',
    'schemas/verification-execution.schema.json',
    'schemas/verification-receipt.schema.json',
    'schemas/dedicated-verification-receipt.schema.json',
    'docs/repair-on-touch.md',
    'agent-integrations/_shared/trust-routing.md',
    'agent-integrations/_shared/final-report-contract.md',
    'agent-integrations/_shared/metrics-reporting.md'
  ],
  approved_local_rebuild_tools: [
    'tools/build-routing-bundle.js',
    'tools/build-search-index.js',
    'tools/build-wiki-graph.js'
  ],
  immutable_runtime_evidence_paths: [
    'maintenance/verification_receipts',
    'maintenance/verification_executions',
    'maintenance/dedicated_verification_receipts'
  ],
  runtime_preserve_paths: [
    'maintenance/repair_opportunities.json',
    'maintenance/repair_on_touch_telemetry.json',
    'maintenance/repair_sessions',
    'maintenance/transactions',
    'maintenance/recertifications.json',
    'settings/operator-profile.json'
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
    'reports',
    'settings',
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
  curated_runtime_mutable_paths: [
    'modules/module_registry.json',
    'evidence/file_facts.json'
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
  system_remove_paths: [
    '.release-notes/v3.2.12.md',
    '.release-notes/v3.3.1.md'
  ],
  // 3.2.11's updater accepts removals only when they also name a source
  // system path. Source-only benchmark material cannot be shipped merely to
  // satisfy that legacy restriction, so modern updaters complete this one
  // migration after a verified 3.2.11 hand-off instead.
  legacy_compatible_remove_paths: [
    'benchmarks',
    'tools/run-benchmarks.js',
    'agent-integrations/codex/skills/release-preparation-workflow.md',
    'agent-integrations/devin/rules/knowledge.md'
  ],
  system_exclude_paths: [
    'benchmarks',
    'benchmarks/results',
    'benchmark-runs',
    'marketing-proof-packs',
    'tools/run-benchmarks.js',
    'agent-integrations/codex/skills/release-preparation-workflow.md',
    'dist',
    '.git',
    '.github',
    '.self-test-tmp',
    '.qa-tmp',
    'node_modules',
    'maintenance/install-backups',
    'maintenance/update-downloads',
    'maintenance/flow-logs',
    'maintenance/events',
    'maintenance/repair_opportunities.json',
    'maintenance/repair_on_touch_telemetry.json',
    'maintenance/verification_receipts',
    'maintenance/verification_executions',
    'maintenance/dedicated_verification_receipts',
    'maintenance/repair_sessions',
    'maintenance/transactions',
    'maintenance/dev-notes',
    'maintenance/github-release-update-log-*.md',
    'exports',
    'modules',
    'pro',
    'docs/canonical',
    'docs/product',
    'docs/strategy',
    'docs/release-gates.md',
    'docs/pro-subscription.md',
    'docs/pro-inspector.md',
    'memory-providers/graphiti',
    'memory-providers/zep',
    'tools/validate-paid-manifest.js',
    'tools/lib/paid-inspector-model.js',
    'tools/release-gate.js',
    'tools/check-public-consistency.js',
    'tools/package-release.js',
    'tools/validate-release-artifact.js',
    'tools/post-release-live-asset.js',
    'tools/conformance-install-smoke.js',
    'tools/classify-release-impact.js',
    'tools/generate-conformance-report.js',
    'tools/validate-sbom.js',
    'tools/validate-third-party-notices.js',
    'tools/validate-source-deliverable.js',
    'tools/self-test-release-gate-p0.js',
    'release-policy.json',
    'tools/verify-routing-rc4-r6-contract.js',
    'tools/verify-workspace-narrowing-rc4-r7.js',
    'tools/self-test-routing-rc4-r4.js',
    'tools/self-test-routing-rc4-r5.js',
    'tools/self-test-workspace-narrowing-rc4-r7.js',
    'tools/lib/release-policy.js',
    'tools/lib/release-step-evidence.js',
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
const LEGACY_OLD_UPDATER_COMPATIBLE_REMOVALS = new Set([
  'benchmarks',
  'tools/run-benchmarks.js',
  'agent-integrations/codex/skills/release-preparation-workflow.md',
  'agent-integrations/devin/rules/knowledge.md'
]);

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
    pruneVerifiedBackups: false,
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
    else if (arg === '--prune-verified-backups') args.pruneVerifiedBackups = true;
    else if (arg === '--no-repair-defaults') args.repairDefaults = false;
    else if (arg === '--repair-defaults') args.repairDefaults = true;
    else if (arg.startsWith('--repair-defaults=')) args.repairDefaults = !['false', '0', 'no', 'off'].includes(arg.slice('--repair-defaults='.length).toLowerCase());
    else if (arg === '--post-upgrade-trust-refresh') args.postUpgradeTrustRefresh = argv[++i];
    else if (arg.startsWith('--post-upgrade-trust-refresh=')) args.postUpgradeTrustRefresh = arg.slice('--post-upgrade-trust-refresh='.length);
  }
  if (!args.verifyUpgrade && !args.preflight && !args.pruneVerifiedBackups && !args.dryRun && !args.apply) args.dryRun = true;
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

function isRegularFile(filePath) {
  try {
    const stat = fs.lstatSync(filePath);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
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
  const merged = (field, aliases = []) => uniqueNormalized([
    ...(DEFAULT_MANIFEST[field] || []),
    ...[field, ...aliases].flatMap((name) =>
      Array.isArray(raw[name]) ? raw[name] : [])
  ]);
  return {
    schema_version: raw.schema_version || DEFAULT_MANIFEST.schema_version,
    system_paths: merged('system_paths'),
    required_system_files: merged('required_system_files'),
    approved_local_rebuild_tools:
      merged('approved_local_rebuild_tools'),
    immutable_runtime_evidence_paths:
      merged('immutable_runtime_evidence_paths'),
    runtime_preserve_paths: merged('runtime_preserve_paths'),
    project_preserve_paths: merged('project_preserve_paths'),
    curated_preserve_paths: merged('curated_preserve_paths'),
    curated_runtime_mutable_paths:
      merged('curated_runtime_mutable_paths'),
    runtime_regenerate_paths: merged('runtime_regenerate_paths'),
    repair_default_paths:
      merged('repair_default_paths', ['project_default_paths']),
    system_remove_paths: merged('system_remove_paths'),
    legacy_compatible_remove_paths: merged('legacy_compatible_remove_paths')
      .filter((relPath) => LEGACY_OLD_UPDATER_COMPATIBLE_REMOVALS.has(relPath)),
    system_exclude_paths: merged('system_exclude_paths'),
    forbidden_paths: merged('forbidden_paths'),
    manifest_path: fs.existsSync(manifestPath) ? manifestPath : null,
    used_default: !fs.existsSync(manifestPath)
  };
}

function obsoleteSystemPaths(manifest) {
  return uniqueNormalized([
    ...(manifest.system_remove_paths || []),
    ...(manifest.legacy_compatible_remove_paths || [])
  ]);
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
  const missing = manifest.system_paths
    .filter((relPath) =>
      !fs.existsSync(sourcePathFor(sourceRoot, relPath)));
  for (const relPath of manifest.required_system_files || []) {
    if (!isRegularFile(sourcePathFor(sourceRoot, relPath))) {
      missing.push(relPath);
    }
  }
  return Array.from(new Set(missing)).sort();
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

  for (const relPath of obsoleteSystemPaths(manifest)) {
    if (fs.existsSync(path.join(targetRoot, relPath))) {
      actions.push({ action: 'remove', path: relPath, reason: 'obsolete_system_path' });
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

function finalizeBackupVerification(backupRoot, state) {
  if (!backupRoot) return null;
  const curatedPreserved = state.curatedProof?.status === 'preserved';
  const runtimePreserved = state.runtimeProof?.status === 'preserved';
  const systemParity = state.systemCompleteness?.status === 'ok' &&
    Number(state.systemCompleteness?.checked_system_files || 0) > 0;
  const postChecksPassed = state.postChecks.length > 0 && state.postChecks.every((check) => check.success === true);
  const safeToRemove = state.errors.length === 0 && curatedPreserved && runtimePreserved && systemParity && postChecksPassed;
  const receipt = {
    schema_version: 'knowledge-update-backup-verification.v1',
    generated_at: new Date().toISOString(),
    status: safeToRemove ? 'verified' : 'retained_for_rollback',
    safe_to_remove: safeToRemove,
    checks: {
      curated_preservation: curatedPreserved ? 'pass' : 'fail',
      runtime_evidence_preservation: runtimePreserved ? 'pass' : 'fail',
      system_sha256_parity: systemParity ? 'pass' : 'fail',
      semantic_post_checks: postChecksPassed ? 'pass' : 'fail'
    },
    checked_system_files: Number(state.systemCompleteness?.checked_system_files || 0),
    mismatched_system_paths: state.systemCompleteness?.mismatched_system_paths || [],
    curated_changed_files: state.curatedProof?.changed_files || [],
    curated_added_files: state.curatedProof?.added_files || [],
    curated_runtime_mutable_changed_files: state.curatedProof?.runtime_mutable_changed_files || [],
    runtime_changed_files: state.runtimeProof?.changed_files || [],
    runtime_removed_files: state.runtimeProof?.removed_files || [],
    runtime_added_files: state.runtimeProof?.added_files || [],
    semantic_post_check_failures: state.postChecks
      .filter((check) => !check.success)
      .map((check) => ({ label: check.label, semantic_errors: check.semantic_errors || [] })),
    update_errors: [...state.errors],
    cleanup_command: 'node .knowledge/tools/update-system-files.js --prune-verified-backups --yes --json'
  };
  try {
    writeJsonAtomic(path.join(backupRoot, 'backup-verification.json'), receipt);
    receipt.receipt_path = path.join(backupRoot, 'backup-verification.json');
    return receipt;
  } catch (error) {
    return {
      ...receipt,
      status: 'verification_receipt_write_failed',
      safe_to_remove: false,
      error: error.message
    };
  }
}

function pruneVerifiedBackups(confirmed) {
  const backupParent = path.join(activeKnowledgeRoot, 'maintenance', 'install-backups');
  const candidates = fs.existsSync(backupParent)
    ? fs.readdirSync(backupParent, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && /^system-files-/.test(entry.name))
      .map((entry) => path.join(backupParent, entry.name))
      .sort()
    : [];
  if (!confirmed) {
    return {
      schema_version: 'knowledge-update-backup-prune.v1',
      status: 'failed',
      phase: 'prune_verified_backups',
      removed: [],
      retained: candidates.map((candidate) => ({ path: candidate, reason: 'confirmation_required' })),
      errors: ['Refusing to prune backups without --yes.']
    };
  }
  const removed = [];
  const retained = [];
  for (const candidate of candidates) {
    const receiptPath = path.join(candidate, 'backup-verification.json');
    const receipt = fs.existsSync(receiptPath) ? readJson(receiptPath, {}) : {};
    if (receipt.schema_version !== 'knowledge-update-backup-verification.v1' ||
        receipt.status !== 'verified' ||
        receipt.safe_to_remove !== true) {
      retained.push({ path: candidate, reason: receipt.status || 'verification_receipt_missing' });
      continue;
    }
    const requiredChecks = [
      'curated_preservation',
      'runtime_evidence_preservation',
      'system_sha256_parity',
      'semantic_post_checks'
    ];
    if (!requiredChecks.every((name) => receipt.checks?.[name] === 'pass')) {
      retained.push({ path: candidate, reason: 'legacy_runtime_proof_required' });
      continue;
    }
    fs.rmSync(candidate, { recursive: true, force: true });
    removed.push(candidate);
  }
  return {
    schema_version: 'knowledge-update-backup-prune.v1',
    status: 'ok',
    phase: 'prune_verified_backups',
    removed,
    retained,
    removed_count: removed.length,
    retained_count: retained.length,
    errors: []
  };
}

function contextEnv(extra = {}) {
  return {
    ...process.env,
    ...extra,
    KNOWLEDGE_SYSTEM_ROOT: activeKnowledgeRoot,
    KNOWLEDGE_TARGET_ROOT: activeRepoRoot,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: activeKnowledgeRoot,
    KNOWLEDGE_STATE_ROOT: activeKnowledgeRoot,
    KNOWLEDGE_FLOW_NO_OPEN: '1',
    KNOWLEDGE_INSPECTOR_NO_OPEN: '1'
  };
}

function runNode(script, args, label = null) {
  const res = spawnSync(process.execPath, [path.join(activeKnowledgeRoot, 'tools', script), ...args], {
    cwd: activeRepoRoot,
    env: contextEnv(),
    encoding: 'utf8',
    windowsHide: true
  });
  const rawStdout = String(res.stdout || '');
  let parsed = null;
  const semanticErrors = [];
  try {
    parsed = parseJsonOutput(rawStdout);
    semanticErrors.push(...inspectSemanticJson(parsed).errors);
  } catch (error) {
    semanticErrors.push(`invalid JSON stdout: ${error.message}`);
  }
  if (res.status !== 0) semanticErrors.push(`exit code ${res.status}`);
  const success = semanticErrors.length === 0;
  return {
    label: label || script.replace(/\.js$/, ''),
    command: `node .knowledge/tools/${script}${args.length ? ' ' + args.join(' ') : ''}`,
    exit: res.status,
    success,
    status: success ? 'pass' : 'fail',
    json_status: parsed?.status || null,
    semantic_errors: semanticErrors,
    stdout: rawStdout.trim().slice(0, 12000),
    stderr: String(res.stderr || '').trim().slice(0, 4000)
  };
}

function assertSystemWriteAllowed(actionPath, manifest) {
  const rel = normalizeRel(actionPath);
  const systemPath = manifest.system_paths.some((candidate) => rel === candidate || rel.startsWith(`${candidate}/`));
  const removablePath = obsoleteSystemPaths(manifest).some((candidate) => rel === candidate || rel.startsWith(`${candidate}/`));
  if (!systemPath && !removablePath) throw new Error(`Refusing to write non-system path: ${actionPath}`);
  if (!removablePath && isExcludedByManifest(rel, manifest)) throw new Error(`Refusing to write excluded system path: ${actionPath}`);
}

function assertRepairDefaultWriteAllowed(actionPath, manifest) {
  const rel = normalizeRel(actionPath);
  const allowed = (manifest.repair_default_paths || []).some((defaultPath) => rel === defaultPath);
  if (!allowed) throw new Error(`Refusing to write non-repair-default path: ${actionPath}`);
  if (isExcludedByManifest(rel, manifest)) throw new Error(`Refusing to write excluded repair default path: ${actionPath}`);
}

function applyActions(sourceRoot, actions, manifest) {
  for (const action of actions) {
    if (action.action === 'remove') {
      assertSystemWriteAllowed(action.path, manifest);
      fs.rmSync(path.join(activeKnowledgeRoot, action.path), { recursive: true, force: true });
      continue;
    }
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

function matchesManifestPath(relPath, patterns = []) {
  const rel = normalizeRel(relPath);
  return patterns.some((pattern) => rel === pattern || rel.startsWith(`${pattern}/`));
}

function curatedPreservationProof(backupRoot, manifest) {
  if (!backupRoot) return null;
  const paths = [];
  const changedFiles = [];
  const addedFiles = [];
  const runtimeMutableChanges = [];
  const mutable = manifest.curated_runtime_mutable_paths || [];
  for (const relPath of manifest.curated_preserve_paths) {
    const before = snapshotPath(backupRoot, relPath);
    const after = snapshotPath(activeKnowledgeRoot, relPath);
    const beforeKeys = Array.from(before.files.keys()).sort();
    const afterKeys = Array.from(after.files.keys()).sort();
    const changed = beforeKeys.filter((key) => (
      !matchesManifestPath(key, mutable) && before.files.get(key) !== after.files.get(key)
    ));
    const mutableChanged = beforeKeys.filter((key) => (
      matchesManifestPath(key, mutable) && before.files.get(key) !== after.files.get(key)
    ));
    const added = afterKeys.filter((key) => !before.files.has(key));
    if (before.exists && !after.exists && beforeKeys.length === 0 && !matchesManifestPath(relPath, mutable)) {
      changed.push(relPath);
    }
    changedFiles.push(...changed);
    addedFiles.push(...added);
    runtimeMutableChanges.push(...mutableChanged);
    paths.push({
      path: relPath,
      backup_exists: before.exists,
      current_exists: after.exists,
      compared_existing_files: beforeKeys.length,
      changed_existing_files: changed,
      added_files: added,
      runtime_mutable_changed_files: mutableChanged
    });
  }
  return {
    status: changedFiles.length ? 'changed' : 'preserved',
    paths,
    changed_files: changedFiles,
    changed_files_count: changedFiles.length,
    added_files: addedFiles,
    added_files_count: addedFiles.length,
    runtime_mutable_changed_files: runtimeMutableChanges,
    runtime_mutable_changed_files_count: runtimeMutableChanges.length
  };
}

function runtimePreservationProof(backupRoot, manifest) {
  if (!backupRoot) return null;
  const paths = uniqueNormalized([
    ...DEFAULT_MANIFEST.immutable_runtime_evidence_paths,
    ...DEFAULT_MANIFEST.runtime_preserve_paths,
    ...(manifest.immutable_runtime_evidence_paths || []),
    ...(manifest.runtime_preserve_paths || [])
  ]);
  const details = [];
  const changedFiles = [];
  const removedFiles = [];
  const addedFiles = [];
  for (const relPath of paths) {
    const before = snapshotPath(backupRoot, relPath);
    const after = snapshotPath(activeKnowledgeRoot, relPath);
    const beforeKeys = Array.from(before.files.keys()).sort();
    const afterKeys = Array.from(after.files.keys()).sort();
    const changed = beforeKeys.filter((key) => after.files.has(key) && before.files.get(key) !== after.files.get(key));
    const removed = beforeKeys.filter((key) => !after.files.has(key));
    const added = afterKeys.filter((key) => !before.files.has(key));
    if (before.exists && !after.exists && beforeKeys.length === 0) removed.push(relPath);
    changedFiles.push(...changed);
    removedFiles.push(...removed);
    addedFiles.push(...added);
    details.push({
      path: relPath,
      backup_exists: before.exists,
      current_exists: after.exists,
      before_files: beforeKeys.length,
      after_files: afterKeys.length,
      changed_files: changed,
      removed_files: removed,
      added_files: added
    });
  }
  const violations = [...changedFiles, ...removedFiles, ...addedFiles];
  return {
    status: violations.length ? 'changed' : 'preserved',
    proof_source: 'live_backup_comparison',
    backup_path: path.resolve(backupRoot),
    required_paths: [...paths].sort(),
    paths: details,
    changed_files: changedFiles,
    changed_files_count: changedFiles.length,
    removed_files: removedFiles,
    removed_files_count: removedFiles.length,
    added_files: addedFiles,
    added_files_count: addedFiles.length,
    hash_set_unchanged: violations.length === 0
  };
}

function legacyBackupPathBinding(rawPath) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    return { ok: false, reason: 'legacy_backup_path_missing', path: null };
  }
  // macOS reports the same temporary directory through both /var and
  // /private/var. Normalize only these documented system aliases before the
  // lexical boundary check; user-created links remain rejected below.
  const backupParent = normalizeSystemAlias(path.resolve(
    activeKnowledgeRoot,
    'maintenance',
    'install-backups'
  ));
  const candidate = normalizeSystemAlias(rawPath);
  const relative = path.relative(backupParent, candidate);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative) ||
      relative.includes(path.sep) || !/^system-files-/.test(relative)) {
    return { ok: false, reason: 'legacy_backup_path_outside_store', path: candidate };
  }
  return { ok: true, reason: null, path: candidate };
}

function safeLegacyBackupPath(rawPath) {
  const binding = legacyBackupPathBinding(rawPath);
  if (!binding.ok) return binding;
  const candidate = binding.path;
  const backupParent = path.resolve(
    activeKnowledgeRoot,
    'maintenance',
    'install-backups'
  );
  let candidateStat;
  try {
    candidateStat = fs.lstatSync(candidate);
  } catch {
    return { ok: false, reason: 'legacy_backup_missing', path: candidate };
  }
  if (!candidateStat.isDirectory() || candidateStat.isSymbolicLink()) {
    return { ok: false, reason: 'legacy_backup_not_real_directory', path: candidate };
  }
  try {
    const realParent = fs.realpathSync(backupParent);
    const realCandidate = fs.realpathSync(candidate);
    const realRelative = path.relative(realParent, realCandidate);
    if (!realRelative || realRelative.startsWith('..') ||
        path.isAbsolute(realRelative) || realRelative.includes(path.sep)) {
      return {
        ok: false,
        reason: 'legacy_backup_realpath_outside_store',
        path: candidate
      };
    }
    return { ok: true, reason: null, path: realCandidate };
  } catch {
    return { ok: false, reason: 'legacy_backup_realpath_unavailable', path: candidate };
  }
}

function requiredRuntimeProofPaths(manifest) {
  return uniqueNormalized([
    ...DEFAULT_MANIFEST.immutable_runtime_evidence_paths,
    ...DEFAULT_MANIFEST.runtime_preserve_paths,
    ...(manifest.immutable_runtime_evidence_paths || []),
    ...(manifest.runtime_preserve_paths || [])
  ]).sort();
}

function validatePreservedRuntimeProof(proof, manifest, expectedBackupPath) {
  const errors = [];
  const requiredPaths = requiredRuntimeProofPaths(manifest);
  if (!proof || typeof proof !== 'object') {
    return { ok: false, errors: ['runtime_proof_missing'], required_paths: requiredPaths };
  }
  if (proof.status !== 'preserved') errors.push('runtime_proof_status_not_preserved');
  if (proof.hash_set_unchanged !== true) errors.push('runtime_proof_hash_set_not_unchanged');
  for (const field of ['changed_files', 'removed_files', 'added_files']) {
    if (!Array.isArray(proof[field]) || proof[field].length !== 0) {
      errors.push(`runtime_proof_${field}_not_empty`);
    }
    if (Number(proof[`${field}_count`]) !== 0) {
      errors.push(`runtime_proof_${field}_count_not_zero`);
    }
  }
  const detailPaths = Array.isArray(proof.paths)
    ? proof.paths.map((item) => normalizeRel(item?.path)).filter(Boolean).sort()
    : [];
  const declaredPaths = Array.isArray(proof.required_paths)
    ? uniqueNormalized(proof.required_paths).sort()
    : detailPaths;
  if (JSON.stringify(declaredPaths) !== JSON.stringify(requiredPaths)) {
    errors.push('runtime_proof_declared_path_coverage_mismatch');
  }
  if (detailPaths.length !== new Set(detailPaths).size ||
      JSON.stringify(detailPaths) !== JSON.stringify(requiredPaths)) {
    errors.push('runtime_proof_required_path_coverage_mismatch');
  }
  for (const detail of Array.isArray(proof.paths) ? proof.paths : []) {
    for (const field of ['changed_files', 'removed_files', 'added_files']) {
      if (!Array.isArray(detail?.[field]) || detail[field].length !== 0) {
        errors.push(`runtime_proof_detail_${field}_not_empty`);
      }
    }
  }
  const proofBinding = legacyBackupPathBinding(proof.backup_path);
  const expectedBinding = legacyBackupPathBinding(expectedBackupPath);
  if (!proofBinding.ok || !expectedBinding.ok ||
      path.resolve(proofBinding.path || '') !== path.resolve(expectedBinding.path || '')) {
    errors.push('runtime_proof_backup_binding_mismatch');
  }
  return {
    ok: errors.length === 0,
    errors: Array.from(new Set(errors)),
    required_paths: requiredPaths
  };
}

function eligibleApplyReport(previousReport, expectedVersion) {
  return previousReport?.status === 'ok' &&
    (previousReport?.phase === 'apply' || previousReport?.mode === 'apply') &&
    previousReport?.installed_version === expectedVersion &&
    previousReport?.source_version === expectedVersion;
}

function reconstructLegacyRuntimeProof(previousReport, manifest, expectedVersion) {
  const eligible = previousReport?.schema_version === '3.2.11' &&
    eligibleApplyReport(previousReport, expectedVersion) &&
    previousReport?.curated_preservation_proof?.status === 'preserved' &&
    Number(previousReport?.curated_preservation_proof?.changed_files_count) === 0;
  if (!eligible) {
    return {
      status: 'not_eligible',
      reason: 'missing_runtime_proof_is_not_an_eligible_3_2_11_apply'
    };
  }
  const backup = safeLegacyBackupPath(previousReport.backup_path);
  if (!backup.ok) {
    return {
      status: 'failed',
      reason: backup.reason,
      backup_path: backup.path
    };
  }
  const proof = runtimePreservationProof(backup.path, manifest);
  const reconstructed = {
    ...proof,
    proof_source: 'reconstructed_legacy_backup',
    reconstructed_at: new Date().toISOString(),
    legacy_report_schema_version: previousReport.schema_version,
    legacy_report_phase: previousReport.phase || previousReport.mode,
    backup_path: backup.path
  };
  return {
    status: proof?.status === 'preserved' ? 'reconstructed' : 'failed',
    reason: proof?.status === 'preserved'
      ? null
      : 'legacy_backup_runtime_evidence_changed',
    backup_path: backup.path,
    proof: reconstructed
  };
}

function revalidatePreviousRuntimeProof(previousReport, manifest, expectedVersion) {
  if (!eligibleApplyReport(previousReport, expectedVersion)) {
    return {
      status: 'failed',
      reason: 'previous_report_is_not_matching_successful_apply',
      errors: ['previous_report_is_not_matching_successful_apply']
    };
  }
  const binding = legacyBackupPathBinding(previousReport.backup_path);
  if (!binding.ok) {
    return { status: 'failed', reason: binding.reason, errors: [binding.reason] };
  }
  const shape = validatePreservedRuntimeProof(
    previousReport.runtime_preservation_proof,
    manifest,
    binding.path
  );
  if (!shape.ok) {
    return {
      status: 'failed',
      reason: 'previous_runtime_proof_invalid',
      errors: shape.errors
    };
  }
  const backup = safeLegacyBackupPath(binding.path);
  if (!backup.ok) {
    return { status: 'failed', reason: backup.reason, errors: [backup.reason] };
  }
  const recomputed = runtimePreservationProof(backup.path, manifest);
  const recomputedShape = validatePreservedRuntimeProof(recomputed, manifest, backup.path);
  if (!recomputedShape.ok) {
    return {
      status: 'failed',
      reason: 'live_backup_runtime_evidence_changed',
      errors: recomputedShape.errors,
      backup_path: backup.path,
      proof: recomputed
    };
  }
  return {
    status: 'revalidated',
    reason: null,
    backup_path: backup.path,
    proof: {
      ...recomputed,
      proof_source: 'previous_update_report_revalidated'
    }
  };
}

function persistReconstructedLegacyProof(context, proof) {
  const reportPath = context?.report_path;
  if (!reportPath || !context?.report_sha256 || !context?.previous_report) {
    return {
      status: 'failed',
      message: 'Legacy proof persistence context is incomplete.'
    };
  }
  try {
    if (!fs.existsSync(reportPath) || sha256(reportPath) !== context.report_sha256) {
      throw new Error('The prior apply report changed before legacy proof persistence.');
    }
    const current = readJson(reportPath);
    const enriched = {
      ...current,
      runtime_preservation_proof: proof,
      runtime_proof_provenance: {
        schema_version: 'knowledge-runtime-proof-provenance.v1',
        source: 'reconstructed_legacy_backup',
        reconstructed_at: new Date().toISOString(),
        apply_report_sha256_before_enrichment: context.report_sha256,
        backup_path: proof.backup_path
      }
    };
    writeJsonAtomic(reportPath, enriched);
    const persisted = readJson(reportPath);
    const validation = validatePreservedRuntimeProof(
      persisted.runtime_preservation_proof,
      context.manifest,
      persisted.backup_path
    );
    if (!validation.ok ||
        persisted.phase !== current.phase ||
        persisted.mode !== current.mode ||
        JSON.stringify(persisted.actions || []) !== JSON.stringify(current.actions || [])) {
      throw new Error('Persisted legacy proof failed read-back validation or changed apply provenance.');
    }
    return {
      status: 'ok',
      path: reportPath,
      report_sha256_before: context.report_sha256,
      report_sha256_after: sha256(reportPath),
      preserved_phase: persisted.phase,
      preserved_actions_count: Array.isArray(persisted.actions) ? persisted.actions.length : 0
    };
  } catch (error) {
    return {
      status: 'failed',
      path: reportPath,
      code: error.code || 'ERROR',
      message: error.message
    };
  }
}

function verifySystemCompleteness(sourceRoot, manifest) {
  const missingSystemPaths = new Set();
  const sourceMissing = [];
  const hashMismatches = [];
  const comparedPaths = new Set();
  let checkedFiles = 0;

  function compareFile(src, dst, relPath) {
    if (!isRegularFile(src)) {
      sourceMissing.push(relPath);
      return;
    }
    if (!isRegularFile(dst)) {
      missingSystemPaths.add(relPath);
      return;
    }
    if (comparedPaths.has(relPath)) return;
    comparedPaths.add(relPath);
    checkedFiles += 1;
    const expected = sha256(src);
    const actual = sha256(dst);
    if (expected !== actual) hashMismatches.push({ path: relPath, expected_sha256: expected, actual_sha256: actual });
  }

  for (const relPath of manifest.system_paths) {
    const src = sourcePathFor(sourceRoot, relPath);
    if (!fs.existsSync(src)) {
      sourceMissing.push(relPath);
      continue;
    }
    const dst = path.join(activeKnowledgeRoot, relPath);
    if (!fs.existsSync(dst)) missingSystemPaths.add(relPath);
    if (isDirectory(src)) {
      for (const file of walkFiles(src)) {
        const relFile = normalizeRel(path.posix.join(relPath, file.rel));
        if (isExcludedByManifest(relFile, manifest)) continue;
        compareFile(file.abs, path.join(activeKnowledgeRoot, relFile), relFile);
      }
    } else if (isFile(src)) {
      compareFile(src, dst, relPath);
    }
  }
  for (const relPath of manifest.required_system_files || []) {
    compareFile(
      sourcePathFor(sourceRoot, relPath),
      path.join(activeKnowledgeRoot, relPath),
      relPath
    );
  }
  const obsoletePathsPresent = obsoleteSystemPaths(manifest)
    .filter((relPath) => fs.existsSync(path.join(activeKnowledgeRoot, relPath)));
  const missing = Array.from(missingSystemPaths).sort();
  const uniqueSourceMissing = Array.from(new Set(sourceMissing)).sort();
  const failed = uniqueSourceMissing.length || missing.length ||
    hashMismatches.length || obsoletePathsPresent.length;
  return {
    status: failed ? 'failed' : 'ok',
    source_missing_system_paths: uniqueSourceMissing,
    missing_system_paths: missing,
    mismatched_system_paths: hashMismatches.map((item) => item.path),
    system_hash_mismatches: hashMismatches,
    obsolete_system_paths_present: obsoletePathsPresent,
    checked_system_files: checkedFiles
  };
}

function verifyInstalledSystemPaths(manifest) {
  const missingSystemPaths = Array.from(new Set([
    ...manifest.system_paths.filter((relPath) =>
      !fs.existsSync(path.join(activeKnowledgeRoot, relPath))),
    ...(manifest.required_system_files || []).filter((relPath) =>
      !isRegularFile(path.join(activeKnowledgeRoot, relPath)))
  ])).sort();
  const obsoletePathsPresent = obsoleteSystemPaths(manifest)
    .filter((relPath) => fs.existsSync(path.join(activeKnowledgeRoot, relPath)));
  return {
    status: missingSystemPaths.length || obsoletePathsPresent.length ? 'failed' : 'ok',
    source_missing_system_paths: [],
    missing_system_paths: missingSystemPaths,
    mismatched_system_paths: [],
    system_hash_mismatches: [],
    obsolete_system_paths_present: obsoletePathsPresent,
    checked_system_files: 0
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
  if (completeness.mismatched_system_paths.length) errors.push(`Installed system artifacts do not match source SHA-256: ${completeness.mismatched_system_paths.slice(0, 20).join(', ')}`);
  if (completeness.obsolete_system_paths_present.length) errors.push(`Obsolete system artifacts are still installed: ${completeness.obsolete_system_paths_present.join(', ')}`);

  const agentsMarkers = markerCounts(path.join(activeRepoRoot, 'AGENTS.md'));
  checks.push({ check: 'agent_integration_markers', status: agentsMarkers.blocks <= 1 ? 'pass' : 'fail', agents_md: agentsMarkers });
  if (agentsMarkers.blocks > 1) errors.push('AGENTS.md contains more than one managed .knowledge block.');

  const missingRepairDefaults = (manifest.repair_default_paths || []).filter((relPath) => !fs.existsSync(path.join(activeKnowledgeRoot, relPath)));
  checks.push({ check: 'repair_defaults', status: missingRepairDefaults.length ? 'fail' : 'pass', missing_paths: missingRepairDefaults });
  if (missingRepairDefaults.length) errors.push(`Installed .knowledge is missing repair default artifacts: ${missingRepairDefaults.join(', ')}`);

  const previousReportPath = path.join(activeKnowledgeRoot, 'maintenance', 'update_system_files_report.json');
  let runtimeProof = null;
  let runtimeProofSource = null;
  let legacyRecovery = null;
  let previousReport = null;
  let runtimeProofValidation = null;
  let legacyPersistenceContext = null;
  const expectedVersion = sourceRoot
    ? readPackageVersion(sourceRoot)
    : readPackageVersion(activeKnowledgeRoot);
  if (fs.existsSync(previousReportPath)) {
    const previousReportSha256 = sha256(previousReportPath);
    previousReport = readJson(previousReportPath, {});
    const curated = previousReport.curated_preservation_proof;
    const changed = Number(curated?.changed_files_count);
    const curatedPreserved = curated?.status === 'preserved' &&
      changed === 0 &&
      Array.isArray(curated?.changed_files) &&
      curated.changed_files.length === 0;
    checks.push({
      check: 'curated_preservation_proof',
      status: curatedPreserved ? 'pass' : 'fail',
      changed_files: Number.isFinite(changed) ? changed : null
    });
    if (!curatedPreserved) errors.push('Curated preservation proof is missing or invalid.');
    if (previousReport.runtime_preservation_proof) {
      runtimeProofValidation = revalidatePreviousRuntimeProof(
        previousReport,
        manifest,
        expectedVersion
      );
      if (runtimeProofValidation.status === 'revalidated') {
        runtimeProof = runtimeProofValidation.proof;
        runtimeProofSource = 'previous_update_report_revalidated';
      }
    } else {
      legacyRecovery = reconstructLegacyRuntimeProof(
        previousReport,
        manifest,
        expectedVersion
      );
      if (legacyRecovery.status === 'reconstructed') {
        runtimeProof = legacyRecovery.proof;
        runtimeProofSource = 'reconstructed_legacy_backup';
        legacyPersistenceContext = {
          report_path: previousReportPath,
          report_sha256: previousReportSha256,
          previous_report: previousReport,
          manifest
        };
      }
    }
    const runtimePreserved = runtimeProof?.status === 'preserved' &&
      (runtimeProofValidation?.status === 'revalidated' ||
        legacyRecovery?.status === 'reconstructed');
    checks.push({
      check: 'runtime_evidence_preservation_proof',
      status: runtimePreserved ? 'pass' : 'fail',
      proof_source: runtimeProofSource,
      recovery_status: legacyRecovery?.status || null,
      recovery_reason: legacyRecovery?.reason || null,
      validation_status: runtimeProofValidation?.status || null,
      validation_reason: runtimeProofValidation?.reason || null,
      validation_errors: runtimeProofValidation?.errors || [],
      changed_files: runtimeProof?.changed_files_count ?? null,
      removed_files: runtimeProof?.removed_files_count ?? null,
      added_files: runtimeProof?.added_files_count ?? null
    });
    if (!runtimePreserved) errors.push('Runtime evidence preservation proof is missing or not preserved.');
  } else {
    checks.push({ check: 'curated_preservation_proof', status: 'warn', note: 'No previous update report found.' });
    checks.push({ check: 'runtime_evidence_preservation_proof', status: 'warn', note: 'No previous update report found.' });
  }

  const postChecks = [
    runNode('install-check.js', ['--json'], 'install_check'),
    runNode('doctor.js', [], 'doctor')
  ];
  for (const check of postChecks) {
    checks.push({
      check: check.label,
      status: check.success ? 'pass' : 'fail',
      command: check.command,
      exit: check.exit,
      json_status: check.json_status,
      semantic_errors: check.semantic_errors
    });
    if (!check.success) errors.push(`${check.command} failed semantic verification: ${check.semantic_errors.join('; ')}.`);
  }
  const previousBackup = safeLegacyBackupPath(previousReport?.backup_path);
  const verifiedBackupPath = legacyRecovery?.status === 'reconstructed'
    ? legacyRecovery.backup_path
    : (runtimeProofValidation?.status === 'revalidated' && previousBackup.ok
      ? previousBackup.path
      : null);
  return {
    checks,
    post_checks: postChecks,
    errors,
    system_completeness: completeness,
    curated_preservation_proof: previousReport?.curated_preservation_proof || null,
    runtime_preservation_proof: runtimeProof,
    runtime_proof_source: runtimeProofSource,
    runtime_proof_validation: runtimeProofValidation,
    legacy_recovery: legacyRecovery,
    backup_path: verifiedBackupPath,
    legacy_persistence_context: legacyPersistenceContext
  };
}

function runtimeBootstrapRequired() {
  if (!fs.existsSync(path.join(activeKnowledgeRoot, 'project_index.json'))) return true;
  const registry = readJson(path.join(activeKnowledgeRoot, 'modules', 'module_registry.json'), { modules: [] });
  return !Array.isArray(registry.modules) || registry.modules.length === 0;
}

function runPostChecks(mode) {
  if (mode === 'none') {
    return {
      runtime_bootstrap_required: false,
      runtime_command: null,
      checks: [
        runNode('install-check.js', ['--json'], 'install_check'),
        runNode('doctor.js', [], 'doctor')
      ]
    };
  }
  const bootstrap = runtimeBootstrapRequired();
  const runtimeFlow = bootstrap ? 'import' : 'release';
  return {
    runtime_bootstrap_required: bootstrap,
    runtime_command: `node .knowledge/tools/flow.js ${runtimeFlow} --json --no-color`,
    checks: [
      runNode('install-check.js', ['--json'], 'install_check'),
      runNode('flow.js', [runtimeFlow, '--json', '--no-color'], 'runtime_regeneration'),
      runNode('doctor.js', [], 'doctor'),
      runNode('flow.js', ['release', '--json', '--no-color'], 'final_release')
    ]
  };
}

function summarize(actions, postChecks, curatedProof, runtimeProof, completeness, errors, migrationDefaults = []) {
  const runtimeRegenerated = postChecks
    .filter((check) => check.label === 'runtime_regeneration' || check.label === 'final_release')
    .map((check) => ({
      command: check.command,
      exit: check.exit,
      status: check.success ? 'ok' : 'failed',
      json_status: check.json_status,
      semantic_errors: check.semantic_errors
    }));
  const migrationCreated = migrationDefaults.filter((a) => a.action === 'repair_default');
  return {
    create: actions.filter((a) => a.action === 'create').length,
    update: actions.filter((a) => a.action === 'update').length,
    remove: actions.filter((a) => a.action === 'remove').length,
    skip: actions.filter((a) => a.action === 'skip').length,
    preserve: actions.filter((a) => a.action === 'preserve').length,
    system_created: actions.filter((a) => a.action === 'create').length,
    system_updated: actions.filter((a) => a.action === 'update').length,
    system_removed: actions.filter((a) => a.action === 'remove').length,
    system_skipped: actions.filter((a) => a.action === 'skip').length,
    project_preserved: actions.filter((a) => a.action === 'preserve').length,
    migration_defaults_created: migrationCreated.length,
    migration_default_paths: migrationCreated.map((action) => action.path),
    runtime_regenerated: runtimeRegenerated,
    missing_system_paths: completeness ? completeness.missing_system_paths : [],
    source_missing_system_paths: completeness ? completeness.source_missing_system_paths : [],
    mismatched_system_paths: completeness ? completeness.mismatched_system_paths : [],
    obsolete_system_paths_present: completeness ? completeness.obsolete_system_paths_present : [],
    checked_system_files: completeness ? completeness.checked_system_files : 0,
    curated_changed_files: curatedProof ? curatedProof.changed_files_count : null,
    runtime_preservation_status: runtimeProof ? runtimeProof.status : null,
    runtime_changed_files: runtimeProof
      ? runtimeProof.changed_files_count + runtimeProof.removed_files_count + runtimeProof.added_files_count
      : null,
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

function cleanupDeprecatedManagedIntegrations(backupPath) {
  const candidates = [
    {
      rel: path.join('.agents', 'skills', 'release-preparation-workflow.md'),
      signatures: ['# Codex Skill: Release Preparation Workflow', 'tools/package-release.js']
    }
  ];
  const results = [];
  for (const candidate of candidates) {
    const filePath = path.join(activeRepoRoot, candidate.rel);
    if (!fs.existsSync(filePath)) {
      results.push({ path: normalizeRel(candidate.rel), status: 'absent' });
      continue;
    }
    let text = '';
    try { text = fs.readFileSync(filePath, 'utf8'); }
    catch (error) {
      results.push({ path: normalizeRel(candidate.rel), status: 'unreadable', error: error.message });
      continue;
    }
    if (!candidate.signatures.every((signature) => text.includes(signature))) {
      results.push({ path: normalizeRel(candidate.rel), status: 'preserved_unrecognized' });
      continue;
    }
    if (backupPath) {
      const backupFile = path.join(backupPath, 'external-managed-integrations', candidate.rel);
      ensureDir(path.dirname(backupFile));
      fs.copyFileSync(filePath, backupFile);
    }
    fs.rmSync(filePath, { force: true });
    results.push({ path: normalizeRel(candidate.rel), status: 'removed_deprecated_managed_file' });
  }
  return results;
}

function legacyBackupForCompatibilityRemoval(relPath) {
  const backupsRoot = path.join(activeKnowledgeRoot, 'maintenance', 'install-backups');
  if (!fs.existsSync(backupsRoot) || !isDirectory(backupsRoot)) return null;
  const candidates = fs.readdirSync(backupsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith('system-files-'))
    .map((entry) => path.join(backupsRoot, entry.name))
    .sort()
    .reverse();
  for (const backupRoot of candidates) {
    // A verify pass is normally read-only. The sole exception is completing
    // the known 3.2.11 hand-off, whose updater has already made this backup
    // and copied the new updater into the installed tree.
    if (readPackageVersion(backupRoot) !== '3.2.11') continue;
    if (fs.existsSync(path.join(backupRoot, relPath))) return backupRoot;
  }
  return null;
}

function completeLegacyUpdaterCompatibilityRemovals(manifest) {
  const results = [];
  for (const relPath of manifest.legacy_compatible_remove_paths || []) {
    const target = path.join(activeKnowledgeRoot, relPath);
    if (!fs.existsSync(target)) {
      results.push({ path: relPath, status: 'absent' });
      continue;
    }
    const backupRoot = legacyBackupForCompatibilityRemoval(relPath);
    if (!backupRoot) {
      results.push({
        path: relPath,
        status: 'retained_without_verified_3_2_11_backup'
      });
      continue;
    }
    try {
      fs.rmSync(target, { recursive: true, force: true });
      results.push({
        path: relPath,
        status: 'removed_after_verified_3_2_11_handoff',
        backup_path: path.relative(activeKnowledgeRoot, backupRoot).replace(/\\/g, '/')
      });
    } catch (error) {
      results.push({
        path: relPath,
        status: 'failed',
        code: error.code || 'ERROR',
        message: error.message
      });
    }
  }
  return results;
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  configureTarget(args.targetKnowledgeRoot);
  if (args.pruneVerifiedBackups) {
    const prune = pruneVerifiedBackups(args.yes);
    console.log(JSON.stringify(prune, null, 2));
    if (prune.status !== 'ok') process.exit(2);
    return prune;
  }
  const warnings = [];
  const errors = [];
  let sourceRoot = null;
  let manifest = loadInstallManifest(activeKnowledgeRoot);
  let actions = [];
  let migrationDefaults = [];
  let backupPath = null;
  let postChecks = [];
  let runtimeRegeneration = null;
  let curatedApplyProof = null;
  let runtimeApplyProof = null;
  let curatedProof = null;
  let runtimeProof = null;
  let systemCompleteness = null;
  let verify = null;
  let permission = null;
  let postUpgradeHealth = null;
  let backupVerification = null;
  let reportWrite = null;
  let legacyProofPersistence = null;
  let deprecatedIntegrationCleanup = [];
  let legacyCompatibilityCleanup = [];

  try {
    if (!['repair_queue', 'report_only', 'none'].includes(args.postUpgradeTrustRefresh)) {
      errors.push(`Invalid --post-upgrade-trust-refresh value: ${args.postUpgradeTrustRefresh}. Use repair_queue, report_only, or none.`);
    }
    if (args.verifyUpgrade) {
      if (args.from) sourceRoot = resolveSourceRoot(args.from);
      manifest = sourceRoot ? loadInstallManifest(sourceRoot) : loadInstallManifest(activeKnowledgeRoot);
      legacyCompatibilityCleanup = completeLegacyUpdaterCompatibilityRemovals(manifest);
      verify = verifyUpgrade(sourceRoot, manifest);
      const legacyPersistenceContext = verify.legacy_persistence_context;
      delete verify.legacy_persistence_context;
      systemCompleteness = verify.system_completeness;
      curatedProof = verify.curated_preservation_proof;
      runtimeProof = verify.runtime_preservation_proof;
      backupPath = verify.backup_path;
      postChecks = verify.post_checks;
      errors.push(...verify.errors);
      if (verify.legacy_recovery?.status === 'reconstructed') {
        legacyProofPersistence = persistReconstructedLegacyProof(
          legacyPersistenceContext,
          runtimeProof
        );
        if (legacyProofPersistence.status !== 'ok') {
          errors.push(
            `Failed to persist reconstructed legacy runtime proof: ${legacyProofPersistence.message}`
          );
          runtimeProof = null;
          verify.runtime_preservation_proof = null;
          verify.runtime_proof_source = null;
        }
      }
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
        deprecatedIntegrationCleanup = cleanupDeprecatedManagedIntegrations(backupPath);
        curatedApplyProof = curatedPreservationProof(backupPath, manifest);
        runtimeApplyProof = runtimePreservationProof(backupPath, manifest);
        systemCompleteness = verifySystemCompleteness(sourceRoot, manifest);
        if (systemCompleteness.source_missing_system_paths.length) errors.push(`Source is missing system artifacts: ${systemCompleteness.source_missing_system_paths.join(', ')}`);
        if (systemCompleteness.missing_system_paths.length) errors.push(`Installed .knowledge is missing system artifacts: ${systemCompleteness.missing_system_paths.slice(0, 20).join(', ')}`);
        if (systemCompleteness.mismatched_system_paths.length) errors.push(`Installed system artifacts do not match source SHA-256: ${systemCompleteness.mismatched_system_paths.slice(0, 20).join(', ')}`);
        if (systemCompleteness.obsolete_system_paths_present.length) errors.push(`Obsolete system artifacts are still installed: ${systemCompleteness.obsolete_system_paths_present.join(', ')}`);
        if (curatedApplyProof && curatedApplyProof.changed_files_count > 0) {
          errors.push(`System-file apply changed ${curatedApplyProof.changed_files_count} protected curated file(s).`);
        }
        if (runtimeApplyProof && runtimeApplyProof.status !== 'preserved') {
          errors.push('System-file apply changed protected runtime evidence or operator settings.');
        }
        if (errors.length === 0) {
          const postCheckRun = runPostChecks(args.postUpgradeTrustRefresh);
          postChecks = postCheckRun.checks;
          runtimeRegeneration = {
            bootstrap_required: postCheckRun.runtime_bootstrap_required,
            command: postCheckRun.runtime_command
          };
          for (const check of postChecks) {
            if (!check.success) errors.push(`${check.command} failed semantic verification: ${check.semantic_errors.join('; ')}.`);
          }
          postUpgradeHealth = collectPostUpgradeHealth(args.postUpgradeTrustRefresh);
        }
        curatedProof = curatedPreservationProof(backupPath, manifest);
        runtimeProof = runtimePreservationProof(backupPath, manifest);
        if (curatedProof && curatedProof.changed_files_count > 0) {
          errors.push(`Post-update verification found ${curatedProof.changed_files_count} changed protected curated file(s).`);
        }
        if (runtimeProof && runtimeProof.status !== 'preserved') {
          errors.push('Post-update verification found a changed protected runtime evidence hash-set.');
        }
      }
    }
  } catch (error) {
    errors.push(error.message);
  }

  if (backupPath) {
    backupVerification = finalizeBackupVerification(backupPath, {
      curatedProof,
      runtimeProof,
      systemCompleteness,
      postChecks,
      errors
    });
    if (backupVerification?.status === 'verification_receipt_write_failed') {
      errors.push(`Backup verification receipt could not be written: ${backupVerification.error}`);
    }
  }

  const report = {
    schema_version: systemVersion(),
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
      curated_runtime_mutable_paths: (manifest.curated_runtime_mutable_paths || []).length,
      required_system_files: (manifest.required_system_files || []).length,
      immutable_runtime_evidence_paths: (manifest.immutable_runtime_evidence_paths || []).length,
      runtime_preserve_paths: (manifest.runtime_preserve_paths || []).length,
      runtime_regenerate_paths: manifest.runtime_regenerate_paths.length,
      repair_default_paths: (manifest.repair_default_paths || []).length,
      system_remove_paths: (manifest.system_remove_paths || []).length,
      legacy_compatible_remove_paths: (manifest.legacy_compatible_remove_paths || []).length
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
    summary: summarize(actions, postChecks, curatedProof, runtimeProof, systemCompleteness, errors, migrationDefaults),
    system_completeness: systemCompleteness,
    curated_apply_preservation_proof: curatedApplyProof,
    runtime_apply_preservation_proof: runtimeApplyProof,
    curated_preservation_proof: curatedProof,
    runtime_preservation_proof: runtimeProof,
    runtime_regeneration: runtimeRegeneration,
    post_upgrade_health: postUpgradeHealth,
    backup_verification: backupVerification,
    legacy_proof_persistence: legacyProofPersistence,
    legacy_compatibility_cleanup: legacyCompatibilityCleanup,
    deprecated_integration_cleanup: deprecatedIntegrationCleanup,
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
  verifySystemCompleteness,
  curatedPreservationProof,
  runtimePreservationProof
};
