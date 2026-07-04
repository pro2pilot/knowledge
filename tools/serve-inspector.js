#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const zlib = require('zlib');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { readJson, ensureDir, writeJsonAtomic } = require('./lib/json-store');
const { listActions, loadEntitlements } = require('./lib/action-registry');
const { runAction, getRun } = require('./lib/action-runner');
const { detectGitContext } = require('./lib/git-context');
const visualInspector = require('./build-visual-inspector');
const checkUpdates = require('./check-updates');

const parsed = parseCliArgs(process.argv.slice(2));
const flags = parsed.flags;
const context = resolveKnowledgeContext(flags);
const host = flags.host || '127.0.0.1';
const port = Number(flags.port || process.env.KNOWLEDGE_INSPECTOR_PORT || 8765);
const token = crypto.randomBytes(24).toString('hex');

if (host !== '127.0.0.1') {
  throw new Error('Inspector must bind only to 127.0.0.1.');
}

function safeJson(rel, fallback) {
  const statePath = path.join(context.stateRoot, rel);
  const projectPath = path.join(context.projectKnowledgeRoot, rel);
  if (fs.existsSync(statePath)) return readJson(statePath, fallback);
  if (fs.existsSync(projectPath)) return readJson(projectPath, fallback);
  return fallback;
}

const DEFAULT_OPERATOR_PROFILE = {
  schema_version: '3.2.9',
  user_mode: 'simple',
  first_run_onboarding_completed: false,
  detected_agent_runtime: null,
  selected_agent_id: null,
  connected_agents: [],
  agent_overrides: {}
};

const DEFAULT_AUTONOMY_POLICY = {
  schema_version: '3.2.9',
  agents_can_do_without_asking: 'run checks and reports',
  network_actions_require_confirmation: true,
  destructive_actions_require_confirmation: true,
  controlled_autonomy: 'planned',
  agent_overrides: {}
};

const DEFAULT_AGENT_POLICY = {
  schema_version: '3.2.9',
  concurrent_work_policy: 'Safe Queue',
  merge_policy: 'Manual Only',
  auto_merge: false,
  safe_queue_default: true,
  agent_overrides: {}
};

const DEFAULT_REPORT_FOOTER = {
  schema_version: '3.2.9',
  mode: 'compact',
  show_token_metrics: true,
  show_restore_action: true,
  show_open_inspector_action: true,
  only_when_trust_incomplete: false,
  agent_overrides: {}
};

function loadSettings() {
  return {
    operator_profile: safeJson('settings/operator-profile.json', DEFAULT_OPERATOR_PROFILE),
    autonomy_policy: safeJson('settings/autonomy-policy.json', DEFAULT_AUTONOMY_POLICY),
    agent_policy: safeJson('settings/agent-policy.json', DEFAULT_AGENT_POLICY),
    report_footer: safeJson('settings/report-footer.json', DEFAULT_REPORT_FOOTER)
  };
}

function choose(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

function onboardingState(settings) {
  const profile = settings.operator_profile || {};
  const completed = profile.first_run_onboarding_completed === true;
  const hasCompletionMarker = Object.prototype.hasOwnProperty.call(profile, 'first_run_onboarding_completed');
  return {
    required: !completed,
    completed,
    reason: completed ? 'completed' : (hasCompletionMarker ? 'not_completed' : 'upgrade_missing_completion_marker'),
    completed_at: profile.onboarding_completed_at || null,
    steps: [
      'Connected agent dropdown',
      'User mode: Simple / Advanced',
      'What can agents do without asking?',
      'Concurrent work policy',
      'Merge policy',
      'Agent report footer'
    ]
  };
}

function cleanAgentId(value) {
  return String(value || '').trim().slice(0, 160);
}

function normalizeConnectedAgent(body = {}, fallbackRuntime = null) {
  const runtime = cleanAgentId(body.agent_runtime || body.detected_agent_runtime || fallbackRuntime || body.agent_id || 'local-agent');
  const id = cleanAgentId(body.agent_id || body.connected_agent_id || runtime || 'local-agent');
  return {
    id,
    label: String(body.agent_display_name || body.agent_label || id).trim().slice(0, 160) || id,
    runtime,
    status: 'configured',
    configured_at: new Date().toISOString()
  };
}

function mergeConnectedAgents(existing = [], agent) {
  const byId = new Map();
  for (const item of Array.isArray(existing) ? existing : []) {
    const normalized = normalizeConnectedAgent({ ...item, agent_id: item.id || item.agent_instance_id, agent_runtime: item.runtime || item.agent_runtime_id });
    if (normalized.id) byId.set(normalized.id, { ...item, ...normalized });
  }
  if (agent?.id) byId.set(agent.id, { ...(byId.get(agent.id) || {}), ...agent });
  return [...byId.values()].slice(-50);
}

function saveOnboarding(body = {}) {
  const settingsDir = path.join(context.projectKnowledgeRoot, 'settings');
  const current = loadSettings();
  const userMode = choose(String(body.user_mode || current.operator_profile.user_mode || 'simple').toLowerCase(), ['simple', 'advanced'], 'simple');
  const permission = choose(String(body.agents_can_do_without_asking || current.autonomy_policy.agents_can_do_without_asking || DEFAULT_AUTONOMY_POLICY.agents_can_do_without_asking), [
    'ask before every action',
    'run checks and reports',
    'run safe local actions'
  ], DEFAULT_AUTONOMY_POLICY.agents_can_do_without_asking);
  const concurrentPolicy = choose(String(body.concurrent_work_policy || current.agent_policy.concurrent_work_policy || 'Safe Queue'), [
    'Observe',
    'Guided',
    'Active Sessions',
    'Safe Queue',
    'Parallel Worktrees',
    'Controlled Autonomy'
  ], 'Safe Queue');
  const mergePolicy = choose(String(body.merge_policy || current.agent_policy.merge_policy || 'Manual Only'), [
    'Manual Only',
    'Assisted Merge',
    'Auto PR',
    'Auto Merge Experimental'
  ], 'Manual Only');
  const footerMode = choose(String(body.report_footer_mode || current.report_footer.mode || 'compact'), [
    'off',
    'compact',
    'full',
    'only_when_trust_incomplete'
  ], 'compact');
  const now = new Date().toISOString();
  const selectedAgent = normalizeConnectedAgent(body, current.operator_profile.detected_agent_runtime);
  const agentId = selectedAgent.id;
  const operator = {
    ...DEFAULT_OPERATOR_PROFILE,
    ...current.operator_profile,
    user_mode: userMode,
    first_run_onboarding_completed: true,
    detected_agent_runtime: selectedAgent.runtime || current.operator_profile.detected_agent_runtime || null,
    selected_agent_id: agentId,
    connected_agents: mergeConnectedAgents(current.operator_profile.connected_agents, selectedAgent),
    agent_overrides: {
      ...(current.operator_profile.agent_overrides || {}),
      [agentId]: {
        user_mode: userMode,
        updated_at: now
      }
    },
    onboarding_completed_at: now
  };
  const autonomy = {
    ...DEFAULT_AUTONOMY_POLICY,
    ...current.autonomy_policy,
    agents_can_do_without_asking: permission,
    network_actions_require_confirmation: true,
    destructive_actions_require_confirmation: true,
    agent_overrides: {
      ...(current.autonomy_policy.agent_overrides || {}),
      [agentId]: {
        agents_can_do_without_asking: permission,
        network_actions_require_confirmation: true,
        destructive_actions_require_confirmation: true,
        updated_at: now
      }
    }
  };
  const agent = {
    ...DEFAULT_AGENT_POLICY,
    ...current.agent_policy,
    concurrent_work_policy: concurrentPolicy,
    merge_policy: mergePolicy,
    auto_merge: mergePolicy === 'Auto Merge Experimental',
    safe_queue_default: concurrentPolicy === 'Safe Queue',
    agent_overrides: {
      ...(current.agent_policy.agent_overrides || {}),
      [agentId]: {
        concurrent_work_policy: concurrentPolicy,
        merge_policy: mergePolicy,
        auto_merge: mergePolicy === 'Auto Merge Experimental',
        safe_queue_default: concurrentPolicy === 'Safe Queue',
        updated_at: now
      }
    }
  };
  const footer = {
    ...DEFAULT_REPORT_FOOTER,
    ...current.report_footer,
    mode: footerMode,
    only_when_trust_incomplete: footerMode === 'only_when_trust_incomplete',
    agent_overrides: {
      ...(current.report_footer.agent_overrides || {}),
      [agentId]: {
        mode: footerMode,
        only_when_trust_incomplete: footerMode === 'only_when_trust_incomplete',
        updated_at: now
      }
    }
  };
  writeJsonAtomic(path.join(settingsDir, 'operator-profile.json'), operator);
  writeJsonAtomic(path.join(settingsDir, 'autonomy-policy.json'), autonomy);
  writeJsonAtomic(path.join(settingsDir, 'agent-policy.json'), agent);
  writeJsonAtomic(path.join(settingsDir, 'report-footer.json'), footer);
  return { selected_agent: selectedAgent, operator_profile: operator, autonomy_policy: autonomy, agent_policy: agent, report_footer: footer };
}

function currentContext() {
  const git = detectGitContext(context.targetRoot);
  return {
    ...context,
    branch: git.branch,
    headSha: git.head_sha,
    isGitWorktree: git.is_git_worktree,
    git,
    warnings: Array.from(new Set([
      ...(context.warnings || []),
      ...(git.warnings || []),
      ...(git.branches?.warnings || [])
    ]))
  };
}

function branchDiagnostics(branchName = null) {
  const git = detectGitContext(context.targetRoot);
  const branchState = git.branches || { active: git.branch || null, selected: git.branch || null, branches: [], warnings: [] };
  const selectedName = branchName || branchState.selected || branchState.active || git.branch || null;
  if (!git.is_git_repo) {
    return { ok: false, error: 'not_git_repository', diagnostics: null, git: branchState };
  }
  const branch = (branchState.branches || []).find((item) => item.name === selectedName) || null;
  if (!branch) {
    return { ok: false, error: 'branch_not_found', selected_branch: selectedName, git: branchState };
  }
  const current = branch.name === branchState.active || branch.current === true;
  return {
    ok: true,
    diagnostics: {
      branch: branch.name,
      active_branch: branchState.active || null,
      current,
      head_sha: branch.head_sha || null,
      upstream: branch.upstream || null,
      worktree_path: branch.worktree_path || null,
      active_worktree: branch.active_worktree === true,
      current_worktree_dirty: current ? git.dirty : null,
      dirty_summary: current ? (git.dirty_summary || { changed: 0, staged: 0, generated_runtime_staged: 0 }) : null,
      note: current
        ? 'Diagnostics are using the active worktree.'
        : (branch.worktree_path ? 'Branch is checked out in another worktree; run diagnostics there for file-level status.' : 'Branch is not checked out in this worktree; select or create a worktree before file-level diagnostics.')
    },
    git: branchState
  };
}

let launchUpdateCheck = null;
let launchUpdateStatus = null;
let server = null;
let shutdownScheduled = false;

function runUpdateCheckOnLaunch() {
  if (process.env.KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH === '1') return null;
  let config;
  try { config = checkUpdates.getConfig(); } catch (error) {
    launchUpdateStatus = { status: 'check_failed', reason: 'config_error', error: error.message };
    return null;
  }
  if (config.auto_check_on_inspector_open === false) {
    launchUpdateStatus = { ...checkUpdates.readStatus(), status: 'disabled', reason: 'auto_check_on_inspector_open_false' };
    return null;
  }
  launchUpdateCheck = checkUpdates.checkNow(config, 'inspector_launch')
    .then((status) => {
      launchUpdateStatus = status;
      return status;
    })
    .catch((error) => {
      launchUpdateStatus = { status: 'check_failed', reason: 'inspector_launch', error: error.message };
      return launchUpdateStatus;
    });
  return launchUpdateCheck;
}

async function updateStatus() {
  if (launchUpdateCheck) await launchUpdateCheck;
  return launchUpdateStatus || checkUpdates.readStatus();
}

function updateDryRunPlan(status, prepared = null) {
  const asset = prepared?.asset_path || status?.asset_url || '<release-zip>';
  return {
    status: prepared ? 'dry_run_ready' : 'manual_plan_required',
    message: prepared
      ? 'Release asset was downloaded, validated and dry-run against the current .knowledge root.'
      : 'Download or extract the release asset, review the dry-run, then apply only after user confirmation.',
    release_asset: asset,
    prepared_source_root: prepared?.source_root || null,
    validation: prepared?.validation || null,
    dry_run: prepared?.dry_run || null,
    commands: [
      'node .knowledge/tools/check-updates.js --json',
      'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --dry-run --json',
      'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --apply --yes --json',
      'node .knowledge/tools/update-system-files.js --verify-upgrade --json'
    ]
  };
}

function eocdOffset(buffer) {
  for (let i = buffer.length - 22; i >= 0; i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) return i;
  }
  throw new Error('ZIP end of central directory not found.');
}

function extractZip(zipPath, dest) {
  const buffer = fs.readFileSync(zipPath);
  const eocd = eocdOffset(buffer);
  const count = buffer.readUInt16LE(eocd + 10);
  let ptr = buffer.readUInt32LE(eocd + 16);
  const destRoot = path.resolve(dest);
  for (let i = 0; i < count; i += 1) {
    if (buffer.readUInt32LE(ptr) !== 0x02014b50) throw new Error(`Invalid central directory header at ${ptr}.`);
    const method = buffer.readUInt16LE(ptr + 10);
    const compressedSize = buffer.readUInt32LE(ptr + 20);
    const nameLength = buffer.readUInt16LE(ptr + 28);
    const extraLength = buffer.readUInt16LE(ptr + 30);
    const commentLength = buffer.readUInt16LE(ptr + 32);
    const localOffset = buffer.readUInt32LE(ptr + 42);
    const name = buffer.slice(ptr + 46, ptr + 46 + nameLength).toString('utf8');
    if (buffer.readUInt32LE(localOffset) !== 0x04034b50) throw new Error(`Invalid local header for ${name}.`);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.slice(dataStart, dataStart + compressedSize);
    const body = method === 0 ? compressed : zlib.inflateRawSync(compressed);
    const target = path.resolve(destRoot, name);
    if (target !== destRoot && !target.startsWith(destRoot + path.sep)) throw new Error(`Unsafe zip entry: ${name}`);
    if (name.endsWith('/')) {
      ensureDir(target);
    } else {
      ensureDir(path.dirname(target));
      fs.writeFileSync(target, body);
    }
    ptr += 46 + nameLength + extraLength + commentLength;
  }
}

function safeVersion(value) {
  return String(value || '').replace(/^v/i, '').replace(/[^0-9A-Za-z._-]/g, '');
}

function updateDownloadsRoot() {
  return path.join(context.projectKnowledgeRoot, 'maintenance', 'update-downloads');
}

function localPathFromAssetUrl(assetUrl) {
  const raw = String(assetUrl || '');
  if (!raw) return null;
  if (raw.startsWith('file://')) {
    try { return decodeURIComponent(new URL(raw).pathname.replace(/^\/([A-Za-z]:)/, '$1')); } catch { return null; }
  }
  if (/^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith('\\\\') || raw.startsWith('/')) return raw;
  return null;
}

async function downloadReleaseAsset(status) {
  const latest = safeVersion(status?.latest_version);
  if (!latest || status?.status !== 'update_available') {
    throw new Error('No newer release is available for update.');
  }
  if (!status.asset_url) throw new Error('Latest release has no exact knowledge-v<version>.zip asset.');
  const downloads = updateDownloadsRoot();
  ensureDir(downloads);
  const fileName = status.asset_name || `knowledge-v${latest}.zip`;
  const zipPath = path.join(downloads, fileName);
  const local = localPathFromAssetUrl(status.asset_url);
  if (local) {
    const source = path.resolve(local);
    if (!fs.existsSync(source)) throw new Error(`Local update asset does not exist: ${source}`);
    if (path.resolve(source) !== path.resolve(zipPath)) fs.copyFileSync(source, zipPath);
    return zipPath;
  }
  const response = await fetch(status.asset_url, {
    method: 'GET',
    headers: { 'Accept': 'application/zip, application/octet-stream', 'User-Agent': 'dot-knowledge-inspector-update' }
  });
  if (!response.ok) throw new Error(`Release asset download failed: ${response.status} ${response.statusText}`);
  const body = Buffer.from(await response.arrayBuffer());
  fs.writeFileSync(zipPath, body);
  return zipPath;
}

function findExtractedKnowledgeRoot(extractRoot) {
  const direct = path.join(extractRoot, 'tools', 'flow.js');
  const nested = path.join(extractRoot, '.knowledge', 'tools', 'flow.js');
  if (fs.existsSync(direct)) return extractRoot;
  if (fs.existsSync(nested)) return path.join(extractRoot, '.knowledge');
  const entries = fs.readdirSync(extractRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory());
  for (const entry of entries) {
    const candidate = path.join(extractRoot, entry.name, '.knowledge');
    if (fs.existsSync(path.join(candidate, 'tools', 'flow.js'))) return candidate;
  }
  throw new Error('Extracted release does not contain a .knowledge/tools/flow.js root.');
}

function runTool(script, args, label) {
  const scriptPath = path.join(context.projectKnowledgeRoot, 'tools', script);
  const fallbackPath = path.join(context.systemRoot, 'tools', script);
  const toolPath = fs.existsSync(scriptPath) ? scriptPath : fallbackPath;
  const res = spawnSync(process.execPath, [toolPath, ...args], {
    cwd: context.targetRoot,
    env: {
      ...process.env,
      KNOWLEDGE_SYSTEM_ROOT: context.systemRoot,
      KNOWLEDGE_TARGET_ROOT: context.targetRoot,
      KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: context.projectKnowledgeRoot,
      KNOWLEDGE_STATE_ROOT: context.stateRoot,
      KNOWLEDGE_FLOW_NO_OPEN: '1'
    },
    encoding: 'utf8',
    windowsHide: true,
    timeout: 300000
  });
  let json = null;
  try { json = JSON.parse((res.stdout || '').trim()); } catch {}
  return {
    label,
    command: `node .knowledge/tools/${script}${args.length ? ' ' + args.join(' ') : ''}`,
    exit: res.status,
    ok: res.status === 0,
    json,
    stdout: (res.stdout || '').trim().slice(0, 12000),
    stderr: (res.stderr || '').trim().slice(0, 4000)
  };
}

function validatePreparedRelease(sourceRoot, zipPath, expectedVersion) {
  const checks = [];
  const requireFile = (relPath) => {
    const ok = fs.existsSync(path.join(sourceRoot, relPath));
    checks.push({ check: relPath, status: ok ? 'pass' : 'fail' });
    return ok;
  };
  let pkg = {};
  try { pkg = readJson(path.join(sourceRoot, 'package.json'), {}); } catch {}
  const versionOk = safeVersion(pkg.version) === safeVersion(expectedVersion);
  checks.push({ check: 'package_version', status: versionOk ? 'pass' : 'fail', expected: expectedVersion, actual: pkg.version || null });
  const requiredOk = [
    'install-manifest.json',
    'tools/flow.js',
    'tools/update-system-files.js',
    'tools/install-check.js',
    'inspector.js',
    'docs/release-artifact.md'
  ].every(requireFile);
  const forbidden = [
    'release-policy.json',
    'tools/release-gate.js',
    'tools/package-release.js',
    'tools/validate-release-artifact.js',
    'tools/post-release-live-asset.js',
    'tools/conformance-install-smoke.js',
    'tools/classify-release-impact.js',
    'tools/generate-conformance-report.js',
    'tools/validate-sbom.js',
    'tools/validate-third-party-notices.js',
    'tools/validate-source-deliverable.js',
    'internal/release-gates.md',
    'docs/release-gates.md'
  ].filter((relPath) => fs.existsSync(path.join(sourceRoot, relPath)));
  checks.push({ check: 'maintainer_only_absent', status: forbidden.length ? 'fail' : 'pass', forbidden });
  const ok = Boolean(zipPath && fs.existsSync(zipPath)) && versionOk && requiredOk && forbidden.length === 0;
  return {
    label: 'public_runtime_embedded_validation',
    command: 'embedded public runtime update validation',
    exit: ok ? 0 : 2,
    ok,
    json: {
      schema_version: 'public-runtime-update-validation.v1',
      status: ok ? 'ok' : 'failed',
      artifact: zipPath,
      source_root: sourceRoot,
      checks,
      forbidden
    },
    stdout: '',
    stderr: ok ? '' : 'Extracted release failed public runtime update validation.'
  };
}

async function prepareUpdate(status, expectedVersion = null) {
  const latest = safeVersion(status?.latest_version);
  if (expectedVersion && safeVersion(expectedVersion) !== latest) {
    throw new Error(`Expected update version ${expectedVersion}, but latest is ${latest}.`);
  }
  const zipPath = await downloadReleaseAsset(status);
  const extractRoot = path.join(updateDownloadsRoot(), `extracted-${latest}-${Date.now()}`);
  ensureDir(extractRoot);
  extractZip(zipPath, extractRoot);
  const sourceRoot = findExtractedKnowledgeRoot(extractRoot);
  const pkg = readJson(path.join(sourceRoot, 'package.json'), {});
  if (safeVersion(pkg.version) !== latest) {
    throw new Error(`Release asset version mismatch: expected ${latest}, got ${pkg.version || 'unknown'}.`);
  }
  const fullValidator = path.join(context.projectKnowledgeRoot, 'tools', 'validate-release-artifact.js');
  const validation = fs.existsSync(fullValidator)
    ? runTool('validate-release-artifact.js', [zipPath, '--json'], 'validate_release_artifact')
    : validatePreparedRelease(sourceRoot, zipPath, latest);
  if (!validation.ok || validation.json?.status === 'failed') {
    throw new Error(`Release artifact validation failed: ${validation.stderr || validation.stdout || 'invalid artifact'}`);
  }
  const dryRun = runTool('update-system-files.js', [
    '--from', sourceRoot,
    '--target-knowledge-root', context.projectKnowledgeRoot,
    '--dry-run',
    '--json'
  ], 'update_dry_run');
  return {
    version: latest,
    asset_path: zipPath,
    extract_root: extractRoot,
    source_root: sourceRoot,
    validation,
    dry_run: dryRun
  };
}

async function applyPreparedUpdate(prepared) {
  const apply = runTool('update-system-files.js', [
    '--from', prepared.source_root,
    '--target-knowledge-root', context.projectKnowledgeRoot,
    '--apply',
    '--yes',
    '--json'
  ], 'update_apply');
  const verify = runTool('update-system-files.js', [
    '--from', prepared.source_root,
    '--target-knowledge-root', context.projectKnowledgeRoot,
    '--verify-upgrade',
    '--json'
  ], 'verify_upgrade');
  let refreshedStatus = null;
  try {
    refreshedStatus = await checkUpdates.checkNow(checkUpdates.getConfig(), 'post_update_apply');
    launchUpdateStatus = refreshedStatus;
  } catch (error) {
    refreshedStatus = { status: 'check_failed', reason: 'post_update_apply', error: error.message };
  }
  return { apply, verify, refreshed_status: refreshedStatus };
}

function scheduleShutdown() {
  if (shutdownScheduled) return;
  shutdownScheduled = true;
  setTimeout(() => {
    if (!server) process.exit(0);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1200).unref();
  }, 60).unref();
}

function state() {
  const liveContext = currentContext();
  const quality = safeJson('maintenance/quality_report.json', {});
  const trust = safeJson('maintenance/trust_report.json', {});
  const routing = safeJson('maintenance/routing_bundle.json', {});
  const stale = safeJson('maintenance/stale_items.json', { items: [] });
  const repair = safeJson('maintenance/repair_queue.json', { queue: [] });
  const external = safeJson('maintenance/external_memory_status.json', {});
  const prImpact = safeJson('maintenance/pr_impact.json', { status: 'not_generated', changed_files: [], affected_modules: [], policy_warnings: [] });
  const agentActivity = safeJson('sessions/agent-registry.json', { sessions: [] });
  const concurrency = safeJson('maintenance/concurrency_policy.json', {});
  const update = safeJson('maintenance/update_status.json', { status: 'never_checked' });
  const settings = loadSettings();
  const footer = settings.report_footer;
  const activeSessions = (agentActivity.sessions || []).filter((session) => ['running', 'waiting'].includes(session.status));
  const staleItems = stale.items || stale.stale_items || [];
  const repairItems = repair.queue || repair.items || [];
  const evidenceFiles = fs.existsSync(path.join(context.projectKnowledgeRoot, 'evidence'))
    ? fs.readdirSync(path.join(context.projectKnowledgeRoot, 'evidence')).filter((name) => name.endsWith('.json')).length
    : 0;
  const prSummaryAvailable = fs.existsSync(path.join(context.stateRoot, 'maintenance', 'pr_summary.md')) ||
    fs.existsSync(path.join(context.projectKnowledgeRoot, 'maintenance', 'pr_summary.md'));
  return {
    schema_version: 'knowledge-inspector-state.v1',
    generated_at: new Date().toISOString(),
    product: {
      name: '.knowledge',
      version: safeJson('package.json', {}).version || '3.2.9',
      formula: 'Repo-local trust, freshness and repair for coding agents.',
      category: 'routing/evidence/trust/freshness/repair/PR-review system',
      no_cloud_required: true,
      telemetry: 'disabled'
    },
    context: jsonContext(liveContext),
    home_cards: {
      repo_readiness: quality.status || (quality.quality_score >= 80 ? 'ready' : 'needs_check'),
      knowledge_trust: trust.status || (staleItems.length || repairItems.length ? 'needs_recheck' : 'unknown'),
      evidence_coverage: evidenceFiles ? `${evidenceFiles} evidence files` : 'missing evidence',
      routing_status: routing.generated_at ? 'available' : 'needs_build',
      repair_pressure: repairItems.length,
      pr_review_status: prSummaryAvailable ? 'available' : 'not_generated',
      agent_activity: activeSessions.length ? `${activeSessions.length} active` : 'no active agents',
      memory_providers: external.status || external.overall_status || 'advisory_only',
      next_recommended_action: repairItems.length || staleItems.length ? 'Restore Trust' : 'Run Health Check',
      recent_reports: [
        prSummaryAvailable ? 'PR summary' : null,
        fs.existsSync(path.join(context.stateRoot, 'maintenance', 'debug-bundle.json')) ? 'Debug bundle' : null,
        fs.existsSync(path.join(context.stateRoot, 'maintenance', 'pro-inspector-snapshot.json')) ? 'Pro snapshot' : null
      ].filter(Boolean)
    },
    review: {
      pr_impact: prImpact,
      changed_files: prImpact.changed_files || [],
      critical_paths: safeJson('maps/critical_paths.json', {}),
      policy_warnings: prImpact.policy_warnings || [],
      auto_merge_default: 'disabled'
    },
    knowledge_trust: { trust, routing, stale, repair },
    agent_activity: {
      registry: agentActivity,
      active_sessions: activeSessions,
      safe_queue: concurrency.safe_queue || { mode: 'Safe Queue', default: true },
      merge_policy: concurrency.merge_policy || { default: 'Manual Only', auto_merge: false }
    },
    memory: {
      ...external,
      source_of_truth_policy: external.source_of_truth_policy || {
        external_memory_source_of_truth: false,
        external_memory_can_raise_trust: false
      }
    },
    settings: {
      ...settings,
      user_mode: settings.operator_profile.user_mode || 'simple',
      onboarding: onboardingState(settings)
    },
    update_status: update,
    pro: loadEntitlements(context.projectKnowledgeRoot)
  };
}

function html() {
  const s = state();
  const data = visualInspector.collect();
  data.generated_at = s.generated_at;
  data.context = s.context;
  data.settings = s.settings;
  data.updateStatus = s.update_status || data.updateStatus || { status: 'never_checked' };
  if (!data.external || !Object.keys(data.external).length) data.external = s.memory || {};
  return visualInspector.renderTabbed(data, { live: true, token, actions: listActions() });
}

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(body);
}

function sendJson(res, status, body) {
  send(res, status, JSON.stringify(body, null, 2), 'application/json; charset=utf-8');
}

function isUnder(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (rel && !rel.startsWith('..') && !path.isAbsolute(rel));
}

function resolveInspectorFile(rawPath) {
  const raw = String(rawPath || '').trim();
  if (!raw || raw.includes('\0')) throw new Error('missing_file_path');
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^file:/i.test(raw)) throw new Error('unsupported_file_url');
  let clean = raw;
  if (/^file:/i.test(clean)) {
    try { clean = decodeURIComponent(new URL(clean).pathname.replace(/^\/([A-Za-z]:)/, '$1')); }
    catch { throw new Error('invalid_file_url'); }
  }
  clean = clean.replace(/\\/g, '/').replace(/^\.\//, '');

  let candidate;
  if (/^[A-Za-z]:\//.test(clean) || clean.startsWith('//') || clean.startsWith('/')) {
    candidate = path.resolve(clean);
  } else if (clean.startsWith('.knowledge/')) {
    candidate = path.resolve(context.projectKnowledgeRoot, clean.slice('.knowledge/'.length));
  } else if (clean.startsWith('knowledge/')) {
    candidate = path.resolve(context.projectKnowledgeRoot, clean.slice('knowledge/'.length));
  } else if (/^(modules|maps|maintenance|wiki|docs|evidence|templates|external_memory|metrics|search|inspector|invariants|sessions|flows|commands|skills|agent-integrations)\//.test(clean)) {
    candidate = path.resolve(context.projectKnowledgeRoot, clean);
  } else {
    candidate = path.resolve(context.targetRoot, clean);
  }

  const allowedRoots = [context.targetRoot, context.projectKnowledgeRoot, context.stateRoot]
    .filter(Boolean)
    .map((item) => path.resolve(item));
  if (!allowedRoots.some((root) => isUnder(candidate, root))) throw new Error('file_outside_workspace');
  if (!fs.existsSync(candidate)) throw new Error('file_not_found');
  const stats = fs.statSync(candidate);
  if (!stats.isFile()) throw new Error('not_a_file');
  if (stats.size > Number(process.env.KNOWLEDGE_INSPECTOR_MAX_OPEN_FILE_BYTES || 2_000_000)) throw new Error('file_too_large');
  return candidate;
}

function fileContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.json') return 'application/json; charset=utf-8';
  if (ext === '.md' || ext === '.markdown') return 'text/markdown; charset=utf-8';
  if (['.txt', '.log', '.ndjson', '.yaml', '.yml', '.toml', '.js', '.ts', '.tsx', '.jsx', '.css', '.html', '.mjs', '.cjs'].includes(ext)) {
    return 'text/plain; charset=utf-8';
  }
  return 'application/octet-stream';
}

function sendInspectorFile(res, rawPath) {
  const filePath = resolveInspectorFile(rawPath);
  const body = fs.readFileSync(filePath);
  res.writeHead(200, {
    'content-type': fileContentType(filePath),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(body);
}

function authOk(req) {
  const url = new URL(req.url, `http://${host}:${port}`);
  if (url.pathname === '/api/session') return true;
  const header = req.headers.authorization || req.headers['x-knowledge-session'] || '';
  const provided = String(header).replace(/^Bearer\s+/i, '');
  return provided === token || url.searchParams.get('token') === token;
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return {}; }
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${host}:${port}`);
  if (url.pathname === '/' || url.pathname === '/index.html') {
    return send(res, 200, html(), 'text/html; charset=utf-8');
  }
  if (!url.pathname.startsWith('/api/')) return sendJson(res, 404, { ok: false, error: 'not_found' });
  if (!authOk(req)) return sendJson(res, 401, { ok: false, error: 'session_token_required' });

  if (req.method === 'GET' && url.pathname === '/api/session') {
    return sendJson(res, 200, { ok: true, token, host, port, scope: 'local-inspector' });
  }
  if (req.method === 'GET' && url.pathname === '/api/state') return sendJson(res, 200, { ok: true, state: state() });
  if (req.method === 'GET' && url.pathname === '/api/files/open') {
    try { return sendInspectorFile(res, url.searchParams.get('path')); }
    catch (error) { return sendJson(res, 404, { ok: false, error: error.message }); }
  }
  if (req.method === 'GET' && url.pathname === '/api/actions') {
    return sendJson(res, 200, { ok: true, actions: listActions(), entitlements: loadEntitlements(context.projectKnowledgeRoot) });
  }
  if (req.method === 'GET' && url.pathname === '/api/trust') return sendJson(res, 200, { ok: true, trust: state().knowledge_trust });
  if (req.method === 'GET' && url.pathname === '/api/repair') return sendJson(res, 200, { ok: true, repair: state().knowledge_trust.repair });
  if (req.method === 'GET' && url.pathname === '/api/team') return sendJson(res, 200, { ok: true, team: state().agent_activity });
  if (req.method === 'GET' && url.pathname === '/api/git/branches') {
    const current = currentContext();
    return sendJson(res, 200, { ok: true, git: current.git.branches });
  }
  if (req.method === 'GET' && url.pathname === '/api/git/diagnostics') {
    const result = branchDiagnostics(url.searchParams.get('branch'));
    return sendJson(res, result.ok ? 200 : 404, result);
  }
  if (req.method === 'GET' && url.pathname === '/api/update/status') {
    let status;
    if (url.searchParams.get('refresh') === '1') {
      status = await checkUpdates.checkNow(checkUpdates.getConfig(), 'inspector_manual_refresh');
      launchUpdateStatus = status;
    } else {
      status = await updateStatus();
    }
    return sendJson(res, 200, { ok: true, status, release: status });
  }
  if (req.method === 'POST' && url.pathname === '/api/update/dry-run') {
    const status = await updateStatus();
    try {
      const prepared = await prepareUpdate(status);
      return sendJson(res, prepared.dry_run.ok ? 200 : 422, { ok: prepared.dry_run.ok, status, dry_run: updateDryRunPlan(status, prepared), prepared });
    } catch (error) {
      return sendJson(res, 422, { ok: false, status, error: error.message, dry_run: updateDryRunPlan(status) });
    }
  }
  if (req.method === 'POST' && url.pathname === '/api/update/apply') {
    const status = await updateStatus();
    const body = await readBody(req);
    if (body.confirm !== true) {
      return sendJson(res, 409, {
        ok: false,
        status,
        error: 'manual_confirmation_required',
        message: 'Inspector applies updates only after explicit confirmation.'
      });
    }
    try {
      const prepared = await prepareUpdate(status, body.expectedVersion || null);
      if (!prepared.dry_run.ok) return sendJson(res, 422, { ok: false, status, prepared, error: 'dry_run_failed' });
      const apply = await applyPreparedUpdate(prepared);
      const ok = apply.apply.ok && apply.verify.ok;
      const refreshedStatus = apply.refreshed_status || status;
      return sendJson(res, ok ? 200 : 500, { ok, status: refreshedStatus, previous_status: status, refreshed_status: refreshedStatus, prepared, apply });
    } catch (error) {
      return sendJson(res, 500, { ok: false, status, error: error.message });
    }
  }
  if (req.method === 'POST' && url.pathname === '/api/shutdown') {
    sendJson(res, 200, { ok: true, status: 'shutting_down', message: 'Inspector server is closing and the port will be released.' });
    scheduleShutdown();
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/settings/onboarding') {
    const body = await readBody(req);
    const settings = saveOnboarding(body);
    return sendJson(res, 200, { ok: true, settings });
  }

  const runMatch = url.pathname.match(/^\/api\/actions\/([^/]+)\/run$/);
  if (req.method === 'POST' && runMatch) {
    const body = await readBody(req);
    const run = runAction(context, decodeURIComponent(runMatch[1]), body);
    const code = run.status === 'passed' ? 200 : run.status === 'needs_confirmation' ? 409 : run.status === 'blocked' ? 423 : 500;
    return sendJson(res, code, { ok: run.status === 'passed', run });
  }

  const getRunMatch = url.pathname.match(/^\/api\/runs\/([^/]+)$/);
  if (req.method === 'GET' && getRunMatch) {
    const run = getRun(decodeURIComponent(getRunMatch[1]));
    return run ? sendJson(res, 200, { ok: true, run }) : sendJson(res, 404, { ok: false, error: 'run_not_found' });
  }

  const streamMatch = url.pathname.match(/^\/api\/runs\/([^/]+)\/stream$/);
  if (req.method === 'GET' && streamMatch) {
    const run = getRun(decodeURIComponent(streamMatch[1]));
    if (!run) return sendJson(res, 404, { ok: false, error: 'run_not_found' });
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store' });
    return res.end(`event: run\ndata: ${JSON.stringify(run)}\n\n`);
  }

  return sendJson(res, 404, { ok: false, error: 'not_found' });
}

function openLocalBrowser(url) {
  if (!flags.open || process.env.KNOWLEDGE_INSPECTOR_NO_OPEN === '1') return;
  const command = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
  child.unref();
}

ensureDir(path.join(context.stateRoot, 'maintenance', 'action-runs'));
runUpdateCheckOnLaunch();
server = http.createServer((req, res) => {
  Promise.resolve(handle(req, res)).catch((error) => sendJson(res, 500, { ok: false, error: error.stack || error.message }));
});
server.listen(port, host, () => {
  const url = `http://${host}:${port}/?token=${token}`;
  const payload = { ok: true, url, host, port, session_token: token, scope: 'local-inspector' };
  console.log(JSON.stringify(payload, null, 2));
  openLocalBrowser(url);
});
