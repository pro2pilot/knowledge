#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
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
  schema_version: '3.2.2',
  user_mode: 'simple',
  first_run_onboarding_completed: false,
  detected_agent_runtime: null
};

const DEFAULT_AUTONOMY_POLICY = {
  schema_version: '3.2.2',
  agents_can_do_without_asking: 'run checks and reports',
  network_actions_require_confirmation: true,
  destructive_actions_require_confirmation: true,
  controlled_autonomy: 'planned'
};

const DEFAULT_AGENT_POLICY = {
  schema_version: '3.2.2',
  concurrent_work_policy: 'Safe Queue',
  merge_policy: 'Manual Only',
  auto_merge: false,
  safe_queue_default: true
};

const DEFAULT_REPORT_FOOTER = {
  schema_version: '3.2.2',
  mode: 'compact',
  show_token_metrics: true,
  show_restore_action: true,
  show_open_inspector_action: true,
  only_when_trust_incomplete: false
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
      'Connected agent detected',
      'User mode: Simple / Advanced',
      'What can agents do without asking?',
      'Concurrent work policy',
      'Merge policy',
      'Agent report footer'
    ]
  };
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
  const operator = {
    ...DEFAULT_OPERATOR_PROFILE,
    ...current.operator_profile,
    user_mode: userMode,
    first_run_onboarding_completed: true,
    detected_agent_runtime: body.detected_agent_runtime || current.operator_profile.detected_agent_runtime || null,
    onboarding_completed_at: now
  };
  const autonomy = {
    ...DEFAULT_AUTONOMY_POLICY,
    ...current.autonomy_policy,
    agents_can_do_without_asking: permission,
    network_actions_require_confirmation: true,
    destructive_actions_require_confirmation: true
  };
  const agent = {
    ...DEFAULT_AGENT_POLICY,
    ...current.agent_policy,
    concurrent_work_policy: concurrentPolicy,
    merge_policy: mergePolicy,
    auto_merge: mergePolicy === 'Auto Merge Experimental',
    safe_queue_default: concurrentPolicy === 'Safe Queue'
  };
  const footer = {
    ...DEFAULT_REPORT_FOOTER,
    ...current.report_footer,
    mode: footerMode,
    only_when_trust_incomplete: footerMode === 'only_when_trust_incomplete'
  };
  writeJsonAtomic(path.join(settingsDir, 'operator-profile.json'), operator);
  writeJsonAtomic(path.join(settingsDir, 'autonomy-policy.json'), autonomy);
  writeJsonAtomic(path.join(settingsDir, 'agent-policy.json'), agent);
  writeJsonAtomic(path.join(settingsDir, 'report-footer.json'), footer);
  return { operator_profile: operator, autonomy_policy: autonomy, agent_policy: agent, report_footer: footer };
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

function updateDryRunPlan(status) {
  const asset = status?.asset_url || '<release-zip>';
  return {
    status: 'manual_plan_required',
    message: 'Download or extract the release asset, review the dry-run, then apply only after user confirmation.',
    release_asset: asset,
    commands: [
      'node .knowledge/tools/check-updates.js --json',
      'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --dry-run --json',
      'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --apply --yes --json',
      'node .knowledge/tools/update-system-files.js --verify-upgrade --json'
    ]
  };
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
      version: safeJson('package.json', {}).version || '3.2.2',
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
    const status = await updateStatus();
    return sendJson(res, 200, { ok: true, status, release: status });
  }
  if (req.method === 'POST' && url.pathname === '/api/update/dry-run') {
    const status = await updateStatus();
    return sendJson(res, 200, { ok: true, status, dry_run: updateDryRunPlan(status) });
  }
  if (req.method === 'POST' && url.pathname === '/api/update/apply') {
    const status = await updateStatus();
    return sendJson(res, 409, {
      ok: false,
      status,
      error: 'manual_confirmation_required',
      message: 'Inspector does not apply updates silently. Review the dry-run plan and run update-system-files manually when ready.'
    });
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
http.createServer((req, res) => {
  Promise.resolve(handle(req, res)).catch((error) => sendJson(res, 500, { ok: false, error: error.stack || error.message }));
}).listen(port, host, () => {
  const url = `http://${host}:${port}/?token=${token}`;
  const payload = { ok: true, url, host, port, session_token: token, scope: 'local-inspector' };
  console.log(JSON.stringify(payload, null, 2));
  openLocalBrowser(url);
});
