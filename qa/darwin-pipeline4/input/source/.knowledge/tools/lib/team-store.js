'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  readJson,
  appendNdjson,
  assertSafeContainmentRoot,
  assertSafeContainedPath,
  writeJsonAtomicContained,
  ensureContainedDir
} = require('./json-store');
const {
  acquireContainedLock,
  withContainedLock,
  inspectLockSafety,
  lockPaths
} = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');
const { systemVersion } = require('./system-version');
const { assertSafePathSegment } = require('./path-segment');

function nowIso() {
  return new Date().toISOString();
}

function repoDir(teamRoot, repoId) {
  return path.join(teamRoot, 'repos', assertSafePathSegment(repoId, 'repoId'));
}

function workspaceDir(teamRoot, repoId, workspaceId) {
  return path.join(repoDir(teamRoot, repoId), 'workspaces', assertSafePathSegment(workspaceId, 'workspaceId'));
}

function workspaceStateDir(teamRoot, repoId, workspaceId) {
  return path.join(workspaceDir(teamRoot, repoId, workspaceId), 'state');
}

function eventPath(teamRoot, repoId, date = nowIso().slice(0, 10)) {
  return path.join(repoDir(teamRoot, repoId), 'events', `${assertSafePathSegment(date, 'event date')}.ndjson`);
}

function prepareTeamRoot(teamRoot) {
  const root = path.resolve(teamRoot);
  let ancestor = root;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }
  ensureContainedDir(assertSafeContainmentRoot(ancestor), root);
  return assertSafeContainmentRoot(root);
}

// A per-repository flow lock cannot protect registry.json shared by every
// repository, or workspace mutations performed outside a flow. Hold one lock
// from the first read through the final write. Internal helpers never acquire
// it again, so registerWorkspace -> initTeam cannot deadlock recursively.
function withTeamRegistryLock(context, operation) {
  const root = prepareTeamRoot(context.teamRoot);
  return withContainedLock({
    context: { ...context, stateRoot: root },
    rootKind: 'state',
    rootPath: root,
    lockName: 'team-registry',
    purpose: LOCKS['team-registry'].purpose
  }, operation);
}

function assertTeamFile(teamRoot, file) {
  assertSafeContainedPath(teamRoot, file, { allowMissing: true });
  if (fs.existsSync(file)) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
      const error = new Error('Team state must be a physical file with one link.');
      error.code = 'contained_path_unsafe';
      throw error;
    }
  }
  return file;
}

function readTeamJson(teamRoot, file, fallback) {
  assertTeamFile(teamRoot, file);
  // Missing state is initialized. Corrupt existing state is never replaced by
  // an empty fallback, because that would destroy another agent's registry.
  if (!fs.existsSync(file)) return fallback;
  const value = readJson(file);
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    const error = new Error('Invalid team state: expected a JSON object.');
    error.code = path.basename(file) === 'registry.json' ? 'team_registry_invalid' : 'team_state_invalid';
    throw error;
  }
  return value;
}

function assertTeamIdentity(value, expected) {
  for (const [field, identity] of Object.entries(expected)) {
    if (Object.prototype.hasOwnProperty.call(value, field) && value[field] !== identity) {
      const error = new Error(`Team state ${field} does not match its directory identity.`);
      error.code = 'team_state_identity_mismatch';
      throw error;
    }
  }
  return value;
}

function writeTeamJson(teamRoot, file, value) {
  assertTeamFile(teamRoot, file);
  return writeJsonAtomicContained(file, value, teamRoot);
}

function appendTeamNdjson(teamRoot, file, value) {
  assertTeamFile(teamRoot, file);
  ensureContainedDir(teamRoot, path.dirname(file));
  assertTeamFile(teamRoot, file);
  return appendNdjson(file, value);
}

function lockPath(teamRoot, repoId, kind = 'flow') {
  if (kind !== 'flow') {
    const error = new Error(`Unknown team lock kind: ${kind}`);
    error.code = 'unknown_lock_name';
    throw error;
  }
  return lockPaths({
    rootPath: repoDir(teamRoot, repoId),
    lockName: 'team-flow'
  }).lockDir;
}

function appendTeamEvent(context, type, payload = {}) {
  if (!context.teamRoot || !context.repoId) return null;
  const event = {
    type,
    generated_at: nowIso(),
    repoId: context.repoId,
    workspaceId: context.workspaceId || null,
    agentId: context.agentId || null,
    branch: context.branch || null,
    headSha: context.headSha || null,
    targetRoot: context.targetRoot || null,
    ...payload
  };
  appendTeamNdjson(context.teamRoot, eventPath(context.teamRoot, context.repoId), event);
  return event;
}

function readRegistry(teamRoot) {
  if (!fs.existsSync(teamRoot)) return { schema_version: systemVersion(), created_at: nowIso(), updated_at: null, repos: [] };
  const registry = readTeamJson(teamRoot, path.join(teamRoot, 'registry.json'), {
    schema_version: systemVersion(),
    created_at: nowIso(),
    updated_at: null,
    repos: []
  });
  if (!registry || typeof registry !== 'object' || Array.isArray(registry) || !Array.isArray(registry.repos)) {
    const error = new Error('Invalid team registry: expected an object with a repos array.');
    error.code = 'team_registry_invalid';
    throw error;
  }
  return registry;
}

function upsertRepoInRegistry(registry, repo) {
  registry.repos = registry.repos || [];
  const idx = registry.repos.findIndex((item) => item.repoId === repo.repoId);
  if (idx === -1) registry.repos.push(repo);
  else registry.repos[idx] = { ...registry.repos[idx], ...repo };
  registry.updated_at = nowIso();
  return registry;
}

function initTeamUnlocked(context) {
  if (context.mode !== 'team') throw new Error('team-init requires team mode context');
  const base = repoDir(context.teamRoot, context.repoId);
  prepareTeamRoot(context.teamRoot);
  const directories = ['locks', 'events', 'workspaces'].map((name) => path.join(base, name));
  for (const directory of directories) assertSafeContainedPath(context.teamRoot, directory, { allowMissing: true });
  assertTeamFile(context.teamRoot, path.join(base, 'repo.json'));
  const existing = assertTeamIdentity(readTeamJson(context.teamRoot, path.join(base, 'repo.json'), {}), { repoId: context.repoId });

  const registry = upsertRepoInRegistry(readRegistry(context.teamRoot), {
    repoId: context.repoId,
    targetRoot: context.targetRoot,
    remoteUrl: context.git.remote_url || null,
    worktreeRoot: context.git.worktree_root || null,
    branch: context.branch,
    headSha: context.headSha,
    updated_at: nowIso()
  });
  for (const directory of directories) ensureContainedDir(context.teamRoot, directory);
  writeTeamJson(context.teamRoot, path.join(context.teamRoot, 'registry.json'), registry);

  const repoJsonPath = path.join(base, 'repo.json');
  const repoJson = {
    schema_version: systemVersion(),
    repoId: context.repoId,
    targetRoot: context.targetRoot,
    projectKnowledgeRoot: context.projectKnowledgeRoot,
    remoteUrl: context.git.remote_url || null,
    worktreeRoot: context.git.worktree_root || null,
    gitCommonDir: context.git.git_common_dir || null,
    branch: context.branch,
    headSha: context.headSha,
    created_at: existing.created_at || nowIso(),
    updated_at: nowIso(),
    status: 'active'
  };
  writeTeamJson(context.teamRoot, repoJsonPath, repoJson);
  appendTeamEvent(context, 'team_init', { repo: repoJson });
  return { registry, repo: repoJson };
}

function registerWorkspaceUnlocked(context, extra = {}) {
  const dir = workspaceDir(context.teamRoot, context.repoId, context.workspaceId);
  const state = workspaceStateDir(context.teamRoot, context.repoId, context.workspaceId);
  prepareTeamRoot(context.teamRoot);
  assertSafeContainedPath(context.teamRoot, dir, { allowMissing: true });
  const filePath = path.join(dir, 'workspace.json');
  const existing = assertTeamIdentity(readTeamJson(context.teamRoot, filePath, {}), { repoId: context.repoId, workspaceId: context.workspaceId });
  if (existing.status === 'active') {
    if (existing.targetRoot && path.resolve(existing.targetRoot) !== path.resolve(context.targetRoot)) {
      throw new Error(`workspaceId duplicate with different targetRoot: ${context.workspaceId}`);
    }
    if (existing.agentId && existing.agentId !== context.agentId) {
      throw new Error(`workspaceId duplicate with different agentId: ${context.workspaceId}`);
    }
  }
  initTeamUnlocked(context);
  ensureContainedDir(context.teamRoot, dir);
  for (const name of ['maintenance', 'metrics', 'search', 'inspector', 'sessions', 'maps']) {
    ensureContainedDir(context.teamRoot, path.join(state, name));
  }
  const duplicateAgentWorkspaces = [];
  const workspacesRoot = path.join(repoDir(context.teamRoot, context.repoId), 'workspaces');
  if (fs.existsSync(workspacesRoot)) {
    for (const id of fs.readdirSync(workspacesRoot)) {
      if (id === context.workspaceId) continue;
      const candidate = readTeamJson(context.teamRoot, path.join(workspacesRoot, id, 'workspace.json'), null);
      if (candidate && candidate.status === 'active' && candidate.agentId === context.agentId) {
        duplicateAgentWorkspaces.push(id);
      }
    }
  }
  const warnings = Array.from(new Set([
    ...(existing.warnings || []),
    ...(context.warnings || []),
    ...(duplicateAgentWorkspaces.length ? [`agentId duplicate in active workspaces: ${duplicateAgentWorkspaces.join(', ')}`] : [])
  ]));
  const workspace = {
    schema_version: systemVersion(),
    workspaceId: context.workspaceId,
    agentId: context.agentId,
    repoId: context.repoId,
    targetRoot: context.targetRoot,
    projectKnowledgeRoot: context.projectKnowledgeRoot,
    stateRoot: state,
    branch: context.branch,
    headSha: context.headSha,
    created_at: existing.created_at || nowIso(),
    updated_at: nowIso(),
    last_flow: existing.last_flow || null,
    last_status: existing.last_status || null,
    last_run_id: existing.last_run_id || null,
    lock_status: existing.lock_status || null,
    pr_number: extra.prNumber || existing.pr_number || null,
    notes: extra.notes || existing.notes || null,
    status: 'active',
    warnings
  };
  writeTeamJson(context.teamRoot, filePath, workspace);
  appendTeamEvent(context, 'workspace_register', { workspace });
  return workspace;
}

function findWorkspace(teamRoot, workspaceId, requestedRepoId = null) {
  assertSafePathSegment(workspaceId, 'workspaceId');
  if (requestedRepoId !== null) assertSafePathSegment(requestedRepoId, 'repoId');
  const reposRoot = path.join(teamRoot, 'repos');
  if (!fs.existsSync(reposRoot)) return null;
  assertSafeContainedPath(teamRoot, reposRoot);
  const matches = [];
  for (const repoId of requestedRepoId ? [requestedRepoId] : fs.readdirSync(reposRoot)) {
    const file = path.join(workspaceDir(teamRoot, repoId, workspaceId), 'workspace.json');
    const workspace = readTeamJson(teamRoot, file, null);
    if (workspace) matches.push({ repoId, workspace: assertTeamIdentity(workspace, { repoId, workspaceId }), path: file });
  }
  if (matches.length > 1) {
    const error = new Error('workspaceId exists in multiple repositories; provide --repo-id.');
    error.code = 'workspace_id_ambiguous';
    throw error;
  }
  return matches[0] || null;
}

function unregisterWorkspaceUnlocked(teamRoot, workspaceId, repoId = null) {
  const found = findWorkspace(teamRoot, workspaceId, repoId);
  if (!found) throw new Error(`Workspace not found: ${workspaceId}`);
  const workspace = {
    ...found.workspace,
    status: 'archived',
    archived_at: nowIso(),
    updated_at: nowIso()
  };
  writeTeamJson(teamRoot, found.path, workspace);
  appendTeamNdjson(teamRoot, eventPath(teamRoot, found.repoId), {
    type: 'workspace_unregister',
    generated_at: nowIso(),
    repoId: found.repoId,
    workspaceId,
    agentId: workspace.agentId || null,
    targetRoot: workspace.targetRoot || null
  });
  return workspace;
}

function teamLockRequest(context, options = {}) {
  if (!context?.teamRoot || !context?.repoId) {
    const error = new Error('Team lock requires explicit teamRoot and repoId.');
    error.code = 'lock_request_invalid';
    throw error;
  }
  const teamRoot = assertSafeContainmentRoot(context.teamRoot);
  const rootPath = ensureContainedDir(teamRoot, repoDir(teamRoot, context.repoId));
  return {
    context: { ...context, stateRoot: rootPath },
    rootKind: 'state',
    rootPath,
    lockName: 'team-flow',
    purpose: LOCKS['team-flow'].purpose,
    timeoutMs: options.timeoutMs,
    staleMs: options.staleMs,
    onRecovery: (event) => appendTeamEvent(context, 'lock_timeout', {
      lock: 'flow',
      recovery_id: event.recovery_id,
      reclaimed: true,
      reclaim_reason: event.reason,
      stale_owner: event.owner
    })
  };
}

function safeErrorCode(error, fallback) {
  return /^[A-Za-z0-9_-]{1,64}$/.test(String(error?.code || '')) ? error.code : fallback;
}

function acquireTeamLock(context, kind = 'flow', options = {}) {
  if (kind !== 'flow') {
    const error = new Error(`Unknown team lock kind: ${kind}`);
    error.code = 'unknown_lock_name';
    throw error;
  }
  let handle;
  try {
    handle = acquireContainedLock(teamLockRequest(context, options));
    appendTeamEvent(context, 'lock_acquired', {
      lock: kind,
      lock_id: handle.lock_id,
      acquired_at: handle.acquired_at
    });
  } catch (error) {
    if (handle) {
      try { handle.release(); }
      catch (cleanupError) { error.lock_release_error = safeErrorCode(cleanupError, 'lock_release_failed'); }
    }
    try { appendTeamEvent(context, 'lock_timeout', { lock: kind, code: safeErrorCode(error, 'lock_acquire_failed') }); }
    catch (eventError) { error.lock_event_error = safeErrorCode(eventError, 'lock_event_failed'); }
    throw error;
  }
  return () => {
    const result = handle.release();
    try {
      appendTeamEvent(context, 'lock_released', {
        lock: kind, lock_id: handle.lock_id, released: result.status === 'released'
      });
    } catch (error) {
      error.physical_release_status = result.status;
      error.lock_id = handle.lock_id;
      throw error;
    }
    return result;
  };
}

function teamLockStatus(context) {
  return inspectLockSafety(teamLockRequest(context));
}

function listTeamStatus(teamRoot) {
  const registry = readRegistry(teamRoot);
  // Shared mutations can be blocked while every repository flow lock is safe.
  // Inspect the registry root separately. Missing roots remain uninitialized:
  // calling the acquisition-oriented request resolver there would create them.
  const registryLock = fs.existsSync(teamRoot) ? inspectLockSafety({
    context: { stateRoot: path.resolve(teamRoot) },
    rootKind: 'state',
    rootPath: path.resolve(teamRoot),
    lockName: 'team-registry',
    purpose: LOCKS['team-registry'].purpose
  }) : null;
  const repos = [];
  const reposRoot = path.join(teamRoot, 'repos');
  if (fs.existsSync(reposRoot)) {
    assertSafeContainedPath(teamRoot, reposRoot);
    for (const repoId of fs.readdirSync(reposRoot)) {
      const base = path.join(reposRoot, repoId);
      const repo = assertTeamIdentity(readTeamJson(teamRoot, path.join(base, 'repo.json'), { repoId }), { repoId });
      const workspaces = [];
      const workspacesRoot = path.join(base, 'workspaces');
      if (fs.existsSync(workspacesRoot)) {
        assertSafeContainedPath(teamRoot, workspacesRoot);
        for (const workspaceId of fs.readdirSync(workspacesRoot)) {
          const ws = readTeamJson(teamRoot, path.join(workspacesRoot, workspaceId, 'workspace.json'), null);
          if (ws) workspaces.push({ ...assertTeamIdentity(ws, { repoId, workspaceId }), ...readTeamFlowStatus(teamRoot, repoId, workspaceId, ws.last_run_id) });
        }
      }
      const flowLock = inspectLockSafety({
        context: { stateRoot: base },
        rootKind: 'state',
        rootPath: base,
        lockName: 'team-flow',
        purpose: LOCKS['team-flow'].purpose
      });
      const locks = { flow: flowLock };
      repos.push({ ...repo, workspaces, locks });
    }
  }
  const activeWorkspaces = repos.flatMap((repo) => repo.workspaces || []).filter((ws) => ws.status !== 'archived');
  const staleAfterMs = Number(process.env.KNOWLEDGE_WORKSPACE_STALE_MS || 24 * 60 * 60 * 1000);
  const staleWorkspaces = activeWorkspaces.filter((ws) => {
    const ts = Date.parse(ws.updated_at || ws.created_at || '');
    return Number.isFinite(ts) && Date.now() - ts > staleAfterMs;
  });
  const warnings = staleWorkspaces.length ? [`${staleWorkspaces.length} stale workspace(s)`] : [];
  if (registryLock?.status === 'unsafe') {
    const codes = Array.from(new Set(registryLock.findings.map((finding) => finding.code))).join(', ');
    warnings.push(`Shared team-registry lock is unsafe (${codes || 'unsafe_lock_path'}); team mutations are blocked.`);
  }
  return {
    schema_version: systemVersion(),
    generated_at: nowIso(),
    teamRoot,
    registry,
    locks: { registry: registryLock },
    repos,
    active_agents: Array.from(new Set(activeWorkspaces.map((ws) => ws.agentId).filter(Boolean))),
    workspaces_total: activeWorkspaces.length,
    stale_workspaces: staleWorkspaces.map((ws) => ({ workspaceId: ws.workspaceId, agentId: ws.agentId, updated_at: ws.updated_at })),
    warnings
  };
}

function updateWorkspaceFlowUnlocked(context, flowResult) {
  if (!context.teamRoot || !context.workspaceId) return null;
  const found = findWorkspace(context.teamRoot, context.workspaceId, context.repoId);
  if (!found) return null;
  const workspace = {
    ...found.workspace,
    branch: context.branch,
    headSha: context.headSha,
    updated_at: nowIso(),
    last_flow: flowResult.flow || flowResult.name || null,
    last_status: 'incomplete',
    last_checks_status: flowResult.checks_status || flowResult.overall_status || null
  };
  writeTeamJson(context.teamRoot, found.path, workspace);
  return workspace;
}

function initTeam(context) {
  if (context.mode !== 'team') throw new Error('team-init requires team mode context');
  assertSafePathSegment(context.repoId, 'repoId');
  if (context.workspaceId !== undefined && context.workspaceId !== null) {
    assertSafePathSegment(context.workspaceId, 'workspaceId');
  }
  return withTeamRegistryLock(context, () => initTeamUnlocked(context));
}

function registerWorkspace(context, extra = {}) {
  if (context.mode !== 'team') throw new Error('team-init requires team mode context');
  assertSafePathSegment(context.repoId, 'repoId');
  assertSafePathSegment(context.workspaceId, 'workspaceId');
  return withTeamRegistryLock(context, () => registerWorkspaceUnlocked(context, extra));
}

function unregisterWorkspace(teamRoot, workspaceId, repoId = null) {
  assertSafePathSegment(workspaceId, 'workspaceId');
  if (repoId !== null) assertSafePathSegment(repoId, 'repoId');
  if (!fs.existsSync(teamRoot)) throw new Error(`Workspace not found: ${workspaceId}`);
  return withTeamRegistryLock({ teamRoot, workspaceId, repoId },
    () => unregisterWorkspaceUnlocked(teamRoot, workspaceId, repoId));
}

function updateWorkspaceFlow(context, flowResult) {
  if (!context.teamRoot || !context.workspaceId) return null;
  assertSafePathSegment(context.repoId, 'repoId');
  assertSafePathSegment(context.workspaceId, 'workspaceId');
  if (!fs.existsSync(context.teamRoot)) return null;
  return withTeamRegistryLock(context, () => updateWorkspaceFlowUnlocked(context, flowResult));
}

const FLOW_RUN = /^TFR-[a-f0-9]{32}$/;
const FLOW_HASH = /^[a-f0-9]{64}$/;
const flowDigest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const flowObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const flowTime = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const flowText = value => typeof value === 'string' && value.length > 0;
const sameFlowPath = (left, right) => typeof left === 'string' && typeof right === 'string' &&
  (process.platform === 'win32' ? path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase() : path.resolve(left) === path.resolve(right));
function flowRecordError(message) {
  return Object.assign(new Error(message), { code: 'team_flow_record_invalid' });
}
// Admission is read-only. Refuse a bad selected root before any start, lock or
// command can create state there. It may be a missing strict descendant of the
// physical team root, including the normal per-workspace state directory.
function teamFlowState(context, relative = null) {
  const root = assertSafeContainmentRoot(context.teamRoot);
  const candidate = relative === null
    ? (context.stateRoot || workspaceStateDir(context.teamRoot, context.repoId, context.workspaceId))
    : path.join(context.teamRoot, relative);
  const state = assertSafeContainedPath(root, candidate, { allowMissing: true });
  const rel = path.relative(root, state).replace(/\\/g, '/');
  if (!rel || rel === '..' || rel.startsWith('../') || path.isAbsolute(rel) ||
      (relative !== null && relative !== rel)) throw flowRecordError('Team flow state must be a strict contained directory');
  if (fs.existsSync(state) && !fs.lstatSync(state).isDirectory()) throw flowRecordError('Team flow state must be a directory');
  // Check existing parents of the log path as well; a regular state root must
  // not conceal a maintenance/flow-logs symlink or physical file.
  const logs = assertSafeContainedPath(root, path.join(state, 'maintenance', 'flow-logs'), { allowMissing: true });
  if (fs.existsSync(logs) && !fs.lstatSync(logs).isDirectory()) throw flowRecordError('Team flow logs must be a directory');
  return { relative: rel, path: path.join(context.teamRoot, rel) };
}
function validateFlowStart(value, context) {
  if (!flowObject(value) || !['knowledge-team-flow-start.v1', 'knowledge-team-flow-start.v2'].includes(value.schema_version) ||
      !FLOW_RUN.test(value.run_id) || !flowText(value.flow) || !flowText(value.agent_id) || !flowTime(value.started_at) ||
      !(value.retry_of === null || FLOW_RUN.test(value.retry_of)) || value.retry_of === value.run_id) {
    throw flowRecordError('Invalid Team flow start shape');
  }
  if (value.schema_version.endsWith('.v2')) {
    if (!flowText(value.state_root) || !flowText(value.target_root) || !path.isAbsolute(value.target_root) ||
        !flowText(value.project_knowledge_root) || !path.isAbsolute(value.project_knowledge_root)) throw flowRecordError('Invalid Team flow context binding');
    teamFlowState(context, value.state_root);
  }
  return value;
}
function validateFlowFinal(value, start) {
  const schema = start.schema_version.endsWith('.v2') ? 'knowledge-team-flow-finalization.v2' : 'knowledge-team-flow-finalization.v1';
  if (!flowObject(value) || value.schema_version !== schema || value.start_sha256 !== start.content_sha256 ||
      value.flow !== start.flow || value.retry_of !== start.retry_of || !flowTime(value.finished_at) ||
      !['ok', 'failed', 'unknown'].includes(value.checks_status) || !['ok', 'failed'].includes(value.final_status) ||
      !flowObject(value.release) || !['released', 'not_requested', 'failed', 'not_acquired'].includes(value.release.status) ||
      !(value.failure_code === null || flowText(value.failure_code))) throw flowRecordError('Invalid Team flow finalization shape');
  if (schema.endsWith('.v2') && value.state_root !== start.state_root) throw flowRecordError('Team flow finalization state changed');
  if (value.flow_log !== null) {
    if (typeof value.flow_log !== 'string' || !/^maintenance\/flow-logs\/[^/\\]+\.json$/.test(value.flow_log) ||
        !FLOW_HASH.test(value.flow_log_sha256) || !Number.isSafeInteger(value.flow_log_bytes) || value.flow_log_bytes <= 0) throw flowRecordError('Invalid Team flow log binding');
  } else if (value.flow_log_sha256 !== null || value.flow_log_bytes !== null) throw flowRecordError('Absent Team flow log has a byte binding');
  if (value.final_status === 'ok' && (value.checks_status !== 'ok' || value.flow_log === null ||
      !['released', 'not_requested'].includes(value.release.status))) throw flowRecordError('Successful Team flow lacks checks or release evidence');
  return value;
}
function validateBoundFlowLog(log, start, context, expectedChecks) {
  const state = teamFlowState(context, start.state_root);
  const observed = log?.context;
  if (!flowObject(log) || log.team_run_id !== start.run_id || log.flow !== start.flow || !flowObject(observed) ||
      observed.mode !== 'team' || observed.repoId !== start.repo_id || observed.workspaceId !== start.workspace_id ||
      observed.agentId !== start.agent_id || !sameFlowPath(observed.teamRoot, context.teamRoot) ||
      !sameFlowPath(observed.targetRoot, start.target_root) || !sameFlowPath(observed.projectKnowledgeRoot, start.project_knowledge_root) ||
      !sameFlowPath(observed.stateRoot, state.path) || !flowTime(log.started_at) ||
      !Number.isFinite(log.duration_total_ms) || log.duration_total_ms < 0 || !Array.isArray(log.steps) ||
      !Number.isSafeInteger(log.steps_total) || log.steps_total <= 0 || log.steps_total !== log.steps.length ||
      !log.steps.every(step => flowObject(step) && typeof step.success === 'boolean') ||
      log.steps_ok !== log.steps.filter(step => step.success).length ||
      log.overall_status !== (log.steps_ok === log.steps_total ? 'ok' : 'failed') || log.overall_status !== expectedChecks) {
    throw flowRecordError('Team flow log does not match its run, context or step outcomes');
  }
  return log;
}
function readRunBytes(teamRoot, file, limit) {
  assertTeamFile(teamRoot, file);
  const prior = fs.lstatSync(file);
  if (prior.size <= 0 || prior.size > limit) throw new Error('Team flow evidence exceeds its limit');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(fd);
    if (before.dev !== prior.dev || before.ino !== prior.ino || before.size !== prior.size || before.mtimeMs !== prior.mtimeMs || before.ctimeMs !== prior.ctimeMs) throw new Error('Team evidence changed');
    const bytes = Buffer.alloc(before.size + 1); let length = 0;
    while (length < bytes.length) { const count = fs.readSync(fd, bytes, length, bytes.length - length, null); if (!count) break; length += count; }
    const after = fs.fstatSync(fd), live = fs.lstatSync(file);
    assertTeamFile(teamRoot, file);
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs ||
        live.dev !== before.dev || live.ino !== before.ino || live.size !== before.size || live.mtimeMs !== before.mtimeMs || live.ctimeMs !== before.ctimeMs) throw new Error('Team evidence changed');
    return bytes.subarray(0, length);
  } finally { fs.closeSync(fd); }
}
function runPath(context, runId, kind) {
  if (!FLOW_RUN.test(runId)) throw Object.assign(new Error('Invalid team flow run identity'), { code: 'team_flow_run_invalid' });
  return path.join(workspaceDir(context.teamRoot, context.repoId, context.workspaceId), 'flow-runs', runId + '.' + kind + '.json');
}
function writeRun(context, runId, kind, value) {
  const file = runPath(context, runId, kind);
  ensureContainedDir(context.teamRoot, path.dirname(file));
  assertTeamFile(context.teamRoot, file);
  const body = JSON.stringify({ ...value, content_sha256: flowDigest(value) }, null, 2) + '\n';
  // Separate immutable per-attempt files; finalizing an older run cannot
  // overwrite the pointer to a newer run or another agent's attempt.
  fs.writeFileSync(file, body, { flag: 'wx' });
  try {
    assertTeamFile(context.teamRoot, file);
    if (readRunBytes(context.teamRoot, file, 256 * 1024).toString('utf8') !== body) throw Object.assign(new Error('Team finalization readback failed'), { code: 'team_flow_readback_failed' });
  } catch (error) {
    // This says that the write returned, not that the bytes were fsynced or
    // independently verified. Preserve the attempt so it can be reconciled.
    error.run_id = runId; error.retry_of = value.retry_of;
    error.record_kind = kind; error.record_write_status = 'write_completed_readback_failed';
    throw error;
  }
  return JSON.parse(body);
}
function readRun(context, runId, kind) {
  const file = runPath(context, runId, kind);
  assertTeamFile(context.teamRoot, file);
  if (!fs.existsSync(file)) return null;
  const value = JSON.parse(readRunBytes(context.teamRoot, file, 256 * 1024));
  if (!flowObject(value)) throw flowRecordError('A present Team flow record must be an object');
  const { content_sha256, ...body } = value;
  if (content_sha256 !== flowDigest(body) || value.run_id !== runId || value.repo_id !== context.repoId || value.workspace_id !== context.workspaceId) {
    throw Object.assign(new Error('Team flow record binding is invalid'), { code: 'team_flow_record_invalid' });
  }
  return value;
}
function beginTeamFlow(context, flow, retryOf = null) {
  if (context.mode !== 'team') return null;
  const selectedState = teamFlowState(context);
  return withTeamRegistryLock(context, () => {
    const found = findWorkspace(context.teamRoot, context.workspaceId, context.repoId);
    if (!found) throw Object.assign(new Error('Register this team workspace before running a flow'), { code: 'team_workspace_required' });
    if (retryOf) {
      const status = readTeamFlowStatus(context.teamRoot, context.repoId, context.workspaceId, retryOf);
      if (status.last_flow !== flow || status.finalization_status !== 'completed' || status.last_status !== 'failed' || teamLockStatus(context).status !== 'safe') {
        throw Object.assign(new Error('Retry requires a failed finalized attempt and a safe current flow lock; inspect incomplete attempts first'), { code: 'team_flow_retry_requires_reconciliation' });
      }
    }
    const runId = 'TFR-' + crypto.randomBytes(16).toString('hex');
    const value = { schema_version: 'knowledge-team-flow-start.v2', run_id: runId,
      repo_id: context.repoId, workspace_id: context.workspaceId, agent_id: context.agentId,
      flow, retry_of: retryOf, started_at: nowIso(), state_root: selectedState.relative,
      target_root: path.resolve(context.targetRoot), project_knowledge_root: path.resolve(context.projectKnowledgeRoot) };
    validateFlowStart(value, context);
    const start = writeRun(context, runId, 'start', value);
    try { writeTeamJson(context.teamRoot, found.path, { ...found.workspace, last_run_id: runId, last_flow: flow, last_status: 'incomplete', updated_at: nowIso() }); }
    catch (error) { error.run_id = runId; error.retry_of = retryOf; throw error; }
    return start;
  });
}
function finalizeTeamFlow(context, start, result, release) {
  if (!start) return null;
  const saved = readRun(context, start.run_id, 'start');
  if (!saved || saved.content_sha256 !== start.content_sha256) throw Object.assign(new Error('Team flow start changed'), { code: 'team_flow_record_invalid' });
  validateFlowStart(saved, context);
  if (saved.schema_version !== 'knowledge-team-flow-start.v2') throw Object.assign(new Error('Incomplete legacy Team flow requires reconciliation'), { code: 'team_flow_retry_requires_reconciliation' });
  const selectedState = teamFlowState(context);
  if (selectedState.relative !== saved.state_root || !sameFlowPath(context.targetRoot, saved.target_root) ||
      !sameFlowPath(context.projectKnowledgeRoot, saved.project_knowledge_root) || context.agentId !== saved.agent_id ||
      (result?.flow !== undefined && result.flow !== saved.flow)) throw flowRecordError('Team flow context changed before finalization');
  let logRelative = null;
  if (result?.flow_log && result.flow_log_status === 'written') {
    const log = path.resolve(context.targetRoot, result.flow_log);
    const state = selectedState.path;
    assertTeamFile(context.teamRoot, log);
    logRelative = path.relative(state, log).replace(/\\/g, '/');
    const body = readRunBytes(context.teamRoot, log, 16 * 1024 * 1024);
    if (!/^maintenance\/flow-logs\/[^/]+\.json$/.test(logRelative) || body.length !== result.flow_log_bytes ||
        crypto.createHash('sha256').update(body).digest('hex') !== result.flow_log_sha256) {
      throw Object.assign(new Error('Team flow log changed before finalization'), { code: 'team_flow_log_drift' });
    }
    const parsed = validateBoundFlowLog(JSON.parse(body), saved, context, result.checks_status);
    if (result.steps_total !== parsed.steps_total || result.steps_ok !== parsed.steps_ok ||
        result.duration_total_ms !== parsed.duration_total_ms) throw flowRecordError('Team flow result counters differ from its log');
  }
  const final = { schema_version: 'knowledge-team-flow-finalization.v2',
    run_id: saved.run_id, repo_id: context.repoId, workspace_id: context.workspaceId, start_sha256: saved.content_sha256,
    flow: saved.flow, retry_of: saved.retry_of, state_root: saved.state_root, finished_at: nowIso(), checks_status: result?.checks_status || 'unknown',
    final_status: result?.overall_status === 'ok' && logRelative && ['released', 'not_requested'].includes(release?.status) ? 'ok' : 'failed',
    release, failure_code: result?.failure_code || null,
    flow_log: logRelative, flow_log_sha256: logRelative ? result.flow_log_sha256 : null, flow_log_bytes: logRelative ? result.flow_log_bytes : null };
  validateFlowFinal(final, saved);
  return writeRun(context, saved.run_id, 'final', final);
}
function readTeamFlowStatus(teamRoot, repoId, workspaceId, runId) {
  if (!runId) return { last_status: 'unknown', finalization_status: 'legacy_unattested' };
  try {
    const context = { teamRoot, repoId, workspaceId };
    const start = readRun(context, runId, 'start'), final = readRun(context, runId, 'final');
    if (!start) throw flowRecordError('Team flow start is missing');
    validateFlowStart(start, context);
    const v2 = start.schema_version === 'knowledge-team-flow-start.v2';
    const stateRoot = v2 ? teamFlowState(context, start.state_root).path : workspaceStateDir(teamRoot, repoId, workspaceId);
    const binding_version = v2 ? 'run_bound_v2' : 'legacy_v1';
    if (!final) return { last_flow: start.flow, last_status: 'incomplete', finalization_status: 'incomplete', last_run_id: runId, stateRoot, binding_version };
    validateFlowFinal(final, start);
    if (final.flow_log) {
      if (!/^maintenance\/flow-logs\/[^/]+\.json$/.test(final.flow_log)) throw new Error('Invalid flow log path');
      const log = path.join(stateRoot, final.flow_log);
      assertTeamFile(teamRoot, log);
      const body = readRunBytes(teamRoot, log, 16 * 1024 * 1024);
      if (body.length !== final.flow_log_bytes || crypto.createHash('sha256').update(body).digest('hex') !== final.flow_log_sha256) throw new Error('Flow log drift');
      if (v2) validateBoundFlowLog(JSON.parse(body), start, context, final.checks_status);
    } else if (final.final_status === 'ok') throw new Error('Flow log required');
    return { last_flow: start.flow, last_status: final.final_status, finalization_status: 'completed', last_run_id: runId, stateRoot, binding_version, finalization: final };
  } catch { return { last_status: 'unknown', finalization_status: 'invalid', last_run_id: runId }; }
}

module.exports = {
  beginTeamFlow, finalizeTeamFlow, readTeamFlowStatus,
  repoDir,
  workspaceDir,
  workspaceStateDir,
  eventPath,
  lockPath,
  appendTeamEvent,
  initTeam,
  registerWorkspace,
  findWorkspace,
  unregisterWorkspace,
  acquireTeamLock,
  teamLockStatus,
  listTeamStatus,
  updateWorkspaceFlow,
  teamLockRequest
};
