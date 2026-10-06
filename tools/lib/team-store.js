'use strict';

const fs = require('fs');
const path = require('path');
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
      try { handle.release(); } catch {}
    }
    appendTeamEvent(context, 'lock_timeout', { lock: kind, code: error.code || 'lock_acquire_failed' });
    throw error;
  }
  return () => {
    const result = handle.release();
    appendTeamEvent(context, 'lock_released', {
      lock: kind,
      lock_id: handle.lock_id,
      released: result.status === 'released'
    });
    return result;
  };
}

function teamLockStatus(context) {
  return inspectLockSafety(teamLockRequest(context));
}

function listTeamStatus(teamRoot) {
  const registry = readRegistry(teamRoot);
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
          if (ws) workspaces.push(assertTeamIdentity(ws, { repoId, workspaceId }));
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
  return {
    schema_version: systemVersion(),
    generated_at: nowIso(),
    teamRoot,
    registry,
    repos,
    active_agents: Array.from(new Set(activeWorkspaces.map((ws) => ws.agentId).filter(Boolean))),
    workspaces_total: activeWorkspaces.length,
    stale_workspaces: staleWorkspaces.map((ws) => ({ workspaceId: ws.workspaceId, agentId: ws.agentId, updated_at: ws.updated_at })),
    warnings: staleWorkspaces.length ? [`${staleWorkspaces.length} stale workspace(s)`] : []
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
    last_status: flowResult.overall_status || null
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

module.exports = {
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
