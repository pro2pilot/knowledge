'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  ensureDir,
  readJson,
  writeJsonAtomic,
  appendNdjson,
  sleepSync
} = require('./json-store');

function nowIso() {
  return new Date().toISOString();
}

function repoDir(teamRoot, repoId) {
  return path.join(teamRoot, 'repos', repoId);
}

function workspaceDir(teamRoot, repoId, workspaceId) {
  return path.join(repoDir(teamRoot, repoId), 'workspaces', workspaceId);
}

function workspaceStateDir(teamRoot, repoId, workspaceId) {
  return path.join(workspaceDir(teamRoot, repoId, workspaceId), 'state');
}

function eventPath(teamRoot, repoId, date = nowIso().slice(0, 10)) {
  return path.join(repoDir(teamRoot, repoId), 'events', `${date}.ndjson`);
}

function lockPath(teamRoot, repoId, kind = 'flow') {
  return path.join(repoDir(teamRoot, repoId), 'locks', `${kind}.lock`);
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
  appendNdjson(eventPath(context.teamRoot, context.repoId), event);
  return event;
}

function readRegistry(teamRoot) {
  return readJson(path.join(teamRoot, 'registry.json'), {
    schema_version: '3.2.0',
    created_at: nowIso(),
    updated_at: null,
    repos: []
  });
}

function upsertRepoInRegistry(registry, repo) {
  registry.repos = registry.repos || [];
  const idx = registry.repos.findIndex((item) => item.repoId === repo.repoId);
  if (idx === -1) registry.repos.push(repo);
  else registry.repos[idx] = { ...registry.repos[idx], ...repo };
  registry.updated_at = nowIso();
  return registry;
}

function initTeam(context) {
  if (context.mode !== 'team') throw new Error('team-init requires team mode context');
  const base = repoDir(context.teamRoot, context.repoId);
  ensureDir(context.teamRoot);
  ensureDir(path.join(base, 'locks'));
  ensureDir(path.join(base, 'events'));
  ensureDir(path.join(base, 'workspaces'));

  const registry = upsertRepoInRegistry(readRegistry(context.teamRoot), {
    repoId: context.repoId,
    targetRoot: context.targetRoot,
    remoteUrl: context.git.remote_url || null,
    worktreeRoot: context.git.worktree_root || null,
    branch: context.branch,
    headSha: context.headSha,
    updated_at: nowIso()
  });
  writeJsonAtomic(path.join(context.teamRoot, 'registry.json'), registry);

  const repoJsonPath = path.join(base, 'repo.json');
  const existing = readJson(repoJsonPath, {});
  const repoJson = {
    schema_version: '3.2.0',
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
  writeJsonAtomic(repoJsonPath, repoJson);
  appendTeamEvent(context, 'team_init', { repo: repoJson });
  return { registry, repo: repoJson };
}

function registerWorkspace(context, extra = {}) {
  initTeam(context);
  const dir = workspaceDir(context.teamRoot, context.repoId, context.workspaceId);
  const state = workspaceStateDir(context.teamRoot, context.repoId, context.workspaceId);
  ensureDir(dir);
  ensureDir(path.join(state, 'maintenance'));
  ensureDir(path.join(state, 'metrics'));
  ensureDir(path.join(state, 'search'));
  ensureDir(path.join(state, 'inspector'));
  ensureDir(path.join(state, 'sessions'));
  ensureDir(path.join(state, 'maps'));

  const filePath = path.join(dir, 'workspace.json');
  const existing = readJson(filePath, {});
  if (existing.status === 'active') {
    if (existing.targetRoot && path.resolve(existing.targetRoot) !== path.resolve(context.targetRoot)) {
      throw new Error(`workspaceId duplicate with different targetRoot: ${context.workspaceId}`);
    }
    if (existing.agentId && existing.agentId !== context.agentId) {
      throw new Error(`workspaceId duplicate with different agentId: ${context.workspaceId}`);
    }
  }
  const duplicateAgentWorkspaces = [];
  const workspacesRoot = path.join(repoDir(context.teamRoot, context.repoId), 'workspaces');
  if (fs.existsSync(workspacesRoot)) {
    for (const id of fs.readdirSync(workspacesRoot)) {
      if (id === context.workspaceId) continue;
      const candidate = readJson(path.join(workspacesRoot, id, 'workspace.json'), null);
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
    schema_version: '3.2.0',
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
  writeJsonAtomic(filePath, workspace);
  appendTeamEvent(context, 'workspace_register', { workspace });
  return workspace;
}

function findWorkspace(teamRoot, workspaceId) {
  const reposRoot = path.join(teamRoot, 'repos');
  if (!fs.existsSync(reposRoot)) return null;
  for (const repoId of fs.readdirSync(reposRoot)) {
    const file = path.join(reposRoot, repoId, 'workspaces', workspaceId, 'workspace.json');
    if (fs.existsSync(file)) return { repoId, workspace: readJson(file, {}), path: file };
  }
  return null;
}

function unregisterWorkspace(teamRoot, workspaceId) {
  const found = findWorkspace(teamRoot, workspaceId);
  if (!found) throw new Error(`Workspace not found: ${workspaceId}`);
  const workspace = {
    ...found.workspace,
    status: 'archived',
    archived_at: nowIso(),
    updated_at: nowIso()
  };
  writeJsonAtomic(found.path, workspace);
  appendNdjson(eventPath(teamRoot, found.repoId), {
    type: 'workspace_unregister',
    generated_at: nowIso(),
    repoId: found.repoId,
    workspaceId,
    agentId: workspace.agentId || null,
    targetRoot: workspace.targetRoot || null
  });
  return workspace;
}

function readLock(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return readJson(filePath, null);
  } catch {
    return { corrupt: true, path: filePath };
  }
}

function processAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function lockOwner(context) {
  return {
    pid: process.pid,
    hostname: os.hostname(),
    agentId: context.agentId || null,
    workspaceId: context.workspaceId || null,
    branch: context.branch || null,
    targetRoot: context.targetRoot || null,
    started_at: nowIso()
  };
}

function acquireTeamLock(context, kind = 'flow', options = {}) {
  const filePath = lockPath(context.teamRoot, context.repoId, kind);
  const timeoutMs = Number(options.timeoutMs || process.env.KNOWLEDGE_LOCK_TIMEOUT_MS || 30000);
  const staleMs = Number(options.staleMs || process.env.KNOWLEDGE_LOCK_STALE_MS || 120000);
  const retryMs = Number(options.retryMs || 100);
  const owner = lockOwner(context);
  const started = Date.now();
  ensureDir(path.dirname(filePath));

  while (true) {
    try {
      fs.writeFileSync(filePath, JSON.stringify(owner, null, 2) + '\n', { encoding: 'utf8', flag: 'wx' });
      appendTeamEvent(context, 'lock_acquired', { lock: kind, lockPath: filePath, owner });
      return () => {
        const current = readLock(filePath);
        if (!current || current.pid === owner.pid) {
          try { fs.unlinkSync(filePath); } catch {}
        }
        appendTeamEvent(context, 'lock_released', { lock: kind, lockPath: filePath, owner });
      };
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const current = readLock(filePath);
      let stale = false;
      try {
        const stat = fs.statSync(filePath);
        stale = Date.now() - stat.mtimeMs > staleMs;
      } catch {
        stale = true;
      }
      if (current && current.pid && !processAlive(current.pid)) stale = true;
      if (stale) {
        try { fs.unlinkSync(filePath); } catch {}
        appendTeamEvent(context, 'lock_timeout', { lock: kind, lockPath: filePath, stale_owner: current });
        continue;
      }
      if (Date.now() - started > timeoutMs) {
        appendTeamEvent(context, 'lock_timeout', { lock: kind, lockPath: filePath, owner: current });
        throw new Error(`Timed out waiting for ${kind} lock at ${filePath}`);
      }
      sleepSync(retryMs);
    }
  }
}

function listTeamStatus(teamRoot) {
  const registry = readRegistry(teamRoot);
  const repos = [];
  const reposRoot = path.join(teamRoot, 'repos');
  if (fs.existsSync(reposRoot)) {
    for (const repoId of fs.readdirSync(reposRoot)) {
      const base = path.join(reposRoot, repoId);
      const repo = readJson(path.join(base, 'repo.json'), { repoId });
      const workspaces = [];
      const workspacesRoot = path.join(base, 'workspaces');
      if (fs.existsSync(workspacesRoot)) {
        for (const workspaceId of fs.readdirSync(workspacesRoot)) {
          const ws = readJson(path.join(workspacesRoot, workspaceId, 'workspace.json'), null);
          if (ws) workspaces.push(ws);
        }
      }
      const locks = {};
      const locksRoot = path.join(base, 'locks');
      if (fs.existsSync(locksRoot)) {
        for (const name of fs.readdirSync(locksRoot)) locks[name] = readLock(path.join(locksRoot, name));
      }
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
    schema_version: '3.2.0',
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

function updateWorkspaceFlow(context, flowResult) {
  if (!context.teamRoot || !context.workspaceId) return null;
  const found = findWorkspace(context.teamRoot, context.workspaceId);
  if (!found) return null;
  const workspace = {
    ...found.workspace,
    branch: context.branch,
    headSha: context.headSha,
    updated_at: nowIso(),
    last_flow: flowResult.flow || flowResult.name || null,
    last_status: flowResult.overall_status || null
  };
  writeJsonAtomic(found.path, workspace);
  return workspace;
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
  listTeamStatus,
  updateWorkspaceFlow,
  readLock
};
