'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { detectGitContext } = require('./git-context');

function camel(key) {
  return String(key || '').replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

function parseCliArgs(argv = process.argv.slice(2)) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const raw = arg.slice(2);
    const eq = raw.indexOf('=');
    if (eq !== -1) {
      flags[camel(raw.slice(0, eq))] = raw.slice(eq + 1);
      continue;
    }
    const key = camel(raw);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      flags[key] = next;
      i += 1;
    } else {
      flags[key] = true;
    }
  }
  return { flags, positional };
}

function opt(options, key, envName) {
  const camelKey = camel(key);
  if (options[camelKey] !== undefined && options[camelKey] !== null && options[camelKey] !== '') return options[camelKey];
  if (options[key] !== undefined && options[key] !== null && options[key] !== '') return options[key];
  if (envName && process.env[envName]) return process.env[envName];
  return null;
}

function hashText(value, length = 12) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex').slice(0, length);
}

function normalizeRemote(remoteUrl) {
  return String(remoteUrl || '')
    .trim()
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/^https?:\/\/([^@/]+@)/i, 'https://')
    .replace(/\.git$/i, '')
    .toLowerCase();
}

function sanitizeId(value) {
  const cleaned = String(value || '')
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, '')
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return cleaned || 'repo';
}

function stableRepoId(git, targetRoot) {
  const basis = git.remote_url ? normalizeRemote(git.remote_url) : path.resolve(targetRoot);
  const stableRoot = git.git_common_dir || git.worktree_root || targetRoot;
  const rootHash = hashText(stableRoot, 10);
  return `${sanitizeId(git.remote_url ? basis : 'local-repo')}-${rootHash}`;
}

function defaultSystemRoot() {
  return path.resolve(__dirname, '..', '..');
}

function isSourceCheckout(systemRoot) {
  if (path.basename(systemRoot) === '.knowledge') return false;
  return fs.existsSync(path.join(systemRoot, 'package.json')) &&
    fs.existsSync(path.join(systemRoot, 'tools')) &&
    fs.existsSync(path.join(systemRoot, 'templates'));
}

function defaultTargetRoot(systemRoot) {
  if (isSourceCheckout(systemRoot)) return systemRoot;
  return path.resolve(systemRoot, '..');
}

function maybeProjectKnowledgeRoot(targetRoot, systemRoot) {
  const candidate = path.join(targetRoot, '.knowledge');
  if (fs.existsSync(candidate)) return candidate;
  return systemRoot;
}

function buildStateRoot(teamRoot, repoId, workspaceId) {
  return path.join(teamRoot, 'repos', repoId, 'workspaces', workspaceId, 'state');
}

function resolveKnowledgeContext(options = {}) {
  const cliFlags = options.__skipCli ? {} : parseCliArgs(process.argv.slice(2)).flags;
  options = { ...cliFlags, ...options };
  const systemRoot = path.resolve(opt(options, 'system-root', 'KNOWLEDGE_SYSTEM_ROOT') || defaultSystemRoot());
  const explicitTarget = opt(options, 'target-root', 'KNOWLEDGE_TARGET_ROOT');
  const targetRoot = path.resolve(explicitTarget || defaultTargetRoot(systemRoot));
  const requestedMode = String(opt(options, 'mode', 'KNOWLEDGE_MODE') || '').toLowerCase();
  const teamRootRaw = opt(options, 'team-root', 'KNOWLEDGE_TEAM_ROOT');
  const workspaceId = opt(options, 'workspace-id', 'KNOWLEDGE_WORKSPACE_ID');
  const agentId = opt(options, 'agent-id', 'KNOWLEDGE_AGENT_ID');
  const mode = requestedMode === 'team' || teamRootRaw || workspaceId ? 'team' : 'repo';
  const warnings = [];

  const git = detectGitContext(targetRoot);
  warnings.push(...(git.warnings || []));
  const repoId = stableRepoId(git, targetRoot);

  if (mode === 'team') {
    if (!teamRootRaw) throw new Error('team mode requires --team-root or KNOWLEDGE_TEAM_ROOT');
    if (!workspaceId) throw new Error('team mode requires --workspace-id or KNOWLEDGE_WORKSPACE_ID');
    if (!agentId) throw new Error('team mode requires --agent-id or KNOWLEDGE_AGENT_ID');
  }

  const teamRoot = teamRootRaw ? path.resolve(teamRootRaw) : null;
  const projectKnowledgeRoot = path.resolve(
    opt(options, 'project-knowledge-root', 'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT') ||
    (mode === 'team' ? maybeProjectKnowledgeRoot(targetRoot, systemRoot) : systemRoot)
  );
  const stateRoot = path.resolve(
    opt(options, 'state-root', 'KNOWLEDGE_STATE_ROOT') ||
    (mode === 'team' ? buildStateRoot(teamRoot, repoId, workspaceId) : projectKnowledgeRoot)
  );

  if (mode === 'team' && !fs.existsSync(projectKnowledgeRoot)) {
    warnings.push('projectKnowledgeRoot does not exist');
  }
  if (mode === 'repo' && (teamRootRaw || workspaceId)) {
    warnings.push('team options ignored in repo mode');
  }

  return {
    mode,
    systemRoot,
    targetRoot,
    projectKnowledgeRoot,
    stateRoot,
    teamRoot,
    repoId,
    workspaceId: mode === 'team' ? String(workspaceId) : null,
    agentId: mode === 'team' ? String(agentId) : (agentId || process.env.KNOWLEDGE_AGENT_ID || null),
    branch: git.branch,
    headSha: git.head_sha,
    isGitWorktree: git.is_git_worktree,
    git,
    warnings
  };
}

function contextEnv(context, extra = {}) {
  const env = {
    ...process.env,
    ...extra,
    KNOWLEDGE_MODE: context.mode,
    KNOWLEDGE_SYSTEM_ROOT: context.systemRoot,
    KNOWLEDGE_TARGET_ROOT: context.targetRoot,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: context.projectKnowledgeRoot,
    KNOWLEDGE_STATE_ROOT: context.stateRoot,
    KNOWLEDGE_REPO_ID: context.repoId
  };
  if (context.teamRoot) env.KNOWLEDGE_TEAM_ROOT = context.teamRoot;
  if (context.workspaceId) env.KNOWLEDGE_WORKSPACE_ID = context.workspaceId;
  if (context.agentId) env.KNOWLEDGE_AGENT_ID = context.agentId;
  return env;
}

function jsonGit(git) {
  if (!git) return null;
  return {
    is_git_repo: git.is_git_repo,
    dirty: git.dirty,
    dirty_summary: git.dirty_summary || { changed: 0, staged: 0, generated_runtime_staged: 0 },
    active_branch: git.branch,
    head_sha: git.head_sha,
    is_git_worktree: git.is_git_worktree,
    branches: git.branches || {
      schema_version: 'knowledge-git-branches.v1',
      active: git.branch || null,
      selected: git.branch || null,
      branches: [],
      warnings: []
    }
  };
}

function jsonContext(context) {
  return {
    mode: context.mode,
    systemRoot: context.systemRoot,
    targetRoot: context.targetRoot,
    projectKnowledgeRoot: context.projectKnowledgeRoot,
    stateRoot: context.stateRoot,
    teamRoot: context.teamRoot,
    repoId: context.repoId,
    workspaceId: context.workspaceId,
    agentId: context.agentId,
    branch: context.branch,
    headSha: context.headSha,
    isGitWorktree: context.isGitWorktree,
    git: jsonGit(context.git),
    warnings: context.warnings
  };
}

module.exports = {
  parseCliArgs,
  resolveKnowledgeContext,
  contextEnv,
  jsonContext,
  stableRepoId,
  sanitizeId,
  normalizeRemote
};
