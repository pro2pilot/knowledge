#!/usr/bin/env node
'use strict';

const path = require('path');
const { parseCliArgs, stableRepoId } = require('./lib/path-context');
const { detectGitContext } = require('./lib/git-context');
const { findWorkspace, listTeamStatus, appendTeamEvent } = require('./lib/team-store');

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const targetRoot = path.resolve(flags.targetRoot || process.env.KNOWLEDGE_TARGET_ROOT || process.cwd());
  const git = detectGitContext(targetRoot);
  const repoId = stableRepoId(git, targetRoot);
  const warnings = [...(git.warnings || [])];
  const teamRoot = flags.teamRoot || process.env.KNOWLEDGE_TEAM_ROOT || null;
  const workspaceId = flags.workspaceId || process.env.KNOWLEDGE_WORKSPACE_ID || null;
  let workspace = null;
  let team = null;

  if (teamRoot) {
    try {
      team = listTeamStatus(path.resolve(teamRoot));
      if (workspaceId) {
        const found = findWorkspace(path.resolve(teamRoot), workspaceId);
        workspace = found ? found.workspace : null;
        if (!workspace) warnings.push('worktree not registered');
        if (workspace && path.resolve(workspace.targetRoot) !== targetRoot) warnings.push('targetRoot does not match registered path');
        if (workspace && workspace.branch && git.branch && workspace.branch !== git.branch) warnings.push('workspace branch mismatch');
        if (workspace && workspace.repoId && workspace.repoId !== repoId) warnings.push('repoId mismatch');
      }
      const activeSameTarget = (team.repos || [])
        .flatMap((repo) => repo.workspaces || [])
        .filter((ws) => ws.status !== 'archived' && ws.targetRoot && path.resolve(ws.targetRoot) === targetRoot);
      if (git.dirty && activeSameTarget.length > 1) warnings.push('dirty working tree shared by multiple active workspaces');
    } catch (error) {
      warnings.push(`team status unavailable: ${error.message}`);
    }
  }

  const out = {
    schema_version: '3.2.0',
    generated_at: new Date().toISOString(),
    target_root: targetRoot,
    repo_id: repoId,
    workspace_id: workspaceId,
    is_git_repo: git.is_git_repo,
    branch: git.branch,
    head_sha: git.head_sha,
    worktree_root: git.worktree_root,
    git_common_dir: git.git_common_dir,
    dirty: git.dirty,
    dirty_summary: git.dirty_summary || { changed: 0, staged: 0, generated_runtime_staged: 0 },
    changed_files: git.changed_files || [],
    staged_files: git.staged_files || [],
    remote_url: git.remote_url,
    is_git_worktree: git.is_git_worktree,
    workspace,
    warnings: Array.from(new Set(warnings))
  };
  if (teamRoot && out.warnings.length > 0) {
    appendTeamEvent({
      teamRoot: path.resolve(teamRoot),
      repoId,
      workspaceId,
      agentId: workspace?.agentId || process.env.KNOWLEDGE_AGENT_ID || null,
      branch: git.branch,
      headSha: git.head_sha,
      targetRoot
    }, 'worktree_warning', { warnings: out.warnings });
  }
  console.log(JSON.stringify(out, null, 2));
  return out;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(JSON.stringify({ ok: false, error: error.message }, null, 2)); process.exit(1); }
}

module.exports = main;
