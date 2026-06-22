'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function runGit(targetRoot, args, options = {}) {
  const result = spawnSync('git', ['-C', targetRoot, ...args], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 10000
  });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: String(result.stdout || '').trim(),
    stderr: String(result.stderr || '').trim()
  };
}

function normalizeStatusPath(value) {
  return String(value || '')
    .replace(/^"|"$/g, '')
    .replace(/\\"/g, '"')
    .replace(/\\/g, '/');
}

function parsePorcelain(output) {
  const changed = [];
  const staged = [];
  for (const line of String(output || '').split(/\r?\n/).filter(Boolean)) {
    const index = line.slice(0, 1);
    const worktree = line.slice(1, 2);
    let file = normalizeStatusPath(line.slice(3));
    if (file.includes(' -> ')) file = normalizeStatusPath(file.split(' -> ').pop());
    const item = { path: file, index, worktree, raw: line };
    changed.push(item);
    if (index && index !== ' ' && index !== '?') staged.push(item);
  }
  return { changed, staged };
}

function stripBranchRef(value) {
  return String(value || '').replace(/^refs\/heads\//, '');
}

function parseWorktreeList(output) {
  const worktrees = [];
  let current = null;
  for (const line of String(output || '').split(/\r?\n/)) {
    if (!line.trim()) {
      if (current) worktrees.push(current);
      current = null;
      continue;
    }
    if (line.startsWith('worktree ')) {
      if (current) worktrees.push(current);
      current = { path: line.slice('worktree '.length), head_sha: null, branch: null, detached: false };
      continue;
    }
    if (!current) continue;
    if (line.startsWith('HEAD ')) current.head_sha = line.slice('HEAD '.length);
    else if (line.startsWith('branch ')) current.branch = stripBranchRef(line.slice('branch '.length));
    else if (line === 'detached') current.detached = true;
  }
  if (current) worktrees.push(current);
  return worktrees;
}

function listGitBranches(targetRoot = process.cwd()) {
  const root = path.resolve(targetRoot);
  const warnings = [];
  if (!fs.existsSync(root)) {
    return {
      schema_version: 'knowledge-git-branches.v1',
      active: null,
      selected: null,
      branches: [],
      warnings: ['targetRoot does not exist']
    };
  }

  const inside = runGit(root, ['rev-parse', '--is-inside-work-tree']);
  if (!inside.ok || inside.stdout !== 'true') {
    return {
      schema_version: 'knowledge-git-branches.v1',
      active: null,
      selected: null,
      branches: [],
      warnings: ['targetRoot is not a git repository']
    };
  }

  const worktreeRoot = runGit(root, ['rev-parse', '--show-toplevel']).stdout || root;
  const branchResult = runGit(root, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const activeBranch = branchResult.ok ? branchResult.stdout : null;
  const headResult = runGit(root, ['rev-parse', 'HEAD']);
  const headSha = headResult.ok ? headResult.stdout : null;
  const branchList = runGit(root, ['branch', '--format=%(refname:short)%09%(objectname)%09%(upstream:short)']);
  const worktreeList = runGit(root, ['worktree', 'list', '--porcelain']);
  const worktrees = worktreeList.ok ? parseWorktreeList(worktreeList.stdout) : [];
  if (!branchList.ok) warnings.push(`branch list unavailable: ${branchList.stderr || 'git branch failed'}`);
  if (!worktreeList.ok) warnings.push(`worktree list unavailable: ${worktreeList.stderr || 'git worktree failed'}`);

  const worktreeByBranch = new Map();
  for (const item of worktrees) {
    if (item.branch) worktreeByBranch.set(item.branch, item);
  }

  const branches = [];
  for (const line of String(branchList.stdout || '').split(/\r?\n/).filter(Boolean)) {
    const [name, objectName, upstream] = line.split('\t');
    if (!name) continue;
    const wt = worktreeByBranch.get(name) || null;
    branches.push({
      name,
      current: name === activeBranch,
      head_sha: objectName || null,
      upstream: upstream || null,
      worktree_path: wt?.path || null,
      active_worktree: wt?.path ? path.resolve(wt.path) === path.resolve(worktreeRoot) : name === activeBranch
    });
  }

  if (activeBranch && !branches.some((branch) => branch.name === activeBranch)) {
    branches.unshift({
      name: activeBranch,
      current: true,
      head_sha: headSha,
      upstream: null,
      worktree_path: worktreeRoot,
      active_worktree: true,
      detached: activeBranch === 'HEAD'
    });
  }

  branches.sort((a, b) => {
    if (a.current !== b.current) return a.current ? -1 : 1;
    return String(a.name).localeCompare(String(b.name));
  });

  return {
    schema_version: 'knowledge-git-branches.v1',
    active: activeBranch,
    selected: activeBranch,
    head_sha: headSha,
    worktree_root: worktreeRoot,
    branches,
    warnings
  };
}

function isGeneratedRuntimePath(filePath) {
  const p = normalizeStatusPath(filePath);
  return [
    '.knowledge/maintenance/',
    '.knowledge/search/',
    '.knowledge/inspector/',
    '.knowledge/metrics/baseline.json',
    '.knowledge/metrics/README.md',
    '.knowledge/maps/wiki_graph.json',
    '.knowledge/maps/file_criticality.json',
    '.knowledge/sessions/'
  ].some((prefix) => p === prefix.replace(/\/$/, '') || p.startsWith(prefix));
}

function detectGitContext(targetRoot = process.cwd()) {
  const root = path.resolve(targetRoot);
  const warnings = [];
  if (!fs.existsSync(root)) {
    return {
      is_git_repo: false,
      target_root: root,
      branch: null,
      head_sha: null,
      worktree_root: null,
      git_common_dir: null,
      dirty: false,
      changed_files: [],
      staged_files: [],
      remote_url: null,
      is_git_worktree: false,
      warnings: ['targetRoot does not exist']
    };
  }

  const inside = runGit(root, ['rev-parse', '--is-inside-work-tree']);
  if (!inside.ok || inside.stdout !== 'true') {
    return {
      is_git_repo: false,
      target_root: root,
      branch: null,
      head_sha: null,
      worktree_root: null,
      git_common_dir: null,
      dirty: false,
      changed_files: [],
      staged_files: [],
      remote_url: null,
      is_git_worktree: false,
      warnings: ['targetRoot is not a git repository']
    };
  }

  const worktreeRoot = runGit(root, ['rev-parse', '--show-toplevel']).stdout || root;
  const commonDirRaw = runGit(root, ['rev-parse', '--git-common-dir']).stdout || '';
  const gitCommonDir = commonDirRaw
    ? path.resolve(worktreeRoot, commonDirRaw)
    : null;
  const branchResult = runGit(root, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const branch = branchResult.ok ? branchResult.stdout : null;
  const headResult = runGit(root, ['rev-parse', 'HEAD']);
  const headSha = headResult.ok ? headResult.stdout : null;
  const remoteResult = runGit(root, ['config', '--get', 'remote.origin.url']);
  const statusResult = runGit(root, ['status', '--porcelain=v1']);
  const parsed = parsePorcelain(statusResult.stdout);
  const branches = listGitBranches(root);
  const generatedRuntimeStaged = parsed.staged
    .filter((item) => isGeneratedRuntimePath(item.path))
    .map((item) => item.path);

  if (branch === 'main' || branch === 'master') warnings.push('agent is on main');
  if (parsed.changed.length > 0) warnings.push('dirty workspace');
  if (generatedRuntimeStaged.length > 0) warnings.push('generated runtime files are staged for commit');

  const dotGit = path.join(worktreeRoot, '.git');
  const isLinkedWorktree = fs.existsSync(dotGit) && fs.statSync(dotGit).isFile();

  return {
    is_git_repo: true,
    target_root: root,
    branch,
    head_sha: headSha,
    worktree_root: worktreeRoot,
    git_common_dir: gitCommonDir,
    dirty: parsed.changed.length > 0,
    dirty_summary: {
      changed: parsed.changed.length,
      staged: parsed.staged.length,
      generated_runtime_staged: generatedRuntimeStaged.length
    },
    changed_files: parsed.changed.map((item) => item.path),
    staged_files: parsed.staged.map((item) => item.path),
    generated_runtime_staged: generatedRuntimeStaged,
    remote_url: remoteResult.ok ? remoteResult.stdout : null,
    is_git_worktree: isLinkedWorktree || Boolean(gitCommonDir && path.resolve(gitCommonDir) !== path.resolve(worktreeRoot, '.git')),
    branches,
    warnings
  };
}

module.exports = {
  detectGitContext,
  listGitBranches,
  runGit,
  isGeneratedRuntimePath
};
