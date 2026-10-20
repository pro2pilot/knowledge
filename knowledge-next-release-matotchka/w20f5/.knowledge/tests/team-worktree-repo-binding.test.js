'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { registerWorkspace, workspaceStateDir, workspaceDir } = require('../tools/lib/team-store');
const { stableRepoId } = require('../tools/lib/path-context');
const { withTempFixture } = require('../tools/lib/strict-temp-cleanup');
const sourceRoot = path.resolve(__dirname, '..');

test('worktree CLI selects the repository composite key before and after an unrelated archive', () => {
  withTempFixture({ prefix: 'team-worktree-binding-' }, root => {
    const teamRoot = path.join(root, 'team');
    // Do not inherit a surrounding checkout as either independent fixture repo.
    const env = { ...process.env, GIT_CEILING_DIRECTORIES: root, KNOWLEDGE_AGENT_ID: 'team-binding-test' };
    function seed(name) {
      const targetRoot = path.join(root, name);
      fs.mkdirSync(path.join(targetRoot, '.knowledge'), { recursive: true });
      const repoId = stableRepoId({}, targetRoot), workspaceId = 'shared-workspace';
      const context = { mode: 'team', teamRoot, repoId, workspaceId, targetRoot,
        projectKnowledgeRoot: path.join(targetRoot, '.knowledge'), systemRoot: sourceRoot,
        agentId: 'team-binding-test', git: {}, warnings: [] };
      context.stateRoot = workspaceStateDir(teamRoot, repoId, workspaceId);
      registerWorkspace(context);
      return context;
    }
    const a = seed('repo-a'), b = seed('repo-b');
    assert.notEqual(a.repoId, b.repoId);
    function cli(tool, args) {
      const run = spawnSync(process.execPath, [path.join(sourceRoot, 'tools', tool), ...args],
        { cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 30000 });
      assert.ifError(run.error);
      return { exit: run.status, body: JSON.parse(run.stdout || run.stderr) };
    }
    const common = ['--team-root', teamRoot, '--workspace-id', b.workspaceId];
    function selected(extra = []) {
      const result = cli('worktree-status.js', [...common, '--target-root', b.targetRoot, ...extra]);
      assert.equal(result.exit, 0);
      assert.equal(result.body.repo_id, b.repoId);
      assert.notEqual(result.body.workspace, null, 'Selected repository/workspace must resolve despite a foreign ID collision');
      assert.equal(result.body.workspace.repoId, b.repoId);
      assert.equal(result.body.workspace.targetRoot, b.targetRoot);
      assert(!result.body.warnings.some(warning => /multiple repositories/.test(warning)));
    }
    selected();
    selected(['--repo-id', b.repoId]);
    const other = path.join(workspaceDir(teamRoot, b.repoId, b.workspaceId), 'workspace.json');
    const before = fs.readFileSync(other);
    assert.equal(cli('workspace-unregister.js', common).exit, 1);
    assert.equal(cli('workspace-unregister.js', [...common, '--repo-id', a.repoId]).exit, 0);
    assert.deepEqual(fs.readFileSync(other), before);
    selected();
    selected(['--repo-id', b.repoId]);
  });
});

function withRealGitWorkspaces(callback) {
  return withTempFixture({ prefix: 'k-wt-git-' }, root => {
    const teamRoot = path.join(root, 'team');
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(KNOWLEDGE_|GIT_)/.test(key)));
    const emptyConfig = path.join(root, 'empty.gitconfig');
    fs.writeFileSync(emptyConfig, '');
    Object.assign(env, { GIT_CEILING_DIRECTORIES: root, GIT_TERMINAL_PROMPT: '0',
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: emptyConfig,
      KNOWLEDGE_AGENT_ID: 'team-binding-test', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' });
    function command(binary, args, cwd, overrides = {}) {
      const result = spawnSync(binary, args, { cwd, env: { ...env, ...overrides },
        encoding: 'utf8', windowsHide: true, timeout: 30000 });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr || result.stdout);
      return result;
    }
    function createRepo(name) {
      const targetRoot = path.join(root, name);
      fs.mkdirSync(path.join(targetRoot, '.knowledge'), { recursive: true });
      command('git', ['init', '--quiet', targetRoot], root);
      return targetRoot;
    }
    function cli(tool, args, targetRoot, overrides = {}) {
      return JSON.parse(command(process.execPath, [path.join(sourceRoot, 'tools', tool), ...args], targetRoot, overrides).stdout);
    }
    function register(targetRoot, overrides = {}) {
      return cli('workspace-register.js', ['--team-root', teamRoot, '--workspace-id', 'shared',
        '--target-root', targetRoot, '--system-root', sourceRoot, '--agent-id', 'team-binding-test'], targetRoot, overrides);
    }
    function status(targetRoot, overrides = {}, extraArgs = []) {
      return cli('worktree-status.js', ['--team-root', teamRoot, '--workspace-id', 'shared',
        '--target-root', targetRoot, ...extraArgs], targetRoot, overrides);
    }
    callback({ teamRoot, createRepo, register, status });
  });
}

for (const disabled of [false, true]) {
  test(`real Git registration and status use the same ${disabled ? 'disabled' : 'default'} discovery identity`, () => {
    withRealGitWorkspaces(({ teamRoot, createRepo, register, status }) => {
      const targetRoot = createRepo('repo'), overrides = disabled ? { KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1' } : {};
      const registered = register(targetRoot, overrides), repoId = registered.context.repoId;
      assert.equal(registered.context.git.is_git_repo, !disabled);
      const workspaceFile = path.join(workspaceDir(teamRoot, repoId, 'shared'), 'workspace.json');
      const before = fs.readFileSync(workspaceFile);
      for (const extraArgs of [[], ['--repo-id', repoId]]) {
        const result = status(targetRoot, overrides, extraArgs);
        assert.notEqual(result.workspace, null, 'A CLI-registered workspace must remain selectable in the same execution profile');
        assert.equal(result.workspace.repoId, repoId);
        assert.equal(result.workspace.targetRoot, targetRoot);
        assert.equal(result.repo_id, repoId);
        assert.equal(result.is_git_repo, !disabled);
        assert(!result.warnings.some(warning => /not registered|mismatch|multiple repositories/.test(warning)), JSON.stringify(result));
        if (disabled) {
          assert.equal(result.git_common_dir, null);
          assert(result.warnings.includes('git discovery disabled by execution profile'));
        }
      }
      assert.deepEqual(fs.readFileSync(workspaceFile), before);
    });
  });
}

test('explicit foreign repo selection remains diagnostic and preserves both real Git workspace records', () => {
  withRealGitWorkspaces(({ teamRoot, createRepo, register, status }) => {
    const a = createRepo('a'), b = createRepo('b');
    const registeredA = register(a), registeredB = register(b);
    const repoA = registeredA.context.repoId, repoB = registeredB.context.repoId;
    assert.notEqual(repoA, repoB);
    const records = [repoA, repoB].map(repoId => path.join(workspaceDir(teamRoot, repoId, 'shared'), 'workspace.json'));
    const before = records.map(file => fs.readFileSync(file));
    const result = status(b, {}, ['--repo-id', repoA]);
    assert.equal(result.workspace.repoId, repoA, 'Explicit repo-id has priority over the current target-derived ID');
    assert.equal(result.workspace.targetRoot, a);
    assert.equal(result.target_root, b);
    assert.equal(result.repo_id, repoB, 'The target repository identity remains distinguishable from the selected workspace');
    assert(result.warnings.includes('targetRoot does not match registered path'));
    assert(result.warnings.includes('repoId mismatch'));
    for (let index = 0; index < records.length; index++) assert.deepEqual(fs.readFileSync(records[index]), before[index]);
  });
});
