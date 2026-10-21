#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const source = path.resolve(__dirname, '..');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-git-hooks-'));
const project = path.join(root, 'project with spaces');
const checks = [];
const check = (name, fn) => { fn(); checks.push(name); };
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, value); };
const child = (cmd, args, cwd = project) => spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 15000, env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' } });
const git = (args, cwd = project) => { const result = child('git', ['-c', 'user.name=Knowledge fixture', '-c', 'user.email=fixture@example.invalid', ...args], cwd); assert.equal(result.status, 0, result.stderr || result.error?.message); return result.stdout.trim(); };
const install = (cwd = project) => child(process.execPath, [path.join(cwd, '.knowledge/tools/install-git-hooks.js')], cwd);
function setup(cwd) {
  const target = path.join(cwd, '.knowledge'); fs.mkdirSync(path.join(target, 'tools'), { recursive: true });
  fs.cpSync(path.join(source, 'tools/lib'), path.join(target, 'tools/lib'), { recursive: true });
  for (const rel of ['tools/install-git-hooks.js', 'tools/init-git-repo.js', 'tools/run-git-hook-sync.js', 'package.json']) fs.copyFileSync(path.join(source, rel), path.join(target, rel));
  write(path.join(target, 'tools/sync-tracked.js'), 'console.log(JSON.stringify({ changed: JSON.parse(process.env.KNOWLEDGE_CHANGED_FILES), trigger: process.env.KNOWLEDGE_TRIGGER }));\n');
}
try {
  setup(project);
  check('hook installer refuses a non-Git project', () => assert.equal(install().status, 1));
  check('init-git-repo supports a project directory with spaces', () => { assert.equal(child(process.execPath, [path.join(project, '.knowledge/tools/init-git-repo.js')]).status, 0); assert(fs.statSync(path.join(project, '.git')).isDirectory()); });
  const files = ['space name.txt', ' leading.txt', 'unicode-юнікод.txt'];
  if (process.platform !== 'win32') files.push('line\nbreak.txt');
  for (const file of files) write(path.join(project, file), 'first\n');
  git(['add', '--', ...files]); git(['commit', '-m', 'fixture initial']);
  const first = git(['rev-parse', 'HEAD']);
  const sync = (...args) => child(process.execPath, [path.join(project, '.knowledge/tools/run-git-hook-sync.js'), ...args]);
  check('root commit changed paths retain whitespace Unicode and NUL boundaries', () => { const result = sync('post-commit'); assert.equal(result.status, 0, result.stderr); assert.deepEqual(JSON.parse(result.stdout).changed.sort(), [...files].sort()); });
  const hooks = path.join(project, '.git/hooks');
  write(path.join(hooks, 'post-commit'), '#!/bin/sh\nprintf "user hook retained\\n"\n');
  check('managed hook installation preserves existing shell logic', () => { const result = install(); assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).installed_hooks.length, 3); assert(fs.readFileSync(path.join(hooks, 'post-commit'), 'utf8').includes('user hook retained')); });
  check('reinstall is idempotent', () => { const before = fs.readFileSync(path.join(hooks, 'post-commit')); assert.equal(install().status, 0); assert.deepEqual(fs.readFileSync(path.join(hooks, 'post-commit')), before); });
  if (process.platform !== 'win32') check('unsafe hook destination blocks the complete hook plan', () => {
    const outside = path.join(root, 'sentinel'); write(outside, 'untouched'); fs.unlinkSync(path.join(hooks, 'post-merge')); fs.symlinkSync(outside, path.join(hooks, 'post-merge'));
    const before = fs.readFileSync(path.join(hooks, 'post-commit')); assert.equal(install().status, 1); assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched'); assert.deepEqual(fs.readFileSync(path.join(hooks, 'post-commit')), before); fs.unlinkSync(path.join(hooks, 'post-merge'));
  });
  check('non-shell user hook is preserved and rejected', () => { write(path.join(hooks, 'post-merge'), '#!/usr/bin/env python3\nprint("user")\n'); const before = fs.readFileSync(path.join(hooks, 'post-merge')); assert.equal(install().status, 1); assert.deepEqual(fs.readFileSync(path.join(hooks, 'post-merge')), before); fs.unlinkSync(path.join(hooks, 'post-merge')); });
  check('configured local core.hooksPath with spaces receives active hooks', () => { git(['config', 'core.hooksPath', 'custom hooks']); const result = install(); assert.equal(result.status, 0, result.stderr); assert(JSON.parse(result.stdout).installed_hooks.every((file) => file.startsWith('custom hooks/'))); assert(fs.existsSync(path.join(project, 'custom hooks/post-commit'))); });
  write(path.join(project, files[0]), 'second\n'); git(['add', '--', files[0]]); git(['commit', '-m', 'fixture second']);
  const second = git(['rev-parse', 'HEAD']);
  check('post-checkout forwards exact changed paths between hook object IDs', () => assert.deepEqual(JSON.parse(sync('post-checkout', first, second, '1').stdout).changed, [files[0]]));
  check('post-merge forwards exact changed paths', () => { git(['update-ref', 'ORIG_HEAD', first]); assert.deepEqual(JSON.parse(sync('post-merge').stdout).changed, [files[0]]); });
  check('external configured hooks directory is not mutated', () => { const outside = path.join(root, 'external hooks'); fs.mkdirSync(outside); git(['config', 'core.hooksPath', outside]); assert.equal(install().status, 1); assert.deepEqual(fs.readdirSync(outside), []); git(['config', '--unset', 'core.hooksPath']); });
  check('linked Git worktree uses its actual shared Git hooks directory', () => { const worktree = path.join(root, 'linked worktree'); git(['worktree', 'add', '--detach', worktree, 'HEAD']); setup(worktree); const result = install(worktree); assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).installed_hooks.length, 3); });
  if (process.platform !== 'win32') check('sync child termination produces a failure exit code', () => { write(path.join(project, '.knowledge/tools/sync-tracked.js'), 'process.kill(process.pid, "SIGTERM");\n'); const result = sync('post-commit'); assert.equal(result.status, 1); assert.match(result.stderr, /SIGTERM/); });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks, platform: process.platform }, null, 2));
} finally { fs.rmSync(root, { recursive: true, force: true }); }
