#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..', '..');
const hookName = process.argv[2] || 'git-hook';
const hookArgs = process.argv.slice(3);

function git(args) {
  const result = spawnSync('git', args, { cwd: repoRoot, encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) return '';
  return result.stdout || '';
}

function uniqueLines(text) {
  return Array.from(new Set(String(text || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean)));
}

function changedFilesForHook(name, args) {
  if (name === 'post-commit') return uniqueLines(git(['diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD']));
  if (name === 'post-merge') return uniqueLines(git(['diff', '--name-only', 'ORIG_HEAD', 'HEAD']));
  if (name === 'post-checkout') {
    const [oldRef, newRef] = args;
    if (oldRef && newRef && oldRef !== newRef) return uniqueLines(git(['diff', '--name-only', oldRef, newRef]));
  }
  return [];
}

const changedFiles = changedFilesForHook(hookName, hookArgs);
const syncPath = path.join(repoRoot, '.knowledge', 'tools', 'sync-tracked.js');
const result = spawnSync(process.execPath, [syncPath], {
  cwd: repoRoot,
  env: {
    ...process.env,
    KNOWLEDGE_TRIGGER: `git-${hookName}`,
    KNOWLEDGE_CHANGED_FILES: JSON.stringify(changedFiles)
  },
  encoding: 'utf8',
  windowsHide: true
});

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exit(result.status || 0);
