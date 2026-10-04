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
  return Array.from(new Set(String(text || '').split('\0').filter((file) => file.length > 0)));
}

function changedFilesForHook(name, args) {
  if (name === 'post-commit') return uniqueLines(git(['diff-tree', '--root', '--no-commit-id', '--name-only', '-z', '-r', 'HEAD']));
  if (name === 'post-merge') return uniqueLines(git(['diff', '--no-ext-diff', '--name-only', '-z', 'ORIG_HEAD', 'HEAD', '--']));
  if (name === 'post-checkout') {
    const [oldRef, newRef] = args;
    if (oldRef && newRef && oldRef !== newRef && /^[a-f0-9]{40,64}$/i.test(oldRef) && /^[a-f0-9]{40,64}$/i.test(newRef)) {
      if (/^0+$/.test(oldRef)) return uniqueLines(git(['diff-tree', '--root', '--no-commit-id', '--name-only', '-z', '-r', newRef]));
      return uniqueLines(git(['diff', '--no-ext-diff', '--name-only', '-z', oldRef, newRef, '--']));
    }
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
if (result.error) process.stderr.write(`${result.error.message}\n`);
if (result.signal) process.stderr.write(`Knowledge sync terminated by ${result.signal}\n`);
process.exit(Number.isInteger(result.status) ? result.status : 1);
