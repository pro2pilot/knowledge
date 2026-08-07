#!/usr/bin/env node
const { spawnSync } = require('child_process');
const path = require('path');

const repoRoot = process.cwd();
const result = spawnSync('git', ['init'], { cwd: repoRoot, stdio: 'inherit', shell: true });
if (result.status !== 0) {
  process.exit(result.status || 1);
}

console.log(JSON.stringify({ initialized: true, repo_root: repoRoot, git_hooks_dir: path.join(repoRoot, '.git', 'hooks') }, null, 2));
