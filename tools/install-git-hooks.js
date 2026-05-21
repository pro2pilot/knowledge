#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, writeFileAtomic, withLock } = require('./lib/json-store');

const repoRoot = path.resolve(__dirname, '..', '..');
const knowledgeRoot = path.join(repoRoot, '.knowledge');
const gitHooksDir = path.join(repoRoot, '.git', 'hooks');
const automationStatusPath = path.join(knowledgeRoot, 'maintenance', 'automation_status.json');
const hookErrorsPath = path.join(knowledgeRoot, 'maintenance', 'hook_errors.log');
const blockStart = '# BEGIN DOT-KNOWLEDGE MANAGED BLOCK';
const blockEnd = '# END DOT-KNOWLEDGE MANAGED BLOCK';

function hookBlock(hookName) {
  return `${blockStart}\n# Runs .knowledge maintenance without replacing user hook logic.\nif [ -f ".knowledge/tools/run-git-hook-sync.js" ]; then\n  node .knowledge/tools/run-git-hook-sync.js ${hookName} "$@" >/dev/null 2>> .knowledge/maintenance/hook_errors.log || { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] .knowledge hook ${hookName} failed" >> .knowledge/maintenance/hook_errors.log; true; }\nfi\n${blockEnd}`;
}

function upsertHook(name) {
  ensureDir(gitHooksDir);
  const hookPath = path.join(gitHooksDir, name);
  const block = hookBlock(name);
  let current = fs.existsSync(hookPath) ? fs.readFileSync(hookPath, 'utf8') : '#!/bin/sh\n';
  if (!current.startsWith('#!')) current = `#!/bin/sh\n${current}`;
  const regex = new RegExp(`${blockStart}[\\s\\S]*?${blockEnd}`, 'm');
  const next = regex.test(current)
    ? current.replace(regex, block)
    : `${current.replace(/\s*$/, '')}\n\n${block}\n`;
  writeFileAtomic(hookPath, next);
  fs.chmodSync(hookPath, 0o755);
  return hookPath;
}

function installGitHooks() {
  if (!fs.existsSync(gitHooksDir)) {
    throw new Error('No .git/hooks directory found. Run `git init` or use `node .knowledge/tools/init-git-repo.js` first.');
  }
  return withLock(path.join(knowledgeRoot, '.lock'), () => {
    ensureDir(path.dirname(hookErrorsPath));
    if (!fs.existsSync(hookErrorsPath)) fs.writeFileSync(hookErrorsPath, '', 'utf8');
    const installed = ['post-commit', 'post-merge', 'post-checkout'].map(upsertHook);
    const status = readJson(automationStatusPath, { mode: 'event-driven' });
    status.hooks_installed = true;
    status.hook_mode = 'managed_block';
    status.hook_errors_log = '.knowledge/maintenance/hook_errors.log';
    status.last_trigger_source = 'install-git-hooks';
    status.last_hooks_installed_at = new Date().toISOString();
    writeJsonAtomic(automationStatusPath, status);
    return { installed_hooks: installed.map((p) => path.relative(repoRoot, p).replace(/\\/g, '/')), hook_errors_log: '.knowledge/maintenance/hook_errors.log' };
  });
}

module.exports = installGitHooks;

if (require.main === module) {
  try {
    console.log(JSON.stringify(installGitHooks(), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
