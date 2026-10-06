#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { readJson, writeJsonAtomicContained, writeFileAtomicContained, assertSafeContainedPath, assertSafeContainmentRoot, ensureContainedDir } = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');

const repoRoot = path.resolve(__dirname, '..', '..');
const knowledgeRoot = path.join(repoRoot, '.knowledge');
let gitHooksDir = null;
let hooksContainmentRoot = null;
const automationStatusPath = path.join(knowledgeRoot, 'maintenance', 'automation_status.json');
const hookErrorsPath = path.join(knowledgeRoot, 'maintenance', 'hook_errors.log');
const GIT_HOOKS_LOCK = Object.freeze({
  context: { projectKnowledgeRoot: knowledgeRoot },
  rootKind: 'project',
  rootPath: knowledgeRoot,
  lockName: 'git-hooks',
  purpose: LOCKS['git-hooks'].purpose
});
const blockStart = '# BEGIN DOT-KNOWLEDGE MANAGED BLOCK';
const blockEnd = '# END DOT-KNOWLEDGE MANAGED BLOCK';

function hookBlock(hookName) {
  return `${blockStart}\n# Runs .knowledge maintenance without replacing user hook logic.\nif [ -f ".knowledge/tools/run-git-hook-sync.js" ]; then\n  node .knowledge/tools/run-git-hook-sync.js ${hookName} "$@" >/dev/null 2>> .knowledge/maintenance/hook_errors.log || { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] .knowledge hook ${hookName} failed" >> .knowledge/maintenance/hook_errors.log; true; }\nfi\n${blockEnd}`;
}

function upsertHook(name) {
  ensureContainedDir(hooksContainmentRoot, gitHooksDir);
  const hookPath = path.join(gitHooksDir, name);
  const block = hookBlock(name);
  let current = fs.existsSync(hookPath) ? fs.readFileSync(hookPath, 'utf8') : '#!/bin/sh\n';
  if (!current.startsWith('#!')) current = `#!/bin/sh\n${current}`;
  const regex = new RegExp(`${blockStart}[\\s\\S]*?${blockEnd}`, 'm');
  const next = regex.test(current)
    ? current.replace(regex, block)
    : `${current.replace(/\s*$/, '')}\n\n${block}\n`;
  writeFileAtomicContained(hookPath, next, hooksContainmentRoot);
  fs.chmodSync(hookPath, 0o755);
  return hookPath;
}

function installGitHooks() {
  const git = (args) => {
    const result = spawnSync('git', args, { cwd: repoRoot, encoding: 'utf8', windowsHide: true });
    if (result.status !== 0) throw new Error(`Git metadata is unavailable: ${result.stderr || result.error?.message || 'not a Git repository'}`);
    return String(result.stdout || '').trim();
  };
  if (path.resolve(git(['rev-parse', '--show-toplevel'])) !== repoRoot) throw new Error('Refusing to install hooks outside the current project Git root.');
  const commonDir = path.resolve(repoRoot, git(['rev-parse', '--git-common-dir']));
  gitHooksDir = path.resolve(repoRoot, git(['rev-parse', '--git-path', 'hooks']));
  const inside = (root, candidate) => { const relative = path.relative(root, candidate); return !relative || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative)); };
  hooksContainmentRoot = inside(repoRoot, gitHooksDir) ? repoRoot : inside(commonDir, gitHooksDir) ? commonDir : null;
  if (!hooksContainmentRoot) throw new Error('External core.hooksPath is outside this project and its Git metadata; install the managed hook manually.');
  assertSafeContainmentRoot(hooksContainmentRoot);
  assertSafeContainedPath(hooksContainmentRoot, gitHooksDir, { allowMissing: true });
  const safeFile = (root, file) => {
    assertSafeContainedPath(root, file, { allowMissing: true });
    if (!fs.existsSync(file)) return;
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`Unsafe Git hook/state file: ${file}`);
  };
  const names = ['post-commit', 'post-merge', 'post-checkout'];
  for (const name of names) {
    const hook = path.join(gitHooksDir, name);
    safeFile(hooksContainmentRoot, hook);
    if (fs.existsSync(hook)) {
      const first = fs.readFileSync(hook, 'utf8').split(/\r?\n/, 1)[0];
      if (first.startsWith('#!') && !/^#!\s*(?:\/usr\/bin\/env\s+)?(?:\S*\/)?(?:ba|da|k|z)?sh(?:\s|$)/.test(first)) {
        throw new Error(`Cannot append a shell managed block to the non-shell hook ${name}.`);
      }
    }
  }
  safeFile(knowledgeRoot, hookErrorsPath);
  safeFile(knowledgeRoot, automationStatusPath);
  return withContainedLock(GIT_HOOKS_LOCK, () => {
    ensureContainedDir(knowledgeRoot, path.dirname(hookErrorsPath));
    if (!fs.existsSync(hookErrorsPath)) writeFileAtomicContained(hookErrorsPath, '', knowledgeRoot);
    const loaded = readJson(automationStatusPath, { mode: 'event-driven' });
    const status = loaded && typeof loaded === 'object' && !Array.isArray(loaded) ? loaded : { mode: 'event-driven' };
    const installed = names.map(upsertHook);
    status.hooks_installed = true;
    status.hook_mode = 'managed_block';
    status.hook_errors_log = '.knowledge/maintenance/hook_errors.log';
    status.last_trigger_source = 'install-git-hooks';
    status.last_hooks_installed_at = new Date().toISOString();
    writeJsonAtomicContained(automationStatusPath, status, knowledgeRoot);
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
