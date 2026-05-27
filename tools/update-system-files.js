#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { ensureDir, writeJsonAtomic } = require('./lib/json-store');

const knowledgeRoot = path.resolve(__dirname, '..');
const repoRoot = path.basename(knowledgeRoot).toLowerCase() === '.knowledge' ? path.dirname(knowledgeRoot) : process.cwd();

const SYSTEM_PATHS = [
  'README.md',
  'Quick-Start.md',
  'Portal.md',
  'LICENSE',
  'NOTICE',
  'package.json',
  'config.yaml',
  'assets',
  'agent-integrations',
  'commands',
  'docs',
  'flows',
  'github-action-templates',
  'models',
  'prompts',
  'skills',
  'templates',
  'tools'
];

const PROJECT_PATHS = [
  'project_index.json',
  'freshness.json',
  'decisions.json',
  'contradictions.json',
  'glossary.json',
  'evidence',
  'external_memory',
  'invariants',
  'maintenance',
  'maps',
  'metrics',
  'modules',
  'search',
  'sessions',
  'wiki',
  'inspector'
];

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function parseArgs(argv) {
  const args = { from: null, dryRun: false, apply: false, yes: false, json: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--from') args.from = argv[++i];
    else if (arg.startsWith('--from=')) args.from = arg.slice('--from='.length);
    else if (arg === '--dry-run') args.dryRun = true;
    else if (arg === '--apply') args.apply = true;
    else if (arg === '--yes') args.yes = true;
    else if (arg === '--json') args.json = true;
  }
  if (!args.dryRun && !args.apply) args.dryRun = true;
  return args;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function isDirectory(filePath) {
  try { return fs.statSync(filePath).isDirectory(); } catch { return false; }
}

function isFile(filePath) {
  try { return fs.statSync(filePath).isFile(); } catch { return false; }
}

function walkFiles(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      const rel = normalizeRel(path.relative(root, abs));
      if (rel.split('/').includes('.git')) continue;
      if (rel.includes('.tmp-') || rel.includes('.bak-')) continue;
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) out.push({ abs, rel });
    }
  }
  walk(root);
  out.sort((a, b) => a.rel.localeCompare(b.rel));
  return out;
}

function resolveSourceRoot(fromArg) {
  if (!fromArg) throw new Error('Missing --from <new-knowledge-root>.');
  const candidate = path.resolve(process.cwd(), fromArg);
  const direct = path.join(candidate, 'tools', 'flow.js');
  const nested = path.join(candidate, '.knowledge', 'tools', 'flow.js');
  if (fs.existsSync(direct)) return candidate;
  if (fs.existsSync(nested)) return path.join(candidate, '.knowledge');
  throw new Error(`Cannot find a .knowledge root at ${candidate}. Expected tools/flow.js or .knowledge/tools/flow.js.`);
}

function planActions(sourceRoot) {
  const actions = [];
  for (const relPath of SYSTEM_PATHS) {
    const src = path.join(sourceRoot, relPath);
    const dst = path.join(knowledgeRoot, relPath);
    if (!fs.existsSync(src)) {
      actions.push({ action: 'skip', path: relPath, reason: 'source_missing' });
      continue;
    }
    if (isDirectory(src)) {
      const files = walkFiles(src);
      if (!fs.existsSync(dst)) actions.push({ action: 'create', path: relPath, kind: 'directory' });
      for (const file of files) {
        const dstFile = path.join(dst, file.rel);
        const relFile = normalizeRel(path.join(relPath, file.rel));
        if (!fs.existsSync(dstFile)) actions.push({ action: 'create', path: relFile, kind: 'file' });
        else if (!isFile(dstFile)) actions.push({ action: 'update', path: relFile, reason: 'replace_non_file' });
        else if (sha256(file.abs) !== sha256(dstFile)) actions.push({ action: 'update', path: relFile, kind: 'file' });
        else actions.push({ action: 'skip', path: relFile, reason: 'unchanged' });
      }
      continue;
    }
    if (isFile(src)) {
      if (!fs.existsSync(dst)) actions.push({ action: 'create', path: relPath, kind: 'file' });
      else if (!isFile(dst)) actions.push({ action: 'update', path: relPath, reason: 'replace_non_file' });
      else if (sha256(src) !== sha256(dst)) actions.push({ action: 'update', path: relPath, kind: 'file' });
      else actions.push({ action: 'skip', path: relPath, reason: 'unchanged' });
    }
  }

  for (const relPath of PROJECT_PATHS) {
    if (fs.existsSync(path.join(knowledgeRoot, relPath))) actions.push({ action: 'preserve', path: relPath, reason: 'project_specific' });
  }
  return actions;
}

function copyPath(src, dst) {
  if (isDirectory(src)) {
    ensureDir(dst);
    for (const file of walkFiles(src)) {
      const target = path.join(dst, file.rel);
      ensureDir(path.dirname(target));
      fs.copyFileSync(file.abs, target);
    }
    return;
  }
  ensureDir(path.dirname(dst));
  fs.copyFileSync(src, dst);
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function copyKnowledgeBackup() {
  const backupRoot = path.join(knowledgeRoot, 'maintenance', 'install-backups', `system-files-${timestamp()}`);
  function copyDir(src, dst) {
    ensureDir(dst);
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
      const from = path.join(src, entry.name);
      const rel = normalizeRel(path.relative(knowledgeRoot, from));
      if (rel.startsWith('.lock/') || rel.startsWith('.runtime/')) continue;
      if (rel.startsWith('maintenance/install-backups/')) continue;
      const to = path.join(dst, entry.name);
      if (entry.isDirectory()) copyDir(from, to);
      else if (entry.isFile()) {
        ensureDir(path.dirname(to));
        fs.copyFileSync(from, to);
      }
    }
  }
  copyDir(knowledgeRoot, backupRoot);
  return backupRoot;
}

function runNode(script, args) {
  const res = spawnSync(process.execPath, [path.join(knowledgeRoot, 'tools', script), ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    windowsHide: true
  });
  return {
    command: `node .knowledge/tools/${script}${args.length ? ' ' + args.join(' ') : ''}`,
    exit: res.status,
    stdout: (res.stdout || '').trim().slice(0, 12000),
    stderr: (res.stderr || '').trim().slice(0, 4000)
  };
}

function applyActions(sourceRoot, actions) {
  for (const action of actions) {
    if (!['create', 'update'].includes(action.action)) continue;
    const top = action.path.split('/')[0];
    if (!SYSTEM_PATHS.includes(top) && !SYSTEM_PATHS.includes(action.path)) {
      throw new Error(`Refusing to write non-system path: ${action.path}`);
    }
    copyPath(path.join(sourceRoot, action.path), path.join(knowledgeRoot, action.path));
  }
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const warnings = [];
  const errors = [];
  let sourceRoot = null;
  let actions = [];
  let backupPath = null;
  let postChecks = [];

  try {
    sourceRoot = resolveSourceRoot(args.from);
    actions = planActions(sourceRoot);
    if (args.apply && !args.yes) errors.push('Refusing --apply without --yes.');
    if (args.apply && args.yes && errors.length === 0) {
      backupPath = copyKnowledgeBackup();
      applyActions(sourceRoot, actions);
      postChecks = [
        runNode('install-check.js', ['--json']),
        runNode('doctor.js', []),
        runNode('flow.js', ['release', '--no-color'])
      ];
      for (const check of postChecks) {
        if (check.exit !== 0) errors.push(`${check.command} failed with exit ${check.exit}.`);
      }
    }
  } catch (error) {
    errors.push(error.message);
  }

  const report = {
    status: errors.length ? 'failed' : 'ok',
    mode: args.apply ? 'apply' : 'dry_run',
    source_root: sourceRoot,
    knowledge_root: knowledgeRoot,
    backup_path: backupPath,
    actions,
    summary: {
      create: actions.filter((a) => a.action === 'create').length,
      update: actions.filter((a) => a.action === 'update').length,
      skip: actions.filter((a) => a.action === 'skip').length,
      preserve: actions.filter((a) => a.action === 'preserve').length
    },
    warnings,
    errors,
    post_checks: postChecks
  };

  if (args.apply && args.yes) {
    const reportPath = path.join(knowledgeRoot, 'maintenance', 'update_system_files_report.json');
    writeJsonAtomic(reportPath, { ...report, generated_at: new Date().toISOString() });
    report.report = '.knowledge/maintenance/update_system_files_report.json';
  }

  console.log(JSON.stringify(report, null, 2));
  if (errors.length) process.exit(2);
}

if (require.main === module) main();

module.exports = { SYSTEM_PATHS, PROJECT_PATHS, planActions, resolveSourceRoot };
