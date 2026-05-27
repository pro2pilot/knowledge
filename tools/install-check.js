#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { ensureDir, writeJsonAtomic } = require('./lib/json-store');

const knowledgeRoot = path.resolve(__dirname, '..');
const repoRoot = path.basename(knowledgeRoot).toLowerCase() === '.knowledge' ? path.dirname(knowledgeRoot) : process.cwd();

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function rel(abs, base = repoRoot) {
  return normalizeRel(path.relative(base, abs));
}

function parseArgs(argv) {
  return {
    json: argv.includes('--json'),
    fix: argv.includes('--fix'),
    yes: argv.includes('--yes')
  };
}

function issue(issues, severity, code, message, artifact = null) {
  issues.push({ severity, code, message, artifact });
}

function compareNodeVersion(version) {
  const major = Number(String(version).replace(/^v/, '').split('.')[0]);
  return Number.isFinite(major) && major >= 18;
}

function commandExists(command, args, cwd) {
  const res = spawnSync(command, args, { cwd, encoding: 'utf8', windowsHide: true });
  return res.status === 0 ? (res.stdout || '').trim() : null;
}

function detectGitRoot() {
  return commandExists('git', ['rev-parse', '--show-toplevel'], repoRoot);
}

function isDirectory(filePath) {
  try { return fs.statSync(filePath).isDirectory(); } catch { return false; }
}

function moveDirectory(src, dst) {
  ensureDir(path.dirname(dst));
  try {
    fs.renameSync(src, dst);
    return;
  } catch (error) {
    if (error.code !== 'EXDEV') throw error;
  }
  copyDirectory(src, dst);
  fs.rmSync(src, { recursive: true, force: true });
}

function copyDirectory(src, dst) {
  ensureDir(dst);
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const from = path.join(src, entry.name);
    const to = path.join(dst, entry.name);
    if (entry.isDirectory()) copyDirectory(from, to);
    else if (entry.isFile()) {
      ensureDir(path.dirname(to));
      fs.copyFileSync(from, to);
    }
  }
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function analyze(options = {}) {
  const issues = [];
  const fixesAvailable = [];
  const fixesApplied = [];
  const nextCommands = [];

  const requiredSystemFiles = [
    'Quick-Start.md',
    'README.md',
    'tools/flow.js',
    'tools/install-agent-integrations.js',
    'tools/doctor.js',
    'tools/lib/json-store.js'
  ];

  if (!compareNodeVersion(process.version)) {
    issue(issues, 'error', 'node_version_unsupported', `Node.js ${process.version} is unsupported. Use Node.js >=18.`, null);
  }

  if (path.basename(knowledgeRoot).toLowerCase() !== '.knowledge') {
    issue(issues, 'warning', 'non_repo_local_layout', `This tool is running from ${knowledgeRoot}; installed repo-local mode expects a .knowledge directory.`, rel(knowledgeRoot));
  }

  const gitRoot = detectGitRoot();
  if (gitRoot && path.resolve(gitRoot) !== path.resolve(repoRoot)) {
    issue(issues, 'warning', 'git_root_mismatch', `Git root is ${gitRoot}, expected ${repoRoot}.`, null);
  }

  const nestedGit = path.join(knowledgeRoot, '.git');
  if (isDirectory(nestedGit)) {
    issue(issues, 'error', 'nested_knowledge_git', 'Nested .knowledge/.git detected. Install from the release artifact, not by copying the source checkout.', '.knowledge/.git');
    fixesAvailable.push({ code: 'move_nested_git', command: 'node .knowledge/tools/install-check.js --fix --yes' });
  }

  const nestedGithub = path.join(knowledgeRoot, '.github');
  if (isDirectory(nestedGithub)) {
    issue(issues, 'error', 'source_repo_copied_into_knowledge', 'A source .github directory exists inside .knowledge. This usually means the whole source repo was copied instead of the release artifact.', '.knowledge/.github');
  }

  for (const required of requiredSystemFiles) {
    if (!fs.existsSync(path.join(knowledgeRoot, required))) {
      issue(issues, 'error', 'missing_system_file', `Missing required system file: ${required}`, `.knowledge/${required}`);
    }
  }

  if (!fs.existsSync(path.join(knowledgeRoot, 'maintenance', 'routing_bundle.json'))) {
    issue(issues, 'info', 'fresh_runtime_missing', 'maintenance/routing_bundle.json is absent. This is normal before first flow import.', '.knowledge/maintenance/routing_bundle.json');
  }

  if (!fs.existsSync(path.join(knowledgeRoot, '.gitignore'))) {
    issue(issues, 'warning', 'knowledge_gitignore_missing', 'Missing .knowledge/.gitignore. Runtime artifacts may appear in git status.', '.knowledge/.gitignore');
  }

  if (!fs.existsSync(path.join(repoRoot, '.gitattributes'))) {
    issue(issues, 'info', 'root_gitattributes_optional', 'Root .gitattributes is optional. See .knowledge/templates/git-policy/gitattributes.snippet for recommendations.', '.gitattributes');
  }

  const hasErrors = issues.some((item) => item.severity === 'error');
  const hasWarnings = issues.some((item) => item.severity === 'warning');
  const routingExists = fs.existsSync(path.join(knowledgeRoot, 'maintenance', 'routing_bundle.json'));
  const systemFilesOk = requiredSystemFiles.every((file) => fs.existsSync(path.join(knowledgeRoot, file)));
  const mode = hasErrors ? 'broken' : (!systemFilesOk ? 'broken' : (routingExists ? 'configured' : 'fresh'));
  const status = hasErrors ? 'failed' : (hasWarnings ? 'warning' : 'ok');

  if (mode === 'fresh') {
    nextCommands.push('node .knowledge/tools/install-agent-integrations.js');
    nextCommands.push('node .knowledge/tools/flow.js import');
  } else if (mode === 'configured') {
    nextCommands.push('node .knowledge/tools/flow.js release --no-color');
  }
  if (fixesAvailable.length && !fixesApplied.length) nextCommands.unshift('node .knowledge/tools/install-check.js --fix --yes');

  return {
    status,
    mode,
    repo_root: repoRoot,
    knowledge_root: knowledgeRoot,
    issues,
    fixes_available: fixesAvailable,
    fixes_applied: fixesApplied,
    next_commands: nextCommands
  };
}

function applyFixes() {
  const fixesApplied = [];
  const nestedGit = path.join(knowledgeRoot, '.git');
  if (isDirectory(nestedGit)) {
    const backupDir = path.join(knowledgeRoot, 'maintenance', 'install-backups', `nested-git-${timestamp()}`);
    moveDirectory(nestedGit, backupDir);
    fixesApplied.push({ code: 'move_nested_git', from: '.knowledge/.git', to: `.knowledge/${rel(backupDir, knowledgeRoot)}` });
  }
  return fixesApplied;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  let result = analyze();
  if (options.fix && !options.yes) {
    result = {
      ...result,
      status: 'failed',
      mode: 'broken',
      issues: [
        ...result.issues,
        { severity: 'error', code: 'fix_requires_yes', message: 'Refusing to apply fixes without --yes.', artifact: null }
      ]
    };
  } else if (options.fix && options.yes) {
    const preFix = analyze();
    const fixesApplied = applyFixes();
    const postFix = analyze();
    const reportPath = path.join(knowledgeRoot, 'maintenance', 'install_check_report.json');
    result = {
      ...postFix,
      fixes_applied: fixesApplied,
      pre_fix: preFix,
      post_fix: postFix,
      report: '.knowledge/maintenance/install_check_report.json',
      generated_at: new Date().toISOString()
    };
    ensureDir(path.dirname(reportPath));
    writeJsonAtomic(reportPath, result);
  }
  console.log(JSON.stringify(result, null, 2));
  if (result.status === 'failed') process.exit(2);
}

if (require.main === module) main();

module.exports = { analyze };
