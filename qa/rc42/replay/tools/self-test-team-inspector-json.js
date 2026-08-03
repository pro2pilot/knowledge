#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync, spawn } = require('child_process');
let packageShouldExclude = null;
try {
  packageShouldExclude = require('./package-release').shouldExclude;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

const sourceKnowledgeRoot = path.resolve(__dirname, '..');
const packageVersion = JSON.parse(fs.readFileSync(path.join(sourceKnowledgeRoot, 'package.json'), 'utf8')).version || '3.3.0';
const keepTemp = process.argv.includes('--keep-temp');
let rootForCleanup = null;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isolatedChildEnv(overrides = {}) {
  const env = { ...process.env };
  const controlledKeys = new Set([
    'KNOWLEDGE_MODE',
    'KNOWLEDGE_SYSTEM_ROOT',
    'KNOWLEDGE_TARGET_ROOT',
    'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT',
    'KNOWLEDGE_STATE_ROOT',
    'KNOWLEDGE_AGENT_ID',
    'KNOWLEDGE_DISABLE_GIT_DISCOVERY',
    'KNOWLEDGE_FLOW_NO_OPEN',
    'KNOWLEDGE_INSPECTOR_NO_OPEN',
    'KNOWLEDGE_TEAM_ROOT',
    'KNOWLEDGE_WORKSPACE_ID',
    'KNOWLEDGE_REPO_ID'
  ]);
  for (const key of Object.keys(env)) {
    if (controlledKeys.has(key.toUpperCase())) delete env[key];
  }
  return {
    ...env,
    KNOWLEDGE_FLOW_NO_OPEN: '1',
    KNOWLEDGE_INSPECTOR_NO_OPEN: '1',
    ...overrides
  };
}

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    cwd: options.cwd,
    env: isolatedChildEnv(options.env || {}),
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 120000
  });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    command: `${cmd} ${args.join(' ')}`
  };
}

function must(cmd, args, options = {}) {
  const result = run(cmd, args, options);
  if (!result.ok) throw new Error(`${result.command}\n${result.stderr || result.stdout}`);
  return result;
}

function parseJson(result, label) {
  try { return JSON.parse(result.stdout); }
  catch (error) { throw new Error(`${label || result.command} did not emit valid JSON: ${error.message}\n${result.stdout}\n${result.stderr}`); }
}

function nodeTool(root, rel, args, options = {}) {
  return must(process.execPath, [path.join(root, '.knowledge', 'tools', rel), ...args], options);
}

function shouldExcludeFromInstalledFixture(rel, entry) {
  if (packageShouldExclude) return packageShouldExclude(rel, entry).exclude;
  const segments = rel.split('/');
  if (rel === '.gitignore' || rel === 'project_index.json' || rel === 'freshness.json') return true;
  if (['.git', '.github', '.qa-tmp', '.self-test-tmp', 'benchmark-runs', 'dist', 'exports', 'inspector', 'modules', 'node_modules', 'pro', 'search'].includes(segments[0])) return true;
  if (segments.includes('.lock') || segments.includes('.runtime')) return true;
  if (rel.startsWith('maintenance/') && !['maintenance/concurrency_policy.json', 'maintenance/restore-trust-report.md'].includes(rel)) return true;
  if (rel.startsWith('maps/') && rel !== 'maps/critical_paths.json') return true;
  if (rel === 'sessions/active_task.json' || rel.startsWith('sessions/active_tasks/')) return true;
  if (/^metrics\/(baseline|external_memory)\.json$/i.test(rel)) return true;
  if (/^external_memory\/(mem0|legacy|claude_mem|claude|claude-auto-memory)(\/|$)/i.test(rel)) return true;
  return /\.tmp-|\.bak-|\.zip$|\.log$|\.cache$/i.test(rel);
}

function copyInstalledKnowledge(targetRoot) {
  const dest = path.join(targetRoot, '.knowledge');
  fs.cpSync(sourceKnowledgeRoot, dest, {
    recursive: true,
    force: true,
    filter: (src) => {
      const rel = path.relative(sourceKnowledgeRoot, src).replace(/\\/g, '/');
      if (!rel) return true;
      let entry;
      try { entry = fs.statSync(src); } catch { return false; }
      return !shouldExcludeFromInstalledFixture(rel, entry);
    }
  });
  fs.copyFileSync(
    path.join(sourceKnowledgeRoot, 'templates', 'git-policy', '.knowledge.gitignore'),
    path.join(dest, '.gitignore')
  );
}

function spawnNode(script, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: options.cwd,
      env: isolatedChildEnv(options.env || {}),
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('close', (code) => resolve({ code, stdout, stderr, script, args }));
  });
}

function walkFiles(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walkFiles(abs, out);
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function parseJsonAndNdjson(root) {
  const errors = [];
  let jsonFiles = 0;
  let ndjsonFiles = 0;
  for (const file of walkFiles(root)) {
    if (file.endsWith('.json')) {
      jsonFiles += 1;
      try { JSON.parse(fs.readFileSync(file, 'utf8')); }
      catch (error) { errors.push({ file, error: error.message }); }
    } else if (file.endsWith('.ndjson')) {
      ndjsonFiles += 1;
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
      for (let i = 0; i < lines.length; i += 1) {
        try { JSON.parse(lines[i]); }
        catch (error) { errors.push({ file, line: i + 1, error: error.message }); }
      }
    }
  }
  return { jsonFiles, ndjsonFiles, errors };
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge team inspector json С‚РµСЃС‚ '));
  rootForCleanup = root;
  const repo = path.join(root, 'repo main with spaces');
  const worktrees = path.join(root, 'worktrees');
  const teamRoot = path.join(root, '.knowledge-team shared');
  fs.mkdirSync(repo, { recursive: true });
  fs.mkdirSync(worktrees, { recursive: true });

  must('git', ['init', '-b', 'main'], { cwd: repo });
  must('git', ['config', 'user.email', 'knowledge-test@example.invalid'], { cwd: repo });
  must('git', ['config', 'user.name', 'Knowledge Test'], { cwd: repo });
  fs.writeFileSync(path.join(repo, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n', 'utf8');
  fs.writeFileSync(path.join(repo, 'index.js'), 'module.exports = 1;\n', 'utf8');
  copyInstalledKnowledge(repo);
  const importFlow = parseJson(nodeTool(repo, 'flow.js', ['import', '--json', '--no-color'], {
    cwd: repo,
    env: { KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_AGENT_ID: 'team-inspector-self-test-import' }
  }), 'flow import');
  assert(importFlow.status === 'ok', `fresh installed fixture import failed: ${JSON.stringify(importFlow)}`);
  assert(fs.existsSync(path.join(repo, '.knowledge', 'project_index.json')), 'fresh installed fixture import did not create project_index.json');
  must('git', ['add', 'package.json', 'index.js'], { cwd: repo });
  must('git', ['add', '-f', '.knowledge'], { cwd: repo });
  must('git', ['commit', '-m', 'initial fixture'], { cwd: repo });

  const w1 = path.join(worktrees, 'codex task 1');
  const w2 = path.join(worktrees, 'claude Р·Р°РґР°С‡Р° 2');
  const w3 = path.join(worktrees, 'opencode task 3');
  must('git', ['worktree', 'add', w1, '-b', 'bot/codex-task-1'], { cwd: repo });
  must('git', ['worktree', 'add', w2, '-b', 'bot/claude-task-2'], { cwd: repo });
  must('git', ['worktree', 'add', w3, '-b', 'bot/opencode-task-3'], { cwd: repo });

  const init = parseJson(nodeTool(repo, 'team-init.js', ['--team-root', teamRoot, '--target-root', repo, '--json'], { cwd: repo }), 'team-init');
  assert(init.ok, 'team-init failed');

  const reg1 = parseJson(nodeTool(w1, 'workspace-register.js', ['--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1 }), 'register 1');
  const reg2 = parseJson(nodeTool(w2, 'workspace-register.js', ['--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'claude-task-2', '--agent-id', 'claude-02', '--json'], { cwd: w2 }), 'register 2');
  const reg3 = parseJson(nodeTool(w3, 'workspace-register.js', ['--team-root', teamRoot, '--target-root', w3, '--workspace-id', 'opencode-task-3', '--agent-id', 'opencode-03', '--json'], { cwd: w3 }), 'register 3');
  assert(new Set([reg1.workspace.stateRoot, reg2.workspace.stateRoot, reg3.workspace.stateRoot]).size === 3, 'workspace state roots must be isolated');

  fs.mkdirSync(path.join(reg1.workspace.stateRoot, 'maintenance'), { recursive: true });
  fs.writeFileSync(path.join(reg1.workspace.stateRoot, 'maintenance', 'windows-path-snippet.json'), JSON.stringify({
    snippet: 'C:\\\\fixture path\\\\with spaces\\\\quoted.json',
    cyrillic: 'РєРёСЂРёР»Р»РёС†Р° survives JSON serialization'
  }, null, 2), 'utf8');

  const doctor = spawnNode(path.join(w1, '.knowledge', 'tools', 'flow.js'), ['doctor', '--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1 });
  const release = spawnNode(path.join(w2, '.knowledge', 'tools', 'flow.js'), ['release', '--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'claude-task-2', '--agent-id', 'claude-02', '--exclusive', '--json'], { cwd: w2 });
  const prSummary = spawnNode(path.join(w3, '.knowledge', 'tools', 'team-pr-summary.js'), ['--team-root', teamRoot, '--workspace-id', 'opencode-task-3', '--json'], { cwd: w3 });
  const parallel = await Promise.all([doctor, release, prSummary]);
  for (const item of parallel) assert(item.code === 0, `parallel command failed: ${item.script}\n${item.stderr || item.stdout}`);

  const repoInspector = parseJson(nodeTool(repo, 'build-visual-inspector.js', ['--json'], { cwd: repo }), 'repo inspector');
  assert(repoInspector.mode === 'repo', 'repo-local Inspector regression failed');
  const teamInspector = parseJson(nodeTool(w1, 'build-visual-inspector.js', ['--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1 }), 'team inspector');
  assert(teamInspector.mode === 'team', 'team Inspector did not report team mode');

  const status = parseJson(nodeTool(repo, 'team-status.js', ['--team-root', teamRoot, '--json'], { cwd: repo }), 'team status');
  assert(status.workspaces_total >= 3, 'team-status did not include all workspaces');
  assert(!fs.existsSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'locks', 'flow.lock')), 'flow lock was not released');
  assert(fs.existsSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'events')), 'events directory missing');

  const parsed = parseJsonAndNdjson(teamRoot);
  assert(parsed.errors.length === 0, `JSON/NDJSON corruption detected: ${JSON.stringify(parsed.errors.slice(0, 5))}`);

  const inspectorDataFiles = walkFiles(teamRoot).filter((file) => file.endsWith(path.join('inspector', 'data.json')));
  assert(inspectorDataFiles.length >= 1, 'team Inspector data.json missing');
  for (const file of inspectorDataFiles) JSON.parse(fs.readFileSync(file, 'utf8'));

  const result = {
    schema_version: packageVersion,
    status: 'pass',
    temp_root: keepTemp ? root : null,
    temp_root_cleaned: !keepTemp,
    metrics: {
      workspaces: status.workspaces_total,
      json_files_parsed: parsed.jsonFiles,
      ndjson_files_parsed: parsed.ndjsonFiles,
      json_corruption_count: parsed.errors.length,
      locks_released: true,
      events_written: true,
      workspace_states_isolated: true,
      repo_local_regression_pass: true
    },
    checks: [
      'temp git repo',
      'fresh installed fixture import',
      'three worktrees',
      'team-init and workspace-register',
      'parallel flow doctor / release --exclusive / team-pr-summary',
      'repo and team Inspector builds',
      'every JSON and NDJSON under teamRoot parses',
      'generated Inspector data JSON parses',
      'paths with spaces and Cyrillic',
      'Windows-style path snippet inside JSON string',
      'locks released',
      'events written',
      'workspace states isolated',
      'team-status accurate',
      'repo-local regression pass'
    ]
  };
  if (!keepTemp) fs.rmSync(root, { recursive: true, force: true });
  console.log(JSON.stringify(result, null, 2));
}

process.on('exit', () => {
  if (!keepTemp && rootForCleanup && fs.existsSync(rootForCleanup)) {
    try { fs.rmSync(rootForCleanup, { recursive: true, force: true }); } catch {}
  }
});

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
