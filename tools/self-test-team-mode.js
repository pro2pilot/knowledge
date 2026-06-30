#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync, spawn } = require('child_process');

const sourceKnowledgeRoot = path.resolve(__dirname, '..');
const keepTemp = process.argv.includes('--keep-temp');
let rootForCleanup = null;

process.on('exit', () => {
  if (!keepTemp && rootForCleanup && fs.existsSync(rootForCleanup)) {
    try { fs.rmSync(rootForCleanup, { recursive: true, force: true }); } catch {}
  }
});

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    cwd: options.cwd,
    env: { ...process.env, ...(options.env || {}) },
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
  if (!result.ok) {
    throw new Error(`${result.command}\n${result.stderr || result.stdout}`);
  }
  return result;
}

function nodeTool(root, rel, args, options = {}) {
  return must(process.execPath, [path.join(root, '.knowledge', 'tools', rel), ...args], options);
}

function parseJson(result) {
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`Invalid JSON from ${result.command}: ${error.message}\n${result.stdout}\n${result.stderr}`);
  }
}

function copyKnowledge(targetRoot) {
  const dest = path.join(targetRoot, '.knowledge');
  fs.cpSync(sourceKnowledgeRoot, dest, {
    recursive: true,
    force: true,
    filter: (src) => {
      const rel = path.relative(sourceKnowledgeRoot, src).replace(/\\/g, '/');
      return rel !== '.git' &&
        !rel.startsWith('.git/') &&
        !rel.startsWith('dist/') &&
        !rel.startsWith('node_modules/') &&
        !rel.startsWith('.qa-tmp/') &&
        !rel.startsWith('.self-test-tmp/') &&
        !rel.startsWith('.lock') &&
        !rel.includes('/.lock/') &&
        !rel.includes('.tmp-');
    }
  });
}

function walkJson(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walkJson(abs, out);
    else if (entry.isFile() && entry.name.endsWith('.json')) out.push(abs);
  }
  return out;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertFails(result, message) {
  if (result.ok) throw new Error(message);
}

function spawnNode(script, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd: options.cwd,
      env: { ...process.env, ...(options.env || {}) },
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

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge team тест '));
  rootForCleanup = root;
  const repo = path.join(root, 'repo main');
  const worktrees = path.join(root, 'worktrees');
  const teamRoot = path.join(root, '.knowledge-team shared');
  const sharedMemory = path.join(root, 'shared claude memory');
  fs.mkdirSync(repo, { recursive: true });
  fs.mkdirSync(worktrees, { recursive: true });
  fs.mkdirSync(sharedMemory, { recursive: true });

  must('git', ['init', '-b', 'main'], { cwd: repo });
  must('git', ['config', 'user.email', 'knowledge-test@example.com'], { cwd: repo });
  must('git', ['config', 'user.name', 'Knowledge Test'], { cwd: repo });
  fs.writeFileSync(path.join(repo, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n', 'utf8');
  fs.writeFileSync(path.join(repo, 'index.js'), 'module.exports = 1;\n', 'utf8');
  copyKnowledge(repo);
  must('git', ['add', 'package.json', 'index.js'], { cwd: repo });
  must('git', ['add', '-f', '.knowledge'], { cwd: repo });
  must('git', ['commit', '-m', 'initial fixture'], { cwd: repo });

  const w1 = path.join(worktrees, 'codex task 1');
  const w2 = path.join(worktrees, 'claude задача 2');
  must('git', ['worktree', 'add', w1, '-b', 'bot/codex-task-1'], { cwd: repo });
  must('git', ['worktree', 'add', w2, '-b', 'bot/claude-task-2'], { cwd: repo });

  const init = parseJson(nodeTool(repo, 'team-init.js', ['--team-root', teamRoot, '--target-root', repo, '--json'], { cwd: repo }));
  assert(init.ok, 'team-init failed');

  assertFails(run(process.execPath, [path.join(w1, '.knowledge', 'tools', 'workspace-register.js'), '--target-root', w1, '--workspace-id', 'missing-team', '--agent-id', 'codex-01', '--json'], { cwd: w1 }), 'workspace-register should fail without teamRoot');
  assertFails(run(process.execPath, [path.join(w1, '.knowledge', 'tools', 'workspace-register.js'), '--team-root', teamRoot, '--target-root', w1, '--agent-id', 'codex-01', '--json'], { cwd: w1 }), 'workspace-register should fail without workspaceId');

  const reg1 = parseJson(nodeTool(w1, 'workspace-register.js', ['--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1 }));
  const reg2 = parseJson(nodeTool(w2, 'workspace-register.js', ['--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'claude-task-2', '--agent-id', 'claude-01', '--json'], { cwd: w2 }));
  assert(reg1.workspace.stateRoot !== reg2.workspace.stateRoot, 'workspace states must be separated');
  assertFails(run(process.execPath, [path.join(w1, '.knowledge', 'tools', 'workspace-register.js'), '--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1 }), 'duplicate workspaceId with different targetRoot should fail');
  const duplicateAgent = parseJson(nodeTool(w2, 'workspace-register.js', ['--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'claude-duplicate-agent', '--agent-id', 'claude-01', '--json'], { cwd: w2 }));
  assert((duplicateAgent.workspace.warnings || []).some((warning) => /agentId duplicate/i.test(warning)), 'duplicate agentId warning missing');

  const staleLockPath = path.join(teamRoot, 'repos', reg1.context.repoId, 'locks', 'flow.lock');
  fs.mkdirSync(path.dirname(staleLockPath), { recursive: true });
  fs.writeFileSync(staleLockPath, JSON.stringify({ pid: 99999999, agentId: 'stale', started_at: '2000-01-01T00:00:00.000Z' }, null, 2), 'utf8');

  const flow1 = spawnNode(path.join(w1, '.knowledge', 'tools', 'flow.js'), ['doctor', '--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1, env: { CLAUDE_MEMORY_PATH: sharedMemory } });
  const flow2 = spawnNode(path.join(w2, '.knowledge', 'tools', 'flow.js'), ['release', '--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'claude-task-2', '--agent-id', 'claude-01', '--exclusive', '--json'], { cwd: w2, env: { CLAUDE_MEMORY_PATH: sharedMemory } });
  const [r1, r2] = await Promise.all([flow1, flow2]);
  assert(r1.code === 0, `doctor flow failed\n${r1.stderr}\n${r1.stdout}`);
  assert(r2.code === 0, `release flow failed\n${r2.stderr}\n${r2.stdout}`);

  for (const file of walkJson(teamRoot)) JSON.parse(fs.readFileSync(file, 'utf8'));
  assert(!fs.existsSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'locks', 'flow.lock')), 'flow lock was not released');
  assert(fs.existsSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'events')), 'events directory missing');
  const eventText = fs.readdirSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'events')).map((name) => fs.readFileSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'events', name), 'utf8')).join('\n');
  assert(/lock_timeout/.test(eventText), 'stale lock event missing');
  assert(/doctor_result/.test(eventText), 'doctor_result event missing');
  assert(/external_memory_status_changed/.test(eventText), 'external_memory_status_changed event missing');
  assert(fs.existsSync(path.join(reg1.workspace.stateRoot, 'maintenance', 'routing_bundle.json')), 'workspace 1 routing bundle missing');
  assert(fs.existsSync(path.join(reg2.workspace.stateRoot, 'maintenance', 'routing_bundle.json')), 'workspace 2 routing bundle missing');

  const status = parseJson(nodeTool(repo, 'team-status.js', ['--team-root', teamRoot, '--json'], { cwd: repo }));
  assert(status.workspaces_total >= 2, 'team-status did not see both workspaces');
  const staleWsFile = path.join(teamRoot, 'repos', reg1.context.repoId, 'workspaces', 'claude-duplicate-agent', 'workspace.json');
  const staleWs = JSON.parse(fs.readFileSync(staleWsFile, 'utf8'));
  staleWs.updated_at = '2000-01-01T00:00:00.000Z';
  fs.writeFileSync(staleWsFile, JSON.stringify(staleWs, null, 2) + '\n', 'utf8');
  const staleStatus = parseJson(nodeTool(repo, 'team-status.js', ['--team-root', teamRoot, '--json'], { cwd: repo }));
  assert((staleStatus.stale_workspaces || []).some((ws) => ws.workspaceId === 'claude-duplicate-agent'), 'stale workspace warning missing');

  fs.writeFileSync(path.join(w1, 'dirty.js'), 'module.exports = 2;\n', 'utf8');
  fs.mkdirSync(path.join(w1, '.knowledge', 'maintenance'), { recursive: true });
  fs.writeFileSync(path.join(w1, '.knowledge', 'maintenance', 'pr_summary.md'), 'generated\n', 'utf8');
  must('git', ['add', '-f', '.knowledge/maintenance/pr_summary.md'], { cwd: w1 });
  const wt = parseJson(nodeTool(w1, 'worktree-status.js', ['--target-root', w1, '--team-root', teamRoot, '--workspace-id', 'codex-task-1', '--json'], { cwd: w1 }));
  assert(wt.warnings.includes('dirty workspace'), 'dirty workspace warning missing');
  assert(wt.warnings.includes('generated runtime files are staged for commit'), 'staged runtime warning missing');
  const wsFile = path.join(teamRoot, 'repos', reg1.context.repoId, 'workspaces', 'codex-task-1', 'workspace.json');
  const wsJson = JSON.parse(fs.readFileSync(wsFile, 'utf8'));
  wsJson.branch = 'bot/wrong-branch';
  fs.writeFileSync(wsFile, JSON.stringify(wsJson, null, 2) + '\n', 'utf8');
  const mismatch = parseJson(nodeTool(w1, 'worktree-status.js', ['--target-root', w1, '--team-root', teamRoot, '--workspace-id', 'codex-task-1', '--json'], { cwd: w1 }));
  assert(mismatch.warnings.includes('workspace branch mismatch'), 'branch mismatch warning missing');

  const missingTarget = parseJson(nodeTool(w1, 'worktree-status.js', ['--target-root', path.join(root, 'missing target'), '--json'], { cwd: w1 }));
  assert((missingTarget.warnings || []).includes('targetRoot does not exist'), 'missing targetRoot warning missing');

  const ext = parseJson(nodeTool(w1, 'external-memory-status.js', ['--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1, env: { CLAUDE_MEMORY_PATH: sharedMemory } }));
  assert((ext.warnings || []).some((warning) => /shared/i.test(warning)), 'shared external memory warning missing');

  parseJson(nodeTool(repo, 'build-visual-inspector.js', ['--json'], { cwd: repo }));
  parseJson(nodeTool(w1, 'build-visual-inspector.js', ['--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1 }));

  const unreg = parseJson(nodeTool(repo, 'workspace-unregister.js', ['--team-root', teamRoot, '--workspace-id', 'codex-task-1', '--json'], { cwd: repo }));
  assert(unreg.workspace.status === 'archived', 'workspace unregister did not archive');

  const result = {
    schema_version: '3.2.3',
    status: 'pass',
    temp_root: keepTemp ? root : null,
    temp_root_cleaned: !keepTemp,
    team_root: teamRoot,
    checks: [
      'temp git repo with spaces and Cyrillic path',
      'two worktrees',
      'team-init',
      'workspace-register for two agents',
      'missing teamRoot and missing workspaceId failures',
      'duplicate workspaceId failure',
      'duplicate agentId warning',
      'parallel doctor/release exclusive flows',
      'stale lock cleanup',
      'JSON corruption scan',
      'lock released',
      'events written',
      'doctor/external memory/worktree events written',
      'workspace states separated',
      'team-status sees both workspaces',
      'team-status reports stale workspaces',
      'branch/head detected',
      'branch mismatch warning',
      'missing targetRoot warning',
      'dirty workspace warning',
      'staged generated runtime warning',
      'shared external memory warning',
      'inspector builds in repo and team modes',
      'workspace archive'
    ]
  };
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error.message);
    process.exit(1);
  });
}

module.exports = main;
