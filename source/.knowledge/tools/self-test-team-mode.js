#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync, spawn } = require('child_process');
const { systemVersion } = require('./lib/system-version');
const { canonicalOwnerText } = require('./lib/lock-owner-schema');
const { LOCKS } = require('./lib/lock-policy');
const { assertSafeContainedFile } = require('./lib/json-store');
let packageShouldExclude = null;
try {
  packageShouldExclude = require('./package-release').shouldExclude;
} catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND') throw error;
}

const sourceKnowledgeRoot = path.resolve(__dirname, '..');
const keepTemp = process.argv.includes('--keep-temp');
let rootForCleanup = null;
const selftestStarted = process.hrtime.bigint();
let nextChildPhase = 0;
function childPhase(event, id, name, details = {}) {
  // Bounded diagnostics only; native receipts remain the cleanup authority.
  fs.writeSync(2, JSON.stringify({ schema_version: 'knowledge-team-selftest-phase.v1',
    event, id, name, elapsed_ms: Number(process.hrtime.bigint() - selftestStarted) / 1e6, ...details }) + '\n');
}

process.on('exit', () => {
  if (!keepTemp && rootForCleanup && fs.existsSync(rootForCleanup)) {
    try { fs.rmSync(rootForCleanup, { recursive: true, force: true }); } catch {}
  }
});

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
  const started = Date.now(), id = ++nextChildPhase;
  const name = path.basename(cmd) + ' ' + path.basename(args[0] || '');
  childPhase('begin', id, name);
  const result = spawnSync(cmd, args, {
    cwd: options.cwd,
    env: isolatedChildEnv(options.env || {}),
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 120000
  });
  childPhase('exit', id, name, { exit_code: result.status, error: result.error?.code || null });
  return {
    ok: result.status === 0 && !result.error && !result.signal,
    status: result.status,
    error: result.error ? { code: result.error.code || null, message: result.error.message } : null,
    signal: result.signal || null,
    pid: Number.isInteger(result.pid) ? result.pid : null,
    argv: [cmd, ...args],
    cwd: options.cwd || process.cwd(),
    started_at: new Date(started).toISOString(),
    duration_ms: Date.now() - started,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    command: `${cmd} ${args.join(' ')}`
  };
}

function physicalFileState(file) {
  try {
    const stat = fs.lstatSync(file);
    return { path: file, exists: true, regular_file: stat.isFile(), bytes: stat.size,
      sha256: stat.isFile() ? crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') : null };
  } catch (error) {
    return { path: file, exists: error.code === 'ENOENT' ? false : null, error: error.code || error.message };
  }
}

function containedPath(root, candidate) {
  if (!root || !candidate || !path.isAbsolute(root) || !path.isAbsolute(candidate)) return false;
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function preserveExclusiveFailure(result, observations, flowLogPath, failure) {
  // Keep failure artifacts outside the fixture removed by the default exit
  // handler. A passing diagnostic must never overwrite an earlier failure.
  const base = process.env.KNOWLEDGE_TEAM_MODE_FAILURE_DIR || path.join(os.tmpdir(), 'knowledge-team-mode-failure-evidence');
  fs.mkdirSync(base, { recursive: true });
  const directory = fs.mkdtempSync(path.join(base, 'exclusive-doctor-'));
  let flowSummary = null;
  let resolvedFlowLogPath = null;
  let expectedStateRoot = null;
  if (result?.stdout) {
    try {
      flowSummary = JSON.parse(String(result.stdout).trim().replace(/^\uFEFF/, ''));
      if (typeof flowSummary.flow_log === 'string' && flowSummary.flow_log) {
        expectedStateRoot = observations?.state_root || flowSummary.state_root || null;
        const candidate = path.isAbsolute(flowSummary.flow_log)
          ? flowSummary.flow_log
          : path.resolve(flowSummary.target_root || result.cwd || process.cwd(), flowSummary.flow_log);
        const expectedDirectory = path.resolve(expectedStateRoot || '', 'maintenance', 'flow-logs');
        const stateRootMatchesObservation = !observations?.state_root ||
          path.resolve(flowSummary.state_root || '') === path.resolve(observations.state_root);
        if (
          stateRootMatchesObservation && rootForCleanup && containedPath(rootForCleanup, expectedStateRoot) &&
          containedPath(rootForCleanup, candidate) && containedPath(expectedDirectory, candidate) &&
          path.dirname(path.resolve(candidate)) === expectedDirectory &&
          path.extname(candidate).toLowerCase() === '.json'
        ) {
          const validatedCandidate = path.resolve(candidate);
          if (!flowLogPath || path.resolve(flowLogPath) === validatedCandidate) {
            resolvedFlowLogPath = validatedCandidate;
          }
        }
      }
    } catch {}
  }
  const captured = {
    failure,
    observations,
    command: result ? { ...result } : null,
    flow_context: flowSummary ? {
      mode: flowSummary.mode || null,
      target_root: flowSummary.target_root || null,
      project_knowledge_root: flowSummary.project_knowledge_root || null,
      state_root: flowSummary.state_root || null,
      team_root: observations?.team_root || null,
      repo_id: flowSummary.repo_id || null,
      workspace_id: flowSummary.workspace_id || null,
      agent_id: flowSummary.agent_id || null
    } : null,
    child_identity: result ? {
      pid: Number.isInteger(result.pid) ? result.pid : null,
      executable: process.execPath,
      executable_sha256: crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'),
      node_version: process.version,
      platform: process.platform,
      arch: process.arch
    } : null,
    original_flow_log: resolvedFlowLogPath,
    flow_log_capture: resolvedFlowLogPath ? 'pending' : flowSummary?.flow_log ? 'rejected_uncontained_or_unexpected_path' : 'unavailable'
  };
  for (const stream of ['stdout', 'stderr']) {
    const bytes = Buffer.from(result?.[stream] || '', 'utf8');
    const output = path.join(directory, `${stream}.log`);
    fs.writeFileSync(output, bytes);
    if (captured.command) captured.command[stream] = { path: output, bytes: bytes.length,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  }
  if (resolvedFlowLogPath && fs.existsSync(resolvedFlowLogPath)) {
    const output = path.join(directory, 'doctor-flow-log.json');
    try {
      assertSafeContainedFile(rootForCleanup, resolvedFlowLogPath, { allowMissing: false });
      fs.copyFileSync(resolvedFlowLogPath, output);
      captured.flow_log = physicalFileState(output);
      captured.flow_log_capture = 'copied';
    } catch (error) {
      captured.flow_log_capture = `rejected:${error.code || error.message}`;
    }
  }
  fs.writeFileSync(path.join(directory, 'failure.json'), `${JSON.stringify(captured, null, 2)}\n`);
  return directory;
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

function checkExclusiveFailureCapture(root) {
  const evidenceRoot = path.join(root, 'failure-capture-evidence');
  const stateRoot = path.join(root, 'failure-capture-state');
  const logDirectory = path.join(stateRoot, 'maintenance', 'flow-logs');
  const logPath = path.join(logDirectory, 'doctor-capture-test.json');
  fs.mkdirSync(logDirectory, { recursive: true });
  fs.writeFileSync(logPath, '{"flow":"doctor","steps":[]}\n', 'utf8');
  const summary = {
    flow: 'doctor', status: 'failed', flow_log: logPath,
    target_root: path.join(root, 'target'),
    project_knowledge_root: path.join(root, 'target', '.knowledge'),
    state_root: stateRoot, mode: 'team', repo_id: 'fixture-repo',
    workspace_id: 'fixture-workspace', agent_id: 'fixture-agent'
  };
  const capture = (flowSummary, observedStateRoot, name) => {
    const capturedDir = preserveExclusiveFailure({
      pid: process.pid,
      argv: [process.execPath, 'flow.js', 'doctor'],
      cwd: root,
      stdout: JSON.stringify(flowSummary),
      stderr: ''
    }, { team_root: path.join(root, '.knowledge-team'), state_root: observedStateRoot }, null, `capture self-test: ${name}`);
    return { directory: capturedDir, result: JSON.parse(fs.readFileSync(path.join(capturedDir, 'failure.json'), 'utf8')) };
  };
  const priorEvidenceRoot = process.env.KNOWLEDGE_TEAM_MODE_FAILURE_DIR;
  process.env.KNOWLEDGE_TEAM_MODE_FAILURE_DIR = evidenceRoot;
  try {
    const { result: captured } = capture(summary, stateRoot, 'contained log');
    assert(captured.flow_log_capture === 'copied', 'failure capture did not copy contained flow log from command JSON');
    assert(captured.child_identity?.pid === process.pid, 'failure capture did not preserve child pid');
    assert(/^[a-f0-9]{64}$/.test(captured.child_identity.executable_sha256), 'failure capture did not preserve Node executable hash');
    assert(captured.flow_context?.state_root === stateRoot, 'failure capture did not preserve selected state root');

    const outsideStateRoot = path.join(root, 'outside-declared-state');
    const outsideLogDirectory = path.join(outsideStateRoot, 'maintenance', 'flow-logs');
    const outsideLogPath = path.join(outsideLogDirectory, 'sentinel.json');
    fs.mkdirSync(outsideLogDirectory, { recursive: true });
    fs.writeFileSync(outsideLogPath, 'OUTSIDE-STATE-SENTINEL\n', 'utf8');
    const outside = capture({ ...summary, flow_log: outsideLogPath }, stateRoot, 'outside declared state');
    assert(outside.result.flow_log_capture === 'rejected_uncontained_or_unexpected_path', 'failure capture accepted a log outside the observed state root');
    assert(!fs.existsSync(path.join(outside.directory, 'doctor-flow-log.json')), 'failure capture copied log outside the observed state root');

    const junctionTarget = path.join(root, 'junction-target');
    const junctionStateRoot = path.join(root, 'junction-state');
    const junctionLogDirectory = path.join(junctionTarget, 'maintenance', 'flow-logs');
    const junctionLogPath = path.join(junctionStateRoot, 'maintenance', 'flow-logs', 'sentinel.json');
    fs.mkdirSync(junctionLogDirectory, { recursive: true });
    fs.writeFileSync(path.join(junctionLogDirectory, 'sentinel.json'), 'JUNCTION-SENTINEL\n', 'utf8');
    fs.symlinkSync(junctionTarget, junctionStateRoot, 'junction');
    const junction = capture({ ...summary, state_root: junctionStateRoot, flow_log: junctionLogPath }, junctionStateRoot, 'junction parent');
    assert(junction.result.flow_log_capture === 'rejected:contained_path_unsafe', 'failure capture accepted a flow log below a junction');
    assert(!fs.existsSync(path.join(junction.directory, 'doctor-flow-log.json')), 'failure capture copied a flow log below a junction');
    return true;
  } finally {
    if (priorEvidenceRoot === undefined) delete process.env.KNOWLEDGE_TEAM_MODE_FAILURE_DIR;
    else process.env.KNOWLEDGE_TEAM_MODE_FAILURE_DIR = priorEvidenceRoot;
  }
}

async function spawnNode(script, args, options = {}) {
  const id = ++nextChildPhase, name = path.basename(script) + ' ' + (args[0] || '');
  childPhase('begin', id, name);
  if (process.platform === 'win32') {
    // Reuse the product's native Job custody. Direct exit is not pipe EOF;
    // cancellation drains all descendants and both streams before returning.
    const result = await require('./lib/command-runner').runOwnedCommand({
      executable: process.execPath, args: [script, ...args],
      cwd: options.cwd || process.cwd(), env: isolatedChildEnv(options.env || {})
    }, {
      budgets: { workMs: options.timeoutMs || 120000, setupMs: 30000, cleanupMs: 60000, progressMs: 0 },
      onNativeReady(descriptor) {
        childPhase('native_ready', id, name, { scope_id: descriptor.scope_id });
      }
    });
    childPhase('exit', id, name, { exit_code: result.status, error: result.error?.code || null,
      cleanup: result.cleanup?.status || 'unconfirmed', output_closed: result.cleanup?.output_closed === true });
    return { code: result.error || result.cleanup?.status !== 'completed' ? null : result.status,
      stdout: result.stdout, stderr: result.stderr, error: result.error, cleanup: result.cleanup, script, args };
  }
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
    child.on('exit', code => childPhase('direct_exit', id, name, { exit_code: code }));
    child.on('close', (code) => {
      childPhase('exit', id, name, { exit_code: code });
      resolve({ code, stdout, stderr, script, args });
    });
  });
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge team тест '));
  rootForCleanup = root;
  checkExclusiveFailureCapture(root);
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
  copyInstalledKnowledge(repo);
  const importFlow = parseJson(nodeTool(repo, 'flow.js', ['import', '--json', '--no-color'], {
    cwd: repo,
    env: { KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_AGENT_ID: 'team-self-test-import' }
  }));
  assert(importFlow.status === 'ok', `fresh installed fixture import failed: ${JSON.stringify(importFlow)}`);
  assert(fs.existsSync(path.join(repo, '.knowledge', 'project_index.json')), 'fresh installed fixture import did not create project_index.json');
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

  const freshTeamDoctorRun = run(process.execPath, [
    path.join(w1, '.knowledge', 'tools', 'doctor.js'),
    '--team-root', teamRoot,
    '--target-root', w1,
    '--workspace-id', 'codex-task-1',
    '--agent-id', 'codex-01',
    '--json'
  ], { cwd: w1 });
  assert(freshTeamDoctorRun.status === 0, `fresh team Doctor failed before runtime artifacts existed\n${freshTeamDoctorRun.stderr}\n${freshTeamDoctorRun.stdout}`);
  const freshTeamDoctor = parseJson(freshTeamDoctorRun);
  assert(
    (freshTeamDoctor.issues || []).every((item) => !path.isAbsolute(String(item.artifact || ''))),
    'fresh team Doctor emitted an absolute state artifact into the repair lifecycle'
  );
  assert(
    (freshTeamDoctor.issues || []).some((item) =>
      item.code === 'missing_runtime_file' &&
      String(item.artifact || '').startsWith('.knowledge-team/repos/')),
    'fresh team Doctor did not expose safe relative team-state diagnostics'
  );
  assertFails(run(process.execPath, [path.join(w1, '.knowledge', 'tools', 'workspace-register.js'), '--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1 }), 'duplicate workspaceId with different targetRoot should fail');
  const duplicateAgent = parseJson(nodeTool(w2, 'workspace-register.js', ['--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'claude-duplicate-agent', '--agent-id', 'claude-01', '--json'], { cwd: w2 }));
  assert((duplicateAgent.workspace.warnings || []).some((warning) => /agentId duplicate/i.test(warning)), 'duplicate agentId warning missing');

  const staleLockPath = path.join(teamRoot, 'repos', reg1.context.repoId, 'locks', 'v1', 'team-flow.lock');
  fs.mkdirSync(staleLockPath, { recursive: true });
  fs.writeFileSync(path.join(staleLockPath, 'owner.json'), canonicalOwnerText({
    schema_version: 'knowledge-lock-owner.v1',
    lock_id: '123e4567-e89b-42d3-a456-426614174000',
    lock_name: 'team-flow',
    purpose: LOCKS['team-flow'].purpose,
    pid: 2147483647,
    hostname: os.hostname(),
    agent_id: 'stale',
    workspace_id: 'codex-task-1',
    process_started_at: '2000-01-01T00:00:00.000Z',
    acquired_at: '2000-01-01T00:00:00.000Z',
    nonce: 'a'.repeat(64)
  }), 'utf8');
  const oldLockTime = new Date('2000-01-01T00:00:00.000Z');
  fs.utimesSync(staleLockPath, oldLockTime, oldLockTime);

  // An old canonical owner has no native PID visibility evidence. The v2
  // reader must retain it, even if its old guessed numerical PID is absent.
  // Remove only this test-created fixture after proving the migration gate;
  // the concurrent flow assertions below remain unchanged.
  const injectedLegacyOwner = fs.readFileSync(path.join(staleLockPath, 'owner.json'), 'utf8');
  const injectedLegacyIdentity = fs.lstatSync(staleLockPath, { bigint: true });
  const blockedLegacyFlow = run(process.execPath, [path.join(w2, '.knowledge', 'tools', 'flow.js'), 'release', '--team-root', teamRoot,
    '--target-root', w2, '--workspace-id', 'claude-task-2', '--agent-id', 'claude-01', '--exclusive', '--json'],
  { cwd: w2, env: { CLAUDE_MEMORY_PATH: sharedMemory, KNOWLEDGE_LOCK_TIMEOUT_MS: '100' } });
  assertFails(blockedLegacyFlow, 'unqualified v1 owner must block automatic stale recovery');
  const blockedLegacyResult = JSON.parse(blockedLegacyFlow.stdout);
  assert(blockedLegacyResult.error?.code === 'lock_timeout', 'legacy owner gate did not retain the lock_timeout contract');
  assert(fs.readFileSync(path.join(staleLockPath, 'owner.json'), 'utf8') === injectedLegacyOwner,
    'legacy owner evidence changed during refusal');
  const retainedLegacyIdentity = fs.lstatSync(staleLockPath, { bigint: true });
  assert(retainedLegacyIdentity.dev === injectedLegacyIdentity.dev && retainedLegacyIdentity.ino === injectedLegacyIdentity.ino,
    'legacy owner directory was replaced during refusal');
  fs.unlinkSync(path.join(staleLockPath, 'owner.json'));
  fs.rmdirSync(staleLockPath);

  const flow1 = spawnNode(path.join(w1, '.knowledge', 'tools', 'flow.js'), ['doctor', '--team-root', teamRoot, '--target-root', w1, '--workspace-id', 'codex-task-1', '--agent-id', 'codex-01', '--json'], { cwd: w1, env: { CLAUDE_MEMORY_PATH: sharedMemory } });
  const flow2 = spawnNode(path.join(w2, '.knowledge', 'tools', 'flow.js'), ['release', '--team-root', teamRoot, '--target-root', w2, '--workspace-id', 'claude-task-2', '--agent-id', 'claude-01', '--exclusive', '--json'], { cwd: w2, env: { CLAUDE_MEMORY_PATH: sharedMemory } });
  const [r1, r2] = await Promise.all([flow1, flow2]);
  assert(r1.code === 0, `doctor flow failed\n${r1.stderr}\n${r1.stdout}`);
  assert(r2.code === 0, `release flow failed\n${r2.stderr}\n${r2.stdout}`);
  const doctorFlow = JSON.parse(r1.stdout);
  const doctorStep = (doctorFlow.steps || []).find((step) => step.step === 'doctor');
  assert(doctorStep?.status === 'pass', 'team doctor did not report a semantic pass');
  assert((doctorStep.semantic_errors || []).length === 0, 'team doctor exposed semantic errors');

  const projectIndexPath = path.join(w1, '.knowledge', 'project_index.json');
  const projectIndexBackup = `${projectIndexPath}.self-test-backup`;
  let failedExclusive = null;
  let failedExclusiveFlow = null;
  let failedExclusiveLog = null;
  let flowLogPath = null;
  const indexObservations = {
    team_root: teamRoot,
    target_root: w1,
    project_knowledge_root: path.join(w1, '.knowledge'),
    state_root: reg1.workspace.stateRoot,
    project_index_path: projectIndexPath,
    before_removal: physicalFileState(projectIndexPath)
  };
  function failExclusive(message) {
    let evidence;
    try { evidence = preserveExclusiveFailure(failedExclusive, indexObservations, flowLogPath, message); }
    catch (error) { throw new Error(`${message}\nFailure evidence capture failed: ${error.message}`); }
    throw new Error(`${message}\nFailure evidence: ${evidence}`);
  }
  function assertExclusive(condition, message) {
    if (!condition) failExclusive(message);
  }
  try {
    fs.renameSync(projectIndexPath, projectIndexBackup);
    indexObservations.before_command = physicalFileState(projectIndexPath);
    failedExclusive = run(process.execPath, [
      path.join(w1, '.knowledge', 'tools', 'flow.js'),
      'doctor',
      '--team-root', teamRoot,
      '--target-root', w1,
      '--workspace-id', 'codex-task-1',
      '--agent-id', 'codex-01',
      '--exclusive',
      '--json',
      '--no-color'
    ], { cwd: w1, env: { CLAUDE_MEMORY_PATH: sharedMemory } });
    indexObservations.after_command = physicalFileState(projectIndexPath);
    assert(!fs.existsSync(staleLockPath), 'failed exclusive flow did not release flow.lock immediately');
    failedExclusiveFlow = parseJson(failedExclusive);
    flowLogPath = path.isAbsolute(failedExclusiveFlow.flow_log)
      ? failedExclusiveFlow.flow_log
      : path.resolve(w1, failedExclusiveFlow.flow_log);
    failedExclusiveLog = JSON.parse(fs.readFileSync(flowLogPath, 'utf8'));
  } catch (error) {
    failExclusive(error.message);
  } finally {
    if (fs.existsSync(projectIndexBackup)) fs.renameSync(projectIndexBackup, projectIndexPath);
    indexObservations.after_restore = physicalFileState(projectIndexPath);
  }
  assertExclusive(failedExclusive && !failedExclusive.ok, 'exclusive doctor should fail when project_index.json is missing');
  assertExclusive(failedExclusiveFlow?.status === 'failed', 'failed exclusive doctor did not report failed flow status');
  const failedDoctorStep = (failedExclusiveLog?.steps || []).find((step) => step.step === 'doctor');
  assertExclusive(failedDoctorStep?.success === false, 'failed exclusive doctor did not preserve semantic failure');
  assertExclusive(
    (failedDoctorStep?.parsed?.issues || []).some((item) =>
      item.code === 'missing_required_file' &&
      /project_index\.json/i.test(`${item.artifact || ''} ${item.message || ''}`)
    ),
    'failed exclusive doctor log did not preserve missing project_index.json evidence'
  );
  const failedWorkspace = JSON.parse(fs.readFileSync(
    path.join(teamRoot, 'repos', reg1.context.repoId, 'workspaces', 'codex-task-1', 'workspace.json'),
    'utf8'
  ));
  assertExclusive(failedWorkspace.last_status === 'incomplete', 'raw workspace snapshot must not claim terminal status without a finalization record');
  const failedFinalStatus = require('./lib/team-store').readTeamFlowStatus(
    teamRoot, reg1.context.repoId, 'codex-task-1', failedWorkspace.last_run_id
  );
  assertExclusive(failedFinalStatus.last_status === 'failed' && failedFinalStatus.finalization_status === 'completed',
    'failed exclusive doctor did not derive terminal status from its completed finalization record');

  const requiredWorkspaceRuntime = [
    'freshness.json',
    'maintenance/trust_report.json',
    'maintenance/handoff_summary.json',
    'maintenance/routing_bundle.json',
    'maps/file_criticality.json',
    'maps/wiki_graph.json',
    'maintenance/wiki_lint_report.json',
    'maintenance/secret_scan_report.json'
  ];
  for (const rel of requiredWorkspaceRuntime) {
    assert(fs.existsSync(path.join(reg1.workspace.stateRoot, rel)), `team doctor runtime artifact missing: ${rel}`);
  }

  for (const file of walkJson(teamRoot)) JSON.parse(fs.readFileSync(file, 'utf8'));
  assert(!fs.existsSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'locks', 'flow.lock')), 'flow lock was not released');
  assert(fs.existsSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'events')), 'events directory missing');
  const eventText = fs.readdirSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'events')).map((name) => fs.readFileSync(path.join(teamRoot, 'repos', reg1.context.repoId, 'events', name), 'utf8')).join('\n');
  assert(/lock_timeout/.test(eventText), 'legacy owner refusal event missing');
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
    schema_version: systemVersion(),
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
      'team doctor semantic health and runtime regeneration',
      'exclusive Doctor failure capture preserves contained flow log and child identity',
      'failed exclusive doctor releases lock and records semantic failure',
      'unqualified legacy owner is retained unchanged before owned-fixture cleanup',
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
