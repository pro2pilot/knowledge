#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const systemRoot = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));
const team = require(path.join(systemRoot, 'tools/lib/team-store'));
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-team-registry-'));
const checks = [];
const live = new Set();
const workerFile = path.join(base, 'worker.js');

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
}
function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function context(root, extra = {}) {
  return {
    mode: 'team', systemRoot, projectKnowledgeRoot: systemRoot,
    targetRoot: root, teamRoot: path.join(root, 'team'), repoId: 'repo-a',
    workspaceId: 'workspace', agentId: 'agent-a', git: {}, branch: null,
    headSha: null, warnings: [], ...extra
  };
}
function lockDir(ctx) { return path.join(ctx.teamRoot, 'locks/v1/team-registry.lock'); }
function registryFile(ctx) { return path.join(ctx.teamRoot, 'registry.json'); }
function workspaceFile(ctx) { return path.join(team.workspaceDir(ctx.teamRoot, ctx.repoId, ctx.workspaceId), 'workspace.json'); }
function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
async function until(predicate, message, milliseconds = 10000) {
  const deadline = Date.now() + milliseconds;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(`Timed out: ${message}`);
    await delay(10);
  }
}

// The hooks only control scheduling around physical reads and mkdir attempts.
// Child A reads the old state and pauses. B must either contend for the shared
// lock, or (in a broken implementation) read that same old state. A then commits
// before B. No successful read, write, lock result, or process exit is mocked.
write(workerFile, `
'use strict';
const fs = require('fs');
const path = require('path');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const nativeRead = fs.readFileSync;
const nativeMkdir = fs.mkdirSync;
let observed = false;
fs.readFileSync = function(file, ...args) {
  const value = nativeRead.call(this, file, ...args);
  if (!observed && typeof file === 'string' && path.resolve(file) === input.readTarget) {
    observed = true;
    fs.writeFileSync(input.readMarker, 'read');
    const deadline = Date.now() + 10000;
    while (!fs.existsSync(input.releaseMarker)) {
      if (Date.now() >= deadline) throw new Error('read barrier timed out');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  return value;
};
fs.mkdirSync = function(directory, ...args) {
  try { return nativeMkdir.call(this, directory, ...args); }
  catch (error) {
    if (error.code === 'EEXIST' && typeof directory === 'string' && path.resolve(directory) === input.lockDir) {
      fs.writeFileSync(input.contentionMarker, 'contended');
    }
    throw error;
  }
};
try {
  const team = require(input.teamModule);
  let value;
  if (input.operation === 'init') value = team.initTeam(input.context);
  else if (input.operation === 'register') value = team.registerWorkspace(input.context, input.extra || {});
  else if (input.operation === 'unregister') value = team.unregisterWorkspace(input.context.teamRoot, input.context.workspaceId, input.context.repoId);
  else if (input.operation === 'update') value = team.updateWorkspaceFlow(input.context, { flow: 'scan', overall_status: 'pass' });
  else throw new Error('Unknown worker operation');
  process.stdout.write(JSON.stringify({ ok: true, value }));
} catch (error) {
  process.stdout.write(JSON.stringify({ ok: false, error: { code: error.code || null, message: error.message } }));
  process.exitCode = 2;
}
`);

function start(root, id, operation, ctx, readTarget, extra) {
  const input = {
    operation, context: ctx, extra, readTarget, lockDir: lockDir(ctx),
    teamModule: path.join(systemRoot, 'tools/lib/team-store'),
    readMarker: path.join(root, `read-${id}`),
    contentionMarker: path.join(root, `contended-${id}`),
    releaseMarker: path.join(root, `release-${id}`)
  };
  const inputFile = path.join(root, `input-${id}.json`);
  write(inputFile, input);
  const child = spawn(process.execPath, [workerFile, inputFile], {
    cwd: root, env: { ...process.env, KNOWLEDGE_LOCK_TIMEOUT_MS: '10000' }, windowsHide: true
  });
  const handle = { child, input, result: null };
  live.add(handle);
  let stdout = ''; let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  handle.done = new Promise(resolve => {
    child.on('error', error => { handle.result = { code: null, error: error.message, stdout, stderr }; live.delete(handle); resolve(handle.result); });
    child.on('close', (code, signal) => {
      let body = null;
      try { body = JSON.parse(stdout); } catch {}
      handle.result = { code, signal, stdout, stderr, body };
      live.delete(handle);
      resolve(handle.result);
    });
  });
  return handle;
}

async function orderedPair(root, operationA, operationB, ctxA, ctxB, readTarget, extraA = {}) {
  const a = start(root, 'a', operationA, ctxA, readTarget, extraA);
  let b;
  try {
    await until(() => fs.existsSync(a.input.readMarker) || a.result, 'A reaches its physical state read');
    assert(!a.result, `A exited before its read: ${JSON.stringify(a.result)}`);
    b = start(root, 'b', operationB, ctxB, readTarget);
    await until(() => fs.existsSync(b.input.readMarker) || fs.existsSync(b.input.contentionMarker) || b.result,
      'B either reads stale state or contends for the shared lock');
    assert(!b.result, `B exited before contention/read: ${JSON.stringify(b.result)}`);
    const secondReadBeforeFirstCommit = fs.existsSync(b.input.readMarker);
    write(a.input.releaseMarker, 'release');
    await until(() => a.result, 'A commits and releases its lock');
    write(b.input.releaseMarker, 'release');
    await until(() => b.result, 'B completes after A');
    return { first: a.result, second: b.result, second_read_before_first_commit: secondReadBeforeFirstCommit };
  } finally {
    for (const handle of [a, b].filter(Boolean)) {
      write(handle.input.releaseMarker, 'release');
      if (!handle.result) handle.child.kill();
      await handle.done;
    }
  }
}

async function check(name, run) {
  const root = path.join(base, String(checks.length));
  fs.mkdirSync(root);
  try {
    const details = await run(root);
    checks.push({ name, status: 'pass', ...(details ? { details } : {}) });
  } catch (error) {
    checks.push({ name, status: 'fail', error: error.stack || error.message });
  }
}

async function main() {
  for (const operation of ['init', 'register']) {
    await check(`concurrent ${operation} preserves both repositories in shared registry`, async root => {
      const a = context(root);
      const b = context(root, { repoId: 'repo-b', agentId: 'agent-b' });
      write(registryFile(a), { schema_version: '3.4.3', repos: [] });
      const pair = await orderedPair(root, operation, operation, a, b, registryFile(a));
      assert.equal(pair.first.code, 0, pair.first.stdout + pair.first.stderr);
      assert.equal(pair.second.code, 0, pair.second.stdout + pair.second.stderr);
      assert.deepEqual(read(registryFile(a)).repos.map(repo => repo.repoId).sort(), ['repo-a', 'repo-b']);
      assert(!pair.second_read_before_first_commit, 'B read the shared registry while A had an uncommitted mutation');
      assert(!fs.existsSync(lockDir(a)), 'shared registry lock was not released');
      if (operation === 'register') {
        assert.equal(read(workspaceFile(a)).repoId, a.repoId);
        assert.equal(read(workspaceFile(b)).repoId, b.repoId);
      }
      return { physical_children: 2, serialized: true };
    });
  }

  await check('concurrent duplicate workspace registration permits only its first owner', async root => {
    const a = context(root);
    const b = context(root, { agentId: 'agent-b' });
    write(registryFile(a), { schema_version: '3.4.3', repos: [] });
    const pair = await orderedPair(root, 'register', 'register', a, b, registryFile(a));
    assert.equal(pair.first.code, 0, pair.first.stdout + pair.first.stderr);
    assert.equal(pair.second.code, 2, pair.second.stdout + pair.second.stderr);
    assert.match(pair.second.body?.error?.message || '', /duplicate/);
    assert.equal(read(workspaceFile(a)).agentId, 'agent-a');
    assert(!fs.existsSync(lockDir(a)), 'error path left the shared lock held');
  });

  await check('flow update after concurrent archive preserves archived status', async root => {
    const ctx = context(root);
    team.registerWorkspace(ctx);
    const pair = await orderedPair(root, 'unregister', 'update', ctx, ctx, workspaceFile(ctx));
    assert.equal(pair.first.code, 0, pair.first.stdout + pair.first.stderr);
    assert.equal(pair.second.code, 0, pair.second.stdout + pair.second.stderr);
    const workspace = read(workspaceFile(ctx));
    assert.equal(workspace.status, 'archived');
    assert.equal(workspace.last_flow, 'scan');
    assert(!pair.second_read_before_first_commit, 'update read stale pre-archive state');
    assert(!fs.existsSync(lockDir(ctx)));
  });

  await check('flow update preserves notes from concurrent workspace registration', async root => {
    const ctx = context(root);
    team.registerWorkspace(ctx);
    const pair = await orderedPair(root, 'register', 'update', ctx, ctx, workspaceFile(ctx), { notes: 'preserve registered notes' });
    assert.equal(pair.first.code, 0, pair.first.stdout + pair.first.stderr);
    assert.equal(pair.second.code, 0, pair.second.stdout + pair.second.stderr);
    const workspace = read(workspaceFile(ctx));
    assert.equal(workspace.notes, 'preserve registered notes');
    assert.equal(workspace.last_flow, 'scan');
    assert(!pair.second_read_before_first_commit, 'update read stale pre-registration state');
    assert(!fs.existsSync(lockDir(ctx)));
  });

  await check('corrupt registry failure preserves bytes, releases lock, and permits a valid retry', root => {
    const ctx = context(root);
    write(registryFile(ctx), '{broken');
    assert.throws(() => team.initTeam(ctx));
    assert.equal(fs.readFileSync(registryFile(ctx), 'utf8'), '{broken');
    assert(!fs.existsSync(lockDir(ctx)), 'validation failure leaked a held lock');
    write(registryFile(ctx), { schema_version: '3.4.3', repos: [] });
    team.registerWorkspace(ctx);
    assert.equal(read(workspaceFile(ctx)).status, 'active');
    assert(!fs.existsSync(lockDir(ctx)));
  });

  await check('unsafe IDs are rejected before creating the team root or lock layout', root => {
    const ctx = context(root, { workspaceId: '../../escape' });
    for (const operation of [() => team.initTeam(ctx), () => team.registerWorkspace(ctx),
      () => team.updateWorkspaceFlow(ctx, { flow: 'scan' }),
      () => team.unregisterWorkspace(ctx.teamRoot, ctx.workspaceId, ctx.repoId)]) {
      assert.throws(operation, error => error.code === 'path_segment_invalid');
      assert(!fs.existsSync(ctx.teamRoot));
    }
  });

  await check('unsafe shared lock parent is rejected before changing registry or outside files', root => {
    const ctx = context(root);
    team.registerWorkspace(ctx);
    const before = fs.readFileSync(registryFile(ctx));
    const outside = path.join(root, 'outside'); fs.mkdirSync(outside);
    write(path.join(outside, 'sentinel'), 'unchanged');
    fs.rmSync(path.join(ctx.teamRoot, 'locks'), { recursive: true, force: true });
    fs.symlinkSync(outside, path.join(ctx.teamRoot, 'locks'), process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(() => team.registerWorkspace({ ...ctx, branch: 'must-not-commit' }), error => error.code === 'unsafe_lock_parent');
    assert.deepEqual(fs.readFileSync(registryFile(ctx)), before);
    assert.deepEqual(fs.readdirSync(outside), ['sentinel']);
    assert.equal(fs.readFileSync(path.join(outside, 'sentinel'), 'utf8'), 'unchanged');
  });
}

main().catch(error => {
  checks.push({ name: 'suite execution', status: 'fail', error: error.stack || error.message });
}).finally(async () => {
  for (const handle of live) handle.child.kill();
  await Promise.all(Array.from(live, handle => handle.done));
  fs.rmSync(base, { recursive: true, force: true });
  const failed = checks.filter(row => row.status === 'fail').length;
  console.log(JSON.stringify({ schema_version: 'knowledge-team-registry-self-test.v1',
    status: failed ? 'fail' : 'pass', checks_total: checks.length,
    passed: checks.length - failed, failed, checks }, null, 2));
  if (failed) process.exitCode = 1;
});
