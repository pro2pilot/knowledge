'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { fork } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');
const { createRequire } = require('module');
const runner = require('../tools/lib/command-runner');
const authority = require('../tools/lib/command-authority-entry');

const flow = path.resolve(__dirname, '../tools/flow.js');
const evaluation = path.resolve(__dirname, '../tools/evaluation-harness.js');
const policy = { workMs: 3000, progressMs: 0, setupMs: 5000, cleanupMs: 5000 };
function command(executable, args, nestedAuthority = true) {
  return { executable, args, cwd: process.cwd(), env: process.env, nestedAuthority };
}

test('foreign path with an authorized basename is rejected before command-scope admission', async () => {
  const foreign = path.resolve(os.tmpdir(), 'untrusted-install', 'flow.js');
  const normalizedAlias = path.dirname(flow) + path.sep + 'foreign' + path.sep + '..' + path.sep + 'flow.js';
  for (const target of [foreign, normalizedAlias]) {
    const candidate = command(process.execPath, [target, '--help']);
    assert.throws(() => authority.validateCommandAuthority(candidate), { code: 'command_authority_target_invalid' });
    const result = await runner.runOwnedCommand(candidate, { budgets: policy });
    assert.equal(result.error?.code, 'command_authority_target_invalid', JSON.stringify(result));
    assert.equal(result.cleanup?.status, 'completed');assert.equal(result.cleanup?.method, 'no_scope_admitted');
  }
});

test('true authority rejects wrong executables and node -e before spawn', async () => {
  const vectors = [
    command(process.execPath + '.foreign', [flow, '--help']),
    command(process.execPath, ['-e', 'process.exit(0)'])
  ];
  for (const candidate of vectors) {
    assert.throws(() => authority.validateCommandAuthority(candidate), { code: 'command_authority_target_invalid' });
    const result = await runner.runOwnedCommand(candidate, { budgets: policy });
    assert.equal(result.error?.code, 'command_authority_target_invalid', JSON.stringify(result));
  }
  assert.throws(() => authority.validateCommandAuthority(command(process.execPath, [flow, '\0bad'])),
    { code: 'command_authority_target_invalid' });
});

test('only exact installed Flow and evaluation entries resolve nested authority', () => {
  assert.equal(authority.installedAuthorityEntry(command(process.execPath, [flow, '--help'])), 'flow');
  assert.equal(authority.installedAuthorityEntry(command(process.execPath, [evaluation, '--help'])), 'evaluation');
  assert.equal(authority.validateCommandAuthority(command(process.execPath, [flow, '--help'])), 'flow');
  assert.equal(authority.validateCommandAuthority(command(process.execPath, [evaluation, '--help'])), 'evaluation');
});

test('false authority flag leaves ordinary commands on the ordinary worker spawn path', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'command-authority-ordinary-'));
  const marker = path.join(root, 'ordinary-spawned');
  const worker = fork(path.resolve(__dirname, '../tools/lib/command-worker.js'), [], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const workerExited = new Promise(resolve => { worker.once('exit', resolve);worker.once('error', resolve); });
  let timer;
  t.after(async () => {
    clearTimeout(timer);
    if (worker.connected) worker.disconnect();
    if (!worker.killed) worker.kill();
    await workerExited;
    fs.rmSync(root, { recursive: true, force: true });
  });
  const candidate = command(process.execPath, ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ordinary')`], false);
  assert.equal(authority.validateCommandAuthority(candidate), null);
  const result = await new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('ordinary worker command timed out')), 5000);
    worker.once('error', reject);
    worker.on('message', message => {
      if (message?.type === 'host_ready') worker.send({ type: 'start', kind: 'command', budgets: policy, payload: candidate });
      else if (message?.type === 'result') resolve(message);
    });
  });
  clearTimeout(timer);
  assert.equal(result.value?.status, 0, JSON.stringify(result));
  assert.equal(fs.readFileSync(marker, 'utf8'), 'ordinary');
});

test('forged worker IPC cannot turn a foreign nested target into a spawn', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'command-authority-worker-'));
  const marker = path.join(root, 'spawned');
  const workerPath = path.resolve(__dirname, '../tools/lib/command-worker.js');
  const worker = fork(workerPath, [], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const workerExited = new Promise(resolve => { worker.once('exit', resolve);worker.once('error', resolve); });
  let timer;
  t.after(async () => {
    clearTimeout(timer);
    if (worker.connected) worker.disconnect();
    if (!worker.killed) worker.kill();
    await workerExited;
    fs.rmSync(root, { recursive: true, force: true });
  });
  const result = await new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('forged worker IPC timed out')), 5000);
    worker.once('error', reject);
    worker.on('message', message => {
      if (message?.type === 'host_ready') {
        worker.send({ type: 'start', kind: 'command', budgets: policy, payload: command(process.execPath,
          ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'spawned')`]) });
      } else if (message?.type === 'result') resolve(message);
    });
  });
  clearTimeout(timer);
  assert.equal(result.error?.code, 'command_authority_target_invalid', JSON.stringify(result));
  assert.equal(fs.existsSync(marker), false);
});

test('owned command snapshot detaches args, cwd and environment and preserves timeout_ms', () => {
  const input = { ...command(process.execPath, [flow, '--json']), env: { MODE: 'original' }, timeout_ms: 1234 };
  const snapshot = authority.snapshotCommand(input);
  input.args[0] = '-e';input.env.MODE = 'changed';input.cwd = path.dirname(input.cwd);input.nestedAuthority = false;
  assert.equal(snapshot.args[0], flow);assert.equal(snapshot.env.MODE, 'original');
  assert.notEqual(snapshot.cwd, input.cwd);assert.equal(snapshot.nestedAuthority, true);assert.equal(snapshot.timeout_ms, 1234);
  assert(Object.isFrozen(snapshot));assert(Object.isFrozen(snapshot.args));assert(Object.isFrozen(snapshot.env));
  assert.equal(authority.snapshotCommand(snapshot), snapshot);
  const actualEnvironment = authority.snapshotCommand(command(process.execPath, [flow]));
  assert.notEqual(actualEnvironment.env, process.env);assert(Object.isFrozen(actualEnvironment.env));
});

test('snapshot rejects getters, proxies and toJSON without executing caller code', async () => {
  let calls = 0;
  const getter = { ...command(process.execPath, [flow]) };
  Object.defineProperty(getter, 'args', { enumerable: true, get() { calls++;return [flow]; } });
  const json = { ...command(process.execPath, [flow]), toJSON() { calls++;return command(process.execPath, ['-e', '0'], false); } };
  const proxy = new Proxy(command(process.execPath, [flow]), { ownKeys() { calls++;throw new Error('trap executed'); } });
  const envGetter = { ...command(process.execPath, [flow]), env: {} };
  Object.defineProperty(envGetter.env, 'KEY', { enumerable: true, get() { calls++;return 'injected'; } });
  for (const input of [getter, json, proxy, envGetter]) {
    const result = await runner.runOwnedCommand(input, { budgets: policy });
    assert.equal(result.error?.code, 'command_input_invalid');assert.equal(result.cleanup.status, 'completed');
    assert.equal(result.cleanup.method, 'no_scope_admitted');
  }
  assert.equal(calls, 0);
});

test('snapshot admission observes its original setup deadline', () => {
  let checks = 0;
  assert.throws(() => authority.snapshotCommand(command(process.execPath, [flow]), () => {
    if (++checks === 5) throw Object.assign(new Error('setup expired'), { code: 'command_setup_timeout' });
  }), { code: 'command_setup_timeout' });
});

function modeledRunner(stepClock = false) {
  const file = process.env.KNOWLEDGE_TEST_AUTHORITY_RUNNER || path.resolve(__dirname, '../tools/lib/command-runner.js');
  const realRequire = createRequire(file), captures = [];
  const descriptor = { backend: 'linux_pid_namespace', observer_pid_namespace: { ino: '10' },
    controller: { proc_pid_chain: [123] }, init: { pid_namespace: { ino: '11' }, proc_pid_chain: [123, 1] } };
  const native = { admitPreparedHelper(value) { return value; }, sameNamespaceIdentity(a, b) { return a.ino === b.ino; },
    spawnLinuxContainedWorker(executable, args, options, settings) {
      const capture = { nativeAuthority: settings.trustedAuthority, options, messages: [] };captures.push(capture);
      const worker = new EventEmitter();Object.assign(worker, { stdout: new PassThrough(), stderr: new PassThrough(), connected: true });
      worker.send = (message, callback) => {
        capture.messages.push(message);callback?.();
        if (message.type === 'start' && message.kind !== 'session') queueMicrotask(() => worker.emit('message', { type: 'result', value: { status: 0 } }));
        if (message.type === 'execute') queueMicrotask(() => worker.emit('message', { type: 'reply', id: message.id, value: { status: 0 } }));
      };
      worker.disconnect = () => { worker.connected = false; };worker.unref = () => {};
      const close = async () => { worker.stdout.end();worker.stderr.end();return { status: 'completed', active_processes: 0 }; };
      const job = { ready: Promise.resolve(), descriptor, permit() {}, close, drain: close };
      queueMicrotask(() => worker.emit('message', { type: 'host_ready' }));return { worker, job };
    } };
  const module = { exports: {} };
  let ticks = 0;
  const context = { module, exports: module.exports, __dirname: path.dirname(file), __filename: file,
    require(name) { if (name === './verification-linux-namespace') return native;
      if (name === './command-scope-proof') return { validateExecutionScope() { return true; } };return realRequire(name); },
    process: { platform: 'linux', execPath: process.execPath, pid: 123, env: {},
      hrtime: stepClock ? { bigint() { return BigInt(++ticks) * 1000000n; } } : process.hrtime },
    Buffer, TextDecoder, setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), context, { filename: file });
  return { runner: module.exports, captures, flowEntry: path.resolve(path.dirname(file), '../flow.js') };
}

test('modeled native admission and late worker IPC use the same immutable command snapshot', async () => {
  const model = modeledRunner();
  const input = { ...command(process.execPath, [model.flowEntry, '--json']), env: { MODE: 'original' } };
  const originalCwd = input.cwd;
  const result = await model.runner.runOwnedCommand(input, { budgets: policy, preparedHelper: {}, onNativeReady() {
    input.nestedAuthority = false;input.args.splice(0, input.args.length, '-e', 'untrusted-code');
    input.env.MODE = 'changed';input.cwd = path.dirname(input.cwd);
  } });
  assert.equal(result.error, undefined, JSON.stringify(result));
  const capture = model.captures[0], delivered = capture.messages.find(message => message.type === 'start').payload;
  assert.equal(capture.nativeAuthority, true);assert.equal(delivered.nestedAuthority, true);
  assert.equal(delivered.args[0], model.flowEntry);assert.equal(delivered.cwd, originalCwd);assert.equal(delivered.env.MODE, 'original');
  assert.equal(capture.options.cwd, originalCwd);assert.equal(capture.options.env.MODE, 'original');
});

test('session admission does not execute a caller serialization hook', async () => {
  const model = modeledRunner();
  const session = await model.runner.createCommandSession({ budgets: policy, preparedHelper: {} });
  let calls = 0;
  try {
    await assert.rejects(session.run({ ...command(process.execPath, ['-e', '0'], false),
      toJSON() { calls++;return command(process.execPath, ['-e', 'untrusted-code'], true); } }), { code: 'command_input_invalid' });
    assert.equal(calls, 0);assert.equal(model.captures[0].messages.some(message => message.type === 'execute'), false);
  } finally { await session.finish(); }
});

test('command copying consumes the original setup allowance before native admission', async () => {
  const model = modeledRunner(true);
  const result = await model.runner.runOwnedCommand({ ...command(process.execPath, [model.flowEntry]), env: {} },
    { budgets: { ...policy, setupMs: 20 }, preparedHelper: {} });
  assert.equal(result.error?.code, 'command_setup_timeout');assert.equal(model.captures.length, 0);
  assert.equal(result.cleanup.status, 'completed');assert.equal(result.cleanup.method, 'no_scope_admitted');
});

test('legitimate installed Flow and evaluation keep the private wrapper and unchanged CLI arguments', async () => {
  const workerFile = path.resolve(__dirname, '../tools/lib/command-worker.js'), realRequire = createRequire(workerFile);
  for (const [target, entry] of [[flow, 'flow'], [evaluation, 'evaluation']]) {
    const sent = [], spawned = [], parent = new EventEmitter();
    Object.assign(parent, { execPath: process.execPath, connected: true, stdout: new EventEmitter(), stderr: new EventEmitter(),
      send(value, callback) { sent.push(value);callback?.(); }, exit() { throw new Error('unexpected process exit'); } });
    const context = { process: parent, __dirname: path.dirname(workerFile), __filename: workerFile,
      require(name) { if (name !== 'child_process') return realRequire(name);
        return { spawn(executable, args, options) { const child = new EventEmitter();
          child.send = value => sent.push(value);spawned.push({ executable, args, options });return child; } }; } };
    vm.runInNewContext(fs.readFileSync(workerFile, 'utf8'), context, { filename: workerFile });
    parent.emit('message', { type: 'start', kind: 'command', budgets: policy,
      payload: { ...command(process.execPath, [target, 'doctor', '--json']), env: {} } });
    await Promise.resolve();
    assert.equal(spawned.length, 1);assert.equal(spawned[0].args[0], path.resolve(__dirname, '../tools/lib/command-cli-worker.js'));
    const admitted = sent.find(value => value.type === 'cli_start');
    assert.equal(admitted.entry, entry);assert.deepEqual([...admitted.argv], ['doctor', '--json']);
    assert.equal(spawned[0].options.stdio[3], 'ipc');
  }
});
