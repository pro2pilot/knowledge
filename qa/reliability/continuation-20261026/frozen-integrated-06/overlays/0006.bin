'use strict';

// Actual adapter source with modeled process/pipe boundaries. These tests do
// not assert physical macOS custody; the hosted native matrix supplies that.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const protocol = 'knowledge-darwin-storage-guardian.v1';
const sha = text => crypto.createHash('sha256').update(text).digest('hex');
const flush = () => new Promise(resolve => setImmediate(resolve));
function model(options = {}, { hangHelper = false, helperKillThrows = false } = {}) {
  const calls = [], helpers = [], errors = [], exits = [], controls = [];
  let guardian, guardArgs;
  const source = 'a'.repeat(64);
  const birth = (pid, parent) => ({ pid, ruid: 501, unique_id: String(pid + 5000), parent_unique_id: String(parent),
    start_sec: 100, start_usec: pid, pidversion: 7 });
  const processModel = { pid: 77, getuid: () => 501, execPath: '/protected/node', hrtime: process.hrtime };
  function child(pid) {
    const value = new EventEmitter();value.pid = pid;value.connected = true;value.stdio = Array.from({ length: 6 }, () => new PassThrough());
    value.stdout = value.stdio[1];value.kill = signal => { calls.push(['kill', pid, signal]);return true; };
    value.send = (body, callback) => { calls.push(['send', pid, body]);queueMicrotask(() => callback?.(null)); };
    value.disconnect = () => { if (value.connected) { value.connected = false;value.emit('disconnect'); } };
    value.unref = () => { calls.push(['unref', pid]); };
    return value;
  }
  function spawn(file, args) {
    calls.push(['spawn', file, args]);
    if (args[0] === '--storage-guardian') {
      guardian = child(101);guardArgs = args;
      guardian.stdio[3].on('data', bytes => controls.push(bytes.toString('utf8')));
      return guardian;
    }
    assert.equal(args[0], '--stop-storage');
    const value = child(201 + helpers.length);helpers.push(value);
    if (helperKillThrows) value.kill = signal => { calls.push(['kill', value.pid, signal]);throw new Error('modeled signal failure'); };
    if (!hangHelper) queueMicrotask(() => {
      // Unknown is deliberate: helper termination alone must not become a
      // writer exit proof in the adapter under test.
      value.stdout.end(JSON.stringify({ protocol, event: 'observed', nonce: args[10], source_sha256: source,
        status: 'unconfirmed', clock_healthy: true, child: birth(102, 5101) }) + '\n');
      value.emit('exit', 1, null);
    });
    return value;
  }
  const file = path.join(__dirname, '../tools/lib/verification-darwin-storage-guardian.js');
  const real = createRequire(file), module = { exports: {} };
  const requireModel = name => name === 'node:child_process' ? { spawn } :
    name === './verification-darwin-client' ? { nativeEnv: () => ({}) } : real(name);
  vm.runInThisContext('(function(require,module,exports,__filename,__dirname,process){\n' + fs.readFileSync(file, 'utf8') + '\n})',
    { filename: file })(requireModel, module, module.exports, file, path.dirname(file), processModel);
  const end = process.hrtime.bigint() + 5000000000n;
  const writer = module.exports.createStorageChild({ config: { broker_path: '/protected/broker' }, source_sha256: source,
    deadline_ns: String(end), cleanup_ms: 1000, ...options });
  writer.on('error', error => errors.push(error.code));writer.on('exit', (...value) => exits.push(value));
  function ready(extra = {}) {
    guardian.stdio[5].write(JSON.stringify({ protocol, event: 'ready', nonce: guardArgs[7], source_sha256: source,
      guardian: birth(101, 77), child: birth(102, 5101), clock: 'node_hrtime_continuous.v1',
      observed_ns: String(process.hrtime.bigint()), deadline_ns: String(end), ...extra }) + '\n');
  }
  async function dispose() {
    writer.stopWithin(process.hrtime.bigint() + 100000000n);await flush();
    guardian.disconnect();guardian.stdio[5].end();guardian.emit('exit', null, 'SIGKILL');await flush();
    for (const stream of guardian.stdio) stream.destroy();
    for (const helper of helpers) for (const stream of helper.stdio) stream.destroy();
  }
  return { writer, calls, errors, exits, controls, ready, dispose, guardian, guardArgs, helpers };
}

test('fixed storage stays behind native P until independent root custody acknowledges exact births', async () => {
  let admit, observed;
  const gate = new Promise(resolve => { admit = resolve; });
  const f = model({ beforeStoragePermit: births => { observed = births;return gate; } });
  try {
    f.ready();await flush();assert.equal(observed.writer.pid, 102);assert.equal(observed.guardian.pid, 101);
    assert.equal(Object.isFrozen(observed), true);assert.equal(f.controls.includes('P\n'), false);
    admit();await f.writer.nativeReady;assert.equal(f.controls.includes('P\n'), true);assert.deepEqual(f.errors, []);
  } finally { await f.dispose(); }
});

test('failed root custody never permits storage and never claims physical writer exit', async () => {
  for (const nativeCode of ['FIXED_WRITER_CUSTODY_BIRTH_CHAIN_INVALID', '/private/secret-token', undefined]) {
    const f = model({ beforeStoragePermit: async () => { throw Object.assign(new Error('private native payload'), { code: nativeCode }); } });
    try {
      f.ready();await assert.rejects(f.writer.nativeReady, error => {
        assert.equal(error.code, 'verification_darwin_storage_guardian_permit');
        assert.equal(error.native_code, nativeCode === 'FIXED_WRITER_CUSTODY_BIRTH_CHAIN_INVALID' ? nativeCode : undefined);
        assert.equal(JSON.stringify(error).includes('private'), false);return true;
      });await flush();
      assert.equal(f.controls.includes('P\n'), false);assert.ok(f.errors.includes('verification_darwin_storage_guardian_permit'));
      assert.equal(f.writer.storageSnapshot().writer_exit_observed, false);assert.deepEqual(f.exits, []);
    } finally { await f.dispose(); }
  }
});

test('abnormal guardian loss notifies admission owner before stopped storage can produce IPC EOF', async () => {
  const f = model();
  try {
    f.ready();await f.writer.nativeReady;
    f.guardian.emit('exit', null, 'SIGKILL');
    assert.ok(f.errors.includes('verification_darwin_storage_guardian_lost'));
    assert.equal(f.writer.storageSnapshot().writer_exit_observed, false);assert.deepEqual(f.exits, []);
    assert.ok(f.calls.some(row => row[0] === 'spawn' && row[2][0] === '--stop-storage'));
  } finally { await f.dispose(); }
});

test('already-running storage stop helper is bounded by the same shorter cleanup epoch without false writer finality', async () => {
  for (const helperKillThrows of [false, true]) {
    const f = model({}, { hangHelper: true, helperKillThrows });
    try {
    f.ready();await f.writer.nativeReady;
    f.guardian.emit('exit', null, 'SIGKILL');assert.equal(f.helpers.length, 1);
    const helper = f.helpers[0];
    f.writer.stopWithin(process.hrtime.bigint() + 30000000n);
    await new Promise(resolve => setTimeout(resolve, 80));
    assert.ok(f.calls.some(row => row[0] === 'kill' && row[1] === helper.pid && row[2] === 'SIGKILL'));
    assert.ok(f.calls.some(row => row[0] === 'unref' && row[1] === helper.pid));
    assert.equal(helper.stdout.destroyed, true);
    assert.equal(f.writer.storageSnapshot().writer_exit_observed, false);assert.deepEqual(f.exits, []);
    // Neither later child exit nor output closure retroactively authorizes an
    // abandoned, deadline-expired writer observation.
    helper.emit('exit', 0, null);helper.stdout.emit('end');await flush();
    assert.equal(f.writer.storageSnapshot().writer_exit_observed, false);assert.deepEqual(f.exits, []);
    } finally { await f.dispose(); }
  }
});

test('macOS operation permit requires native workspace sandbox and exact configured-root digest', async () => {
  const f = model({ macosWorkerRoot: '/protected/package', macosWritableRoot: '/work/project', beforeMacOSPermit: async () => {} });
  try {
    assert.equal(f.guardArgs.length, 9);assert.equal(f.guardArgs[8], '/work/project');
    f.ready({ writer_sandbox: 'workspace.v1', writable_root_sha256: sha('/work/project') });
    await f.writer.nativeReady;
    assert.equal(f.writer.storageSnapshot().writer_sandbox, 'workspace.v1');assert.equal(f.controls.includes('P\n'), true);
  } finally { await f.dispose(); }
  for (const observation of [{}, { writer_sandbox: 'none', writable_root_sha256: null },
    { writer_sandbox: 'workspace.v1', writable_root_sha256: sha('/work/elsewhere') }]) {
    const rejected = model({ macosWorkerRoot: '/protected/package', macosWritableRoot: '/work/project', beforeMacOSPermit: async () => {} });
    try {
      rejected.ready(observation);await assert.rejects(rejected.writer.nativeReady);await flush();
      assert.equal(rejected.controls.includes('P\n'), false);assert.equal(rejected.writer.storageSnapshot().writer_exit_observed, false);
    } finally { await rejected.dispose(); }
  }
});

test('macOS authority role remains separately attested and cannot masquerade as a confined operation writer', async () => {
  const f = model({ macosWorkerRoot: '/protected/package', beforeMacOSPermit: async () => {} });
  try {
    assert.equal(f.guardArgs.length, 8);
    f.ready({ writer_sandbox: 'none', writable_root_sha256: null });await f.writer.nativeReady;
    assert.equal(f.writer.storageSnapshot().writer_sandbox, 'none');assert.equal(f.controls.includes('P\n'), true);
  } finally { await f.dispose(); }
});
