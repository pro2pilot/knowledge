'use strict';
// Exact JavaScript capability parser with synthetic native receipts. These are
// admission regression tests, never physical namespace or cleanup evidence.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(process.env.KNOWLEDGE_TEST_NATIVE_JS_SOURCE ||
  path.join(__dirname, '../tools/lib/verification-linux-namespace.js'), 'utf8');
const protocol = 'knowledge-linux-namespace-helper.v2';
const provider = 'linux_procfs_pid_namespace_link.v1';
const root = '/synthetic-trusted/tools/lib';
const helper = { schema_version: 'knowledge-command-native-binary.v1', platform: 'linux', architecture: 'x64',
  binary: 'verification-linux-namespace', source_sha256: 'a'.repeat(64), binary_sha256: 'b'.repeat(64), binary_bytes: 123,
  executable: root + '/native/linux-x64/verification-linux-namespace' };
const ns = ino => ({ provider, ino: String(ino) });
const identity = (pid, proc, local, space) => ({ pid, proc_pid: proc, namespace_pid: local,
  start_ticks: String(1000 + proc), os_creation_time: '2026-10-28T00:00:00.000Z', pid_namespace: ns(space) });
function receipts() {
  const common = { protocol, status: 'ready', boot_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    procfs_dev: '5', namespace_identity_provider: provider, no_new_privileges: true };
  const outer = { ...common, observer_pid_namespace: ns(10), capability_profile: 'authority_none', identities: {
    controller: identity(111, 111, 111, 10), keeper: identity(222, 222, 222, 10),
    init: identity(333, 333, 1, 20), worker: identity(334, 334, 2, 20) } };
  const inner = { ...common, observer_pid_namespace: ns(20), capability_profile: 'worker_none', identities: {
    controller: identity(2, 334, 2, 20), keeper: identity(3, 335, 3, 20),
    init: identity(4, 336, 1, 30), worker: identity(5, 337, 2, 30) } };
  const closed = { protocol, status: 'closed', active_processes: 0, init_exit_observed: true, init_reaped: true };
  return [outer, inner, { ...closed }, { ...closed, probe_depth: 2 }];
}
function capability(rows, overrides = {}) {
  const calls = [], module = { exports: {} };
  const processFixture = { platform: 'linux', arch: 'x64', pid: 111, getuid: () => 1000,
    env: { PATH: '/usr/bin', LD_PRELOAD: '/synthetic-untrusted.so' }, hrtime: process.hrtime };
  const wrapped = vm.runInNewContext('(function(require,module,exports,__dirname){' + source + '\n})', {
    process: processFixture, Buffer, setTimeout, clearTimeout, console
  }, { filename: 'actual-linux-namespace-parser.js' });
  wrapped(name => name === 'child_process' ? {
    spawn() { throw new Error('This regression must never start a process'); },
    spawnSync(file, argv, options) {
      calls.push({ file, argv: [...argv], options });
      return { pid: 222, status: 0, signal: null,
        stdout: rows.map(row => JSON.stringify(row)).join('\n') + '\n', ...overrides };
    }
  } : name === 'path' ? path.posix : require(name), module, module.exports, root);
  module.exports.setInvocationHelper(helper);
  return { result: module.exports.containmentCapability(), calls };
}
test('nested capability requires fixed native self-probe and both bound cleanup receipts', () => {
  const { result, calls } = capability(receipts());
  assert.equal(result.status, 'requires_runtime_setup');
  assert.equal(result.probe_depth, 2);
  assert.equal(result.reason, 'nested_namespace_init_pidfd_exit_required');
  assert.equal(calls.length, 1); assert.deepEqual(calls[0].argv, ['--probe-nested']);
  assert.equal(calls[0].options.timeout, 20000);
  assert.equal(calls[0].options.maxBuffer, 65536);
  assert.equal(calls[0].options.env.LD_PRELOAD, undefined);
});
const mutations = [
  ['single-level successful probe', rows => [rows[0], rows[2]]],
  ['swapped drain receipts', rows => [rows[0], rows[1], rows[3], rows[2]]],
  ['extra receipt', rows => [...rows, rows[3]]],
  ['interleaved outer started receipt', rows => [rows[0], { protocol, status: 'started' }, ...rows.slice(1)]],
  ['wrong protocol', rows => { rows[1].protocol += '-foreign'; return rows; }],
  ['unreaped inner init', rows => { rows[2].init_reaped = false; return rows; }],
  ['unobserved outer init', rows => { rows[3].init_exit_observed = false; return rows; }],
  ['nested marker on inner receipt', rows => { rows[2].probe_depth = 2; return rows; }],
  ['wrong nested observer namespace', rows => { rows[1].observer_pid_namespace = ns(99); return rows; }],
  ['keeper substituted for authority', rows => { rows[1].identities.keeper.proc_pid = rows[0].identities.worker.proc_pid; return rows; }],
  ['keeper substituted for capability-full init', rows => { rows[1].identities.keeper.proc_pid = rows[0].identities.init.proc_pid; return rows; }],
  ['changed authority controller birth', rows => { rows[1].identities.controller.start_ticks += '1'; return rows; }],
  ['capability-full init substituted as controller', rows => { rows[1].identities.controller = identity(1,333,1,20); return rows; }],
  ['wrong outer controller', rows => { rows[0].identities.controller.pid += 1; return rows; }],
  ['wrong outer keeper', rows => { rows[0].identities.keeper.pid += 1; return rows; }],
  ['worker granted authority profile', rows => { rows[1].capability_profile = 'authority_none'; return rows; }]
];
for (const [name, mutate] of mutations) test('nested capability rejects ' + name, () => {
  assert.equal(capability(mutate(receipts())).result.status, 'unavailable');
});
test('native nested denial keeps the original failure instead of promoting outer ready', () => {
  const rows = receipts();
  const result = capability([rows[0], { protocol, status: 'unconfirmed', code: 'namespace_create_denied', errno: 1 }], { status: 1 }).result;
  assert.equal(result.status, 'unavailable'); assert.equal(result.reason, 'namespace_create_denied');
});
test('a late/nonzero helper cannot qualify even with complete-looking receipts', () => {
  assert.equal(capability(receipts(), { status: 1 }).result.status, 'unavailable');
  assert.equal(capability(receipts(), { error: { code: 'ETIMEDOUT' }, status: null }).result.status, 'unavailable');
});
