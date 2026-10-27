'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { test } = require('node:test');

const client = require('../tools/lib/verification-darwin-client');
const SOURCE = path.join(__dirname, '../tools/lib/verification-darwin-broker.m');
const STUB_SOURCE = path.join(__dirname, '../tools/lib/verification-darwin-stub.c');
const sourceHash = file => crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, '../tools/lib', file))).digest('hex');
function historyMetadata() {
  const host_id = '00000000-0000-0000-0000-000000000001';
  return { host_id, boot_id: 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA', entry_store_loaded: true,
    daemon_epoch: '4'.repeat(64), guardian_protocol: 'KVR2', qa_persistence_gate: false, qa_build_id: null,
    transport_header_sha256: sourceHash('verification-darwin-transport.h'),
    registry_quarantine_reason: null,
    account_policy: { id: 'admin_reserved_interval_no_runtime_nss.v1', healthy: true, reason: 'HEALTHY',
      sha256: '3'.repeat(64), configured_owner_count: 1, runtime_directory_lookups: false },
    uid_history: { healthy_cached: true, reason: 'HEALTHY', health_source: 'disk_refresh_attempt',
      last_refresh_attempt_started_monotonic_ms: 123,
      installation_id_cached: '1'.repeat(64),
      checkpoint_cached: { schema: 'knowledge-darwin-uid-checkpoint.v1', installation_id: '1'.repeat(64),
        host_id, seq: '0', tip_sha256: '0'.repeat(64), next_uid: 1000000000 },
      header_sha256: sourceHash('verification-darwin-uid-history.h'),
      source_sha256: sourceHash('verification-darwin-uid-history.m') } };
}

test('configuration is explicit, inert, strict, and normalizes copy limits', () => {
  assert.deepEqual(client.config(), { darwin: { enabled: false } });
  assert.deepEqual(client.config({}), { darwin: { enabled: false } });
  assert.deepEqual(client.config({ darwin: { enabled: false } }), { darwin: { enabled: false } });
  const normalized = client.config({ darwin: { enabled: true, mode: 'isolated_copy',
    broker_path: '/Library/Application Support/KnowledgeVerification/broker',
    broker_socket: '/Library/Application Support/KnowledgeVerification/control/broker.sock',
    copy: { max_files: 3, max_bytes: 8192, max_file_bytes: 4096 } } });
  assert.equal(normalized.darwin.enabled, true);
  assert.equal(normalized.darwin.mode, 'isolated_copy');
  assert.deepEqual(normalized.darwin.copy, { max_files: 3, max_bytes: 8192, max_file_bytes: 4096 });

  for (const invalid of [
    { darwin: { enabled: true } },
    { darwin: { enabled: true, mode: 'process_group', broker_path: '/a/b', broker_socket: '/a/s', copy: {} } },
    { darwin: { enabled: false, mode: 'isolated_copy' } },
    { darwin: { enabled: true, mode: 'isolated_copy', broker_path: 'C:\\broker', broker_socket: '/a/s', copy: {} } },
    { darwin: { enabled: true, mode: 'isolated_copy', broker_path: '/a/../b', broker_socket: '/a/s', copy: {} } },
    { darwin: { enabled: true, mode: 'isolated_copy', broker_path: '/a/b/', broker_socket: '/a/s', copy: {} } },
    { darwin: { enabled: true, mode: 'isolated_copy', broker_path: '/a//b', broker_socket: '/a/s', copy: {} } },
    { darwin: { enabled: true, mode: 'isolated_copy', broker_path: '/a/b', broker_socket: '/a/s', copy: { max_bytes: 1, unexpected: true } } },
    { darwin: { enabled: true, mode: 'isolated_copy', broker_path: '/a/b', broker_socket: '/'.padEnd(105, 's'), copy: {} } },
    { darwin: { enabled: true, mode: 'isolated_copy', broker_path: '/a/b', broker_socket: '/a/s', copy: {} }, unexpected: true }
  ]) assert.throws(() => client.config(invalid), { code: 'verification_darwin_config_invalid' });

  let invoked = false;
  const accessor = { get darwin() { invoked = true; return { enabled: false }; } };
  assert.throws(() => client.config(accessor), { code: 'verification_darwin_config_invalid' });
  assert.equal(invoked, false);
  assert.throws(() => client.config(new Proxy({}, {})), { code: 'verification_darwin_config_invalid' });
});

test('native environment removes dynamic loader and script injection variables without mutation', () => {
  const input = { PATH: '/usr/bin', HOME: '/Users/test', DYLD_INSERT_LIBRARIES: '/tmp/x.dylib',
    DYLD_LIBRARY_PATH: '/tmp', LD_PRELOAD: '/tmp/x.so', NODE_OPTIONS: '--require x', NODE_PATH: '/tmp/node',
    BASH_ENV: '/tmp/bashrc', ENV: '/tmp/envrc' };
  const before = { ...input };
  assert.deepEqual({ ...client.nativeEnv(input) }, { PATH: '/usr/bin', HOME: '/Users/test' });
  assert.deepEqual(input, before);
  assert.throws(() => client.nativeEnv({ PATH: 7 }), { code: 'verification_darwin_environment_invalid' });
});

test('reply decoder rejects oversized, malformed, unknown, and mistyped protocol bodies', () => {
  assert.throws(() => client.decodeReply(Buffer.alloc(client.MAX_REPLY_BYTES + 1)), {
    code: 'verification_darwin_reply_oversized'
  });
  assert.throws(() => client.decodeReply(Buffer.from('{')), { code: 'verification_darwin_protocol_invalid' });
  assert.throws(() => client.decodeReply(Buffer.from('{"schema":"other","ok":true,"source_sha256":"' + '0'.repeat(64) + '"}')),
    { code: 'verification_darwin_protocol_invalid' });
  assert.throws(() => client.decodeReply(Buffer.from('{"schema":"knowledge-darwin-broker.v1","ok":"yes","source_sha256":"' + '0'.repeat(64) + '"}')),
    { code: 'verification_darwin_protocol_invalid' });
  assert.throws(() => client.decodeReply(Buffer.from('{"schema":"knowledge-darwin-broker.v1","ok":true,"source_sha256":"' + '0'.repeat(64) + '","capability_qualified":"false","registry_healthy":true,"binary_sha256":"' + '0'.repeat(64) + '","allowed_runtimes":{}}')),
    { code: 'verification_darwin_protocol_invalid' });
  assert.throws(() => client.decodeReply(Buffer.from('{"schema":"knowledge-darwin-broker.v1","ok":true,"source_sha256":"' + '0'.repeat(64) + '","extra":1}')),
    { code: 'verification_darwin_protocol_invalid' });

  const validShape = Buffer.from(JSON.stringify({ ...historyMetadata(), schema: client.SCHEMA, ok: true, source_sha256: '0'.repeat(64),
    capability_qualified: false, qualification_mode: false, registry_healthy: true, binary_sha256: '0'.repeat(64),
    stub_source_sha256: '0'.repeat(64), stub_binary_sha256: '0'.repeat(64), stub_wire_version: 'KVS2', allowed_runtimes: {} }));
  const expectedFailure = fs.existsSync(SOURCE)
    ? 'verification_darwin_source_pin_mismatch'
    : 'verification_darwin_source_unavailable';
  assert.throws(() => client.decodeReply(validShape), { code: expectedFailure });
  if (fs.existsSync(SOURCE)) {
    const source_sha256 = crypto.createHash('sha256').update(fs.readFileSync(SOURCE)).digest('hex');
    const stub_source_sha256 = crypto.createHash('sha256').update(fs.readFileSync(STUB_SOURCE)).digest('hex');
    const unqualified = { ...historyMetadata(), schema: client.SCHEMA, ok: true, source_sha256,
      capability_qualified: false, qualification_mode: false, registry_healthy: true, binary_sha256: '0'.repeat(64),
      stub_source_sha256, stub_binary_sha256: '0'.repeat(64), stub_wire_version: 'KVS2', allowed_runtimes: {} };
    const decoded = client.decodeReply(Buffer.from(JSON.stringify(unqualified)));
    assert.equal(Object.getPrototypeOf(decoded), null);
    assert.deepEqual(JSON.parse(JSON.stringify(decoded)), unqualified);
    // Parsing an honest negative capability never changes it into an admission.
    assert.equal(client.decodeReply(Buffer.from(JSON.stringify(unqualified))).capability_qualified, false);
    assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, stub_source_sha256: '0'.repeat(64) }))),
      { code: 'verification_darwin_stub_source_pin_mismatch' });
    assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, transport_header_sha256: '0'.repeat(64) }))),
      { code: 'verification_darwin_transport_source_pin_mismatch' });
    for (const value of [undefined, null, 1, true, 'bad']) {
      assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, transport_header_sha256: value }))),
        { code: 'verification_darwin_protocol_invalid' });
    }
    // Execution migrates to KVS2/KVR2; KVS1 remains cleanup-only in the native
    // registry and is still rejected by current production probe admission.
    for (const patch of [{ stub_wire_version: 'KVS1' }, { stub_binary_sha256: null }, { qualification_mode: 'false' },
      { daemon_epoch: null }, { guardian_protocol: 'KVR1' }, { qa_persistence_gate: 1 },
      { qa_persistence_gate: true, qa_build_id: null }]) {
      assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, ...patch }))),
        { code: 'verification_darwin_protocol_invalid' });
    }
    for (const patch of [
      { entry_store_loaded: 'true' }, { host_id: null }, { boot_id: [] }, { registry_quarantine_reason: 1 },
      { registry_quarantine_reason: 'raw unexpected detail' },
      { registry_quarantine_reason: 'ENTRY_STORE_MISSING_OR_CHANGED' },
      { uid_history: { ...unqualified.uid_history, healthy_cached: 'true' } },
      { uid_history: { ...unqualified.uid_history, health_source: 'heartbeat' } },
      { uid_history: { ...unqualified.uid_history, last_refresh_attempt_started_monotonic_ms: true } },
      { uid_history: { ...unqualified.uid_history, checkpoint_cached: null } },
      { uid_history: { ...unqualified.uid_history, checkpoint_cached: {
        ...unqualified.uid_history.checkpoint_cached, installation_id: '2'.repeat(64) } } },
      { uid_history: { ...unqualified.uid_history, checkpoint_cached: {
        ...unqualified.uid_history.checkpoint_cached, host_id: '00000000-0000-0000-0000-000000000002' } } },
      { uid_history: { ...unqualified.uid_history, checkpoint_cached: {
        ...unqualified.uid_history.checkpoint_cached, seq: '00' } } },
      { uid_history: { ...unqualified.uid_history, checkpoint_cached: {
        ...unqualified.uid_history.checkpoint_cached, next_uid: 1000000001 } } }
    ]) assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, ...patch }))),
      { code: 'verification_darwin_protocol_invalid' });
    for (const field of ['header_sha256', 'source_sha256']) {
      assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified,
        uid_history: { ...unqualified.uid_history, [field]: '0'.repeat(64) } }))),
      { code: 'verification_darwin_uid_source_pin_mismatch' });
    }
    for (const patch of [{ healthy: 1 }, { id: 'implicit_lookup' }, { sha256: null },
      { configured_owner_count: 0 }, { configured_owner_count: 65 }, { configured_owner_count: true },
      { runtime_directory_lookups: true }, { reason: 'ACCOUNT_POLICY_CHANGED' }, { extra: true }]) {
      assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified,
        account_policy: { ...unqualified.account_policy, ...patch } }))),
      { code: 'verification_darwin_protocol_invalid' });
    }
    const quarantined = { ...unqualified, registry_healthy: false, entry_store_loaded: false,
      registry_quarantine_reason: 'ENTRY_STORE_MISSING_OR_CHANGED',
      uid_history: { ...unqualified.uid_history, healthy_cached: false, reason: 'REGISTRY_CHECKPOINT_MISMATCH',
        health_source: 'cached_quarantine', checkpoint_cached: null, installation_id_cached: null,
        last_refresh_attempt_started_monotonic_ms: null } };
    assert.equal(client.decodeReply(Buffer.from(JSON.stringify(quarantined))).uid_history.healthy_cached, false);
    const policyQuarantined = { ...unqualified, account_policy: { ...unqualified.account_policy,
      healthy: false, reason: 'ACCOUNT_POLICY_MISSING_INVALID_OR_UNBOUND', sha256: null, configured_owner_count: 0 } };
    assert.equal(client.decodeReply(Buffer.from(JSON.stringify(policyQuarantined))).account_policy.healthy, false);
  }
});

test('unqualified hosts fail closed without attempting any broker process', () => {
  const original = childProcess.spawnSync;
  let calls = 0;
  childProcess.spawnSync = () => { calls++; throw new Error('platform gate failed to prevent broker launch'); };
  try {
    const result = client.containmentCapability({ darwin: { enabled: true, mode: 'isolated_copy',
      broker_path: '/definitely/missing/knowledge-broker', broker_socket: '/definitely/missing/broker.sock', copy: {} } });
    assert.equal(result.status, 'unavailable');
    assert.notEqual(result.status, 'available');
    assert.equal(calls, 0);
    if (process.platform !== 'darwin') assert.equal(result.reason, 'darwin_required');
  } finally { childProcess.spawnSync = original; }
});

test('probe wrapper preserves the helper lifecycle budget and passes both native timing limits', () => {
  // Exercise the actual macOS branch with an inert protected-file/process
  // adapter. This asserts the public launch contract, not native time keeping.
  const vm = require('node:vm');
  const { createRequire } = require('node:module');
  const file = require.resolve('../tools/lib/verification-darwin-client');
  const actualRequire = createRequire(file);
  const calls = [], protectedCalls = [];
  const adaptedRequire = name => name === './lock-publication' ? {
    verifyProtectedExecutable: (binary, options) => {
      assert.equal(binary, '/audit/broker');
      assert.equal(options.maxBytes, 268435456);
      assert.equal(options.remainingMs, 30000);
      assert.equal(calls.length, 0, 'independent protection check precedes any helper launch');
      protectedCalls.push(binary);
      // Explicit ACL/root-ancestry model; never presented as native Darwin.
      return { sha256: crypto.createHash('sha256').update('b').digest('hex') };
    }
  } : name === 'fs' ? { ...fs, readFileSync: (name, ...args) => name === '/audit/node' ?
    Buffer.from('modeled runtime bytes') : fs.readFileSync(name, ...args) } : name === 'child_process' ? {
    spawnSync: (...args) => {
      calls.push(args);
      // The OS/native program remains a fixed test responder, but production
      // stdin and encoding options go through Node's real spawnSync. A string
      // input with encoding:'buffer' must not hide ERR_UNKNOWN_ENCODING.
      return childProcess.spawnSync(process.execPath, ['-e',
        'process.stdin.resume();process.stdin.on("end",()=>process.exit(1));'], { ...args[2], env: process.env });
    }
  } : actualRequire(name);
  const module = { exports: {} };
  const wrapper = vm.runInNewContext('(function(require,module,exports,__filename,__dirname){' +
    fs.readFileSync(process.env.KNOWLEDGE_DARWIN_CLIENT_QUERY_TARGET || file, 'utf8') + '\n})', { Buffer, TextDecoder,
      process: { platform: 'darwin', execPath: '/audit/node', env: {} } });
  wrapper(adaptedRequire, module, module.exports, file, path.dirname(file));
  const result = module.exports.containmentCapability({ darwin: { enabled: true, mode: 'isolated_copy',
    broker_path: '/audit/broker', broker_socket: '/audit/broker.sock', copy: {} } });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.reason, 'broker_probe_failed');
  assert.equal(protectedCalls.length, 1);
  assert.equal(calls.length, 1);
  const [binary, argv, options] = calls[0];
  assert.equal(binary, '/audit/broker');
  const flag = name => Number(argv.find(x => x.startsWith(name + '=')).split('=')[1]);
  assert.ok(flag('--lifecycle-timeout-ms') >= 120_000);
  assert.ok(flag('--transport-timeout-ms') >= 30_000);
  assert.ok(options.timeout >= flag('--lifecycle-timeout-ms'));
  assert.equal(options.shell, false);
  assert.equal(Buffer.isBuffer(options.input), true);
  assert.equal(options.input.toString('utf8'), '{"op":"probe"}');
});
