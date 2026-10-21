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
  let invoked = false;
  assert.throws(() => client.nativeEnv({ get PATH() { invoked = true; return '/tmp'; } }),
    { code: 'verification_darwin_environment_invalid' });
  assert.equal(invoked, false);
  assert.throws(() => client.nativeEnv(new Proxy({}, { ownKeys() { invoked = true; return []; } })),
    { code: 'verification_darwin_environment_invalid' });
  assert.equal(invoked, false);
});

test('the actual native process environment is accepted without weakening caller data admission', () => {
  const before = Object.getOwnPropertyDescriptors(process.env);
  const result = client.nativeEnv();
  assert.equal(Object.getPrototypeOf(result), null);
  // Never dump host environment values into a failing TAP assertion.
  assert.equal(JSON.stringify(Object.getOwnPropertyDescriptors(process.env)) === JSON.stringify(before), true,
    'host environment unchanged');
  assert.ok(Object.values(result).every(value => typeof value === 'string'));
  assert.ok(Object.keys(result).every(key => !/^(?:DYLD_|LD_)/i.test(key) &&
    !/^(?:NODE_OPTIONS|NODE_PATH|BASH_ENV|ENV)$/i.test(key)));
  assert.throws(() => client.nativeEnv(Object.assign(Object.create({ custom: true }), { PATH: '/bin' })),
    { code: 'verification_darwin_environment_invalid' });
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
    stub_source_sha256: '0'.repeat(64), stub_binary_sha256: '0'.repeat(64), stub_wire_version: 'KVS1', allowed_runtimes: {} }));
  const expectedFailure = fs.existsSync(SOURCE)
    ? 'verification_darwin_source_pin_mismatch'
    : 'verification_darwin_source_unavailable';
  assert.throws(() => client.decodeReply(validShape), { code: expectedFailure });
  if (fs.existsSync(SOURCE)) {
    const source_sha256 = crypto.createHash('sha256').update(fs.readFileSync(SOURCE)).digest('hex');
    const stub_source_sha256 = crypto.createHash('sha256').update(fs.readFileSync(STUB_SOURCE)).digest('hex');
    const unqualified = { ...historyMetadata(), schema: client.SCHEMA, ok: true, source_sha256,
      capability_qualified: false, qualification_mode: false, registry_healthy: true, binary_sha256: '0'.repeat(64),
      stub_source_sha256, stub_binary_sha256: '0'.repeat(64), stub_wire_version: 'KVS1', allowed_runtimes: {} };
    const decoded = client.decodeReply(Buffer.from(JSON.stringify(unqualified)));
    assert.equal(Object.getPrototypeOf(decoded), null);
    assert.deepEqual(JSON.parse(JSON.stringify(decoded)), unqualified);
    // Parsing an honest negative capability never changes it into an admission.
    assert.equal(client.decodeReply(Buffer.from(JSON.stringify(unqualified))).capability_qualified, false);
    for (const patch of [{ qa_persistence_gate: false, qa_build_id: null },
      { qa_persistence_gate: true, qa_build_id: 'a'.repeat(64) }]) {
      const qa = client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, ...patch })));
      assert.equal(qa.qa_persistence_gate, patch.qa_persistence_gate);
      assert.equal(qa.capability_qualified, false);
    }
    for (const patch of [{ qa_persistence_gate: true }, { qa_build_id: null },
      { qa_persistence_gate: false, qa_build_id: 'a'.repeat(64) },
      { qa_persistence_gate: true, qa_build_id: 'unverified' },
      { qa_persistence_gate: 1, qa_build_id: null }]) {
      assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, ...patch }))),
        { code: 'verification_darwin_protocol_invalid' });
    }
    assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, stub_source_sha256: '0'.repeat(64) }))),
      { code: 'verification_darwin_stub_source_pin_mismatch' });
    assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, transport_header_sha256: '0'.repeat(64) }))),
      { code: 'verification_darwin_transport_source_pin_mismatch' });
    for (const value of [undefined, null, 1, true, 'bad']) {
      assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, transport_header_sha256: value }))),
        { code: 'verification_darwin_protocol_invalid' });
    }
    for (const patch of [{ stub_wire_version: 'KVS2' }, { stub_binary_sha256: null }, { qualification_mode: 'false' }]) {
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
  const virtualFd = 0x7ffffffe;
  const stat = isFile => ({ uid: 0, mode: 0o755, nlink: 1, dev: 1, ino: 2, size: 1,
    isSymbolicLink: () => false, isFile: () => isFile, isDirectory: () => !isFile });
  const adaptedFs = { ...fs,
    lstatSync: p => p === '/audit' ? stat(false) : p === '/audit/broker' ? stat(true) : fs.lstatSync(p),
    openSync: p => { assert.equal(p, '/audit/broker'); return virtualFd; },
    fstatSync: fd => { assert.equal(fd, virtualFd); return stat(true); },
    closeSync: fd => assert.equal(fd, virtualFd),
    readFileSync: (...args) => args[0] === virtualFd ? Buffer.from('b') : fs.readFileSync(...args)
  };
  const calls = [];
  const adaptedRequire = name => name === 'fs' ? adaptedFs : name === 'child_process' ? {
    spawnSync: (...args) => {
      calls.push(args);
      // Use the real host transport options with binary non-UTF8 output. The
      // native service itself remains unexercised by this portable test.
      const child = require('node:child_process').spawnSync(process.execPath,
        ['-e', 'if(require("node:fs").readFileSync(0,"utf8")!==JSON.stringify({op:"probe"}))process.exit(9);'+
          'process.stdout.write(Buffer.from([255,0,97]));process.stderr.write(Buffer.from([254,0,98]))'], args[2]);
      assert.equal(child.status, 0);
      assert.equal(child.error, undefined);
      assert.equal(Buffer.isBuffer(child.stdout), true);
      assert.equal(child.stdout.equals(Buffer.from([255, 0, 97])), true);
      assert.equal(Buffer.isBuffer(child.stderr), true);
      assert.equal(child.stderr.equals(Buffer.from([254, 0, 98])), true);
      return { status: 1, stdout: Buffer.alloc(0) };
    }
  } : actualRequire(name);
  const module = { exports: {} };
  const wrapper = vm.runInNewContext('(function(require,module,exports,__filename,__dirname){' +
    fs.readFileSync(file, 'utf8') + '\n})', { Buffer, TextDecoder,
      process: { platform: 'darwin', execPath: process.execPath, env: {} } });
  wrapper(adaptedRequire, module, module.exports, file, path.dirname(file));
  const result = module.exports.containmentCapability({ darwin: { enabled: true, mode: 'isolated_copy',
    broker_path: '/audit/broker', broker_socket: '/audit/broker.sock', copy: {} } });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.reason, 'broker_probe_failed');
  assert.throws(() => module.exports.diagnosticProbe({ darwin: { enabled: true, mode: 'isolated_copy',
    broker_path: '/audit/broker', broker_socket: '/audit/broker.sock', copy: {} } }),
  { code: 'verification_darwin_probe_failed' });
  assert.equal(calls.length, 2);
  const [binary, argv, options] = calls[0];
  assert.equal(binary, '/audit/broker');
  const flag = name => Number(argv.find(x => x.startsWith(name + '=')).split('=')[1]);
  assert.ok(flag('--lifecycle-timeout-ms') >= 120_000);
  assert.ok(flag('--transport-timeout-ms') >= 30_000);
  assert.ok(options.timeout >= flag('--lifecycle-timeout-ms'));
  assert.equal(options.shell, false);
  assert.equal(options.input, '{"op":"probe"}');
});
