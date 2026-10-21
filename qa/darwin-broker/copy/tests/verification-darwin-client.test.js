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

  const validShape = Buffer.from(JSON.stringify({ schema: client.SCHEMA, ok: true, source_sha256: '0'.repeat(64),
    capability_qualified: false, qualification_mode: false, registry_healthy: true, binary_sha256: '0'.repeat(64),
    stub_source_sha256: '0'.repeat(64), stub_binary_sha256: '0'.repeat(64), stub_wire_version: 'KVS1', allowed_runtimes: {} }));
  const expectedFailure = fs.existsSync(SOURCE)
    ? 'verification_darwin_source_pin_mismatch'
    : 'verification_darwin_source_unavailable';
  assert.throws(() => client.decodeReply(validShape), { code: expectedFailure });
  if (fs.existsSync(SOURCE)) {
    const source_sha256 = crypto.createHash('sha256').update(fs.readFileSync(SOURCE)).digest('hex');
    const stub_source_sha256 = crypto.createHash('sha256').update(fs.readFileSync(STUB_SOURCE)).digest('hex');
    const unqualified = { schema: client.SCHEMA, ok: true, source_sha256,
      capability_qualified: false, qualification_mode: false, registry_healthy: true, binary_sha256: '0'.repeat(64),
      stub_source_sha256, stub_binary_sha256: '0'.repeat(64), stub_wire_version: 'KVS1', allowed_runtimes: {} };
    const decoded = client.decodeReply(Buffer.from(JSON.stringify(unqualified)));
    assert.equal(Object.getPrototypeOf(decoded), null);
    assert.deepEqual(JSON.parse(JSON.stringify(decoded)), unqualified);
    // Parsing an honest negative capability never changes it into an admission.
    assert.equal(client.decodeReply(Buffer.from(JSON.stringify(unqualified))).capability_qualified, false);
    assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, stub_source_sha256: '0'.repeat(64) }))),
      { code: 'verification_darwin_stub_source_pin_mismatch' });
    for (const patch of [{ stub_wire_version: 'KVS2' }, { stub_binary_sha256: null }, { qualification_mode: 'false' }]) {
      assert.throws(() => client.decodeReply(Buffer.from(JSON.stringify({ ...unqualified, ...patch }))),
        { code: 'verification_darwin_protocol_invalid' });
    }
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
