'use strict';
// Exact JavaScript query path with explicitly modeled OS/native boundaries.
// This is not native Darwin qualification; the physical matrix is separate.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');
const filename = path.join(__dirname, '../tools/lib/verification-darwin-scope.js');
const sourceTarget = process.env.KNOWLEDGE_DARWIN_SCOPE_QUERY_TARGET || filename;
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fixtureBytes = Buffer.from('modeled stable source');
const sourceHash = sha(fixtureBytes), binaryHash = 'b'.repeat(64);
const config = { enabled: true, mode: 'isolated_copy', copy: {},
  broker_path: '/protected/broker', broker_socket: '/protected/socket' };
const host = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', boot = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
function query({ readError, protectedError, rawIdentity, transportError, realTransport = false } = {}) {
  const operations = [];
  const client = require('../tools/lib/verification-darwin-client');
  const module = new Module(filename, moduleParent());
  module.filename = filename; module.paths = Module._nodeModulePaths(path.dirname(filename));
  const originalRequire = module.require.bind(module);
  module.require = name => {
    if (name === './stable-file') return { readStableFile() { if (readError) throw readError;return fixtureBytes; } };
    if (name === './lock-publication') return { verifyProtectedExecutable() {
      if (protectedError) throw protectedError;return { sha256: binaryHash };
    } };
    if (name === './verification-darwin-client') return { ...client, nativeEnv: () => ({}), decodeReply: () => ({
      ok: true, capability_qualified: true, qualification_mode: false, qa_persistence_gate: false,
      registry_healthy: true, entry_store_loaded: true,
      uid_history: { healthy_cached: true, health_source: 'disk_refresh_attempt', installation_id_cached: 'c'.repeat(64) },
      account_policy: { healthy: true }, binary_sha256: binaryHash, stub_binary_sha256: 'd'.repeat(64),
      host_id: host, boot_id: boot, daemon_epoch: 'e'.repeat(64)
    }) };
    if (name === 'node:child_process') return { spawnSync(binary, argv, options) {
      const request = JSON.parse(options.input);operations.push(request.op);
      if (transportError) throw transportError;
      const identity = { schema: 'knowledge-darwin-process-identity.v1', host_id: host, boot_id: boot,
        owner_uid: process.getuid(), birth: { pid: process.pid, unique_id: '123', parent_unique_id: '100',
          start_sec: 1000, start_usec: 1, ruid: process.getuid(), pidversion: 10 } };
      const result = { ok: true, schema: 'knowledge-darwin-identity-observation.v1',
        observation_nonce: request.observation_nonce, host_id: host, boot_id: boot, daemon_epoch: 'e'.repeat(64),
        source_sha256: sourceHash, binary_sha256: binaryHash, capability_qualified: true, qualification_mode: false,
        qa_persistence_gate: false, proof_current: false, cleanup_only: true, observed_monotonic_ms: 2000,
        status: 'active', identity };
      const response = request.op === 'peer_identity' && rawIdentity !== undefined ? rawIdentity : JSON.stringify(result);
      if (realTransport) {
        // Preserve the exact production input/encoding/timeout options through
        // real Node spawnSync. Only the native executable is substituted with
        // this fixed harmless responder, which also consumes the whole input.
        const source = 'const fs=require("node:fs");JSON.parse(fs.readFileSync(0,"utf8"));' +
          'process.stdout.write(' + JSON.stringify(response) + ');';
        return require('node:child_process').spawnSync(process.execPath, ['-e', source], { ...options, env: process.env });
      }
      return { status: 0, signal: null, stdout: Buffer.from(response) };
    } };
    return originalRequire(name);
  };
  module._compile(fs.readFileSync(sourceTarget, 'utf8'), filename);
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  try {
    Object.defineProperty(process, 'platform', { ...platform, value: 'darwin' });
    return { value: module.exports.currentProcessIdentity(config, { timeoutMs: 5000 }), operations };
  } finally { Object.defineProperty(process, 'platform', platform); }
}
function moduleParent() { return require.cache[__filename]; }

test('modeled synchronous scope identity query reaches both native requests and validates its peer', () => {
  const { value, operations } = query();
  assert.deepEqual(operations, ['probe', 'peer_identity']);
  assert.equal(value.status, 'observed');assert.equal(value.identity.birth.pid, process.pid);
});
test('real spawnSync consumes UTF8 request bytes while its response remains a Buffer', () => {
  const { value, operations } = query({ realTransport: true });
  assert.deepEqual(operations, ['probe', 'peer_identity']);
  assert.equal(value.status, 'observed', JSON.stringify(value));
  assert.equal(value.identity.birth.pid, process.pid);
});
test('source I/O denial is fail-closed and exposes only an allowlisted diagnostic', () => {
  const { value, operations } = query({ readError: Object.assign(new Error('NEVER_PUBLIC_path_or_token'), { code: 'EACCES' }) });
  assert.deepEqual(operations, []);assert.equal(value.status, 'unconfirmed');
  assert.equal(value.code, 'verification_darwin_scope_query_unconfirmed');
  assert.deepEqual(value.query_diagnostic, { phase: 'source_read', exception: 'Error', system_code: 'EACCES' });
  assert(!JSON.stringify(value).includes('NEVER_PUBLIC'));
});
test('malformed identity reply never becomes a proof and identifies its decoder stage', () => {
  const { value } = query({ rawIdentity: '{NEVER_PUBLIC_payload' });
  assert.equal(value.status, 'unconfirmed');
  assert.deepEqual(value.query_diagnostic, { phase: 'operation_decode', exception: 'SyntaxError', system_code: null });
  assert(!JSON.stringify(value).includes('NEVER_PUBLIC'));
});
test('protected executable failure keeps the existing typed code and cannot leak exception text', () => {
  const { value, operations } = query({ protectedError: Object.assign(new Error('NEVER_PUBLIC_private_binary'),
    { code: 'darwin_protected_path_unsafe' }) });
  assert.deepEqual(operations, []);assert.equal(value.code, 'darwin_protected_path_unsafe');
  assert.equal(value.query_diagnostic.phase, 'protected_broker');assert(!JSON.stringify(value).includes('NEVER_PUBLIC'));
});
test('unknown exception metadata is discarded and native request errors stay unconfirmed', () => {
  const error = Object.assign(new Error('NEVER_PUBLIC_secret'), { name: 'NEVER_PUBLIC_exception', code: 'NEVER_PUBLIC_CODE' });
  const { value } = query({ transportError: error });
  assert.equal(value.status, 'unconfirmed');
  assert.deepEqual(value.query_diagnostic, { phase: 'probe_transport', exception: null, system_code: null });
  assert(!JSON.stringify(value).includes('NEVER_PUBLIC'));
});
