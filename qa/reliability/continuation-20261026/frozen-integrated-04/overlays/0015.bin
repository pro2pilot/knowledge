'use strict';
// Portable coordinator contract tests. The exact product module and inert-data
// reader run unchanged in an isolated module closure; native observations,
// child transport and monotonic elapsed time are explicit models. These tests
// do not qualify an OS, native process death or physical I/O cancellation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');

const source = process.env.KNOWLEDGE_SCOPE_QUERY_TEST_SOURCE || path.join(__dirname, '..');
const target = path.join(source, 'tools/lib/command-scope-proof.js');
const targetCode = fs.readFileSync(target, 'utf8');
const sourceRequire = createRequire(target);
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const outside = () => ({ status: 'unconfirmed', method: 'model-native-observation', code: 'command_scope_observer_outside_lineage' });
const completed = () => ({ status: 'completed', method: 'model-native-observation', proof_marker: 'preserved' });

function fixture(options = {}) {
  let now = 1000000000n;
  const localCalls = [], transportCalls = [];
  const advance = ms => { now += BigInt(Math.round(ms * 1000000)); };
  const namespace = { provider: 'linux_nsfs_stat.v1', dev: '4', ino: '5' };
  const identity = (pid, chain = [pid]) => ({ pid, proc_pid: chain[0], namespace_pid: chain[chain.length - 1], proc_pid_chain: chain });
  const scope = {
    schema_version: 'knowledge-command-scope.v1', backend: 'linux_pid_namespace',
    descriptor: { schema_version: 'model-linux-descriptor.v1', observer_pid_namespace: namespace,
      controller: identity(101), keeper: identity(102), init: identity(103, [103, 1]), worker: identity(104, [104, 2]) },
    observer_lineage: [{ namespace, depth: 1 }]
  };
  const native = {
    validDescriptor(value) { advance(options.validationMs || 0); return value?.schema_version === 'model-linux-descriptor.v1' && !options.invalidScope; },
    validNamespaceIdentity(value) { return value?.provider === namespace.provider && value.dev === namespace.dev && value.ino === namespace.ino; },
    sameNamespaceIdentity(left, right) { return JSON.stringify(left) === JSON.stringify(right); },
    queryCommandScope(_descriptor, _lineage, request) {
      localCalls.push({ ...request }); advance(options.localMs || 0);
      return options.localProof || outside();
    }
  };
  function spawnSync(executable, args, request) {
    const input = JSON.parse(request.input);
    transportCalls.push({ executable, args, request, input });
    advance(options.relayMs || 0);
    const response = { scope_sha256: options.wrongDigest ? '0'.repeat(64) : digest(input.scope), proof: options.relayProof || completed() };
    return { status: options.exitStatus ?? 0, stdout: options.malformed ? '{' : JSON.stringify(response),
      error: options.spawnError ? Object.assign(new Error('modeled transport timeout'), { code: 'ETIMEDOUT' }) : undefined };
  }
  const modeledProcess = { platform: 'linux', execPath: process.execPath,
    env: { NODE_OPTIONS: '--require forbidden', NODE_PATH: 'forbidden', RETAINED_SETTING: 'yes' },
    hrtime: { bigint: () => now } };
  const module = { exports: {} };
  function modeledRequire(name) {
    if (name === './verification-linux-namespace') return native;
    if (name === 'child_process') return { spawnSync };
    return sourceRequire(name);
  }
  const compile = vm.runInThisContext('(function(require,module,exports,process,__dirname,__filename){\n' + targetCode + '\n})', { filename: target });
  compile(modeledRequire, module, module.exports, modeledProcess, path.dirname(target), target);
  module.exports.setScopeProofRelay({ address: { host: '127.0.0.1', port: 32123 }, token: 'a'.repeat(64) });
  return { api: module.exports, scope, localCalls, transportCalls };
}

function assertTimeout(result, scope) {
  assert.equal(result.status, 'unconfirmed');
  assert.equal(result.code, 'command_scope_query_timeout');
  assert.equal(result.scope_sha256, digest(scope));
}

test('modeled scope query exhaustion prevents a new relay invocation', () => {
  const f = fixture({ localMs: 101 });
  const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
  assert.equal(f.localCalls.length, 1);
  assert.equal(f.transportCalls.length, 0, 'A completed local wait cannot authorize a new transport budget');
  assertTimeout(result, f.scope);
});

test('modeled relay receives only the fractional remaining allowance without transport grace', () => {
  const f = fixture({ localMs: 60.25, relayMs: 20 });
  const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100.9 });
  assert.equal(f.localCalls[0].timeoutMs, 100);
  assert.equal(f.transportCalls.length, 1);
  const sent = f.transportCalls[0];
  assert.equal(sent.input.timeoutMs, 39);
  assert.equal(sent.request.timeout, 39);
  assert.equal(sent.request.killSignal, 'SIGKILL');
  assert.equal(result.status, 'completed');
  assert.equal(result.proof_marker, 'preserved');
  assert.equal(result.scope_sha256, digest(f.scope));
});

test('modeled late positive relay reply cannot authorize closure', () => {
  const f = fixture({ localMs: 40, relayMs: 61 });
  const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
  assert.equal(f.transportCalls.length, 1);
  assertTimeout(result, f.scope);
});

test('modeled late local positive reply cannot authorize closure', () => {
  const f = fixture({ localMs: 101, localProof: completed() });
  const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
  assert.equal(f.transportCalls.length, 0);
  assertTimeout(result, f.scope);
});

test('modeled submillisecond remainder cannot start a relay with a fresh millisecond', () => {
  const f = fixture({ localMs: 99.5 });
  const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100.9 });
  assert.equal(f.transportCalls.length, 0);
  assertTimeout(result, f.scope);
});

test('modeled scope validation consumes the original query allowance', () => {
  const f = fixture({ validationMs: 45, localMs: 1, localProof: completed() });
  const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
  assert.equal(f.localCalls[0].timeoutMs, 55);
  assert.equal(result.status, 'completed');
  assert.equal(result.proof_marker, 'preserved');
});

test('modeled exhausted validation cannot admit a native query', () => {
  const f = fixture({ validationMs: 101, localProof: completed() });
  const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
  assert.equal(f.localCalls.length, 0);
  assert.equal(f.transportCalls.length, 0);
  assertTimeout(result, f.scope);
});

test('modeled timely native replies and local-only lineage refusal keep their meaning', () => {
  const successful = fixture({ localMs: 99.5, localProof: completed() });
  const positive = successful.api.queryScopeClosure(successful.scope, { timeoutMs: 100 });
  assert.equal(positive.status, 'completed');
  assert.equal(positive.proof_marker, 'preserved');
  assert.equal(positive.scope_sha256, digest(successful.scope));
  assert.equal(successful.transportCalls.length, 0);
  const localOnly = fixture({ localMs: 4 });
  const refusal = localOnly.api.queryScopeClosure(localOnly.scope, { timeoutMs: 100, localOnly: true });
  assert.equal(refusal.code, 'command_scope_observer_outside_lineage');
  assert.equal(localOnly.transportCalls.length, 0);
});

test('modeled relay preserves digest, transport-status and proof-status admission predicates', () => {
  for (const options of [{ wrongDigest: true }, { exitStatus: 1 }, { spawnError: true }, { malformed: true }, { relayProof: { status: 'invented' } }]) {
    const f = fixture(options);
    const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
    assert.equal(result.status, 'unconfirmed');
    assert.equal(result.code, 'command_scope_relay_unconfirmed');
    assert.equal(result.scope_sha256, digest(f.scope));
    assert.equal(f.transportCalls.length, 1);
    assert.equal(f.transportCalls[0].request.env.NODE_OPTIONS, undefined);
    assert.equal(f.transportCalls[0].request.env.NODE_PATH, undefined);
    assert.equal(f.transportCalls[0].request.env.RETAINED_SETTING, 'yes');
  }
});

test('modeled reused namespace coordinate refusal can be resolved only by the fixed outer observer', () => {
  for (const code of ['native_proc_visibility_unconfirmed', 'native_observer_translation_unconfirmed', 'native_pidfd_identity_unconfirmed']) {
    const f = fixture({ localMs: 12.25, localProof: { status: 'unconfirmed', method: 'linux_pid_namespace', code }, relayMs: 10 });
    const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
    assert.equal(f.transportCalls.length, 1, 'An ambiguous local coordinate must permit an independent fixed observer');
    assert.equal(f.transportCalls[0].input.timeoutMs, 87, 'The second observation shares the original deadline');
    assert.equal(result.status, 'completed');
    assert.equal(result.proof_marker, 'preserved');
    assert.equal(result.scope_sha256, digest(f.scope));
  }
});

test('modeled ambiguous local observation remains unknown without a confirmed relay proof', () => {
  const localProof = { status: 'unconfirmed', method: 'linux_pid_namespace', code: 'native_proc_visibility_unconfirmed' };
  for (const relayProof of [localProof, { status: 'active', method: 'linux_pid_namespace' }]) {
    const f = fixture({ localProof, relayProof });
    const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
    assert.equal(f.transportCalls.length, 1);
    assert.equal(result.status, relayProof.status);
    assert.notEqual(result.status, 'completed');
  }
  const only = fixture({ localProof });
  assert.equal(only.api.queryScopeClosure(only.scope, { timeoutMs: 100, localOnly: true }).code, localProof.code);
  assert.equal(only.transportCalls.length, 0);
});

test('modeled active local scope is never overridden by an outer closure reply', () => {
  const f = fixture({ localProof: { status: 'active', method: 'linux_pid_namespace' }, relayProof: completed() });
  assert.equal(f.api.queryScopeClosure(f.scope, { timeoutMs: 100 }).status, 'active');
  assert.equal(f.transportCalls.length, 0);
});

test('modeled local helper integrity or cleanup failure cannot be masked by an outer observer', () => {
  for (const localProof of [
    { status: 'unconfirmed', code: 'native_helper_pin_mismatch' },
    { status: 'unconfirmed', code: 'command_native_snapshot_cleanup_unconfirmed', artifact_cleanup: { status: 'unconfirmed' } },
    { status: 'unconfirmed', code: 'native_proc_visibility_unconfirmed', artifact_cleanup: { status: 'unconfirmed' } }
  ]) {
    const f = fixture({ localProof, relayProof: completed() });
    const result = f.api.queryScopeClosure(f.scope, { timeoutMs: 100 });
    assert.equal(result.status, 'unconfirmed');
    assert.equal(result.code, localProof.code);
    assert.equal(f.transportCalls.length, 0);
  }
});

test('modeled invalid scope and invalid time budgets remain refused without observations', () => {
  const invalidScope = fixture({ invalidScope: true });
  assert.equal(invalidScope.api.queryScopeClosure(invalidScope.scope, { timeoutMs: 100 }).code, 'command_scope_invalid');
  assert.equal(invalidScope.localCalls.length, 0);
  assert.equal(invalidScope.transportCalls.length, 0);
  for (const timeoutMs of [0, 0.9, -1, 600001, Infinity, NaN]) {
    const f = fixture();
    assert.equal(f.api.queryScopeClosure(f.scope, { timeoutMs }).code, 'command_scope_invalid');
    assert.equal(f.localCalls.length, 0);
    assert.equal(f.transportCalls.length, 0);
  }
});
