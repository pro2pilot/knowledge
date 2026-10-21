'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const path = require('node:path');
const wire = require('../tools/lib/verification-darwin-diagnostic-protocol');
const { runDiagnostic } = require('../tools/lib/verification-darwin-diagnostic');
const supervisor = require('../tools/lib/verification-supervisor');
const execution = require('../tools/lib/verification-execution');
const hex = c => c.repeat(64);
const clone = value => JSON.parse(JSON.stringify(value));
function request() {
  const repoRoot = path.resolve('diagnostic-fixture');
  return { report_only: true, repoRoot, stateRoot: path.join(repoRoot, '.knowledge'),
    test: { argv: ['node', '--test', 'sample.test.js'], cwd: '.', timeout_ms: 30000 }, sourceFiles: ['sample.test.js'],
    nativeExecution: { darwin: { enabled: true, mode: 'isolated_copy', broker_path: '/Library/KV/broker',
      broker_socket: '/Library/KV/control.sock', copy: {} } },
    verificationPolicy: { work_budget_ms: 300000, cleanup_budget_ms: 60000, no_progress_ms: 0 } };
}
function binding() {
  const descriptor = { source_sha256: hex('a'), transport_header_sha256: hex('b'), installation_id: hex('c'),
    allocation_seq: '12', allocation_sha256: hex('d'), host_id: 'host', boot_id: 'boot',
    task_ruid: 1000000012,
    account_policy_id: 'admin_reserved_interval_no_runtime_nss.v1', account_policy_sha256: hex('e') };
  return { attempt_id: hex('f'), descriptor_sha256: wire.digest(descriptor), descriptor };
}
function result(b, command) {
  const d = b.descriptor;
  return { ok: true, schema: 'knowledge-darwin-command-result.v1', attempt_id: b.attempt_id,
    descriptor_sha256: b.descriptor_sha256, command_ordinal: 1, command_sha256: wire.digest(command),
    ...Object.fromEntries(['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq',
      'allocation_sha256', 'host_id', 'boot_id'].map(key => [key, d[key]])),
    timed_out: false, stop_latched: false, exit_code: 0, signal: null, admission_closed: false, capability_qualified: false };
}
function readback(b, plan) {
  const body = { schema: 'knowledge-darwin-copy-readback.v1', attempt_id: b.attempt_id,
    descriptor_sha256: b.descriptor_sha256, phase: 'commands_drained', manifest_sha256: plan.manifest_sha256,
    directories_sha256: plan.directories_sha256, workspace_identity: { device: '42', inode: '9007199254740993' },
    files: plan.files.length, directories: plan.directories.length, bytes: plan.total_bytes, verified_current: true,
    allocation_tuple_verified_current: true, observed_monotonic_ms: 12345, capability_qualified: false };
  return { ok: true, ...body, readback_sha256: wire.digest(body) };
}
function facts(b, terminal) {
  const p = { schema: terminal ? 'knowledge-darwin-private-ruid-proof.v1' : 'knowledge-darwin-command-drain-proof.v1',
    attempt_id: b.attempt_id, descriptor_sha256: b.descriptor_sha256, ...b.descriptor,
    capability_qualified: false, terminal_cleanup: terminal, kernel_membership_zero: true, admission_closed: true,
    spawn_exclusion_acquired: true, spawn_intents_resolved: true, native_cleanup_facts_confirmed: true,
    cleanup_confirmed: false, registered_authority_exited: true, native_command_drain_facts_confirmed: true,
    command_drain_confirmed: false, registered_authority_alive: true, spawn_exclusion_held_until_terminal: true,
    uid_history_tuple_verified: true, cleanup_budget_exceeded: false };
  return { ok: true, attempt_id: b.attempt_id, descriptor_sha256: b.descriptor_sha256,
    allocation_tuple_verified_current: true, registry_healthy: true, cleanup_budget_exceeded: false,
    stop_reason: 'commands_complete',
    state: terminal ? 'closed' : 'commands_drained', [terminal ? 'proof' : 'command_drain_proof']: p,
    [terminal ? 'proof_sha256' : 'command_drain_sha256']: wire.digest(p) };
}
test('diagnostic admission is inert, report-only, one canonical command and original selected state root', () => {
  const input = request();
  assert.equal(wire.request(input).report_only, true);
  assert.deepEqual(wire.request(input).sourceFiles, ['sample.test.js']);
  const subdir = request(); subdir.test.cwd = 'suite';
  assert.ok(wire.request(subdir).sourceFiles.includes('suite/sample.test.js'));
  for (const mutate of [
    x => { x.report_only = false; }, x => { x.stateRoot = path.dirname(x.stateRoot); },
    x => { x.test.argv = ['node', '-e', 'process.exit(0)']; }, x => { x.test.env = { SECRET: 'masked' }; },
    x => { x.test.argv = ['node', 'sample.test.js', '--write-back']; }, x => { x.sourceFiles = []; },
    x => { x.test.cwd = '../outside'; }, x => { x.nativeExecution.darwin.enabled = false; },
    x => { x.verificationPolicy.no_progress_ms = 10; }, x => { x.currency = true; }
  ]) { const altered = request(); mutate(altered); assert.throws(() => wire.request(altered)); }
  let getter = false;
  assert.throws(() => wire.request({ get report_only() { getter = true; return true; } }));
  assert.equal(getter, false);
  assert.throws(() => wire.request(new Proxy(input, {})));
});
test('transport exit or stdout JSON cannot replace a typed command result', () => {
  const b = binding(), command = { argv: ['/Library/KV/node', 'sample.js'], env: {}, cwd: '.', timeout_ms: 30000 };
  const good = result(b, command);
  assert.equal(wire.commandPassed(wire.commandResult(good, b, command)), true);
  for (const changed of [{ ok: true, exit_code: 0 }, { ...good, command_sha256: hex('0') },
    { ...good, attempt_id: hex('0') }, { ...good, command_ordinal: 2 }, { ...good, allocation_seq: '13' },
    { ...good, capability_qualified: true }, { ...good, signal: 'SIGTERM' }, { ...good, signal: 9 },
    { ...good, exit_code: null }, { ...good, output: 'PASS' }]) {
    assert.throws(() => wire.commandResult(changed, b, command), { code: 'darwin_diagnostic_command_result_invalid' });
  }
  for (const changed of [{ ...good, exit_code: 1 }, { ...good, timed_out: true },
    { ...good, stop_latched: true }, { ...good, admission_closed: true }, { ...good, exit_code: null, signal: 9 }]) {
    assert.equal(wire.commandPassed(wire.commandResult(changed, b, command)), false);
  }
});
test('copy readback is current, phase-bound and digest-bound with lossless inode strings', () => {
  const b = binding(), plan = { files: [{}], directories: ['suite'], total_bytes: 99,
    manifest_sha256: hex('1'), directories_sha256: hex('2') };
  const good = readback(b, plan);
  assert.equal(wire.readback(good, b, plan, 'commands_drained'), good);
  for (const mutate of [x => { x.phase = 'sealed'; }, x => { x.verified_current = false; },
    x => { x.allocation_tuple_verified_current = false; }, x => { x.files++; },
    x => { x.workspace_identity.inode = 9007199254740992; }, x => { x.readback_sha256 = hex('0'); }]) {
    const altered = clone(good); mutate(altered);
    assert.throws(() => wire.readback(altered, b, plan, 'commands_drained'), { code: 'darwin_diagnostic_copy_readback_invalid' });
  }
});
test('cached observation and diagnostic facts never become qualified closure', () => {
  const b = binding();
  for (const terminal of [false, true]) {
    const good = facts(b, terminal); assert.ok(wire.facts(good, b, terminal));
    for (const mutate of [x => { x.observation_cached = true; }, x => { x.cleanup_budget_exceeded = true; },
      x => { x.registry_healthy = false; }, x => { x.allocation_tuple_verified_current = false; },
      x => { x.stop_reason = 'daemon_stopping'; },
      x => { x[terminal ? 'proof' : 'command_drain_proof'].capability_qualified = true; },
      x => { x[terminal ? 'proof' : 'command_drain_proof'].kernel_membership_zero = false; },
      x => { x[terminal ? 'proof' : 'command_drain_proof'].source_sha256 = hex('0'); },
      x => { x[terminal ? 'proof' : 'command_drain_proof'].uid_history_tuple_verified = false; },
      x => { x[terminal ? 'proof_sha256' : 'command_drain_sha256'] = hex('0'); }]) {
      const altered = clone(good); mutate(altered); assert.throws(() => wire.facts(altered, b, terminal));
    }
  }
  assert.equal(supervisor.containmentCapability(request().nativeExecution).status, 'unavailable');
  const diagnostic = { schema_version: 'knowledge-darwin-diagnostic-lifecycle.v1', status: 'diagnostic_completed',
    production_acceptance: false, capability_qualified: false, command: { exit_code: 0 } };
  assert.equal(execution.validateExecutionRecord(diagnostic).ok, false);
});
test('non-macOS diagnostic refusal occurs before filesystem/process admission', { skip: process.platform === 'darwin' }, async () => {
  await assert.rejects(runDiagnostic(request()), { code: 'darwin_diagnostic_requires_macos' });
});
