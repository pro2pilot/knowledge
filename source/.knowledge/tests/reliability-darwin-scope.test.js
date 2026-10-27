'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const api = require('../tools/lib/verification-darwin-scope');
const wire = require('../tools/lib/verification-darwin-session-protocol');
const clone = value => JSON.parse(JSON.stringify(value));
const hex = n => String(n).repeat(64);
function fixture() {
  const capability = { source_sha256: hex(1), binary_sha256: hex(2), stub_source_sha256: hex(3),
    stub_binary_sha256: hex(4), transport_header_sha256: hex(5), uid_history_header_sha256: hex(6),
    uid_history_source_sha256: hex(7), daemon_epoch: hex(8), installation_id: hex(9),
    host_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', boot_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' };
  const d = { ...capability, schema: 'knowledge-darwin-private-ruid-descriptor.v2', backend: 'darwin_private_ruid',
    mode: 'isolated_copy', stub_wire_version: 'KVS2', guardian_protocol: 'KVR2', capability_qualified: true,
    qualification_mode: false, attempt_id: hex('a'), boundary_id: hex('a'), attempt_nonce: hex('b'),
    broker_binary_sha256: capability.binary_sha256, account_policy_id: 'admin_reserved_interval_no_runtime_nss.v1',
    account_policy_sha256: hex('c'), allocation_seq: '1', allocation_sha256: hex('d'), owner_uid: 501,
    task_ruid: 1000000000, task_gid: 1000000000, workspace_path: '/protected/work/' + hex('a'),
    allowed_runtimes: { '/protected/node': hex('e') }, work_started_monotonic_ms: 1000,
    work_budget_ms: 10000, work_deadline_ms: 11000, cleanup_budget_ms: 5000 };
  const scope = { schema_version: 'knowledge-command-scope.v1', backend: 'darwin_uid_guardian',
    broker_path: '/protected/broker', broker_socket: '/protected/socket',
    binding: { attempt_id: d.attempt_id, descriptor: d, descriptor_sha256: wire.digest(d) } };
  const nonce = hex('f');
  const observation = { ...capability, ok: true, schema: 'knowledge-darwin-scope-observation.v1',
    attempt_id: d.attempt_id, descriptor_sha256: scope.binding.descriptor_sha256, observation_nonce: nonce,
    capability_qualified: true, qualification_mode: false, qa_persistence_gate: false,
    proof_current: false, cleanup_only: true, observation_cached: false, observed_monotonic_ms: 2000,
    status: 'completed', state: 'closed', active_attempt: false, clock_healthy: true,
    lifecycle_basis: 'same_boot_terminal', historical_terminal_before_new_boot: false,
    reboot_recovery_confirmed: false, recovery_epoch: null, recovery_started_monotonic_ms: null,
    recovery_deadline_monotonic_ms: null, recovery_observed_monotonic_ms: null, authority_identity: null };
  for (const key of ['installation_id', 'allocation_seq', 'allocation_sha256', 'account_policy_id', 'account_policy_sha256', 'task_ruid']) {
    observation[key] = d[key];
  }
  for (const key of ['cleanup_observation_current', 'registry_healthy', 'allocation_tuple_verified_current', 'admission_closed',
    'spawn_exclusion_acquired', 'spawn_intents_resolved', 'kernel_membership_zero', 'guardian_exit_confirmed',
    'root_child_exit_confirmed', 'registered_authority_exited', 'native_scope_closed']) observation[key] = true;
  return { capability, scope, observation, nonce };
}
test('scope wrapper carries immutable token-free descriptor and never enables diagnostic capability', () => {
  const f = fixture();assert.equal(api.validateCommandScope(f.scope), true);
  const scope = api.commandScope({ config: { broker_path: f.scope.broker_path, broker_socket: f.scope.broker_socket }, binding: f.scope.binding });
  assert.ok(Object.isFrozen(scope.binding.descriptor.allowed_runtimes));assert.ok(!JSON.stringify(scope).includes('token'));
  for (const mutate of [d => { d.capability_qualified = false; }, d => { d.qualification_mode = true; },
    d => { d.task_ruid++; }, d => { d.owner_uid = 0; }, d => { d.allocation_seq = '2'; },
    d => { d.stub_wire_version = 'KVS1'; }, d => { d.work_deadline_ms++; },
    d => { d.workspace_path = '/protected/../foreign'; }, d => { d.scratch_path = '/foreign'; }]) {
    const scope = clone(f.scope);mutate(scope.binding.descriptor);scope.binding.descriptor_sha256 = wire.digest(scope.binding.descriptor);
    assert.equal(api.validateCommandScope(scope), false);
  }
});
test('scope validation rejects getters/proxies and unknown wrapper members without evaluating them', () => {
  const f = fixture();let touched = 0;
  const value = { ...f.scope };Object.defineProperty(value, 'binding', { get() { touched++;throw new Error('executed'); }, enumerable: true });
  assert.equal(api.validateCommandScope(value), false);assert.equal(touched, 0);
  assert.equal(api.validateCommandScope(new Proxy(f.scope, { get() { touched++;return null; } })), false);assert.equal(touched, 0);
  assert.equal(api.validateCommandScope({ ...f.scope, token: hex(0) }), false);
});
test('fresh cleanup observation is bound to nonce, current host/boot/source and immutable allocation', () => {
  const f = fixture();const result = api.validateObservation(f.observation, f.scope, f.capability, f.nonce);
  assert.equal(result.status, 'completed');assert.equal(result.proof_current, false);assert.equal(result.cleanup_only, true);
  assert.equal(result.observation_sha256, wire.digest(f.observation));
  for (const patch of [{ observation_nonce: hex(0) }, { descriptor_sha256: hex(0) }, { daemon_epoch: hex(0) },
    { source_sha256: hex(0) }, { task_ruid: 1000000001 }, { allocation_seq: '2' }, { host_id: 'cccccccc-cccc-cccc-cccc-cccccccccccc' },
    { proof_current: true }, { observation_cached: true }, { capability_qualified: false }, { qualification_mode: true },
    { cleanup_only: false }, { registry_healthy: false }, { clock_healthy: false }, { active_attempt: true }]) {
    assert.equal(api.validateObservation({ ...f.observation, ...patch }, f.scope, f.capability, f.nonce).status, 'unconfirmed');
  }
});
test('zero UID count does not replace exact child, guardian, authority and admission closure', () => {
  const f = fixture();
  for (const key of ['spawn_exclusion_acquired', 'spawn_intents_resolved', 'guardian_exit_confirmed',
    'root_child_exit_confirmed', 'registered_authority_exited', 'native_scope_closed', 'admission_closed']) {
    assert.equal(api.validateObservation({ ...f.observation, [key]: false }, f.scope, f.capability, f.nonce).status, 'unconfirmed', key);
  }
  assert.equal(api.validateObservation({ ...f.observation, status: 'active' }, f.scope, f.capability, f.nonce).status, 'active');
});
test('new boot requires an independent bounded cleanup epoch without interpreting old monotonic time', () => {
  const f = fixture();f.capability.boot_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
  Object.assign(f.observation, { boot_id: f.capability.boot_id, lifecycle_basis: 'reboot_cleanup_epoch',
    reboot_recovery_confirmed: true, recovery_epoch: hex(0), recovery_started_monotonic_ms: 10,
    recovery_deadline_monotonic_ms: 1010, recovery_observed_monotonic_ms: 20, observed_monotonic_ms: 30 });
  assert.equal(api.validateObservation(f.observation, f.scope, f.capability, f.nonce).status, 'completed');
  for (const patch of [{ recovery_observed_monotonic_ms: 9 }, { recovery_observed_monotonic_ms: 1010 },
    { recovery_deadline_monotonic_ms: 5011 }, { recovery_observed_monotonic_ms: 31 },
    { recovery_epoch: null }, { reboot_recovery_confirmed: false }, { lifecycle_basis: 'same_boot_terminal' }]) {
    assert.equal(api.validateObservation({ ...f.observation, ...patch }, f.scope, f.capability, f.nonce).status, 'unconfirmed');
  }
});
test('a terminal record from an earlier boot is cleanup-only history with a fresh current observation', () => {
  const f = fixture();f.capability.boot_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
  Object.assign(f.observation, { boot_id: f.capability.boot_id, lifecycle_basis: 'historical_terminal_precedes_new_boot',
    historical_terminal_before_new_boot: true, reboot_recovery_confirmed: false, observed_monotonic_ms: 10 });
  const result = api.validateObservation(f.observation, f.scope, f.capability, f.nonce);
  assert.equal(result.status, 'completed');assert.equal(result.proof_current, false);
  assert.equal(api.validateObservation({ ...f.observation, historical_terminal_before_new_boot: false }, f.scope, f.capability, f.nonce).status, 'unconfirmed');
});
test('second reboot after pre-admission crash emits the same permanent revocation used for native closure', () => {
  // Exact production expression and actual JS consumer. Kernel and persistence
  // inputs are explicitly modeled; this does not claim a physical reboot.
  const filename = process.env.KNOWLEDGE_DARWIN_SCOPE_BROKER || path.join(__dirname, '../tools/lib/verification-darwin-broker.m');
  const source = fs.readFileSync(filename, 'utf8');
  const start = source.indexOf('static NSDictionary *observeScope('), end = source.indexOf('static ', start + 10);
  const expression = source.slice(start, end).match(/@"admission_closed":@\(\(bool\)\(([^\n]+?)\)\),/)[1]
    .replace('[e[@"admission_closed"] boolValue]', 'original');
  assert.equal(expression.replace(/original|reboot|newBoot/g, '').replace(/[()!|& ]/g, ''), '');
  const emitted = Function('original', 'reboot', 'newBoot', `return !!(${expression});`);
  const f = fixture();f.capability.boot_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
  Object.assign(f.observation, { boot_id: f.capability.boot_id, lifecycle_basis: 'historical_terminal_precedes_new_boot',
    historical_terminal_before_new_boot: true, admission_closed: emitted(false, false, true) });
  assert.equal(api.validateObservation(f.observation, f.scope, f.capability, f.nonce).status, 'completed',
    'original admission was never published, but a durable prior reboot cleanup revoked it permanently');
  assert.equal(emitted(false, false, false), false);assert.equal(emitted(true, false, false), true);
});
test('process identity keeps birth/boot values strict; PID alone and credential coercion are insufficient', () => {
  const f = fixture();const value = { schema: 'knowledge-darwin-process-identity.v1', host_id: f.capability.host_id,
    boot_id: f.capability.boot_id, owner_uid: 501, birth: { pid: 125, unique_id: '123', parent_unique_id: '100',
      start_sec: 1000, start_usec: 1, ruid: 501, pidversion: 10 } };
  assert.equal(api.validateProcessIdentity(value), true);
  for (const patch of [{ unique_id: '18446744073709551616' }, { unique_id: '00123' }, { ruid: '501' },
    { start_usec: 1000000 }, { pidversion: 0 }, { pid: 1 }, { parent_unique_id: '-1' }]) {
    assert.equal(api.validateProcessIdentity({ ...value, birth: { ...value.birth, ...patch } }), false);
  }
});
test('non-Darwin cleanup APIs never guess a platform result or run a fallback', { skip: process.platform === 'darwin' }, () => {
  const f = fixture();
  for (const method of [api.queryCommandScope, api.recoverCommandScope, api.retireCommandScope]) {
    const result = method(f.scope, { timeoutMs: 100 });
    assert.equal(result.status, 'unconfirmed');assert.equal(result.code, 'command_scope_platform_mismatch');
  }
});
