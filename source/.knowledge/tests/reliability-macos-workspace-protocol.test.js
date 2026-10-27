'use strict';
// Native and filesystem claims here are modeled. These tests qualify only
// the JavaScript predicates; the physical macOS cohort remains independent.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const wire = require('../tools/lib/verification-darwin-session-protocol');
const readonly = require('../tools/lib/verification-darwin-scope');
const protocol = require('../tools/lib/macos-workspace-protocol');
const scopeApi = require('../tools/lib/macos-command-scope');
const clone = value => JSON.parse(JSON.stringify(value));
const hex = value => String(value).repeat(64);
function fixture() {
  const capability = { source_sha256: hex(1), binary_sha256: hex(2), stub_source_sha256: hex(3),
    stub_binary_sha256: hex(4), transport_header_sha256: hex(5), uid_history_header_sha256: hex(6),
    uid_history_source_sha256: hex(7), daemon_epoch: hex(8), installation_id: hex(9),
    host_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', boot_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    account_policy_id: 'admin_reserved_interval_no_runtime_nss.v1', account_policy_sha256: hex('c'),
    runtime_path: '/protected/node', runtime_sha256: hex('e') };
  const d = { ...capability, schema: protocol.SCHEMA, backend: 'darwin_private_ruid', mode: protocol.MODE,
    stub_wire_version: 'KVS3', guardian_protocol: 'KVR2', capability_qualified: true, qualification_mode: false,
    attempt_id: hex('a'), boundary_id: hex('a'), attempt_nonce: hex('b'), broker_binary_sha256: capability.binary_sha256,
    allocation_seq: '1', allocation_sha256: hex('d'), owner_uid: 501, task_ruid: 1000000000, task_gid: 2000000000,
    workspace_path: '/protected/work/' + hex('a'), scratch_path: '/protected/work/' + hex('a') + '.scratch',
    scratch_policy: 'admin_workspace_acl_sibling.v1', allowed_runtimes: { [capability.runtime_path]: capability.runtime_sha256 },
    work_started_monotonic_ms: 1000, work_budget_ms: 10000, work_deadline_ms: 11000, cleanup_budget_ms: 5000,
    workspace_id: hex('f'), workspace_capability_sha256: hex(0), writable_root: '/project',
    writable_identity: { device: '1', inode: '2', owner_uid: 501, group_gid: 2000000000, mode: 0o770 },
    protected_worker_root: '/protected/runtime' };
  const reply = { ok: true, attempt_id: d.attempt_id, descriptor_sha256: wire.digest(d), descriptor: d,
    token: hex('f'), workspace_path: d.workspace_path };
  const binding = protocol.validateDescriptor(reply, capability, d.attempt_nonce);
  const config = { broker_path: '/protected/broker', broker_socket: '/protected/socket' };
  const scope = scopeApi.commandScope({ config, binding });
  const nonce = hex('e');
  const observation = { ...capability, ok: true, schema: 'knowledge-darwin-scope-observation.v1',
    attempt_id: d.attempt_id, descriptor_sha256: reply.descriptor_sha256, observation_nonce: nonce,
    capability_qualified: true, qualification_mode: false, qa_persistence_gate: false,
    proof_current: false, cleanup_only: true, observation_cached: false, observed_monotonic_ms: 2000,
    status: 'completed', state: 'closed', active_attempt: false, clock_healthy: true,
    lifecycle_basis: 'same_boot_terminal', historical_terminal_before_new_boot: false,
    reboot_recovery_confirmed: false, recovery_epoch: null, recovery_started_monotonic_ms: null,
    recovery_deadline_monotonic_ms: null, recovery_observed_monotonic_ms: null, authority_identity: null };
  for (const key of ['allocation_seq', 'allocation_sha256', 'task_ruid']) observation[key] = d[key];
  for (const key of ['cleanup_observation_current', 'registry_healthy', 'allocation_tuple_verified_current', 'admission_closed',
    'spawn_exclusion_acquired', 'spawn_intents_resolved', 'kernel_membership_zero', 'guardian_exit_confirmed',
    'root_child_exit_confirmed', 'registered_authority_exited', 'native_scope_closed']) observation[key] = true;
  return { capability, d, reply, binding, config, scope, observation, nonce };
}
function changedReply(f, mutate) {
  const reply = clone(f.reply);mutate(reply.descriptor);reply.descriptor_sha256 = wire.digest(reply.descriptor);return reply;
}
test('writable descriptors use a separate immutable KVS3 binding and never satisfy readonly admission', () => {
  const f = fixture();assert.equal(scopeApi.validateCommandScope(f.scope), true);
  assert(Object.isFrozen(f.binding.descriptor.writable_identity));assert(Object.isFrozen(f.scope.binding.descriptor));
  assert.equal(readonly.validateCommandScope({ ...f.scope, backend: 'darwin_uid_guardian' }), false);
  assert.throws(() => wire.validateDescriptor(f.reply, f.capability, f.d.attempt_nonce), { code: 'verification_darwin_descriptor_invalid' });
  assert(!JSON.stringify(f.scope).includes('"token"'));
});
test('writable admission binds native source runtime host boot epoch allocation and nonce', () => {
  const f = fixture();
  for (const mutate of [d => { d.source_sha256 = hex(0); }, d => { d.daemon_epoch = hex(0); },
    d => { d.stub_binary_sha256 = hex(0); }, d => { d.host_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'; },
    d => { d.allowed_runtimes['/protected/node'] = hex(0); }, d => { d.allocation_seq = '2'; },
    d => { d.boundary_id = hex(0); }, d => { d.attempt_nonce = hex(0); }, d => { d.capability_qualified = false; },
    d => { d.qualification_mode = true; }, d => { d.stub_wire_version = 'KVS2'; }, d => { d.mode = 'isolated_copy'; },
    d => { d.scratch_policy = 'private_uid_sibling.v1'; }]) {
    assert.throws(() => protocol.validateDescriptor(changedReply(f, mutate), f.capability, f.d.attempt_nonce),
      { code: 'macos_workspace_descriptor_invalid' });
  }
});
test('native writable root identity requires reserved group owner permissions and nonoverlapping canonical roots', () => {
  const f = fixture();
  for (const mutate of [d => { d.task_gid = d.task_ruid; }, d => { d.task_gid = 1999999999; },
    d => { d.task_gid = 2100000000; }, d => { d.writable_identity.group_gid++; },
    d => { d.writable_identity.owner_uid = 0; }, d => { d.writable_identity.mode = 0o777; },
    d => { d.writable_identity.mode = 0o40770; }, d => { d.writable_identity.inode = '0'; },
    d => { d.writable_identity.device = '18446744073709551616'; }, d => { d.workspace_id = 'unsafe'; },
    d => { d.workspace_capability_sha256 = 'unsafe'; }, d => { d.writable_root = '/project/../foreign'; },
    d => { d.protected_worker_root = '/project/runtime'; }, d => { d.writable_root = '/protected/runtime/project'; },
    d => { d.protected_worker_root = d.writable_root; }, d => { d.writable_root = '/'; }]) {
    assert.equal(protocol.validDescriptorFields(changedReply(f, mutate).descriptor), false);
  }
});
test('descriptor and wrapper validation reject executable values without invoking them', () => {
  const f = fixture();let calls = 0;
  const bad = { ...f.d };Object.defineProperty(bad, 'writable_root', { get() { calls++;return '/project'; }, enumerable: true });
  assert.equal(protocol.validDescriptorFields(bad), false);
  assert.equal(protocol.validDescriptorFields(new Proxy(f.d, { get() { calls++;return null; } })), false);
  assert.equal(scopeApi.validateCommandScope({ ...f.scope, token: hex(0) }), false);
  assert.equal(scopeApi.validateCommandScope({ ...f.scope, binding: { ...f.binding, descriptor_sha256: hex(0) } }), false);
  assert.equal(calls, 0);
});
test('writable cleanup observation binds the unchanged descriptor and is never a current acceptance proof', () => {
  const f = fixture(), proof = scopeApi.validateObservation(f.observation, f.scope, f.capability, f.nonce);
  assert.equal(proof.status, 'completed');assert.equal(proof.proof_current, false);assert.equal(proof.cleanup_only, true);
  assert.equal(proof.observation_sha256, wire.digest(f.observation));
  for (const patch of [{ observation_nonce: hex(0) }, { descriptor_sha256: hex(0) }, { daemon_epoch: hex(0) },
    { source_sha256: hex(0) }, { task_ruid: 1000000001 }, { allocation_seq: '2' }, { proof_current: true },
    { observation_cached: true }, { cleanup_only: false }, { registry_healthy: false }, { active_attempt: true }]) {
    assert.equal(scopeApi.validateObservation({ ...f.observation, ...patch }, f.scope, f.capability, f.nonce).status, 'unconfirmed');
  }
});
test('writable cleanup requires all independent closure facts including authority exit', () => {
  const f = fixture();
  for (const key of ['spawn_exclusion_acquired', 'spawn_intents_resolved', 'guardian_exit_confirmed',
    'root_child_exit_confirmed', 'registered_authority_exited', 'native_scope_closed', 'admission_closed', 'kernel_membership_zero']) {
    assert.equal(scopeApi.validateObservation({ ...f.observation, [key]: false }, f.scope, f.capability, f.nonce).status, 'unconfirmed');
  }
  assert.equal(scopeApi.validateObservation({ ...f.observation, authority_identity: { pid: 23 } }, f.scope, f.capability, f.nonce).status, 'unconfirmed');
  assert.equal(scopeApi.validateObservation({ ...f.observation, status: 'active' }, f.scope, f.capability, f.nonce).status, 'active');
});
test('writable scope reboot observations consume their own bounded epoch and cannot reuse old clocks', () => {
  const f = fixture();f.capability.boot_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
  Object.assign(f.observation, { boot_id: f.capability.boot_id, lifecycle_basis: 'reboot_cleanup_epoch',
    reboot_recovery_confirmed: true, recovery_epoch: hex(0), recovery_started_monotonic_ms: 10,
    recovery_deadline_monotonic_ms: 1010, recovery_observed_monotonic_ms: 20, observed_monotonic_ms: 30 });
  assert.equal(scopeApi.validateObservation(f.observation, f.scope, f.capability, f.nonce).status, 'completed');
  for (const patch of [{ recovery_observed_monotonic_ms: 9 }, { recovery_observed_monotonic_ms: 1010 },
    { recovery_deadline_monotonic_ms: 5011 }, { recovery_epoch: null }, { reboot_recovery_confirmed: false }]) {
    assert.equal(scopeApi.validateObservation({ ...f.observation, ...patch }, f.scope, f.capability, f.nonce).status, 'unconfirmed');
  }
});
test('foreign-platform writable queries never guess a native cleanup result', () => {
  const f = fixture(), platform = Object.getOwnPropertyDescriptor(process, 'platform');
  try {
    Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
    assert.equal(scopeApi.queryCommandScope(f.scope).code, 'command_scope_platform_mismatch');
  } finally { Object.defineProperty(process, 'platform', platform); }
});
test('writable query performs only probe and observe_scope through actual Buffer-input spawnSync', () => {
  const f = fixture(), filename = path.join(__dirname, '../tools/lib/macos-command-scope.js');
  const module = new Module(filename, require.cache[__filename]);module.filename = filename;
  module.paths = Module._nodeModulePaths(path.dirname(filename));const originalRequire = module.require.bind(module), operations = [];
  const sourceBytes = Buffer.from('modeled sources'), sourceHash = wire.sha(sourceBytes);
  for (const key of ['source_sha256', 'stub_source_sha256', 'transport_header_sha256', 'uid_history_header_sha256', 'uid_history_source_sha256']) {
    f.capability[key] = sourceHash;f.observation[key] = sourceHash;
  }
  module.require = name => name === './stable-file' ? { readStableFile: () => sourceBytes } :
    name === './lock-publication' ? { verifyProtectedExecutable: () => ({ sha256: f.capability.binary_sha256 }) } :
    name === './verification-darwin-client' ? { ...originalRequire(name), nativeEnv: () => ({}), decodeReply: () => ({
      ...f.capability, ok: true, capability_qualified: true, qualification_mode: false, qa_persistence_gate: false,
      registry_healthy: true, entry_store_loaded: true, uid_history: { healthy_cached: true, health_source: 'disk_refresh_attempt',
        installation_id_cached: f.capability.installation_id }, account_policy: { healthy: true }
    }) } : name === 'node:child_process' ? { spawnSync(binary, argv, options) {
      assert(Buffer.isBuffer(options.input));assert.equal(options.shell, false);
      const body = JSON.parse(options.input);operations.push(body.op);
      assert.deepEqual(Object.keys(body).sort(), body.op === 'probe' ? ['op'] : ['attempt_id', 'descriptor_sha256', 'observation_nonce', 'op']);
      const response = { ...f.observation, observation_nonce: body.observation_nonce };
      return require('node:child_process').spawnSync(process.execPath, ['-e',
        'JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write(' + JSON.stringify(JSON.stringify(response)) + ')'],
        { ...options, env: process.env });
    } } : originalRequire(name);
  module._compile(fs.readFileSync(filename, 'utf8'), filename);
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  try {
    Object.defineProperty(process, 'platform', { ...platform, value: 'darwin' });
    const result = module.exports.queryCommandScope(f.scope, { timeoutMs: 20000 });
    assert.equal(result.status, 'completed', JSON.stringify(result));
    assert.deepEqual(operations, ['probe', 'observe_scope']);assert.equal(result.proof_current, false);
  } finally { Object.defineProperty(process, 'platform', platform); }
});
