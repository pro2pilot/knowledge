'use strict';

// Token-free, READONLY cleanup observation for the separately registered
// writable-workspace protocol. Never calls prepare, register, stop or recover.
// Synchronous I/O belongs only in an isolated lifetime-owned query worker.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const { copyInertData } = require('./inert-data');
const { readStableFile } = require('./stable-file');
const native = require('./verification-darwin-client');
const wire = require('./verification-darwin-session-protocol');
const readonly = require('./verification-darwin-scope');
const protocol = require('./macos-workspace-protocol');
const METHOD = 'macos_uid_guardian';
const NAMES = Object.freeze({ source_sha256: 'verification-darwin-broker.m',
  stub_source_sha256: 'verification-darwin-stub.c', transport_header_sha256: 'verification-darwin-transport.h',
  uid_history_header_sha256: 'verification-darwin-uid-history.h', uid_history_source_sha256: 'verification-darwin-uid-history.m' });
const integer = value => Number.isSafeInteger(value) && value >= 0;
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const unknown = code => ({ status: 'unconfirmed', method: METHOD, code });
const failure = code => Object.assign(new Error(code), { code });
function inert(value, maximum = 32768) {
  const data = copyInertData(value, null, maximum * 32);
  if (Buffer.byteLength(JSON.stringify(data)) > maximum) throw failure('macos_command_scope_invalid');
  return data;
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child);Object.freeze(value); }
  return value;
}
function validateCommandScope(value) {
  try {
    const scope = inert(value), binding = scope?.binding, d = binding?.descriptor;
    return !!(exact(scope, ['schema_version', 'backend', 'binding', 'broker_path', 'broker_socket']) &&
      scope.schema_version === 'knowledge-command-scope.v1' && scope.backend === METHOD &&
      protocol.canonicalPath(scope.broker_path) && protocol.canonicalPath(scope.broker_socket) && scope.broker_socket.length <= 103 &&
      exact(binding, ['attempt_id', 'descriptor_sha256', 'descriptor']) && wire.hex(binding.attempt_id) &&
      wire.hex(binding.descriptor_sha256) && wire.digest(d) === binding.descriptor_sha256 &&
      protocol.validDescriptorFields(d) && d.attempt_id === binding.attempt_id);
  } catch { return false; }
}
function commandScope(input) {
  const { config, binding } = inert(input, 65536);
  const scope = inert({ schema_version: 'knowledge-command-scope.v1', backend: METHOD, binding,
    broker_path: config.broker_path, broker_socket: config.broker_socket });
  if (!validateCommandScope(scope)) throw failure('macos_command_scope_invalid');
  return freeze(scope);
}
function stableHash(file) {
  const absolute = path.resolve(file), root = path.parse(absolute).root, parents = [];
  let current = root;
  for (const part of ['', ...path.relative(root, absolute).split(path.sep)]) {
    if (part) current = path.join(current, part);
    const st = fs.lstatSync(current, { bigint: true }), leaf = current === absolute;
    if (st.isSymbolicLink() || (leaf ? !st.isFile() || st.nlink !== 1n : !st.isDirectory())) {
      throw failure('macos_command_scope_path_unsafe');
    }
    parents.push({ name: current, dev: st.dev, ino: st.ino, mode: st.mode, uid: st.uid });
  }
  const hash = wire.sha(readStableFile(root, absolute, { maxBytes: 2 * 1024 * 1024 }));
  for (const expected of parents) {
    const st = fs.lstatSync(expected.name, { bigint: true });
    if (st.isSymbolicLink() || !['dev', 'ino', 'mode', 'uid'].every(key => st[key] === expected[key])) {
      throw failure('macos_command_scope_path_changed');
    }
  }
  return hash;
}
function validateObservation(value, scope, capability, nonce) {
  try {
    if (!validateCommandScope(scope)) return unknown('macos_command_scope_observation_invalid');
    scope = inert(scope);capability = inert(capability, 8192);value = inert(value, native.MAX_REPLY_BYTES);
    const d = scope.binding.descriptor;
    if (![...Object.keys(NAMES), 'binary_sha256', 'stub_binary_sha256', 'daemon_epoch'].every(key => wire.hex(capability?.[key])) ||
        !uuid(capability.host_id) || !uuid(capability.boot_id) || value?.ok !== true || value.schema !== 'knowledge-darwin-scope-observation.v1' ||
        value.observation_nonce !== nonce || !wire.hex(nonce) || value.attempt_id !== scope.binding.attempt_id ||
        value.descriptor_sha256 !== scope.binding.descriptor_sha256 || value.host_id !== d.host_id ||
        value.host_id !== capability.host_id || value.boot_id !== capability.boot_id ||
        value.daemon_epoch !== capability.daemon_epoch || !wire.hex(value.daemon_epoch) ||
        value.capability_qualified !== true || value.qualification_mode !== false || value.qa_persistence_gate !== false ||
        value.proof_current !== false || value.cleanup_only !== true || value.observation_cached !== false ||
        ![...Object.keys(NAMES), 'binary_sha256', 'stub_binary_sha256'].every(key => value[key] === capability[key]) ||
        !['installation_id', 'allocation_seq', 'allocation_sha256', 'account_policy_id', 'account_policy_sha256', 'task_ruid']
          .every(key => value[key] === d[key]) || !integer(value.observed_monotonic_ms) ||
        !['completed', 'active', 'unconfirmed'].includes(value.status)) return unknown('macos_command_scope_observation_invalid');
    if (value.status === 'active') return { status: 'active', method: METHOD, code: 'macos_command_scope_active', observation: value };
    if (value.status !== 'completed') return { ...unknown('macos_command_scope_native_unconfirmed'), observation: value };
    if (!['cleanup_observation_current', 'registry_healthy', 'allocation_tuple_verified_current', 'admission_closed',
      'spawn_exclusion_acquired', 'spawn_intents_resolved', 'kernel_membership_zero', 'guardian_exit_confirmed',
      'root_child_exit_confirmed', 'registered_authority_exited', 'native_scope_closed'].every(key => value[key] === true) ||
        value.state !== 'closed' || value.active_attempt !== false || value.clock_healthy !== true) return unknown('macos_command_scope_closure_unconfirmed');
    const newBoot = value.boot_id.toLowerCase() !== d.boot_id.toLowerCase();
    const historical = newBoot && value.lifecycle_basis === 'historical_terminal_precedes_new_boot' &&
      value.historical_terminal_before_new_boot === true && value.reboot_recovery_confirmed === false;
    if (!newBoot && (value.lifecycle_basis !== 'same_boot_terminal' || value.historical_terminal_before_new_boot !== false) ||
        newBoot && !historical && (value.lifecycle_basis !== 'reboot_cleanup_epoch' || value.reboot_recovery_confirmed !== true || !wire.hex(value.recovery_epoch) ||
        !integer(value.recovery_started_monotonic_ms) || !integer(value.recovery_deadline_monotonic_ms) ||
        value.recovery_deadline_monotonic_ms <= value.recovery_started_monotonic_ms ||
        value.recovery_deadline_monotonic_ms - value.recovery_started_monotonic_ms > d.cleanup_budget_ms ||
        !integer(value.recovery_observed_monotonic_ms) || value.recovery_observed_monotonic_ms < value.recovery_started_monotonic_ms ||
        value.recovery_observed_monotonic_ms >= value.recovery_deadline_monotonic_ms ||
        value.recovery_observed_monotonic_ms > value.observed_monotonic_ms)) return unknown('macos_command_scope_reboot_unconfirmed');
    if (value.authority_identity !== null && !readonly.validateProcessIdentity({ schema: 'knowledge-darwin-process-identity.v1',
      host_id: d.host_id, boot_id: d.boot_id, owner_uid: d.owner_uid, birth: value.authority_identity })) return unknown('macos_command_scope_authority_invalid');
    return { status: 'completed', method: METHOD, cleanup_only: true, proof_current: false,
      cleanup_observation_current: true, observation_sha256: wire.digest(value), daemon_epoch: value.daemon_epoch,
      boot_id: value.boot_id, descriptor_sha256: value.descriptor_sha256, observation: value };
  } catch { return unknown('macos_command_scope_observation_invalid'); }
}
function queryCommandScope(value, { timeoutMs = 5000 } = {}) {
  if (!validateCommandScope(value) || !Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) return unknown('macos_command_scope_invalid');
  if (process.platform !== 'darwin') return unknown('command_scope_platform_mismatch');
  const scope = inert(value), started = process.hrtime.bigint(), budget = Math.floor(timeoutMs);
  const remaining = () => Math.max(0, Math.floor(budget - Number(process.hrtime.bigint() - started) / 1e6));
  const checkpoint = () => { if (!remaining()) throw failure('macos_command_scope_budget_exceeded'); };
  try {
    checkpoint();const pins = Object.fromEntries(Object.entries(NAMES).map(([key, file]) => {
      checkpoint();return [key, stableHash(path.join(__dirname, file))];
    }));
    checkpoint();const binarySHA = require('./lock-publication').verifyProtectedExecutable(scope.broker_path,
      { maxBytes: 256 * 1024 * 1024, remainingMs: remaining() }).sha256;checkpoint();
    function request(body) {
      // Fixed op allowlist: no caller can smuggle a native side effect here.
      if (!['probe', 'observe_scope'].includes(body.op)) throw failure('macos_command_scope_readonly_required');
      checkpoint();const limit = remaining();
      const result = childProcess.spawnSync(scope.broker_path, ['--request', `--socket=${scope.broker_socket}`,
        `--lifecycle-timeout-ms=${limit}`, '--transport-timeout-ms=30000'], { shell: false,
        input: Buffer.from(JSON.stringify(body), 'utf8'), encoding: 'buffer', timeout: limit, killSignal: 'SIGKILL',
        maxBuffer: native.MAX_REPLY_BYTES, windowsHide: true, env: native.nativeEnv() });
      checkpoint();
      if (result.error || result.status !== 0 || result.signal !== null || !Buffer.isBuffer(result.stdout) ||
          result.stdout.length > native.MAX_REPLY_BYTES) throw failure('macos_command_scope_helper_unconfirmed');
      return result.stdout;
    }
    const probe = native.decodeReply(request({ op: 'probe' }), pins);
    if (probe.ok !== true || probe.capability_qualified !== true || probe.qualification_mode !== false ||
        probe.qa_persistence_gate !== false || probe.registry_healthy !== true || probe.entry_store_loaded !== true ||
        probe.uid_history.healthy_cached !== true || probe.uid_history.health_source !== 'disk_refresh_attempt' ||
        probe.account_policy.healthy !== true || probe.binary_sha256 !== binarySHA) return unknown('macos_command_scope_broker_unqualified');
    const capability = { ...pins, binary_sha256: binarySHA, stub_binary_sha256: probe.stub_binary_sha256,
      host_id: probe.host_id, boot_id: probe.boot_id, daemon_epoch: probe.daemon_epoch,
      installation_id: probe.uid_history.installation_id_cached };
    if (capability.host_id !== scope.binding.descriptor.host_id || capability.installation_id !== scope.binding.descriptor.installation_id) {
      return unknown('macos_command_scope_host_installation_mismatch');
    }
    const nonce = crypto.randomBytes(32).toString('hex');
    const body = request({ op: 'observe_scope', attempt_id: scope.binding.attempt_id,
      descriptor_sha256: scope.binding.descriptor_sha256, observation_nonce: nonce });
    const observation = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(body));
    checkpoint();const result = validateObservation(observation, scope, capability, nonce);checkpoint();return result;
  } catch (error) {
    return unknown(/^[a-z0-9_]{1,96}$/.test(error?.code || '') ? error.code : 'macos_command_scope_query_unconfirmed');
  }
}
module.exports = { commandScope, validateCommandScope, validateObservation, queryCommandScope };
