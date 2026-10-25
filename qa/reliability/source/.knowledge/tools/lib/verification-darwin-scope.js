'use strict';

// Public, token-free cleanup binding for common-lock recovery. This module is
// deliberately synchronous: invoke it only in an isolated storage/reclaimer
// process which retains the lock while a filesystem or native query is stuck.
// The query never requests stop, recovery, registration or command execution.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const { copyInertData } = require('./inert-data');
const { readStableFile } = require('./stable-file');
const native = require('./verification-darwin-client');
const wire = require('./verification-darwin-session-protocol');
const { MAX_WORK_MS, MAX_CLEANUP_MS } = require('./verification-policy');
const METHOD = 'darwin_uid_guardian';
const NAMES = Object.freeze({ source_sha256: 'verification-darwin-broker.m',
  stub_source_sha256: 'verification-darwin-stub.c', transport_header_sha256: 'verification-darwin-transport.h',
  uid_history_header_sha256: 'verification-darwin-uid-history.h', uid_history_source_sha256: 'verification-darwin-uid-history.m' });
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const canonicalPath = value => typeof value === 'string' && value.length <= 4096 && value.startsWith('/') &&
  value !== '/' && !value.includes('\0') && !value.includes('\\') && value.split('/').slice(1).every(part => part && part !== '.' && part !== '..');
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const unknown = code => ({ status: 'unconfirmed', method: METHOD, code });
const failure = code => Object.assign(new Error(code), { code });
const now = () => process.hrtime.bigint();

function validateCommandScope(value) {
  try {
    const scope = copyInertData(value, null, 32768), binding = scope?.binding, d = binding?.descriptor;
    if (!exact(scope, ['schema_version', 'backend', 'binding', 'broker_path', 'broker_socket']) ||
        scope.schema_version !== 'knowledge-command-scope.v1' || scope.backend !== METHOD ||
        !canonicalPath(scope.broker_path) || !canonicalPath(scope.broker_socket) || scope.broker_socket.length > 103 ||
        !exact(binding, ['attempt_id', 'descriptor_sha256', 'descriptor']) || !wire.hex(binding.attempt_id) ||
        !wire.hex(binding.descriptor_sha256) || !d || wire.digest(d) !== binding.descriptor_sha256 ||
        d.attempt_id !== binding.attempt_id || d.boundary_id !== binding.attempt_id || !wire.hex(d.attempt_nonce) ||
        d.schema !== 'knowledge-darwin-private-ruid-descriptor.v2' || d.backend !== 'darwin_private_ruid' ||
        d.mode !== 'isolated_copy' || d.stub_wire_version !== 'KVS2' || d.guardian_protocol !== 'KVR2' ||
        d.capability_qualified !== true || d.qualification_mode !== false ||
        ![...Object.keys(NAMES), 'broker_binary_sha256', 'stub_binary_sha256', 'daemon_epoch',
          'installation_id', 'account_policy_sha256', 'allocation_sha256'].every(key => wire.hex(d[key])) ||
        !uuid(d.host_id) || !uuid(d.boot_id) || d.account_policy_id !== 'admin_reserved_interval_no_runtime_nss.v1' ||
        !integer(d.owner_uid) || d.owner_uid < 1 || d.owner_uid >= 1000000000 ||
        !integer(d.task_ruid) || d.task_ruid < 1000000000 || d.task_ruid >= 1900000000 || d.task_gid !== d.task_ruid ||
        typeof d.allocation_seq !== 'string' || !/^[1-9][0-9]{0,8}$/.test(d.allocation_seq) ||
        Number(d.allocation_seq) !== d.task_ruid - 1000000000 + 1 || !canonicalPath(d.workspace_path) ||
        (d.scratch_path !== undefined || d.scratch_policy !== undefined) &&
          (d.scratch_path !== d.workspace_path + '.scratch' || d.scratch_policy !== 'private_uid_sibling.v1') ||
        !integer(d.work_started_monotonic_ms) || !integer(d.work_budget_ms) || d.work_budget_ms < 1 ||
        d.work_budget_ms > MAX_WORK_MS || !integer(d.work_deadline_ms) ||
        d.work_deadline_ms !== d.work_started_monotonic_ms + d.work_budget_ms ||
        !integer(d.cleanup_budget_ms) || d.cleanup_budget_ms < 1 || d.cleanup_budget_ms > MAX_CLEANUP_MS ||
        !d.allowed_runtimes || Array.isArray(d.allowed_runtimes) || typeof d.allowed_runtimes !== 'object' ||
        Object.keys(d.allowed_runtimes).length < 1 || Object.keys(d.allowed_runtimes).length > 32 ||
        !Object.entries(d.allowed_runtimes).every(([name, hash]) => canonicalPath(name) && wire.hex(hash))) return false;
    return Buffer.byteLength(JSON.stringify(scope)) <= 32768;
  } catch { return false; }
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child);Object.freeze(value); }
  return value;
}
function commandScope(input) {
  const { config, binding } = copyInertData(input, null, 65536);
  const scope = copyInertData({ schema_version: 'knowledge-command-scope.v1', backend: METHOD,
    binding, broker_path: config.broker_path, broker_socket: config.broker_socket }, null, 32768);
  if (!validateCommandScope(scope)) throw failure('verification_darwin_scope_invalid');
  return freeze(scope);
}

// Stable bounded bytes and protected pathname metadata. Regular-file syscalls
// may still block: the containing worker owns physical lifetime and the lock.
function stableHash(file, maximum, protectedRoot = false, remainingMs = 30000) {
  if (protectedRoot) return require('./lock-publication').verifyProtectedExecutable(file,
    { maxBytes: maximum, remainingMs }).sha256;
  const absolute = path.resolve(file), root = path.parse(absolute).root, parents = [];
  let current = root;
  for (const part of ['', ...path.relative(root, absolute).split(path.sep)]) {
    if (part) current = path.join(current, part);
    const st = fs.lstatSync(current, { bigint: true }), leaf = current === absolute;
    const sticky = !leaf && current === '/private/tmp' && (st.mode & 0o1000n) !== 0n;
    if (st.isSymbolicLink() || (leaf ? !st.isFile() || st.nlink !== 1n : !st.isDirectory()) ||
        protectedRoot && (st.uid !== 0n || (st.mode & 0o22n) !== 0n && !sticky || leaf && (st.mode & 0o6000n) !== 0n)) {
      throw failure('verification_darwin_scope_path_unsafe');
    }
    parents.push({ name: current, dev: st.dev, ino: st.ino, mode: st.mode, uid: st.uid });
  }
  const hash = wire.sha(readStableFile(root, absolute, { maxBytes: maximum }));
  for (const expected of parents) {
    const current = fs.lstatSync(expected.name, { bigint: true });
    if (current.isSymbolicLink() || !['dev', 'ino', 'mode', 'uid'].every(key => current[key] === expected[key])) {
      throw failure('verification_darwin_scope_path_changed');
    }
  }
  return hash;
}

function validateObservation(value, scope, capability, nonce) {
  try {
    if (!validateCommandScope(scope)) return unknown('verification_darwin_scope_observation_invalid');
    scope = copyInertData(scope, null, 32768);capability = copyInertData(capability, null, 8192);
    value = copyInertData(value, null, native.MAX_REPLY_BYTES);
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
        !['completed', 'active', 'unconfirmed'].includes(value.status)) return unknown('verification_darwin_scope_observation_invalid');
    if (value.status === 'active') return { status: 'active', method: METHOD, code: 'verification_darwin_scope_active', observation: value };
    if (value.status !== 'completed') return { ...unknown('verification_darwin_scope_native_unconfirmed'), observation: value };
    if (!['cleanup_observation_current', 'registry_healthy', 'allocation_tuple_verified_current', 'admission_closed',
      'spawn_exclusion_acquired', 'spawn_intents_resolved', 'kernel_membership_zero', 'guardian_exit_confirmed',
      'root_child_exit_confirmed', 'registered_authority_exited', 'native_scope_closed'].every(key => value[key] === true) ||
        value.state !== 'closed' || value.active_attempt !== false || value.clock_healthy !== true) {
      return unknown('verification_darwin_scope_closure_unconfirmed');
    }
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
        value.recovery_observed_monotonic_ms > value.observed_monotonic_ms)) {
      return unknown('verification_darwin_scope_reboot_unconfirmed');
    }
    if (value.authority_identity !== null && !validBirth(value.authority_identity, d.owner_uid)) {
      return unknown('verification_darwin_scope_authority_invalid');
    }
    return { status: 'completed', method: METHOD, cleanup_only: true, proof_current: false,
      cleanup_observation_current: true, observation_sha256: wire.digest(value), daemon_epoch: value.daemon_epoch,
      boot_id: value.boot_id, descriptor_sha256: value.descriptor_sha256, observation: value };
  } catch { return unknown('verification_darwin_scope_observation_invalid'); }
}

function withQuery(config, timeoutMs, work) {
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000 ||
      !canonicalPath(config?.broker_path) || !canonicalPath(config?.broker_socket)) return unknown('verification_darwin_scope_invalid');
  if (process.platform !== 'darwin') return unknown('command_scope_platform_mismatch');
  const started = now(), budget = Math.floor(timeoutMs);
  const remaining = () => Math.max(0, Math.floor(budget - Number(now() - started) / 1e6));
  const checkpoint = () => { if (!remaining()) throw failure('verification_darwin_scope_budget_exceeded'); };
  try {
    checkpoint();const pins = Object.fromEntries(Object.entries(NAMES).map(([key, file]) => {
      checkpoint();return [key, stableHash(path.join(__dirname, file), 2 * 1024 * 1024)];
    }));
    checkpoint();const binarySHA = stableHash(config.broker_path, 256 * 1024 * 1024, true, remaining());checkpoint();
    function request(body) {
      checkpoint();const limit = remaining();
      const result = childProcess.spawnSync(config.broker_path, ['--request', `--socket=${config.broker_socket}`,
        `--lifecycle-timeout-ms=${limit}`, '--transport-timeout-ms=30000'], { shell: false,
        input: JSON.stringify(body), encoding: 'buffer', timeout: limit, killSignal: 'SIGKILL',
        maxBuffer: native.MAX_REPLY_BYTES, windowsHide: true, env: native.nativeEnv() });
      checkpoint();
      if (result.error || result.status !== 0 || result.signal !== null || !Buffer.isBuffer(result.stdout) ||
          result.stdout.length > native.MAX_REPLY_BYTES) throw failure('verification_darwin_scope_helper_unconfirmed');
      return result.stdout;
    }
    const probe = native.decodeReply(request({ op: 'probe' }), pins);
    if (probe.ok !== true || probe.capability_qualified !== true || probe.qualification_mode !== false ||
        probe.qa_persistence_gate !== false || probe.registry_healthy !== true || probe.entry_store_loaded !== true ||
        probe.uid_history.healthy_cached !== true || probe.uid_history.health_source !== 'disk_refresh_attempt' ||
        probe.account_policy.healthy !== true || probe.binary_sha256 !== binarySHA) {
      return unknown('verification_darwin_scope_broker_unqualified');
    }
    const capability = { ...pins, binary_sha256: binarySHA, stub_binary_sha256: probe.stub_binary_sha256,
      host_id: probe.host_id, boot_id: probe.boot_id, daemon_epoch: probe.daemon_epoch,
      installation_id: probe.uid_history.installation_id_cached };
    const result = work({ capability, request, checkpoint, remaining });checkpoint();return result;
  } catch (error) {
    return unknown(/^[a-z0-9_]{1,96}$/.test(error?.code || '') ? error.code : 'verification_darwin_scope_query_unconfirmed');
  }
}
function queryCommandScope(value, { timeoutMs = 5000 } = {}) {
  if (!validateCommandScope(value)) return unknown('verification_darwin_scope_invalid');
  const scope = copyInertData(value, null, 32768);
  return withQuery(scope, timeoutMs, ({ capability, request, checkpoint }) => {
    if (capability.host_id !== scope.binding.descriptor.host_id || capability.installation_id !== scope.binding.descriptor.installation_id) {
      return unknown('verification_darwin_scope_host_installation_mismatch');
    }
    const nonce = crypto.randomBytes(32).toString('hex');
    const bytes = request({ op: 'observe_scope', attempt_id: scope.binding.attempt_id,
      descriptor_sha256: scope.binding.descriptor_sha256, observation_nonce: nonce });
    const observation = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
    checkpoint();return validateObservation(observation, scope, capability, nonce);
  });
}
// Mutating recovery is a separate entry point. The common control owner must
// durably reserve recovery before calling it; ordinary scope queries stay pure.
// The caller cannot supply PIDs, a signal, a token, executable code or a new work
// deadline. Native recovery owns the original/reboot cleanup epoch and budget.
function recoverCommandScope(value, { timeoutMs = 5000 } = {}) {
  if (!validateCommandScope(value)) return unknown('verification_darwin_scope_invalid');
  const scope = copyInertData(value, null, 32768), d = scope.binding.descriptor;
  return withQuery(scope, timeoutMs, ({ capability, request, checkpoint, remaining }) => {
    if (capability.host_id !== d.host_id || capability.installation_id !== d.installation_id) {
      return unknown('verification_darwin_scope_host_installation_mismatch');
    }
    function observe() {
      const nonce = crypto.randomBytes(32).toString('hex');
      const bytes = request({ op: 'observe_scope', attempt_id: scope.binding.attempt_id,
        descriptor_sha256: scope.binding.descriptor_sha256, observation_nonce: nonce });
      const observation = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
      checkpoint();return validateObservation(observation, scope, capability, nonce);
    }
    const before = observe();if (before.status === 'completed') return before;
    checkpoint();const cleanup = Math.min(d.cleanup_budget_ms, remaining());
    if (cleanup < 1) return unknown('verification_darwin_scope_budget_exceeded');
    const response = copyInertData(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(request({
      op: 'recover', attempt_id: scope.binding.attempt_id, descriptor_sha256: scope.binding.descriptor_sha256,
      cleanup_budget_ms: cleanup
    }))), null, native.MAX_REPLY_BYTES);
    checkpoint();
    if (response?.ok !== true || response.attempt_id !== scope.binding.attempt_id ||
        response.descriptor_sha256 !== scope.binding.descriptor_sha256) return unknown('verification_darwin_scope_recovery_unconfirmed');
    return observe();
  });
}
function validBirth(value, owner) {
  return exact(value, ['pid', 'unique_id', 'parent_unique_id', 'start_sec', 'start_usec', 'ruid', 'pidversion']) &&
    Number.isSafeInteger(value.pid) && value.pid > 1 && value.pid <= 2147483647 && integer(value.start_sec) && value.start_sec > 0 &&
    integer(value.start_usec) && value.start_usec < 1000000 && value.ruid === owner && integer(value.pidversion) && value.pidversion > 0 &&
    typeof value.unique_id === 'string' && /^[1-9][0-9]{0,19}$/.test(value.unique_id) && BigInt(value.unique_id) <= 18446744073709551615n &&
    typeof value.parent_unique_id === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value.parent_unique_id) && BigInt(value.parent_unique_id) <= 18446744073709551615n;
}
function validateProcessIdentity(value) {
  try {
    value = copyInertData(value, null, 4096);
    return exact(value, ['schema', 'host_id', 'boot_id', 'owner_uid', 'birth']) &&
      value.schema === 'knowledge-darwin-process-identity.v1' && uuid(value.host_id) && uuid(value.boot_id) &&
      integer(value.owner_uid) && value.owner_uid < 1000000000 && validBirth(value.birth, value.owner_uid);
  } catch { return false; }
}
function identityQuery(configValue, identity, timeoutMs) {
  let config;
  try { config = native.config({ darwin: configValue }).darwin; }
  catch { return unknown('verification_darwin_scope_invalid'); }
  if (!config.enabled || identity && !validateProcessIdentity(identity)) return unknown('verification_darwin_identity_invalid');
  if (identity) identity = copyInertData(identity, null, 4096);
  return withQuery(config, timeoutMs, ({ capability, request, checkpoint }) => {
    const nonce = crypto.randomBytes(32).toString('hex'), body = identity ?
      { op: 'observe_identity', identity, observation_nonce: nonce } : { op: 'peer_identity', observation_nonce: nonce };
    const value = copyInertData(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(request(body))), null, native.MAX_REPLY_BYTES);
    checkpoint();
    if (value?.ok !== true || value.schema !== 'knowledge-darwin-identity-observation.v1' || value.observation_nonce !== nonce ||
        !['host_id', 'boot_id', 'daemon_epoch', 'source_sha256', 'binary_sha256'].every(key => value[key] === capability[key]) ||
        value.capability_qualified !== true || value.qualification_mode !== false || value.qa_persistence_gate !== false ||
        value.proof_current !== false || value.cleanup_only !== true || !integer(value.observed_monotonic_ms)) {
      return unknown('verification_darwin_identity_observation_invalid');
    }
    if (!identity) {
      if (value.status !== 'active' || !validateProcessIdentity(value.identity) || value.identity.birth.pid !== process.pid ||
          value.identity.owner_uid !== process.getuid() || value.identity.boot_id !== capability.boot_id || value.identity.host_id !== capability.host_id) {
        return unknown('verification_darwin_peer_identity_mismatch');
      }
      return { status: 'observed', method: 'darwin_proc_birth', identity: freeze(value.identity), observation: value };
    }
    if (value.identity_sha256 !== wire.digest(identity) || value.host_id !== identity.host_id ||
        !['active', 'exited', 'unconfirmed'].includes(value.status) ||
        value.status === 'exited' && !(value.observation_basis === 'new_kernel_boot' && value.boot_id.toLowerCase() !== identity.boot_id.toLowerCase() ||
          value.observation_basis === 'exact_birth_absent_or_replaced' && value.boot_id.toLowerCase() === identity.boot_id.toLowerCase())) {
      return unknown('verification_darwin_identity_observation_invalid');
    }
    return { status: value.status, method: 'darwin_proc_birth', confirmed: value.status === 'exited', observation: value };
  });
}
function currentProcessIdentity(config, { timeoutMs = 5000 } = {}) { return identityQuery(config, null, timeoutMs); }
function verifyProcessExit(config, identity, { timeoutMs = 5000 } = {}) { return identityQuery(config, identity, timeoutMs); }
function retireCommandScope(scope, options = {}) {
  const proof = queryCommandScope(scope, options);
  return proof.status === 'completed' ? { ...proof, retirement: 'not_required' } : proof;
}
module.exports = { commandScope, validateCommandScope, validateObservation, queryCommandScope, recoverCommandScope, retireCommandScope,
  currentProcessIdentity, verifyProcessExit, validateProcessIdentity };
