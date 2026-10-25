'use strict';

// Production acceptance predicates. Diagnostic/old-source/old-epoch receipts
// are useful history and cleanup input, but cannot satisfy these predicates.
const crypto = require('node:crypto');
const path = require('node:path');
const { copyInertData } = require('./inert-data');
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const fail = code => { throw Object.assign(new Error(code), { code }); };
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort()
    .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const digest = value => sha(canonical(value));
const integer = value => Number.isSafeInteger(value) && value >= 0;
function inert(value) {
  try { return copyInertData(value, null, 1024 * 1024); }
  catch { fail('verification_darwin_protocol_invalid'); }
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child);Object.freeze(value); }
  return value;
}
function validateDescriptor(value, capability, nonce) {
  value = inert(value); const d = value?.descriptor;
  if (value?.ok !== true || !hex(value.attempt_id) || !hex(value.descriptor_sha256) || !d ||
      digest(d) !== value.descriptor_sha256 || d.attempt_id !== value.attempt_id || d.boundary_id !== value.attempt_id ||
      d.attempt_nonce !== nonce || d.schema !== 'knowledge-darwin-private-ruid-descriptor.v2' ||
      d.backend !== 'darwin_private_ruid' || d.mode !== 'isolated_copy' ||
      d.stub_wire_version !== 'KVS2' || d.guardian_protocol !== 'KVR2' ||
      d.capability_qualified !== true || d.qualification_mode !== false ||
      !hex(d.daemon_epoch) || d.daemon_epoch !== capability.daemon_epoch ||
      !['source_sha256', 'stub_source_sha256', 'stub_binary_sha256', 'transport_header_sha256',
        'uid_history_header_sha256', 'uid_history_source_sha256', 'installation_id',
        'account_policy_id', 'account_policy_sha256', 'host_id', 'boot_id']
        .every(key => d[key] === capability[key]) || d.broker_binary_sha256 !== capability.binary_sha256 ||
      d.allowed_runtimes?.[capability.runtime_path] !== capability.runtime_sha256 ||
      !integer(d.task_ruid) || d.task_ruid < 1000000000 || d.task_ruid >= 1900000000 || d.task_gid !== d.task_ruid ||
      !integer(d.owner_uid) || d.owner_uid < 1 || d.owner_uid >= 1000000000 ||
      !hex(d.installation_id) || !hex(d.allocation_sha256) ||
      typeof d.allocation_seq !== 'string' || !/^[1-9][0-9]{0,8}$/.test(d.allocation_seq) ||
      Number(d.allocation_seq) !== d.task_ruid - 1000000000 + 1 ||
      !path.posix.isAbsolute(d.workspace_path || '') || d.workspace_path !== value.workspace_path ||
      !integer(d.work_started_monotonic_ms) || !integer(d.work_budget_ms) || d.work_budget_ms < 1 ||
      d.work_deadline_ms !== d.work_started_monotonic_ms + d.work_budget_ms ||
      !integer(d.cleanup_budget_ms) || d.cleanup_budget_ms < 1 || d.cleanup_budget_ms > 3600000 ||
      !hex(value.token)) fail('verification_darwin_descriptor_invalid');
  return freeze({ attempt_id: value.attempt_id, descriptor_sha256: value.descriptor_sha256, descriptor: d });
}
function current(value, binding, capability) {
  const d = binding.descriptor;
  return value && value.attempt_id === binding.attempt_id && value.descriptor_sha256 === binding.descriptor_sha256 &&
    value.daemon_epoch === d.daemon_epoch && value.daemon_epoch === capability.daemon_epoch &&
    value.proof_current === true && integer(value.writer_generation) && value.writer_generation > 0 &&
    value.capability_qualified === true;
}
function validateCommand(value, binding, capability, command, ordinal) {
  value = inert(value);const d = binding.descriptor;
  if (!current(value, binding, capability) || value.ok !== true || value.schema !== 'knowledge-darwin-command-result.v1' ||
      value.command_ordinal !== ordinal || value.command_sha256 !== digest(command) ||
      !['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq', 'allocation_sha256', 'host_id', 'boot_id']
        .every(key => value[key] === d[key]) || value.guardian_protocol !== 'KVR2' || value.guardian_reaped !== true ||
      value.permit_observed !== true || value.timed_out !== false || value.stop_latched !== false ||
      value.admission_closed !== false ||
      !(value.exit_code === null || integer(value.exit_code) && value.exit_code <= 255) ||
      !(value.signal === null || integer(value.signal) && value.signal >= 1 && value.signal <= 128) ||
      (value.exit_code === null) === (value.signal === null)) fail('verification_darwin_command_receipt_invalid');
  return value;
}
function validateProof(value, binding, capability, terminal) {
  value = inert(value);const p = terminal ? value?.proof : value?.command_drain_proof, d = binding.descriptor;
  if (!current(value, binding, capability) || !current(p, binding, capability) || value.ok !== true ||
      p.writer_generation !== value.writer_generation || value.cleanup_only !== false ||
      value.allocation_tuple_verified_current !== true || value.registry_healthy !== true || value.observation_cached === true ||
      value.cleanup_budget_exceeded !== false || value.abort_latched !== false || p.abort_latched !== false ||
      p.schema !== (terminal ? 'knowledge-darwin-private-ruid-proof.v1' : 'knowledge-darwin-command-drain-proof.v1') ||
      !['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq', 'allocation_sha256',
        'host_id', 'boot_id', 'account_policy_id', 'account_policy_sha256', 'task_ruid'].every(key => p[key] === d[key]) ||
      value[terminal ? 'proof_sha256' : 'command_drain_sha256'] !== digest(p) || p.uid_history_tuple_verified !== true ||
      p.terminal_cleanup !== terminal || p.kernel_membership_zero !== true || p.admission_closed !== true ||
      p.spawn_exclusion_acquired !== true || p.spawn_intents_resolved !== true ||
      p.guardian_exit_confirmed !== true || p.root_child_exit_confirmed !== true ||
      !integer(p.observed_monotonic_ms) || !integer(p.cleanup_started_monotonic_ms) ||
      !integer(p.cleanup_deadline_monotonic_ms) || p.cleanup_deadline_monotonic_ms <= p.cleanup_started_monotonic_ms ||
      p.cleanup_deadline_monotonic_ms - p.cleanup_started_monotonic_ms > d.cleanup_budget_ms ||
      p.observed_monotonic_ms < p.cleanup_started_monotonic_ms || p.observed_monotonic_ms >= p.cleanup_deadline_monotonic_ms ||
      (terminal ? value.state !== 'closed' || value.planned_terminal !== true || p.planned_terminal !== true ||
          p.native_cleanup_facts_confirmed !== true || p.cleanup_confirmed !== true || p.registered_authority_exited !== true ||
          p.cleanup_budget_exceeded !== false || value.stop_reason !== 'close_requested'
        : value.state !== 'commands_drained' || value.stop_reason !== 'commands_complete' ||
          p.native_command_drain_facts_confirmed !== true || p.command_drain_confirmed !== true ||
          p.registered_authority_alive !== true || p.spawn_exclusion_held_until_terminal !== true)) {
    fail('verification_darwin_current_proof_invalid');
  }
  return p;
}
function validateReadback(value, binding, plan, phase) {
  value = inert(value);const { ok, readback_sha256, ...body } = value || {};
  if (ok !== true || value.schema !== 'knowledge-darwin-copy-readback.v1' ||
      value.attempt_id !== binding.attempt_id || value.descriptor_sha256 !== binding.descriptor_sha256 ||
      value.phase !== phase || value.manifest_sha256 !== plan.manifest_sha256 ||
      value.directories_sha256 !== plan.directories_sha256 || value.files !== plan.files.length ||
      value.directories !== plan.directories.length || value.bytes !== plan.total_bytes ||
      value.verified_current !== true || value.allocation_tuple_verified_current !== true || value.capability_qualified !== true ||
      !value.workspace_identity || !['device', 'inode'].every(key => typeof value.workspace_identity[key] === 'string' &&
        /^(?:0|[1-9][0-9]*)$/.test(value.workspace_identity[key])) ||
      !integer(value.observed_monotonic_ms) || !hex(readback_sha256) || digest(body) !== readback_sha256) {
    fail('verification_darwin_copy_readback_invalid');
  }
  return value;
}
module.exports = { hex, sha, canonical, digest, validateDescriptor, validateCommand, validateProof, validateReadback };
