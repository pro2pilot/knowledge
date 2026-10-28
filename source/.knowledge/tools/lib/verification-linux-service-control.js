'use strict';

// The Linux service owns its private A/W namespace; its PIDs are not ordinary
// controller children. Preserve the actual native allocation descriptor and
// exact terminal bytes instead of inventing common-ledger process identities.
const f = require('./verification-linux-service-finalization');
const SCHEMA = 'knowledge-linux-service-control-descriptor.v1';
const METHOD = f.METHOD;
const STORAGE_PROTOCOL = 'lifetime_lease.v1';
const digest = value => f.hash(JSON.stringify(value));
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function fail(code = 'verification_linux_service_control_proof_invalid') { throw Object.assign(new Error(code), { code }); }
function need(value, code) { if (!value) fail(code); }
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
function validateDescriptor(input) {
  try {
    const value = f.inert(input, 32768);
    return exact(value, ['schema_version', 'backend', 'storage_protocol', 'capability', 'opened']) &&
      value.schema_version === SCHEMA && value.backend === METHOD && value.storage_protocol === STORAGE_PROTOCOL &&
      f.validateCapability(value.capability) && f.validateOpened(value.opened) &&
      value.opened.authority_uid !== value.capability.controller_uid && value.opened.worker_uid !== value.capability.controller_uid;
  } catch { return false; }
}
function descriptor(input) {
  input = f.inert(input, 32768);
  need(exact(input, ['capability', 'opened']), 'verification_linux_service_control_descriptor_invalid');
  const value = { schema_version: SCHEMA, backend: METHOD, storage_protocol: STORAGE_PROTOCOL,
    capability: input.capability, opened: input.opened };
  need(validateDescriptor(value), 'verification_linux_service_control_descriptor_invalid');
  return freeze(value);
}
function validateAttemptBinding(attempt, containment = attempt?.containment) {
  try {
    return attempt?.storage_protocol === STORAGE_PROTOCOL && validateDescriptor(containment?.descriptor) &&
      containment.backend === METHOD && Array.isArray(containment.spawn_ids) && containment.spawn_ids.length === 0 &&
      Array.isArray(attempt.processes) && attempt.processes.length === 0 &&
      attempt.startup_nonce_sha256 === f.hash(containment.descriptor.opened.nonce) &&
      attempt.profile.cleanup_budget_ms === containment.descriptor.opened.cleanup_budget_ms;
  } catch { return false; }
}
function normalProof(input) {
  const { descriptor: d, terminalReply, terminalRaw, capability } = f.inert(input, 32768);
  need(validateDescriptor(d) && f.same(capability, d.capability));
  const terminal = f.validateTerminal({ capability, terminalReply, terminalRaw, opened: d.opened,
    successful: terminalReply?.status === 'completed' });
  return { status: 'completed', method: METHOD, descriptor_sha256: digest(d),
    native_terminal_sha256: terminal.proof_sha256, storage_protocol: STORAGE_PROTOCOL,
    proof_kind: 'normal_current', proof_current: true, cleanup_only: terminal.status !== 'completed',
    active_processes: 0, controller_excluded_from_boundary: true, controller_exited: false,
    worker_exited: true, keeper_exited: true, init_exit_observed: true, init_reaped: true, namespace_drained: true,
    terminal_reply: terminal, terminal_raw: terminalRaw, capability };
}
function validateProof(input, d) {
  try {
    const proof = f.inert(input, 32768);
    if (proof.proof_kind !== 'normal_current') return false;
    const expected = normalProof({ descriptor: d, terminalReply: proof.terminal_reply,
      terminalRaw: proof.terminal_raw, capability: proof.capability });
    return Object.entries(expected).every(([key, value]) => f.same(proof[key], value));
  } catch { return false; }
}
// A fresh process has no retained original pidfd/cgroup custody. The root
// service fences lost custody durably. Missing PIDs/cgroups cannot clear it.
function recoverContainer() { return { status: 'unconfirmed', method: METHOD, code: 'verification_linux_service_custody_unconfirmed' }; }
module.exports = { SCHEMA, METHOD, STORAGE_PROTOCOL, descriptor, validateDescriptor, validateAttemptBinding,
  normalProof, validateProof, recoverContainer };
