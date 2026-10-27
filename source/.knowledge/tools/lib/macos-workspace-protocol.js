'use strict';

// Writable workspace admission is deliberately a different protocol. A KVS3
// descriptor can never pass the isolated-copy/KVS2 validator, and this module
// does not authorize a workspace: the native administrator capability does.
const wire = require('./verification-darwin-session-protocol');
const { copyInertData } = require('./inert-data');
const { MAX_WORK_MS, MAX_CLEANUP_MS } = require('./verification-policy');
const SCHEMA = 'knowledge-macos-writable-descriptor.v1';
const MODE = 'admin_writable_workspace.v1';
const SOURCE_KEYS = Object.freeze(['source_sha256', 'stub_source_sha256', 'stub_binary_sha256',
  'transport_header_sha256', 'uid_history_header_sha256', 'uid_history_source_sha256']);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);
const decimal = value => typeof value === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value) &&
  BigInt(value) <= 18446744073709551615n;
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const canonicalPath = value => typeof value === 'string' && value.length <= 4096 && value.startsWith('/') &&
  value !== '/' && !/[\x00-\x1f\x7f\\]/.test(value) && value.split('/').slice(1).every(part => part && part !== '.' && part !== '..');
const inside = (root, value) => root === value || value.startsWith(root + '/');
const fail = () => { throw Object.assign(new Error('Writable macOS descriptor is invalid'), { code: 'macos_workspace_descriptor_invalid' }); };
function inert(value, maximum = 65536) {
  // Keep the wire-byte ceiling independent from conservative traversal work
  // accounting, which otherwise charges every UTF16 unit as six bytes.
  const data = copyInertData(value, null, maximum * 32);
  if (Buffer.byteLength(JSON.stringify(data)) > maximum) fail();
  return data;
}
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child);Object.freeze(value); }
  return value;
}
function validDescriptorFields(value) {
  try {
    const d = inert(value, 32768), identity = d?.writable_identity;
    return !!(d && d.schema === SCHEMA && d.backend === 'darwin_private_ruid' && d.mode === MODE &&
      d.stub_wire_version === 'KVS3' && d.guardian_protocol === 'KVR2' &&
      d.capability_qualified === true && d.qualification_mode === false &&
      [...SOURCE_KEYS, 'broker_binary_sha256', 'daemon_epoch', 'installation_id', 'allocation_sha256',
        'account_policy_sha256', 'workspace_id', 'workspace_capability_sha256', 'attempt_id', 'attempt_nonce']
        .every(key => wire.hex(d[key])) && d.boundary_id === d.attempt_id &&
      uuid(d.host_id) && uuid(d.boot_id) && d.account_policy_id === 'admin_reserved_interval_no_runtime_nss.v1' &&
      integer(d.owner_uid) && d.owner_uid >= 1 && d.owner_uid < 1000000000 &&
      integer(d.task_ruid) && d.task_ruid >= 1000000000 && d.task_ruid < 1900000000 &&
      integer(d.task_gid) && d.task_gid >= 2000000000 && d.task_gid < 2100000000 && d.task_gid !== d.task_ruid &&
      typeof d.allocation_seq === 'string' && /^[1-9][0-9]{0,8}$/.test(d.allocation_seq) &&
      Number(d.allocation_seq) === d.task_ruid - 1000000000 + 1 &&
      canonicalPath(d.workspace_path) && d.scratch_policy === 'admin_workspace_acl_sibling.v1' &&
      d.scratch_path === d.workspace_path + '.scratch' &&
      canonicalPath(d.writable_root) && canonicalPath(d.protected_worker_root) &&
      !inside(d.writable_root, d.protected_worker_root) && !inside(d.protected_worker_root, d.writable_root) &&
      exact(identity, ['device', 'inode', 'owner_uid', 'group_gid', 'mode']) &&
      decimal(identity.device) && decimal(identity.inode) && identity.inode !== '0' &&
      identity.owner_uid === d.owner_uid && identity.group_gid === d.task_gid &&
      identity.mode === 0o770 &&
      integer(d.work_started_monotonic_ms) && integer(d.work_budget_ms) && d.work_budget_ms >= 1 &&
      d.work_budget_ms <= MAX_WORK_MS && integer(d.work_deadline_ms) &&
      d.work_deadline_ms === d.work_started_monotonic_ms + d.work_budget_ms &&
      integer(d.cleanup_budget_ms) && d.cleanup_budget_ms >= 1 && d.cleanup_budget_ms <= MAX_CLEANUP_MS &&
      d.allowed_runtimes && !Array.isArray(d.allowed_runtimes) && typeof d.allowed_runtimes === 'object' &&
      Object.keys(d.allowed_runtimes).length >= 1 && Object.keys(d.allowed_runtimes).length <= 64 &&
      Object.entries(d.allowed_runtimes).every(([name, hash]) => canonicalPath(name) && wire.hex(hash)));
  } catch { return false; }
}
function validateDescriptor(value, capability, nonce) {
  try {
    value = inert(value);capability = inert(capability);const d = value?.descriptor;
    if (!validDescriptorFields(d) || value.ok !== true || !wire.hex(value.attempt_id) ||
        !wire.hex(value.descriptor_sha256) || wire.digest(d) !== value.descriptor_sha256 ||
        d.attempt_id !== value.attempt_id || d.attempt_nonce !== nonce || !wire.hex(nonce) ||
        d.workspace_path !== value.workspace_path || !wire.hex(value.token) ||
        ![...SOURCE_KEYS, 'daemon_epoch', 'installation_id', 'account_policy_id', 'account_policy_sha256', 'host_id', 'boot_id']
          .every(key => d[key] === capability[key]) ||
        d.broker_binary_sha256 !== capability.binary_sha256 ||
        !canonicalPath(capability.runtime_path) || !wire.hex(capability.runtime_sha256) ||
        d.allowed_runtimes[capability.runtime_path] !== capability.runtime_sha256) fail();
    return freeze({ attempt_id: value.attempt_id, descriptor_sha256: value.descriptor_sha256, descriptor: d });
  } catch { fail(); }
}
module.exports = { SCHEMA, MODE, SOURCE_KEYS, canonicalPath, validDescriptorFields, validateDescriptor };
