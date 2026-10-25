'use strict';

const { validNativeOwnerIdentity } = require('./lock-policy');

const OWNER_FIELDS = Object.freeze([
  'schema_version',
  'lock_id',
  'lock_name',
  'purpose',
  'pid',
  'hostname',
  'agent_id',
  'workspace_id',
  'process_started_at',
  'acquired_at',
  'nonce',
]);
const V2_OWNER_FIELDS = Object.freeze([...OWNER_FIELDS, 'native_identity']);
const V3_OWNER_FIELDS = Object.freeze([...V2_OWNER_FIELDS, 'publication', 'kernel_lease', 'execution_scope']);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE_PATTERN = /^[0-9a-f]{32,128}$/;

function ownerError(reason) {
  const error = new Error(`Lock owner metadata is invalid (${reason}).`);
  error.code = 'lock_owner_invalid';
  error.reason = reason;
  return error;
}

function boundedString(value, field, max, options = {}) {
  if (value === null && options.nullable) return null;
  if (typeof value !== 'string' || value.length < (options.min || 1) || value.length > max) {
    throw ownerError(`${field}_invalid`);
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) throw ownerError(`${field}_control_character`);
  return value;
}

function isoTimestamp(value, field) {
  boundedString(value, field, 64);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) throw ownerError(`${field}_invalid`);
  return value;
}

function validateOwner(owner, expected = {}) {
  if (!owner || typeof owner !== 'object' || Array.isArray(owner)) throw ownerError('not_object');
  const fields = owner.schema_version === 'knowledge-lock-owner.v3' ? V3_OWNER_FIELDS
    : owner.schema_version === 'knowledge-lock-owner.v2' ? V2_OWNER_FIELDS : OWNER_FIELDS;
  const keys = Object.keys(owner);
  const unknown = keys.filter((key) => !fields.includes(key));
  const missing = fields.filter((key) => !Object.prototype.hasOwnProperty.call(owner, key));
  if (unknown.length) throw ownerError('unknown_fields');
  if (missing.length) throw ownerError('missing_fields');
  if (keys.length !== fields.length || keys.some((key, index) => key !== fields[index])) {
    throw ownerError('noncanonical_field_order');
  }
  if (!['knowledge-lock-owner.v1', 'knowledge-lock-owner.v2', 'knowledge-lock-owner.v3'].includes(owner.schema_version)) throw ownerError('schema_version_invalid');
  if (!UUID_PATTERN.test(String(owner.lock_id || ''))) throw ownerError('lock_id_invalid');
  boundedString(owner.lock_name, 'lock_name', 63);
  boundedString(owner.purpose, 'purpose', 256);
  if (!Number.isSafeInteger(owner.pid) || owner.pid <= 0) throw ownerError('pid_invalid');
  boundedString(owner.hostname, 'hostname', 255);
  boundedString(owner.agent_id, 'agent_id', 256, { nullable: true });
  boundedString(owner.workspace_id, 'workspace_id', 256, { nullable: true });
  isoTimestamp(owner.process_started_at, 'process_started_at');
  isoTimestamp(owner.acquired_at, 'acquired_at');
  if (!NONCE_PATTERN.test(String(owner.nonce || ''))) throw ownerError('nonce_invalid');
  if (['knowledge-lock-owner.v2', 'knowledge-lock-owner.v3'].includes(owner.schema_version) && owner.native_identity !== null &&
      !validNativeOwnerIdentity(owner.native_identity, owner.pid)) throw ownerError('native_identity_invalid');
  if (owner.schema_version === 'knowledge-lock-owner.v3') {
    if (owner.publication !== 'atomic-directory-noreplace.v1') throw ownerError('publication_invalid');
    const lease = owner.kernel_lease;
    const leaseFields = ['method', 'owner_dev', 'owner_ino', 'directory_dev', 'directory_ino'];
    if (!lease || typeof lease !== 'object' || Array.isArray(lease) ||
        Object.keys(lease).length !== leaseFields.length ||
        Object.keys(lease).some((key, index) => key !== leaseFields[index]) ||
        !['owner-inode-lease.v1','windows-owner-event.v1'].includes(lease.method) ||
        lease.owner_ino === '0' || lease.directory_ino === '0' ||
        leaseFields.slice(1).some(key => typeof lease[key] !== 'string' || !/^(0|[1-9][0-9]{0,39})$/.test(lease[key]))) {
      throw ownerError('kernel_lease_invalid');
    }
    if (owner.execution_scope !== null) {
      const scope = owner.execution_scope;
      const fields = ['schema_version', 'backend', 'sha256'];
      if (!scope || typeof scope !== 'object' || Array.isArray(scope) || Object.keys(scope).length !== fields.length ||
          Object.keys(scope).some((key, index) => key !== fields[index]) ||
          scope.schema_version !== 'knowledge-command-scope-binding.v1' ||
          !['linux_pid_namespace', 'windows_job_object', 'darwin_uid_guardian'].includes(scope.backend) ||
          !/^[0-9a-f]{64}$/.test(String(scope.sha256 || ''))) throw ownerError('execution_scope_binding_invalid');
    }
  }
  if (expected.lockName && owner.lock_name !== expected.lockName) throw ownerError('lock_name_mismatch');
  if (expected.purpose && owner.purpose !== expected.purpose) throw ownerError('purpose_mismatch');
  return owner;
}

function canonicalOwnerText(owner) {
  validateOwner(owner, { lockName: owner.lock_name, purpose: owner.purpose });
  return `${JSON.stringify(owner, null, 2)}\n`;
}

function sanitizedOwner(owner) {
  if (!owner || typeof owner !== 'object') return null;
  return {
    pid: Number.isSafeInteger(owner.pid) && owner.pid > 0 ? owner.pid : null,
    hostname: typeof owner.hostname === 'string' ? owner.hostname.slice(0, 255) : null,
    agent_id: typeof owner.agent_id === 'string' ? owner.agent_id.slice(0, 256) : null,
    acquired_at: typeof owner.acquired_at === 'string' ? owner.acquired_at.slice(0, 64) : null,
  };
}

module.exports = {
  OWNER_FIELDS,
  V2_OWNER_FIELDS,
  V3_OWNER_FIELDS,
  validateOwner,
  canonicalOwnerText,
  sanitizedOwner,
};
