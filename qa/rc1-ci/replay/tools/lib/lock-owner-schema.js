'use strict';

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
  const keys = Object.keys(owner);
  const unknown = keys.filter((key) => !OWNER_FIELDS.includes(key));
  const missing = OWNER_FIELDS.filter((key) => !Object.prototype.hasOwnProperty.call(owner, key));
  if (unknown.length) throw ownerError('unknown_fields');
  if (missing.length) throw ownerError('missing_fields');
  if (keys.length !== OWNER_FIELDS.length || keys.some((key, index) => key !== OWNER_FIELDS[index])) {
    throw ownerError('noncanonical_field_order');
  }
  if (owner.schema_version !== 'knowledge-lock-owner.v1') throw ownerError('schema_version_invalid');
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
  validateOwner,
  canonicalOwnerText,
  sanitizedOwner,
};
