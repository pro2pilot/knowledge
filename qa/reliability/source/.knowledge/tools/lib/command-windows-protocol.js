'use strict';

// These signatures bind a trusted holder's terminal observation to one
// immutable scope. They are not a sandbox against a malicious same-SID
// process which can inject into or duplicate handles from another process.
const crypto = require('crypto');
const path = require('path');
const { copyInertData } = require('./inert-data');
const MAX_BYTES = 32768;
const ASSIGNMENT = 'exact-root-once-no-breakaway.v1';
const HEX = /^[a-f0-9]{64}$/;
const decimal = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const digest = value => sha(canonical(value));
function validIdentity(value) {
  return exact(value, ['pid', 'birth_filetime']) && Number.isSafeInteger(value.pid) && value.pid > 0 && value.pid <= 4294967295 && decimal(value.birth_filetime);
}
function validKey(value) {
  try {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{59}=$/.test(value)) return false;
    const bytes = Buffer.from(value, 'base64');
    return bytes.length === 44 && bytes.toString('base64') === value &&
      crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' }).asymmetricKeyType === 'ed25519';
  } catch { return false; }
}
function validHost(value) {
  return exact(value, ['machine_guid_sha256', 'computer_name_sha256', 'user_sid_sha256', 'session_id']) &&
    ['machine_guid_sha256', 'computer_name_sha256', 'user_sid_sha256'].every(key => HEX.test(value[key] || '')) &&
    Number.isSafeInteger(value.session_id) && value.session_id >= 0 && value.session_id <= 4294967295;
}
function validNative(value) {
  return exact(value, ['schema_version', 'source_sha256', 'binary_sha256', 'architecture', 'assignment', 'watchdog']) &&
    value.schema_version === 'knowledge-command-windows-native.v1' && HEX.test(value.source_sha256 || '') &&
    HEX.test(value.binary_sha256 || '') && ['x64', 'arm64'].includes(value.architecture) &&
    value.assignment === ASSIGNMENT && value.watchdog === 'native-pipe-process-handles.v1';
}
function validStore(value) {
  // The pathname is a fixed-format, physical per-scope directory in the
  // creating user's temp area. All I/O also checks its original file ID.
  return exact(value, ['directory', 'dev', 'ino', 'scope_id']) && typeof value.directory === 'string' &&
    value.directory.length <= 4096 && !value.directory.includes('\0') && !value.directory.startsWith('\\\\') &&
    /^[A-Za-z]:\\/.test(value.directory) && path.win32.normalize(value.directory) === value.directory &&
    value.directory.slice(2).indexOf(':') === -1 && !value.directory.split('\\').some(part => /[ .]$/.test(part)) &&
    path.win32.basename(value.directory) === `knowledge-command-receipt-${value.scope_id}` &&
    HEX.test(value.scope_id || '') && /^(?:0|[1-9][0-9]{0,19})$/.test(value.dev || '') && decimal(value.ino);
}
function validateDescriptor(input) {
  try {
    const d = copyInertData(input, null, MAX_BYTES);
    if (!exact(d, ['schema_version', 'backend', 'scope_id', 'job_name', 'native', 'host', 'controller', 'root', 'primary', 'secondary', 'receipt_store']) ||
        d.schema_version !== 'knowledge-windows-command-job.v2' || d.backend !== 'windows_job_object' || !HEX.test(d.scope_id || '') ||
        d.job_name !== `Local\\KnowledgeCommand-${d.scope_id}` || !validNative(d.native) || !validHost(d.host) ||
        !validIdentity(d.controller) || !validIdentity(d.root) ||
        !exact(d.primary, ['identity', 'public_key']) || !validIdentity(d.primary.identity) || !validKey(d.primary.public_key)) return false;
    const identities = [d.controller, d.root, d.primary.identity];
    if (d.secondary !== null) {
      if (!exact(d.secondary, ['identity', 'controller', 'public_key']) || !validIdentity(d.secondary.identity) ||
          !validIdentity(d.secondary.controller) || !validKey(d.secondary.public_key) ||
          !validStore(d.receipt_store) || d.receipt_store.scope_id !== d.scope_id) return false;
      identities.push(d.secondary.identity);
      if (d.primary.public_key === d.secondary.public_key) return false;
      if ([d.root, d.primary.identity, d.secondary.identity].some(row => row.pid === d.secondary.controller.pid)) return false;
    } else if (d.receipt_store !== null) return false;
    return new Set(identities.map(value => value.pid)).size === identities.length;
  } catch { return false; }
}
function commandScope(descriptor) {
  if (!validateDescriptor(descriptor)) throw Object.assign(new Error('Invalid Windows command scope'), { code: 'command_windows_scope_invalid' });
  return Object.freeze(copyInertData({ schema_version: 'knowledge-command-scope.v1', backend: 'windows_job_object', descriptor }, null, MAX_BYTES));
}
function validateScope(value) {
  return exact(value, ['schema_version', 'backend', 'descriptor']) && value.schema_version === 'knowledge-command-scope.v1' &&
    value.backend === 'windows_job_object' && validateDescriptor(value.descriptor);
}
function keyPair() {
  const pair = crypto.generateKeyPairSync('ed25519');
  return { privateKey: pair.privateKey, publicKey: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
}
function signTerminal(scope, role, observation, privateKey) {
  if (!validateScope(scope) || !scope.descriptor.secondary || !['primary', 'secondary'].includes(role) ||
      observation?.drained !== true || observation.stop_latched !== true || observation.kernel_query_ok !== true ||
      observation.active_processes !== 0 || observation.root_exited !== true) {
    throw Object.assign(new Error('A fresh kernel terminal observation is required'), { code: 'command_windows_receipt_precondition' });
  }
  const body = {
    schema_version: 'knowledge-windows-command-terminal.v1', scope_sha256: digest(scope), descriptor_sha256: digest(scope.descriptor),
    scope_id: scope.descriptor.scope_id, role, holder: scope.descriptor[role].identity,
    root: scope.descriptor.root, native: scope.descriptor.native, host: scope.descriptor.host,
    assignment: ASSIGNMENT, admission_sealed: true, root_exited: true, kernel_membership_zero: true,
    active_processes: 0, receipt_nonce: crypto.randomBytes(32).toString('hex')
  };
  return { body, signature: crypto.sign(null, Buffer.from(canonical(body)), privateKey).toString('base64') };
}
function validateTerminal(value, scope) {
  try {
    value = copyInertData(value, null, MAX_BYTES);
    if (!validateScope(scope) || !scope.descriptor.secondary || !exact(value, ['body', 'signature']) ||
        !exact(value.body, ['schema_version', 'scope_sha256', 'descriptor_sha256', 'scope_id', 'role', 'holder', 'root', 'native', 'host',
          'assignment', 'admission_sealed', 'root_exited', 'kernel_membership_zero', 'active_processes', 'receipt_nonce'])) return false;
    const b = value.body, d = scope.descriptor;
    if (b.schema_version !== 'knowledge-windows-command-terminal.v1' || b.scope_sha256 !== digest(scope) ||
        b.descriptor_sha256 !== digest(d) || b.scope_id !== d.scope_id || !['primary', 'secondary'].includes(b.role) ||
        ![ ['holder', d[b.role].identity], ['root', d.root], ['native', d.native], ['host', d.host] ]
          .every(([key, expected]) => canonical(b[key]) === canonical(expected)) ||
        b.assignment !== ASSIGNMENT || b.admission_sealed !== true || b.root_exited !== true || b.kernel_membership_zero !== true ||
        b.active_processes !== 0 || !HEX.test(b.receipt_nonce || '') || typeof value.signature !== 'string' ||
        !/^[A-Za-z0-9+/]{86}==$/.test(value.signature)) return false;
    const signature = Buffer.from(value.signature, 'base64');
    return signature.length === 64 && signature.toString('base64') === value.signature && crypto.verify(null,
      Buffer.from(canonical(b)), crypto.createPublicKey({ key: Buffer.from(d[b.role].public_key, 'base64'), format: 'der', type: 'spki' }), signature);
  } catch { return false; }
}
module.exports = { MAX_BYTES, ASSIGNMENT, HEX, canonical, digest, sha, validIdentity, validHost, validNative, validStore,
  validateDescriptor, commandScope, validateScope, keyPair, signTerminal, validateTerminal };
