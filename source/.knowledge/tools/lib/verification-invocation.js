'use strict';
// The runner creates this binding from actual native admission, before the
// worker can import project storage. A request or persisted PID is not proof.
const crypto = require('crypto');
const { copyInertData } = require('./inert-data');
const SCHEMA = 'knowledge-verification-invocation.v1';
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const invalid = () => Object.assign(new Error('Verification invocation is not bound to this native worker'), { code: 'verification_invocation_invalid' });
function freeze(value) { if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function validInvocation(value) {
  try {
    value = copyInertData(value, null, 32768);
    return value && Object.keys(value).sort().join(',') === 'nonce_sha256,schema_version,scope,scope_sha256' &&
      value.schema_version === SCHEMA && /^[a-f0-9]{64}$/.test(value.nonce_sha256 || '') &&
      /^[a-f0-9]{64}$/.test(value.scope_sha256 || '') && value.scope_sha256 === digest(value.scope) &&
      ['linux_pid_namespace', 'windows_job_object'].includes(value.scope?.backend) &&
      require('./command-scope-proof').validateExecutionScope(value.scope) &&
      (value.scope.backend !== 'windows_job_object' || !!value.scope.descriptor.secondary);
  } catch { return false; }
}
function createInvocation(scope) {
  scope = copyInertData(scope, null, 32768);
  const value = { schema_version: SCHEMA, nonce_sha256: digest(crypto.randomBytes(32).toString('hex')),
    scope_sha256: digest(scope), scope };
  if (!validInvocation(value)) throw invalid();
  return freeze(value);
}
function admitWorkerInvocation(value, helper) {
  if (!validInvocation(value)) throw invalid();
  value = copyInertData(value, null, 32768);
  const d = value.scope.descriptor;
  if (process.platform === 'linux' && value.scope.backend === 'linux_pid_namespace') {
    const provider = require('./verification-linux-namespace');
    provider.setInvocationHelper(helper);
    const current = provider.currentProcessIdentity(), expected = d.worker, actual = current.identity;
    if (current.boot_id !== d.boot_id || current.procfs_dev !== d.procfs_dev ||
        current.namespace_identity_provider !== d.namespace_identity_provider || actual.pid !== process.pid ||
        actual.proc_pid !== expected.proc_pid || actual.start_ticks !== expected.start_ticks ||
        actual.namespace_pid !== expected.namespace_pid || !provider.sameNamespaceIdentity(actual.pid_namespace, expected.pid_namespace) ||
        JSON.stringify(actual.proc_pid_chain) !== JSON.stringify(expected.proc_pid_chain) ||
        helper.source_sha256 !== d.helper.source_sha256 || helper.binary_sha256 !== d.helper.binary_sha256) throw invalid();
  } else if (process.platform === 'win32' && value.scope.backend === 'windows_job_object') {
    const loader = require('./command-windows-native'), protocol = require('./command-windows-protocol');
    const loaded = loader.loadPreparedHelper(helper), actual = loaded.native.currentIdentity();
    if (protocol.canonical(actual) !== protocol.canonical(d.root) || protocol.canonical(loaded.binding) !== protocol.canonical(d.native) ||
        protocol.canonical(loader.hostBinding(loaded.native)) !== protocol.canonical(d.host) || !loaded.native.memberOf(d.job_name, actual)) throw invalid();
  } else throw invalid();
  return freeze(value);
}
module.exports = { SCHEMA, createInvocation, validInvocation, admitWorkerInvocation };
