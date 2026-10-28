'use strict';
const crypto = require('crypto');
const path = require('path');
const { spawnSync } = require('child_process');
const { copyInertData } = require('./inert-data');
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
let relay;
const macosTerminals = new Map();
function validateExecutionScope(value) {
  try {
    const scope = copyInertData(value);
    if (!scope || scope.schema_version !== 'knowledge-command-scope.v1' || Buffer.byteLength(JSON.stringify(scope)) > 32768) return false;
    if (scope.backend === 'darwin_uid_guardian') return require('./verification-darwin-scope').validateCommandScope(scope);
    if (scope.backend === 'macos_uid_guardian') return require('./macos-command-scope').validateCommandScope(scope);
    if (scope.backend === 'linux_pid_namespace') {
      const descriptor = scope.descriptor;
      const native = require('./verification-linux-namespace');
      if (!native.validDescriptor(descriptor) || !Array.isArray(scope.observer_lineage) || !scope.observer_lineage.length || scope.observer_lineage.length > 64) return false;
      let prior = 0; const seen = new Set();
      for (const row of scope.observer_lineage) {
        if (!native.validNamespaceIdentity(row.namespace) || row.namespace.provider !== descriptor.observer_pid_namespace.provider ||
            !Number.isSafeInteger(row.depth) || row.depth <= prior || row.depth > 64) return false;
        const key = `${row.namespace.provider || 'linux_nsfs_stat.v1'}:${row.namespace.dev || ''}:${row.namespace.ino}`;
        if (seen.has(key)) return false;
        prior = row.depth; seen.add(key);
      }
      const last = scope.observer_lineage[scope.observer_lineage.length - 1];
      if (!native.sameNamespaceIdentity(last.namespace, descriptor.observer_pid_namespace)) return false;
      for (const role of ['controller', 'keeper', 'init', 'worker']) {
        const identity = descriptor[role], chain = identity.proc_pid_chain;
        if (!Array.isArray(chain) || !chain.length || chain.length > 64 || chain.some(p => !Number.isSafeInteger(p) || p < 1) ||
            chain[0] !== identity.proc_pid || chain[chain.length - 1] !== identity.namespace_pid || chain[last.depth - 1] !== identity.pid) return false;
      }
      return descriptor.controller.proc_pid_chain.length === last.depth && descriptor.init.proc_pid_chain.length === last.depth + 1;
    }
    if (scope.backend === 'windows_job_object') {
      if (scope.descriptor?.schema_version === 'knowledge-windows-command-job.v2') {
        return require('./command-windows-protocol').validateScope(scope) && scope.descriptor.secondary !== null;
      }
      const descriptor = scope.descriptor, host = descriptor?.host;
      return descriptor?.schema_version === 'knowledge-windows-job.v1' && descriptor.backend === scope.backend &&
        /^Local\\KnowledgeVerification-[a-f0-9]{64}$/.test(descriptor.job_name || '') && /^[a-f0-9]{64}$/.test(descriptor.source_sha256 || '') &&
        host && ['machine_guid_sha256', 'computer_name_sha256', 'user_sid_sha256'].every(key => /^[a-f0-9]{64}$/.test(host[key] || '')) &&
        Number.isSafeInteger(host.session_id) && host.session_id >= 0 && ['controller', 'keeper', 'worker'].every(role =>
          Number.isSafeInteger(descriptor.identities?.[role]?.pid) && descriptor.identities[role].pid > 0 && Number.isFinite(Date.parse(descriptor.identities[role].os_creation_time)));
    }
    return false;
  } catch { return false; }
}
function setScopeProofRelay(value) {
  if (!value || value.address?.host !== '127.0.0.1' || !Number.isInteger(value.address.port) || value.address.port < 1 || value.address.port > 65535 || !/^[a-f0-9]{64}$/.test(value.token || '')) throw Object.assign(new Error('Invalid proof relay'), { code: 'command_scope_relay_invalid' });
  relay = Object.freeze({ address: Object.freeze({ host: value.address.host, port: value.address.port }), token: value.token });
}
// Only the fixed, immutable ordinary-UID operation worker installs this after
// authenticated parent IPC supplies a freshly observed irreversible terminal.
// It has no native-spawn permission and must not launch a helper during lock
// release. Other generations/scopes never inherit this local observation.
function setMacOSTerminalObservation(scope, observation, capability, nonce) {
  const api = require('./macos-command-scope');
  if (process.platform !== 'darwin' || !api.validateCommandScope(scope) || scope.binding.descriptor.owner_uid !== process.getuid()) {
    throw Object.assign(new Error('Invalid macOS scope'), { code: 'command_macos_scope_invalid' });
  }
  const proof = api.validateObservation(observation, scope, capability, nonce);
  const key = digest(scope);
  if (proof.status !== 'completed' || !macosTerminals.has(key) && macosTerminals.size >= 64) {
    throw Object.assign(new Error('Invalid macOS terminal'), { code: 'command_macos_terminal_invalid' });
  }
  macosTerminals.set(key, Object.freeze({ scopeSha256: key, proof: copyInertData(proof, null, 65536) }));
}
function queryScopeClosure(value, { timeoutMs = 5000, localOnly = false } = {}) {
  const started = process.hrtime.bigint();
  const unknown = code => ({ status: 'unconfirmed', method: value?.backend || 'unknown', code });
  // Lock release supplies the fractional remainder of a monotonic budget.
  // Round down, never extend it or reject an otherwise valid scope for that.
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) return unknown('command_scope_invalid');
  timeoutMs = Math.floor(timeoutMs);
  const deadline = started + BigInt(timeoutMs) * 1000000n;
  if (!validateExecutionScope(value)) return unknown('command_scope_invalid');
  const scope = copyInertData(value);
  const scopeSha256 = digest(scope);
  const remainingMs = () => Math.max(0, Number((deadline - process.hrtime.bigint()) / 1000000n));
  const expired = () => process.hrtime.bigint() >= deadline;
  const timeout = () => ({ ...unknown('command_scope_query_timeout'), scope_sha256: scopeSha256 });
  if (scope.backend === 'macos_uid_guardian' && macosTerminals.has(scopeSha256)) {
    return expired() ? timeout() : { ...copyInertData(macosTerminals.get(scopeSha256).proof, null, 65536), scope_sha256: scopeSha256 };
  }
  // Validation, module loading, local observation and relay transport all use
  // the same deadline. A synchronous provider may return late; such a reply
  // cannot authorize reclamation, even if it says that the scope is closed.
  let observe, result;
  if (scope.backend === 'linux_pid_namespace' && process.platform === 'linux') {
    const native = require('./verification-linux-namespace');
    observe = left => native.queryCommandScope(scope.descriptor, scope.observer_lineage, { timeoutMs: left });
  } else if (scope.backend === 'windows_job_object' && process.platform === 'win32') {
    if (scope.descriptor.schema_version === 'knowledge-windows-command-job.v2') {
      const native = require('./command-windows-runtime');
      observe = left => native.queryScopeClosure(scope, { timeoutMs: left });
    } else {
      const native = require('./verification-windows-recovery');
      observe = left => typeof native.queryScopeClosure === 'function' ? native.queryScopeClosure(scope.descriptor, { timeoutMs: left }) : unknown('command_scope_query_unavailable');
    }
  } else if (scope.backend === 'darwin_uid_guardian' && process.platform === 'darwin') {
    // Fixed readonly adapter. Common-lock inspection never requests native
    // recovery, registration, admission or KVE acceptance as a side effect.
    const native = require('./verification-darwin-scope');
    observe = left => native.queryCommandScope(scope, { timeoutMs: left });
  } else if (scope.backend === 'macos_uid_guardian' && process.platform === 'darwin') {
    observe = left => require('./macos-command-scope').queryCommandScope(scope, { timeoutMs: left });
  }
  const localTimeoutMs = remainingMs();
  if (localTimeoutMs < 1) return timeout();
  result = observe ? observe(localTimeoutMs) : unknown('command_scope_platform_mismatch');
  if (expired()) return timeout();
  // A namespace inode is stable only while that namespace remains alive or
  // held open. After a crash Linux may reuse its inode for the next command
  // scope. A matching lineage frame then does not make the old namespace PID
  // coordinate usable: the exact native birth observer correctly refuses it.
  // Let the fixed, authenticated outer observer independently prove closure
  // after an identity/visibility refusal from this Linux observer. The relay
  // still validates the whole
  // scope, exact helper pins, boot/procfs and its own recorded frame, and uses
  // the native birth/pidfd observer. Unknown is not evidence, and an active or
  // completed local observation must never be overridden by another observer.
  const linuxObserverRefusals = new Set([
    'native_proc_visibility_unconfirmed', 'native_observer_translation_unconfirmed',
    'native_pidfd_identity_unconfirmed', 'native_pidfd_unavailable',
    'native_identity_unconfirmed', 'native_identity_raced', 'native_namespace_mismatch',
    'native_identity_denied', 'native_observer_mismatch', 'native_observer_unavailable'
  ]);
  const relayEligible = result.status === 'unconfirmed' && result.artifact_cleanup?.status !== 'unconfirmed' &&
    (result.code === 'command_scope_observer_outside_lineage' ||
      scope.backend === 'linux_pid_namespace' && linuxObserverRefusals.has(result.code));
  if (relayEligible && relay && !localOnly) {
    const env = require('./command-runner').safeEnvironment(process.env);
    const relayTimeoutMs = remainingMs();
    if (relayTimeoutMs < 1) return timeout();
    const input = JSON.stringify({ relay, scope, timeoutMs: relayTimeoutMs });
    const transportTimeoutMs = remainingMs();
    if (transportTimeoutMs < 1) return timeout();
    const response = spawnSync(process.execPath, [path.join(__dirname, 'command-scope-query-client.js')], {
      input, encoding: 'utf8', env, maxBuffer: 65536,
      timeout: transportTimeoutMs, killSignal: 'SIGKILL', windowsHide: true
    });
    if (expired()) return timeout();
    try {
      const decoded = JSON.parse(response.stdout);
      result = !response.error && response.status === 0 && decoded.scope_sha256 === scopeSha256 && ['completed', 'active', 'unconfirmed'].includes(decoded.proof?.status)
        ? decoded.proof : unknown('command_scope_relay_unconfirmed');
    } catch { result = unknown('command_scope_relay_unconfirmed'); }
  }
  const response = { ...result, scope_sha256: scopeSha256 };
  return expired() ? timeout() : response;
}
module.exports = { validateExecutionScope, queryScopeClosure, setScopeProofRelay, setMacOSTerminalObservation };
if (require.main === module) {
  let body = '', invalid = false;
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', data => { body += data; if (Buffer.byteLength(body) > 65536) { invalid = true; process.exitCode = 1; process.stdin.destroy(); } });
  process.stdin.on('end', () => {
    try {
      if (invalid) throw new Error('oversized');
      const request = JSON.parse(body);
      process.stdout.write(JSON.stringify({ scope_sha256: digest(request.scope), proof: queryScopeClosure(request.scope, { timeoutMs: request.timeoutMs, localOnly: true }) }));
    } catch { process.stdout.write(JSON.stringify({ proof: { status: 'unconfirmed', code: 'command_scope_request_invalid' } })); process.exitCode = 1; }
  });
}
