'use strict';
const crypto = require('crypto');
const path = require('path');
const { spawnSync } = require('child_process');
const { copyInertData } = require('./inert-data');
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
let relay;
function validNamespace(value) { return value && /^\d+$/.test(value.dev || '') && /^\d+$/.test(value.ino || ''); }
function validateExecutionScope(value) {
  try {
    const scope = copyInertData(value);
    if (!scope || scope.schema_version !== 'knowledge-command-scope.v1' || Buffer.byteLength(JSON.stringify(scope)) > 32768) return false;
    if (scope.backend === 'linux_pid_namespace') {
      const descriptor = scope.descriptor;
      if (!require('./verification-linux-namespace').validDescriptor(descriptor) || !Array.isArray(scope.observer_lineage) || !scope.observer_lineage.length || scope.observer_lineage.length > 64) return false;
      let prior = 0; const seen = new Set();
      for (const row of scope.observer_lineage) {
        if (!validNamespace(row.namespace) || !Number.isSafeInteger(row.depth) || row.depth <= prior || row.depth > 64) return false;
        const key = `${row.namespace.dev}:${row.namespace.ino}`;
        if (seen.has(key)) return false;
        prior = row.depth; seen.add(key);
      }
      const last = scope.observer_lineage[scope.observer_lineage.length - 1];
      if (last.namespace.dev !== descriptor.observer_pid_namespace.dev || last.namespace.ino !== descriptor.observer_pid_namespace.ino) return false;
      for (const role of ['controller', 'keeper', 'init', 'worker']) {
        const identity = descriptor[role], chain = identity.proc_pid_chain;
        if (!Array.isArray(chain) || !chain.length || chain.length > 64 || chain.some(p => !Number.isSafeInteger(p) || p < 1) ||
            chain[0] !== identity.proc_pid || chain[chain.length - 1] !== identity.namespace_pid || chain[last.depth - 1] !== identity.pid) return false;
      }
      return descriptor.controller.proc_pid_chain.length === last.depth && descriptor.init.proc_pid_chain.length === last.depth + 1;
    }
    if (scope.backend === 'windows_job_object') {
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
function queryScopeClosure(value, { timeoutMs = 5000, localOnly = false } = {}) {
  const unknown = code => ({ status: 'unconfirmed', method: value?.backend || 'unknown', code });
  // Lock release supplies the fractional remainder of a monotonic budget.
  // Round down, never extend it or reject an otherwise valid scope for that.
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000 || !validateExecutionScope(value)) return unknown('command_scope_invalid');
  timeoutMs = Math.floor(timeoutMs);
  const scope = copyInertData(value);
  let result;
  if (scope.backend === 'linux_pid_namespace' && process.platform === 'linux') {
    result = require('./verification-linux-namespace').queryCommandScope(scope.descriptor, scope.observer_lineage, { timeoutMs });
  } else if (scope.backend === 'windows_job_object' && process.platform === 'win32') {
    const native = require('./verification-windows-recovery');
    result = typeof native.queryScopeClosure === 'function' ? native.queryScopeClosure(scope.descriptor, { timeoutMs }) : unknown('command_scope_query_unavailable');
  } else result = unknown('command_scope_platform_mismatch');
  if (result.status === 'unconfirmed' && result.code === 'command_scope_observer_outside_lineage' && relay && !localOnly) {
    const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.NODE_PATH;
    const response = spawnSync(process.execPath, [path.join(__dirname, 'command-scope-query-client.js')], {
      input: JSON.stringify({ relay, scope, timeoutMs }), encoding: 'utf8', env, maxBuffer: 65536,
      timeout: timeoutMs + 2000, killSignal: 'SIGKILL', windowsHide: true
    });
    try {
      const decoded = JSON.parse(response.stdout);
      result = !response.error && response.status === 0 && decoded.scope_sha256 === digest(scope) && ['completed', 'active', 'unconfirmed'].includes(decoded.proof?.status)
        ? decoded.proof : unknown('command_scope_relay_unconfirmed');
    } catch { result = unknown('command_scope_relay_unconfirmed'); }
  }
  return { ...result, scope_sha256: digest(scope) };
}
module.exports = { validateExecutionScope, queryScopeClosure, setScopeProofRelay };
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
