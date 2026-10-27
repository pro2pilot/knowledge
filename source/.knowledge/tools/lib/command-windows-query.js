'use strict';
// Fixed readonly subprocess. A native self-watchdog is armed before host or
// receipt storage reads; controller death and elapsed budget kill only this
// exact query process, never a PID found by enumerating unrelated processes.
const protocol = require('./command-windows-protocol');
function query(request) {
  if (!protocol.validateScope(request?.scope) || !protocol.HEX.test(request.nonce || '') ||
      !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > 600000) throw new Error('Invalid readonly request');
  const loader = require('./command-windows-native');
  const loaded = loader.loadPreparedHelper(request.helper), native = loaded.native;
  const parent = native.processIdentity(process.ppid);
  if (parent.exited) throw new Error('Query controller exited');
  native.armReadonlyGuard({ pid: parent.pid, birth_filetime: parent.birth_filetime }, request.timeoutMs);
  const d = request.scope.descriptor, host = loader.hostBinding(native);
  if (!['machine_guid_sha256', 'computer_name_sha256'].every(key => host[key] === d.host[key])) {
    return { status: 'unconfirmed', method: 'windows_job_object', code: 'command_windows_host_mismatch' };
  }
  if (d.secondary) {
    const terminal = require('./command-windows-receipts').readTerminal(request.scope);
    if (terminal.status === 'completed') return { ...terminal, current_host_verified: true };
  }
  // Local Job names are scoped to the original logon session. A previously
  // signed terminal fact is independent of later logon/user changes, but a
  // fresh named-object observation must use the exact original context.
  if (protocol.canonical(host) !== protocol.canonical(d.host)) return { status: 'unconfirmed', method: 'windows_job_object', code: 'command_windows_logon_context_mismatch' };
  // A historical signed terminal receipt remains immutable truth across a
  // package update. A live kernel query must match the current native pins.
  if (protocol.canonical(d.native) !== protocol.canonical(loaded.binding)) return { status: 'unconfirmed', method: 'windows_job_object', code: 'command_windows_native_pin_mismatch' };
  const observation = native.observe(d.job_name, d.root);
  if (observation.status === 'completed' && observation.active_processes === 0 && observation.root_exited === true &&
      ['exact_birth_replaced', 'exact_handle_signaled', 'exact_pid_absent'].includes(observation.root_basis)) {
    return { status: 'completed', method: 'windows_job_object', basis: 'current_kernel_job_zero', active_processes: 0,
      root_exited: true, admission_sealed: true, root_basis: observation.root_basis, current_host_verified: true };
  }
  if (observation.status === 'active') return { status: 'active', method: 'windows_job_object' };
  return { status: 'unconfirmed', method: 'windows_job_object', code: observation.status === 'missing' ? 'command_windows_job_missing_without_receipt' : 'command_windows_native_query_unconfirmed' };
}
if (require.main === module) {
  let body = '', tooLarge = false;
  process.stdin.setEncoding('utf8'); process.stdin.on('data', part => { body += part; if (Buffer.byteLength(body) > 65536) { tooLarge = true; process.stdin.destroy(); process.exitCode = 1; } });
  process.stdin.on('end', () => {
    let request;
    try {
      if (tooLarge) throw new Error('oversized'); request = JSON.parse(body);
      const proof = query(request);
      process.stdout.write(JSON.stringify({ nonce: request.nonce, scope_sha256: protocol.digest(request.scope), proof }));
    } catch (error) {
      process.stdout.write(JSON.stringify({ nonce: request?.nonce || null, scope_sha256: request?.scope ? protocol.digest(request.scope) : null,
        proof: { status: 'unconfirmed', method: 'windows_job_object', code: /^[a-zA-Z0-9_]{1,96}$/.test(error.code || '') ? error.code : 'command_windows_query_failed' } }));
      process.exitCode = 1;
    }
  });
}
module.exports = { query };
