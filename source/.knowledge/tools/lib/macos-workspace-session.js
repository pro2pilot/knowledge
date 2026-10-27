'use strict';

// An explicit administrator-owned writable-workspace capability. This is not
// isolated-copy verification and never changes a project ACL itself.
const path = require('node:path');
const crypto = require('node:crypto');
const { copyInertData } = require('./inert-data');
const native = require('./verification-darwin-client');
const transport = require('./verification-darwin-session');
const wire = require('./verification-darwin-session-protocol');
const { MAX_WORK_MS, MAX_CLEANUP_MS } = require('./verification-policy');
const fail = code => Object.assign(new Error(code), { code });
const now = () => process.hrtime.bigint();
const ms = value => Math.max(0, Math.floor(Number(value - now()) / 1e6));

function configuration(options = {}, environment = process.env) {
  const raw = options.macosWorkspace ?? {
    workspace_id: environment.KNOWLEDGE_MACOS_WORKSPACE_ID,
    broker_path: environment.KNOWLEDGE_MACOS_BROKER_PATH,
    broker_socket: environment.KNOWLEDGE_MACOS_BROKER_SOCKET
  };
  if (!raw?.workspace_id || !raw?.broker_path || !raw?.broker_socket) throw fail('command_macos_workspace_required');
  let data;
  try { data = copyInertData(raw, null, 65536); } catch { throw fail('command_macos_workspace_config_invalid'); }
  if (!data || Object.keys(data).sort().join(',') !== 'broker_path,broker_socket,workspace_id' || !wire.hex(data.workspace_id)) {
    throw fail('command_macos_workspace_required');
  }
  const config = native.config({ darwin: { enabled: true, mode: 'isolated_copy', broker_path: data.broker_path,
    broker_socket: data.broker_socket, copy: {} } }).darwin;
  return Object.freeze({ workspace_id: data.workspace_id, config });
}

async function openSession({ config, workspace_id, deadlineNs, cleanupMs, signal, nonce = crypto.randomBytes(32).toString('hex') }) {
  const left = () => ms(deadlineNs);
  if (!wire.hex(workspace_id) || !wire.hex(nonce) || typeof deadlineNs !== 'bigint' || !left() || left() > MAX_WORK_MS ||
      !Number.isSafeInteger(cleanupMs) || cleanupMs < 1 || cleanupMs > MAX_CLEANUP_MS) throw fail('command_macos_budget_invalid');
  const capability = await transport.probeSession(config, { signal, setupBudgetMs: left() });
  if (process.execPath !== capability.runtime_path) throw fail('command_macos_protected_runtime_required');
  let prepared, binding;
  try {
    prepared = (await transport.rpc(config, { op: 'prepare', mode: 'admin_writable_workspace.v1', workspace_id,
      attempt_nonce: nonce, work_budget_ms: left(), cleanup_budget_ms: cleanupMs },
    { signal, limitMs: left() + cleanupMs })).reply;
    binding = require('./macos-workspace-protocol').validateDescriptor(prepared, capability, nonce);
    if (binding.descriptor.workspace_id !== workspace_id) throw fail('command_macos_workspace_binding_invalid');
    if (binding.descriptor.protected_worker_root !== path.resolve(__dirname, '../..')) throw fail('command_macos_protected_package_required');
  } catch (error) {
    if (!prepared) {
      try { prepared = (await transport.rpc(config, { op: 'lookup', attempt_nonce: nonce }, { limitMs: cleanupMs })).reply; } catch {}
    }
    if (wire.hex(prepared?.attempt_id) && wire.hex(prepared?.descriptor_sha256)) {
      try { await transport.rpc(config, { op: 'stop', attempt_id: prepared.attempt_id,
        descriptor_sha256: prepared.descriptor_sha256, cleanup_budget_ms: cleanupMs }, { limitMs: cleanupMs }); } catch {}
    }
    const publicBinding = wire.hex(prepared?.attempt_id) && wire.hex(prepared?.descriptor_sha256) ?
      { attempt_id: prepared.attempt_id, descriptor_sha256: prepared.descriptor_sha256 } : null;
    throw Object.assign(fail(/^[A-Za-z0-9_]{1,100}$/.test(error?.code || '') ? error.code : 'command_macos_prepare_unconfirmed'),
      { recovery_required: true, attempt_nonce: nonce, binding: publicBinding });
  }
  const d = binding.descriptor, auth = { attempt_id: binding.attempt_id, token: prepared.token };
  let stopped = false, drained = null, terminal = null, ordinal = 0, active = false, stopPromise;
  const work = new AbortController();
  function check() {
    if (stopped || signal?.aborted || !left()) throw fail(signal?.aborted ? 'command_cancelled' : 'command_work_timeout');
  }
  async function request(op, extra = {}, limit = left(), cleanup = false) {
    if (!cleanup) check();
    const response = await transport.rpc(config, { op, ...auth, ...extra }, { limitMs: Math.max(1, limit),
      ...(cleanup ? {} : { signal: work.signal }) });
    if (!cleanup) check();
    return response;
  }
  function stop(reason = 'cancelled') {
    stopped = true;work.abort();
    stopPromise ||= request('stop', { descriptor_sha256: binding.descriptor_sha256, cleanup_budget_ms: cleanupMs }, cleanupMs, true)
      .then(result => ({ ...result, reason }));
    stopPromise.catch(() => {});return stopPromise;
  }
  const abort = () => { stop('cancelled'); };
  signal?.addEventListener('abort', abort, { once: true });
  const scope = require('./macos-command-scope').commandScope({ config, binding });
  return Object.freeze({ binding, capability, config, scope, remaining: left,
    authorityInput() { return { config, auth, binding, deadline_ns: String(deadlineNs) }; },
    async expectAuthority() { return (await request('expect_authority')).reply; },
    async registerStateWriter(births) {
      const value = (await request('register_state_writer', births)).reply;
      if (value.ok !== true || wire.digest(value.writer) !== wire.digest(births.writer) ||
          wire.digest(value.guardian) !== wire.digest(births.guardian)) throw fail('command_macos_writer_custody_unconfirmed');
      return value;
    },
    async registerAuthorityCustody(births) {
      const value = (await request('register_authority_custody', births)).reply;
      if (value.ok !== true || wire.digest(value.writer) !== wire.digest(births.writer) ||
          wire.digest(value.guardian) !== wire.digest(births.guardian)) throw fail('command_macos_authority_custody_unconfirmed');
      return value;
    },
    async permit() { return (await request('permit')).reply; },
    async run(raw, output = {}) {
      check();if (active || drained || terminal) throw fail('command_macos_admission_closed');
      const value = copyInertData(raw, null, 1024 * 1024);
      if (!value || value.executable !== process.execPath || !Array.isArray(value.args) ||
          value.args.some(arg => typeof arg !== 'string' || arg.includes('\0')) || !path.posix.isAbsolute(value.cwd || '')) {
        throw fail('command_invalid');
      }
      const relative = path.posix.relative(d.writable_root, value.cwd);
      if (relative === '..' || relative.startsWith('../') || path.posix.isAbsolute(relative)) throw fail('command_macos_cwd_outside_workspace');
      const env = native.nativeEnv(value.env || {});
      for (const key of Object.keys(env)) if (/^(?:KNOWLEDGE_MACOS_|NODE_CHANNEL_)/.test(key)) delete env[key];
      Object.assign(env, { HOME: d.scratch_path, TMPDIR: d.scratch_path, TMP: d.scratch_path, TEMP: d.scratch_path });
      const command = { argv: [capability.runtime_path, ...value.args], cwd: relative || '.', env, timeout_ms: left() };
      active = true;
      try {
        const response = await transport.rpc(config, { op: 'run', ...auth, ...command }, { run: true, signal: work.signal,
          limitMs: command.timeout_ms + cleanupMs, onStdout: output.onStdout, onStderr: output.onStderr });
        check();const result = wire.validateCommand(response.reply, binding, capability, command, ++ordinal);
        if (result.command_cleanup_confirmed !== true || result.kernel_membership_zero !== true ||
            result.cleanup_command_ordinal !== ordinal) throw fail('command_macos_command_cleanup_unconfirmed');
        return { status: result.exit_code, signal: result.signal === null ? null : 'SIG' + result.signal,
          error: null, cleanup: { status: 'completed', method: 'macos_private_uid_command_sweep',
            command_ordinal: ordinal, proof: result }, helper: response.helper, scope };
      } catch (error) { stop('command_failed_or_unconfirmed');throw error; }
      finally { active = false; }
    },
    async drain() {
      check();if (active) throw fail('command_concurrent_request');
      if (drained) return drained;
      const response = await request('drain_commands', { cleanup_budget_ms: cleanupMs }, Math.min(left(), cleanupMs));
      const proof = wire.validateProof(response.reply, binding, capability, false);
      drained = { status: 'completed', method: 'macos_private_uid_drain', proof };return drained;
    },
    async close() {
      check();if (active || !drained) throw fail('command_macos_terminal_order_invalid');
      if (terminal) return terminal;
      const response = await request('close', { descriptor_sha256: binding.descriptor_sha256, cleanup_budget_ms: cleanupMs },
        Math.min(left(), cleanupMs));
      const proof = wire.validateProof(response.reply, binding, capability, true);
      terminal = { status: 'completed', method: 'macos_private_uid_terminal', proof };
      signal?.removeEventListener('abort', abort);return terminal;
    },
    stop,
    async recover(limitMs) {
      const response = await transport.rpc(config, { op: 'recover', attempt_id: binding.attempt_id,
        descriptor_sha256: binding.descriptor_sha256, cleanup_budget_ms: Math.min(cleanupMs, limitMs) }, { limitMs });
      return response.reply;
    }
  });
}
module.exports = { configuration, openSession };
