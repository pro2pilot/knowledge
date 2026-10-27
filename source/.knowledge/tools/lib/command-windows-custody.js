'use strict';
// The original responsive controller owns these fixed custodians outside its
// A Job. Only authenticated private relay messages reach this dispatcher.
const protocol = require('./command-windows-protocol');
const runtime = require('./command-windows-runtime');
const mono = () => Number(process.hrtime.bigint()) / 1e6;
const fail = code => Object.assign(new Error(code), { code });
function createCustodyManager(context) {
  const entries = new Map(), stopped = new Set(); let closing = false;
  async function dispatch(request) {
    if (process.platform !== 'win32' || closing || !protocol.HEX.test(request.scope_id || '') ||
        !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > 600000) throw fail('command_windows_custodian_request_invalid');
    const id = request.scope_id;
    if (request.operation === 'windows_custodian_create') {
      if (stopped.has(id)) throw fail('command_windows_custodian_stopped');
      const current = context(), outer = current.descriptor;
      if (!protocol.validateDescriptor(outer) || !current.helper || !protocol.validIdentity(request.root) || !protocol.validIdentity(request.primary) ||
          request.job_name !== `Local\\KnowledgeCommand-${id}` || !protocol.validNative(request.native) || !protocol.validHost(request.host) ||
          protocol.canonical(request.native) !== protocol.canonical(outer.native) || protocol.canonical(request.host) !== protocol.canonical(outer.host) ||
          !Number.isSafeInteger(request.lifetimeMs) || request.lifetimeMs < 1 || request.lifetimeMs > 2147483647 ||
          !Number.isSafeInteger(request.setupMs) || request.setupMs < 1 || request.setupMs > 2147483647 ||
          !Number.isSafeInteger(request.cleanupMs) || request.cleanupMs < 1 || request.cleanupMs > 2147483647) throw fail('command_windows_custodian_binding_invalid');
      const body = { role: 'secondary', helper: current.helper, scope_id: id, job_name: request.job_name, root: request.root,
        primary: request.primary, lifetimeMs: request.lifetimeMs, cleanupMs: request.cleanupMs, setupMs: Math.min(request.setupMs, request.timeoutMs), outerScope: outer };
      const key = protocol.digest(body);
      let entry = entries.get(id);
      if (entry && entry.key !== key) throw fail('command_windows_custodian_replay_mismatch');
      if (!entry) {
        if (entries.size >= 32 || stopped.size >= 128) throw fail('command_windows_custodian_capacity');
        entry = { key, holder: runtime.startHolder(body), scope: null, bind: null }; entries.set(id, entry);
      }
      const info = await runtime.bounded(entry.holder.ready, request.timeoutMs, 'command_windows_custodian_setup_timeout');
      if (closing || stopped.has(id)) { entry.holder.stop(); throw fail('command_windows_custodian_stopped'); }
      return { ok: true, scope_id: id, info };
    }
    if (request.operation === 'windows_custodian_close') {
      // Close may beat creation on another TCP connection. Latch it before
      // lookup so a delayed create can never resurrect stopped admission.
      if (stopped.size >= 128 && !stopped.has(id)) throw fail('command_windows_custodian_capacity');
      stopped.add(id); const entry = entries.get(id);
      if (!entry) return { ok: true, scope_id: id, exit_observed: true, ipc_closed: true, no_custodian_created: true, terminal: null };
      entry.holder.stop(); const observed = await entry.holder.wait(request.timeoutMs);
      if (!observed.exit_observed || !observed.ipc_closed) entry.holder.kill();
      return { ok: true, scope_id: id, ...observed, terminal: entry.holder.terminal || null };
    }
    if (request.operation === 'windows_custodian_bind') {
      if (stopped.has(id) || !protocol.validateScope(request.scope) || request.scope.descriptor.scope_id !== id) throw fail('command_windows_custodian_binding_invalid');
      const entry = entries.get(id); if (!entry) throw fail('command_windows_custodian_unknown');
      if (entry.scope && protocol.digest(entry.scope) !== protocol.digest(request.scope)) throw fail('command_windows_custodian_replay_mismatch');
      if (!entry.bind) { entry.scope = request.scope; entry.bind = entry.holder.bind(request.scope); }
      await runtime.bounded(entry.bind, request.timeoutMs, 'command_windows_custodian_bind_timeout');
      if (closing || stopped.has(id)) throw fail('command_windows_custodian_stopped');
      return { ok: true, scope_id: id, scope_sha256: protocol.digest(request.scope), bound: true };
    }
    throw fail('command_windows_custodian_request_invalid');
  }
  async function close(allowance = 60000) {
    closing = true; const start = mono();
    for (const entry of entries.values()) entry.holder.stop();
    const rows = await Promise.all([...entries].map(async ([id, entry]) => {
      const exited = await entry.holder.wait(Math.max(1, allowance - (mono() - start)));
      if (!exited.exit_observed || !exited.ipc_closed) entry.holder.kill();
      return { scope_id: id, ...exited, terminal_receipt_observed: !!entry.holder.terminal?.receipt };
    }));
    return { status: rows.every(row => row.exit_observed && row.ipc_closed) && mono() - start < allowance ? 'completed' : 'unconfirmed',
      method: 'windows_independent_custodians', holders: rows };
  }
  return { dispatch, close };
}
module.exports = { createCustodyManager };
