'use strict';
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const protocol = require('./command-windows-protocol');
const runtime = require('./command-windows-runtime');
const mono = () => Number(process.hrtime.bigint()) / 1e6;
const equal = (a, b) => protocol.canonical(a) === protocol.canonical(b);
const fail = (code, details) => Object.assign(new Error(code), { code, ...details });
function spawnWindowsContainedWorker(options = {}, settings = {}) {
  const helper = require('./command-windows-native').admitPreparedHelper(settings.preparedHelper);
  const worker = spawn(process.execPath, [path.join(__dirname, 'command-windows-guard.js')], { ...options, detached: false });
  let guardResolve, guardReject;
  const guardReady = new Promise((resolve, reject) => { guardResolve = resolve; guardReject = reject; }); guardReady.catch(() => {});
  let workerExitResolve;
  const workerExited = new Promise(resolve => { workerExitResolve = resolve; });
  let primary, secondary, secondaryRemote = false, descriptor, scope, firstError, stopping = false, permitted = false, closure, retirement;
  const created = mono(), setupRemaining = () => Math.max(0, settings.setupMs - (mono() - created));
  const scopeId = crypto.randomBytes(32).toString('hex'), jobName = `Local\\KnowledgeCommand-${scopeId}`;
  const reject = error => { firstError ||= error; guardReject(error); if (!stopping) settings.onFailure?.(error); };
  worker.on('error', error => { if (!worker.pid) workerExitResolve(true); reject(fail('command_windows_guard_spawn_failed', { os_code: error.code })); });
  worker.on('exit', () => { workerExitResolve(true); if (!stopping) reject(fail('command_windows_guard_exited')); });
  worker.on('message', message => {
    if (message?.type === 'native_ready') {
      if (!protocol.validIdentity(message.identity) || message.identity.pid !== worker.pid || !protocol.validNative(message.binding) ||
          message.binding.source_sha256 !== helper.source_sha256 || message.binding.binary_sha256 !== helper.binary_sha256) reject(fail('command_windows_guard_binding_invalid'));
      else guardResolve(message);
    } else if (message?.type === 'native_failed') reject(fail(/^[a-zA-Z0-9_]{1,96}$/.test(message.code || '') ? message.code : 'command_windows_guard_unconfirmed'));
  });
  const ready = (async () => {
    const guard = await runtime.bounded(guardReady, setupRemaining(), 'command_setup_timeout');
    if (stopping || firstError) throw firstError || fail('command_stopped');
    const base = { helper, scope_id: scopeId, job_name: jobName, root: guard.identity,
      lifetimeMs: settings.lifetimeMs, cleanupMs: settings.cleanupMs, setupMs: Math.max(1, Math.floor(setupRemaining())) };
    primary = runtime.startHolder({ ...base, role: 'primary', durable: settings.durable === true }, reject);
    const primaryInfo = await runtime.bounded(primary.ready, setupRemaining(), 'command_setup_timeout');
    if (!equal(primaryInfo.native, guard.binding)) throw fail('command_windows_guard_binding_invalid');
    if (stopping || firstError) throw firstError || fail('command_stopped');
    let secondaryInfo = null;
    if (settings.durable === true) {
      if (settings.proofRelay) {
        secondaryRemote = true;
        const response = await runtime.rpc(settings.proofRelay, { operation: 'windows_custodian_create', scope_id: scopeId,
          job_name: jobName, root: guard.identity, primary: primaryInfo.identity, native: primaryInfo.native, host: primaryInfo.host,
          lifetimeMs: settings.lifetimeMs, cleanupMs: settings.cleanupMs, setupMs: Math.max(1, Math.floor(setupRemaining())) }, setupRemaining());
        secondaryInfo = response.info;
      } else {
        secondary = runtime.startHolder({ ...base, setupMs: Math.max(1, Math.floor(setupRemaining())), role: 'secondary', primary: primaryInfo.identity }, reject);
        secondaryInfo = await runtime.bounded(secondary.ready, setupRemaining(), 'command_setup_timeout');
      }
      if (!secondaryInfo || secondaryInfo.role !== 'secondary' || secondaryInfo.scope_id !== scopeId ||
          !equal(secondaryInfo.native, primaryInfo.native) || !equal(secondaryInfo.host, primaryInfo.host)) throw fail('command_windows_custodian_binding_invalid');
    }
    descriptor = { schema_version: 'knowledge-windows-command-job.v2', backend: 'windows_job_object', scope_id: scopeId, job_name: jobName,
      native: primaryInfo.native, host: primaryInfo.host, controller: primaryInfo.controller, root: guard.identity,
      primary: { identity: primaryInfo.identity, public_key: primaryInfo.public_key },
      secondary: secondaryInfo ? { identity: secondaryInfo.identity, controller: secondaryInfo.controller, public_key: secondaryInfo.public_key } : null,
      receipt_store: secondaryInfo?.receipt_store || null };
    scope = protocol.commandScope(descriptor);
    const binds = [primary.bind(scope)];
    if (secondaryRemote) binds.push(runtime.rpc(settings.proofRelay, { operation: 'windows_custodian_bind', scope_id: scopeId, scope }, setupRemaining()));
    else if (secondary) binds.push(secondary.bind(scope));
    await runtime.bounded(Promise.all(binds), setupRemaining(), 'command_setup_timeout');
    if (stopping || firstError) throw firstError || fail('command_stopped');
    return descriptor;
  })();
  ready.catch(error => reject(error));
  // The caller installs its protocol/output handlers before this first IPC
  // request, and no project imports happen in the guarded process yet.
  queueMicrotask(() => worker.send({ type: 'native_prepare', helper }, error => { if (error) reject(fail('command_windows_guard_transport')); }));
  async function close(allowance = 60000) {
    if (closure) return closure;
    stopping = true;
    closure = (async () => {
      const started = mono(), left = () => Math.max(0, allowance - (mono() - started));
      primary?.stop(); secondary?.stop();
      let remote;
      const remoteWait = secondaryRemote ? runtime.rpc(settings.proofRelay, { operation: 'windows_custodian_close', scope_id: scopeId }, Math.max(1, left())).then(value => { remote = value; }, error => { remote = { ok: false, code: error.code }; }) : Promise.resolve();
      // This creator-owned handle is safe even if setup failed before native
      // assignment. Descendant drain is still the Job's independent duty.
      if (worker.exitCode === null && worker.signalCode === null) worker.kill('SIGKILL');
      const exits = await Promise.all([primary ? primary.wait(Math.max(1, left())) : Promise.resolve(null),
        secondary ? secondary.wait(Math.max(1, left())) : Promise.resolve(null), remoteWait,
        runtime.bounded(workerExited, Math.max(1, left())).catch(() => false)]);
      const ownsExited = (!primary || exits[0]?.exit_observed && exits[0]?.ipc_closed) &&
        (!secondary || exits[1]?.exit_observed && exits[1]?.ipc_closed) && (!secondaryRemote || remote?.exit_observed === true && remote?.ipc_closed === true);
      let proof;
      const terminal = primary?.terminal || secondary?.terminal || remote?.terminal;
      if (scope && terminal?.scope_sha256 === protocol.digest(scope) &&
          (!descriptor.secondary || protocol.validateTerminal(terminal.receipt, scope)) && terminal.cleanup_budget_exceeded === false) {
        proof = { status: 'completed', method: 'windows_job_object', active_processes: 0, root_exited: true, admission_sealed: true,
          basis: descriptor.secondary ? 'signed_terminal_receipt' : 'native_terminal_observation' };
      } else if (scope && descriptor.secondary && left() >= 1) proof = await runtime.queryPreparedScope(scope, helper, left());
      else if (!scope && primary?.terminal?.scope_sha256 === null) proof = { status: 'completed', method: 'windows_job_object', active_processes: 0, root_exited: true, basis: 'unpublished_native_scope' };
      else if (!permitted && exits[3] && ownsExited) proof = { status: 'completed', method: 'windows_job_object', active_processes: 0, root_exited: true, basis: 'guard_never_admitted' };
      if (!ownsExited) { primary?.kill(); secondary?.kill(); }
      if (worker.exitCode === null && worker.signalCode === null && !primary) worker.kill('SIGKILL');
      const completed = ownsExited && exits[3] && proof?.status === 'completed' && mono() - started < allowance;
      return { ...proof, status: completed ? 'completed' : 'unconfirmed', method: 'windows_job_object',
        primary_holder_exited: !primary || exits[0]?.exit_observed === true && exits[0]?.ipc_closed === true,
        secondary_holder_exited: !settings.durable || (secondaryRemote ? remote?.exit_observed === true && remote?.ipc_closed === true : exits[1]?.exit_observed === true && exits[1]?.ipc_closed === true),
        ...(completed ? {} : { code: 'command_windows_cleanup_unconfirmed', primary_error: firstError?.code }) };
    })();
    return closure;
  }
  const job = {
    ready, get descriptor() { return descriptor ? JSON.parse(JSON.stringify(descriptor)) : undefined; },
    permit() {
      if (!scope || stopping || firstError || permitted) throw firstError || fail('command_windows_permit_invalid');
      permitted = true; worker.send({ type: 'native_permit' }, error => { if (error) reject(fail('command_windows_guard_transport')); });
    },
    drain: close, close,
    async retireProof(allowance) {
      if (!scope?.descriptor.secondary) return { status: 'not_required' };
      const closed = closure ? await closure : null;
      if (closed?.status !== 'completed' || closed.primary_holder_exited !== true || closed.secondary_holder_exited !== true) {
        return { status: 'unconfirmed', method: 'windows_terminal_receipt_store', code: 'command_windows_holders_exit_unconfirmed' };
      }
      if (!retirement) retirement = runtime.retirePreparedScope(scope, helper, allowance);
      return retirement;
    }
  };
  return { worker, job };
}
module.exports = { spawnWindowsContainedWorker };
