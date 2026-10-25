'use strict';
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const protocol = require('./command-windows-protocol');
const mono = () => Number(process.hrtime.bigint()) / 1e6;
const fail = (code, details) => Object.assign(new Error(code), { code, ...details });
const equal = (a, b) => protocol.canonical(a) === protocol.canonical(b);
const env = () => require('./command-runner').safeEnvironment();
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); promise.catch(() => {}); return { promise, resolve, reject }; }
async function bounded(promise, allowance, code = 'command_windows_timeout') {
  if (!Number.isFinite(allowance) || allowance < 1) throw fail(code);
  let timer; const start = mono();
  try {
    const value = await Promise.race([promise, new Promise((resolve, reject) => { timer = setTimeout(() => reject(fail(code)), Math.max(1, Math.floor(allowance))); })]);
    if (mono() - start >= allowance) throw fail(code); return value;
  } finally { clearTimeout(timer); }
}
function startHolder(initialization, onFailure = () => {}) {
  const child = spawn(process.execPath, [path.join(__dirname, 'command-windows-holder.js')], {
    env: env(), stdio: ['pipe', 'ignore', 'ignore', 'ipc'], windowsHide: true
  });
  const ready = deferred(), bound = deferred(), exited = deferred();
  let readyValue, scope, terminal, error, stopping = false, exitObserved = false, disconnectObserved = false;
  function reject(value) { error ||= value; ready.reject(value); bound.reject(value); if (!stopping) onFailure(value); }
  function finishExit() { if (exitObserved && disconnectObserved) exited.resolve({ exit_observed: true, ipc_closed: true, code: child.exitCode, signal: child.signalCode }); }
  child.stdin.on('error', () => { if (!stopping) reject(fail('command_windows_control_pipe_failed')); });
  child.on('error', cause => { reject(fail('command_windows_holder_spawn_failed', { os_code: cause.code })); if (!child.pid) { exitObserved = disconnectObserved = true; finishExit(); } });
  child.on('disconnect', () => { disconnectObserved = true; finishExit(); if (!stopping && !terminal) reject(fail('command_windows_holder_transport_closed')); });
  child.on('exit', () => { exitObserved = true; finishExit(); if (!stopping && !terminal) reject(fail('command_windows_holder_exited')); });
  child.on('message', message => {
    try {
      if (!message || Buffer.byteLength(JSON.stringify(message)) > 65536 || message.role !== initialization.role) throw fail('command_windows_holder_protocol');
      if (message.type === 'holder_ready' && !readyValue && !scope && !stopping) {
        if (message.scope_id !== initialization.scope_id || !protocol.validIdentity(message.identity) || message.identity.pid !== child.pid ||
            !protocol.validIdentity(message.controller) || message.controller.pid !== process.pid || !protocol.validNative(message.native) ||
            message.native.source_sha256 !== initialization.helper.source_sha256 || message.native.binary_sha256 !== initialization.helper.binary_sha256 ||
            !protocol.validHost(message.host)) throw fail('command_windows_holder_binding_invalid');
        readyValue = message; ready.resolve(message);
      } else if (message.type === 'bound' && scope && equal(message.identity, readyValue.identity) && message.scope_sha256 === protocol.digest(scope)) bound.resolve(true);
      else if (message.type === 'terminal' && !terminal) {
        const observed = message.observation;
        if (!observed || observed.drained !== true || observed.kernel_query_ok !== true || observed.stop_latched !== true ||
            observed.root_exited !== true || observed.active_processes !== 0 || !Number.isFinite(message.elapsed_cleanup_ms) ||
            message.elapsed_cleanup_ms < 0 || typeof message.cleanup_budget_exceeded !== 'boolean' ||
            message.scope_sha256 !== (scope ? protocol.digest(scope) : null) ||
            scope?.descriptor.secondary && !protocol.validateTerminal(message.receipt, scope) ||
            !scope?.descriptor.secondary && message.receipt !== null) throw fail('command_windows_terminal_invalid');
        terminal = message;
      } else if (message.type === 'holder_error') reject(fail(/^[a-zA-Z0-9_]{1,96}$/.test(message.code || '') ? message.code : 'command_windows_holder_failed',
        { native_error: Number.isSafeInteger(message.native_error) ? message.native_error : null }));
      else throw fail('command_windows_holder_protocol');
    } catch (cause) { reject(cause); }
  });
  child.send({ type: 'init', ...initialization }, cause => { if (cause) reject(fail('command_windows_holder_transport_failed')); });
  return {
    child, ready: ready.promise, exited: exited.promise,
    get info() { return readyValue; }, get terminal() { return terminal; }, get error() { return error; },
    get exitObserved() { return exitObserved && disconnectObserved; },
    bind(value) {
      if (scope || stopping || !readyValue || !protocol.validateScope(value)) return Promise.reject(fail('command_windows_binding_invalid'));
      scope = value; child.send({ type: 'bind', scope }, cause => { if (cause) reject(fail('command_windows_holder_transport_failed')); }); return bound.promise;
    },
    stop() {
      stopping = true;
      if (!child.stdin.destroyed && !child.stdin.writableEnded) child.stdin.end(Buffer.from([1]));
      if (child.connected) child.send({ type: 'stop' }, () => {});
    },
    kill() { stopping = true; if (!exitObserved) child.kill('SIGKILL'); },
    async wait(allowance) {
      try { return await bounded(exited.promise, allowance, 'command_windows_holder_exit_unconfirmed'); }
      catch (cause) { return { exit_observed: exitObserved, ipc_closed: disconnectObserved, code: cause.code }; }
    }
  };
}
function rpc(relay, request, timeoutMs) {
  if (relay?.address?.host !== '127.0.0.1' || !Number.isInteger(relay.address.port) || !protocol.HEX.test(relay.token || '')) return Promise.reject(fail('command_scope_relay_invalid'));
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: relay.address.port, allowHalfOpen: true });
    let data = '', ended = false; const start = mono();
    const timer = setTimeout(() => { socket.destroy(); reject(fail('command_windows_custodian_timeout')); }, Math.max(1, Math.floor(timeoutMs)));
    socket.setEncoding('utf8'); socket.on('error', cause => { clearTimeout(timer); reject(fail('command_windows_custodian_transport', { os_code: cause.code })); });
    socket.on('connect', () => socket.end(JSON.stringify({ ...request, token: relay.token, timeoutMs: Math.max(1, Math.floor(timeoutMs)) })));
    socket.on('data', part => { data += part; if (Buffer.byteLength(data) > 65536) socket.destroy(fail('command_windows_custodian_oversized')); });
    socket.on('end', () => {
      ended = true; clearTimeout(timer);
      try { const value = JSON.parse(data); if (mono() - start >= timeoutMs || value.ok !== true || value.scope_id !== request.scope_id) throw fail(value.code || 'command_windows_custodian_unconfirmed'); resolve(value); }
      catch (cause) { reject(cause); }
    });
    socket.on('close', () => { clearTimeout(timer); if (!ended) reject(fail('command_windows_custodian_truncated')); });
  });
}
async function queryPreparedScope(scope, helper, timeoutMs) {
  const nonce = crypto.randomBytes(32).toString('hex');
  const child = spawn(process.execPath, [path.join(__dirname, 'command-windows-query.js')], { env: env(), stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true });
  let output = '', end = false, error, exited = false; const done = deferred(), start = mono();
  const timer = setTimeout(() => { error = 'command_windows_query_timeout'; child.kill('SIGKILL'); }, Math.max(1, Math.floor(timeoutMs)));
  child.stdout.setEncoding('utf8'); child.stdout.on('data', part => { output += part; if (Buffer.byteLength(output) > 65536) { error = 'command_windows_query_oversized'; child.kill('SIGKILL'); } });
  child.stdout.on('end', () => { end = true; }); child.stdout.on('error', () => { error = 'command_windows_query_transport'; child.kill('SIGKILL'); });
  child.stdin.on('error', () => { error ||= 'command_windows_query_transport'; });
  child.on('error', () => { error = 'command_windows_query_spawn_failed'; done.resolve(); });
  child.on('close', () => { exited = true; done.resolve(); });
  child.stdin.end(JSON.stringify({ nonce, scope, helper, timeoutMs: Math.max(1, Math.floor(timeoutMs)) }));
  try {
    await bounded(done.promise, timeoutMs + 1000, 'command_windows_query_exit_unconfirmed');
    const value = JSON.parse(output);
    if (!error && exited && end && child.exitCode === 0 && !child.signalCode && mono() - start < timeoutMs &&
        value.nonce === nonce && value.scope_sha256 === protocol.digest(scope) && ['completed', 'active', 'unconfirmed'].includes(value.proof?.status)) return value.proof;
  } catch {}
  finally { clearTimeout(timer); if (!exited) { child.kill('SIGKILL'); child.stdout.destroy(); child.stdin.destroy(); child.unref(); } }
  return { status: 'unconfirmed', method: 'windows_job_object', code: error || 'command_windows_query_unconfirmed', query_exit_observed: exited };
}
function queryScopeClosure(scope, { timeoutMs = 5000 } = {}) {
  if (process.platform !== 'win32' || !protocol.validateScope(scope) || !Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) return { status: 'unconfirmed', code: 'command_windows_scope_invalid' };
  const start = mono(), loader = require('./command-windows-native'); let helper, proof;
  try {
    helper = loader.preparePackagedHelper({ verifyLoad: false });
    const left = Math.floor(timeoutMs - (mono() - start)); if (left < 1) throw fail('command_windows_query_timeout');
    const nonce = crypto.randomBytes(32).toString('hex');
    const result = spawnSync(process.execPath, [path.join(__dirname, 'command-windows-query.js')], {
      input: JSON.stringify({ nonce, scope, helper, timeoutMs: left }), encoding: 'utf8', env: env(), windowsHide: true,
      timeout: left, killSignal: 'SIGKILL', maxBuffer: 65536
    });
    const value = JSON.parse(result.stdout);
    if (result.error || result.status !== 0 || result.signal || mono() - start >= timeoutMs || value.nonce !== nonce ||
        value.scope_sha256 !== protocol.digest(scope) || !['completed', 'active', 'unconfirmed'].includes(value.proof?.status)) throw fail('command_windows_query_unconfirmed');
    proof = value.proof;
  } catch (cause) { proof = { status: 'unconfirmed', method: 'windows_job_object', code: cause.code || 'command_windows_query_unconfirmed' }; }
  finally {
    if (helper) { const cleanup = loader.cleanupPreparedHelper(helper); if (cleanup.status !== 'completed') proof = { status: 'unconfirmed', code: 'command_windows_query_cleanup_unconfirmed', artifact_cleanup: cleanup }; }
  }
  if (mono() - start >= timeoutMs) return { status: 'unconfirmed', code: 'command_windows_query_timeout' };
  return proof;
}
module.exports = { startHolder, bounded, rpc, queryPreparedScope, queryScopeClosure };
