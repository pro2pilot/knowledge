'use strict';

// The control side contains no project storage. All synchronous context,
// command and finalization work runs in a native-owned guarded process.
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { MAX_CHILD_JSON_BYTES } = require('./semantic-json');
const SCHEMA = 'knowledge-command-scope.v1';
const MAX_TIMER = 2147483647;
const HOST = path.join(__dirname, 'command-worker.js');
const mono = () => Number(process.hrtime.bigint()) / 1e6;
const fail = (code, message, details = {}) => Object.assign(new Error(message || code), { code, ...details });
const clone = value => JSON.parse(JSON.stringify(value));
function budgets(value = {}) {
  const result = {
    workMs: value.workMs ?? 3600000,
    progressMs: value.progressMs ?? 0,
    cleanupMs: value.cleanupMs ?? 60000,
    setupMs: value.setupMs ?? 60000
  };
  for (const [key, n] of Object.entries(result)) {
    if (!Number.isSafeInteger(n) || n < (key === 'progressMs' ? 0 : 1) || n > MAX_TIMER) throw fail('command_budget_invalid', `Invalid ${key}`);
  }
  if (result.workMs + result.cleanupMs + result.setupMs > MAX_TIMER) throw fail('command_budget_invalid', 'The combined native lifetime exceeds the platform limit');
  return Object.freeze(result);
}
function cliBudgets(flags = {}) {
  const value = {};
  for (const [key, flag, variable] of [
    ['workMs', 'workTimeoutMs', 'KNOWLEDGE_WORK_TIMEOUT_MS'],
    ['progressMs', 'progressTimeoutMs', 'KNOWLEDGE_PROGRESS_TIMEOUT_MS'],
    ['cleanupMs', 'cleanupTimeoutMs', 'KNOWLEDGE_CLEANUP_TIMEOUT_MS'],
    ['setupMs', 'setupTimeoutMs', 'KNOWLEDGE_SETUP_TIMEOUT_MS']
  ]) {
    const input = flags[flag] ?? process.env[variable];
    if (input !== undefined && input !== '') {
      if (typeof input !== 'number' && (typeof input !== 'string' || !/^\d+$/.test(input))) throw fail('command_budget_invalid', `Invalid ${flag}`);
      value[key] = Number(input);
    }
  }
  return budgets(value);
}
function safeEnvironment(input = process.env) {
  const env = { ...input };
  for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'NODE_CHANNEL_FD', 'NODE_CHANNEL_SERIALIZATION_MODE']) delete env[key];
  for (const key of Object.keys(env)) if (key.startsWith('LD_')) delete env[key];
  return env;
}
function deadlineError(signal) {
  return fail(signal?.aborted ? 'command_cancelled' : 'command_work_timeout');
}
function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(fail('command_cancelled')); return; }
    const cancel = () => { clearTimeout(timer); signal.removeEventListener('abort', cancel); reject(fail('command_cancelled')); };
    const timer = setTimeout(() => { signal?.removeEventListener('abort', cancel); resolve(); }, ms);
    signal?.addEventListener('abort', cancel, { once: true });
  });
}

async function cleanupLinux(helper, allowance, { allowIncomplete = false } = {}) {
  if (!helper?.snapshot) return { status: 'not_owned' };
  if (allowance < 1) return { status: 'unconfirmed', method: 'private_native_snapshot', code: 'command_native_snapshot_cleanup_timeout', directory: helper.snapshot.directory };
  const child = spawn(process.execPath, [path.join(__dirname, 'command-runtime-prepare.js'), '--cleanup'], {
    env: safeEnvironment(), stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true
  });
  return new Promise(resolve => {
    const start = mono(); let candidate, done = false, exited = false, disconnected = false, failure, stopTimer;
    function finish() {
      if (done || !exited || !disconnected) return;
      done = true; clearTimeout(timer); clearTimeout(stopTimer);
      resolve(!failure && child.exitCode === 0 && !child.signalCode && candidate && mono() - start <= allowance
        ? candidate : { status: 'unconfirmed', method: 'private_native_snapshot', code: failure || 'command_native_snapshot_cleanup_failed', directory: helper.snapshot.directory });
    }
    const timer = setTimeout(() => {
      failure = 'command_native_snapshot_cleanup_timeout';
      if (!exited) child.kill('SIGKILL');
      stopTimer = setTimeout(() => {
        if (done) return; done = true;
        if (child.connected) child.disconnect(); child.unref();
        resolve({ status: 'unconfirmed', method: 'private_native_snapshot', code: failure, exit_observed: exited, directory: helper.snapshot.directory });
      }, Math.min(1000, Math.max(1, allowance)));
    }, Math.max(1, Math.floor(allowance)));
    child.on('message', message => {
      if (done) return;
      if (candidate || message?.type !== 'cleaned' || !['completed', 'unconfirmed'].includes(message.receipt?.status)) failure = 'command_native_snapshot_cleanup_protocol';
      else candidate = message.receipt;
    });
    child.once('exit', () => { exited = true; finish(); });
    child.once('disconnect', () => { disconnected = true; finish(); });
    child.once('error', () => { failure = 'command_native_snapshot_cleanup_spawn_failed'; if (!child.pid) { exited = disconnected = true; finish(); } });
    child.send({ type: 'cleanup', helper, allowIncomplete }, error => { if (error) failure = 'command_native_snapshot_cleanup_transport'; });
  });
}

async function prepareLinux(options, policy) {
  if (options.preparedHelper) return require('./verification-linux-namespace').admitPreparedHelper(options.preparedHelper);
  if (options.signal?.aborted) throw fail('command_cancelled');
  const child = spawn(process.execPath, [path.join(__dirname, 'command-runtime-prepare.js')], {
    env: safeEnvironment(), stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true
  });
  return new Promise((resolve, reject) => {
    const start = mono(); let candidate, staged, error, terminal = false, exited = false, disconnected = false, stopTimer, cleanupStarted;
    const finish = async () => {
      if (terminal || !exited || !disconnected) return;
      terminal = true; clearTimeout(timer); clearTimeout(stopTimer); options.signal?.removeEventListener('abort', cancel);
      if (!error && mono() - start >= policy.setupMs) error = fail('command_setup_timeout');
      if (!error && (!candidate || child.exitCode !== 0 || child.signalCode)) error = fail('command_setup_unconfirmed');
      let admitted;
      if (!error) { try { admitted = require('./verification-linux-namespace').admitPreparedHelper(candidate); } catch (cause) { error = cause; } }
      if (error) {
        const artifact = await cleanupLinux(candidate || staged, Math.max(0, policy.cleanupMs - (cleanupStarted ? mono() - cleanupStarted : 0)), { allowIncomplete: true });
        error.cleanup = { status: ['completed', 'not_owned'].includes(artifact.status) ? 'completed' : 'unconfirmed',
          method: 'isolated_preparer', exit_observed: true, artifact_cleanup: artifact };
        reject(error);
      } else {
        resolve(admitted);
      }
    };
    const stop = why => {
      if (error || terminal) return;
      error = why; cleanupStarted = mono();
      if (!exited) child.kill('SIGKILL');
      stopTimer = setTimeout(() => {
        if (terminal) return; terminal = true; clearTimeout(timer); options.signal?.removeEventListener('abort', cancel);
        error.cleanup = { status: 'unconfirmed', method: 'isolated_preparer', code: 'command_setup_exit_unconfirmed', snapshot: staged?.snapshot || null };
        if (child.connected) child.disconnect(); child.unref(); reject(error);
      }, policy.cleanupMs);
      finish();
    };
    const cancel = () => stop(fail('command_cancelled'));
    const timer = setTimeout(() => stop(fail('command_setup_timeout')), policy.setupMs);
    child.on('error', e => { if (!child.pid) { exited = disconnected = true; } stop(fail('command_setup_failed', e.message)); });
    child.on('message', message => {
      if (error || terminal || candidate) return;
      if (message?.type === 'snapshot_created' && !staged) staged = message.helper;
      else if (message?.type === 'prepared') candidate = message.helper;
      else stop(fail(message?.code || 'command_setup_failed', message?.message));
    });
    child.once('exit', () => { exited = true; finish(); });
    child.once('disconnect', () => { disconnected = true; finish(); });
    options.signal?.addEventListener('abort', cancel, { once: true });
    if (options.signal?.aborted) cancel();
  });
}

async function createScope(kind, payload, options = {}) {
  const policy = budgets(options.budgets);
  const created = mono();
  let helper;
  if (process.platform === 'linux') helper = await prepareLinux(options, policy);
  else if (process.platform !== 'win32') throw fail('command_containment_unavailable', 'This platform has no qualified native scope for ordinary project writes');
  const ownsHelper = !!helper?.snapshot && !options.preparedHelper;
  if (options.signal?.aborted) {
    const artifact = ownsHelper ? await cleanupLinux(helper, policy.cleanupMs) : { status: 'not_owned' };
    throw fail('command_cancelled', undefined, { cleanup: artifact });
  }
  let worker, job, firstError, stopping = false, started = false, result, resultResolve, observerLineage;
  let hostReadyResolve, hostReadyReject;
  const hostReady = new Promise((resolve, reject) => { hostReadyResolve = resolve; hostReadyReject = reject; });
  hostReady.catch(() => {});
  const candidate = new Promise(resolve => { resultResolve = resolve; });
  const pending = new Map();
  let nextRequest = 0;
  let stopResolve;
  const stopped = new Promise(resolve => { stopResolve = resolve; });
  const reject = error => {
    if (stopping || firstError) return;
    firstError = error instanceof Error ? error : fail('command_transport_failed');
    hostReadyReject(firstError); stopResolve(firstError); resultResolve();
    for (const { reject } of pending.values()) reject(firstError);
    pending.clear();
    // Close admission and begin drain even if a caller neglects to await a
    // session result. Native lifetime remains the independent final backstop.
    queueMicrotask(() => { close({ retain: kind === 'session' }).catch(() => {}); });
  };
  const nativeOptions = { cwd: options.cwd, env: safeEnvironment(options.env), stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true };
  const lifetimeMs = policy.setupMs + policy.workMs + policy.cleanupMs;
  if (process.platform === 'linux') {
    const backend = require('./verification-linux-namespace');
    ({ worker, job } = backend.spawnLinuxContainedWorker(process.execPath, [HOST], nativeOptions, {
      preparedHelper: helper, lifetimeMs, trustedAuthority: kind !== 'command' || payload.nestedAuthority === true,
      onFailure: reject
    }));
  } else {
    worker = spawn(process.execPath, [HOST], nativeOptions);
    worker.on('error', error => reject(fail('command_worker_spawn_failed', error.message)));
    try { job = require('./verification-windows-job').createWindowsJob(worker, () => reject(fail('command_native_authority_failed')), lifetimeMs); }
    catch (error) { worker.kill('SIGKILL'); throw error; }
  }
  const output = { stdout: [], stderr: [] };
  const outputEnd = {};
  let bytes = 0;
  for (const name of ['stdout', 'stderr']) {
    const stream = worker[name];
    outputEnd[name] = new Promise(resolve => {
      let ended = false;
      stream.once('end', () => { ended = true; resolve(true); });
      stream.once('error', error => { reject(fail('command_output_error', error.message)); resolve(false); });
      stream.once('close', () => { if (!ended) resolve(false); });
    });
    stream.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > (options.maxOutputBytes ?? MAX_CHILD_JSON_BYTES)) { reject(fail('command_output_limit')); return; }
      output[name].push(chunk);
      // Output is deliberately not a progress heartbeat.
      if (typeof options.onOutput === 'function') {
        try { options.onOutput(name, chunk); } catch (error) { reject(fail('command_output_callback_failed', error.message)); }
      }
    });
  }
  worker.on('error', error => reject(fail('command_worker_spawn_failed', error.message)));
  worker.on('disconnect', () => reject(fail('command_worker_transport_closed')));
  worker.on('exit', (code, signal) => reject(fail('command_worker_exited', `Guard exited (${code}, ${signal || 'no signal'})`)));
  worker.on('message', message => {
    if (stopping || firstError) return;
    if (!message || typeof message !== 'object') { reject(fail('command_protocol_invalid')); return; }
    if (message.type === 'host_ready' && !started) { hostReadyResolve(); return; }
    if (!started) { reject(fail('command_protocol_invalid')); return; }
    // Timer callbacks can run late under load. A late completion/heartbeat
    // cannot outrun the absolute deadline merely by winning event ordering.
    if (mono() - workStart >= policy.workMs) { reject(fail('command_work_timeout')); return; }
    if (policy.progressMs && mono() - lastProgress >= policy.progressMs) { reject(fail('command_progress_timeout')); return; }
    if (message.type === 'progress' && Number.isSafeInteger(message.sequence) && message.sequence > progressSequence) {
      progressSequence = message.sequence; lastProgress = mono();
      try { options.onProgress?.(message); } catch (error) { reject(fail('command_progress_callback_failed', error.message)); }
      return;
    }
    if (message.type === 'result' && result === undefined && kind !== 'session') {
      result = message; resultResolve(); return;
    }
    if (message.type === 'reply' && Number.isSafeInteger(message.id) && pending.has(message.id)) {
      const request = pending.get(message.id); pending.delete(message.id);
      if (message.error) request.reject(fail(message.error.code || 'command_failed', message.error.message, message.error));
      else request.resolve(message.value);
      return;
    }
    reject(fail('command_protocol_invalid'));
  });
  let progressSequence = 0, lastProgress = mono(), workStart, workTimer, progressTimer;
  const cancel = () => reject(fail('command_cancelled'));
  options.signal?.addEventListener('abort', cancel, { once: true });
  const setupTimer = setTimeout(() => reject(fail('command_setup_timeout')), Math.max(1, policy.setupMs - (mono() - created)));
  let closure, disposal, cleanupStarted;
  const cleanupRemaining = () => cleanupStarted === undefined ? policy.cleanupMs : Math.max(0, policy.cleanupMs - (mono() - cleanupStarted));
  async function dispose() {
    if (!ownsHelper) return { status: 'not_owned' };
    if (disposal) return disposal;
    if (!closure || (await closure).status !== 'completed') return { status: 'unconfirmed', method: 'private_native_snapshot', code: 'command_scope_exit_unconfirmed', directory: helper.snapshot.directory };
    disposal = cleanupLinux(helper, cleanupRemaining());
    return disposal;
  }
  async function close({ retain = false } = {}) {
    if (closure) return closure;
    stopping = true; clearTimeout(setupTimer); clearTimeout(workTimer); clearInterval(progressTimer);
    options.signal?.removeEventListener('abort', cancel);
    for (const request of pending.values()) request.reject(firstError || fail('command_stopped'));
    pending.clear();
    const cleanupStart = cleanupStarted = mono();
    closure = (async () => {
      const receipt = retain && typeof job.drain === 'function' ? await job.drain(policy.cleanupMs) : await job.close(policy.cleanupMs);
      const remaining = Math.max(0, policy.cleanupMs - (mono() - cleanupStart));
      let timer;
      const ends = await Promise.race([
        Promise.all([outputEnd.stdout, outputEnd.stderr]),
        new Promise(resolve => { timer = setTimeout(() => resolve([false, false]), Math.max(1, remaining)); })
      ]);
      clearTimeout(timer);
      if (worker.connected) worker.disconnect();
      if (!ends.every(Boolean)) { worker.stdout.destroy(); worker.stderr.destroy(); }
      worker.unref();
      return receipt?.status === 'completed' && ends.every(Boolean) && mono() - cleanupStart <= policy.cleanupMs
        ? { ...receipt, output_closed: true, cleanup_duration_ms: Math.round(mono() - cleanupStart) }
        : { ...receipt, status: 'unconfirmed', output_closed: ends.every(Boolean), code: receipt?.code || 'command_cleanup_unconfirmed' };
    })();
    return closure;
  }
  try {
    await Promise.race([job.ready, stopped.then(error => { throw error; })]);
    if (firstError || options.signal?.aborted) throw firstError || fail('command_cancelled');
    options.onNativeReady?.(job.descriptor, helper);
    if (process.platform === 'linux') {
      const descriptor = job.descriptor;
      observerLineage = clone(options.observerLineage || []);
      const current = { namespace: descriptor.observer_pid_namespace, depth: descriptor.controller.proc_pid_chain?.length };
      if (!Number.isSafeInteger(current.depth)) throw fail('command_scope_identity_invalid');
      const last = observerLineage[observerLineage.length - 1];
      if (!last || last.namespace.dev !== current.namespace.dev || last.namespace.ino !== current.namespace.ino) observerLineage.push(current);
      if (!require('./command-scope-proof').validateExecutionScope({ schema_version: SCHEMA, backend: descriptor.backend, descriptor, observer_lineage: observerLineage })) throw fail('command_scope_identity_invalid');
    }
    if (typeof job.permit === 'function') job.permit();
    await Promise.race([hostReady, stopped.then(error => { throw error; })]);
    if (firstError || options.signal?.aborted) throw firstError || fail('command_cancelled');
    clearTimeout(setupTimer);
    started = true; workStart = lastProgress = mono();
    workTimer = setTimeout(() => reject(fail('command_work_timeout')), policy.workMs);
    if (policy.progressMs) progressTimer = setInterval(() => {
      if (mono() - lastProgress >= policy.progressMs) reject(fail('command_progress_timeout'));
    }, Math.max(1, Math.min(100, policy.progressMs)));
    const childLineage = observerLineage ? [...observerLineage, { namespace: job.descriptor.init.pid_namespace, depth: job.descriptor.init.proc_pid_chain.length }] : undefined;
    worker.send({ type: 'start', kind, payload, budgets: policy, helper, observerLineage: childLineage, proofRelay: options.proofRelay }, error => { if (error) reject(fail('command_transport_failed', error.message)); });
  } catch (error) {
    const cleanup = await close();
    const artifact = await dispose();
    if (artifact.status !== 'not_owned') cleanup.artifact_cleanup = artifact;
    if (artifact.status === 'unconfirmed') cleanup.status = 'unconfirmed';
    throw Object.assign(error, { cleanup });
  }
  const scope = Object.freeze({ schema_version: SCHEMA, backend: job.descriptor.backend, descriptor: clone(job.descriptor),
    ...(observerLineage ? { observer_lineage: observerLineage } : {}) });
  return {
    scope,
    get error() { return firstError; },
    remaining() { return Math.max(0, policy.workMs - (mono() - workStart)); },
    async result() {
      await candidate;
      const cleanup = await close();
      if (!options.deferHelperCleanup) {
        const artifact = await dispose();
        if (artifact.status !== 'not_owned') cleanup.artifact_cleanup = artifact;
        if (artifact.status === 'unconfirmed') cleanup.status = 'unconfirmed';
      }
      const body = Object.fromEntries(Object.entries(output).map(([key, chunks]) => [key, Buffer.concat(chunks).toString('utf8')]));
      if (cleanup.status !== 'completed') throw fail('command_cleanup_unconfirmed', 'Native command cleanup was not confirmed', { cleanup, primary_error: firstError?.code, ...body });
      if (firstError) throw Object.assign(firstError, { cleanup, ...body });
      try { body.stdout = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(output.stdout)); }
      catch { throw fail('command_output_encoding', 'Command stdout is not complete UTF-8', { cleanup, stderr: body.stderr }); }
      if (!result || result.error) throw fail(result?.error?.code || 'command_result_missing', result?.error?.message, { ...result?.error, cleanup, ...body });
      return { value: result.value, cleanup, scope, ...body };
    },
    async request(command) {
      if (stopping || firstError || mono() - workStart >= policy.workMs) throw firstError || fail('command_work_timeout');
      if (pending.size) throw fail('command_concurrent_request', 'A command session admits one command at a time');
      const id = ++nextRequest;
      return new Promise((resolve, requestReject) => {
        pending.set(id, { resolve, reject: requestReject });
        worker.send({ type: 'execute', id, command, remainingMs: Math.max(1, Math.floor(policy.workMs - (mono() - workStart))) }, error => {
          if (error) reject(fail('command_transport_failed', error.message));
        });
      });
    },
    close,
    cleanupRemaining, dispose,
    async finish() {
      const drained = await close();
      const receipt = await job.close(Math.max(1, cleanupRemaining()));
      const artifact = await dispose();
      return { ...receipt, ...(artifact.status === 'not_owned' ? {} : { artifact_cleanup: artifact }),
        status: receipt.status === 'completed' && drained.status === 'completed' && artifact.status !== 'unconfirmed' ? 'completed' : 'unconfirmed' };
    }
  };
}

async function runOwnedOperation(operation, payload, options = {}) {
  const relay = options.proofRelay ? null : await require('./command-scope-relay').createScopeRelay();
  let result, failure, scope;
  try {
    scope = await createScope('operation', { operation, payload }, { ...options, deferHelperCleanup: true, proofRelay: options.proofRelay || relay?.descriptor,
      onNativeReady: (descriptor, helper) => { relay?.configure(descriptor, helper); options.onNativeReady?.(descriptor, helper); } });
    result = await scope.result();
  } catch (error) { failure = error; }
  const relayCleanup = relay ? await relay.close(scope?.cleanupRemaining() ?? budgets(options.budgets).cleanupMs) : { status: 'not_owned' };
  if (relayCleanup.status === 'unconfirmed') throw fail('command_cleanup_unconfirmed', 'Read-only proof relay cleanup was not confirmed', { cleanup: relayCleanup, primary_error: failure?.code });
  const artifact = scope ? await scope.dispose() : { status: 'not_owned' };
  if (artifact.status === 'unconfirmed') throw fail('command_cleanup_unconfirmed', 'The private native snapshot was retained because its cleanup was not confirmed', { cleanup: artifact, primary_error: failure?.code });
  if (result && artifact.status !== 'not_owned') result.cleanup.artifact_cleanup = artifact;
  if (failure) throw failure;
  if (result.value && typeof result.value === 'object') result.value.ownership = { status: 'completed', scope: result.scope, cleanup: result.cleanup };
  return result;
}
async function runOwnedCommand(command, options = {}) {
  if (!command || !Array.isArray(command.args) || command.args.some(x => typeof x !== 'string' || x.includes('\0')) ||
      !path.isAbsolute(command.executable || '') || !path.isAbsolute(command.cwd || '')) throw fail('command_invalid');
  try {
    const scope = await createScope('command', command, { ...options, cwd: command.cwd, env: command.env });
    const result = await scope.result();
    return { ...result.value, stdout: result.stdout, stderr: result.stderr, cleanup: result.cleanup, scope: result.scope };
  } catch (error) {
    return { status: null, signal: null, error: { code: error.code || 'command_failed', message: error.message },
      stdout: error.stdout || '', stderr: error.stderr || '', cleanup: error.cleanup || { status: 'unconfirmed' } };
  }
}
async function createCommandSession(options = {}) {
  const scope = await createScope('session', {}, options);
  return { scope: scope.scope, run: command => scope.request(command), drain: () => scope.close({ retain: true }), finish: () => scope.finish(), remaining: () => scope.remaining() };
}

// Synchronous compatibility is an isolated driver, not unrestricted spawnSync.
// A synchronous caller cannot dispatch an in-process AbortSignal; reject it
// explicitly rather than advertising cancellation that cannot run.
function runOwnedOperationSync(operation, payload, options = {}) {
  if (options.signal) throw fail('command_sync_signal_unsupported', 'Use the asynchronous API for AbortSignal cancellation');
  const policy = budgets(options.budgets);
  const result = spawnSync(process.execPath, [path.join(__dirname, 'command-sync-driver.js')], {
    input: JSON.stringify({ operation, payload, budgets: policy }), env: safeEnvironment(),
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe', 'pipe'], maxBuffer: MAX_CHILD_JSON_BYTES * 2,
    timeout: policy.setupMs + policy.workMs + policy.cleanupMs + 5000, killSignal: 'SIGKILL', windowsHide: true
  });
  let response;
  try { response = JSON.parse(result.stdout); } catch { throw fail('command_sync_transport_unconfirmed', result.error?.message || 'Isolated driver returned no complete result'); }
  if (result.error || result.signal || result.status !== 0 || response.error) throw fail(response.error?.code || 'command_sync_transport_unconfirmed', response.error?.message, response.error || {});
  return response.value;
}
module.exports = { SCHEMA, budgets, cliBudgets, safeEnvironment, mono, delay, deadlineError, createScope, createCommandSession, runOwnedCommand, runOwnedOperation, runOwnedOperationSync };
