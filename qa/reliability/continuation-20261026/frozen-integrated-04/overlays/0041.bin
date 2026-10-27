'use strict';

// Responsive ordinary-UID controller. Project storage is confined to fixed
// child programs; native private-UID commands cannot access the signing key.
// Timers revoke acceptance, while exact child/native observations prove exit.
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { copyInertData } = require('./inert-data');
const policyAPI = require('./verification-policy');
const sessions = require('./verification-darwin-session');
const wire = require('./verification-darwin-session-protocol');
const native = require('./verification-darwin-client');
const scopeAPI = require('./verification-darwin-scope');
const finalization = require('./verification-finalization');
const darwinFinalization = require('./verification-darwin-finalization');
const control = require('./verification-control');
const adapter = require('./verification-darwin-control');
const storageGuardian = require('./verification-darwin-storage-guardian');
const PROTOCOL = 'knowledge-darwin-production.v1';
const STORE_PROTOCOL = 'knowledge-darwin-storage.v1';
const AUTHORITY_PROTOCOL = 'knowledge-darwin-authority.v1';
const MAX_BYTES = 32 * 1024 * 1024;
const diagnostic = value => [...wire.PROOF_DIAGNOSTICS, ...adapter.CONTROL_DIAGNOSTICS].includes(value) ? value : null;
const clock = () => process.hrtime.bigint();
const elapsed = started => Number(clock() - started) / 1e6;
const left = deadline => Math.max(0, Number(deadline - clock()) / 1e6);
const failure = (code, fields = {}) => Object.assign(new Error(code), { code, ...fields });
function inert(value) { return copyInertData(value, null, MAX_BYTES); }
function guardInput(request, timeoutMs, started) {
  if (process.platform !== 'darwin') throw failure('verification_darwin_required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > policyAPI.MAX_WORK_MS ||
      typeof started !== 'bigint' || started < 0n || started > clock()) throw failure('verification_clock_invalid');
  const config = policyAPI.nativeExecutionRequest(request)?.darwin;
  if (!config?.enabled) throw failure('verification_darwin_opt_in_required');
  return config;
}
function childChannel(file, protocol, { onEvent, onUnexpectedExit, autoExit = false, guardian } = {}) {
  const args = file === 'verification-darwin-store.js' ? [path.join(__dirname, file), String(process.pid)] : [path.join(__dirname, file)];
  const child = file === 'verification-darwin-store.js' ? storageGuardian.createStorageChild(guardian) : spawn(process.execPath, args, {
    env: native.nativeEnv(), stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true
  });
  let sequence = 0, pending, allowedExit = autoExit, exited = false, disconnected = false, closed = false;
  let exitCode = null, signal = null, chain = Promise.resolve();
  const waiters = new Set();
  const snapshot = () => ({ pid: child.pid || null, exit_observed: exited, ipc_closed: disconnected,
    exit_code: exitCode, signal, ...(child.storageSnapshot ? { storage_guardian: child.storageSnapshot() } : {}) });
  function notifyExit() {
    if (exited && disconnected) for (const done of waiters) done(snapshot());
  }
  function rejectPending(code) {
    if (pending) { const old = pending;pending = null;old.reject(failure(code)); }
  }
  child.on('message', raw => {
    let message;try { message = inert(raw); } catch { onUnexpectedExit?.(failure('verification_darwin_ipc_invalid'));return; }
    if (message?.protocol !== protocol) { onUnexpectedExit?.(failure('verification_darwin_ipc_invalid'));return; }
    if (message.type) {
      Promise.resolve(onEvent?.(message, child)).catch(error => onUnexpectedExit?.(error));return;
    }
    if (!pending || message.id !== pending.id || typeof message.ok !== 'boolean') {
      onUnexpectedExit?.(failure('verification_darwin_ipc_invalid'));return;
    }
    const old = pending;pending = null;
    if (message.ok) old.resolve(message.value);
    else old.reject(failure(/^[a-zA-Z0-9_]{1,100}$/.test(message.code || '') ? message.code : 'verification_darwin_storage_failed'));
  });
  child.once('exit', (code, value) => {
    exited = true;exitCode = code;signal = value;rejectPending('verification_darwin_child_exited');
    if (!allowedExit) onUnexpectedExit?.(failure('verification_darwin_child_exited', snapshot()));
    notifyExit();
  });
  child.once('disconnect', () => { disconnected = true;rejectPending('verification_darwin_child_disconnected');notifyExit(); });
  child.once('error', () => {
    if (!child.pid) { exited = disconnected = true;notifyExit(); }
    rejectPending('verification_darwin_child_spawn_failed');onUnexpectedExit?.(failure('verification_darwin_child_spawn_failed'));
  });
  const send = value => {
    if (closed || !child.connected) return Promise.reject(failure('verification_darwin_child_disconnected'));
    if (Buffer.byteLength(JSON.stringify(value)) > MAX_BYTES) return Promise.reject(failure('verification_transport_oversized'));
    return new Promise((resolve, reject) => child.send(value, error => error ? reject(error) : resolve()));
  };
  return {
    child, snapshot, allowExit() { allowedExit = true; },
    send: value => send({ protocol, ...value }),
    request(op, value = {}) {
      const job = chain.then(() => {
        if (closed || exited || pending) throw failure('verification_darwin_storage_unavailable');
        const id = ++sequence;
        return new Promise((resolve, reject) => {
          pending = { id, resolve, reject };
          send({ protocol, id, op, ...value }).catch(error => { if (pending?.id === id) pending = null;reject(error); });
        });
      });
      chain = job.catch(() => {});return job;
    },
    async waitExit(deadline) {
      if (exited && disconnected) return snapshot();
      if (!left(deadline)) return snapshot();
      return new Promise(resolve => {
        let timer;
        const done = value => { clearTimeout(timer);waiters.delete(done);resolve(value); };
        waiters.add(done);timer = setTimeout(() => done(snapshot()), policyAPI.timerDelay(left(deadline)));
        notifyExit();
      });
    },
    async finish(deadline) {
      await chain;allowedExit = true;
      if (!exited && !autoExit) await send({ protocol, id: ++sequence, op: 'exit' });
      const observed = await this.waitExit(deadline);
      if (!observed.exit_observed || !observed.ipc_closed || observed.exit_code !== 0 || observed.signal !== null) {
        throw failure('verification_darwin_storage_cleanup_unconfirmed', { child: observed });
      }
      closed = true;child.stdio[3]?.destroy();return observed;
    },
    async terminate(deadline) {
      allowedExit = true;closed = true;rejectPending('verification_darwin_cancelled');
      if (!exited) { if (child.stopWithin) child.stopWithin(deadline);else child.kill('SIGKILL'); }
      const observed = await this.waitExit(deadline);
      if (!observed.exit_observed || !observed.ipc_closed) {
        // Native custody continues independently. An I/O-stuck writer may
        // leave G waiting forever on waitpid; G's referenced status pipe must
        // not retain this caller after its cleanup deadline. Closing our
        // transport is not a writer-exit observation or permission to reclaim.
        try { if (child.connected) child.disconnect(); } catch {}
        try { child.unref(); } catch {}
        for (const stream of child.stdio || []) { try { stream?.destroy?.(); } catch {} }
      }
      child.stdio[3]?.destroy();return observed;
    }
  };
}
function completeResult(message, request, batchId, requestDigest, publicKey) {
  return Array.isArray(message?.result) && message.result.length === request.tests.length && message.result.length > 0 &&
    message.result.every((item, index) => item?.record?.batch_id === batchId && item.record.batch_ordinal === index &&
      item.record.batch_request_sha256 === requestDigest && item.record.batch_public_key === publicKey &&
      item.record.status === 'pass' && item.record.exit_code === 0 && item.record.signal === null &&
      item.record.timed_out === false && wire.canonical(item.record.command_argv) === wire.canonical(request.tests[index].argv));
}
function firstCommandFailure(message, request, batchId, requestDigest, publicKey) {
  // This is a diagnostic for a completed nonzero command, never an acceptance
  // predicate. Timeout, missing records and unbound results retain their own
  // incomplete/failure path, and every failed batch still receives no ACK.
  if (!Array.isArray(message?.result) || message.result.length !== request.tests.length || !message.result.length) return null;
  let failed = null;
  for (const [index, item] of message.result.entries()) {
    const record = item?.record;
    if (!record || record.batch_id !== batchId || record.batch_ordinal !== index ||
        record.batch_request_sha256 !== requestDigest || record.batch_public_key !== publicKey ||
        !/^KVE-[a-f0-9]{64}$/.test(record.execution_id || '') ||
        !['pass', 'fail'].includes(record.status) || !Number.isSafeInteger(record.exit_code) ||
        record.exit_code < 0 || record.exit_code > 255 || record.signal !== null || record.timed_out !== false ||
        (record.status === 'pass') !== (record.exit_code === 0) ||
        wire.canonical(record.command_argv) !== wire.canonical(request.tests[index].argv)) return null;
    if (record.status === 'fail' && !failed) failed = { execution_id: record.execution_id,
      status: 'fail', exit_code: record.exit_code, signal: null };
  }
  return failed;
}
async function runAsync(request, timeoutMs, started = clock(), options = {}) {
  request = inert(request);const config = guardInput(request, timeoutMs, started);
  const policy = policyAPI.resolvePolicy(request.verificationPolicy, timeoutMs);
  const workDeadline = started + BigInt(policy.work_budget_ms) * 1000000n;
  let phaseDeadline = workDeadline, cleanupDeadline, workElapsed, workComplete = false;
  let stopped = false, primary, session, store, authority, poller, finalizer, owner, descriptor, plan;
  let terminalCommitStarted = false, terminalCommitObserved = null;
  let storageCapability;
  let polling = false, timer, pollTimer, parentChannel, lastProgress = clock(), progressAvailable = false;
  let phaseName = 'setup', copyFiles = 0, copyBytes = 0, preparedResolve, registeredResolve, completedResolve;
  const registered = new Promise(resolve => { registeredResolve = resolve; });
  const prepared = new Promise(resolve => { preparedResolve = resolve; });
  const completed = new Promise(resolve => { completedResolve = resolve; });
  const abort = new AbortController();let rejectStopped;
  const interrupted = new Promise((_, reject) => { rejectStopped = reject; });
  interrupted.catch(() => {});
  const deadline = () => cleanupDeadline || workDeadline;
  const guardedStorage = extra => {
    const end = deadline(), cleanupPhase = !!cleanupDeadline, custodyNonce = crypto.randomBytes(32).toString('hex');
    // Root custody is an immutable lifetime hard bound, not the current phase
    // deadline. The initial writer may legitimately finalize after work ends.
    // Its native guardian enforces the narrower latched cleanup epoch; this
    // independent fallback never extends beyond original work plus cleanup.
    const custodyEnd = cleanupDeadline || workDeadline + BigInt(policy.cleanup_budget_ms) * 1000000n;
    return childChannel('verification-darwin-store.js', STORE_PROTOCOL, {
      ...extra, guardian: { config: { ...config, broker_path: storageCapability?.broker_path || config.broker_path },
        source_sha256: storageCapability?.source_sha256, deadline_ns: String(end),
        cleanup_ms: policy.cleanup_budget_ms, phase: cleanupPhase ? 'cleanup' : 'work',
        async beforeStoragePermit(births) {
          const remaining = Math.floor(left(end)), custodyRemaining = Math.floor(left(custodyEnd));
          if (remaining < 1 || custodyRemaining < 1) throw failure('verification_darwin_storage_custody_expired');
          // Register before S receives its native execution permit. The root
          // observer owns exact writer/guardian births even if BOTH ordinary
          // enforcers die during project I/O; this kill-only registration does
          // not allocate a private UID or admit repository execution.
          const reply = (await sessions.rpc(config, { op: 'register_fixed_writer', ...births,
            custody_nonce: custodyNonce, deadline_ns: String(custodyEnd), work_budget_ms: custodyRemaining },
          { limitMs: remaining, ...(cleanupPhase ? {} : { signal: abort.signal }) })).reply;
          if (clock() >= end || reply.ok !== true || reply.custody_nonce !== custodyNonce ||
              reply.schema !== 'knowledge-macos-fixed-writer-custody.v1' || reply.deadline_ns !== String(custodyEnd) ||
              reply.kill_only !== true || reply.execute_authority_granted !== false || reply.owner_uid !== process.getuid() ||
              !['source_sha256', 'binary_sha256', 'host_id', 'boot_id', 'installation_id'].every(key => reply[key] === storageCapability[key]) ||
              reply.controller?.pid !== process.pid || !scopeAPI.validateProcessIdentity({ schema: 'knowledge-darwin-process-identity.v1',
                host_id: storageCapability.host_id, boot_id: storageCapability.boot_id, owner_uid: process.getuid(), birth: reply.controller }) ||
              wire.digest(reply.writer) !== wire.digest(births.writer) || wire.digest(reply.guardian) !== wire.digest(births.guardian)) {
            throw failure('verification_darwin_storage_custody_unconfirmed');
          }
        } }
    });
  };
  function guard() {
    if (stopped) throw primary || failure('verification_darwin_cancelled');
    if (!left(deadline())) throw failure(workComplete ? 'verification_cleanup_unconfirmed' : 'verification_timeout');
  }
  function interrupt(error) {
    if (stopped) return;
    stopped = true;primary = error;abort.abort();
    // No disk write precedes independent native stop or acceptance revocation.
    session?.stop(error.code).catch(() => {});
    rejectStopped(error);
  }
  const cancel = () => interrupt(failure('verification_cancelled'));
  function tick() {
    if (stopped) return;
    const now = clock();
    if (now >= deadline() || !workComplete && now >= phaseDeadline) {
      interrupt(failure(workComplete ? 'verification_cleanup_unconfirmed' : 'verification_timeout', { timed_out: !workComplete }));return;
    }
    if (!workComplete && progressAvailable && policy.no_progress_ms > 0 && Number(now - lastProgress) / 1e6 >= policy.no_progress_ms) {
      interrupt(failure('verification_progress_timeout', { timed_out: true }));return;
    }
    timer = setTimeout(tick, Math.min(100, policyAPI.timerDelay(left(deadline()))));
  }
  function meaningful() { lastProgress = clock(); }
  function startCleanup() {
    if (workComplete) return;
    guard();workComplete = true;workElapsed = elapsed(started);
    cleanupDeadline = clock() + BigInt(policy.cleanup_budget_ms) * 1000000n;
    progressAvailable = false;
  }
  async function poll() {
    if (!polling || stopped || !owner || poller) return;
    const current = guardedStorage();poller = current;
    try {
      const value = await current.request('status_only', { request });
      const exit = await current.finish(deadline());
      if (!exit.exit_observed || !exit.ipc_closed) throw failure('verification_darwin_status_cleanup_unconfirmed');
      const observed = value?.attempt;
      if (!observed || observed.attempt_id !== owner.attempt_id || observed.generation !== owner.generation) throw failure('verification_attempt_mismatch');
      if (observed.cancel.requested || observed.stop_reason || observed.recovery) throw failure(observed.cancel.requested ? 'verification_cancelled' : 'verification_stopped');
    } catch (error) { if (polling) interrupt(error); }
    finally {
      if (poller === current) poller = null;
      if (polling && !stopped) pollTimer = setTimeout(poll, Math.max(250, policy.control_poll_ms));
    }
  }
  process.on('SIGTERM', cancel);process.on('SIGINT', cancel);
  options.signal?.addEventListener('abort', cancel, { once: true });
  if (options.parentFd !== undefined) {
    parentChannel = new net.Socket({ fd: options.parentFd, readable: true, writable: false });
    parentChannel.on('end', cancel);parentChannel.on('error', cancel);parentChannel.resume();
  }
  tick();if (options.signal?.aborted) cancel();
  const batchId = 'KVB-' + crypto.randomBytes(16).toString('hex');
  const requestDigest = finalization.digest(request);
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const nonce = crypto.randomBytes(32).toString('hex');
  const main = async () => {
    // An unavailable broker must not reserve a project claim.
    const capability = await sessions.probeSession(config, { signal: abort.signal, setupBudgetMs: Math.max(1, Math.floor(left(workDeadline))) });guard();
    storageCapability = capability;
    store = guardedStorage({
      onUnexpectedExit: interrupt,
      onEvent: async (event, child) => {
        guard();
        if (event.type === 'copy_progress') {
          if (Number.isSafeInteger(event.files) && event.files > copyFiles && Number.isSafeInteger(event.bytes) && event.bytes >= copyBytes) {
            copyFiles = event.files;copyBytes = event.bytes;meaningful();
          } else throw failure('verification_darwin_copy_progress_invalid');
          return;
        }
        if (event.type !== 'copy_request' || !Number.isSafeInteger(event.copy_id) ||
            !['mkdir', 'put_begin', 'put_chunk', 'put_commit', 'seal'].includes(event.input?.op) || !session) throw failure('verification_darwin_copy_protocol');
        const auth = session.privateBinding();
        // Only this phase exposes a finite unit of data progress to M. Hashing,
        // source readback and native commands may legitimately remain silent;
        // their cancellation and absolute work deadlines still apply.
        progressAvailable = event.input.op === 'put_chunk' && typeof event.input.data === 'string' && event.input.data.length > 0;
        if (progressAvailable) { phaseName = 'copy_chunk';meaningful(); }
        try {
          const answer = await sessions.rpc(config, { ...event.input, attempt_id: session.binding.attempt_id, token: auth.token },
            { signal: abort.signal, limitMs: Math.max(1, Math.floor(left(workDeadline))) });guard();
          child.send({ protocol: STORE_PROTOCOL, type: 'copy_reply', copy_id: event.copy_id, ok: true, value: answer.reply });
        } catch (error) {
          if (child.connected) child.send({ protocol: STORE_PROTOCOL, type: 'copy_reply', copy_id: event.copy_id, ok: false, code: error.code });
          throw error;
        } finally { progressAvailable = false; }
      }
    });
    const opened = await store.request('init', { request, profile: { work_budget_ms: policy.work_budget_ms,
      no_progress_ms: policy.no_progress_ms, cleanup_budget_ms: policy.cleanup_budget_ms }, nonce, config, deadline_ns: String(workDeadline) });
    owner = opened.owner;guard();meaningful();
    polling = true;pollTimer = setTimeout(poll, Math.max(250, policy.control_poll_ms));
    await store.request('update', { event: { type: 'phase', phase: 'preparing' } });guard();
    session = await sessions.openSession({ config, nonce, workBudgetMs: Math.max(1, Math.floor(left(workDeadline))),
      cleanupBudgetMs: policy.cleanup_budget_ms, signal: abort.signal, expectedCapability: capability });guard();
    const identityNonce = crypto.randomBytes(32).toString('hex');
    const peer = (await sessions.rpc(config, { op: 'peer_identity', observation_nonce: identityNonce },
      { signal: abort.signal, limitMs: Math.max(1, Math.floor(left(workDeadline))) })).reply;
    if (peer.observation_nonce !== identityNonce || peer.status !== 'active' || !scopeAPI.validateProcessIdentity(peer.identity) ||
        peer.identity.birth.pid !== process.pid || peer.identity.host_id !== capability.host_id || peer.identity.boot_id !== capability.boot_id) {
      throw failure('verification_darwin_controller_identity_unconfirmed');
    }
    descriptor = adapter.descriptor({ scope: session.commandScope(), controller_identity: peer.identity, authority_identity: null });
    await store.request('update', { event: { type: 'containment_bound', descriptor, spawn_ids: [] } });guard();
    const implementation = await store.request('pin_implementation');guard();
    plan = await store.request('prepare_copy', { request, limits: config.copy });guard();
    const sealedReadback = await session.readback(plan, 'sealed');guard();meaningful();
    await session.expectAuthority();guard();
    authority = childChannel('verification-darwin-authority.js', AUTHORITY_PROTOCOL, {
      onUnexpectedExit: interrupt,
      onEvent: async event => {
        guard();
        if (event.type === 'registered') { registeredResolve(event.registration);meaningful();return; }
        if (event.type === 'prepared') { preparedResolve();meaningful();return; }
        if (event.type === 'error') throw failure(event.code || 'verification_darwin_authority_failed');
        if (event.type === 'phase') {
          if (typeof event.deadline_ns !== 'string' || !/^\d{1,32}$/.test(event.deadline_ns)) throw failure('verification_clock_invalid');
          const bound = BigInt(event.deadline_ns);
          if (bound > workDeadline || bound <= clock()) throw failure('verification_timeout');
          phaseDeadline = bound;phaseName = event.stage;progressAvailable = false;meaningful();
          await authority.send({ type: 'ack', id: event.id });return;
        }
        if (event.type === 'committed') { meaningful();return; }
        if (event.type === 'work_complete') {
          if (!completeResult(event, request, batchId, requestDigest, publicKey)) {
            const commandFailure = firstCommandFailure(event, request, batchId, requestDigest, publicKey);
            if (commandFailure) throw failure('verification_command_failed', { command_failure: commandFailure });
            throw failure('verification_batch_incomplete');
          }
          startCleanup();await store.request('cleanup_epoch', { deadline_ns: String(cleanupDeadline) });return;
        }
        if (event.type === 'complete') { completedResolve(event);return; }
        throw failure('verification_darwin_authority_protocol');
      }
    });
    await authority.send({ type: 'prepare', session: session.privateBinding(), request, plan,
      deadline_ns: String(workDeadline), batch_id: batchId, public_key: publicKey, request_sha256: requestDigest });
    const registration = await registered;guard();
    const authorityIdentity = { schema: 'knowledge-darwin-process-identity.v1', host_id: capability.host_id,
      boot_id: capability.boot_id, owner_uid: session.binding.descriptor.owner_uid, birth: registration.authority };
    if (!scopeAPI.validateProcessIdentity(authorityIdentity) || authorityIdentity.birth.pid !== authority.child.pid) {
      throw failure('verification_darwin_authority_identity_unconfirmed');
    }
    descriptor = adapter.descriptor({ scope: session.commandScope(), controller_identity: peer.identity, authority_identity: authorityIdentity });
    await store.request('update', { event: { type: 'darwin_authority_bound', descriptor, pid: authority.child.pid,
      process_nonce: owner.generation, executable_sha256: capability.runtime_sha256 } });guard();
    await prepared;guard();
    await store.request('update', { event: { type: 'phase', phase: 'running' } });guard();
    await session.permit();guard();await authority.send({ type: 'run' });
    const complete = await completed;guard();
    if (!workComplete || !completeResult(complete, request, batchId, requestDigest, publicKey)) throw failure('verification_batch_incomplete');
    const drain = wire.validateProof(complete.drain.reply, session.binding, capability, false);
    wire.validateReadback(complete.readback, session.binding, plan, 'commands_drained');
    authority.allowExit();const terminal = await session.close();guard();
    const authorityExit = await authority.waitExit(cleanupDeadline);guard();
    if (!authorityExit.exit_observed || !authorityExit.ipc_closed || authorityExit.signal !== 'SIGKILL') {
      throw failure('verification_darwin_authority_cleanup_unconfirmed', { authority_exit: authorityExit });
    }
    authorityExit.process_nonce = owner.generation;authorityExit.method = 'process_handle_signaled';
    const teardown = adapter.normalProof({ descriptor, terminalReply: terminal.reply, capability,
      authorityExit: { pid: authorityExit.pid, process_nonce: owner.generation, method: 'process_handle_signaled', exit_observed: true } });
    const closedReadback = await session.readback(plan, 'closed');guard();
    await store.request('update', { event: { type: 'process_exit', spawn_id: 1, pid: authorityExit.pid,
      process_nonce: owner.generation, method: 'process_handle_signaled' } });guard();
    polling = false;clearTimeout(pollTimer);
    if (poller) { const observed = await poller.terminate(cleanupDeadline);poller = null;
      if (!observed.exit_observed || !observed.ipc_closed) throw failure('verification_darwin_status_cleanup_unconfirmed'); }
    const record = { schema_version: darwinFinalization.SCHEMA, batch_id: batchId, public_key: publicKey,
      request_sha256: requestDigest, task_id: String(request.taskId), session_id: String(request.sessionId),
      status: 'commands_and_teardown_observed', backend: 'darwin_private_ruid', teardown,
      timeout_ms: policy.work_budget_ms, observed_elapsed_ms: elapsed(started), work_elapsed_ms: workElapsed,
      cleanup_budget_ms: policy.cleanup_budget_ms, runtime_sha256: capability.runtime_sha256,
      executions: complete.result.map(item => ({ execution_id: item.record.execution_id })),
      darwin: { binding: session.binding, scope: session.commandScope(), capability,
        plan_summary: darwinFinalization.planSummary(plan), source_snapshot: complete.result[0].record.source_snapshot,
        readbacks: [sealedReadback, complete.readback, closedReadback], commands: complete.commands,
        command_results: complete.command_results, streams: complete.streams,
        command_drain_reply: complete.drain.reply, terminal_reply: terminal.reply, authority_exit: authorityExit } };
    if (terminal.proof.command_drain_sha256 !== wire.digest(drain)) throw failure('verification_darwin_drain_binding_mismatch');
    const reference = await store.request('finalize', { record, plan, implementation_before: implementation });guard();
    const acceptance = finalization.acceptFinalization(reference, policy.work_budget_ms, elapsed(started), keys.privateKey,
      { work_elapsed_ms: workElapsed, cleanup_budget_ms: policy.cleanup_budget_ms });guard();
    await store.request('verify_acceptance', { ids: complete.result.map(item => item.record.execution_id), acceptance });guard();
    const storageExit = await store.finish(cleanupDeadline);guard();
    finalizer = guardedStorage({ onUnexpectedExit: interrupt });
    terminalCommitStarted = true;
    const finish = await finalizer.request('finish_only', { request, owner, deadline_ns: String(cleanupDeadline), input: {
      outcome: 'passed', cleanup_proof: control.bindCleanupProof(owner, teardown), ack_sha256: finalization.digest([acceptance]),
      deadline_ns: String(cleanupDeadline) } });
    terminalCommitObserved = finish.status;guard();
    const finishExit = await finalizer.finish(cleanupDeadline);guard();
    if (finish.status !== 'passed' || finish.ack_released !== true) throw failure(finish.status === 'cancelled' ? 'verification_cancelled' : 'verification_stopped');
    return { protocol: PROTOCOL, status: 'completed', result: complete.result, acceptances: [acceptance],
      budget: { timeout_ms: policy.work_budget_ms, work_budget_ms: policy.work_budget_ms,
        cleanup_budget_ms: policy.cleanup_budget_ms, no_progress_ms: policy.no_progress_ms,
        progress_monitored_operations: ['native_copy_chunk'],
        work_elapsed_ms: workElapsed, total_elapsed_ms: elapsed(started), attempt_id: owner.attempt_id,
        clock: 'process.hrtime.bigint', teardown, storage_exit: storageExit, finalizer_exit: finishExit } };
  };
  try { return await Promise.race([main(), interrupted]); }
  catch (error) {
    interrupt(error);polling = false;clearTimeout(pollTimer);
    cleanupDeadline ||= clock() + BigInt(policy.cleanup_budget_ms) * 1000000n;
    const observed = await Promise.all([authority, store, poller, finalizer].filter(Boolean).map(child => child.terminate(cleanupDeadline)));
    let recovery = null;
    // Once all original storage writers actually exited, a fixed reclaimer
    // holds the same lifetime lease while checking fresh native closure. A
    // lost init ACK can select only our random startup nonce, never a different
    // current attempt with an identical request or an older reservation.
    if (store && observed.every(value => value.exit_observed && value.ipc_closed) && left(cleanupDeadline) > 0) {
      const reclaimer = guardedStorage();
      let recoveryTimer;
      try {
        const result = await Promise.race([reclaimer.request('recover_only', { request, owner,
          startup_nonce_sha256: finalization.hash(nonce), cancelled: primary?.code === 'verification_cancelled',
          deadline_ns: String(cleanupDeadline) }), new Promise((_, reject) => {
          recoveryTimer = setTimeout(() => reject(failure('verification_cleanup_unconfirmed')), policyAPI.timerDelay(left(cleanupDeadline)));
        })]);
        const exit = await reclaimer.finish(cleanupDeadline);
        recovery = { status: result.status, ack_released: result.ack_released === true, exit,
          cleanup: result.attempt?.cleanup || null, claimed: result.attempt?.claimed ?? null,
          terminal_outcome: result.attempt?.terminal?.outcome || null };
      } catch (cause) {
        const exit = await reclaimer.terminate(cleanupDeadline);
        recovery = { status: 'unconfirmed', code: cause.code || 'verification_native_recovery_failed', exit };
      } finally { clearTimeout(recoveryTimer); }
    }
    const recovered = recovery && ['failed', 'cancelled', 'already_terminal'].includes(recovery.status) &&
      recovery.claimed === false && recovery.cleanup?.status === 'confirmed' && recovery.ack_released === false;
    const preflight = !store && !session;
    const helperUnconfirmed = preflight && primary?.helper?.pid && primary.helper.exit_observed !== true;
    const unavailable = preflight && !helperUnconfirmed &&
      !['verification_cancelled', 'verification_darwin_cancelled', 'verification_timeout',
        'verification_progress_timeout', 'verification_darwin_setup_budget_exceeded',
        'verification_darwin_helper_budget_exceeded'].includes(primary?.code);
    return { protocol: PROTOCOL, status: 'failed', error: { code: unavailable ? 'verification_containment_unavailable' : primary?.code || 'verification_darwin_failed',
      ...(preflight ? { execution: { status: 'not_started' } } : {}),
      ...(unavailable ? { containment: { platform: process.platform, backend: 'darwin_private_ruid',
        status: 'unavailable', reason: primary?.code || 'broker_preflight_failed' } } : {}),
      timed_out: primary?.timed_out === true, darwin_diagnostic: diagnostic(primary?.darwin_diagnostic), attempt_id: owner?.attempt_id || null,
      ...(primary?.code === 'verification_command_failed' && primary.command_failure ? { command_failure: primary.command_failure } : {}),
      recovery_required: !!store && !recovered, stage: phaseName,
      result_visibility: 'ack_not_delivered',
      terminal_commit: recovery?.terminal_outcome || terminalCommitObserved ||
        (terminalCommitStarted ? 'may_have_committed' : 'not_started') }, completed_executions: [],
      teardown: { status: preflight && !helperUnconfirmed ? 'not_required' : recovered ? 'completed' : 'unconfirmed',
        reason: preflight ? 'preflight_no_work_admitted' : recovered ? 'fresh_native_recovery_and_storage_exit_observed' : 'fresh_native_recovery_required',
        ...(preflight && primary?.helper ? { readonly_helper: primary.helper } : {}),
        owned_children: observed, recovery },
      budget: { timeout_ms: policy.work_budget_ms, cleanup_budget_ms: policy.cleanup_budget_ms, total_elapsed_ms: elapsed(started) } };
  } finally {
    clearTimeout(timer);clearTimeout(pollTimer);polling = false;
    process.removeListener('SIGTERM', cancel);process.removeListener('SIGINT', cancel);
    options.signal?.removeEventListener('abort', cancel);parentChannel?.destroy();
  }
}
function runSync(request, timeoutMs, started = clock()) {
  request = inert(request);guardInput(request, timeoutMs, started);
  const policy = policyAPI.resolvePolicy(request.verificationPolicy, timeoutMs);
  const input = JSON.stringify({ protocol: PROTOCOL, request, timeout_ms: timeoutMs, started_ns: String(started) });
  if (Buffer.byteLength(input) > MAX_BYTES) throw failure('verification_transport_oversized');
  const observed = spawnSync(process.execPath, [__filename, '--controller'], { input, encoding: 'utf8',
    env: native.nativeEnv(), stdio: ['pipe', 'pipe', 'pipe', 'pipe'], maxBuffer: MAX_BYTES,
    timeout: Math.max(1, Math.ceil(policy.work_budget_ms - elapsed(started) + policy.cleanup_budget_ms + 1000)), killSignal: 'SIGKILL' });
  let value;try { value = inert(JSON.parse(observed.stdout)); } catch {}
  if (observed.error || observed.signal || observed.status !== 0 || value?.protocol !== PROTOCOL) {
    throw failure('verification_darwin_transport_failed', { teardown: { status: 'unconfirmed' }, recovery_required: true });
  }
  if (value.status !== 'completed') throw failure(value.error?.code || 'verification_darwin_failed', {
    ...value.error, teardown: value.teardown, verification_budget: value.budget });
  if (!Array.isArray(value.result) || value.acceptances?.length !== 1) throw failure('verification_darwin_transport_failed');
  Object.defineProperty(value.result, 'verification_acceptances', { value: value.acceptances });
  Object.defineProperty(value.result, 'verification_budget', { value: value.budget });
  return value.result;
}
if (require.main === module && process.argv[2] === '--controller') {
  let bytes = 0;const chunks = [];
  process.stdin.on('data', chunk => { bytes += chunk.length;if (bytes > MAX_BYTES) process.exit(2);chunks.push(chunk); });
  process.stdin.on('end', async () => {
    try {
      const input = inert(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      if (input.protocol !== PROTOCOL || typeof input.started_ns !== 'string' || !/^\d{1,32}$/.test(input.started_ns)) throw failure('verification_clock_invalid');
      const result = await runAsync(input.request, input.timeout_ms, BigInt(input.started_ns), { parentFd: 3 });
      process.stdout.write(JSON.stringify(result), () => process.exit(0));
    } catch (error) { process.stdout.write(JSON.stringify({ protocol: PROTOCOL, status: 'failed', error: { code: error.code || 'verification_darwin_failed' },
      teardown: { status: 'unconfirmed' } }), () => process.exit(0)); }
  });
}
module.exports = { PROTOCOL, runSync, runAsync, completeResult, firstCommandFailure };
