'use strict';

// Responsive ordinary-UID controller. All project filesystem work is confined
// to registered storage children; the signing key stays in this process.
// Native private UIDs own A/W, and separate native guardians own each S writer.
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { copyInertData } = require('./inert-data');
const { safeEnvironment } = require('./command-runner');
const policyAPI = require('./verification-policy');
const clientAPI = require('./verification-linux-service-client');
const finalization = require('./verification-finalization');
const serviceFinalization = require('./verification-linux-service-finalization');
const adapter = require('./verification-linux-service-control');
const control = require('./verification-control');
const PROTOCOL = 'knowledge-linux-service-production.v1';
const STORE_PROTOCOL = 'knowledge-linux-service-storage.v1';
const MAX_MESSAGE = 64 * 1024 * 1024;
const MAX_REQUEST = 2 * 1024 * 1024;
const clock = () => process.hrtime.bigint();
const elapsed = started => Number(clock() - started) / 1e6;
const left = deadline => Math.max(0, Number(deadline - clock()) / 1e6);
const failure = (code, fields = {}) => Object.assign(new Error(code), { code, ...fields });
const inert = value => copyInertData(value, null, MAX_REQUEST);
function within(promise, deadline) {
  const input = Promise.resolve(promise);
  return new Promise((resolve, reject) => {
    const remaining = left(deadline);
    if (!remaining) { input.catch(() => {});reject(failure('verification_cleanup_unconfirmed'));return; }
    const timer = setTimeout(() => reject(failure('verification_cleanup_unconfirmed')), policyAPI.timerDelay(remaining));
    input.then(value => { clearTimeout(timer);resolve(value); }, error => { clearTimeout(timer);reject(error); });
  });
}
function writerClosureValid(closed, registration, maximum, observedBefore) {
  const value = closed?.value, source = registration?.value;
  return value?.event === 'writer_closed' && value.status === 'closed' && source?.event === 'writer_registered' &&
    value.pid === source.pid && value.birth_ticks === source.birth_ticks && value.registration_ordinal === source.ordinal &&
    ['pidfd_exit_observed', 'guardian_reaped', 'writer_cgroup_empty', 'registration_removed', 'closed_in_budget'].every(key => value[key] === true) &&
    /^[1-9]\d{0,19}$/.test(value.deadline_ns || '') && /^[1-9]\d{0,19}$/.test(value.observed_ns || '') &&
    BigInt(value.observed_ns) < BigInt(value.deadline_ns) && BigInt(value.deadline_ns) <= maximum &&
    BigInt(value.observed_ns) < observedBefore;
}
function guardInput(request, timeoutMs, started) {
  if (process.platform !== 'linux') throw failure('verification_linux_required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > policyAPI.MAX_WORK_MS ||
      typeof started !== 'bigint' || started < 0n || started > clock()) throw failure('verification_clock_invalid');
  const config = policyAPI.nativeExecutionRequest(request)?.linux;
  if (!config?.enabled) throw failure('verification_linux_service_opt_in_required');
  if (!Array.isArray(request.tests) || request.tests.length < 1 || request.tests.length > 64) throw failure('verification_linux_batch_limit');
  return config;
}
function storageChannel({ onFailure, onEvent }) {
  const child = spawn(process.execPath, [path.join(__dirname, 'verification-linux-service-store.js'), String(process.pid)], {
    env: safeEnvironment(process.env), stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true
  });
  let sequence = 0, pending, allowedExit = false, exited = false, disconnected = false,
    exitCode = null, exitSignal = null, closed = false, chain = Promise.resolve();
  const waiters = new Set();
  const snapshot = () => ({ pid: child.pid || null, exit_observed: exited, ipc_closed: disconnected,
    exit_code: exitCode, signal: exitSignal });
  function rejectPending(error) { if (pending) { const prior = pending;pending = null;prior.reject(error); } }
  function wake() { if (exited && disconnected) for (const resolve of waiters) resolve(snapshot()); }
  child.on('message', raw => {
    // This channel's sender is our fixed S. IPC deserialization already yields
    // inert JSON; source bytes can be larger than the public request budget.
    let message;
    try {
      const bytes = JSON.stringify(raw);if (Buffer.byteLength(bytes) > MAX_MESSAGE) throw failure('verification_transport_oversized');
      message = JSON.parse(bytes);
    } catch { onFailure(failure('verification_linux_storage_protocol'));return; }
    if (message?.protocol !== STORE_PROTOCOL) { onFailure(failure('verification_linux_storage_protocol'));return; }
    if (message.type) { try { onEvent?.(message); } catch (error) { onFailure(error); }return; }
    if (!pending || message.id !== pending.id || typeof message.ok !== 'boolean') { onFailure(failure('verification_linux_storage_protocol'));return; }
    const prior = pending;pending = null;
    if (message.ok) prior.resolve(message.value);
    else prior.reject(failure(/^[a-zA-Z0-9_]{1,100}$/.test(message.code || '') ? message.code : 'verification_linux_storage_failed'));
  });
  child.on('exit', (code, signal) => {
    exited = true;exitCode = code;exitSignal = signal;rejectPending(failure('verification_linux_storage_exited'));
    if (!allowedExit) onFailure(failure('verification_linux_storage_exited'));wake();
  });
  child.on('disconnect', () => { disconnected = true;rejectPending(failure('verification_linux_storage_disconnected'));wake(); });
  child.on('error', () => { if (!child.pid) exited = disconnected = true;rejectPending(failure('verification_linux_storage_spawn_failed'));
    onFailure(failure('verification_linux_storage_spawn_failed'));wake(); });
  const send = value => {
    if (closed || !child.connected) return Promise.reject(failure('verification_linux_storage_disconnected'));
    if (Buffer.byteLength(JSON.stringify(value)) > MAX_MESSAGE) return Promise.reject(failure('verification_transport_oversized'));
    return new Promise((resolve, reject) => child.send(value, error => error ? reject(error) : resolve()));
  };
  return { child, snapshot, get pending() { return pending !== null && pending !== undefined; },
    request(op, fields = {}) {
      const work = chain.then(() => {
        if (closed || exited) throw failure('verification_linux_storage_exited');
        const id = ++sequence;
        return new Promise((resolve, reject) => {
          pending = { id, resolve, reject };
          send({ protocol: STORE_PROTOCOL, id, op, ...fields }).catch(error => { if (pending?.id === id) pending = null;reject(error); });
        });
      });chain = work.catch(() => {});return work;
    },
    waitExit(deadline) {
      if (exited && disconnected || !left(deadline)) return Promise.resolve(snapshot());
      return new Promise(resolve => {
        let timer;
        const done = value => { clearTimeout(timer);waiters.delete(done);resolve(value); };
        waiters.add(done);timer = setTimeout(() => done(snapshot()), policyAPI.timerDelay(left(deadline)));wake();
      });
    },
    async finish(deadline) {
      await within(chain, deadline);allowedExit = true;
      if (!exited) await within(send({ protocol: STORE_PROTOCOL, id: ++sequence, op: 'exit' }), deadline);
      const observed = await this.waitExit(deadline);closed = true;child.stdio[3]?.destroy();
      if (!observed.exit_observed || !observed.ipc_closed || observed.exit_code !== 0 || observed.signal !== null) {
        throw failure('verification_linux_storage_cleanup_unconfirmed', { child: observed });
      }
      return observed;
    },
    async terminate(deadline) {
      allowedExit = true;closed = true;rejectPending(failure('verification_cancelled'));
      if (!exited) child.kill('SIGKILL');
      const observed = await this.waitExit(deadline);
      if (!observed.exit_observed || !observed.ipc_closed) {
        try { if (child.connected) child.disconnect(); } catch {}
        child.unref();for (const stream of child.stdio) stream?.destroy?.();
      }
      child.stdio[3]?.destroy();return observed;
    }
  };
}
function completeResult(authority, request, batchId, requestDigest, publicKey) {
  return authority?.batch_id === batchId && authority.request_sha256 === requestDigest && authority.public_key === publicKey &&
    Array.isArray(authority.result) && authority.result.length > 0 && authority.result.length === request.tests.length &&
    authority.result.every((item, index) => item.record?.batch_id === batchId && item.record.batch_ordinal === index &&
      item.record.batch_request_sha256 === requestDigest && item.record.batch_public_key === publicKey &&
      item.record.task_id === String(request.taskId) && item.record.session_id === String(request.sessionId) &&
      item.record.status === 'pass' && item.record.exit_code === 0 && item.record.signal === null && item.record.timed_out === false &&
      serviceFinalization.same(item.record.command_argv, request.tests[index].argv));
}
async function runAsync(request, timeoutMs, started = clock(), options = {}) {
  request = inert(request);const config = guardInput(request, timeoutMs, started);
  const policy = policyAPI.resolvePolicy(request.verificationPolicy, timeoutMs);
  const workDeadline = started + BigInt(policy.work_budget_ms) * 1000000n;
  const maximumEnd = workDeadline + BigInt(policy.cleanup_budget_ms) * 1000000n;
  const nonce = crypto.randomBytes(32).toString('hex'), batchId = 'KVB-' + crypto.randomBytes(16).toString('hex');
  const requestDigest = finalization.digest(request), keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  let client, capability, store, finalizer, owner, descriptor, plan, implementation, terminalEvent, teardown,
    cleanupDeadline, cleanupStart, nativeCleanupEnd, workElapsed, storeCleanup = false, stopped = false, primary, timer,
    parentChannel, polling = false, pollTimer, pollPromise, stage = 'preflight', finalCommit = null, claimStarted = false, openSent = false;
  const owned = new Set();
  let copyFiles = 0, copyBytes = 0, lastProgress = clock(), progressAvailable = false;
  let rejectInterrupted;
  const interrupted = new Promise((_, reject) => { rejectInterrupted = reject; });interrupted.catch(() => {});
  const deadline = () => cleanupDeadline || workDeadline;
  const guard = () => { if (stopped) throw primary;if (!left(deadline())) throw failure(cleanupDeadline ? 'verification_cleanup_unconfirmed' : 'verification_timeout'); };
  function latchCleanup(value) {
    if (value.nonce !== nonce || value.work_deadline_ns !== String(workDeadline) || value.cleanup_budget_ms !== policy.cleanup_budget_ms ||
        !/^[1-9]\d{0,19}$/.test(value.cleanup_started_ns || '') || !/^[1-9]\d{0,19}$/.test(value.cleanup_deadline_ns || '')) {
      throw failure('verification_linux_cleanup_epoch_invalid');
    }
    const begin = BigInt(value.cleanup_started_ns), end = BigInt(value.cleanup_deadline_ns);
    if (begin < started || end <= begin || end > maximumEnd || end - begin > BigInt(policy.cleanup_budget_ms) * 1000000n ||
        cleanupStart && (cleanupStart !== begin || nativeCleanupEnd !== end)) throw failure('verification_linux_cleanup_epoch_invalid');
    cleanupStart = begin;nativeCleanupEnd = end;cleanupDeadline = cleanupDeadline && cleanupDeadline < end ? cleanupDeadline : end;
    workElapsed = Number(begin - started) / 1e6;progressAvailable = false;
  }
  function interrupt(error) {
    if (stopped) return;stopped = true;primary = error;polling = false;clearTimeout(pollTimer);
    client?.stop();rejectInterrupted(error);
  }
  const cancel = () => interrupt(failure('verification_cancelled'));
  function tick() {
    if (stopped) return;
    const now = clock();
    if (now >= deadline()) { interrupt(failure(cleanupDeadline ? 'verification_cleanup_unconfirmed' : 'verification_timeout', { timed_out: !cleanupDeadline }));return; }
    if (!cleanupDeadline && progressAvailable && policy.no_progress_ms > 0 && Number(now - lastProgress) / 1e6 >= policy.no_progress_ms) {
      interrupt(failure('verification_progress_timeout', { timed_out: true }));return;
    }
    timer = setTimeout(tick, Math.min(100, policyAPI.timerDelay(left(deadline()))));
  }
  function onNativeEvent(event) {
    if (event.kind === 'cleanup_started') latchCleanup(event.value);
    if (event.kind === 'terminal') {
      latchCleanup(event.value);terminalEvent = event;
      if (event.value.status !== 'completed') interrupt(failure(event.value.status === 'timed_out' ? 'verification_timeout' :
        event.value.status === 'cancelled' ? 'verification_cancelled' : 'verification_linux_native_failed', {
        timed_out: event.value.status === 'timed_out' }));
    }
  }
  async function newStore() {
    guard();const value = storageChannel({ onFailure: interrupt, onEvent(event) {
      if (event.type !== 'copy_progress' || !Number.isSafeInteger(event.files) || event.files <= copyFiles ||
          !Number.isSafeInteger(event.bytes) || event.bytes < copyBytes) throw failure('verification_linux_copy_progress_invalid');
      copyFiles = event.files;copyBytes = event.bytes;lastProgress = clock();
    } });
    // No operation is sent before the service acknowledges exact writer
    // custody and durable registration for this P birth and child PID.
    owned.add(value);
    const registered = await client.registerWriter(value.child.pid, deadline(), ordinal => { value.registrationOrdinal = ordinal; });
    value.registration = registered;guard();
    const r = registered.value;
    if (r.status !== 'registered' || r.pid !== value.child.pid || r.controller_pid !== process.pid ||
        r.controller_birth_ticks !== capability.controller_birth_ticks || r.registered_before_storage_permit !== true ||
        !/^[1-9]\d{0,19}$/.test(r.birth_ticks || '') || BigInt(r.deadline_ns) > maximumEnd ||
        cleanupDeadline && BigInt(r.deadline_ns) !== cleanupDeadline) throw failure('verification_linux_storage_custody_unconfirmed');
    value.registration = registered;guard();return value;
  }
  async function closeStore(value) {
    const observed = await value.finish(deadline());guard();
    const closed = await client.writerClosed(observed.pid, deadline(), value.registration);guard();
    if (!writerClosureValid(closed, value.registration, nativeCleanupEnd || maximumEnd, deadline())) throw failure('verification_linux_storage_cleanup_unconfirmed');
    return { ...observed, native_registration: value.registration.value, native_closure: closed.value };
  }
  async function ensureCleanupEpoch() {
    if (!cleanupDeadline) throw failure('verification_linux_cleanup_epoch_missing');
    if (!storeCleanup) { await store.request('cleanup_epoch', { deadline_ns: String(cleanupDeadline) });storeCleanup = true; }
  }
  function poll() {
    if (!polling || stopped) return;
    pollPromise = (async () => {
      const observed = (await store.request('status')).attempt;
      if (!observed || observed.attempt_id !== owner.attempt_id || observed.generation !== owner.generation) throw failure('verification_attempt_mismatch');
      if (observed.cancel.requested || observed.stop_reason || observed.recovery) throw failure(observed.cancel.requested ? 'verification_cancelled' : 'verification_stopped');
    })().catch(interrupt).finally(() => {
      pollPromise = null;if (polling && !stopped) pollTimer = setTimeout(poll, Math.max(250, policy.control_poll_ms));
    });
  }
  process.on('SIGTERM', cancel);process.on('SIGINT', cancel);options.signal?.addEventListener('abort', cancel, { once: true });
  if (options.parentFd !== undefined) {
    parentChannel = new net.Socket({ fd: options.parentFd, readable: true, writable: false });
    parentChannel.on('end', cancel);parentChannel.on('error', cancel);parentChannel.resume();
  }
  tick();if (options.signal?.aborted) cancel();
  const main = async () => {
    guard();client = clientAPI.createClient({ config, nonce, workDeadline, cleanupMs: policy.cleanup_budget_ms,
      onEvent: onNativeEvent, onFailure: interrupt });
    capability = (await client.hello()).value;guard();
    if (!serviceFinalization.validateCapability(capability) || capability.client_pid !== client.child.pid ||
        capability.controller_pid !== process.pid || capability.controller_uid !== process.getuid()) throw failure('verification_linux_capability_unconfirmed');
    store = await newStore();guard();stage = 'source_preparation';
    await store.request('init', { request, capability, deadline_ns: String(workDeadline) });guard();
    progressAvailable = true;lastProgress = clock();
    const prepared = await store.request('prepare_copy', { request, limits: config.copy });guard();
    plan = prepared.plan;progressAvailable = false;implementation = await store.request('pin_implementation');guard();
    claimStarted = true;
    const openedAttempt = await store.request('begin', { request, nonce, profile: { work_budget_ms: policy.work_budget_ms,
      no_progress_ms: policy.no_progress_ms, cleanup_budget_ms: policy.cleanup_budget_ms } });owner = openedAttempt.owner;guard();
    stage = 'native_execution';
    const envelope = JSON.stringify({ source: prepared.source, authority: { batch_id: batchId, deadline_ns: String(workDeadline),
      nonce, public_key: publicKey, request, request_sha256: requestDigest } });
    if (Buffer.byteLength(envelope) > 64 * 1024 * 1024) throw failure('verification_transport_oversized');
    openSent = true;await client.send(3, envelope);guard();
    const opened = (await client.event('opened', deadline())).value;guard();
    if (!serviceFinalization.validateOpened(opened) || opened.nonce !== nonce || opened.work_deadline_ns !== String(workDeadline) ||
        opened.cleanup_budget_ms !== policy.cleanup_budget_ms) throw failure('verification_linux_open_unconfirmed');
    descriptor = adapter.descriptor({ capability, opened });
    if (cleanupDeadline) await ensureCleanupEpoch();
    await store.request('update', { event: { type: 'containment_bound', backend: adapter.METHOD, descriptor, spawn_ids: [] } });guard();
    if (!cleanupDeadline) await store.request('update', { event: { type: 'phase', phase: 'running' } });guard();
    // Native OPEN reserves custody but its namespace gate remains closed.
    // Repository execution is permitted only after durable project binding.
    await client.send(6);await client.event('permitted', deadline());guard();
    polling = true;pollTimer = setTimeout(poll, Math.max(250, policy.control_poll_ms));
    // Native cleanup may start before the original work endpoint. Waits use
    // the immutable maximum here; tick and native custody enforce the earlier
    // work endpoint until the exact native cleanup latch has arrived.
    const [terminal, authorityEvent] = await Promise.all([client.event('terminal', maximumEnd), client.event('authority_result', maximumEnd)]);guard();
    terminalEvent = terminal;teardown = adapter.normalProof({ descriptor, capability, terminalReply: terminal.value, terminalRaw: terminal.raw });
    serviceFinalization.validateTerminal({ capability, terminalReply: terminal.value, terminalRaw: terminal.raw, opened });
    const authority = authorityEvent.value;
    if (!completeResult(authority, request, batchId, requestDigest, publicKey)) throw failure('verification_command_failed');
    polling = false;clearTimeout(pollTimer);if (pollPromise) await pollPromise;guard();
    await ensureCleanupEpoch();guard();stage = 'finalization';
    const record = { schema_version: serviceFinalization.SCHEMA, batch_id: batchId, public_key: publicKey,
      request_sha256: requestDigest, task_id: String(request.taskId), session_id: String(request.sessionId),
      status: 'commands_and_teardown_observed', backend: adapter.METHOD, teardown,
      timeout_ms: policy.work_budget_ms, observed_elapsed_ms: elapsed(started), work_elapsed_ms: workElapsed,
      cleanup_budget_ms: policy.cleanup_budget_ms, runtime_sha256: capability.node_sha256,
      executions: authority.result.map(item => ({ execution_id: item.record.execution_id })),
      linux: { capability, terminal_reply: terminal.value, terminal_raw: terminal.raw, authority_raw: authorityEvent.raw,
        plan_summary: serviceFinalization.planSummary(plan), source_snapshot: authority.result[0].record.source_snapshot } };
    const persisted = await store.request('finalize', { record, plan, implementation_before: implementation });guard();
    const acceptance = finalization.acceptFinalization(persisted.reference, policy.work_budget_ms, elapsed(started), keys.privateKey,
      { work_elapsed_ms: workElapsed, cleanup_budget_ms: policy.cleanup_budget_ms });guard();
    await store.request('verify_acceptance', { ids: persisted.result.map(item => item.record.execution_id), acceptance });guard();
    const storageExit = await closeStore(store);guard();stage = 'terminal_commit';
    finalizer = await newStore();guard();
    finalCommit = 'may_have_committed';
    const finish = await finalizer.request('finish_only', { request, capability, owner, deadline_ns: String(cleanupDeadline), input: {
      outcome: 'passed', cleanup_proof: control.bindCleanupProof(owner, teardown), ack_sha256: finalization.digest([acceptance]),
      deadline_ns: String(cleanupDeadline) } });finalCommit = finish.status;guard();
    const finalizerExit = await closeStore(finalizer);guard();
    if (finish.status !== 'passed' || finish.ack_released !== true) throw failure(finish.status === 'cancelled' ? 'verification_cancelled' : 'verification_stopped');
    const clientExit = await client.finish(cleanupDeadline);guard();
    return { protocol: PROTOCOL, status: 'completed', result: persisted.result, acceptances: [acceptance],
      budget: { timeout_ms: policy.work_budget_ms, work_budget_ms: policy.work_budget_ms, cleanup_budget_ms: policy.cleanup_budget_ms,
        no_progress_ms: policy.no_progress_ms, progress_monitored_operations: ['source_copy_file'], work_elapsed_ms: workElapsed,
        total_elapsed_ms: elapsed(started), clock: 'process.hrtime.bigint', attempt_id: owner.attempt_id,
        teardown, storage_exit: storageExit, finalizer_exit: finalizerExit, client_exit: clientExit } };
  };
  try { return await Promise.race([main(), interrupted]); }
  catch (error) {
    interrupt(error);polling = false;clearTimeout(pollTimer);
    // Cancellation fixes one endpoint. A later native event may tighten it;
    // neither a retry nor final storage admission is allowed to extend it.
    cleanupDeadline ||= clock() + BigInt(policy.cleanup_budget_ms) * 1000000n;
    if (cleanupDeadline > maximumEnd) cleanupDeadline = maximumEnd;
    const children = [...owned];
    const exits = await Promise.all(children.map(child => child.terminate(cleanupDeadline)));
    let recovered = false, recovery = null, allStorageClosed = exits.every(value => value.exit_observed && value.ipc_closed);
    const nativeStorageClosures = [];
    for (const child of children) {
      try {
        if (!allStorageClosed) break;
        // A lost registration ACK is unknown custody. Recover only the exact
        // ordinal from this live authenticated session before matching closure.
        if (child.registrationOrdinal === undefined) {
          if (child.registration) throw failure('verification_linux_storage_custody_unconfirmed');
          continue;
        }
        const registration = child.registration || await client.event('writer_registered', cleanupDeadline,
          value => value.pid === child.child.pid && value.ordinal === child.registrationOrdinal);
        const closed = await client.writerClosed(child.child.pid, cleanupDeadline, registration);
        if (!writerClosureValid(closed, registration, nativeCleanupEnd || maximumEnd, cleanupDeadline)) throw failure('verification_linux_storage_cleanup_unconfirmed');
        nativeStorageClosures.push({ registration: registration.value, closure: closed.value });
      } catch { allStorageClosed = false; }
    }
    try {
      if (client && owner && descriptor && allStorageClosed && left(cleanupDeadline)) {
        const terminal = terminalEvent || await client.event('terminal', cleanupDeadline);
        const proof = adapter.normalProof({ descriptor, capability, terminalReply: terminal.value, terminalRaw: terminal.raw });
        // The client is still the original authenticated session; its retained
        // native receipt supports a cleanup-only failed terminal transition.
        if (!left(cleanupDeadline)) throw failure('verification_cleanup_unconfirmed');
        const value = storageChannel({ onFailure: () => {}, onEvent: () => {} });owned.add(value);
        try {
          const registration = await within(client.registerWriter(value.child.pid, cleanupDeadline,
            ordinal => { value.registrationOrdinal = ordinal; }), cleanupDeadline);value.registration = registration;
          const result = await within(value.request('finish_only', { request, capability, owner, deadline_ns: String(cleanupDeadline), input: {
            outcome: primary?.timed_out ? 'timed_out' : primary?.code === 'verification_cancelled' ? 'cancelled' : 'failed',
            cleanup_proof: control.bindCleanupProof(owner, proof), deadline_ns: String(cleanupDeadline) }, descriptor }), cleanupDeadline);
          const exit = await value.finish(cleanupDeadline), closure = await client.writerClosed(value.child.pid, cleanupDeadline, registration);
          recovered = ['failed', 'cancelled', 'timed_out', 'already_terminal'].includes(result.status) && result.ack_released !== true &&
            exit.exit_observed && exit.ipc_closed && writerClosureValid(closure, registration, nativeCleanupEnd || maximumEnd, cleanupDeadline);
          recovery = { status: result.status, ack_released: result.ack_released === true, exit, native_closure: closure.value };
        } finally { await value.terminate(cleanupDeadline); }
      } else if (client && claimStarted && !openSent && allStorageClosed && left(cleanupDeadline) > 20) {
        // No OPEN frame was ever issued. Once every original S has physically
        // closed, a fresh storage-only native session can resolve a lost begin
        // reply by its random startup nonce. Its hard bound is the old endpoint.
        await client.finish(cleanupDeadline);
        const recoveryEnd = cleanupDeadline - 1000000n;
        const recoveryClient = clientAPI.createClient({ config, nonce: crypto.randomBytes(32).toString('hex'),
          workDeadline: recoveryEnd, cleanupMs: 1, onEvent: () => {}, onFailure: () => {} });
        let value;
        try {
          const observedCapability = (await within(recoveryClient.hello(), cleanupDeadline)).value;
          if (!serviceFinalization.validateCapability(observedCapability) || observedCapability.controller_pid !== process.pid ||
              observedCapability.client_pid !== recoveryClient.child.pid ||
              !['installation_id', 'host_id', 'boot_id', 'daemon_epoch', 'native_source_sha256', 'trusted_runtime_manifest_sha256',
                'trusted_source_manifest_sha256', 'node_sha256', 'broker_binary_sha256'].every(key => observedCapability[key] === capability[key])) {
            throw failure('verification_linux_storage_custody_unconfirmed');
          }
          if (left(cleanupDeadline) <= 1) throw failure('verification_cleanup_unconfirmed');
          value = storageChannel({ onFailure: () => {}, onEvent: () => {} });owned.add(value);
          const registration = await within(recoveryClient.registerWriter(value.child.pid, cleanupDeadline,
            ordinal => { value.registrationOrdinal = ordinal; }), cleanupDeadline);value.registration = registration;
          const result = await within(value.request('recover_initial', { request, capability: observedCapability,
            startup_nonce_sha256: finalization.hash(nonce), deadline_ns: String(cleanupDeadline) }), cleanupDeadline);
          const exit = await value.finish(cleanupDeadline), closed = await recoveryClient.writerClosed(value.child.pid, cleanupDeadline, registration);
          const helper = await recoveryClient.finish(cleanupDeadline);
          recovered = ['not_published', 'failed', 'cancelled', 'already_terminal'].includes(result.status) && result.ack_released !== true &&
            exit.exit_observed && exit.ipc_closed && writerClosureValid(closed, registration, cleanupDeadline, cleanupDeadline) && helper.exit_observed && helper.close_observed;
          recovery = { status: result.status, ack_released: false, exact_startup_nonce: true, no_open_frame_issued: true,
            exit, native_closure: closed.value, client_exit: helper };
        } finally {
          if (value) await value.terminate(cleanupDeadline);
          await recoveryClient.terminate(cleanupDeadline);
        }
      }
    } catch (cause) { recovery = { status: 'unconfirmed', code: cause.code || 'verification_linux_recovery_failed' }; }
    const clientExit = client ? await client.terminate(cleanupDeadline) : null;
    const noClaim = !claimStarted;
    const noClaimClosed = noClaim && allStorageClosed &&
      (!client || clientExit?.exit_observed === true && clientExit.close_observed === true);
    return { protocol: PROTOCOL, status: 'failed', error: { code: primary?.code || 'verification_linux_service_failed',
      timed_out: primary?.timed_out === true, stage, attempt_id: owner?.attempt_id || null,
      recovery_required: primary?.code === 'verification_recovery_required' || claimStarted && !recovered,
      result_visibility: 'ack_not_delivered', terminal_commit: finalCommit || 'not_started',
      ...(noClaim ? { execution: { status: 'not_started' } } : {}) }, completed_executions: [],
      teardown: { status: (recovered || noClaimClosed) && (!client || clientExit?.exit_observed === true &&
        clientExit.close_observed === true && clientExit.stdout_eof === true && clientExit.stderr_eof === true) ? 'completed' : 'unconfirmed',
        owned_children: exits, native_storage_closures: nativeStorageClosures, client_exit: clientExit, recovery },
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
  if (Buffer.byteLength(input) > MAX_REQUEST) throw failure('verification_transport_oversized');
  const observed = spawnSync(process.execPath, [__filename, '--controller'], { input, encoding: 'utf8',
    env: safeEnvironment(process.env), stdio: ['pipe', 'pipe', 'pipe', 'pipe'], maxBuffer: MAX_REQUEST,
    timeout: Math.max(1, Math.ceil(policy.work_budget_ms - elapsed(started) + policy.cleanup_budget_ms + 1000)), killSignal: 'SIGKILL' });
  let value;try { value = inert(JSON.parse(observed.stdout)); } catch {}
  if (observed.error || observed.signal || observed.status !== 0 || value?.protocol !== PROTOCOL) {
    throw failure('verification_linux_transport_failed', { teardown: { status: 'unconfirmed' }, recovery_required: true });
  }
  if (value.status !== 'completed') throw failure(value.error?.code || 'verification_linux_service_failed', {
    ...value.error, teardown: value.teardown, verification_budget: value.budget });
  if (!Array.isArray(value.result) || value.acceptances?.length !== 1) throw failure('verification_linux_transport_failed');
  Object.defineProperty(value.result, 'verification_acceptances', { value: value.acceptances });
  Object.defineProperty(value.result, 'verification_budget', { value: value.budget });return value.result;
}
if (require.main === module && process.argv[2] === '--controller') {
  let count = 0;const chunks = [];
  process.stdin.on('data', chunk => { count += chunk.length;if (count > MAX_REQUEST) process.exit(2);chunks.push(chunk); });
  process.stdin.on('end', async () => {
    try {
      const input = inert(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      if (input.protocol !== PROTOCOL || typeof input.started_ns !== 'string' || !/^\d{1,20}$/.test(input.started_ns)) throw failure('verification_clock_invalid');
      const result = await runAsync(input.request, input.timeout_ms, BigInt(input.started_ns), { parentFd: 3 });
      process.stdout.write(JSON.stringify(result), () => process.exit(0));
    } catch (error) { process.stdout.write(JSON.stringify({ protocol: PROTOCOL, status: 'failed', error: { code: error.code || 'verification_linux_service_failed' },
      teardown: { status: 'unconfirmed' } }), () => process.exit(0)); }
  });
}
module.exports = { PROTOCOL, runSync, runAsync, completeResult, storageChannel, writerClosureValid };
