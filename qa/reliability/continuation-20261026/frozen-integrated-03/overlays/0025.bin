'use strict';

// Original-UID controller: no project filesystem access. Two independent
// native guardians own the fixed trusted authority and state worker. All
// repository programs execute through the private-UID workspace session.
const crypto = require('node:crypto');
const { copyInertData } = require('./inert-data');
const { MAX_CHILD_JSON_BYTES } = require('./semantic-json');
const sessions = require('./macos-workspace-session');
const transport = require('./verification-darwin-session');
const { createStorageChild } = require('./verification-darwin-storage-guardian');
const PROTOCOL = 'knowledge-macos-command-worker.v1';
const MAX_MESSAGE = MAX_CHILD_JSON_BYTES * 2 + 1024 * 1024;
const fail = (code, details = {}) => Object.assign(new Error(code), { code, ...details });
const clock = () => process.hrtime.bigint();
const remaining = end => Math.max(0, Math.floor(Number(end - clock()) / 1e6));
const deferred = () => { let resolve, reject;const promise = new Promise((a, b) => { resolve = a;reject = b; });
  promise.catch(() => {});return { promise, resolve, reject }; };

async function runOwnedOperation(operation, payload, options = {}) {
  if (process.platform !== 'darwin') throw fail('command_macos_required');
  if (!['flow-main', 'flow-run', 'flow-step', 'evaluation-main', 'evaluation-check', 'watch-main', 'macos-command'].includes(operation)) {
    throw fail('command_macos_operation_unsupported');
  }
  const runner = require('./command-runner'), policy = runner.budgets(options.budgets);
  const input = sessions.configuration(options), started = clock();
  const setupEnd = started + BigInt(policy.setupMs) * 1000000n;
  const workEnd = options.absoluteWorkDeadlineNs === undefined ?
    setupEnd + BigInt(policy.workMs) * 1000000n : BigInt(options.absoluteWorkDeadlineNs);
  if (workEnd <= started || workEnd - started > BigInt(policy.setupMs + policy.workMs) * 1000000n) throw fail('command_clock_invalid');
  const aborted = new AbortController(), done = deferred(), registered = deferred(), failed = deferred();
  const attemptNonce = crypto.randomBytes(32).toString('hex');
  let session, authority, worker, firstError, finishing = false, result, timer, cleanupEnd, nativeClosed = false, settingUp = true;
  let requestActive = false, requestOrdinal = 0, sequence = 0, terminalReceipt, lastProgress = started, cleanupEpoch, unsubscribeLifecycle;
  const children = [];
  const beginCleanup = () => cleanupEnd ||= clock() + BigInt(policy.cleanupMs) * 1000000n;
  function interrupt(error) {
    firstError ||= error;beginCleanup();aborted.abort();
    session?.stop(error.code).catch(() => {});
    for (const child of children) child.process.stopWithin(cleanupEnd);
    registered.reject(firstError);done.reject(firstError);failed.reject(firstError);
  }
  const cancel = () => interrupt(fail('command_cancelled'));
  options.signal?.addEventListener('abort', cancel, { once: true });
  function guard() {
    if (firstError) throw firstError;
    if (options.signal?.aborted || clock() >= (cleanupEnd || workEnd)) throw fail(options.signal?.aborted ? 'command_cancelled' : cleanupEnd ? 'command_cleanup_timeout' : 'command_work_timeout');
  }
  async function owned(value) { const result = await Promise.race([value, failed.promise]);guard();return result; }
  async function bounded(value, end) {
    let timer;
    try { return await Promise.race([value, new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(fail('command_cleanup_timeout')), Math.max(1, remaining(end)));
    })]); } finally { clearTimeout(timer); }
  }
  if (options.subscribeLifecycle) unsubscribeLifecycle = options.subscribeLifecycle(event => {
    try {
      if (settingUp || cleanupEpoch || event?.type !== 'cleanup_epoch' ||
          !['work_completed', 'work_timeout', 'failure', 'cancelled'].includes(event.reason) ||
          typeof event.at_ns !== 'string' || !/^[1-9]\d{0,31}$/.test(event.at_ns)) throw fail('command_lifecycle_invalid');
      const at = BigInt(event.at_ns);
      if (at < started || at > clock()) throw fail('command_lifecycle_invalid');
      cleanupEpoch = { at_ns: event.at_ns, reason: event.reason };
      cleanupEnd = at + BigInt(policy.cleanupMs) * 1000000n;
      for (const child of children) child.process.send({ protocol: PROTOCOL, op: 'cleanup_epoch',
        type: 'cleanup_epoch', deadline_ns: String(cleanupEnd) }, error => { if (error) interrupt(fail('command_macos_cleanup_epoch_failed')); });
    } catch (error) { interrupt(error); }
  }, interrupt);
  function spawnWorker(role) {
    const out = { role, exited: deferred(), exit: null, expectedExit: false };
    out.process = createStorageChild({ config: input.config, source_sha256: session.capability.source_sha256,
      deadline_ns: String(workEnd), cleanup_ms: policy.cleanupMs, macosWorkerRoot: session.binding.descriptor.protected_worker_root,
      ...(role === 'operation' ? { macosWritableRoot: session.binding.descriptor.writable_root } : {}),
      beforeMacOSPermit: births => owned(role === 'operation' ? session.registerStateWriter(births) : session.registerAuthorityCustody(births)) });
    children.push(out);
    out.process.on('error', error => { if (!finishing) interrupt(error); });
    out.process.once('exit', (code, signal) => {
      out.exit = { exit_observed: true, code, signal, ...out.process.storageSnapshot() };
      out.exited.resolve(out.exit);
      if (!out.expectedExit && !finishing && (role !== 'operation' || code !== 0 || signal !== null)) interrupt(fail('command_macos_worker_exited'));
    });
    out.send = value => new Promise((resolve, reject) => out.process.send({ protocol: PROTOCOL, ...value },
      error => error ? reject(fail('command_macos_transport_failed')) : resolve()));
    out.process.on('message', raw => {
      Promise.resolve().then(async () => {
        const message = copyInertData(raw, null, MAX_MESSAGE);
        if (message?.protocol !== PROTOCOL || !message.type) throw fail('command_macos_worker_protocol');
        if (message.type === 'error') throw fail(message.error?.code || 'command_macos_worker_failed', message.error || {});
        if (role === 'authority') {
          if (message.type !== 'registered' || out.registered) throw fail('command_macos_authority_protocol');
          const birth = message.registration?.authority;
          if (message.registration?.ok !== true || birth?.pid !== out.process.pid || birth?.ruid !== process.getuid()) {
            throw fail('command_macos_authority_identity_invalid');
          }
          out.registered = true;lastProgress = clock();registered.resolve(message.registration);return;
        }
        guard();
        if (message.type === 'cancel_active' && requestActive && message.id === requestOrdinal) {
          // Native stop is independent of worker I/O. Until a cancelled-command
          // terminal can be returned, this conservative path publishes no
          // graceful/durable watcher completion claim.
          interrupt(fail('command_cancelled'));return;
        }
        if (message.type === 'progress') {
          if (!Number.isSafeInteger(message.sequence) || message.sequence !== sequence + 1 || typeof message.phase !== 'string') {
            throw fail('command_progress_invalid');
          }
          sequence = message.sequence;lastProgress = clock();options.onProgress?.(message.phase, message.detail);return;
        }
        if (message.type === 'result') {
          if (result || requestActive) throw fail('command_macos_result_order_invalid');
          out.expectedExit = true;result = message;done.resolve(message);return;
        }
        if (message.type !== 'request' || !Number.isSafeInteger(message.id) || message.id !== requestOrdinal + 1 || requestActive ||
            !['execute', 'drain', 'finish', 'observe_scope'].includes(message.op)) throw fail('command_macos_request_invalid');
        if (cleanupEpoch && message.op === 'execute') throw fail('command_macos_admission_closed');
        requestOrdinal = message.id;requestActive = true;
        let value;
        try {
          if (message.op === 'observe_scope') {
            const previous = message.scope, api = require('./macos-command-scope');
            if (!api.validateCommandScope(previous) || previous.broker_path !== input.config.broker_path ||
                previous.broker_socket !== input.config.broker_socket || previous.binding.descriptor.owner_uid !== process.getuid() ||
                previous.binding.descriptor.writable_root !== session.binding.descriptor.writable_root ||
                previous.binding.descriptor.host_id !== session.capability.host_id ||
                previous.binding.descriptor.installation_id !== session.capability.installation_id) throw fail('command_macos_preflight_scope_invalid');
            const nonce = crypto.randomBytes(32).toString('hex');
            const response = await owned(transport.rpc(input.config, { op: 'observe_scope',
              attempt_id: previous.binding.attempt_id, descriptor_sha256: previous.binding.descriptor_sha256,
              observation_nonce: nonce }, { signal: aborted.signal, limitMs: Math.min(30000, remaining(cleanupEnd || workEnd)) }));
            const closure = api.validateObservation(response.reply, previous, session.capability, nonce);
            // An active/unknown old generation never becomes cached authority.
            value = closure.status === 'completed' ? { status: 'completed', scope: previous, closure,
              capability: session.capability, observation_nonce: nonce } : { status: closure.status, code: closure.code };
          } else if (message.op === 'execute') {
            const output = [[], []], counts = [0, 0];
            const receive = index => chunk => {
              counts[index] += chunk.length;
              if (counts[index] > MAX_CHILD_JSON_BYTES) throw fail('command_output_limit');
              output[index].push(Buffer.from(chunk));
            };
            value = await owned(session.run(message.command, { onStdout: receive(0), onStderr: receive(1) }));
            const bytes = output.map((rows, index) => Buffer.concat(rows, counts[index]));
            if (value.helper.stdout_bytes !== counts[0] || value.helper.stderr_bytes !== counts[1] ||
                value.helper.stdout_sha256 !== crypto.createHash('sha256').update(bytes[0]).digest('hex') ||
                value.helper.stderr_sha256 !== crypto.createHash('sha256').update(bytes[1]).digest('hex')) throw fail('command_output_unconfirmed');
            value.stdout = new TextDecoder('utf8', { fatal: true }).decode(bytes[0]);
            value.stderr = new TextDecoder('utf8', { fatal: true }).decode(bytes[1]);
          } else if (message.op === 'drain') {
            const drain = await owned(session.drain());
            authority.expectedExit = true;const closed = await owned(session.close());nativeClosed = true;
            const exit = await owned(authority.exited.promise);
            if (!exit.writer_exit_observed || exit.signal !== 'SIGKILL') throw fail('command_macos_authority_exit_unconfirmed');
            const nonce = crypto.randomBytes(32).toString('hex');
            const observation = (await owned(transport.rpc(input.config, { op: 'observe_scope', attempt_id: session.binding.attempt_id,
              descriptor_sha256: session.binding.descriptor_sha256, observation_nonce: nonce },
            { signal: aborted.signal, limitMs: Math.min(policy.cleanupMs, remaining(workEnd)) }))).reply;
            const closure = require('./macos-command-scope').validateObservation(observation, session.scope, session.capability, nonce);
            if (closure.status !== 'completed') throw fail('command_macos_scope_closure_unconfirmed');
            terminalReceipt = { ...closed, authority_exit: exit, closure, capability: session.capability, observation_nonce: nonce };
            value = { ...drain, terminal: terminalReceipt };
          } else {
            if (!terminalReceipt) throw fail('command_macos_terminal_order_invalid');
            value = terminalReceipt;
          }
          guard();requestActive = false;lastProgress = clock();await owned(out.send({ type: 'reply', id: message.id, value }));
        } finally { requestActive = false; }
      }).catch(interrupt);
    });
    return out;
  }
  function tick() {
    if (firstError || finishing) return;
    if (settingUp && clock() >= setupEnd) interrupt(fail('command_setup_timeout'));
    else if (clock() >= (cleanupEnd || workEnd)) interrupt(fail(cleanupEnd ? 'command_cleanup_timeout' : 'command_work_timeout'));
    else if (!settingUp && !cleanupEpoch && !requestActive && policy.progressMs > 0 && Number(clock() - lastProgress) / 1e6 >= policy.progressMs) {
      interrupt(fail('command_progress_timeout'));
    }
    // No heartbeat or stdout renews work. Only explicit semantic events may
    // satisfy an optional progress deadline; silent commands remain valid.
    else timer = setTimeout(tick, Math.min(100, Math.max(1, remaining(cleanupEnd || workEnd))));
  }
  try {
    if (options.signal?.aborted) cancel();guard();tick();
    const opening = sessions.openSession({ ...input, nonce: attemptNonce, deadlineNs: workEnd, cleanupMs: policy.cleanupMs, signal: aborted.signal });
    opening.then(late => { if (firstError) late.stop('controller_cancelled_during_setup').catch(() => {}); }, () => {});
    session = await owned(opening);
    if (clock() >= setupEnd) throw fail('command_setup_timeout');
    await owned(session.expectAuthority());
    authority = spawnWorker('authority');
    await owned(authority.send({ type: 'start', role: 'authority', input: session.authorityInput() }));
    await owned(registered.promise);
    worker = spawnWorker('operation');
    await owned(worker.process.nativeReady);
    await owned(session.permit());
    await owned(worker.send({ type: 'start', role: 'operation', operation, payload, budgets: policy,
      scope: session.scope, descriptor: session.binding.descriptor, deadline_ns: String(workEnd),
      environment: runner.safeEnvironment(options.env || process.env) }));
    settingUp = false;lastProgress = clock();
    const answer = await owned(done.promise);
    if (!nativeClosed || !answer.value) throw fail('command_macos_terminal_missing');
    const exit = await owned(worker.exited.promise);
    if (!exit.writer_exit_observed || exit.code !== 0 || exit.signal !== null) throw fail('command_macos_state_worker_exit_unconfirmed');
    finishing = true;
    const cleanup = { status: 'completed', method: 'macos_composite_owned_scope',
      command_scope_closed: true, authority_exit: authority.exit, state_worker_exit: exit,
      ...(cleanupEpoch ? { cleanup_epoch: cleanupEpoch, cleanup_deadline_ns: String(cleanupEnd) } : {}) };
    if (answer.value && typeof answer.value === 'object') answer.value.ownership = { status: 'completed', scope: session.scope, cleanup };
    return { value: answer.value, scope: session.scope, cleanup, stdout: '', stderr: '' };
  } catch (error) {
    interrupt(error);finishing = true;
    const end = beginCleanup();
    if (session && remaining(end)) {
      try { await bounded(session.stop(error.code), end);if (remaining(end)) await bounded(session.recover(remaining(end)), end); } catch {}
    }
    for (const child of children) child.process.stopWithin(end);
    if (remaining(end)) {
      let exitTimer;
      try { await Promise.race([Promise.all(children.map(child => child.exited.promise)),
        new Promise(resolve => { exitTimer = setTimeout(resolve, Math.max(1, remaining(end))); })]); }
      finally { clearTimeout(exitTimer); }
    }
    const exits = children.map(child => ({ role: child.role, ...(child.exit || child.process.storageSnapshot()) }));
    // Recovery RPC success alone is not a closure proof; a typed readonly
    // observer must confirm the irreversible native scope and every writer.
    let closure = { status: 'unconfirmed' };
    if (session && remaining(end)) {
      try {
        const nonce = crypto.randomBytes(32).toString('hex');
        const observation = (await bounded(transport.rpc(input.config, { op: 'observe_scope', attempt_id: session.binding.attempt_id,
          descriptor_sha256: session.binding.descriptor_sha256, observation_nonce: nonce }, { limitMs: remaining(end) }), end)).reply;
        closure = require('./macos-command-scope').validateObservation(observation, session.scope, session.capability, nonce);
      } catch {}
    }
    const completed = closure.status === 'completed' && children.every(child => child.exit?.writer_exit_observed === true) && clock() < end;
    for (const child of children) if (!child.exit) {
      child.process.disconnect();for (const stream of child.process.stdio || []) stream?.destroy?.();child.process.unref();
    }
    throw Object.assign(firstError || error, { cleanup: { status: completed ? 'completed' : 'unconfirmed',
      method: 'macos_composite_owned_scope', native_closure: closure, children: exits },
      recovery_required: !completed, attempt_nonce: attemptNonce,
      ...(session ? { scope: session.scope, attempt_id: session.binding.attempt_id } : {}) });
  } finally {
    clearTimeout(timer);unsubscribeLifecycle?.();options.signal?.removeEventListener('abort', cancel);
  }
}
module.exports = { runOwnedOperation, PROTOCOL };
