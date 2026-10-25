'use strict';

// The public runner stays synchronous. This separate event loop owns the
// worker tree and its watchdog, including while the worker blocks in sync I/O.
const { spawn, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const finalization = require('./verification-finalization');
const { copyInertData } = require('./inert-data');
const { resolvePolicy, timerDelay } = require('./verification-policy');
const PROTOCOL = 'knowledge-verification-supervisor.v1';
const MAX_BYTES = 32 * 1024 * 1024;
const TEARDOWN_MS = 5000;
const clock = () => process.hrtime.bigint();
const remaining = deadline => Math.max(0, Number(deadline - clock()) / 1e6);
const authorityCleanupReserve = timeoutMs => Math.min(1000, Math.max(100, Math.ceil(timeoutMs / 5)));
const safeCode = (value, fallback) => /^[A-Za-z0-9_-]{1,80}$/.test(String(value || '')) ? value : fallback;

function verificationRequestData(value, checkBudget = null) {
  try { return copyInertData(value, checkBudget, MAX_BYTES); }
  catch (error) {
    if (error.code === 'verification_timeout') throw error;
    throw Object.assign(new Error('Verification request must be bounded inert data'), {
      code: 'verification_input_invalid'
    });
  }
}

function validateTiming(timeoutMs, started) {
  if (typeof timeoutMs !== 'number' || !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw Object.assign(new Error('Verification batch budget must be a positive safe integer number of milliseconds'), {
      code: 'verification_timeout_invalid'
    });
  }
  if (typeof started !== 'bigint' || started < 0n || started > clock()) {
    throw Object.assign(new Error('Verification start must be an observed monotonic bigint timestamp'), {
      code: 'verification_clock_invalid'
    });
  }
}

function containmentCapability(nativeExecution) {
  if (nativeExecution !== undefined) {
    const normalized = require('./verification-policy').nativeExecutionConfig(nativeExecution);
    if (normalized.darwin.enabled) return {
      platform: process.platform, backend: 'darwin_private_ruid',
      status: process.platform === 'darwin' ? 'requires_runtime_setup' : 'unavailable',
      reason: process.platform === 'darwin' ? 'protected_broker_current_epoch_and_private_uid_finality_required' : 'darwin_required'
    };
  }
  const windows = process.platform === 'win32';
  const linux = process.platform === 'linux';
  return {
    platform: process.platform,
    backend: windows ? 'windows_job_object' : linux ? 'linux_pid_namespace' : null,
    status: windows || linux ? 'requires_runtime_setup' : 'unavailable',
    reason: windows
      ? 'job_assignment_and_zero_active_processes_required'
      : linux ? 'private_pid_namespace_pidfd_and_compiled_helper_required'
      : 'kernel_tree_containment_backend_unavailable'
  };
}

function assertContainmentAvailable(nativeExecution) {
  const capability = containmentCapability(nativeExecution);
  if (capability.status === 'unavailable') {
    throw Object.assign(new Error(`Native verification cannot safely contain owned descendants on ${capability.platform}`), {
      code: 'verification_containment_unavailable',
      containment: capability,
      execution: { status: 'not_started' },
      teardown: { status: 'not_required', reason: 'no_worker_started' }
    });
  }
  return capability;
}

function containmentFailure(timeoutMs, started, deadline, nativeExecution) {
  let error;
  try { assertContainmentAvailable(nativeExecution); return null; }
  catch (failure) { error = failure; }
  // A process group does not contain descendants that create a new session.
  // Refuse before probes until this platform has a stronger ownership backend.
  return {
    protocol: PROTOCOL,
    status: 'failed',
    error: {
      code: error.code,
      message: error.message,
      containment: error.containment,
      execution: error.execution
    },
    completed_executions: [],
    teardown: { status: 'not_required', reason: 'no_worker_started' },
    budget: {
      timeout_ms: timeoutMs,
      clock: 'process.hrtime.bigint',
      stage: 'containment_setup',
      total_elapsed_ms: Number(clock() - started) / 1e6,
      deadline_exceeded: clock() >= deadline,
      interrupted_finalization_receipt: 'none'
    }
  };
}

function timeoutFailure(timeoutMs, started, stage = 'setup') {
  return Object.assign(new Error('Native verification total budget expired'), {
    code: 'verification_timeout', timed_out: true, stage,
    completed_executions: [], teardown: stage === 'setup'
      ? { status: 'not_required', reason: 'no_worker_started' } : { status: 'unconfirmed' },
    verification_budget: { timeout_ms: timeoutMs, clock: 'process.hrtime.bigint', stage,
      total_elapsed_ms: Number(clock() - started) / 1e6, deadline_exceeded: true,
      interrupted_finalization_receipt: stage === 'setup' ? 'none' : 'may_exist_unacknowledged',
      execution_observation: stage === 'setup' ? 'not_started' : 'not_received' }
  });
}

// Only inert admission and bounded transport run in the synchronous caller.
// All filesystem work, key generation and signing are behind an independent
// watchdog and its kernel Job. A killed watchdog closes the Job's control pipe.
function runSupervised(request, timeoutMs, started = clock()) {
  validateTiming(timeoutMs, started);
  let deadline = started + BigInt(timeoutMs) * 1000000n;
  request = verificationRequestData(request, () => {
    if (clock() >= deadline) throw timeoutFailure(timeoutMs, started);
  });
  const nativeExecution = require('./verification-policy').nativeExecutionRequest(request);
  if (nativeExecution !== undefined) {
    delete request.native_execution;
    request.nativeExecution = nativeExecution;
  }
  const policy = resolvePolicy(request.verificationPolicy, timeoutMs);
  timeoutMs = policy.work_budget_ms;
  deadline = started + BigInt(timeoutMs) * 1000000n;
  if (nativeExecution?.darwin.enabled && process.platform === 'darwin') {
    return require('./verification-darwin-production').runSync(request, timeoutMs, started);
  }
  const unavailable = containmentFailure(timeoutMs, started, deadline, nativeExecution);
  if (unavailable) throw Object.assign(new Error(unavailable.error.message), unavailable.error, {
    verification_budget: unavailable.budget, completed_executions: [], teardown: unavailable.teardown
  });
  const requestJson = JSON.stringify(request);
  if (Buffer.byteLength(requestJson) > MAX_BYTES - 8192) throw Object.assign(new Error('Verification request exceeds transport limit'), { code: 'verification_transport_oversized' });
  // A normal host prerequisite failure must not reserve an unrecoverable
  // project claim. Probe actual kernel support and prepare the pinned helper
  // before beginAttempt; the probe never admits a user command or writes KVE.
  if (process.platform === 'linux') {
    const capability = require('./verification-linux-namespace').containmentCapability();
    if (capability.status === 'unavailable') throw Object.assign(
      new Error('Linux native containment prerequisites are unavailable'), {
        code: 'verification_containment_unavailable', containment: capability,
        execution: { status: 'not_started' }, completed_executions: [],
        teardown: { status: 'not_required', reason: 'no_verification_worker_started' }
      });
  }
  const left = remaining(deadline);
  if (left <= 0) {
    const error = timeoutFailure(timeoutMs, started);
    error.teardown = { status: 'not_required', reason: 'no_worker_started' };
    throw error;
  }
  const control = require('./verification-control');
  const context = { stateRoot: request.stateRoot, projectKnowledgeRoot: request.stateRoot,
    targetRoot: request.repoRoot, systemRoot: path.resolve(__dirname, '../..') };
  const attempt = control.beginAttempt(context, { request_sha256: finalization.digest(request),
    profile: { work_budget_ms: timeoutMs, no_progress_ms: policy.no_progress_ms, cleanup_budget_ms: policy.cleanup_budget_ms } });
  const owner = attempt.owner;
  let spawnId;
  try {
    control.updateAttempt(context, owner, { type: 'phase', phase: 'preparing' });
    if (remaining(deadline) <= 0) {
      control.updateAttempt(context, owner, { type: 'stop', reason: 'work_timeout' });
      throw timeoutFailure(timeoutMs, started);
    }
    spawnId = control.updateAttempt(context, owner, { type: 'spawn_intent', role: 'watchdog' }).spawn_id;
  } catch (error) {
    let terminal;
    try { terminal = control.recoverAttempt(context, { attempt_id: owner.attempt_id, generation: owner.generation }); } catch {}
    if (terminal?.status === 'cancelled') error = Object.assign(new Error('Verification cancelled before process startup'), {
      code: 'verification_cancelled', teardown: { status: 'not_required', reason: 'no_processes_started' } });
    throw error;
  }
  const input = JSON.stringify({ protocol: PROTOCOL, timeout_ms: timeoutMs, policy,
    test_count: request.tests.length, request_sha256: finalization.digest(request),
    control: { context, owner, spawn_id: spawnId },
    started_ns: String(started), deadline_ns: String(deadline) }) + '\n' + requestJson;
  const transportLeft = remaining(deadline);
  if (transportLeft <= 0) {
    control.updateAttempt(context, owner, { type: 'spawn_aborted', spawn_id: spawnId, reason: 'before_spawn_syscall' });
    control.updateAttempt(context, owner, { type: 'stop', reason: 'work_timeout' });
    const terminal = control.recoverAttempt(context, { attempt_id: owner.attempt_id, generation: owner.generation });
    if (terminal.status === 'cancelled') throw Object.assign(new Error('Verification cancelled before process startup'), {
      code: 'verification_cancelled', teardown: { status: 'not_required', reason: 'no_processes_started' } });
    throw timeoutFailure(timeoutMs, started);
  }
  const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.NODE_PATH;
  const child = spawnSync(process.execPath, [path.join(__dirname, 'verification-watchdog.js')], {
    input, encoding: 'utf8', windowsHide: true, env, maxBuffer: MAX_BYTES,
    // A last-resort transport bound, not a millisecond return guarantee.
    // spawnSync accepts a wide integer; do not truncate a large work budget.
    timeout: Math.max(1, Math.ceil(transportLeft + policy.cleanup_budget_ms)), killSignal: 'SIGKILL'
  });
  const quarantine = error => {
    try {
      control.updateAttempt(context, owner, { type: 'stop', reason: error.timed_out ? 'work_timeout' : 'failure' });
      control.updateAttempt(context, owner, { type: 'cleanup_started' });
      control.updateAttempt(context, owner, { type: 'cleanup_unconfirmed' });
    } catch {}
    error.attempt_id = owner.attempt_id;
    error.teardown = { ...error.teardown, status: 'unconfirmed' };
    error.recovery_required = true;
    return error;
  };
  // libuv has waited for this exact child handle. The logical nonce cannot be
  // reused as cross-session PID-recovery evidence.
  try {
    let observed = control.readStatus(context).attempt.processes.find(p => p.spawn_id === spawnId);
    if (!observed.pid && child.pid) {
      control.updateAttempt(context, owner, { type: 'spawn_observed', spawn_id: spawnId,
        pid: child.pid, logical_nonce: owner.generation, executable_sha256: finalization.hash(fs.readFileSync(process.execPath)) });
      observed = control.readStatus(context).attempt.processes.find(p => p.spawn_id === spawnId);
    }
    if (child.pid && observed.pid === child.pid) control.updateAttempt(context, owner, {
      type: 'process_exit', spawn_id: spawnId, pid: child.pid, logical_nonce: owner.generation,
      os_creation_time: observed.os_creation_time,
      method: 'process_handle_signaled' });
  } catch (error) { throw quarantine(error); }
  let envelope;
  try { envelope = JSON.parse(child.stdout); } catch {}
  if (envelope?.authority_payload) envelope = { ...envelope.authority_payload,
    watchdog_budget: envelope.watchdog_budget, authority_teardown: envelope.authority_teardown };
  if (child.error || child.signal || child.status !== 0 || envelope?.protocol !== PROTOCOL ||
      !['completed', 'failed'].includes(envelope?.status)) {
    // An early cancellation can end the watchdog before any authority intent.
    // The parent's exact child-handle wait is sufficient only for that narrow
    // controller-only case; never use this fallback for an owned worker tree.
    let recovered;
    try { recovered = control.recoverAttempt(context, { attempt_id: owner.attempt_id, generation: owner.generation }); } catch {}
    if (recovered?.ack_released === false && ['failed', 'cancelled'].includes(recovered.status)) {
      throw Object.assign(new Error('Verification stopped before authority startup'), {
        code: recovered.status === 'cancelled' ? 'verification_cancelled' : 'verification_transport_failed',
        attempt_id: owner.attempt_id, teardown: { status: 'completed', method: 'controller_only' }
      });
    }
    throw quarantine(Object.assign(new Error('Native authority transport failed; cleanup is unconfirmed'), {
      code: 'verification_transport_failed', teardown_status: 'unconfirmed', teardown: { status: 'unconfirmed' }
    }));
  }
  const teardown = envelope.authority_teardown;
  if (teardown?.status !== 'completed' || teardown.active_processes !== 0 || !teardown.keeper_exited) {
    throw quarantine(Object.assign(new Error('Native authority cleanup is unconfirmed'), {
      code: 'verification_cleanup_unconfirmed', teardown, verification_budget: envelope.budget || envelope.error?.verification_budget }));
  }
  if (envelope.status === 'completed' && (!Array.isArray(envelope.result) || !envelope.result.length ||
      !Array.isArray(envelope.acceptances) || envelope.acceptances.length !== 1)) {
    throw quarantine(Object.assign(new Error('Incomplete native authority result'), { code: 'verification_transport_failed' }));
  }
  const terminalInput = { outcome: envelope.status === 'completed' ? 'passed' : envelope.error?.timed_out ? 'timed_out' : 'failed',
    cleanup_proof: control.bindCleanupProof(owner,teardown) };
  if (envelope.status === 'completed') terminalInput.ack_sha256 = finalization.digest(envelope.acceptances);
  if (envelope.status === 'completed') {
    terminalInput.deadline_ns = String(started + BigInt(Math.floor(envelope.budget.work_elapsed_ms * 1e6)) +
      BigInt(policy.cleanup_budget_ms) * 1000000n);
  }
  let terminal;
  try { terminal = control.commitFinish(context, owner, terminalInput); }
  catch (error) { throw quarantine(error); }
  if (terminal.status === 'cancelled') throw Object.assign(new Error('Native verification cancelled by the user'), {
    code: 'verification_cancelled', teardown, attempt_id: owner.attempt_id,
    verification_budget: envelope.watchdog_budget || envelope.error?.verification_budget || envelope.budget });
  if (envelope.status === 'completed' && !terminal.ack_released) throw Object.assign(new Error('Attempt was stopped before acceptance'), {
    code: terminal.status === 'timed_out' ? 'verification_timeout' : 'verification_stopped', teardown, attempt_id: owner.attempt_id });
  if (envelope.status === 'failed') {
    const error = Object.assign(new Error(envelope.error?.message || 'Native verification failed'), envelope.error || {});
    error.code = safeCode(error.code, 'verification_worker_failed');
    error.authority_teardown = envelope.authority_teardown;
    throw error;
  }
  if (!Array.isArray(envelope.result) || !Array.isArray(envelope.acceptances) || envelope.acceptances.length !== 1 ||
      envelope.authority_teardown?.status !== 'completed' || envelope.authority_teardown?.active_processes !== 0) {
    throw Object.assign(new Error('Native authority teardown is incomplete'), { code: 'verification_transport_failed' });
  }
  Object.defineProperty(envelope.result, 'verification_acceptances', { value: envelope.acceptances });
  Object.defineProperty(envelope.result, 'verification_budget', { value: { ...envelope.budget,
    total_elapsed_ms: Number(clock() - started) / 1e6, authority_teardown: envelope.authority_teardown,
    watchdog: envelope.watchdog_budget, attempt_id: owner.attempt_id } });
  return envelope.result;
}

// Called only in the idle authority after the watchdog's Job assignment. The
// key stays here; neither the ordinary worker nor the watchdog receives it.
function runAuthority(request, timeoutMs, started = clock(), channels = {}) {
  validateTiming(timeoutMs, started);
  request = verificationRequestData(request);
  const deadline = started + BigInt(timeoutMs) * 1000000n;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const policy = resolvePolicy(request.verificationPolicy, timeoutMs);
  const input = JSON.stringify({ protocol: PROTOCOL, public_key: publicKeyDer, request,
    started_ns: String(started), deadline_ns: String(deadline), timeout_ms: timeoutMs,
    policy, progress_channel: channels.progress_channel });
  if (Buffer.byteLength(input) > MAX_BYTES) throw Object.assign(new Error('Verification request exceeds the supervisor transport limit'), { code: 'verification_transport_oversized' });
  const unavailable = containmentFailure(timeoutMs, started, deadline);
  if (unavailable) {
    throw Object.assign(new Error(unavailable.error.message), unavailable.error, {
      verification_budget: unavailable.budget,
      completed_executions: unavailable.completed_executions,
      teardown: unavailable.teardown
    });
  }
  const env = { ...process.env }; delete env.NODE_OPTIONS; delete env.NODE_PATH;
  const left = remaining(deadline);
  if (left <= 0) throw timeoutFailure(timeoutMs, started);
  const child = spawnSync(process.execPath, [__filename, '--supervisor'], {
    input, encoding: 'utf8', windowsHide: true, env, maxBuffer: MAX_BYTES,
    // Last-resort transport bound; the responsive supervisor owns normal
    // timeout and teardown. A transport failure is never a verification PASS.
    timeout: Math.max(1, Math.ceil(left + policy.cleanup_budget_ms)), killSignal: 'SIGKILL'
  });
  let envelope;
  try { envelope = JSON.parse(child.stdout); } catch {}
  if (child.error || child.signal || child.status !== 0 || envelope?.protocol !== PROTOCOL ||
      !['completed', 'failed'].includes(envelope?.status)) {
    throw Object.assign(new Error('Native verification supervisor transport failed; tree cleanup is unconfirmed'), {
      code: 'verification_transport_failed', transport_code: safeCode(child.error?.code, 'invalid_response'),
      teardown_status: 'unconfirmed'
    });
  }
  if (envelope.status === 'failed') {
    const error = Object.assign(new Error(envelope.error?.message || 'Native verification failed'), envelope.error || {});
    error.code = safeCode(error.code, 'verification_worker_failed');
    error.verification_budget = envelope.budget;
    error.completed_executions = envelope.completed_executions || [];
    error.teardown = envelope.teardown;
    throw error;
  }
  if (!Array.isArray(envelope.result) || envelope.teardown?.status !== 'completed') {
    throw Object.assign(new Error('Native verification result or teardown is incomplete'), { code: 'verification_transport_failed' });
  }
  const cleanupDeadline = started + BigInt(Math.floor(envelope.budget.work_elapsed_ms * 1e6)) +
    BigInt(policy.cleanup_budget_ms) * 1000000n;
  if (clock() >= cleanupDeadline) {
    throw Object.assign(new Error('Native verification total budget expired before the result was returned'), {
      code: 'verification_cleanup_unconfirmed', stage: 'response',
      verification_budget: { ...envelope.budget, total_elapsed_ms: Number(clock() - started) / 1e6, deadline_exceeded: true },
      completed_executions: envelope.completed_executions || [], teardown: envelope.teardown
    });
  }
  // This candidate remains in a private channel until the outer watchdog has
  // closed the authority Job. A persisted receipt alone has no authority.
  const acceptance = finalization.acceptFinalization(envelope.finalization, timeoutMs, Number(clock() - started) / 1e6, privateKey,
    { work_elapsed_ms: envelope.budget.work_elapsed_ms, cleanup_budget_ms: policy.cleanup_budget_ms });
  if (clock() >= cleanupDeadline) throw Object.assign(new Error('Acceptance exceeded cleanup budget'), {
    code: 'verification_cleanup_unconfirmed', stage: 'acceptance', teardown: envelope.teardown });
  Object.defineProperty(envelope.result, 'verification_acceptances', { value: [acceptance] });
  Object.defineProperty(envelope.result, 'verification_budget', { value: { ...envelope.budget, teardown: envelope.teardown } });
  return envelope.result;
}

async function supervise(payload, workerFile = path.join(__dirname, 'verification-worker.js')) {
  payload = verificationRequestData(payload);
  const clockString = value => typeof value === 'string' && value.length <= 32 && /^\d+$/.test(value);
  if (payload?.protocol !== PROTOCOL || !clockString(payload.deadline_ns) || !clockString(payload.started_ns)) {
    throw Object.assign(new Error('Invalid supervisor request'), { code: 'verification_protocol_invalid' });
  }
  const deadline = BigInt(payload.deadline_ns), started = BigInt(payload.started_ns);
  validateTiming(payload.timeout_ms, started);
  if (deadline !== started + BigInt(payload.timeout_ms) * 1000000n) {
    throw Object.assign(new Error('Verification deadline must match the declared monotonic budget'), {
      code: 'verification_clock_invalid'
    });
  }
  if (typeof workerFile !== 'string' || workerFile.includes('\0')) {
    throw Object.assign(new Error('Verification worker path must be a string'), { code: 'verification_worker_invalid' });
  }
  const unavailable = containmentFailure(payload.timeout_ms, started, deadline);
  if (unavailable) return unavailable;
  const policy = resolvePolicy(payload.request.verificationPolicy, payload.timeout_ms);
  const workDeadline = deadline;
  const reporter = await require('./verification-progress').connect(payload.progress_channel, deadline,
    payload.progress_channel !== undefined);
  const committed = [];
  const batchId = 'KVB-' + crypto.randomBytes(16).toString('hex');
  let worker, nativeContainer, exited = false, settled = false, timer, stage = 'setup', phaseDeadline = workDeadline;
  return new Promise(resolve => {
    const finish = async (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      const teardownStarted = clock();
      const workElapsed = Number(teardownStarted - started) / 1e6;
      const cleanupDeadline = teardownStarted + BigInt(policy.cleanup_budget_ms) * 1000000n;
      // Check the complete worker batch before declaring work complete. A
      // partial commit or a late result can never enter successful cleanup.
      if (!error && clock() >= workDeadline) error = { code: 'verification_timeout', timed_out: true, stage };
      if (!error && (!Array.isArray(result) || !result.length || result.length !== committed.length ||
          result.length !== payload.request.tests.length || result.some((item, index) =>
            item.record?.batch_id !== batchId || item.record?.batch_ordinal !== index ||
            item.record?.execution_id !== committed[index].execution_id ||
            item.record?.content_sha256 !== committed[index].execution_sha256 ||
            JSON.stringify(item.record?.command_argv) !== JSON.stringify(payload.request.tests[index].argv.map(String))))) {
        error = { code: 'verification_batch_incomplete', message: 'Incomplete command batch' };
      }
      try {
        reporter.send({ type: error ? 'stopping' : 'work_completed', at_ns: String(teardownStarted),
          count: committed.length, reason: error?.timed_out ? 'work_timeout' : 'failure' });
      } catch { error ||= { code: 'verification_progress_transport_failed', message: 'Private progress channel failed' }; }
      const allowance = remaining(cleanupDeadline);
      let teardown = { status: 'not_started', allowance_ms: allowance };
      if (!worker?.pid) teardown.status = 'completed';
      else if (nativeContainer) {
        teardown = { ...teardown, ...(await nativeContainer.close(allowance)) };
      } else if (exited || worker.exitCode !== null || worker.signalCode !== null) {
        teardown = { ...teardown, status: 'unconfirmed', code: 'worker_exited_before_tree_sweep' };
      } else {
        teardown = { ...teardown, ...(await stopOwnedTree(worker, () => exited, allowance)) };
      }
      // Even when tree teardown cannot be proved, close our own live worker
      // handle so an idle IPC child cannot hide the primary result indefinitely.
      if (worker && teardown.status !== 'completed') {
        if (!exited && worker.exitCode === null && worker.signalCode === null) worker.kill('SIGKILL');
        if (worker.connected) worker.disconnect();
        worker.unref();
      }
      teardown.duration_ms = Number(clock() - teardownStarted) / 1e6;
      if (!error && clock() >= cleanupDeadline) error = { code: 'verification_cleanup_unconfirmed', message: 'Native verification cleanup budget expired', stage: 'teardown' };
      if (!error && teardown.status !== 'completed') error = { code: 'verification_cleanup_unconfirmed', message: 'Verification tree teardown could not be confirmed' };
      let finalized;
      if (!error) {
        try {
          stage = 'batch_receipt';
          // Receipt readback remains inside the shared cleanup budget. A late
          // write can leave an unaccepted receipt, never a terminal ACK.
          const persist = async () => {
            const implementation = await Promise.all(finalization.IMPLEMENTATION_PATHS.map(async name =>
              ({ path: name, sha256: finalization.hash(await fs.promises.readFile(path.join(__dirname, '../..', name))) })));
            const runtime = finalization.hash(await fs.promises.readFile(process.execPath));
            const executions = await Promise.all(result.map(async item => ({ execution_id: item.record.execution_id,
              physical_sha256: finalization.hash(await fs.promises.readFile(item.path)) })));
            if (clock() >= cleanupDeadline) throw Object.assign(new Error('Batch receipt cleanup budget expired'), { code: 'verification_cleanup_unconfirmed' });
            return finalization.persistFinalization(payload.request.stateRoot, {
              schema_version: finalization.SCHEMA, batch_id: batchId,
              public_key: payload.public_key, request_sha256: finalization.digest(payload.request),
              task_id: String(payload.request.taskId), session_id: String(payload.request.sessionId),
              status: 'commands_and_teardown_observed', backend: teardown.method, teardown,
              timeout_ms: payload.timeout_ms, observed_elapsed_ms: Number(clock() - started) / 1e6,
              work_elapsed_ms: workElapsed, cleanup_budget_ms: policy.cleanup_budget_ms,
              runtime_sha256: runtime, implementation, executions
            });
          };
          let finalTimer;
          try {
            finalized = await Promise.race([persist(), new Promise((_, reject) => {
              finalTimer = setTimeout(() => reject(Object.assign(new Error('Batch receipt cleanup budget expired'), { code: 'verification_cleanup_unconfirmed' })), timerDelay(remaining(cleanupDeadline)));
            })]);
          } finally { clearTimeout(finalTimer); }
          if (clock() >= cleanupDeadline) throw Object.assign(new Error('Batch finalization exceeded cleanup budget'), { code: 'verification_cleanup_unconfirmed' });
        } catch (failure) { error = { code: safeCode(failure.code, 'verification_finalization_failed'), message: 'Batch finalization was not accepted', stage, ...(failure.code === 'verification_timeout' ? { timed_out: true } : {}) }; }
      }
      resolve({ protocol: PROTOCOL, status: error ? 'failed' : 'completed', ...(error ? { error } : { result }),
        completed_executions: committed, teardown, ...(finalized ? { finalization: finalized } : {}),
        budget: { timeout_ms: payload.timeout_ms, clock: 'process.hrtime.bigint', stage,
          work_budget_ms: payload.timeout_ms, cleanup_budget_ms: policy.cleanup_budget_ms,
          no_progress_ms: policy.no_progress_ms, profile: policy.profile,
          work_elapsed_ms: workElapsed, total_elapsed_ms: Number(clock() - started) / 1e6,
          cleanup_elapsed_ms: Number(clock() - teardownStarted) / 1e6,
          deadline_exceeded: workElapsed >= payload.timeout_ms, interrupted_finalization_receipt: error ? 'may_exist_unacknowledged' : 'none' } });
    };
    const timeout = () => finish({ code: 'verification_timeout', message: `Native verification budget expired during ${stage}`, timed_out: true, stage });
    const arm = () => {
      clearTimeout(timer);
      if (remaining(phaseDeadline) <= 0) { timeout(); return false; }
      timer = setTimeout(() => { if (remaining(phaseDeadline) <= 0) timeout(); else arm(); }, Math.min(2147483647, Math.max(1, Math.ceil(remaining(phaseDeadline)))));
      return true;
    };
    if (!arm()) return;
    try {
      if (process.platform === 'linux') {
        const contained = require('./verification-linux-namespace').spawnLinuxContainedWorker(
          process.execPath, [workerFile], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }, {
            lifetimeMs: remaining(deadline) + policy.cleanup_budget_ms,
            onFailure: error => finish({ code: safeCode(error?.code, 'verification_namespace_failed'), message: 'Linux verification containment failed' })
          });
        worker = contained.worker; nativeContainer = contained.job;
      } else worker = spawn(process.execPath, [workerFile], {
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true });
    } catch (error) {
      finish({ code: safeCode(error.code, 'verification_worker_spawn_failed'), message: error.message }); return;
    }
    worker.on('error', error => finish({ code: safeCode(error.code, 'verification_worker_spawn_failed'), message: 'Native verification worker failed to start' }));
    worker.on('disconnect', () => {
      if (!settled) finish({ code: 'verification_worker_transport_closed', message: 'Worker IPC closed before completing the protocol' });
    });
    worker.on('exit', () => { exited = true; if (!settled) finish({ code: 'verification_worker_exited', message: 'Native verification worker exited without completing the protocol' }); });
    worker.on('message', message => {
      if (settled) return;
      if (remaining(phaseDeadline) <= 0) { timeout(); return; }
      if (message?.protocol !== PROTOCOL) { finish({ code: 'verification_protocol_invalid', message: 'Invalid worker protocol' }); return; }
      if (message.type === 'phase' && /^\d+$/.test(message.deadline_ns || '') && Number.isInteger(message.id)) {
        stage = String(message.stage).replace(/[^a-z0-9_-]/gi, '').slice(0, 64) || 'verification';
        phaseDeadline = BigInt(message.deadline_ns) < workDeadline ? BigInt(message.deadline_ns) : workDeadline;
        try { reporter.send({ type: 'phase', ordinal: committed.length, phase: stage }); }
        catch { finish({ code: 'verification_progress_transport_failed', message: 'Progress reporting failed' }); return; }
        if (arm()) worker.send({ protocol: PROTOCOL, type: 'ack', id: message.id });
      } else if (message.type === 'committed' && /^KVE-[a-f0-9]{64}$/.test(message.value?.execution_id || '')) {
        if (committed.some(item => item.execution_id === message.value.execution_id) || committed.length >= payload.request.tests.length) {
          finish({ code: 'verification_protocol_invalid', message: 'Duplicate or excess command receipt' }); return;
        }
        try { reporter.send({ type: 'committed', ordinal: committed.length, execution_id: message.value.execution_id }); }
        catch { finish({ code: 'verification_progress_transport_failed', message: 'Progress reporting failed' }); return; }
        committed.push(message.value);
      } else if (message.type === 'result' && Array.isArray(message.result)) {
        finish(null, message.result);
      } else if (message.type === 'error' && message.error && typeof message.error.message === 'string') {
        finish(message.error);
      } else finish({ code: 'verification_protocol_invalid', message: 'Unexpected worker message' });
    });
    worker.once('spawn', async () => {
      try {
        if (process.platform === 'win32' && !settled) {
          nativeContainer = require('./verification-windows-job').createWindowsJob(worker,
            () => finish({ code: 'verification_job_failed', message: 'Windows verification job failed' }),
            remaining(deadline) + policy.cleanup_budget_ms);
        }
        if (nativeContainer) await nativeContainer.ready;
        if (nativeContainer?.permit && !settled) {
          nativeContainer.permit();
          await nativeContainer.started;
        }
        if (!settled && remaining(workDeadline) > 0) worker.send({ protocol: PROTOCOL, type: 'run', request: payload.request, batch_id: batchId, public_key: payload.public_key, request_sha256: finalization.digest(payload.request), deadline_ns: String(workDeadline) });
        else if (!settled) timeout();
      } catch (error) { finish({ code: safeCode(error.code, 'verification_job_failed'), message: error.message }); }
    });
  });
}

function stopOwnedTree(worker, hasExited, allowance = TEARDOWN_MS) {
  return new Promise(resolve => {
    const start = clock(); let done = false, killer;
    const finish = result => { if (done) return; done = true; clearTimeout(limit); resolve(result); };
    const limit = setTimeout(() => {
      if (killer && killer.exitCode === null && killer.signalCode === null) killer.kill('SIGKILL');
      if (!hasExited()) worker.kill('SIGKILL');
      finish({ status: 'unconfirmed', code: 'tree_teardown_timeout' });
    }, Math.max(1, allowance));
    if (hasExited() || worker.exitCode !== null || worker.signalCode !== null) { finish({ status: 'unconfirmed', code: 'worker_identity_lost' }); return; }
    if (process.platform === 'win32') {
      const systemRoot = process.env.SystemRoot || process.env.WINDIR;
      if (!systemRoot || !path.isAbsolute(systemRoot)) { finish({ status: 'unconfirmed', code: 'taskkill_unavailable' }); return; }
      killer = spawn(path.join(systemRoot, 'System32', 'taskkill.exe'), ['/PID', String(worker.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
      killer.on('error', () => finish({ status: 'unconfirmed', code: 'taskkill_spawn_failed' }));
      killer.on('exit', code => {
        if (code !== 0) finish({ status: 'unconfirmed', code: 'taskkill_failed' });
        else if (hasExited()) finish({ status: 'completed', method: 'owned_worker_taskkill_tree' });
        else worker.once('exit', () => finish({ status: 'completed', method: 'owned_worker_taskkill_tree' }));
      });
    } else {
      try {
        process.kill(-worker.pid, 'SIGKILL');
        if (hasExited()) finish({ status: 'completed', method: 'owned_worker_process_group' });
        else worker.once('exit', () => finish({ status: 'completed', method: 'owned_worker_process_group' }));
      } catch { finish({ status: 'unconfirmed', code: 'process_group_kill_failed' }); }
    }
  });
}

function runStdioSupervisor() {
  let input = '', oversized = false;
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => { input += chunk; if (Buffer.byteLength(input) > MAX_BYTES) { oversized = true; input = ''; process.stdin.destroy(); } });
  process.stdin.on('end', async () => {
    try {
      if (oversized) throw new Error('Oversized supervisor input');
      const value = await supervise(JSON.parse(input));
      const output = JSON.stringify(value);
      if (Buffer.byteLength(output) > MAX_BYTES) throw new Error('Oversized supervisor output');
      // supervise has already closed the owned Job or reported an unconfirmed
      // teardown. A losing receipt-I/O promise must not keep this controller
      // alive and replace its typed timeout with a transport timeout. Flush
      // the complete response before exiting; no acceptance is issued here.
      process.stdout.write(output, () => process.exit(0));
    } catch { process.stderr.write('Verification supervisor protocol failed\n'); process.exitCode = 1; }
  });
}
if (require.main === module) runStdioSupervisor();
module.exports = { runSupervised, containmentCapability, assertContainmentAvailable, verificationRequestData,
  __test: { supervise, runStdioSupervisor, runAuthority, authorityCleanupReserve, PROTOCOL, TEARDOWN_MS } };
