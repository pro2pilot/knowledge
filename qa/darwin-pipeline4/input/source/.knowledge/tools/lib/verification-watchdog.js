'use strict';

// Responsive authority watchdog. Work starts only after the native container
// and its recovery descriptor are durably bound to this exact attempt.
// ACK candidates stay private until zero active processes AND keeper exit.
const { spawn } = require('child_process');
const path = require('path');
const PROTOCOL = 'knowledge-verification-supervisor.v1';
const MAX_BYTES = 32 * 1024 * 1024;
const clock = () => process.hrtime.bigint();
const remaining = deadline => Math.max(0, Number(deadline - clock()) / 1e6);

function errorData(error) {
  const value = { message: String(error.message || 'Native verification failed') };
  for (const key of ['code', 'timed_out', 'stage', 'verification_budget', 'completed_executions', 'teardown', 'teardown_status', 'containment', 'execution']) {
    if (error[key] !== undefined) value[key] = error[key];
  }
  return value;
}

function runAuthority() {
  let admitted = false, control, ended = false, size = 0;
  const chunks = [];
  const execute = () => {
    if (admitted || !control || !ended) return;
    admitted = true;
    let envelope;
    try {
      if (size > MAX_BYTES) throw new Error('Oversized authority input');
      const result = require('./verification-supervisor').__test.runAuthority(
        JSON.parse(Buffer.concat(chunks, size).toString('utf8')), control.timeout_ms, BigInt(control.started_ns),
        { progress_channel: control.progress_channel });
      envelope = { protocol: PROTOCOL, status: 'completed', result,
        acceptances: result.verification_acceptances, budget: result.verification_budget };
    } catch (error) { envelope = { protocol: PROTOCOL, status: 'failed', error: errorData(error) }; }
    // No inherited stdout/stderr pipe can keep the public spawnSync waiting.
    // Remain alive and idle until the watchdog proves the outer Job is empty.
    const output = JSON.stringify(envelope);
    const bytes = Buffer.byteLength(output);
    if (bytes > MAX_BYTES) { process.disconnect(); return; }
    process.stdout.write(output, () => process.send({ protocol: PROTOCOL, type: 'candidate', bytes, status: envelope.status }));
  };
  process.stdin.on('data', chunk => { size += chunk.length; if (size <= MAX_BYTES) chunks.push(chunk); });
  process.stdin.on('end', () => { ended = true; execute(); });
  process.on('message', message => {
    if (control || message?.protocol !== PROTOCOL || message.type !== 'run') return;
    control = message.payload;
    execute();
  });
  process.on('disconnect', () => process.exit(1));
}

async function watch(payload) {
  const boundary = require('./verification-supervisor');
  const { resolvePolicy, createProgress, timerDelay } = require('./verification-policy');
  const control = require('./verification-control');
  const finalization = require('./verification-finalization');
  const fs = require('fs');
  boundary.assertContainmentAvailable();
  if (payload?.protocol !== PROTOCOL || !/^\d{1,32}$/.test(payload.started_ns || '') ||
      !/^\d{1,32}$/.test(payload.deadline_ns || '') || !Number.isSafeInteger(payload.timeout_ms) || payload.timeout_ms <= 0) {
    throw new Error('Invalid authority watchdog payload');
  }
  const started = BigInt(payload.started_ns), deadline = BigInt(payload.deadline_ns);
  if (started > clock() || deadline !== started + BigInt(payload.timeout_ms) * 1000000n) throw new Error('Invalid authority deadline');
  const policy = resolvePolicy({
    profile: payload.policy?.profile, work_budget_ms: payload.timeout_ms,
    no_progress_ms: payload.policy?.no_progress_ms, cleanup_budget_ms: payload.policy?.cleanup_budget_ms
  });
  const { context, owner, spawn_id: ownSpawnId } = payload.control;
  const update = event => control.updateAttempt(context, owner, event);
  const nodeHash = finalization.hash(fs.readFileSync(process.execPath));
  const progress = createProgress(policy, started);
  const expectedCount = payload.test_count;
  if (!Number.isSafeInteger(expectedCount) || expectedCount < 1) throw new Error('Invalid expected command count');
  let progressOrdinal = 0;
  const checkpoint = (milestone, evidence) => update({ type: 'progress', milestone,
    ordinal: ++progressOrdinal, evidence_sha256: finalization.digest(evidence) });
  checkpoint('admission_complete', { request: payload.request_sha256 });
  let worker, job, timer, settled = false, finishing = false, candidateBytes, candidateStatus, received = 0;
  let cleanupStarted = null, cleanupDeadline = null, stopReason = null, workCompleted = false;
  let authoritySpawnId, keeperSpawnId, keeperPid, pendingFailure;
  const candidateChunks = [], committed = [];
  const budget = () => ({
    timeout_ms: policy.work_budget_ms, work_budget_ms: policy.work_budget_ms,
    cleanup_budget_ms: policy.cleanup_budget_ms, no_progress_ms: policy.no_progress_ms,
    profile: policy.profile, clock: 'process.hrtime.bigint',
    work_elapsed_ms: Number((cleanupStarted || clock()) - started) / 1e6,
    cleanup_elapsed_ms: cleanupStarted ? Number(clock() - cleanupStarted) / 1e6 : 0,
    total_elapsed_ms: Number(clock() - started) / 1e6,
    stop_reason: stopReason, ...progress.snapshot(clock()),
    progress_signal_available: cleanupStarted === null && progress.snapshot(clock()).progress_signal_available
  });
  const failed = (code, message, timedOut = false) => ({ protocol: PROTOCOL, status: 'failed',
    error: { code, message, stage: progress.snapshot(clock()).phase, ...(timedOut ? { timed_out: true } : {}),
      completed_executions: committed.slice(), verification_budget: budget() } });
  const observe = () => {
    const now = clock(), snapshot = progress.snapshot(now);
    update({ type: 'observation', stage: cleanupStarted !== null ? 'cleanup' :
      snapshot.phase === 'preparation' ? 'setup' : snapshot.phase,
      elapsed_ms: Number(now - started) / 1e6,
      last_meaningful_progress_elapsed_ms: snapshot.last_meaningful_progress_elapsed_ms,
      progress_signal_available: cleanupStarted === null && snapshot.progress_signal_available,
      wait_reason: stopReason === 'cancelled' ? 'cancel' :
        ['work_timeout', 'progress_timeout'].includes(stopReason) ? stopReason : cleanupStarted !== null ? 'cleanup' : 'work' });
  };
  let finish, tryCandidate = () => {};
  const beginCleanup = (at, reason) => {
    if (reason && !stopReason) {
      stopReason = reason;
      if (reason !== 'cancelled') update({ type: 'stop', reason });
    }
    if (cleanupStarted === null) {
      cleanupStarted = at;
      cleanupDeadline = at + BigInt(policy.cleanup_budget_ms) * 1000000n;
      update({ type: 'cleanup_started' });
      observe();
    }
  };
  const channel = await require('./verification-progress').listen(event => {
    if (settled || finishing) return;
    try {
      if (event.type === 'work_completed' || event.type === 'stopping') {
        if (cleanupStarted !== null || !/^\d{1,32}$/.test(event.at_ns || '')) throw new Error('Duplicate stop transition');
        const at = BigInt(event.at_ns);
        if (at < started || at > clock()) throw new Error('Invalid stop timestamp');
        if (event.type === 'work_completed') {
          if (stopReason || at >= deadline || clock() >= deadline ||
              event.count !== expectedCount || committed.length !== expectedCount) {
            beginCleanup(clock(), 'work_timeout');
            finish(failed('verification_timeout', 'Work budget expired before complete batch observation', true));
            return;
          }
          workCompleted = true;
          beginCleanup(at, null);
          tryCandidate();
        } else beginCleanup(at, event.reason === 'work_timeout' ? 'work_timeout' : 'failure');
        return;
      }
      if (cleanupStarted !== null) throw new Error('Progress after work completion');
      if (event.type === 'phase' && ['batch_finalization', 'between_tests'].includes(event.phase)) return;
      if (!progress.advance(event, clock())) throw new Error('Invalid or repeated semantic progress');
      if (event.type === 'committed') {
        if (committed.length >= expectedCount) throw new Error('Excess command receipt');
        committed.push({ execution_id: event.execution_id });
        // Individual KVE files retain every command. Keep this small control
        // journal bounded even for a 100000-command batch; live observation
        // below still advances at every verified command/phase transition.
        if (committed.length === 1 || committed.length === expectedCount) {
          checkpoint('command_verified', { execution_id: event.execution_id });
        }
      }
      observe();
    } catch {
      pendingFailure = 'verification_progress_invalid';
      if (finish) finish(failed(pendingFailure, 'Trusted progress protocol failed'));
    }
  }, code => {
    // The inner supervisor normally exits before the authority signs. This is
    // expected only after its complete-batch/stop transition was observed.
    if (code === 'verification_progress_transport_closed' && cleanupStarted !== null) return;
    pendingFailure = code;
    if (finish && !finishing && !settled) finish(failed(code, 'Trusted progress channel failed'));
  });
  return new Promise(resolve => {
    finish = async envelope => {
      if (settled || finishing) return;
      finishing = true; clearTimeout(timer);
      let teardown = { status: 'unconfirmed', code: 'authority_assignment_incomplete' };
      try {
        if (cleanupStarted === null) beginCleanup(clock(), envelope.authority_payload ? 'failure' : stopReason || 'failure');
        if (job) teardown = await job.close(remaining(cleanupDeadline));
        if (clock() >= cleanupDeadline) {
          envelope = failed('verification_cleanup_unconfirmed', 'Cleanup budget expired; recovery is required');
          // A late exit can improve safety, but cannot certify this attempt.
          teardown = { ...teardown, status: 'unconfirmed', code: 'cleanup_budget_exceeded' };
        }
        if (teardown.status === 'completed') {
          for (const [spawnId, pid] of [[authoritySpawnId, job.identities.worker.pid], [keeperSpawnId, keeperPid]]) {
            update({ type: 'process_exit', spawn_id: spawnId, pid,
              os_creation_time: (spawnId === authoritySpawnId ? job.identities.worker : job.identities.keeper).os_creation_time,
              method: 'process_handle_signaled' });
          }
          // Persist the kernel proof before the last caller/commit boundary.
          // A later recovery can use it even after the native handle is gone.
          update({ type: 'cleanup_proven', proof: teardown });
        } else update({ type: 'cleanup_unconfirmed' });
      } catch {
        teardown = { ...teardown, status: 'unconfirmed', code: 'authority_cleanup_failed' };
        try { update({ type: 'cleanup_unconfirmed' }); } catch {}
      }
      if (worker?.pid && teardown.status !== 'completed') {
        try { if (worker.exitCode === null && worker.signalCode === null) worker.kill('SIGKILL'); } catch {}
        try { if (worker.connected) worker.disconnect(); } catch {}
        worker.unref();
      }
      if (envelope.authority_status === 'completed' && (!workCompleted || stopReason || teardown.status !== 'completed')) {
        envelope = failed(stopReason === 'work_timeout' ? 'verification_timeout' : 'verification_cleanup_unconfirmed',
          'Complete work and confirmed cleanup are required', stopReason === 'work_timeout');
      }
      settled = true;
      channel.close();
      if (envelope.error) envelope.error = { ...envelope.error, teardown,
        verification_budget: budget() };
      resolve({ ...envelope, authority_teardown: teardown, watchdog_budget: budget() });
    };
    const tick = () => {
      if (settled || finishing) return;
      try {
        const state = control.readStatus(context).attempt;
        if (state?.attempt_id !== owner.attempt_id || state.generation !== owner.generation) throw new Error('Attempt identity changed');
        if (state.recovery !== null && state.recovery !== undefined) {
          finish(failed('verification_recovery_in_progress', 'Native recovery has fenced this owner')); return;
        }
        if (state.cancel.requested) {
          beginCleanup(clock(), 'cancelled');
          finish(failed('verification_cancelled', 'Verification cancelled by the user')); return;
        }
        if (cleanupStarted !== null) {
          if (clock() >= cleanupDeadline) {
            finish(failed('verification_cleanup_unconfirmed', 'Cleanup or result finalization exceeded its budget')); return;
          }
        } else if (clock() >= deadline) {
          beginCleanup(clock(), 'work_timeout');
          finish(failed('verification_timeout', 'Verification work budget exceeded', true)); return;
        } else if (progress.isStalled(clock())) {
          beginCleanup(clock(), 'progress_timeout');
          finish(failed('verification_progress_timeout', 'No new trusted stage checkpoint within the configured interval', true)); return;
        }
        timer = setTimeout(tick, timerDelay(Math.min(policy.control_poll_ms,
          remaining(cleanupDeadline || deadline))));
      } catch { finish(failed('verification_control_failed', 'Attempt status could not be read safely')); }
    };
    if (pendingFailure) { finish(failed(pendingFailure, 'Progress channel failed')); return; }
    tick();
    if (finishing) return;
    const failure = code => finish(failed(code, 'Native authority failed before terminal acceptance'));
    try {
      authoritySpawnId = update({ type: 'spawn_intent', role: 'authority' }).spawn_id;
      keeperSpawnId = update({ type: 'spawn_intent', role: 'keeper' }).spawn_id;
      if (process.platform === 'linux') {
        const contained = require('./verification-linux-namespace').spawnLinuxContainedWorker(
          process.execPath, [__filename, '--authority'], { stdio: ['pipe', 'pipe', 'ignore', 'ipc'] }, {
            lifetimeMs: remaining(deadline) + policy.cleanup_budget_ms,
            trustedAuthority: true,
            onFailure: error => failure(/^[a-z0-9_]{1,128}$/.test(error?.code || '') ? error.code : 'verification_authority_namespace_failed')
          });
        worker = contained.worker; job = contained.job; keeperPid = job.keeper_pid;
      } else worker = spawn(process.execPath, [__filename, '--authority'], {
        stdio: ['pipe', 'pipe', 'ignore', 'ipc'], windowsHide: true
      });
    } catch { finish(failed('verification_authority_spawn_failed', 'Authority did not start')); return; }
    worker.on('error', () => failure('verification_authority_spawn_failed'));
    worker.stdin.on('error', () => failure('verification_authority_transport_failed'));
    const candidateReady = tryCandidate = () => {
      if (candidateBytes === undefined || received !== candidateBytes || settled || finishing) return;
      // Candidate stdout/IPC and trusted progress use independent transports.
      // A complete candidate can arrive before the final progress frame. Keep
      // it private and let the existing work/cancel/cleanup timers govern the
      // wait; arrival order is neither a failed command nor proof of success.
      if (candidateStatus === 'completed' && !workCompleted) return;
      // Only the small IPC discriminator is decoded here. Large candidate
      // bytes are parsed in the facade after the authority Job is empty.
      finish({ authority_status: candidateStatus,
        authority_payload: Buffer.concat(candidateChunks, received).toString('utf8') });
    };
    worker.stdout.on('data', chunk => {
      received += chunk.length;
      if (received > MAX_BYTES || candidateBytes !== undefined && received > candidateBytes) {
        failure('verification_transport_oversized'); return;
      }
      candidateChunks.push(chunk); candidateReady();
    });
    worker.on('exit', () => { if (!settled && !finishing) failure('verification_authority_exited'); });
    worker.on('message', message => {
      if (settled || finishing) return;
      if (message?.protocol !== PROTOCOL || message.type !== 'candidate' ||
          candidateBytes !== undefined || !['completed', 'failed'].includes(message.status) ||
          !Number.isSafeInteger(message.bytes) || message.bytes < 1 || message.bytes > MAX_BYTES) {
        failure('verification_protocol_invalid'); return;
      }
      candidateBytes = message.bytes;
      candidateStatus = message.status;
      if (received > candidateBytes) failure('verification_protocol_invalid');
      else candidateReady();
    });
    worker.once('spawn', async () => {
      try {
        if (settled || finishing) return;
        if (process.platform === 'win32') {
          job = require('./verification-windows-job').createWindowsJob(worker,
            () => failure('verification_authority_job_failed'), remaining(deadline) + policy.cleanup_budget_ms);
          keeperPid = job.keeper_pid;
        }
        await job.ready;
        const identities = job.identities;
        const keeperHash = process.platform === 'linux' ? job.keeper_executable_sha256 :
          finalization.hash(fs.readFileSync(path.join(process.env.SystemRoot || process.env.WINDIR,
            'System32/WindowsPowerShell/v1.0/powershell.exe')));
        // The Linux worker is an inert pre-exec stub at this observation.
        // Record its actual helper image; the later KVE pins the Node image.
        for (const [spawnId, key, pid, executable] of [
          [ownSpawnId, 'controller', process.pid, nodeHash],
          [authoritySpawnId, 'worker', identities.worker.pid, process.platform === 'linux' ? keeperHash : nodeHash],
          [keeperSpawnId, 'keeper', keeperPid, keeperHash]]) {
          if (identities?.[key]?.pid !== pid || !Number.isFinite(Date.parse(identities[key].os_creation_time))) {
            throw new Error('Native process identity unavailable');
          }
          update({ type: 'spawn_observed', spawn_id: spawnId, pid,
            os_creation_time: identities[key].os_creation_time, executable_sha256: executable });
        }
        update({ type: 'containment_bound', descriptor: job.descriptor,
          spawn_ids: [ownSpawnId, authoritySpawnId, keeperSpawnId] });
        control.assertResourceAvailable(context, owner);
        if (job.permit && !settled && !finishing && remaining(deadline) > 0) {
          job.permit();
          await job.started;
        }
        if (!settled && !finishing && remaining(deadline) > 0) {
          checkpoint('containment_ready', { authority: identities.worker.pid, keeper: keeperPid });
          update({ type: 'phase', phase: 'running' });
          worker.send({ protocol: PROTOCOL, type: 'run', payload: {
            timeout_ms: payload.timeout_ms, started_ns: payload.started_ns,
            progress_channel: channel.descriptor
          } });
          worker.stdin.end(payload.request_json);
        } else if (!settled && !finishing) tick();
      } catch { failure('verification_authority_job_failed'); }
    });
  });
}


function runStdioWatchdog() {
  let bytes = 0, oversized = false;
  const chunks = [];
  process.stdin.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > MAX_BYTES) oversized = true;
    else chunks.push(chunk);
  });
  process.stdin.on('end', async () => {
    try {
      if (oversized) throw new Error('Oversized watchdog input');
      const input = Buffer.concat(chunks, bytes).toString('utf8');
      const split = input.indexOf('\n');
      if (split < 1 || split > 8192) throw new Error('Invalid watchdog header');
      const header = JSON.parse(input.slice(0, split));
      const envelope = await watch({ ...header, request_json: input.slice(split + 1) });
      const output = envelope.authority_payload
        ? '{"watchdog_budget":' + JSON.stringify(envelope.watchdog_budget) + ',"authority_teardown":' + JSON.stringify(envelope.authority_teardown) + ',"authority_payload":' + envelope.authority_payload + '}'
        : JSON.stringify(envelope);
      if (Buffer.byteLength(output) > MAX_BYTES) throw new Error('Oversized watchdog output');
      process.stdout.write(output, () => process.exit(0));
    } catch { process.stderr.write('Verification authority protocol failed\n'); process.exitCode = 1; }
  });
}
if (require.main === module) {
  if (process.argv[2] === '--authority') runAuthority();
  else runStdioWatchdog();
}
module.exports = { __test: { watch, runAuthority, runStdioWatchdog } };
