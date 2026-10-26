'use strict';
const net = require('net');
const controller = new AbortController();
const startedNs = process.hrtime.bigint();
// Extra spawnSync pipes are child-writable. POSIX socketpairs happen to allow
// reading them too; Windows named pipes do not. A bounded, one-byte write is
// only a negative parent-liveness signal, never command progress. Native
// ownership and the original work/cleanup deadlines remain independent.
const parent = new net.Socket({ fd: 3, readable: false, writable: true });
let finished = false, heartbeat, pending = false;
const parentFailed = () => { if (!finished) controller.abort(); };
parent.on('error', parentFailed);
parent.on('close', parentFailed);
function pulse() {
  if (finished || pending || controller.signal.aborted) return;
  pending = true;
  parent.write(Buffer.from([0]), error => { pending = false; if (error) parentFailed(); });
}
async function admitParent(setupDeadlineNs) {
  if (controller.signal.aborted) throw Object.assign(new Error('Parent channel closed'), { code: 'command_cancelled' });
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer); controller.signal.removeEventListener('abort', cancel); error ? reject(error) : resolve(); };
    const cancel = () => finish(Object.assign(new Error('Parent channel closed'), { code: 'command_cancelled' }));
    const remaining = Number(setupDeadlineNs - process.hrtime.bigint()) / 1e6;
    if (remaining <= 0) { reject(Object.assign(new Error('Setup deadline expired'), { code: 'command_setup_timeout' })); return; }
    const timer = setTimeout(() => finish(Object.assign(new Error('Setup deadline expired'), { code: 'command_setup_timeout' })), Math.max(1, Math.ceil(remaining)));
    controller.signal.addEventListener('abort', cancel, { once: true });
    pending = true;
    parent.write(Buffer.from([0]), error => {
      pending = false;
      if (error || controller.signal.aborted) cancel();
      else if (process.hrtime.bigint() >= setupDeadlineNs) finish(Object.assign(new Error('Setup deadline expired'), { code: 'command_setup_timeout' }));
      else finish();
    });
  });
  heartbeat = setInterval(pulse, 1000);
}
function closeParent() { finished = true; clearInterval(heartbeat); parent.destroy(); }
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => controller.abort());
const chunks = []; let bytes = 0;
process.stdin.on('data', chunk => { bytes += chunk.length; if (bytes > 64 * 1024 * 1024) process.exit(1); chunks.push(chunk); });
process.stdin.on('end', async () => {
  try {
    const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const runner = require('./command-runner'), policy = runner.budgets(request.budgets);
    let setupDeadlineNs = startedNs + BigInt(policy.setupMs) * 1000000n;
    if (request.absoluteWorkDeadlineNs !== undefined) {
      if (typeof request.absoluteWorkDeadlineNs !== 'string' || !/^[1-9]\d{0,31}$/.test(request.absoluteWorkDeadlineNs)) throw Object.assign(new Error('Invalid work deadline'), { code: 'command_clock_invalid' });
      if (BigInt(request.absoluteWorkDeadlineNs) < setupDeadlineNs) setupDeadlineNs = BigInt(request.absoluteWorkDeadlineNs);
    }
    await admitParent(setupDeadlineNs);
    const remainingSetupMs = Math.floor(Number(setupDeadlineNs - process.hrtime.bigint()) / 1e6);
    if (remainingSetupMs < 1) throw Object.assign(new Error('Setup deadline expired'), { code: 'command_setup_timeout' });
    const answer = await runner.runOwnedOperation(request.operation, request.payload, {
      budgets: { ...policy, setupMs: remainingSetupMs }, signal: controller.signal, absoluteWorkDeadlineNs: request.absoluteWorkDeadlineNs,
      invocationStartedNs: request.invocationStartedNs, ...(request.macosWorkspace ? { macosWorkspace: request.macosWorkspace } : {}) });
    process.stdout.write(JSON.stringify({ value: answer.value }), () => { closeParent(); process.exit(0); });
  } catch (error) {
    const detail = { code: error.code || 'command_failed', message: error.message };
    for (const key of ['cleanup', 'run_id', 'retry_of', 'team_release', 'lock_release_error', 'lock_event_error', 'finalization_error', 'record_write_status', 'record_kind', 'timed_out', 'stage', 'verification_budget', 'completed_executions', 'teardown', 'authority_teardown',
      'attempt_id', 'attempt_nonce', 'scope', 'recovery_required', 'result_visibility', 'terminal_commit', 'containment', 'execution', 'primary_error', 'invocation', 'cleanup_deadline_ns', 'invocation_recovery', 'recovery_teardown']) {
      if (error[key] !== undefined) detail[key] = error[key];
    }
    process.stdout.write(JSON.stringify({ error: detail }), () => { closeParent(); process.exit(1); });
  }
});
