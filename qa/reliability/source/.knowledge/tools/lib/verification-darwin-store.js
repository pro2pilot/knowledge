'use strict';

// Fixed storage worker. It never executes a repository command. Its lifetime
// lease spans every read/write and remains held if a kernel syscall stalls.
// The responsive controller observes the exact child exit before acceptance.
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const control = require('./verification-control');
const { copyInertData } = require('./inert-data');
const { readStableFile } = require('./stable-file');
const { ensureContainedDir, assertSafeContainedPath } = require('./json-store');
const finalization = require('./verification-finalization');
const darwinFinalization = require('./verification-darwin-finalization');
const isolated = require('./verification-isolated-copy');
const execution = require('./verification-execution');
const MAX_BYTES = 32 * 1024 * 1024;
const PROTOCOL = 'knowledge-darwin-storage.v1';
const clock = () => process.hrtime.bigint();
const fail = code => { throw Object.assign(new Error(code), { code }); };
let context, owner, lease, deadline, initialized = false, sealed = false, busy = false, sequence = 0;
let copySequence = 0;
const copyReplies = new Map();
function nativeCopyRequest(input) {
  guard();const copy_id = ++copySequence;
  return new Promise((resolve, reject) => {
    copyReplies.set(copy_id, { resolve, reject });
    process.send({ protocol: PROTOCOL, type: 'copy_request', copy_id, input }, error => {
      if (error) { copyReplies.delete(copy_id);reject(error); }
    });
  });
}
function guard(allowExpired = false) {
  if (sealed || !process.connected) fail('verification_darwin_storage_revoked');
  if (!allowExpired && deadline && clock() >= deadline) fail('verification_darwin_storage_deadline');
}
function contextFor(request) {
  if (!request || !['stateRoot', 'repoRoot'].every(key => typeof request[key] === 'string' && path.isAbsolute(request[key]))) {
    fail('verification_darwin_storage_context_invalid');
  }
  return { stateRoot: request.stateRoot, projectKnowledgeRoot: request.stateRoot,
    targetRoot: request.repoRoot, systemRoot: path.resolve(__dirname, '../..') };
}
function releaseAndExit(code = 0) {
  // Permanent in-memory sealing precedes release. No queued operation can
  // regain storage authority after the lifetime lease has been relinquished.
  sealed = true;
  try { if (lease) { const held = lease; lease = null; held.release(); } }
  catch { code = 1; }
  process.exit(code);
}
function immutableIntent(request, nonce, nativeConfig) {
  if (!/^[a-f0-9]{64}$/.test(nonce)) fail('verification_darwin_nonce_invalid');
  const directory = path.join(context.stateRoot, 'maintenance', 'verification-control', 'native-intents');
  ensureContainedDir(context.stateRoot, directory);
  const target = path.join(directory, owner.attempt_id + '.json');
  assertSafeContainedPath(context.stateRoot, target, { allowMissing: true });
  const body = Buffer.from(JSON.stringify({ schema_version: 'knowledge-darwin-prepare-intent.v1',
    attempt_id: owner.attempt_id, generation: owner.generation, request_sha256: finalization.digest(request),
    attempt_nonce: nonce, native_config: nativeConfig }, null, 2) + '\n');
  const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
    (fs.constants.O_NOFOLLOW || 0), 0o600);
  try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const directoryFd = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0));
  try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
  if (!readStableFile(context.stateRoot, target, { maxBytes: 65536 }).equals(body)) fail('verification_darwin_intent_readback');
  return { path: path.relative(context.stateRoot, target).split(path.sep).join('/'), sha256: finalization.hash(body) };
}
function observedPins(names) {
  const root = path.resolve(__dirname, '../..');
  return names.map(name => ({ path: name,
    sha256: finalization.hash(readStableFile(root, path.join(root, name), { maxBytes: 4 * 1024 * 1024 })) }));
}
async function dispatch(message) {
  guard(['cleanup_epoch', 'stop', 'cancel'].includes(message.op));
  if (message.op === 'status_only') {
    if (initialized) fail('verification_darwin_storage_reinitialized');
    initialized = true;context = contextFor(message.request);
    return control.readStatus(context);
  }
  if (message.op === 'init' || message.op === 'finish_only' || message.op === 'recover_only') {
    if (initialized) fail('verification_darwin_storage_reinitialized');
    initialized = true;
    if (typeof message.deadline_ns !== 'string' || !/^\d{1,32}$/.test(message.deadline_ns)) fail('verification_clock_invalid');
    deadline = BigInt(message.deadline_ns); guard();
    context = contextFor(message.request);
    lease = control.acquireStorageLease(context, {
      timeoutMs: Math.max(1, Math.min(600000, Math.floor(Number(deadline - clock()) / 1e6))) });
    guard();
    if (message.op === 'recover_only') {
      const current = control.readStatus(context).attempt;
      if (!current) return { status: 'no_attempt' };
      if (message.owner ? current.attempt_id !== message.owner.attempt_id || current.generation !== message.owner.generation
        : !/^[a-f0-9]{64}$/.test(message.startup_nonce_sha256 || '') || current.startup_nonce_sha256 !== message.startup_nonce_sha256) {
        fail('verification_attempt_mismatch');
      }
      if (message.cancelled === true) control.requestCancel(context, { attempt_id: current.attempt_id,
        generation: current.generation, reason_code: 'user_requested' });
      return require('./verification-recovery').recoverAttempt(context, { attempt_id: current.attempt_id,
        generation: current.generation, deadline_ns: message.deadline_ns });
    }
    if (message.op === 'finish_only') {
      owner = message.owner;
      const result = control.commitFinish(context, owner, message.input);
      guard(); return result;
    }
    const opened = control.beginAttempt(context, { request_sha256: finalization.digest(message.request), profile: message.profile,
      storage_protocol: 'lifetime_lease.v1', startup_nonce_sha256: finalization.hash(message.nonce) });
    owner = opened.owner;
    const intent = immutableIntent(message.request, message.nonce, message.config);
    guard();
    return { ...opened, intent };
  }
  if (!initialized || !owner || !lease) fail('verification_darwin_storage_not_initialized');
  if (message.op === 'prepare_copy') {
    const request = message.request, required = (request.sourceFiles || []).map(item => String(item.path || item));
    for (const test of request.tests) {
      if (!Array.isArray(test.argv) || !['node', 'node.exe'].includes(test.argv[0])) fail('verification_darwin_command_unsupported');
      required.push(isolated.relativeName(test.argv[1] === '--test' ? test.argv[2] : test.argv[1]));
    }
    const plan = await isolated.planProject(request.repoRoot, { required: [...new Set(required)],
      limits: message.limits, checkpoint: guard });
    await isolated.transferProject(plan, nativeCopyRequest, { checkpoint: guard,
      progress: value => process.send({ protocol: PROTOCOL, type: 'copy_progress', ...value }) });
    guard();return plan;
  }
  if (message.op === 'cleanup_epoch') {
    if (typeof message.deadline_ns !== 'string' || !/^\d{1,32}$/.test(message.deadline_ns)) fail('verification_clock_invalid');
    // The controller establishes this one cleanup epoch. A subsequent retry
    // cannot extend it. Work has permanently ended at this transition.
    if (dispatch.cleanupStarted) fail('verification_darwin_cleanup_epoch_repeated');
    dispatch.cleanupStarted = true; deadline = BigInt(message.deadline_ns); guard();
    return control.updateAttempt(context, owner, { type: 'cleanup_started' });
  }
  if (message.op === 'update') return control.updateAttempt(context, owner, message.event);
  if (message.op === 'status') return control.readStatus(context);
  if (message.op === 'stop') {
    return control.updateAttempt(context, owner, { type: 'stop', reason: message.reason });
  }
  if (message.op === 'cancel') return control.requestCancel(context, { attempt_id: owner.attempt_id,
    generation: owner.generation, reason_code: 'user_requested' });
  if (message.op === 'pin_implementation') return observedPins(darwinFinalization.IMPLEMENTATION_PATHS);
  if (message.op === 'finalize') {
    if (!dispatch.cleanupStarted) fail('verification_darwin_cleanup_epoch_missing');
    const { record, plan, implementation_before } = message;
    await isolated.verifyProjectPlan(plan, { checkpoint: guard }); guard();
    const summary = darwinFinalization.planSummary(plan);
    if (finalization.digest(summary) !== finalization.digest(record.darwin.plan_summary)) fail('verification_copy_manifest_invalid');
    for (const row of record.darwin.source_snapshot) {
      if (!plan.files.some(file => file.path === row.path && file.sha256 === row.sha256)) fail('verification_copy_source_changed');
    }
    const live = control.readStatus(context).attempt;
    if (!live?.claimed || live.cancel.requested || live.stop_reason || live.recovery) fail('verification_stopped');
    const implementation = observedPins(darwinFinalization.IMPLEMENTATION_PATHS);
    if (finalization.digest(implementation) !== finalization.digest(implementation_before)) fail('verification_implementation_changed');
    if (record.request_sha256 !== live.request_sha256 || record.backend !== 'darwin_private_ruid' ||
        !Array.isArray(record.executions) || !record.executions.length) fail('verification_batch_incomplete');
    const executions = record.executions.map((pin, index) => {
      guard();
      const loaded = execution.readExecutionRecord(context.stateRoot, pin.execution_id);
      const validation = loaded && execution.validateExecutionRecord(loaded.record);
      if (!loaded || validation.errors.length || validation.digest !== loaded.expected_digest ||
          loaded.record.status !== 'pass' || loaded.record.batch_id !== record.batch_id ||
          loaded.record.batch_ordinal !== index || loaded.record.batch_public_key !== record.public_key ||
          loaded.record.batch_request_sha256 !== record.request_sha256 ||
          loaded.record.task_id !== record.task_id || loaded.record.session_id !== record.session_id) {
        fail('verification_batch_incomplete');
      }
      darwinFinalization.validateExecution(record, loaded.record, index);
      return { execution_id: pin.execution_id, physical_sha256: loaded.physical_sha256 };
    });
    const complete = { ...record, implementation, executions };
    darwinFinalization.validate(complete); guard();
    const reference = await finalization.persistFinalization(context.stateRoot, complete);
    guard();return reference;
  }
  if (message.op === 'verify_acceptance') {
    guard(); const result = finalization.requireFinalizedExecutions(context.stateRoot, message.ids, [message.acceptance]);
    const live = control.readStatus(context).attempt;
    if (!live?.claimed || live.cancel.requested || live.stop_reason || live.recovery) fail('verification_stopped');
    guard();return { status: result.status, executions: result.execution_records.length };
  }
  if (message.op === 'finish_failed') return control.commitFinish(context, owner, message.input);
  fail('verification_darwin_storage_opcode_invalid');
}
function start() {
  const parent = new net.Socket({ fd: 3, readable: true, writable: false });
  const stop = () => { sealed = true; if (!busy) releaseAndExit(1); };
  parent.on('end', stop); parent.on('error', stop); parent.resume();
  process.on('disconnect', stop); process.on('SIGTERM', stop); process.on('SIGINT', stop);
  process.on('message', async raw => {
    if (sealed) return;
    let message;
    try { message = copyInertData(raw, null, MAX_BYTES); }
    catch { stop(); return; }
    if (message?.protocol === PROTOCOL && message.type === 'copy_reply') {
      const waiting = copyReplies.get(message.copy_id);copyReplies.delete(message.copy_id);
      if (!waiting) { stop();return; }
      if (message.ok === true) waiting.resolve(message.value);
      else waiting.reject(Object.assign(new Error('Native copy request failed'), { code: message.code || 'verification_darwin_copy_failed' }));
      return;
    }
    if (message?.protocol !== PROTOCOL || !Number.isSafeInteger(message.id) || message.id !== sequence + 1 || busy) { stop(); return; }
    sequence = message.id;
    if (message.op === 'exit') { releaseAndExit(0); return; }
    busy = true;
    try {
      const value = await dispatch(message); guard();
      process.send({ protocol: PROTOCOL, id: message.id, ok: true, value }, error => { if (error) stop(); });
    } catch (error) {
      if (process.connected) process.send({ protocol: PROTOCOL, id: message.id, ok: false,
        code: /^[a-zA-Z0-9_]{1,100}$/.test(error.code || '') ? error.code : 'verification_darwin_storage_failed' });
    } finally { busy = false; if (sealed) releaseAndExit(1); }
  });
}
if (require.main === module) start();
module.exports = { PROTOCOL, contextFor };
