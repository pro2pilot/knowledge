'use strict';

// Fixed project-storage worker. P registers this exact direct child with the
// native service before sending the first operation. The lifetime lease spans
// every project read/write, including a syscall that remains blocked in-kernel.
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const control = require('./verification-control');
const finalization = require('./verification-finalization');
const serviceFinalization = require('./verification-linux-service-finalization');
const isolated = require('./verification-isolated-copy');
const importer = require('./verification-linux-service-importer');
const execution = require('./verification-execution');
const { copyInertData } = require('./inert-data');
const { readStableFile } = require('./stable-file');
const PROTOCOL = 'knowledge-linux-service-storage.v1';
const MAX_MESSAGE = 64 * 1024 * 1024;
const clock = () => process.hrtime.bigint();
const fail = code => { throw Object.assign(new Error(code), { code }); };
const expectedParent = /^[1-9]\d{0,9}$/.test(process.argv[2] || '') ? Number(process.argv[2]) : 0;
let owner, context, lease, deadline, initialized = false, sealed = false, busy = false, sequence = 0, cleanupStarted = false;
function guard(allowExpired = false) {
  if (sealed || !process.connected || process.ppid !== expectedParent || expectedParent <= 1) {
    sealed = true;fail('verification_linux_storage_revoked');
  }
  if (!allowExpired && deadline && clock() >= deadline) fail('verification_linux_storage_deadline');
}
function contextFor(request) {
  if (!request || !['stateRoot', 'repoRoot'].every(key => typeof request[key] === 'string' && path.isAbsolute(request[key]))) {
    fail('verification_linux_storage_context_invalid');
  }
  return { stateRoot: request.stateRoot, projectKnowledgeRoot: request.stateRoot,
    targetRoot: request.repoRoot, systemRoot: path.resolve(__dirname, '../..') };
}
function setDeadline(value) {
  if (typeof value !== 'string' || !/^\d{1,20}$/.test(value)) fail('verification_clock_invalid');
  deadline = BigInt(value);
}
function releaseAndExit(code = 0) {
  sealed = true;
  try { if (lease) { const held = lease;lease = null;held.release(); } } catch { code = 1; }
  process.exit(code);
}
function observedPins() {
  const root = path.resolve(__dirname, '../..');
  return serviceFinalization.IMPLEMENTATION_PATHS.map(name => {
    guard();return { path: name, sha256: finalization.hash(readStableFile(root, path.join(root, name), { maxBytes: 4 * 1024 * 1024 })) };
  });
}
function trustedSourceManifest() {
  const root = path.resolve(__dirname, '../..'), entries = [];
  function visit(directory, relative = '') {
    guard();
    for (const name of fs.readdirSync(directory)) {
      const rel = relative ? relative + '/' + name : name;
      if (!importer.allowedSourcePath(rel) && !(relative === '' && importer.sourcePolicy.directories.includes(name))) continue;
      isolated.relativeName(rel);
      const filename = path.join(directory, name), stat = fs.lstatSync(filename);
      if (stat.isSymbolicLink()) fail('verification_linux_runtime_source_unsafe');
      if (stat.isDirectory()) visit(filename, rel);
      else {
        if (!stat.isFile() || stat.nlink !== 1) fail('verification_linux_runtime_source_unsafe');
        const bytes = readStableFile(root, filename, { maxBytes: 32 * 1024 * 1024 });
        entries.push({ path: rel, sha256: finalization.hash(bytes) });
      }
    }
  }
  visit(root);entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return { sha256: finalization.hash(entries.map(row => row.sha256 + ' knowledge/' + row.path + '\n').join('')), files: entries.length };
}
async function sourceEnvelope(request, limits) {
  const required = (request.sourceFiles || []).map(item => String(item.path || item));
  for (const test of request.tests) {
    if (!Array.isArray(test.argv) || !['node', 'node.exe'].includes(test.argv[0])) fail('verification_linux_command_unsupported');
    required.push(isolated.relativeName(test.argv[1] === '--test' ? test.argv[2] : test.argv[1]));
  }
  const plan = await isolated.planProject(request.repoRoot, { required: [...new Set(required)], limits, checkpoint: guard });
  const files = [];let current;
  await isolated.transferProject(plan, async message => {
    guard();
    if (message.op === 'put_begin') current = { path: message.path, bytes: message.bytes,
      mode: message.mode, sha256: message.sha256, chunks: [], offset: 0 };
    else if (message.op === 'put_chunk') {
      if (!current || message.path !== current.path || message.offset !== current.offset) fail('verification_linux_copy_sequence');
      const bytes = Buffer.from(message.data, 'base64');current.offset += bytes.length;current.chunks.push(bytes);
    } else if (message.op === 'put_commit') {
      if (!current || message.path !== current.path || current.offset !== current.bytes) fail('verification_linux_copy_sequence');
      const bytes = Buffer.concat(current.chunks);
      if (finalization.hash(bytes) !== current.sha256) fail('verification_copy_source_changed');
      files.push({ path: current.path, bytes: current.bytes, mode: current.mode, sha256: current.sha256, data_base64: bytes.toString('base64') });
      current = null;
    }
  }, { checkpoint: guard, progress: value => process.send({ protocol: PROTOCOL, type: 'copy_progress', ...value }) });
  const source = { schema_version: importer.SCHEMA, directories: plan.directories, files,
    manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256 };
  // Validate the same closed import contract before sending any source to I.
  importer.validateImport(Buffer.from(JSON.stringify(source)));guard();
  return { plan, source };
}
async function dispatch(message) {
  guard(['cleanup_epoch', 'stop', 'cancel'].includes(message.op));
  if (message.op === 'init' || message.op === 'finish_only') {
    if (initialized) fail('verification_linux_storage_reinitialized');
    initialized = true;setDeadline(message.deadline_ns);guard();context = contextFor(message.request);
    // Candidate/runtime equality is checked before opening a project claim.
    const runtimeSource = trustedSourceManifest();
    if (runtimeSource.sha256 !== message.capability?.trusted_source_manifest_sha256) fail('verification_linux_runtime_source_mismatch');
    lease = control.acquireStorageLease(context, { timeoutMs: Math.max(1, Math.min(600000, Math.floor(Number(deadline - clock()) / 1e6))) });guard();
    if (message.op === 'finish_only') {
      owner = message.owner;const result = control.commitFinish(context, owner, message.input);guard();return result;
    }
    if (control.readStatus(context).attempt?.claimed) fail('verification_recovery_required');
    guard();return { runtime_source: runtimeSource };
  }
  if (!initialized || !lease) fail('verification_linux_storage_not_initialized');
  if (message.op === 'prepare_copy') return sourceEnvelope(message.request, message.limits);
  if (message.op === 'pin_implementation') return observedPins();
  if (message.op === 'status') return control.readStatus(context);
  if (message.op === 'begin') {
    if (owner) fail('verification_linux_storage_reinitialized');
    const opened = control.beginAttempt(context, { request_sha256: finalization.digest(message.request), profile: message.profile,
      storage_protocol: 'lifetime_lease.v1', startup_nonce_sha256: finalization.hash(message.nonce) });
    owner = opened.owner;guard();return opened;
  }
  if (!owner) fail('verification_linux_storage_not_initialized');
  if (message.op === 'update') return control.updateAttempt(context, owner, message.event);
  if (message.op === 'stop') return control.updateAttempt(context, owner, { type: 'stop', reason: message.reason });
  if (message.op === 'cancel') return control.requestCancel(context, { attempt_id: owner.attempt_id, generation: owner.generation, reason_code: 'user_requested' });
  if (message.op === 'cleanup_epoch') {
    if (cleanupStarted) fail('verification_linux_cleanup_epoch_repeated');
    cleanupStarted = true;setDeadline(message.deadline_ns);guard();return control.updateAttempt(context, owner, { type: 'cleanup_started' });
  }
  if (message.op === 'finalize') {
    if (!cleanupStarted) fail('verification_linux_cleanup_epoch_missing');
    const { record, plan, implementation_before } = message;
    await isolated.verifyProjectPlan(plan, { checkpoint: guard });guard();
    if (finalization.digest(serviceFinalization.planSummary(plan)) !== finalization.digest(record.linux.plan_summary)) fail('verification_copy_manifest_invalid');
    const live = control.readStatus(context).attempt;
    if (!live?.claimed || live.cancel.requested || live.stop_reason || live.recovery || live.request_sha256 !== record.request_sha256) fail('verification_stopped');
    const implementation = observedPins();
    if (finalization.digest(implementation) !== finalization.digest(implementation_before)) fail('verification_implementation_changed');
    const authority = JSON.parse(record.linux.authority_raw);
    if (!Array.isArray(authority.result) || authority.result.length !== record.executions.length) fail('verification_batch_incomplete');
    const result = [], executions = authority.result.map((item, index) => {
      guard();const source = item.record;
      if (source?.execution_id !== record.executions[index].execution_id || source.batch_id !== record.batch_id ||
          source.batch_public_key !== record.public_key || source.batch_request_sha256 !== record.request_sha256 ||
          source.batch_ordinal !== index || source.task_id !== record.task_id || source.session_id !== record.session_id) fail('verification_batch_incomplete');
      serviceFinalization.validateExecution(record, source, index);
      const saved = require('./repair-on-touch').saveExecutionRecord(context.stateRoot, source);
      const loaded = execution.readExecutionRecord(context.stateRoot, source.execution_id);
      if (!loaded || finalization.digest(loaded.record) !== finalization.digest(source) || loaded.physical_sha256 !== saved.physical_sha256) fail('verification_batch_incomplete');
      result.push({ record: source, path: saved.path, relative_path: path.relative(context.stateRoot, saved.path).split(path.sep).join('/'), idempotent: saved.idempotent });
      return { execution_id: source.execution_id, physical_sha256: saved.physical_sha256 };
    });
    const complete = { ...record, implementation, executions };
    serviceFinalization.validate(complete);guard();
    const reference = await finalization.persistFinalization(context.stateRoot, complete);guard();return { reference, result };
  }
  if (message.op === 'verify_acceptance') {
    const result = finalization.requireFinalizedExecutions(context.stateRoot, message.ids, [message.acceptance]);
    const live = control.readStatus(context).attempt;
    if (!live?.claimed || live.cancel.requested || live.stop_reason || live.recovery) fail('verification_stopped');
    guard();return { status: result.status, executions: result.execution_records.length };
  }
  if (message.op === 'finish_failed') return control.commitFinish(context, owner, message.input);
  fail('verification_linux_storage_opcode_invalid');
}
function start() {
  const parent = new net.Socket({ fd: 3, readable: true, writable: false });
  const stop = () => { sealed = true;if (!busy) releaseAndExit(1); };
  parent.on('end', stop);parent.on('error', stop);parent.resume();
  process.on('disconnect', stop);process.on('SIGTERM', stop);process.on('SIGINT', stop);
  process.on('message', async raw => {
    if (sealed) return;
    let message;
    try { message = copyInertData(raw, null, MAX_MESSAGE); } catch { stop();return; }
    if (message?.protocol !== PROTOCOL || !Number.isSafeInteger(message.id) || message.id !== sequence + 1 || busy) { stop();return; }
    sequence = message.id;if (message.op === 'exit') { releaseAndExit(0);return; }
    busy = true;
    try {
      const value = await dispatch(message);guard();
      if (Buffer.byteLength(JSON.stringify(value)) > MAX_MESSAGE) fail('verification_transport_oversized');
      process.send({ protocol: PROTOCOL, id: message.id, ok: true, value }, error => { if (error) stop(); });
    } catch (error) {
      if (process.connected) process.send({ protocol: PROTOCOL, id: message.id, ok: false,
        code: /^[a-zA-Z0-9_]{1,100}$/.test(error.code || '') ? error.code : 'verification_linux_storage_failed' });
    } finally { busy = false;if (sealed) releaseAndExit(1); }
  });
}
if (require.main === module) start();
module.exports = { PROTOCOL, contextFor, trustedSourceManifest };
