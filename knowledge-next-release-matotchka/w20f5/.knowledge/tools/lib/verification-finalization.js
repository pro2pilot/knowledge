'use strict';

// Command evidence and batch acceptance are different authorities. A worker
// can persist command-only KVE. The isolated authority signs after command
// teardown and readback; its watchdog gates release on authority teardown.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { copyInertData } = require('./inert-data');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const stable = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
const digest = value => hash(stable(value));
const SCHEMA = 'knowledge-verification-finalization.v2';
const ACK_SCHEMA = 'knowledge-verification-acceptance.v2';
const LEGACY_SCHEMA = 'knowledge-verification-finalization.v1';
const LEGACY_ACK_SCHEMA = 'knowledge-verification-acceptance.v1';
const MAX_WORK_MS = 600000 * 100000;
const MAX_CLEANUP_MS = 3600000;
const HASH = /^[a-f0-9]{64}$/;
const BATCH = /^KVB-[a-f0-9]{32}$/;
const STORE = 'verification_finalizations';
// Exact ordered paths keep this provenance list meaningful. These pins record
// observed implementation bytes; they are not a hermetic process attestation.
const LEGACY_IMPLEMENTATION_PATHS = Object.freeze([
  'tools/lib/verification-supervisor.js',
  'tools/lib/verification-worker.js',
  'tools/lib/verification-windows-job.js',
  'tools/lib/verification-windows-job.ps1',
  'tools/lib/verification-finalization.js',
  'tools/lib/verification-execution.js',
  'tools/lib/repair-on-touch.js',
  'schemas/verification-execution-v2.schema.json'
]);
const PREVIOUS_IMPLEMENTATION_PATHS = Object.freeze([...LEGACY_IMPLEMENTATION_PATHS, 'tools/lib/verification-watchdog.js', 'tools/lib/inert-data.js']);
const IMPLEMENTATION_PATHS = Object.freeze([...PREVIOUS_IMPLEMENTATION_PATHS,
  'tools/lib/verification-policy.js', 'tools/lib/verification-progress.js',
  'tools/lib/verification-control.js', 'verification-policy.json',
  'tools/lib/lock-policy.js', 'tools/lib/contained-lock-manager.js']);
const fail = () => { throw Object.assign(new Error('Native verification requires an accepted, complete batch with confirmed teardown'), { code: 'verification_finalization_required' }); };

async function persistFinalization(stateRoot, value) {
  const body = Buffer.from(JSON.stringify(value, null, 2) + '\n');
  if (body.length > 256 * 1024) fail();
  const root = path.resolve(stateRoot);
  const parents = [];
  let directory = root;
  for (const part of ['', 'maintenance', STORE]) {
    if (part) {
      directory = path.join(directory, part);
      try { await fs.promises.mkdir(directory); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    }
    const stat = await fs.promises.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
    parents.push({ path: directory, dev: stat.dev, ino: stat.ino });
  }
  if (path.relative(await fs.promises.realpath(root), await fs.promises.realpath(directory)).replace(/\\/g, '/') !== 'maintenance/' + STORE) fail();
  const content = digest(value), target = path.join(directory, content + '.json');
  // Unique batch identity makes collisions unexpected. Exclusive creation
  // keeps an interrupted file diagnostic-only; it is never overwritten.
  const file = await fs.promises.open(target, 'wx');
  try { await file.writeFile(body); } finally { await file.close(); }
  for (const parent of parents) {
    const live = await fs.promises.lstat(parent.path);
    if (!live.isDirectory() || live.isSymbolicLink() || live.dev !== parent.dev || live.ino !== parent.ino) fail();
  }
  const loaded = require('./verification-execution').readNativeRecord(root, content, STORE);
  if (!loaded || loaded.physical_sha256 !== hash(body) || digest(loaded.record) !== content) fail();
  return { receipt_id: 'KVF-' + content, physical_sha256: hash(body), batch_id: value.batch_id,
    ...(value.schema_version === SCHEMA ? { work_elapsed_ms: value.work_elapsed_ms,
      cleanup_budget_ms: value.cleanup_budget_ms, observed_elapsed_ms: value.observed_elapsed_ms } : {}) };
}

function workCleanupTiming(timeoutMs, workMs, cleanupMs, acceptedMs) {
  return Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= MAX_WORK_MS &&
    Number.isFinite(workMs) && workMs >= 0 && workMs < timeoutMs &&
    Number.isSafeInteger(cleanupMs) && cleanupMs > 0 && cleanupMs <= MAX_CLEANUP_MS &&
    Number.isFinite(acceptedMs) && acceptedMs >= workMs && acceptedMs < workMs + cleanupMs;
}

function acceptFinalization(reference, timeoutMs, elapsedMs, privateKey, timing = undefined) {
  try {
    reference = copyInertData(reference);
    timing = timing === undefined ? {} : copyInertData(timing);
  } catch { fail(); }
  if (!reference || typeof reference !== 'object' || Array.isArray(reference) ||
      !timing || typeof timing !== 'object' || Array.isArray(timing) ||
      Object.keys(timing).some(key => !['work_elapsed_ms', 'cleanup_budget_ms'].includes(key))) fail();
  const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const workMs = own(timing, 'work_elapsed_ms') ? timing.work_elapsed_ms : reference.work_elapsed_ms;
  const cleanupMs = own(timing, 'cleanup_budget_ms') ? timing.cleanup_budget_ms : reference.cleanup_budget_ms;
  if (!BATCH.test(reference.batch_id) || !/^KVF-[a-f0-9]{64}$/.test(reference.receipt_id) ||
      !HASH.test(reference.physical_sha256) || !workCleanupTiming(timeoutMs, workMs, cleanupMs, elapsedMs) ||
      own(reference, 'work_elapsed_ms') && reference.work_elapsed_ms !== workMs ||
      own(reference, 'cleanup_budget_ms') && reference.cleanup_budget_ms !== cleanupMs ||
      own(reference, 'observed_elapsed_ms') && (!Number.isFinite(reference.observed_elapsed_ms) ||
        reference.observed_elapsed_ms < workMs || reference.observed_elapsed_ms > elapsedMs)) fail();
  // Reference metadata is not spread into the signed shape. The v2 fields
  // retain work and cleanup as distinct contracts; v1 is reader-only legacy.
  const value = { schema_version: ACK_SCHEMA, receipt_id: reference.receipt_id,
    physical_sha256: reference.physical_sha256, batch_id: reference.batch_id,
    timeout_ms: timeoutMs, accepted_elapsed_ms: elapsedMs,
    work_elapsed_ms: workMs, cleanup_budget_ms: cleanupMs };
  return { ...value, signature: crypto.sign(null, Buffer.from(stable(value)), privateKey).toString('hex') };
}

function requireFinalizedExecutions(stateRoot, executionIds, acceptances, privacyMode = 'strict') {
  try {
    if (!['strict', 'caller_policy_required'].includes(privacyMode)) fail();
    executionIds = copyInertData(executionIds); acceptances = copyInertData(acceptances);
    if (!Array.isArray(executionIds) || !executionIds.length || new Set(executionIds).size !== executionIds.length ||
        !Array.isArray(acceptances) || !acceptances.length || acceptances.length > executionIds.length) fail();
    const core = require('./verification-execution');
    const requested = new Set(executionIds), covered = new Set(), batches = new Set(), bindings = [], executionRecords = [];
    const physicalBindings = new Map();
    const bind = (loaded, details = {}) => {
      const file = path.resolve(loaded.path), prior = physicalBindings.get(file);
      // Preserve every physical dependency read for this authorization. A
      // subset still relies on all siblings remaining valid until commit.
      if (prior) {
        if (prior.physical_sha256 !== loaded.physical_sha256) fail();
        return;
      }
      const pin = { path: file, physical_sha256: loaded.physical_sha256, ...details };
      physicalBindings.set(file, pin); bindings.push(pin);
    };
    for (const ack of acceptances) {
      const modern = ack?.schema_version === ACK_SCHEMA;
      const keys = modern
        ? 'accepted_elapsed_ms,batch_id,cleanup_budget_ms,physical_sha256,receipt_id,schema_version,signature,timeout_ms,work_elapsed_ms'
        : 'accepted_elapsed_ms,batch_id,physical_sha256,receipt_id,schema_version,signature,timeout_ms';
      if (!ack || Object.keys(ack).sort().join(',') !== keys ||
          ![ACK_SCHEMA, LEGACY_ACK_SCHEMA].includes(ack.schema_version) || !BATCH.test(ack.batch_id) || batches.has(ack.batch_id) ||
          !/^KVF-[a-f0-9]{64}$/.test(ack.receipt_id) || !HASH.test(ack.physical_sha256) ||
          (modern ? !workCleanupTiming(ack.timeout_ms, ack.work_elapsed_ms, ack.cleanup_budget_ms, ack.accepted_elapsed_ms)
            : !Number.isSafeInteger(ack.timeout_ms) || ack.timeout_ms <= 0 || !Number.isFinite(ack.accepted_elapsed_ms) ||
              ack.accepted_elapsed_ms < 0 || ack.accepted_elapsed_ms >= ack.timeout_ms)) fail();
      const loaded = core.readNativeRecord(stateRoot, ack.receipt_id.slice(4), STORE);
      if (!loaded || loaded.physical_sha256 !== ack.physical_sha256 || digest(loaded.record) !== ack.receipt_id.slice(4)) fail();
      const record = loaded.record;
      if (typeof record.public_key !== 'string' || !/^[a-f0-9]{88}$/.test(record.public_key)) fail();
      const publicKey = crypto.createPublicKey({ key: Buffer.from(record.public_key, 'hex'), type: 'spki', format: 'der' });
      const { signature, ...unsigned } = ack;
      if (publicKey.asymmetricKeyType !== 'ed25519' || typeof signature !== 'string' || !/^[a-f0-9]{128}$/.test(signature) ||
          !crypto.verify(null, Buffer.from(stable(unsigned)), publicKey, Buffer.from(signature, 'hex'))) fail();
      if (record.schema_version !== (modern ? SCHEMA : LEGACY_SCHEMA) || record.batch_id !== ack.batch_id || record.status !== 'commands_and_teardown_observed' ||
          record.timeout_ms !== ack.timeout_ms || !Number.isFinite(record.observed_elapsed_ms) || record.observed_elapsed_ms < 0 ||
          record.observed_elapsed_ms > ack.accepted_elapsed_ms ||
          modern && (record.work_elapsed_ms !== ack.work_elapsed_ms || record.cleanup_budget_ms !== ack.cleanup_budget_ms ||
            record.observed_elapsed_ms < record.work_elapsed_ms || record.teardown?.keeper_exited !== true) || record.teardown?.status !== 'completed' ||
          record.teardown.method !== 'windows_job_object' || record.teardown.active_processes !== 0 ||
          record.backend !== 'windows_job_object' || !Array.isArray(record.executions) || !record.executions.length ||
          !HASH.test(record.request_sha256) || !HASH.test(record.runtime_sha256) || !Array.isArray(record.implementation) ||
          !(modern ? [IMPLEMENTATION_PATHS] : [PREVIOUS_IMPLEMENTATION_PATHS, LEGACY_IMPLEMENTATION_PATHS]).some(paths => record.implementation.length === paths.length &&
            record.implementation.every((pin, index) => pin && pin.path === paths[index] && HASH.test(pin.sha256)))) fail();
      const ordered = [], seen = new Set();
      for (let index = 0; index < record.executions.length; index++) {
        const pin = record.executions[index];
        if (!pin || !/^KVE-[a-f0-9]{64}$/.test(pin.execution_id) || !HASH.test(pin.physical_sha256) || seen.has(pin.execution_id)) fail();
        const execution = core.readExecutionRecord(stateRoot, pin.execution_id);
        const validation = execution && core.validateExecutionRecord(execution.record);
        // Batch attestation is not privacy authorization. Consumers retain
        // their own recording policy, including exact user-approved paths.
        // Every structural/digest/status check remains mandatory here.
        if (!execution || validation.digest !== execution.expected_digest || validation.errors.some(code => privacyMode === 'strict' || code !== 'execution_secret_like_value') ||
            execution.physical_sha256 !== pin.physical_sha256 || execution.record.schema_version !== 'knowledge-verification-execution.v2' ||
            execution.record.batch_id !== ack.batch_id || execution.record.batch_public_key !== record.public_key || execution.record.batch_request_sha256 !== record.request_sha256 || execution.record.batch_ordinal !== index ||
            execution.record.task_id !== record.task_id || execution.record.session_id !== record.session_id ||
            execution.record.runtime_binding === 'process_exec_path' && execution.record.runtime_sha256 !== record.runtime_sha256) fail();
        seen.add(pin.execution_id); ordered.push(pin.execution_id);
        bind(execution);
        executionRecords.push(execution.record);
        if (requested.has(pin.execution_id)) covered.add(pin.execution_id);
      }
      // A subset cannot turn a later command failure into a complete batch.
      // Every batch member is read and verified, even when reusing one KVE.
      if (!ordered.some(id => requested.has(id))) fail();
      batches.add(ack.batch_id); bind(loaded, { execution_ids: ordered });
    }
    if (covered.size !== requested.size) fail();
    return { status: privacyMode === 'strict' ? 'accepted' : 'cryptographically_finalized',
      privacy_status: privacyMode === 'strict' ? 'strict' : 'not_evaluated', bindings, execution_records: executionRecords };
  } catch (error) { if (error.code === 'verification_finalization_required') throw error; fail(); }
}

module.exports = { SCHEMA, ACK_SCHEMA, LEGACY_SCHEMA, LEGACY_ACK_SCHEMA, LEGACY_IMPLEMENTATION_PATHS, PREVIOUS_IMPLEMENTATION_PATHS, IMPLEMENTATION_PATHS, digest, hash, persistFinalization, acceptFinalization, requireFinalizedExecutions };
