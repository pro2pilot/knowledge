'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertSafeContainmentRoot, ensureContainedDir, assertSafeContainedPath, assertSafeContainedFile, readJson, writeJsonAtomicContained, writeFileAtomicContained } = require('./json-store');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');

const MAX_STATE_BYTES = 1024 * 1024;
const MAX_AGGREGATE_REBASE_ATTEMPTS = 3;
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const identity = stat => ({ dev: String(stat.dev), ino: String(stat.ino) });
const sameIdentity = (left, right) => left?.dev === right?.dev && left?.ino === right?.ino;

function readAutomationStatus(stateRoot) {
  const root = assertSafeContainmentRoot(stateRoot);
  const file = path.join(root, 'maintenance', 'automation_status.json');
  let current;
  try { assertSafeContainedFile(root, file); current = readJson(file); }
  catch (error) { if (error.code !== 'ENOENT') throw error; current = { mode: 'event-driven' }; }
  if (!current || typeof current !== 'object' || Array.isArray(current) ||
      (current.active_watchers !== undefined && (!current.active_watchers || typeof current.active_watchers !== 'object' || Array.isArray(current.active_watchers)))) {
    throw Object.assign(new Error('Watcher aggregate has an invalid shape'), { code: 'watcher_status_invalid' });
  }
  return current;
}

// Every known aggregate writer takes this one short publication lock. Callers
// rebuild only their own fields from the latest value, never a cached whole
// document. The bounded rebase also handles uncoordinated writers observed
// between read and publication; it is not an atomic filesystem CAS.
function updateAutomationStatus(context, update, options = {}) {
  const root = assertSafeContainmentRoot(context.stateRoot);
  const file = path.join(root, 'maintenance', 'automation_status.json');
  const assertAuthority = options.assertAuthority || (() => {});
  const validate = options.validate || (() => {});
  assertAuthority();
  return withContainedLock({ context, rootKind: 'state', rootPath: root, lockName: 'watch-maintenance', purpose: LOCKS['watch-maintenance'].purpose }, () => {
    for (let attempt = 1; attempt <= MAX_AGGREGATE_REBASE_ATTEMPTS; attempt++) {
      assertAuthority();
      const current = readAutomationStatus(root);
      validate(current);
      const snapshot = JSON.stringify(current);
      const payload = update(current);
      assertAuthority();
      try {
        writeJsonAtomicContained(file, payload, root, { hooks: {
          renameSync(temporary, destination) {
            assertAuthority();
            const latest = readAutomationStatus(root);
            validate(latest);
            if (JSON.stringify(latest) !== snapshot) {
              throw Object.assign(new Error('Watcher aggregate changed before publication'), { code: 'watcher_status_changed' });
            }
            fs.renameSync(temporary, destination);
          }
        } });
        return payload;
      } catch (error) {
        // Ownership, namespace, malformed-state and cleanup failures cannot be
        // reclassified as ordinary concurrent progress. Rebuild a new payload
        // only after the rejected temporary file was verifiably removed.
        if (error.code !== 'watcher_status_changed' || error.temp_cleanup_status !== 'removed') throw error;
        error.attempts = attempt;
        error.max_attempts = MAX_AGGREGATE_REBASE_ATTEMPTS;
        if (attempt === MAX_AGGREGATE_REBASE_ATTEMPTS) {
          error.message = `Watcher aggregate changed before publication after ${attempt} attempts`;
          throw error;
        }
      }
    }
  }, { timeoutMs: 10000 });
}

function createWatcherStateStore(options) {
  if (!options || typeof options.stateRoot !== 'string' || typeof options.watcherId !== 'string' || !/^[a-zA-Z0-9_.-]+$/.test(options.watcherId)) {
    throw new TypeError('Watcher state requires a root and safe watcher id');
  }
  const requestedRoot = path.resolve(options.stateRoot), watcherId = options.watcherId;
  const attemptId = crypto.randomBytes(16).toString('hex');
  let root = requestedRoot, directory = path.join(root, '.runtime', 'watchers'), file = path.join(directory, watcherId + '.json');
  let parents = null, expected = null, removed = false;

  function refusal(reason, cause) {
    const error = new Error(`Watcher state ownership lost: ${reason}`, cause ? { cause } : undefined);
    error.code = 'watcher_state_ownership_lost'; error.reason = reason; error.watcher_id = watcherId; error.attempt_id = attemptId; error.path = file;
    return error;
  }
  function assertParents() {
    if (!parents) throw refusal('attempt_not_initialized');
    for (const parent of parents) {
      let stat;
      try { stat = fs.lstatSync(parent.path, { bigint: true }); }
      catch (error) { if (error.code === 'ENOENT') throw refusal('parent_missing', error); throw error; }
      if (!stat.isDirectory() || stat.isSymbolicLink() || !sameIdentity(parent, identity(stat))) throw refusal('physical_parent_replaced');
    }
    assertSafeContainedPath(root, directory);
  }
  function physicalFile(candidate) {
    let stat;
    try { stat = fs.lstatSync(candidate, { bigint: true }); }
    catch (error) { if (error.code === 'ENOENT') throw refusal('state_missing', error); throw error; }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) throw refusal('state_not_unshared_regular_file');
    return stat;
  }
  function assertOwned() {
    assertParents();
    if (!expected || removed) throw refusal('attempt_not_initialized');
    const stat = physicalFile(file);
    if (!sameIdentity(expected, identity(stat))) throw refusal('physical_state_replaced');
    if (stat.size > BigInt(MAX_STATE_BYTES)) throw refusal('state_record_too_large');
    let descriptor = null, primary = null;
    try {
      descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
      const opened = fs.fstatSync(descriptor, { bigint: true });
      if (!opened.isFile() || opened.nlink !== 1n || !sameIdentity(expected, identity(opened))) throw refusal('state_changed_during_open');
      // A file may grow after stat. Read at most the known published byte count
      // plus one sentinel byte, with a fixed upper bound before allocation.
      const bytes = Buffer.allocUnsafe(Math.min(expected.bytes + 1, MAX_STATE_BYTES + 1));
      let length = 0;
      while (length < bytes.length) {
        const count = fs.readSync(descriptor, bytes, length, bytes.length - length, null);
        if (!count) break;
        length += count;
      }
      if (length !== expected.bytes || digest(bytes.subarray(0, length)) !== expected.sha256) throw refusal('state_bytes_changed');
      assertParents();
      if (!sameIdentity(expected, identity(physicalFile(file)))) throw refusal('state_changed_during_read');
      return true;
    } catch (error) { primary = error; throw error; }
    finally {
      if (descriptor !== null) {
        try { fs.closeSync(descriptor); }
        catch (error) { if (primary) primary.close_error = { code: error.code, message: error.message }; else throw error; }
      }
    }
  }
  function payload(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Watcher state payload must be an object');
    return { ...value, watcher_id: watcherId, attempt_id: attemptId };
  }
  function serialize(value) {
    const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
    if (bytes.length > MAX_STATE_BYTES) {
      throw Object.assign(new Error(`Watcher state payload exceeds ${MAX_STATE_BYTES} bytes`), {
        code: 'watcher_state_payload_too_large', limit_bytes: MAX_STATE_BYTES, actual_bytes: bytes.length, watcher_id: watcherId, attempt_id: attemptId
      });
    }
    return bytes;
  }
  function initialize(value) {
    if (parents || expected || removed) throw refusal('attempt_already_initialized');
    const next = payload(value), body = serialize(next);
    root = assertSafeContainmentRoot(requestedRoot);
    directory = path.join(root, '.runtime', 'watchers'); file = path.join(directory, watcherId + '.json');
    ensureContainedDir(root, directory);
    parents = [root, path.join(root, '.runtime'), directory].map(parent => ({ path: parent, ...identity(fs.lstatSync(parent, { bigint: true })) }));
    assertParents();
    let descriptor = null, primary = null;
    try {
      // Exclusive creation never adopts an old PID-named record. Failed initial
      // publication stays explicit; cleanup will not remove unverified bytes.
      descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      expected = { ...identity(fs.fstatSync(descriptor, { bigint: true })), sha256: digest(body), bytes: body.length };
      fs.writeFileSync(descriptor, body); fs.fsyncSync(descriptor);
    } catch (error) {
      primary = error.code === 'EEXIST' ? refusal('initial_state_conflict', error) : error; throw primary;
    } finally {
      if (descriptor !== null) {
        try { fs.closeSync(descriptor); }
        catch (error) { if (primary) primary.close_error = { code: error.code, message: error.message }; else throw error; }
      }
    }
    assertOwned(); return next;
  }
  function write(value) {
    const next = payload(value), body = serialize(next);
    assertOwned();
    writeFileAtomicContained(file, body, root, { hooks: {
      renameSync(temporary, destination) {
        // The check repeats on every atomic writer retry. After our rename,
        // ownership follows the exact temporary inode that was published.
        assertOwned();
        if (destination !== file || path.dirname(temporary) !== directory) throw refusal('unexpected_atomic_destination');
        const nextIdentity = { ...identity(physicalFile(temporary)), sha256: digest(body), bytes: body.length };
        fs.renameSync(temporary, destination); expected = nextIdentity;
      }
    } });
    assertOwned(); return next;
  }
  function remove() {
    if (removed || !expected) return { status: removed ? 'removed' : 'not_created' };
    assertOwned();
    // This is a bounded ownership check, not an atomic pathname compare/delete.
    fs.unlinkSync(file); expected = null; removed = true;
    return { status: 'removed' };
  }
  return { attemptId, watcherId, get filePath() { return file; }, initialize, write, remove, assertOwned, assertScope: assertParents };
}

module.exports = { createWatcherStateStore, MAX_STATE_BYTES, readAutomationStatus, updateAutomationStatus };
