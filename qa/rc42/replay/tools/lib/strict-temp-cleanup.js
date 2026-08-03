'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const RETRYABLE = new Set(['EBUSY', 'EPERM', 'ENOTEMPTY']);

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function removeTempDirStrict(dir, options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('cleanup options must be an object');
  const attempts = options.attempts ?? 8;
  const initialDelayMs = options.initialDelayMs ?? 25;
  const maxDelayMs = options.maxDelayMs ?? 1600;
  const maxElapsedMs = options.maxElapsedMs ?? 5000;
  const remove = options.remove ?? ((target) => fs.rmSync(target, { recursive: true, force: true, maxRetries: 0 }));
  const exists = options.exists ?? ((target) => fs.existsSync(target));
  const listEntries = options.listEntries ?? ((target) => fs.readdirSync(target).slice(0, 100));
  const wait = options.sleep ?? sleep;
  if (!Number.isInteger(attempts) || attempts < 1) throw new TypeError('attempts must be an integer >= 1');
  if (!Number.isFinite(initialDelayMs) || initialDelayMs < 0) throw new TypeError('initialDelayMs must be finite and >= 0');
  if (!Number.isFinite(maxDelayMs) || maxDelayMs < 0) throw new TypeError('maxDelayMs must be finite and >= 0');
  if (!Number.isFinite(maxElapsedMs) || maxElapsedMs <= 0) throw new TypeError('maxElapsedMs must be finite and > 0');
  if (typeof remove !== 'function') throw new TypeError('remove must be a function');
  if (typeof exists !== 'function') throw new TypeError('exists must be a function');
  if (typeof listEntries !== 'function') throw new TypeError('listEntries must be a function');
  if (typeof wait !== 'function') throw new TypeError('sleep must be a function');
  const started = process.hrtime.bigint();
  const diagnostics = [];
  let originalError = null;
  const elapsedMs = () => Number(process.hrtime.bigint() - started) / 1e6;
  const directoryExists = () => Boolean(exists(dir));
  const remainingEntries = () => {
    try {
      if (!directoryExists()) return [];
      const entries = listEntries(dir);
      return Array.isArray(entries) ? entries.slice(0, 100).map(String) : ['<invalid-listEntries-result>'];
    } catch (error) {
      return [`<unreadable:${error.code || 'UNKNOWN'}>`];
    }
  };
  const failure = (reason, lastCode, cause) => {
    const error = new Error(`Temporary fixture cleanup failed: ${dir}; ${reason}; ${JSON.stringify(diagnostics)}`, { cause });
    error.name = 'TempFixtureCleanupError';
    error.code = 'TEMP_FIXTURE_CLEANUP_FAILED';
    error.reason = reason;
    error.directory = dir;
    error.attempts = diagnostics.length;
    error.elapsed_ms = elapsedMs();
    error.last_error_code = lastCode;
    error.diagnostics = diagnostics;
    error.remaining_entries = remainingEntries();
    return error;
  };
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    let code = null;
    let message = null;
    try {
      remove(dir);
      if (!directoryExists()) return { status: 'removed', attempts: attempt, elapsed_ms: elapsedMs(), diagnostics };
      code = 'STILL_EXISTS';
      message = 'remove returned but directory still exists';
      originalError ||= Object.assign(new Error(message), { code });
    } catch (error) {
      originalError ||= error;
      code = error.code || 'UNKNOWN';
      message = error.message;
    }
    if (code === 'STILL_EXISTS') {
      diagnostics.push({ attempt, elapsed_ms: elapsedMs(), delay_ms: 0, code, message, directory_exists: directoryExists(), remaining_entries: remainingEntries() });
      throw failure('cleanup_postcondition_failed', code, originalError);
    }
    if (!RETRYABLE.has(code)) {
      diagnostics.push({ attempt, elapsed_ms: elapsedMs(), delay_ms: 0, code, message, directory_exists: directoryExists(), remaining_entries: remainingEntries() });
      throw failure('non_retryable_cleanup_error', code, originalError);
    }
    const delay = Math.min(initialDelayMs * (2 ** (attempt - 1)), maxDelayMs, Math.max(0, maxElapsedMs - elapsedMs()));
    const terminal = attempt === attempts || elapsedMs() >= maxElapsedMs;
    diagnostics.push({ attempt, elapsed_ms: elapsedMs(), delay_ms: terminal ? 0 : delay, code, message, directory_exists: directoryExists(), remaining_entries: remainingEntries() });
    if (terminal) throw failure('persistent_resource_lock', code, originalError);
    if (delay > 0) wait(delay);
  }
  throw failure('persistent_resource_lock', diagnostics.at(-1)?.code || 'UNKNOWN', originalError);
}

function withTempFixture(options, callback) {
  if (!options || typeof options !== 'object') throw new TypeError('fixture options must be an object');
  if (typeof callback !== 'function') throw new TypeError('fixture callback must be a function');
  const prefix = options.prefix ?? 'knowledge-fixture-';
  const baseDir = path.resolve(options.baseDir ?? os.tmpdir());
  const evidenceDir = options.evidenceDir ? path.resolve(options.evidenceDir) : null;
  const keepOnFailure = options.keepOnFailure ?? false;
  if (typeof prefix !== 'string' || !prefix || /[\\/]/.test(prefix)) throw new TypeError('fixture prefix must be a non-empty base name');
  if (typeof keepOnFailure !== 'boolean') throw new TypeError('keepOnFailure must be boolean');
  fs.mkdirSync(baseDir, { recursive: true });
  const dir = fs.mkdtempSync(path.join(baseDir, prefix));
  const fixtureId = path.basename(dir);
  fs.writeFileSync(path.join(dir, '.fixture-id.json'), `${JSON.stringify({ fixture_id: fixtureId, created_at: new Date().toISOString() }, null, 2)}\n`, 'utf8');
  let callbackResult;
  let callbackError = null;
  let preservationError = null;
  let evidencePath = null;
  try {
    callbackResult = callback(dir);
  } catch (error) {
    callbackError = error;
    const preservationRoot = evidenceDir || (keepOnFailure ? path.join(baseDir, 'knowledge-fixture-failures') : null);
    if (preservationRoot) {
      try {
        fs.mkdirSync(preservationRoot, { recursive: true });
        const label = String(options.evidenceLabel ?? prefix).replace(/[^a-z0-9_.-]+/gi, '-').replace(/^-+|-+$/g, '') || 'fixture';
        evidencePath = path.join(preservationRoot, `${label}-${process.pid}-${Date.now()}`);
        fs.cpSync(dir, evidencePath, { recursive: true });
        fs.writeFileSync(path.join(evidencePath, 'failure.txt'), `${error.stack || error.message}\n`, 'utf8');
        error.fixture_evidence_path = evidencePath;
      } catch (errorDuringPreservation) {
        preservationError = errorDuringPreservation;
      }
    }
  }

  let cleanupError = null;
  try { removeTempDirStrict(dir, options.cleanupOptions || {}); } catch (error) { cleanupError = error; }

  if (callbackError && (preservationError || cleanupError)) {
    const errors = [callbackError];
    if (preservationError) errors.push(preservationError);
    if (cleanupError) errors.push(cleanupError);
    const combined = new AggregateError(errors, 'Temporary fixture callback failed and fixture finalization was incomplete', { cause: callbackError });
    combined.name = 'TempFixtureLifecycleError';
    combined.code = 'TEMP_FIXTURE_CALLBACK_AND_CLEANUP_FAILED';
    combined.fixture_id = fixtureId;
    combined.fixture_directory = dir;
    combined.fixture_evidence_path = evidencePath;
    combined.callback_error = callbackError;
    combined.preservation_error = preservationError;
    combined.cleanup_error = cleanupError;
    throw combined;
  }
  if (callbackError) throw callbackError;
  if (cleanupError) throw cleanupError;
  return callbackResult;
}

module.exports = { removeTempDirStrict, withTempFixture, RETRYABLE };
