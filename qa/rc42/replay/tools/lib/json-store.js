'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { removeTempDirStrict } = require('./strict-temp-cleanup');

function stripBom(value) {
  return typeof value === 'string' && value.charCodeAt(0) === 0xfeff ? value.slice(1) : value;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function pathIdentity(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32'
    ? resolved.toLowerCase()
    : resolved;
}

function containedPath(rootPath, candidatePath) {
  const root = path.resolve(rootPath);
  const candidate = path.resolve(candidatePath);
  const relative = path.relative(root, candidate);
  return relative === '' ||
    (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function containmentError(message) {
  const error = new Error(message);
  error.code = 'contained_path_unsafe';
  return error;
}

function assertSafeContainmentRoot(rootPath) {
  const root = path.resolve(rootPath);
  let stat;
  try {
    stat = fs.lstatSync(root);
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw containmentError(
        `Containment root does not exist: ${root}`
      );
    }
    throw error;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw containmentError(
      `Containment root is not a physical directory: ${root}`
    );
  }
  const real = fs.realpathSync(root);
  if (pathIdentity(real) !== pathIdentity(root)) {
    throw containmentError(
      `Containment root resolves through a reparse path: ${root}`
    );
  }
  return root;
}

function assertSafeContainedPath(
  rootPath,
  candidatePath,
  options = {}
) {
  const root = assertSafeContainmentRoot(rootPath);
  const candidate = path.resolve(candidatePath);
  if (!containedPath(root, candidate)) {
    throw containmentError(
      `Path escapes containment root: ${candidate}`
    );
  }
  const relative = path.relative(root, candidate);
  if (!relative) return candidate;
  const segments = relative.split(path.sep).filter(Boolean);
  let current = root;
  for (let index = 0; index < segments.length; index += 1) {
    current = path.join(current, segments[index]);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch (error) {
      if (
        error.code === 'ENOENT' &&
        options.allowMissing === true
      ) {
        return candidate;
      }
      throw error;
    }
    if (stat.isSymbolicLink()) {
      throw containmentError(
        `Path contains a symlink or junction: ${current}`
      );
    }
    if (index < segments.length - 1 && !stat.isDirectory()) {
      throw containmentError(
        `Path parent is not a directory: ${current}`
      );
    }
    const real = fs.realpathSync(current);
    if (
      pathIdentity(real) !== pathIdentity(current) ||
      !containedPath(root, real)
    ) {
      throw containmentError(
        `Path resolves outside its physical identity: ${current}`
      );
    }
  }
  return candidate;
}

function ensureContainedDir(rootPath, dirPath) {
  const root = assertSafeContainmentRoot(rootPath);
  const directory = path.resolve(dirPath);
  if (!containedPath(root, directory)) {
    throw containmentError(
      `Directory escapes containment root: ${directory}`
    );
  }
  const relative = path.relative(root, directory);
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      fs.mkdirSync(current);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw containmentError(
        `Contained directory is a symlink, junction, or file: ${current}`
      );
    }
    const real = fs.realpathSync(current);
    if (
      pathIdentity(real) !== pathIdentity(current) ||
      !containedPath(root, real)
    ) {
      throw containmentError(
        `Contained directory changed physical identity: ${current}`
      );
    }
  }
  return directory;
}

function sleepSync(ms) {
  const buffer = new SharedArrayBuffer(4);
  const view = new Int32Array(buffer);
  Atomics.wait(view, 0, 0, ms);
}

function readJson(filePath, fallback) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(stripBom(raw));
  } catch (error) {
    if (arguments.length >= 2 && (error.code === 'ENOENT' || error instanceof SyntaxError)) return fallback;
    throw error;
  }
}

const ATOMIC_RETRY_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);
const DEFAULT_ATOMIC_RETRY_DELAYS_MS = Object.freeze([50, 100, 200, 400, 800]);

function retryDelayMs(baseMs, random) {
  const sample = Number(random());
  const bounded = Number.isFinite(sample) ? Math.max(0, Math.min(1, sample)) : 0;
  return baseMs + Math.floor(baseMs * 0.1 * bounded);
}

function replaceFileWithRetry(tmpPath, filePath, hooks = {}) {
  const renameSync = hooks.renameSync || fs.renameSync;
  const wait = hooks.sleepSync || sleepSync;
  const random = hooks.random || Math.random;
  const retryDelays = Array.isArray(hooks.retryDelaysMs)
    ? hooks.retryDelaysMs
    : DEFAULT_ATOMIC_RETRY_DELAYS_MS;
  let attempts = 0;
  while (true) {
    attempts += 1;
    try {
      renameSync(tmpPath, filePath);
      return { attempts };
    } catch (error) {
      const retryable = ATOMIC_RETRY_CODES.has(error?.code);
      if (!retryable) throw error;
      if (attempts > retryDelays.length) {
        const exhausted = new Error(`Atomic rename failed after ${attempts} attempts: ${error.message}`);
        exhausted.code = 'atomic_write_retry_exhausted';
        exhausted.os_code = error.code || null;
        exhausted.attempts = attempts;
        exhausted.operation = 'rename';
        exhausted.cause = error;
        throw exhausted;
      }
      wait(retryDelayMs(Number(retryDelays[attempts - 1]) || 0, random));
    }
  }
}

function writeJsonAtomic(filePath, value, options = {}) {
  const body = JSON.stringify(value, null, 2) + '\n';
  return writeFileAtomic(filePath, body, options);
}

function writeJsonAtomicContained(
  filePath,
  value,
  containmentRoot,
  options = {}
) {
  const body = JSON.stringify(value, null, 2) + '\n';
  return writeFileAtomicContained(
    filePath,
    body,
    containmentRoot,
    options
  );
}

function writeFileAtomicContained(
  filePath,
  body,
  containmentRoot,
  options = {}
) {
  const root = assertSafeContainmentRoot(containmentRoot);
  const target = path.resolve(filePath);
  if (!containedPath(root, target)) {
    throw containmentError(
      `Atomic write target escapes containment root: ${target}`
    );
  }
  const parent = ensureContainedDir(root, path.dirname(target));
  if (fs.existsSync(target)) {
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw containmentError(
        `Atomic write target is not a physical file: ${target}`
      );
    }
    assertSafeContainedPath(root, target);
  }
  const tmpPath = path.join(
    parent,
    `.${path.basename(target)}.tmp-${process.pid}-` +
      `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`
  );
  let descriptor = null;
  let primaryError = null;
  try {
    descriptor = fs.openSync(tmpPath, 'wx');
    fs.writeFileSync(
      descriptor,
      body,
      options.encoding || 'utf8'
    );
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertSafeContainedPath(root, parent);
    if (fs.existsSync(target)) {
      assertSafeContainedPath(root, target);
    }
    replaceFileWithRetry(
      tmpPath,
      target,
      options.hooks || {}
    );
    assertSafeContainedPath(root, target);
    return undefined;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
    if (fs.existsSync(tmpPath)) {
      try {
        fs.unlinkSync(tmpPath);
        if (primaryError) {
          primaryError.temp_cleanup_status = 'removed';
        }
      } catch (cleanupError) {
        if (primaryError) {
          primaryError.temp_cleanup_status = 'failed';
          primaryError.temp_cleanup_error_code =
            cleanupError.code || null;
        } else {
          throw cleanupError;
        }
      }
    }
  }
}

function appendNdjsonContained(
  filePath,
  event,
  containmentRoot,
  options = {}
) {
  const target = path.resolve(filePath);
  let prior = '';
  if (fs.existsSync(target)) {
    assertSafeContainedPath(containmentRoot, target);
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw containmentError(
        `NDJSON target is not a physical file: ${target}`
      );
    }
    prior = fs.readFileSync(target, 'utf8');
  }
  return writeFileAtomicContained(
    target,
    `${prior}${JSON.stringify(event)}\n`,
    containmentRoot,
    options
  );
}

function writeFileAtomic(filePath, body, options = {}) {
  ensureDir(path.dirname(filePath));
  const tmpPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  let primaryError = null;
  try {
    if (options.backup && fs.existsSync(filePath)) {
      const backupPath = `${filePath}.bak-${new Date().toISOString().replace(/[:.]/g, '-')}`;
      fs.copyFileSync(filePath, backupPath);
    }
    fs.writeFileSync(tmpPath, body, 'utf8');
    replaceFileWithRetry(tmpPath, filePath, options.hooks || {});
    return undefined;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    if (fs.existsSync(tmpPath)) {
      try {
        fs.unlinkSync(tmpPath);
        if (primaryError) primaryError.temp_cleanup_status = 'removed';
      } catch (cleanupError) {
        if (primaryError) {
          primaryError.temp_cleanup_status = 'failed';
          primaryError.temp_cleanup_error_code = cleanupError.code || null;
        } else {
          throw cleanupError;
        }
      }
    } else if (primaryError) {
      primaryError.temp_cleanup_status = 'not_present';
    }
  }
}

function updateJsonAtomic(filePath, updater, fallback = {}) {
  const current = readJson(filePath, fallback);
  const next = updater(current) || current;
  writeJsonAtomic(filePath, next);
  return next;
}

function removeDirRecursive(dirPath, options = {}) {
  return removeTempDirStrict(dirPath, options);
}

function getAgentId() {
  return process.env.KNOWLEDGE_AGENT_ID || `${os.hostname()}-${process.pid}`;
}

function appendNdjson(filePath, event) {
  ensureDir(path.dirname(filePath));
  fs.appendFileSync(filePath, JSON.stringify(event) + '\n', 'utf8');
}

function normalizeRelative(filePath) {
  return String(filePath || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

module.exports = {
  stripBom,
  ensureDir,
  readJson,
  writeJsonAtomic,
  writeFileAtomic,
  writeJsonAtomicContained,
  writeFileAtomicContained,
  appendNdjsonContained,
  assertSafeContainmentRoot,
  assertSafeContainedPath,
  ensureContainedDir,
  containedPath,
  updateJsonAtomic,
  appendNdjson,
  normalizeRelative,
  getAgentId,
  sleepSync,
  __test: {
    replaceFileWithRetry,
    removeDirRecursive,
    retryDelayMs,
    ATOMIC_RETRY_CODES,
    DEFAULT_ATOMIC_RETRY_DELAYS_MS
  }
};
