'use strict';

// One atomic container is the commit point for a report with several views.
// A reader never stitches together individually replaced public view files.
// This also bounds disk use: no ever-growing chain of immutable generations.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { performance } = require('perf_hooks');
const { ensurePhysicalRoot, ensureContainedDir, assertSafeContainedFile, writeFileAtomicContained } = require('./json-store');
const { readStableFile, decodeUtf8 } = require('./stable-file');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');
const SCHEMA = 'knowledge-report-generation.v1';
const CURRENT = 'CURRENT.json';
const FORMAT = '.generation-format.json';
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_CONTAINER_BYTES = 256 * 1024 * 1024;
const MAX_FILES = 32;
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const error = (code, message, details = {}) => Object.assign(new Error(message), { code, ...details });
function filename(name) {
  if (typeof name !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(name) ||
      /^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/i.test(name) || /[.]$/.test(name) ||
      [CURRENT.toLowerCase(), 'locks'].includes(name.toLowerCase())) throw error('report_filename_invalid', 'Report views require portable plain file names');
  return name;
}
function validateNames(names) {
  if (!Array.isArray(names) || names.length < 1 || names.length > MAX_FILES) throw error('report_file_set_invalid', 'Invalid report view count');
  const seen = new Set();
  for (const name of names) {
    filename(name);
    const key = name.toLowerCase();
    if (seen.has(key)) throw error('report_file_set_invalid', 'Report view names must be distinct on every supported platform');
    seen.add(key);
  }
}
function prepareReportOutput(rootPath, directoryPath, names) {
  validateNames(names);
  const root = ensurePhysicalRoot(rootPath);
  const directory = ensureContainedDir(root, directoryPath);
  for (const name of [...names, CURRENT, FORMAT]) assertSafeContainedFile(root, path.join(directory, name), { allowMissing: true });
  return { root, directory };
}
function syncDirectory(root, directory, requiredFile = CURRENT) {
  // Windows Node does not expose a portable directory FlushFileBuffers handle.
  // File fsync + atomic replacement still provides process-crash atomicity;
  // power-loss durability is not inferred from that property.
  if (process.platform === 'win32') return 'file_fsync_atomic_replace';
  const before = fs.lstatSync(directory, { bigint: true });
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino) throw error('report_directory_changed', 'Report directory changed before persistence');
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  const live = fs.lstatSync(directory, { bigint: true });
  if (!live.isDirectory() || live.isSymbolicLink() || live.dev !== before.dev || live.ino !== before.ino) throw error('report_directory_changed', 'Report directory changed during persistence');
  assertSafeContainedFile(root, path.join(directory, requiredFile));
  return 'file_and_directory_fsync_atomic_replace';
}
function parseSnapshot(body) {
  let value;
  try { value = JSON.parse(decodeUtf8(body)); } catch (cause) { throw error('report_generation_invalid', 'Committed report is not valid UTF-8 JSON', { cause }); }
  if (!value || value.schema !== SCHEMA || !/^[a-f0-9]{32}$/.test(value.generation || '') ||
      !value.files || typeof value.files !== 'object' || Array.isArray(value.files)) throw error('report_generation_invalid', 'Invalid report generation envelope');
  const names = Object.keys(value.files);
  validateNames(names);
  const files = Object.create(null);
  let total = 0;
  for (const name of names) {
    const file = value.files[name];
    if (!file || file.encoding !== 'utf8' || typeof file.body !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256 || '') ||
        !Number.isSafeInteger(file.bytes) || file.bytes < 0 || file.bytes > MAX_FILE_BYTES) throw error('report_generation_invalid', 'Invalid report view descriptor');
    const bytes = Buffer.from(file.body, 'utf8');
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES || file.bytes !== bytes.length || sha(bytes) !== file.sha256) throw error('report_generation_invalid', 'Report view does not match its committed digest');
    files[name] = bytes;
  }
  return { generation: value.generation, created_at: value.created_at, files, snapshot_sha256: sha(body), schema: SCHEMA };
}
function readReportGeneration(root, directory, options = {}) {
  const file = path.join(directory, CURRENT);
  const deadline = performance.now() + (options.retryBudgetMs === undefined ? 1000 : options.retryBudgetMs);
  let last;
  for (let attempt = 0; attempt < 4; attempt++) {
    try { return parseSnapshot(readStableFile(root, file, { maxBytes: MAX_CONTAINER_BYTES })); }
    catch (cause) {
      last = cause;
      if (cause.code !== 'stable_file_changed' || performance.now() >= deadline) throw cause;
    }
  }
  throw error('report_generation_busy', 'Report changed repeatedly during a bounded read; retry the operation', { cause: last });
}
function readReportFile(root, group, name, fallback) {
  filename(name);
  const directory = path.resolve(root, group);
  try {
    const snapshot = readReportGeneration(root, directory);
    if (!Object.hasOwn(snapshot.files, name)) throw error('report_view_missing', 'The committed report does not contain the requested view');
    return snapshot.files[name];
  } catch (cause) {
    if (cause.code !== 'ENOENT') throw cause;
    // Legacy migration is allowed only when no generation format exists.
    // Once migrated, a missing/damaged commit must never expose stale views.
    for (const marker of [CURRENT, FORMAT]) {
      try { fs.lstatSync(path.join(directory, marker)); throw error('report_generation_missing', 'The committed generation is unavailable; regenerate the report'); }
      catch (check) { if (check.code !== 'ENOENT') throw check; }
    }
    let body;
    try { body = readStableFile(root, path.join(directory, name), { maxBytes: MAX_FILE_BYTES }); }
    catch (legacy) { if (legacy.code === 'ENOENT' && arguments.length >= 4) return fallback; throw legacy; }
    // A first publication racing this legacy read must use the commit.
    try { fs.lstatSync(path.join(directory, CURRENT)); return readReportGeneration(root, directory).files[name]; }
    catch (check) { if (check.code !== 'ENOENT') throw check; }
    return body;
  }
}
function readReportJson(root, group, name, fallback) {
  const missing = Symbol('missing');
  const body = readReportFile(root, group, name, missing);
  if (body === missing) return fallback;
  // Invalid committed or legacy bytes remain visible as an error.
  return JSON.parse(decodeUtf8(body));
}
function publishReportGeneration(rootPath, directoryPath, views, options = {}) {
  if (!views || typeof views !== 'object' || Array.isArray(views)) throw error('report_file_set_invalid', 'Expected report views');
  const names = Object.keys(views).sort();
  const { root, directory } = prepareReportOutput(rootPath, directoryPath, names);
  const generation = crypto.randomBytes(16).toString('hex');
  const files = Object.create(null);
  let total = 0;
  for (const name of names) {
    if (typeof views[name] !== 'string' && !Buffer.isBuffer(views[name])) throw error('report_body_invalid', 'Report body must be text or a UTF-8 buffer');
    const bytes = Buffer.isBuffer(views[name]) ? views[name] : Buffer.from(views[name], 'utf8');
    const body = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    total += bytes.length;
    if (bytes.length > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES) throw error('report_body_too_large', 'Report exceeds the admitted size limit');
    files[name] = { encoding: 'utf8', body, bytes: bytes.length, sha256: sha(bytes) };
  }
  const snapshot = JSON.stringify({ schema: SCHEMA, generation, created_at: new Date().toISOString(), files }) + '\n';
  if (Buffer.byteLength(snapshot) > MAX_CONTAINER_BYTES) throw error('report_body_too_large', 'Encoded report exceeds the container limit');
  const publish = () => {
    prepareReportOutput(root, directory, names);
    let commitState = 'not_attempted';
    try {
      // Establish the migration fence before the first new-format commit.
      // An interrupted first migration can require regeneration, but can
      // never later resurrect uncommitted compatibility views.
      writeFileAtomicContained(path.join(directory, FORMAT), JSON.stringify({ schema: SCHEMA }) + '\n', root);
      syncDirectory(root, directory, FORMAT);
      options.beforeCommit?.({ generation });
      commitState = 'unconfirmed';
      writeFileAtomicContained(path.join(directory, CURRENT), snapshot, root, { hooks: options.writeHooks });
      const durability = syncDirectory(root, directory);
      commitState = 'committed';
      options.afterCommit?.({ generation });
      const mirrorErrors = [];
      for (const name of names) {
        try {
          options.beforeMirror?.(name);
          writeFileAtomicContained(path.join(directory, name), files[name].body, root, { hooks: options.mirrorHooks });
        } catch (cause) { mirrorErrors.push({ file: name, code: cause.code || 'write_failed', message: cause.message }); }
      }
      return { schema: SCHEMA, generation, snapshot: path.join(directory, CURRENT), snapshot_sha256: sha(snapshot),
        commit_state: 'committed', durability, mirrors_complete: mirrorErrors.length === 0, mirror_errors: mirrorErrors };
    } catch (cause) {
      cause.report_publication = { generation, commit_state: commitState, snapshot: path.join(directory, CURRENT) };
      throw cause;
    }
  };
  return withContainedLock({ context: { stateRoot: directory }, rootPath: directory, rootKind: 'state',
    lockName: 'report-generation', purpose: LOCKS['report-generation'].purpose }, publish);
}
module.exports = { SCHEMA, CURRENT, FORMAT, MAX_FILE_BYTES, MAX_TOTAL_BYTES, prepareReportOutput,
  publishReportGeneration, readReportGeneration, readReportFile, readReportJson };
