'use strict';

// Bounded reads bind the file and every parent to one physical identity.
// O_NONBLOCK prevents a swapped FIFO from trapping open(); it does not turn
// regular-file I/O into a deadline. Run storage work behind a control process.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertSafeContainmentRoot, assertSafeContainedPath } = require('./json-store');
const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function same(a, b) {
  return ['dev', 'ino', 'size', 'nlink', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);
}
function readStableFile(rootPath, filePath, options = {}) {
  const maxBytes = options.maxBytes === undefined ? DEFAULT_MAX_BYTES : options.maxBytes;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 1024 * 1024 * 1024) {
    throw failure('stable_file_limit_invalid', 'A finite file-size limit is required');
  }
  const root = assertSafeContainmentRoot(rootPath);
  const file = assertSafeContainedPath(root, filePath);
  const parents = [];
  let parent = root;
  for (const part of ['', ...path.relative(root, path.dirname(file)).split(path.sep).filter(Boolean)]) {
    if (part) parent = path.join(parent, part);
    const stat = fs.lstatSync(parent, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw failure('stable_file_unsafe', 'A file parent is not physical');
    parents.push({ path: parent, dev: stat.dev, ino: stat.ino });
  }
  const before = fs.lstatSync(file, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw failure('stable_file_unsafe', 'Expected an unshared regular file');
  }
  if (before.size < 0n || before.size > BigInt(maxBytes)) throw failure('stable_file_too_large', 'File exceeds the admitted size limit');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let body;
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile() || !same(before, opened)) throw failure('stable_file_changed', 'File changed before it could be read');
    // At most the admitted initial size plus one byte, even if a concurrent
    // writer keeps extending the file. Never read until unbounded EOF.
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < buffer.length) {
      const n = fs.readSync(fd, buffer, used, Math.min(64 * 1024, buffer.length - used), null);
      if (!n) break;
      used += n;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const live = fs.lstatSync(file, { bigint: true });
    if (BigInt(used) !== opened.size || !after.isFile() || !live.isFile() || live.isSymbolicLink() ||
        !same(opened, after) || !same(after, live)) throw failure('stable_file_changed', 'File changed while it was read');
    body = buffer.subarray(0, used);
  } finally { fs.closeSync(fd); }
  for (const expected of parents) {
    const live = fs.lstatSync(expected.path, { bigint: true });
    if (!live.isDirectory() || live.isSymbolicLink() || live.dev !== expected.dev || live.ino !== expected.ino) {
      throw failure('stable_file_changed', 'File parent changed while it was read');
    }
  }
  assertSafeContainedPath(root, file);
  return body;
}
function decodeUtf8(body) { return new TextDecoder('utf-8', { fatal: true }).decode(body).replace(/^\uFEFF/, ''); }
function readStableJson(root, file, options = {}) { return JSON.parse(decodeUtf8(readStableFile(root, file, options))); }
function stableFileHash(root, file, options = {}) { return crypto.createHash('sha256').update(readStableFile(root, file, options)).digest('hex'); }
module.exports = { readStableFile, readStableJson, stableFileHash, decodeUtf8, DEFAULT_MAX_BYTES };
