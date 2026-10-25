'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { assertSafeContainedPath, assertSafeContainmentRoot } = require('./json-store');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function uniqueRoots(values) {
  const seen = new Set();
  const rows = [];
  for (const value of values) {
    if (!value) continue;
    const resolved = path.resolve(value);
    const key = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push(resolved);
  }
  return rows;
}

function rootsForPolicy(context, policy = 'curated') {
  if (policy === 'runtime') {
    return uniqueRoots([context.stateRoot, context.projectKnowledgeRoot]);
  }
  if (policy === 'target') {
    return uniqueRoots([context.targetRoot]);
  }
  return uniqueRoots([context.projectKnowledgeRoot, context.stateRoot]);
}

function normalizeKnowledgeRelative(relative) {
  return String(relative || '')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\.knowledge\//, '')
    .replace(/\/+/g, '/');
}

function readContainedJsonFromRoot(root, relative, options = {}) {
  const normalized = normalizeKnowledgeRelative(relative);
  let file = path.resolve(root, ...normalized.split('/').filter(Boolean));
  let rootResolved = path.resolve(root);
  const relation = path.relative(rootResolved, file);
  if (relation.startsWith('..') || path.isAbsolute(relation)) {
    return { available: true, error: 'role_source_unsafe', file, root: rootResolved, relative: normalized };
  }
  if (!fs.existsSync(file)) {
    return { available: false, error: 'role_source_missing', file, root: rootResolved, relative: normalized };
  }
  try {
    rootResolved = assertSafeContainmentRoot(rootResolved);
    file = path.resolve(rootResolved, ...normalized.split('/').filter(Boolean));
    assertSafeContainedPath(rootResolved, file);
    const stat = fs.lstatSync(file, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink()) {
      return { available: true, error: 'role_source_unsafe', file, root: rootResolved, relative: normalized };
    }
    const maxBytes = Number.isFinite(Number(options.maxBytes)) ? Number(options.maxBytes) : null;
    if (maxBytes !== null && Number(stat.size) > maxBytes) {
      return { available: true, error: 'role_source_size_anomaly', file, root: rootResolved, relative: normalized, bytes: Number(stat.size) };
    }
    const changed = () => { throw Object.assign(new Error('Artifact changed physical identity or bytes while being read'), { code: 'contained_path_unsafe' }); };
    const same = (a, b) => ['dev', 'ino', 'size', 'nlink', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
    const parents = [];
    let parent = rootResolved;
    // A finite downward walk also respects Windows case-insensitive roots.
    for (const part of ['', ...path.relative(rootResolved, path.dirname(file)).split(path.sep).filter(Boolean)]) {
      if (part) parent = path.join(parent, part);
      const identity = fs.lstatSync(parent, { bigint: true });
      if (!identity.isDirectory() || identity.isSymbolicLink()) changed();
      parents.push({ path: parent, dev: identity.dev, ino: identity.ino });
    }
    // A file can become a FIFO after the path checks. O_NONBLOCK gets us to
    // fstat without a writer; it is not a deadline for slow regular-file I/O.
    const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    let raw;
    try {
      const opened = fs.fstatSync(fd, { bigint: true });
      if (!opened.isFile() || !same(stat, opened) || !Number.isSafeInteger(Number(opened.size))) changed();
      // Limit the read itself, including concurrent growth after the stat.
      const buffer = Buffer.alloc(Number(opened.size) + 1);
      let used = 0;
      while (used < buffer.length) {
        const count = fs.readSync(fd, buffer, used, buffer.length - used, null);
        if (!count) break;
        used += count;
      }
      const after = fs.fstatSync(fd, { bigint: true }), live = fs.lstatSync(file, { bigint: true });
      if (BigInt(used) !== opened.size || !after.isFile() || !live.isFile() || live.isSymbolicLink() ||
          !same(opened, after) || !same(after, live)) changed();
      raw = buffer.subarray(0, used);
    } finally { fs.closeSync(fd); }
    for (const parent of parents) {
      const live = fs.lstatSync(parent.path, { bigint: true });
      if (!live.isDirectory() || live.isSymbolicLink() || live.dev !== parent.dev || live.ino !== parent.ino) changed();
    }
    assertSafeContainedPath(rootResolved, file);
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw).replace(/^\uFEFF/, ''));
    return {
      available: true,
      error: null,
      file,
      root: rootResolved,
      relative: normalized,
      value,
      raw_sha256: sha256(raw),
      bytes: raw.length
    };
  } catch (error) {
    let code = 'role_source_invalid_json';
    if (error?.code === 'contained_path_unsafe') code = 'role_source_unsafe';
    else if (error?.code === 'EACCES' || error?.code === 'EPERM') code = 'role_source_unreadable';
    return { available: true, error: code, file, root: rootResolved, relative: normalized, detail: error.message };
  }
}

function readContainedJson(context, relative, policy = 'curated', options = {}) {
  const allRoots = rootsForPolicy(context, policy);
  const roots = options.allowFallback === false ? allRoots.slice(0, 1) : allRoots;
  const missing = [];
  for (const root of roots) {
    if (!fs.existsSync(root)) {
      missing.push({ root, reason: 'root_missing' });
      continue;
    }
    const result = readContainedJsonFromRoot(root, relative, options);
    if (!result.available) {
      missing.push({ root, file: result.file, reason: result.error });
      continue;
    }
    // Once a preferred root contains the artifact, invalid/unsafe state is
    // authoritative. Never fall back to a stale lower-priority copy.
    return { ...result, source_policy: policy, fallback_used: missing.length > 0, candidates: missing };
  }
  return { available: false, error: 'role_source_missing', file: null, root: null, source_policy: policy, candidates: missing };
}

module.exports = {
  normalizeKnowledgeRelative,
  rootsForPolicy,
  readContainedJsonFromRoot,
  readContainedJson
};
