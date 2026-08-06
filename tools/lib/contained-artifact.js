'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { assertSafeContainedPath } = require('./json-store');

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
  const file = path.resolve(root, ...normalized.split('/').filter(Boolean));
  const rootResolved = path.resolve(root);
  const relation = path.relative(rootResolved, file);
  if (relation.startsWith('..') || path.isAbsolute(relation)) {
    return { available: true, error: 'role_source_unsafe', file, root: rootResolved, relative: normalized };
  }
  if (!fs.existsSync(file)) {
    return { available: false, error: 'role_source_missing', file, root: rootResolved, relative: normalized };
  }
  try {
    assertSafeContainedPath(rootResolved, file);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      return { available: true, error: 'role_source_unsafe', file, root: rootResolved, relative: normalized };
    }
    const maxBytes = Number.isFinite(Number(options.maxBytes)) ? Number(options.maxBytes) : null;
    if (maxBytes !== null && stat.size > maxBytes) {
      return { available: true, error: 'role_source_size_anomaly', file, root: rootResolved, relative: normalized, bytes: stat.size };
    }
    const raw = fs.readFileSync(file);
    const value = JSON.parse(raw.toString('utf8').replace(/^\uFEFF/, ''));
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
    return { ...result, source_policy: policy, fallback_used: false, candidates: missing };
  }
  return { available: false, error: 'role_source_missing', file: null, root: null, source_policy: policy, candidates: missing };
}

module.exports = {
  normalizeKnowledgeRelative,
  rootsForPolicy,
  readContainedJsonFromRoot,
  readContainedJson
};
