'use strict';

const { types: { isProxy } } = require('node:util');
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
function invalid() {
  const error = new Error('Module ownership requires safe project-relative boundaries and plain data.');
  error.code = 'module_ownership_invalid';
  throw error;
}
// Reject proxies before every reflective operation, including revoked proxies.
// Return descriptor-value snapshots: callers never consume unchecked getters.
function validatedOwnObject(value) {
  if (isProxy(value) || !value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const data = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || forbidden.has(key)) invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !own(descriptor, 'value')) invalid();
    data[key] = descriptor.value;
  }
  return data;
}
function validatedOwnArray(value) {
  if (isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid();
  const keys = Reflect.ownKeys(value);
  const length = Object.getOwnPropertyDescriptor(value, 'length');
  if (!length || length.enumerable || !own(length, 'value') || keys.length !== length.value + 1) invalid();
  const data = [];
  for (const key of keys) {
    if (key === 'length') continue;
    if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= length.value) invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !own(descriptor, 'value')) invalid();
    data[Number(key)] = descriptor.value;
  }
  return data;
}
function moduleData(value) {
  const data = validatedOwnObject(value);
  if (!own(data, 'module_id') || typeof data.module_id !== 'string' ||
      !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(data.module_id) || forbidden.has(data.module_id)) invalid();
  return data;
}
function normalizeOwnershipPath(value, allowRoot = false) {
  if (typeof value !== 'string' || !value || value !== value.trim()) invalid();
  const normalized = value.replace(/\\/g, '/');
  if (normalized === '.' && allowRoot) return normalized;
  if (/^[\/]|[\x00-\x1f\x7f:*?<>"|]/.test(normalized)) invalid();
  const body = normalized.endsWith('/') ? normalized.slice(0, -1) : normalized;
  if (!body || body.split('/').some(part => !part || part === '.' || part === '..' ||
      part !== part.trim() || /[. ]$/.test(part) || forbidden.has(part) ||
      /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) invalid();
  return body;
}
function pathComparisonIdentity(value) {
  return process.platform === 'win32' ? value.toLowerCase() : value;
}
function assertNoPathAliases(values) {
  const spellings = new Map();
  for (const value of values) {
    const file = normalizeOwnershipPath(value, true);
    const segments = file.split('/');
    for (let index = 1; index <= segments.length; index++) {
      const spelling = segments.slice(0, index).join('/');
      const identity = pathComparisonIdentity(spelling);
      if (spellings.has(identity) && spellings.get(identity) !== spelling) invalid();
      spellings.set(identity, spelling);
    }
  }
}
function normalizedOwnershipPaths(moduleInfo) {
  const data = moduleData(moduleInfo);
  if (!own(data, 'ownership_paths')) return [];
  const paths = validatedOwnArray(data.ownership_paths).map(value => {
    const boundary = normalizeOwnershipPath(value);
    return boundary + (/[\\/]$/.test(value) ? '/' : '');
  });
  assertNoPathAliases(paths);
  return [...new Set(paths)].sort();
}
function moduleOwnershipBoundaries(moduleInfo) {
  const data = moduleData(moduleInfo);
  const additional = normalizedOwnershipPaths(data);
  const boundaries = [];
  if (own(data, 'path')) {
    const primary = normalizeOwnershipPath(data.path, true);
    // Legacy primary paths denote directories, with or without a slash.
    if (primary !== '.') boundaries.push({ path: primary, directory: true });
  }
  for (const value of additional) boundaries.push({
    path: normalizeOwnershipPath(value), directory: value.endsWith('/')
  });
  assertNoPathAliases(boundaries.map(boundary => boundary.path));
  return boundaries;
}
function normalizedConditionalDependencies(moduleInfo) {
  const data = moduleData(moduleInfo);
  if (!own(data, 'conditional_dependencies')) return [];
  const targets = new Map();
  const allPaths = [];
  for (const value of validatedOwnArray(data.conditional_dependencies)) {
    const edge = validatedOwnObject(value);
    if (Reflect.ownKeys(edge).some(key => !['module_id', 'when_paths'].includes(key)) ||
        !own(edge, 'module_id') || typeof edge.module_id !== 'string' ||
        !/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(edge.module_id) ||
        forbidden.has(edge.module_id) || !own(edge, 'when_paths')) invalid();
    const paths = validatedOwnArray(edge.when_paths);
    if (!paths.length) invalid();
    const merged = targets.get(edge.module_id) || new Set();
    for (const pathValue of paths) {
      const boundary = normalizeOwnershipPath(pathValue);
      const typed = boundary + (/[\\/]$/.test(pathValue) ? '/' : '');
      merged.add(typed);
      allPaths.push(typed);
    }
    targets.set(edge.module_id, merged);
  }
  assertNoPathAliases(allPaths);
  return [...targets].sort(([left], [right]) => left.localeCompare(right))
    .map(([module_id, paths]) => ({ module_id, when_paths: [...paths].sort() }));
}
function moduleExplicitReferences(moduleInfo) {
  const data = moduleData(moduleInfo);
  const references = ['key_files', 'evidence_files'].flatMap(key => !own(data, key) ? [] :
    validatedOwnArray(data[key]).map(value => normalizeOwnershipPath(
      typeof value === 'string' ? value : validatedOwnObject(value).path)));
  assertNoPathAliases(references);
  return references;
}
// One typed registry/card union for routing, factual review and maintenance.
// Never let object spread silently replace a conflicting primary boundary.
function mergeModuleDeclaration(registeredValue, cardValue = {}) {
  const { copyInertData } = require('./json-transaction');
  const registered = validatedOwnObject(copyInertData(registeredValue));
  const card = validatedOwnObject(copyInertData(cardValue));
  if (own(card, 'module_id') && card.module_id !== registered.module_id) invalid();
  if (own(card, 'path') && own(registered, 'path') &&
      normalizeOwnershipPath(card.path, true) !== normalizeOwnershipPath(registered.path, true)) invalid();
  const item = { ...card, ...registered };
  for (const key of ['key_files', 'evidence_files', 'entry_points', 'ownership_paths', 'conditional_dependencies', 'dependencies', 'depends_on']) {
    const fromCard = own(card, key) ? validatedOwnArray(card[key]) : [];
    const fromRegistry = own(registered, key) ? validatedOwnArray(registered[key]) : [];
    if (fromCard.length || fromRegistry.length) {
      const seen = new Set();
      item[key] = [...fromCard, ...fromRegistry].filter(value => {
        const identity = JSON.stringify(value);
        if (seen.has(identity)) return false;
        seen.add(identity); return true;
      });
    }
  }
  moduleOwnershipBoundaries(item); moduleExplicitReferences(item); normalizedConditionalDependencies(item);
  return item;
}
function validatedModuleRegistry(registry, allowModuleMap = false) {
  const data = validatedOwnObject(registry);
  if (!own(data, 'modules')) invalid();
  // isProxy must precede Array.isArray, which throws on revoked proxies.
  if (isProxy(data.modules)) invalid();
  const values = Array.isArray(data.modules) ? validatedOwnArray(data.modules) :
    allowModuleMap ? Object.values(validatedOwnObject(data.modules)) : invalid();
  const modules = values.map(moduleData);
  const ids = new Set();
  const paths = [];
  for (const moduleInfo of modules) {
    if (ids.has(moduleInfo.module_id)) invalid();
    ids.add(moduleInfo.module_id);
    paths.push(...moduleOwnershipBoundaries(moduleInfo).map(row => row.path),
      ...moduleExplicitReferences(moduleInfo),
      ...normalizedConditionalDependencies(moduleInfo).flatMap(row => row.when_paths));
  }
  assertNoPathAliases(paths);
  return { ...data, modules };
}
function boundaryContains(boundary, file) {
  const base = pathComparisonIdentity(boundary.path);
  const candidate = pathComparisonIdentity(file);
  return candidate === base || (boundary.directory && candidate.startsWith(base + '/'));
}
function inferModuleOwners(file, registry) {
  const normalized = normalizeOwnershipPath(file);
  const modules = validatedModuleRegistry(registry).modules;
  const identity = pathComparisonIdentity(normalized);
  const entries = modules.map(moduleInfo => ({
    moduleInfo, boundaries: moduleOwnershipBoundaries(moduleInfo), references: moduleExplicitReferences(moduleInfo)
  }));
  const explicit = entries.filter(entry => entry.references.some(reference => pathComparisonIdentity(reference) === identity));
  // Routing retains all explicit claimants of a shared file. The singular
  // compatibility API still returns one deterministic longest-boundary owner.
  if (explicit.length) return explicit.sort((a, b) =>
    Math.max(0, ...b.boundaries.map(row => row.path.length)) - Math.max(0, ...a.boundaries.map(row => row.path.length)) ||
    a.moduleInfo.module_id.localeCompare(b.moduleInfo.module_id)).map(entry => entry.moduleInfo.module_id);
  const candidates = entries.flatMap(entry => entry.boundaries.filter(boundary => boundaryContains(boundary, normalized))
    .map(boundary => ({ id: entry.moduleInfo.module_id, length: boundary.path.length })));
  const longest = Math.max(-1, ...candidates.map(row => row.length));
  return candidates.length ? [...new Set(candidates.filter(row => row.length === longest).map(row => row.id))].sort() : ['root'];
}
function inferModuleOwnership(file, registry) {
  return inferModuleOwners(file, registry)[0];
}

module.exports = {
  inferModuleOwnership, inferModuleOwners, normalizeOwnershipPath, normalizedOwnershipPaths,
  moduleOwnershipBoundaries, moduleExplicitReferences, boundaryContains, normalizedConditionalDependencies,
  validatedOwnObject, validatedOwnArray, validatedModuleRegistry, pathComparisonIdentity, assertNoPathAliases,
  mergeModuleDeclaration
};
