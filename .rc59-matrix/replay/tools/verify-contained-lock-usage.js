'use strict';

const fs = require('fs');
const path = require('path');
const { LOCK_POLICY, LOCKS } = require('./lib/lock-policy');

const toolsRoot = __dirname;
const sourceRoot = path.resolve(toolsRoot, '..');
const allowedImplementationFiles = new Set([
  'lib/contained-lock-manager.js',
  'lib/lock-owner-schema.js',
  'lib/lock-policy.js',
]);
const sourceOnlyPrefixes = ['self-test-', 'verify-'];
const legacyPathReferenceExceptions = new Set([
  // Read-only diagnostics for the external Qdrant provider's own lock file.
  'lib/memory-providers.js',
]);

function walk(root, rel = '') {
  const files = [];
  for (const entry of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const child = path.posix.join(rel.replace(/\\/g, '/'), entry.name);
    if (entry.isDirectory()) files.push(...walk(root, child));
    else if (entry.isFile() && child.endsWith('.js')) files.push(child);
  }
  return files.sort();
}

function isPublicRuntime(rel) {
  if (allowedImplementationFiles.has(rel)) return false;
  return !sourceOnlyPrefixes.some((prefix) => path.posix.basename(rel).startsWith(prefix));
}

function occurrence(source, pattern) {
  return pattern.test(source);
}

function main() {
  const files = walk(toolsRoot);
  const publicFiles = files.filter(isPublicRuntime);
  const results = [];
  const push = (id, pass, detail) => results.push({ id, pass: Boolean(pass), detail });

  const rules = [
    ['no_legacy_acquire_api', /\bacquireLock\s*\(/, 'Legacy acquireLock() call'],
    ['no_legacy_with_api', /\bwithLock\s*\(/, 'Legacy withLock() call'],
    ['no_direct_owner_read', /(?:readFileSync|openSync)\s*\([^\n;]*owner\.json/, 'Direct owner.json read'],
    ['no_direct_lock_removal', /(?:rmSync|rmdirSync|unlinkSync)\s*\([^\n;]*(?:\.lock|locks)/, 'Direct lock removal'],
    ['no_direct_lock_rename', /renameSync\s*\([^\n;]*(?:\.lock|locks)/, 'Direct lock rename'],
    ['no_legacy_lock_construction', /path\.join\s*\([^\n;]*['"]\.lock['"]/, 'Legacy .lock path construction'],
    ['no_raw_owner_diagnostic', /(?:JSON\.stringify\s*\(\s*(?:owner|existingOwner)|ownerRaw|rawOwner)/, 'Raw lock-owner diagnostic'],
  ];

  for (const [id, pattern, label] of rules) {
    const offenders = publicFiles.filter((rel) => {
      if (id === 'no_legacy_lock_construction' && legacyPathReferenceExceptions.has(rel)) return false;
      return occurrence(fs.readFileSync(path.join(toolsRoot, rel), 'utf8'), pattern);
    });
    push(id, offenders.length === 0, offenders.length ? `${label}: ${offenders.join(', ')}` : `${label}: none`);
  }

  const jsonStore = fs.readFileSync(path.join(toolsRoot, 'lib', 'json-store.js'), 'utf8');
  push('json_store_exports_no_lock_primitive', !/\b(?:acquireLock|withLock)\b/.test(jsonStore), 'json-store has no lock primitive or export');

  const manager = fs.readFileSync(path.join(toolsRoot, 'lib', 'contained-lock-manager.js'), 'utf8');
  for (const api of ['acquireContainedLock', 'withContainedLock', 'inspectLockSafety', 'inspectAllLockSafety', 'inspectContextLockSafety']) {
    push(`manager_exports_${api}`, new RegExp(`\\b${api}\\b`).test(manager), `manager API ${api}`);
  }

  const combinedPublic = publicFiles.map((rel) => fs.readFileSync(path.join(toolsRoot, rel), 'utf8')).join('\n');
  for (const [lockName, definition] of Object.entries(LOCKS)) {
    if (!definition.root_kinds.some((kind) => LOCK_POLICY.root_kinds[kind]?.public)) continue;
    const nameUsed = combinedPublic.includes(`'${lockName}'`) || combinedPublic.includes(`\"${lockName}\"`);
    const escapedName = lockName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const policyPurposeReference = new RegExp(`LOCKS(?:\\[['\"]${escapedName}['\"]\\]|\\.${escapedName})\\.purpose`).test(combinedPublic);
    const purposeUsed = combinedPublic.includes(definition.purpose) || policyPurposeReference;
    push(`policy_consumer_${lockName}`, nameUsed && purposeUsed, nameUsed && purposeUsed
      ? `allowlisted lock ${lockName} has a declared public consumer`
      : `allowlisted lock ${lockName} lacks an exact name/purpose consumer`);
  }

  const report = {
    schema_version: 'knowledge-contained-lock-usage.v1',
    generated_at: new Date().toISOString(),
    source_root: sourceRoot,
    scanned_public_files: publicFiles.length,
    checks_total: results.length,
    passed_total: results.filter((item) => item.pass).length,
    failed_total: results.filter((item) => !item.pass).length,
    status: results.every((item) => item.pass) ? 'pass' : 'fail',
    results,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.status !== 'pass') process.exitCode = 1;
  return report;
}

if (require.main === module) main();

module.exports = { main };
