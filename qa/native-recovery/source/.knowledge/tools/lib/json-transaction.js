'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { copyPlainData, copyInertData, dataDescriptor } = require('./inert-data');
const {
  ensureDir,
  readJson,
  writeJsonAtomic,
  writeFileAtomic,
  normalizeSystemAlias
} = require('./json-store');

const TRANSACTION_SCHEMA = 'knowledge-json-transaction.v1';

function admittedOptions(value) {
  const options = copyInertData(value);
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw transactionError('transaction_input_invalid', 'Expected inert options');
  for (const key of ['allowedContainmentRoots', 'allowedGuardRoots', 'allowedWriteRoots', 'exactWritePaths']) {
    if (options[key] === undefined) continue;
    if (!Array.isArray(options[key]) || options[key].some(item => typeof item !== 'string' || !path.isAbsolute(item))) {
      throw transactionError('transaction_policy_invalid', 'Policy paths must be absolute path arrays');
    }
  }
  for (const key of ['expectedIntentSha256', 'expectedManifestSha256']) {
    if (options[key] !== undefined && !/^[a-f0-9]{64}$/.test(options[key])) throw transactionError('transaction_policy_invalid', 'Invalid expected digest');
  }
  if (options.expectedTransactionId !== undefined && (typeof options.expectedTransactionId !== 'string' || validateTransactionId(options.expectedTransactionId) !== options.expectedTransactionId)) {
    throw transactionError('transaction_policy_invalid', 'Invalid expected transaction identity');
  }
  if (options.exactWritePaths && new Set(options.exactWritePaths.map(targetIdentity)).size !== options.exactWritePaths.length) {
    throw transactionError('transaction_policy_invalid', 'Duplicate exact output path');
  }
  return options;
}

function readManifestSnapshot(txRoot) {
  const file = manifestPath(txRoot);
  assertNoReparseParents(inferredStateRoot(txRoot), file);
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > 32 * 1024 * 1024) {
    throw transactionError('transaction_manifest_invalid', 'Unsafe manifest file');
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  let body;
  try {
    const before = fs.fstatSync(fd);
    if (before.dev !== stat.dev || before.ino !== stat.ino || before.nlink !== 1) throw transactionError('transaction_manifest_changed', 'Manifest changed');
    body = fs.readFileSync(fd);
    const after = fs.fstatSync(fd), live = fs.lstatSync(file);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs ||
        live.dev !== before.dev || live.ino !== before.ino || live.nlink !== 1 || live.isSymbolicLink() ||
        live.size !== body.length || live.mtimeMs !== before.mtimeMs || live.ctimeMs !== before.ctimeMs) {
      throw transactionError('transaction_manifest_changed', 'Manifest changed');
    }
  } finally { fs.closeSync(fd); }
  return { body, sha256: sha256(body), value: copyInertData(JSON.parse(body.toString('utf8').replace(/^\uFEFF/, ''))) };
}

function writeRoots(stateRoot, options) {
  return normalizeAllowedContainmentRoots(stateRoot, options.allowedWriteRoots === undefined ? options.allowedContainmentRoots : options.allowedWriteRoots);
}
function guardRoots(stateRoot, options) {
  return normalizeAllowedContainmentRoots(stateRoot, options.allowedGuardRoots === undefined ? options.allowedContainmentRoots : options.allowedGuardRoots);
}
function enforceWriteTarget(write, stateRoot, options) {
  const target = path.resolve(write.target), containment = path.resolve(write.containment_root);
  containingTrustedRoot(containment, writeRoots(stateRoot, options));
  relativeInside(containment, target);
  if (options.exactWritePaths && !options.exactWritePaths.some(item => targetIdentity(item) === targetIdentity(target))) {
    throw transactionError('transaction_write_policy_denied', 'Write is outside the exact trusted output set');
  }
}
function enforceWriteSet(writes, stateRoot, options) {
  for (const write of writes) enforceWriteTarget(write, stateRoot, options);
  if (options.exactWritePaths && (writes.length !== options.exactWritePaths.length ||
      new Set(writes.map(write => targetIdentity(write.target))).size !== writes.length)) {
    throw transactionError('transaction_write_policy_denied', 'Transaction does not match the exact trusted output set');
  }
}
function enforceManifestExpectation(txRoot, manifest, options, snapshot = null) {
  if (options.expectedTransactionId !== undefined && manifest?.transaction_id !== options.expectedTransactionId) {
    throw transactionError('transaction_recovery_binding_changed', 'Transaction identity changed after inspection');
  }
  if (options.expectedIntentSha256 !== undefined && (manifest?.intent_sha256 !== options.expectedIntentSha256 || intentHash(manifest.intent) !== options.expectedIntentSha256)) {
    throw transactionError('transaction_recovery_binding_changed', 'Transaction intent changed after inspection');
  }
  if (options.expectedManifestSha256 !== undefined) {
    const actual = snapshot || readManifestSnapshot(txRoot);
    if (actual.sha256 !== options.expectedManifestSha256 || stableJson(actual.value) !== stableJson(manifest)) {
      throw transactionError('transaction_recovery_binding_changed', 'Manifest bytes changed after inspection');
    }
  }
}
function enforceEntryExpectation(txRoot, entry, options) {
  if (options.expectedManifestSha256 === undefined) return;
  const actual = readManifestSnapshot(txRoot);
  enforceManifestExpectation(txRoot, actual.value, options, actual);
  enforceWriteSet(actual.value.intent.writes, inferredStateRoot(txRoot), options);
  if (stableJson(actual.value.writes[entry.index]) !== stableJson(entry)) {
    throw transactionError('transaction_recovery_binding_changed', 'Actual replay entry changed');
  }
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function fileHash(filePath) {
  return sha256(fs.readFileSync(filePath));
}

function relativeInside(root, target) {
  // macOS exposes /var and /tmp as system aliases for /private/var and
  // /private/tmp. A transaction can receive one spelling from mkdtemp and
  // the other from a physical-path verifier; normalize only those platform
  // aliases before containment checks. User-controlled symlinks/junctions
  // remain rejected by assertNoReparseParents below.
  const base = normalizeSystemAlias(root);
  const resolved = normalizeSystemAlias(target);
  const relative = path.relative(base, resolved);
  if (!relative || relative === '.') return '';
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    const error = new Error(`Transaction target escapes state root: ${target}`);
    error.code = 'transaction_target_escape';
    throw error;
  }
  return relative.replace(/\\/g, '/');
}

function assertNoReparseParents(root, target) {
  const base = normalizeSystemAlias(root);
  const resolved = normalizeSystemAlias(target);
  relativeInside(base, resolved);
  let baseStats;
  try {
    baseStats = fs.lstatSync(base);
  } catch {
    throw transactionError(
      'transaction_reparse_path',
      `Transaction containment root is unavailable: ${base}`,
      { containment_root: base }
    );
  }
  if (baseStats.isSymbolicLink() || !baseStats.isDirectory()) {
    throw transactionError(
      'transaction_reparse_path',
      `Transaction containment root is not a real directory: ${base}`,
      { containment_root: base }
    );
  }
  let current = path.dirname(resolved);
  while (current !== base) {
    if (!current.startsWith(`${base}${path.sep}`)) break;
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
      const error = new Error(`Transaction target crosses a symlink or junction: ${current}`);
      error.code = 'transaction_reparse_path';
      throw error;
    }
    current = path.dirname(current);
  }
}

function transactionRoot(stateRoot) {
  return path.join(stateRoot, 'maintenance', 'transactions');
}

function targetIdentity(target) {
  const resolved = path.resolve(target);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function fault(point, options) {
  const requested = options.faultAt || process.env.KNOWLEDGE_TRANSACTION_FAULT || null;
  if (requested && requested === point) {
    const error = new Error(`Injected transaction fault at ${point}`);
    error.code = 'transaction_fault_injected';
    error.fault_point = point;
    throw error;
  }
}

function copyAtomic(source, target, expectedSha256 = null) {
  const body = fs.readFileSync(source);
  if (expectedSha256 !== null && sha256(body) !== expectedSha256) throw transactionError('transaction_source_hash_mismatch', 'Journal bytes changed before copying');
  writeFileAtomic(target, body);
}

function manifestPath(root) {
  return path.join(root, 'manifest.json');
}

function commitMarkerPath(root) {
  return path.join(root, 'commit.json');
}

function preparedManifestPath(root) {
  return path.join(root, 'prepared.json');
}

function terminalMarkerPath(root) {
  return path.join(root, 'terminal.json');
}

function transactionError(code, message, details = {}) {
  const error = new Error(message);
  Object.defineProperty(error, 'code', dataDescriptor(code));
  const keys = Object.keys(details);
  for (let index = 0; index < keys.length; index++) {
    const key = keys[index];
    const descriptor = Object.getOwnPropertyDescriptor(details, key);
    if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, 'value')) Object.defineProperty(error, key, dataDescriptor(descriptor.value));
  }
  return error;
}

function validateTransactionId(transactionId) {
  const normalized = String(transactionId || '');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(normalized)) {
    throw transactionError('transaction_id_invalid', `Unsafe transaction ID: ${JSON.stringify(transactionId)}`);
  }
  if (normalized.toLowerCase() === 'archives') {
    throw transactionError(
      'transaction_id_reserved',
      `Transaction ID is reserved by the transaction registry: ${normalized}`
    );
  }
  return normalized;
}

function inferredStateRoot(txRoot) {
  return path.dirname(path.dirname(path.dirname(path.resolve(txRoot))));
}

function normalizeAllowedContainmentRoots(stateRoot, values = []) {
  const roots = [stateRoot, ...(values || [])]
    .filter(Boolean)
    .map((value) => path.resolve(value));
  const unique = [];
  const identities = new Set();
  for (const root of roots) {
    const identity = targetIdentity(root);
    if (identities.has(identity)) continue;
    identities.add(identity);
    if (
      !fs.existsSync(root) ||
      fs.lstatSync(root).isSymbolicLink() ||
      !fs.lstatSync(root).isDirectory()
    ) {
      throw transactionError(
        'transaction_reparse_path',
        `Allowed transaction containment root is not a real directory: ${root}`,
        { containment_root: root }
      );
    }
    unique.push(root);
  }
  return unique;
}

function containingTrustedRoot(containmentRoot, allowedContainmentRoots) {
  for (const trustedRoot of allowedContainmentRoots) {
    try {
      relativeInside(trustedRoot, containmentRoot);
      assertNoReparseParents(trustedRoot, containmentRoot);
      assertNoReparseParents(containmentRoot, containmentRoot);
      const realTrustedRoot = fs.realpathSync.native(trustedRoot);
      const realContainmentRoot = fs.realpathSync.native(containmentRoot);
      try {
        relativeInside(realTrustedRoot, realContainmentRoot);
      } catch (error) {
        if (error.code !== 'transaction_target_escape') throw error;
        throw transactionError(
          'transaction_reparse_path',
          `Transaction containment root resolves outside its trusted root: ${containmentRoot}`,
          {
            containment_root: containmentRoot,
            trusted_root: trustedRoot
          }
        );
      }
      return trustedRoot;
    } catch (error) {
      if (!['transaction_target_escape'].includes(error.code)) throw error;
    }
  }
  throw transactionError(
    'transaction_containment_untrusted',
    `Transaction containment root is not authorized by the caller: ${containmentRoot}`,
    { containment_root: containmentRoot }
  );
}

function logicalIntentWrite(value) {
  return {
    target: path.resolve(value.target),
    target_relative: String(value.target_relative || '').replace(/\\/g, '/'),
    containment_root: path.resolve(value.containment_root),
    new_sha256: String(value.new_sha256 || '')
  };
}

function normalizeTreeGuardExclusions(values = []) {
  if (!Array.isArray(values)) {
    throw transactionError(
      'transaction_guard_invalid',
      'Tree guard exclusions must be an array'
    );
  }
  const normalized = values.map((value) => {
    const relative = String(value || '')
      .replace(/\\/g, '/')
      .replace(/^\.\//, '')
      .replace(/\/+$/, '');
    if (
      !relative ||
      path.posix.isAbsolute(relative) ||
      relative.split('/').some((part) =>
        !part || part === '.' || part === '..')
    ) {
      throw transactionError(
        'transaction_guard_invalid',
        `Invalid tree guard exclusion: ${JSON.stringify(value)}`
      );
    }
    return relative;
  });
  return Array.from(new Set(normalized)).sort();
}

function treeGuardObservationError(root, error) {
  if (error && error.code === 'transaction_guard_drift') {
    return error;
  }
  return transactionError(
    'transaction_guard_drift',
    `Tree guard could not be observed safely: ${root}`,
    {
      target: root,
      cause_code: String(error?.code || 'unknown')
    }
  );
}

function treeGuardFileHash(filePath) {
  const noFollow = Number(fs.constants.O_NOFOLLOW || 0);
  let handle = null;
  try {
    handle = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | noFollow
    );
    const before = fs.fstatSync(handle, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) {
      throw transactionError(
        'transaction_guard_drift',
        `Tree guard entry is not a regular file: ${filePath}`,
        { target: filePath }
      );
    }
    const body = fs.readFileSync(handle);
    const after = fs.fstatSync(handle, { bigint: true });
    const live = fs.lstatSync(filePath, { bigint: true });
    if (
      !after.isFile() ||
      !live.isFile() ||
      live.isSymbolicLink() ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      after.dev !== live.dev ||
      after.ino !== live.ino ||
      after.size !== live.size ||
      after.mtimeNs !== live.mtimeNs ||
      after.ctimeNs !== live.ctimeNs
    ) {
      throw transactionError(
        'transaction_guard_drift',
        `Tree guard file changed while it was read: ${filePath}`,
        { target: filePath }
      );
    }
    return sha256(body);
  } finally {
    if (handle !== null) fs.closeSync(handle);
  }
}

function treeGuardHash(rootPath, excludedPaths = []) {
  rootPath = copyInertData(rootPath);excludedPaths = copyInertData(excludedPaths);
  if (typeof rootPath !== 'string' || !Array.isArray(excludedPaths)) throw transactionError('transaction_input_invalid', 'Expected inert tree guard paths');
  const root = path.resolve(rootPath);
  const exclusions =
    normalizeTreeGuardExclusions(excludedPaths);
  const exclusionRoots = new Set(exclusions);
  try {
    const rootStat = fs.lstatSync(root);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
      throw transactionError(
        'transaction_guard_drift',
        `Tree guard root is not a physical directory: ${root}`,
        { target: root }
      );
    }
    const files = [];
    const walk = (directory, relativeDirectory = '') => {
      const entries = fs.readdirSync(
        directory,
        { withFileTypes: true }
      ).sort((left, right) =>
        left.name < right.name
          ? -1
          : left.name > right.name
            ? 1
            : 0);
      for (const entry of entries) {
        const relative = relativeDirectory
          ? `${relativeDirectory}/${entry.name}`
          : entry.name;
        const absolute = path.join(directory, entry.name);
        const stat = fs.lstatSync(absolute);
        if (entry.isSymbolicLink() || stat.isSymbolicLink()) {
          throw transactionError(
            'transaction_guard_drift',
            `Tree guard contains a link: ${absolute}`,
            { target: absolute }
          );
        }
        if (exclusionRoots.has(relative)) {
          if (!stat.isDirectory() && !stat.isFile()) {
            throw transactionError(
              'transaction_guard_drift',
              `Tree guard exclusion is not physical: ${absolute}`,
              { target: absolute }
            );
          }
          continue;
        }
        if (stat.isDirectory()) {
          walk(absolute, relative);
        } else if (stat.isFile()) {
          files.push({
            path: relative,
            sha256: treeGuardFileHash(absolute)
          });
        } else {
          throw transactionError(
            'transaction_guard_drift',
            `Tree guard contains a non-file entry: ${absolute}`,
            { target: absolute }
          );
        }
      }
    };
    walk(root);
    return sha256(files.map((item) =>
      `${item.path}\0${item.sha256}\n`).join(''));
  } catch (error) {
    throw treeGuardObservationError(root, error);
  }
}

function logicalIntentGuard(value) {
  if (value.kind === 'tree') {
    return {
      kind: 'tree',
      target: path.resolve(value.target),
      target_relative: String(
        value.target_relative || ''
      ).replace(/\\/g, '/'),
      containment_root: path.resolve(
        value.containment_root
      ),
      expected_sha256:
        String(value.expected_sha256 || '').toLowerCase(),
      excluded_paths: normalizeTreeGuardExclusions(
        value.excluded_paths || []
      )
    };
  }
  const expectedExists = value.expected_exists !== false;
  return {
    target: path.resolve(value.target),
    target_relative: String(value.target_relative || '').replace(/\\/g, '/'),
    containment_root: path.resolve(value.containment_root),
    ...(expectedExists
      ? {
          expected_sha256:
            String(value.expected_sha256 || '').toLowerCase()
        }
      : { expected_exists: false })
  };
}

function intentPayload(metadata, writes, guards = null) {
  const intent = {
    metadata: metadata && typeof metadata === 'object' ? metadata : {},
    writes: (writes || []).map(logicalIntentWrite)
  };
  if (guards !== null) intent.guards = (guards || []).map(logicalIntentGuard);
  return intent;
}

function intentHash(intent) {
  return sha256(stableJson(intent));
}

function sameLogicalWrite(left, right) {
  const a = logicalIntentWrite(left);
  const b = logicalIntentWrite(right);
  return (
    targetIdentity(a.target) === targetIdentity(b.target) &&
    targetIdentity(a.containment_root) === targetIdentity(b.containment_root) &&
    a.target_relative === b.target_relative &&
    a.new_sha256 === b.new_sha256
  );
}

function transactionArtifactPath(txRoot, relative, expected, kind) {
  const normalized = String(relative || '').replace(/\\/g, '/');
  if (!normalized || normalized !== expected) {
    throw transactionError(
      'transaction_manifest_invalid',
      `Invalid ${kind} journal path: ${JSON.stringify(relative)}`,
      { artifact: relative || null }
    );
  }
  const absolute = path.resolve(txRoot, normalized);
  if (!relativeInside(txRoot, absolute)) {
    throw transactionError('transaction_entry_escape', `${kind} escapes transaction root: ${relative}`, { artifact: relative });
  }
  assertNoReparseParents(txRoot, absolute);
  if (fs.existsSync(absolute) && fs.lstatSync(absolute).isSymbolicLink()) {
    throw transactionError('transaction_reparse_path', `${kind} is a symlink or junction: ${relative}`, { artifact: relative });
  }
  return absolute;
}

function validateEntry(entry, txRoot, expectedIndex, options = {}) {
  if (!entry || typeof entry !== 'object' || entry.index !== expectedIndex) {
    throw transactionError('transaction_manifest_invalid', `Invalid transaction entry at index ${expectedIndex}`);
  }
  const expectedStaged = `staged/${String(expectedIndex).padStart(3, '0')}.new`;
  const expectedBackup = `backups/${String(expectedIndex).padStart(3, '0')}.old`;
  if (!/^[a-f0-9]{64}$/.test(String(entry.new_sha256 || ''))) {
    throw transactionError('transaction_manifest_invalid', `Invalid new hash at transaction entry ${expectedIndex}`);
  }
  if (
    typeof entry.target !== 'string' ||
    typeof entry.containment_root !== 'string' ||
    !path.isAbsolute(entry.target) ||
    !path.isAbsolute(entry.containment_root)
  ) {
    throw transactionError('transaction_manifest_invalid', `Missing target containment at transaction entry ${expectedIndex}`);
  }
  const target = path.resolve(entry.target);
  const containmentRoot = path.resolve(entry.containment_root);
  enforceEntryExpectation(txRoot, entry, options);
  enforceWriteTarget(entry, inferredStateRoot(txRoot), options);
  const allowedContainmentRoots = writeRoots(inferredStateRoot(txRoot), options);
  containingTrustedRoot(containmentRoot, allowedContainmentRoots);
  const targetRelative = relativeInside(containmentRoot, target);
  if (targetRelative !== String(entry.target_relative || '').replace(/\\/g, '/')) {
    throw transactionError(
      'transaction_manifest_invalid',
      `Target-relative binding mismatch at transaction entry ${expectedIndex}`,
      { target: entry.target }
    );
  }
  assertNoReparseParents(containmentRoot, target);
  if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) {
    throw transactionError('transaction_reparse_path', `Transaction target is a symlink or junction: ${target}`);
  }
  const staged = transactionArtifactPath(txRoot, entry.staged, expectedStaged, 'staged file');
  if (!fs.existsSync(staged) || fileHash(staged) !== entry.new_sha256) {
    throw transactionError(
      'transaction_staged_corrupt',
      `Missing or corrupt staged transaction file: ${entry.staged}`,
      { artifact: entry.staged }
    );
  }
  let backup = null;
  if (entry.old_exists) {
    if (!/^[a-f0-9]{64}$/.test(String(entry.old_sha256 || ''))) {
      throw transactionError('transaction_manifest_invalid', `Invalid old hash at transaction entry ${expectedIndex}`);
    }
    backup = transactionArtifactPath(txRoot, entry.backup, expectedBackup, 'backup file');
    if (!fs.existsSync(backup) || fileHash(backup) !== entry.old_sha256) {
      throw transactionError(
        'transaction_backup_corrupt',
        `Missing or corrupt transaction backup: ${entry.backup}`,
        { artifact: entry.backup }
      );
    }
  } else if (entry.backup !== null || entry.old_sha256 !== null) {
    throw transactionError('transaction_manifest_invalid', `Unexpected backup metadata at transaction entry ${expectedIndex}`);
  }
  return { entry, target, containmentRoot, staged, backup };
}

function validateManifest(txRoot, manifest, options = {}) {
  if (
    !manifest ||
    typeof manifest !== 'object' ||
    manifest.schema_version !== TRANSACTION_SCHEMA ||
    !Array.isArray(manifest.writes) ||
    !manifest.intent ||
    typeof manifest.intent !== 'object' ||
    !Array.isArray(manifest.intent.writes) ||
    !/^[a-f0-9]{64}$/.test(String(manifest.intent_sha256 || ''))
  ) {
    throw transactionError('transaction_manifest_invalid', `Invalid transaction manifest: ${manifestPath(txRoot)}`);
  }
  const transactionId = validateTransactionId(manifest.transaction_id);
  enforceManifestExpectation(txRoot, manifest, options);
  if (path.basename(txRoot) !== transactionId) {
    throw transactionError(
      'transaction_manifest_invalid',
      `Transaction directory and manifest ID differ: ${path.basename(txRoot)} != ${transactionId}`
    );
  }
  if (!['preparing', 'prepared'].includes(String(manifest.status || ''))) {
    throw transactionError('transaction_manifest_invalid', `Invalid transaction status: ${manifest.status}`);
  }
  const hasGuards = Object.prototype.hasOwnProperty.call(
    manifest.intent,
    'guards'
  );
  if (hasGuards && !Array.isArray(manifest.intent.guards)) {
    throw transactionError(
      'transaction_manifest_invalid',
      'Transaction intent guards must be an array'
    );
  }
  const canonicalIntent = intentPayload(
    manifest.metadata,
    manifest.intent.writes,
    hasGuards ? manifest.intent.guards : null
  );
  if (
    stableJson(canonicalIntent) !== stableJson(manifest.intent) ||
    intentHash(canonicalIntent) !== manifest.intent_sha256
  ) {
    throw transactionError(
      'transaction_intent_invalid',
      `Transaction intent is malformed or has been modified: ${manifest.transaction_id}`
    );
  }
  if (manifest.writes.length > manifest.intent.writes.length) {
    throw transactionError('transaction_manifest_invalid', 'Transaction journal contains more writes than its bound intent');
  }
  if (manifest.status === 'prepared' && manifest.writes.length !== manifest.intent.writes.length) {
    throw transactionError('transaction_manifest_invalid', 'Prepared transaction does not contain its complete bound intent');
  }
  // This checks the actual complete intent BEFORE validating/copying any staged
  // entry, including incomplete journals and rollback/cleanup recovery.
  enforceWriteSet(manifest.intent.writes, inferredStateRoot(txRoot), options);
  const entries = manifest.writes.map((entry, index) => {
    if (!sameLogicalWrite(entry, manifest.intent.writes[index])) {
      throw transactionError(
        'transaction_intent_mismatch',
        `Transaction entry ${index} differs from its bound intent`
      );
    }
    return validateEntry(entry, txRoot, index, options);
  });
  const targets = new Set();
  for (const { target } of entries) {
    const identity = targetIdentity(target);
    if (targets.has(identity)) {
      throw transactionError(
        'transaction_duplicate_target',
        `Transaction contains the same target more than once: ${target}`,
        { target }
      );
    }
    targets.add(identity);
  }
  validateGuardBindings(
    canonicalIntent.guards || [],
    guardRoots(inferredStateRoot(txRoot), options)
  );
  return entries;
}

function validateGuardBindings(guards, allowedContainmentRoots) {
  const identities = new Set();
  return (guards || []).map((raw, index) => {
    const guard = logicalIntentGuard(raw);
    if (
      raw.kind !== undefined &&
      raw.kind !== 'tree'
    ) {
      throw transactionError(
        'transaction_guard_invalid',
        `Transaction guard ${index} has an invalid kind`
      );
    }
    if (
      guard.expected_exists !== false &&
      !/^[a-f0-9]{64}$/.test(guard.expected_sha256)
    ) {
      throw transactionError(
        'transaction_guard_invalid',
        `Transaction guard ${index} has an invalid expected hash`
      );
    }
    containingTrustedRoot(guard.containment_root, allowedContainmentRoots);
    const relative = relativeInside(guard.containment_root, guard.target);
    if (relative !== guard.target_relative) {
      throw transactionError(
        'transaction_guard_invalid',
        `Transaction guard ${index} has a mismatched relative path`
      );
    }
    assertNoReparseParents(guard.containment_root, guard.target);
    if (guard.kind === 'tree') {
      let stat;
      try {
        stat = fs.lstatSync(guard.target);
      } catch {
        stat = null;
      }
      if (
        !stat ||
        !stat.isDirectory() ||
        stat.isSymbolicLink()
      ) {
        throw transactionError(
          'transaction_guard_invalid',
          `Transaction tree guard ${index} is not a physical directory`
        );
      }
    }
    const identity = targetIdentity(guard.target);
    if (identities.has(identity)) {
      throw transactionError(
        'transaction_guard_duplicate',
        `Transaction guard target is duplicated: ${guard.target}`
      );
    }
    identities.add(identity);
    return guard;
  });
}

function validateGuardHashes(guards, {
  writes = [],
  allowWriteTransitions = false
} = {}) {
  const writeHashes = new Map(
    (writes || []).map((write) => [
      targetIdentity(write.target),
      String(write.new_sha256 || '').toLowerCase()
    ])
  );
  for (const guard of guards || []) {
    if (guard.kind === 'tree') {
      const actual = treeGuardHash(
        guard.target,
        guard.excluded_paths
      );
      if (actual !== guard.expected_sha256) {
        throw transactionError(
          'transaction_guard_drift',
          `Transaction tree guard changed: ${guard.target}`,
          {
            target: guard.target,
            expected_sha256: guard.expected_sha256,
            actual_sha256: actual
          }
        );
      }
      continue;
    }
    const expectedMissing = guard.expected_exists === false;
    const intendedWriteHash = allowWriteTransitions
      ? writeHashes.get(targetIdentity(guard.target))
      : null;
    let stat;
    try {
      stat = fs.lstatSync(guard.target);
    } catch {
      if (expectedMissing) continue;
      throw transactionError(
        'transaction_guard_drift',
        `Transaction guard target is missing: ${guard.target}`,
        { target: guard.target }
      );
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw transactionError(
        'transaction_guard_drift',
        `Transaction guard target is not a safe regular file: ${guard.target}`,
        { target: guard.target }
      );
    }
    const actual = fileHash(guard.target);
    if (expectedMissing) {
      if (intendedWriteHash && actual === intendedWriteHash) continue;
      throw transactionError(
        'transaction_guard_drift',
        `Transaction guard target appeared outside its bound transition: ${guard.target}`,
        {
          target: guard.target,
          expected_exists: false,
          intended_write_sha256: intendedWriteHash || null,
          actual_sha256: actual
        }
      );
    }
    if (
      actual !== guard.expected_sha256 &&
      (!intendedWriteHash || actual !== intendedWriteHash)
    ) {
      throw transactionError(
        'transaction_guard_drift',
        `Transaction guard target changed outside its bound transition: ${guard.target}`,
        {
          target: guard.target,
          expected_sha256: guard.expected_sha256,
          intended_write_sha256: intendedWriteHash || null,
          actual_sha256: actual
        }
      );
    }
  }
}

function readVerifiedCommitMarker(txRoot, manifest, options = {}) {
  const markerFile = commitMarkerPath(txRoot);
  if (!fs.existsSync(markerFile)) return null;
  if (fs.lstatSync(markerFile).isSymbolicLink()) {
    throw transactionError('transaction_commit_marker_invalid', `Commit marker is a symlink: ${markerFile}`);
  }
  const marker = readJson(markerFile, null);
  if (
    !marker ||
    marker.schema_version !== TRANSACTION_SCHEMA ||
    marker.transaction_id !== manifest.transaction_id ||
    !/^[a-f0-9]{64}$/.test(String(marker.manifest_sha256 || ''))
  ) {
    throw transactionError('transaction_commit_marker_invalid', `Invalid commit marker: ${markerFile}`);
  }
  const preparedFile = transactionArtifactPath(txRoot, 'prepared.json', 'prepared.json', 'prepared manifest');
  if (!fs.existsSync(preparedFile)) {
    throw transactionError('transaction_commit_marker_invalid', `Prepared manifest is missing: ${preparedFile}`);
  }
  const actualManifestHash = fileHash(preparedFile);
  if (marker.manifest_sha256 !== actualManifestHash) {
    throw transactionError(
      'transaction_manifest_hash_mismatch',
      `Commit marker does not match prepared manifest for ${manifest.transaction_id}`,
      { expected_sha256: marker.manifest_sha256, actual_sha256: actualManifestHash }
    );
  }
  const prepared = readJson(preparedFile, null);
  validateManifest(txRoot, prepared, options);
  const liveManifestHash = fileHash(manifestPath(txRoot));
  if (liveManifestHash !== actualManifestHash) {
    throw transactionError(
      'transaction_manifest_hash_mismatch',
      `Live manifest differs from the commit-bound prepared manifest for ${manifest.transaction_id}`,
      { expected_sha256: actualManifestHash, actual_sha256: liveManifestHash }
    );
  }
  if (
    prepared.status !== 'prepared' ||
    prepared.transaction_id !== manifest.transaction_id ||
    prepared.intent_sha256 !== manifest.intent_sha256
  ) {
    throw transactionError(
      'transaction_commit_marker_invalid',
      `Commit marker is not bound to the live prepared transaction ${manifest.transaction_id}`
    );
  }
  return { marker, prepared, manifest_sha256: actualManifestHash };
}

function writeTerminalMarker(txRoot, manifest, status, recoveryAction = null, options = {}) {
  enforceManifestExpectation(txRoot, manifest, options);
  enforceWriteSet(manifest.intent.writes, inferredStateRoot(txRoot), options);
  const markerFile = commitMarkerPath(txRoot);
  const terminal = {
    schema_version: TRANSACTION_SCHEMA,
    transaction_id: manifest.transaction_id,
    status,
    completed_at: new Date().toISOString(),
    recovery_action: recoveryAction,
    intent_sha256: manifest.intent_sha256,
    manifest_sha256: fileHash(manifestPath(txRoot)),
    commit_marker_sha256: ['committed', 'guard_failed'].includes(status)
      ? fileHash(markerFile)
      : null
  };
  writeJsonAtomic(terminalMarkerPath(txRoot), terminal);
  return terminal;
}

function readVerifiedTerminalMarker(txRoot, manifest, options = {}) {
  const terminalFile = terminalMarkerPath(txRoot);
  if (!fs.existsSync(terminalFile)) return null;
  if (fs.lstatSync(terminalFile).isSymbolicLink()) {
    throw transactionError('transaction_terminal_marker_invalid', `Terminal marker is a symlink: ${terminalFile}`);
  }
  const terminal = readJson(terminalFile, null);
  if (
    !terminal ||
    terminal.schema_version !== TRANSACTION_SCHEMA ||
    terminal.transaction_id !== manifest.transaction_id ||
    !['committed', 'rolled_back', 'guard_failed'].includes(String(terminal.status || '')) ||
    terminal.intent_sha256 !== manifest.intent_sha256 ||
    terminal.manifest_sha256 !== fileHash(manifestPath(txRoot))
  ) {
    throw transactionError('transaction_terminal_marker_invalid', `Invalid terminal marker: ${terminalFile}`);
  }
  const commitFile = commitMarkerPath(txRoot);
  if (['committed', 'guard_failed'].includes(terminal.status)) {
    const verifiedCommit = readVerifiedCommitMarker(txRoot, manifest, options);
    if (
      !verifiedCommit ||
      !/^[a-f0-9]{64}$/.test(String(terminal.commit_marker_sha256 || '')) ||
      terminal.commit_marker_sha256 !== fileHash(commitFile)
    ) {
      throw transactionError(
        'transaction_terminal_marker_invalid',
        `Committed terminal marker is not bound to commit intent: ${terminalFile}`
      );
    }
  } else if (fs.existsSync(commitFile) || terminal.commit_marker_sha256 !== null) {
    throw transactionError(
      'transaction_terminal_marker_invalid',
      `Rolled-back terminal marker conflicts with commit intent: ${terminalFile}`
    );
  }
  return terminal;
}

function validateOldTargets(entries) {
  for (const { entry, target } of entries) {
    if (entry.old_exists) {
      if (!fs.existsSync(target) || fileHash(target) !== entry.old_sha256) {
        throw transactionError(
          'transaction_precommit_target_drift',
          `Pre-commit target no longer matches old state: ${target}`,
          { target }
        );
      }
    } else if (fs.existsSync(target)) {
      throw transactionError(
        'transaction_precommit_target_drift',
        `Pre-commit target unexpectedly exists: ${target}`,
        { target }
      );
    }
  }
}

function validateNewTargets(entries) {
  for (const { entry, target } of entries) {
    if (!fs.existsSync(target) || fileHash(target) !== entry.new_sha256) {
      throw transactionError(
        'transaction_committed_target_drift',
        `Committed transaction target does not match new state: ${target}`,
        { target }
      );
    }
  }
}

function validateRecoverableTargets(entries) {
  for (const { entry, target } of entries) {
    if (!fs.existsSync(target)) {
      if (!entry.old_exists) continue;
      throw transactionError(
        'transaction_recovery_target_drift',
        `Transaction target disappeared after commit intent: ${target}`,
        { target }
      );
    }
    const current = fileHash(target);
    if (current === entry.new_sha256 ||
        (entry.old_exists && current === entry.old_sha256)) {
      continue;
    }
    throw transactionError(
      'transaction_recovery_target_drift',
      `Transaction target changed outside the transaction after commit intent: ${target}`,
      { target }
    );
  }
}

function restoreOld(entry, txRoot, options = {}) {
  const validated = validateEntry(entry, txRoot, entry.index, options);
  if (entry.old_exists) copyAtomic(validated.backup, validated.target, entry.old_sha256);
  else if (fs.existsSync(validated.target)) {
    if (options.exactWritePaths && fileHash(validated.target) !== entry.new_sha256) throw transactionError('transaction_recovery_target_drift', 'Cleanup target changed');
    enforceEntryExpectation(txRoot, entry, options);
    fs.unlinkSync(validated.target);
  }
}

function promoteNew(entry, txRoot, options = {}) {
  const validated = validateEntry(entry, txRoot, entry.index, options);
  if (!fs.existsSync(validated.target) || fileHash(validated.target) !== entry.new_sha256) {
    assertNoReparseParents(validated.containmentRoot, validated.target);
    enforceEntryExpectation(txRoot, entry, options);
    copyAtomic(validated.staged, validated.target, entry.new_sha256);
  }
}

function rollbackGuardedCommit(txRoot, manifest, entries, error, options = {}) {
  validateManifest(txRoot, manifest, options);
  validateRecoverableTargets(entries);
  for (const { entry } of entries) restoreOld(entry, txRoot, options);
  validateOldTargets(entries);
  writeTerminalMarker(
    txRoot,
    manifest,
    'guard_failed',
    'rolled_back_guard_drift',
    options
  );
  return {
    transaction_id: manifest.transaction_id,
    status: 'guard_failed',
    recovery_action: 'rolled_back_guard_drift',
    error_code: error.code || 'transaction_guard_drift'
  };
}

function recoverOne(txRoot, options = {}) {
  options = admittedOptions(options);
  txRoot = copyInertData(txRoot);
  if (typeof txRoot !== 'string') throw transactionError('transaction_input_invalid', 'Expected transaction path');
  if (fs.existsSync(txRoot) && fs.lstatSync(txRoot).isSymbolicLink()) {
    throw transactionError(
      'transaction_reparse_path',
      `Transaction directory is a symlink or junction: ${txRoot}`
    );
  }
  const snapshot = readManifestSnapshot(txRoot), manifest = snapshot.value;
  enforceManifestExpectation(txRoot, manifest, options, snapshot);
  const entries = validateManifest(txRoot, manifest, options);
  const terminal = readVerifiedTerminalMarker(txRoot, manifest, options);
  if (terminal) {
    return {
      transaction_id: manifest.transaction_id,
      status: terminal.status,
      recovery_action: 'already_terminal'
    };
  }
  const commitMarker = readVerifiedCommitMarker(txRoot, manifest, options);
  if (commitMarker) {
    // validateManifest verifies every staged file and backup before the first
    // target mutation, preventing a late corrupt entry from producing a mixed
    // recovery state.
    validateRecoverableTargets(entries);
    try {
      validateGuardHashes(manifest.intent.guards || [], {
        writes: manifest.intent.writes,
        allowWriteTransitions: true
      });
      for (const { entry } of entries) {
        validateGuardHashes(manifest.intent.guards || [], {
          writes: manifest.intent.writes,
          allowWriteTransitions: true
        });
        promoteNew(entry, txRoot, options);
      }
      validateGuardHashes(manifest.intent.guards || [], {
        writes: manifest.intent.writes,
        allowWriteTransitions: true
      });
      validateManifest(txRoot, manifest, options);
      validateNewTargets(entries);
    } catch (error) {
      if (error.code !== 'transaction_guard_drift') throw error;
      return rollbackGuardedCommit(txRoot, manifest, entries, error, options);
    }
    writeTerminalMarker(txRoot, manifest, 'committed', 'completed_commit', options);
    return { transaction_id: manifest.transaction_id, status: 'committed', recovery_action: 'completed_commit' };
  }
  // No target is promoted before the commit marker. Verify that the old state
  // still exists, but do not rewrite it from mutable journal backups.
  validateOldTargets(entries);
  writeTerminalMarker(txRoot, manifest, 'rolled_back', 'restored_old_state', options);
  return { transaction_id: manifest.transaction_id, status: 'rolled_back', recovery_action: 'restored_old_state' };
}

function inspectTransaction(txRoot, options = {}) {
  options = admittedOptions(options);
  txRoot = copyInertData(txRoot);
  if (typeof txRoot !== 'string') throw transactionError('transaction_input_invalid', 'Expected transaction path');
  if (fs.existsSync(txRoot) && fs.lstatSync(txRoot).isSymbolicLink()) {
    throw transactionError(
      'transaction_reparse_path',
      `Transaction directory is a symlink or junction: ${txRoot}`
    );
  }
  const snapshot = readManifestSnapshot(txRoot), manifest = snapshot.value;
  enforceManifestExpectation(txRoot, manifest, options, snapshot);
  const entries = validateManifest(txRoot, manifest, options);
  const terminal = readVerifiedTerminalMarker(txRoot, manifest, options);
  const commitMarker = readVerifiedCommitMarker(txRoot, manifest, options);
  if (options.validateTerminalTargets === true) {
    if (terminal?.status === 'committed') validateNewTargets(entries);
    if (['rolled_back', 'guard_failed'].includes(terminal?.status)) {
      validateOldTargets(entries);
    }
  }
  return {
    manifest,
    manifest_sha256: snapshot.sha256,
    entries,
    terminal,
    commit_marker: commitMarker,
    status: terminal?.status ||
      (commitMarker ? 'commit_intent_pending' : manifest.status)
  };
}

function recoverTransactions(stateRoot, options = {}) {
  options = admittedOptions(options);
  stateRoot = copyInertData(stateRoot);
  if (typeof stateRoot !== 'string') throw transactionError('transaction_input_invalid', 'Expected state path');
  const root = transactionRoot(stateRoot);
  if (!fs.existsSync(root)) return [];
  const transactionIdPrefixes = options.transactionIdPrefixes === undefined
    ? null
    : options.transactionIdPrefixes;
  if (
    transactionIdPrefixes !== null &&
    (
      !Array.isArray(transactionIdPrefixes) ||
      transactionIdPrefixes.length === 0 ||
      transactionIdPrefixes.some((prefix) =>
        typeof prefix !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(prefix)
      )
    )
  ) {
    throw transactionError(
      'transaction_filter_invalid',
      'transactionIdPrefixes must be a non-empty array of safe transaction ID prefixes'
    );
  }
  const recovered = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.name === 'archives') {
      if (entry.isSymbolicLink() || !entry.isDirectory()) {
        throw transactionError(
          'transaction_archive_invalid',
          `Transaction archive registry is not a real directory: ${path.join(root, entry.name)}`
        );
      }
      continue;
    }
    if (
      transactionIdPrefixes &&
      !transactionIdPrefixes.some((prefix) => entry.name.startsWith(prefix))
    ) {
      continue;
    }
    if (entry.isSymbolicLink()) {
      throw transactionError(
        'transaction_reparse_path',
        `Transaction registry contains a symlink or junction: ${path.join(root, entry.name)}`
      );
    }
    if (!entry.isDirectory()) continue;
    const txRoot = path.join(root, entry.name);
    const result = recoverOne(txRoot, {
      ...options,
      allowedContainmentRoots: normalizeAllowedContainmentRoots(
        stateRoot,
        options.allowedContainmentRoots
      )
    });
    if (result.recovery_action !== 'already_terminal') recovered.push(result);
  }
  return recovered;
}

function commitJsonTransaction(input) {
  let {
  stateRoot,
  transactionId,
  writes,
  guards = [],
  metadata = {},
  faultAt = null,
  allowedContainmentRoots = [],
  allowedGuardRoots,
  allowedWriteRoots,
  exactWritePaths
  } = copyPlainData(input, true);
  const policy = admittedOptions({allowedContainmentRoots, allowedGuardRoots, allowedWriteRoots, exactWritePaths});
  if (!transactionId || !Array.isArray(writes) || !writes.length) {
    throw new Error('transactionId and non-empty writes are required');
  }
  transactionId = validateTransactionId(transactionId);
  const trustedContainmentRoots = writeRoots(stateRoot, policy);
  const trustedGuardRoots = guardRoots(stateRoot, policy);
  const requestedTargets = new Set();
  const preparedWrites = writes.map((item) => {
    if (!item || typeof item !== 'object' || !item.path) {
      throw transactionError('transaction_write_invalid', 'Every transaction write requires a path');
    }
    const target = path.resolve(item.path);
    const containmentRoot = path.resolve(item.containmentRoot || stateRoot);
    enforceWriteTarget({target, containment_root:containmentRoot}, stateRoot, policy);
    containingTrustedRoot(containmentRoot, trustedContainmentRoots);
    const targetRelative = relativeInside(containmentRoot, target);
    assertNoReparseParents(containmentRoot, target);
    if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) {
      throw transactionError(
        'transaction_reparse_path',
        `Transaction target is a symlink or junction: ${target}`
      );
    }
    const identity = targetIdentity(target);
    if (requestedTargets.has(identity)) {
      throw transactionError(
        'transaction_duplicate_target',
        `Transaction contains the same target more than once: ${target}`,
        { target }
      );
    }
    requestedTargets.add(identity);
    const oldExists = fs.existsSync(target);
    const oldBody = oldExists ? fs.readFileSync(target) : null;
    const serialized = item.body !== undefined
      ? item.body
      : `${JSON.stringify(item.value, null, 2)}\n`;
    if (serialized === undefined) {
      throw transactionError(
        'transaction_write_invalid',
        `Transaction value cannot be serialized: ${target}`,
        { target }
      );
    }
    const newBody = Buffer.from(serialized, item.encoding || 'utf8');
    return {
      item,
      target,
      containmentRoot,
      targetRelative,
      oldExists,
      oldBody,
      newBody
    };
  });
  const requestedIntent = intentPayload(metadata, preparedWrites.map((item) => ({
    target: item.target,
    target_relative: item.targetRelative,
    containment_root: item.containmentRoot,
    new_sha256: sha256(item.newBody)
  })), guards.length ? validateGuardBindings(
    guards.map((item) => {
      if (!item || typeof item !== 'object' || !item.path) {
        throw transactionError(
          'transaction_guard_invalid',
          'Every transaction guard requires a path'
        );
      }
      const target = path.resolve(item.path);
      const containmentRoot = path.resolve(item.containmentRoot || stateRoot);
      if (item.kind === 'tree') {
        return {
          kind: 'tree',
          target,
          target_relative:
            relativeInside(containmentRoot, target),
          containment_root: containmentRoot,
          expected_sha256: item.expected_sha256,
          excluded_paths: item.excluded_paths || []
        };
      }
      return {
        target,
        target_relative: relativeInside(containmentRoot, target),
        containment_root: containmentRoot,
        ...(item.expected_exists === false
          ? { expected_exists: false }
          : { expected_sha256: item.expected_sha256 })
      };
    }),
    trustedGuardRoots
  ) : null);
  validateGuardHashes(requestedIntent.guards || []);
  const requestedIntentSha256 = intentHash(requestedIntent);
  enforceWriteSet(requestedIntent.writes, stateRoot, policy);
  const transactionOptions = {...policy, expectedTransactionId:transactionId, expectedIntentSha256:requestedIntentSha256};
  const root = transactionRoot(stateRoot);
  const txRoot = path.join(root, transactionId);
  assertNoReparseParents(path.resolve(stateRoot), txRoot);
  if (fs.existsSync(txRoot) && fs.lstatSync(txRoot).isSymbolicLink()) {
    throw transactionError(
      'transaction_reparse_path',
      `Transaction directory is a symlink or junction: ${txRoot}`
    );
  }
  if (fs.existsSync(txRoot)) {
    const priorSnapshot = readManifestSnapshot(txRoot), prior = priorSnapshot.value;
    // Authenticate the inspected PRIOR intent independently. Comparing it to
    // the requested intent below preserves the legacy refusal code without
    // weakening the snapshot/identity binding used for actual replay.
    const priorOptions = {...transactionOptions, expectedIntentSha256:prior.intent_sha256, expectedManifestSha256:priorSnapshot.sha256};
    const priorEntries = validateManifest(txRoot, prior, priorOptions);
    if (
      prior.intent_sha256 !== requestedIntentSha256 ||
      stableJson(prior.intent) !== stableJson(requestedIntent)
    ) {
      throw transactionError(
        'transaction_intent_mismatch',
        `Transaction ID ${transactionId} is already bound to a different write intent`
      );
    }
    const recovered = recoverOne(txRoot, priorOptions);
    if (recovered.status === 'committed') {
      validateNewTargets(priorEntries);
      return { ...prior, status: 'committed', idempotent: true };
    }
    // A rolled-back attempt is all-old and safe to retain as audit evidence,
    // but it must not permanently poison the deterministic transaction ID.
    const archiveRoot = path.join(root, 'archives');
    ensureDir(archiveRoot);
    assertNoReparseParents(path.resolve(stateRoot), archiveRoot);
    if (fs.lstatSync(archiveRoot).isSymbolicLink()) {
      throw transactionError(
        'transaction_reparse_path',
        `Transaction archive registry is a symlink or junction: ${archiveRoot}`
      );
    }
    const archived = path.join(
      archiveRoot,
      `rolled-back-${sha256(transactionId).slice(0, 16)}-` +
      `${Date.now()}-${process.pid}-${crypto.randomBytes(4).toString('hex')}`
    );
    validateManifest(txRoot, prior, priorOptions);
    fs.renameSync(txRoot, archived);
  }
  ensureDir(path.join(txRoot, 'staged'));
  ensureDir(path.join(txRoot, 'backups'));
  const entries = [];
  const manifest = {
    schema_version: TRANSACTION_SCHEMA,
    transaction_id: transactionId,
    status: 'preparing',
    prepared_at: null,
    metadata,
    intent: requestedIntent,
    intent_sha256: requestedIntentSha256,
    writes: entries
  };
  writeJsonAtomic(manifestPath(txRoot), manifest);
  fault('after_initial_manifest', { faultAt });
  for (let index = 0; index < preparedWrites.length; index += 1) {
    const {
      target,
      containmentRoot,
      targetRelative,
      oldExists,
      oldBody,
      newBody
    } = preparedWrites[index];
    assertNoReparseParents(containmentRoot, target);
    const staged = `staged/${String(index).padStart(3, '0')}.new`;
    const backup = `backups/${String(index).padStart(3, '0')}.old`;
    writeFileAtomic(path.join(txRoot, staged), newBody);
    if (oldExists) writeFileAtomic(path.join(txRoot, backup), oldBody);
    entries.push({
      index,
      target,
      target_relative: targetRelative,
      containment_root: containmentRoot,
      old_exists: oldExists,
      old_sha256: oldExists ? sha256(oldBody) : null,
      new_sha256: sha256(newBody),
      staged,
      backup: oldExists ? backup : null
    });
    manifest.writes = entries;
    writeJsonAtomic(manifestPath(txRoot), manifest);
    fault(`after_stage_${index}`, { faultAt });
  }
  manifest.status = 'prepared';
  manifest.prepared_at = new Date().toISOString();
  writeJsonAtomic(manifestPath(txRoot), manifest);
  fault('after_prepare_manifest', { faultAt });
  const preparedSnapshot = readManifestSnapshot(txRoot), preparedManifest = preparedSnapshot.value;
  if (stableJson(preparedManifest) !== stableJson(manifest)) throw transactionError('transaction_recovery_binding_changed', 'Prepared manifest differs from the requested transaction');
  const boundOptions = {...transactionOptions, expectedManifestSha256:preparedSnapshot.sha256};
  const preparedEntries = validateManifest(txRoot, preparedManifest, boundOptions);
  // The caller's lock is necessary but not sufficient: another writer might
  // ignore it. Bind the commit intent only while every target still matches
  // the backed-up pre-transaction state.
  validateOldTargets(preparedEntries);
  validateGuardHashes(preparedManifest.intent.guards || []);
  writeFileAtomic(preparedManifestPath(txRoot), preparedSnapshot.body);
  writeJsonAtomic(commitMarkerPath(txRoot), {
    schema_version: TRANSACTION_SCHEMA,
    transaction_id: transactionId,
    committed_intent_at: new Date().toISOString(),
    manifest_sha256: preparedSnapshot.sha256
  });
  fault('after_commit_marker', { faultAt });
  try {
    validateGuardHashes(preparedManifest.intent.guards || [], {
      writes: preparedManifest.intent.writes,
      allowWriteTransitions: true
    });
    for (let index = 0; index < entries.length; index += 1) {
      validateGuardHashes(preparedManifest.intent.guards || [], {
        writes: preparedManifest.intent.writes,
        allowWriteTransitions: true
      });
      promoteNew(entries[index], txRoot, boundOptions);
      fault(`after_promote_${index}`, { faultAt });
    }
    validateGuardHashes(preparedManifest.intent.guards || [], {
      writes: preparedManifest.intent.writes,
      allowWriteTransitions: true
    });
    validateNewTargets(preparedEntries);
  } catch (error) {
    if (error.code !== 'transaction_guard_drift') throw error;
    rollbackGuardedCommit(
      txRoot,
      manifest,
      preparedEntries,
      error,
      boundOptions
    );
    throw error;
  }
  writeTerminalMarker(txRoot, manifest, 'committed', 'completed_commit', boundOptions);
  fault('after_committed_manifest', { faultAt });
  return {
    ...manifest,
    status: 'committed',
    committed_at: new Date().toISOString(),
    idempotent: false
  };
}

module.exports = {
  TRANSACTION_SCHEMA,
  copyInertData,
  commitJsonTransaction,
  recoverTransactions,
  recoverOne,
  inspectTransaction,
  treeGuardHash,
  relativeInside,
  assertNoReparseParents,
  __test: {
    sha256,
    fileHash,
    promoteNew,
    restoreOld,
    transactionRoot,
    validateTransactionId,
    normalizeAllowedContainmentRoots,
    containingTrustedRoot,
    intentPayload,
    intentHash,
    validateEntry,
    validateManifest,
    readVerifiedCommitMarker,
    readVerifiedTerminalMarker,
    writeTerminalMarker,
    validateOldTargets,
    validateNewTargets,
    validateRecoverableTargets,
    targetIdentity
  }
};
