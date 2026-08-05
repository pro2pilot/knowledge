'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  assertSafeContainmentRoot,
  assertSafeContainedPath,
  containedPath,
  ensureContainedDir,
  normalizeSystemAlias,
  sleepSync,
  writeFileAtomicContained,
} = require('./json-store');
const { removeTempDirStrict } = require('./strict-temp-cleanup');
const { LOCK_POLICY, lockDefinition } = require('./lock-policy');
const { canonicalOwnerText, sanitizedOwner, validateOwner } = require('./lock-owner-schema');

function lockError(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  for (const [key, value] of Object.entries(details)) error[key] = value;
  return error;
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function samePhysicalPath(left, right) {
  const a = normalizeSystemAlias(left);
  const b = normalizeSystemAlias(right);
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function ensureAllowedRoot(rootPath) {
  const requested = path.resolve(rootPath);
  let ancestor = requested;
  while (true) {
    try {
      fs.lstatSync(ancestor);
      break;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const parent = path.dirname(ancestor);
      if (parent === ancestor) throw error;
      ancestor = parent;
    }
  }
  const physicalAncestor = assertSafeContainmentRoot(ancestor);
  ensureContainedDir(physicalAncestor, requested);
  return assertSafeContainmentRoot(requested);
}

function policyDuration(value, fallback, minimum, maximum, field) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isFinite(number) || number < minimum || number > maximum) {
    throw lockError('lock_policy_limit', `${field} must be between ${minimum} and ${maximum} milliseconds.`);
  }
  return number;
}

function requestPolicy(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw lockError('lock_request_invalid', 'Contained lock acquisition requires a policy request object.');
  }
  const { rootKind, rootPath, lockName, purpose } = request;
  const definition = lockDefinition(lockName, rootKind, purpose, { maintainer: request.maintainer === true });
  let resourceId = request.resourceId === undefined || request.resourceId === null
    ? null : String(request.resourceId);
  if (definition.resource_id === 'task_hash_or_index') {
    if (resourceId !== 'index' && !/^[a-f0-9]{64}$/.test(String(resourceId || ''))) {
      throw lockError('lock_resource_id_invalid', 'Task-routing lock requires resource "index" or one canonical task hash.');
    }
  } else if (resourceId !== null) {
    throw lockError('lock_resource_id_forbidden', `Lock "${lockName}" does not accept a resource ID.`);
  }
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath)) {
    throw lockError('lock_path_outside_state_root', 'Contained lock acquisition requires an explicit absolute allowed root.');
  }
  if (!request.context || typeof request.context !== 'object' || Array.isArray(request.context)) {
    throw lockError('lock_request_invalid', 'Contained lock acquisition requires an explicit resolved context.');
  }
  const contextRootKey = rootKind === 'state' ? 'stateRoot'
    : (rootKind === 'project' ? 'projectKnowledgeRoot' : 'systemRoot');
  const expectedRoot = request.context[contextRootKey];
  if (typeof expectedRoot !== 'string' || !path.isAbsolute(expectedRoot) ||
      !samePhysicalPath(expectedRoot, rootPath)) {
    throw lockError('lock_root_context_mismatch', `Lock root does not match context.${contextRootKey}.`);
  }
  let root;
  try { root = ensureAllowedRoot(rootPath); }
  catch (error) {
    throw lockError('unsafe_lock_parent', 'The allowed lock root is not a physical directory.', { os_code: error.code || null });
  }
  return {
    ...request,
    rootKind,
    rootPath: root,
    lockName,
    purpose,
    resourceId,
    timeoutMs: policyDuration(
      request.timeoutMs === undefined ? process.env.KNOWLEDGE_LOCK_TIMEOUT_MS : request.timeoutMs,
      LOCK_POLICY.default_timeout_ms,
      LOCK_POLICY.min_timeout_ms,
      LOCK_POLICY.max_timeout_ms,
      'timeoutMs'
    ),
    staleMs: policyDuration(
      request.staleMs === undefined ? process.env.KNOWLEDGE_LOCK_STALE_MS : request.staleMs,
      LOCK_POLICY.default_stale_ms,
      LOCK_POLICY.min_stale_ms,
      LOCK_POLICY.max_stale_ms,
      'staleMs'
    ),
    retryMs: LOCK_POLICY.default_retry_ms,
    remoteStaleMs: LOCK_POLICY.remote_stale_ms,
  };
}

function lockPaths(policy) {
  const layoutRoot = path.join(policy.rootPath, 'locks');
  const versionRoot = path.join(layoutRoot, `v${LOCK_POLICY.layout_version}`);
  return {
    root: policy.rootPath,
    legacy: path.join(policy.rootPath, '.lock'),
    layoutRoot,
    versionRoot,
    staleRoot: path.join(versionRoot, '.stale'),
    releaseRoot: path.join(versionRoot, '.release'),
    lockDir: path.join(versionRoot, `${policy.lockName}${policy.resourceId ? `--${policy.resourceId}` : ''}.lock`),
  };
}

function mapContainmentFailure(error, code = 'unsafe_lock_parent') {
  if (error?.code && String(error.code).startsWith('lock_')) return error;
  return lockError(code, 'Lock storage is not physically contained in its allowed root.', { os_code: error?.code || null });
}

function validatePhysicalDirectory(root, directory, code = 'unsafe_lock_path') {
  let stat;
  try { stat = fs.lstatSync(directory); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw mapContainmentFailure(error, code);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw lockError(code, 'Lock path is not a physical directory.');
  }
  try {
    assertSafeContainedPath(root, directory);
    const real = fs.realpathSync.native ? fs.realpathSync.native(directory) : fs.realpathSync(directory);
    if (!samePhysicalPath(real, directory) || !containedPath(root, real)) {
      throw lockError(code, 'Lock directory resolves through a reparse point.');
    }
  } catch (error) {
    throw mapContainmentFailure(error, code);
  }
  return stat;
}

function statIdentity(stat) {
  return {
    dev: String(stat.dev),
    ino: String(stat.ino),
    size: String(stat.size),
    nlink: String(stat.nlink),
  };
}

function sameIdentity(left, right) {
  const a = statIdentity(left);
  const b = statIdentity(right);
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.nlink === b.nlink;
}

function boundedPhysicalRead(root, ownerPath) {
  let before;
  try { before = fs.lstatSync(ownerPath, { bigint: true }); }
  catch (error) {
    if (error.code === 'ENOENT') throw lockError('lock_owner_invalid', 'Lock owner metadata is missing.', { reason: 'missing' });
    throw mapContainmentFailure(error, 'unsafe_lock_owner');
  }
  if (!before.isFile() || before.isSymbolicLink()) {
    throw lockError('unsafe_lock_owner', 'Lock owner metadata is not a physical regular file.');
  }
  if (before.nlink !== 1n) {
    throw lockError('lock_owner_hardlinked', 'Lock owner metadata has more than one physical link.');
  }
  if (before.size > BigInt(LOCK_POLICY.owner_max_bytes)) {
    throw lockError('lock_owner_oversized', 'Lock owner metadata exceeds the policy size limit.');
  }
  try {
    assertSafeContainedPath(root, ownerPath);
    const real = fs.realpathSync.native ? fs.realpathSync.native(ownerPath) : fs.realpathSync(ownerPath);
    if (!samePhysicalPath(real, ownerPath) || !containedPath(root, real)) {
      throw lockError('unsafe_lock_owner', 'Lock owner metadata resolves through a reparse point.');
    }
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw lockError('lock_owner_invalid', 'Lock owner metadata is missing.', { reason: 'missing' });
    }
    throw mapContainmentFailure(error, 'unsafe_lock_owner');
  }

  let descriptor;
  const noFollow = process.platform === 'win32' ? 0 : (fs.constants.O_NOFOLLOW || 0);
  try { descriptor = fs.openSync(ownerPath, fs.constants.O_RDONLY | noFollow); }
  catch (error) {
    if (error?.code === 'ENOENT') {
      throw lockError('lock_owner_invalid', 'Lock owner metadata is missing.', { reason: 'missing' });
    }
    throw mapContainmentFailure(error, 'unsafe_lock_owner');
  }
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.size > BigInt(LOCK_POLICY.owner_max_bytes) || !sameIdentity(before, opened)) {
      throw lockError(opened.nlink !== 1n ? 'lock_owner_hardlinked' : 'unsafe_lock_owner', 'Lock owner identity changed before read.');
    }
    const raw = fs.readFileSync(descriptor, 'utf8');
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(opened, after)) throw lockError('unsafe_lock_owner', 'Lock owner identity changed during read.');
    return { raw, digest: hash(Buffer.from(raw, 'utf8')), stat: after };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readStrictOwner(root, lockDir, expected) {
  validatePhysicalDirectory(root, lockDir, 'unsafe_lock_path');
  const ownerPath = path.join(lockDir, 'owner.json');
  const read = boundedPhysicalRead(root, ownerPath);
  let owner;
  try { owner = JSON.parse(read.raw); }
  catch {
    throw lockError('lock_owner_invalid', 'Lock owner metadata is invalid (malformed_json).', { reason: 'malformed_json' });
  }
  try {
    validateOwner(owner, expected);
    if (canonicalOwnerText(owner) !== read.raw) {
      throw lockError('lock_owner_invalid', 'Lock owner metadata is invalid (noncanonical_json).', { reason: 'noncanonical_json' });
    }
  } catch (error) {
    if (error.code === 'lock_owner_invalid') throw error;
    throw lockError('lock_owner_invalid', 'Lock owner metadata is invalid.', { reason: 'schema' });
  }
  return { owner, digest: read.digest, stat: read.stat };
}

const LEGACY_FIELDS = Object.freeze(['lock_id', 'pid', 'hostname', 'agent_id', 'started_at', 'cwd']);

function readLegacyOwner(root, lockDir) {
  const ownerPath = path.join(lockDir, 'owner.json');
  const read = boundedPhysicalRead(root, ownerPath);
  let owner;
  try { owner = JSON.parse(read.raw); }
  catch {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid (malformed_json).', { reason: 'malformed_json' });
  }
  if (!owner || typeof owner !== 'object' || Array.isArray(owner)) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'not_object' });
  }
  const keys = Object.keys(owner);
  if (keys.some((key) => !LEGACY_FIELDS.includes(key)) || !['lock_id', 'pid', 'hostname', 'started_at'].every((key) => keys.includes(key))) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'unknown_or_missing_fields' });
  }
  if (typeof owner.lock_id !== 'string' || owner.lock_id.length < 1 || owner.lock_id.length > 128) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'lock_id_invalid' });
  }
  if (!Number.isSafeInteger(owner.pid) || owner.pid <= 0) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'pid_invalid' });
  }
  if (typeof owner.hostname !== 'string' || owner.hostname.length < 1 || owner.hostname.length > 255) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'hostname_invalid' });
  }
  if (owner.agent_id !== undefined && owner.agent_id !== null && (typeof owner.agent_id !== 'string' || owner.agent_id.length > 256)) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'agent_id_invalid' });
  }
  const started = Date.parse(owner.started_at);
  if (!Number.isFinite(started) || new Date(started).toISOString() !== owner.started_at) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'started_at_invalid' });
  }
  if (owner.cwd !== undefined && (typeof owner.cwd !== 'string' || owner.cwd.length > 2048)) {
    throw lockError('lock_owner_invalid', 'Legacy lock owner metadata is invalid.', { reason: 'cwd_invalid' });
  }
  return {
    owner,
    digest: read.digest,
    sanitized: {
      pid: owner.pid,
      hostname: owner.hostname,
      agent_id: typeof owner.agent_id === 'string' ? owner.agent_id : null,
      acquired_at: owner.started_at,
    },
  };
}

function processAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === 'EPERM'; }
}

function ownerDisposition(owner, ageMs, policy) {
  const local = String(owner.hostname || '').toLowerCase() === os.hostname().toLowerCase();
  if (local) {
    const alive = processAlive(Number(owner.pid));
    return {
      local: true,
      alive,
      stale: !alive && ageMs >= policy.staleMs,
      reason: alive ? 'live_local_owner' : (ageMs >= policy.staleMs ? 'dead_local_owner' : 'dead_local_owner_not_old_enough'),
    };
  }
  return {
    local: false,
    alive: null,
    stale: ageMs >= policy.remoteStaleMs,
    reason: ageMs >= policy.remoteStaleMs ? 'remote_owner_conservative_age_expired' : 'remote_owner_liveness_unverifiable',
  };
}

function inspectLegacy(policy) {
  const paths = lockPaths(policy);
  let stat;
  try { stat = fs.lstatSync(paths.legacy); }
  catch (error) {
    if (error.code === 'ENOENT') return { status: 'safe', present: false, findings: [] };
    return { status: 'unsafe', present: true, findings: [{ code: 'unsafe_lock_path', reason: 'lstat_failed', os_code: error.code || null }] };
  }
  try {
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw lockError('unsafe_lock_path', 'Legacy lock path is not a physical directory.');
    validatePhysicalDirectory(policy.rootPath, paths.legacy, 'unsafe_lock_path');
    const read = readLegacyOwner(policy.rootPath, paths.legacy);
    const ageMs = Math.max(0, Date.now() - stat.mtimeMs);
    const disposition = ownerDisposition(read.owner, ageMs, policy);
    return {
      status: disposition.stale ? 'stale' : 'active',
      present: true,
      findings: [],
      age_ms: ageMs,
      disposition,
      owner: read.owner,
      owner_digest: read.digest,
      sanitized_owner: read.sanitized,
    };
  } catch (error) {
    return {
      status: 'unsafe',
      present: true,
      findings: [{ code: error.code || 'unsafe_lock_owner', reason: error.reason || 'unsafe_legacy_lock', os_code: error.os_code || null }],
    };
  }
}

function ensureLayout(policy) {
  const paths = lockPaths(policy);
  try {
    ensureContainedDir(policy.rootPath, paths.layoutRoot);
    ensureContainedDir(policy.rootPath, paths.versionRoot);
    ensureContainedDir(policy.rootPath, paths.staleRoot);
    ensureContainedDir(policy.rootPath, paths.releaseRoot);
  } catch (error) {
    throw mapContainmentFailure(error, 'unsafe_lock_parent');
  }
  return paths;
}

function strictRemoveDirectory(root, directory) {
  validatePhysicalDirectory(root, directory, 'unsafe_lock_path');
  removeTempDirStrict(directory, {
    label: 'contained lock directory',
    retryCodes: ['EBUSY', 'EPERM', 'ENOTEMPTY', 'EACCES'],
  });
  if (fs.existsSync(directory)) throw lockError('lock_cleanup_failed', 'Contained lock directory cleanup did not complete.');
}

function quarantineName(prefix, policy) {
  return `${prefix}-${policy.lockName}-${crypto.randomUUID()}.lock`;
}

function recoverLegacy(policy, inspected) {
  if (inspected.status !== 'stale' || !inspected.owner_digest) {
    throw lockError('unsafe_lock_path', 'Legacy lock cannot be recovered without validated stale ownership.');
  }
  const paths = ensureLayout(policy);
  const current = inspectLegacy(policy);
  if (current.status !== 'stale' || current.owner_digest !== inspected.owner_digest) {
    throw lockError('lock_ownership_changed', 'Legacy lock ownership changed before recovery.');
  }
  const quarantine = path.join(paths.staleRoot, quarantineName('legacy', policy));
  try { fs.renameSync(paths.legacy, quarantine); }
  catch (error) {
    if (error.code === 'ENOENT') return { recovered: false, reason: 'lock_disappeared' };
    throw mapContainmentFailure(error, 'unsafe_lock_path');
  }
  validatePhysicalDirectory(policy.rootPath, quarantine, 'unsafe_lock_path');
  const moved = readLegacyOwner(policy.rootPath, quarantine);
  if (moved.digest !== inspected.owner_digest) {
    throw lockError('lock_ownership_changed', 'Legacy lock ownership changed during recovery.');
  }
  strictRemoveDirectory(policy.rootPath, quarantine);
  const event = {
    schema_version: 'knowledge-lock-recovery.v1',
    recovery_id: crypto.randomUUID(),
    lock_name: policy.lockName,
    reason: inspected.disposition.reason,
    owner: inspected.sanitized_owner,
  };
  if (typeof policy.onRecovery === 'function') policy.onRecovery(event);
  return { recovered: true, event };
}

function timeoutError(policy, owner) {
  const safe = owner || {};
  const pid = Number.isSafeInteger(safe.pid) && safe.pid > 0 ? safe.pid : 'unknown';
  const hostname = typeof safe.hostname === 'string' && safe.hostname ? safe.hostname : 'unknown';
  const since = typeof safe.acquired_at === 'string' && safe.acquired_at ? ` since ${safe.acquired_at}` : '';
  return lockError('lock_timeout', `Lock "${policy.lockName}" is held by pid ${pid} on host "${hostname}"${since}.`);
}

function waitForLegacy(policy, startedAt) {
  while (true) {
    const inspected = inspectLegacy(policy);
    if (!inspected.present) return;
    if (inspected.status === 'unsafe') {
      const finding = inspected.findings[0] || { code: 'unsafe_lock_path' };
      throw lockError(finding.code, 'Legacy lock storage is unsafe.', { reason: finding.reason || null });
    }
    if (inspected.status === 'stale') {
      recoverLegacy(policy, inspected);
      continue;
    }
    if (Date.now() - startedAt >= policy.timeoutMs) throw timeoutError(policy, inspected.sanitized_owner);
    sleepSync(policy.retryMs);
  }
}

function createOwner(policy) {
  const now = new Date().toISOString();
  return {
    schema_version: 'knowledge-lock-owner.v1',
    lock_id: crypto.randomUUID(),
    lock_name: policy.lockName,
    purpose: policy.purpose,
    pid: process.pid,
    hostname: os.hostname(),
    agent_id: typeof policy.context?.agentId === 'string'
      ? policy.context.agentId
      : (typeof process.env.KNOWLEDGE_AGENT_ID === 'string' ? process.env.KNOWLEDGE_AGENT_ID : null),
    workspace_id: typeof policy.context?.workspaceId === 'string' ? policy.context.workspaceId : null,
    process_started_at: new Date(Date.now() - process.uptime() * 1000).toISOString(),
    acquired_at: now,
    nonce: crypto.randomBytes(32).toString('hex'),
  };
}

function inspectCurrent(policy, paths) {
  let stat;
  try { stat = fs.lstatSync(paths.lockDir); }
  catch (error) {
    if (error.code === 'ENOENT') return { status: 'missing' };
    throw mapContainmentFailure(error, 'unsafe_lock_path');
  }
  const currentDirectory = () => {
    try {
      // A releasing owner may rename its physical directory after the lstat
      // above but before the containment walk reaches it. That is a normal
      // lock-state transition, not evidence of a reparse point.
      return validatePhysicalDirectory(policy.rootPath, paths.lockDir, 'unsafe_lock_path');
    } catch (error) {
      if (error?.os_code === 'ENOENT') return null;
      throw error;
    }
  };
  if (!currentDirectory()) return { status: 'missing' };
  let read;
  try { read = readStrictOwner(policy.rootPath, paths.lockDir, { lockName: policy.lockName, purpose: policy.purpose }); }
  catch (error) {
    // A releasing owner can rename its directory after currentDirectory()
    // succeeded but before readStrictOwner() repeats the physical walk. An
    // ENOENT at that exact boundary is an expected state transition. Any
    // surviving path is validated again by the next acquire loop; reparse,
    // symlink, ownership, and non-ENOENT containment failures stay strict.
    if (error.code === 'unsafe_lock_path' && error.os_code === 'ENOENT') {
      return { status: 'missing' };
    }
    if (error.code === 'lock_owner_invalid' && error.reason === 'missing') {
      const refreshed = currentDirectory();
      if (!refreshed) return { status: 'missing' };
      const ageMs = Math.max(0, Date.now() - refreshed.mtimeMs);
      if (ageMs < LOCK_POLICY.owner_initialization_grace_ms) {
        return { status: 'initializing', age_ms: ageMs };
      }
    }
    throw error;
  }
  const ageMs = Math.max(0, Date.now() - stat.mtimeMs);
  const disposition = ownerDisposition(read.owner, ageMs, policy);
  return {
    status: disposition.stale ? 'stale' : 'active',
    owner: read.owner,
    owner_digest: read.digest,
    sanitized_owner: sanitizedOwner(read.owner),
    disposition,
    age_ms: ageMs,
  };
}

function recoverCurrent(policy, paths, inspected) {
  const latest = inspectCurrent(policy, paths);
  if (latest.status !== 'stale' || latest.owner_digest !== inspected.owner_digest) {
    throw lockError('lock_ownership_changed', 'Lock ownership changed before stale recovery.');
  }
  const quarantine = path.join(paths.staleRoot, quarantineName('stale', policy));
  try { fs.renameSync(paths.lockDir, quarantine); }
  catch (error) {
    if (error.code === 'ENOENT') return { recovered: false, reason: 'lock_disappeared' };
    throw mapContainmentFailure(error, 'unsafe_lock_path');
  }
  validatePhysicalDirectory(policy.rootPath, quarantine, 'unsafe_lock_path');
  const moved = readStrictOwner(policy.rootPath, quarantine, { lockName: policy.lockName, purpose: policy.purpose });
  if (moved.digest !== inspected.owner_digest) {
    throw lockError('lock_ownership_changed', 'Lock ownership changed during stale recovery.');
  }
  strictRemoveDirectory(policy.rootPath, quarantine);
  const event = {
    schema_version: 'knowledge-lock-recovery.v1',
    recovery_id: crypto.randomUUID(),
    lock_name: policy.lockName,
    reason: inspected.disposition.reason,
    owner: inspected.sanitized_owner,
  };
  if (typeof policy.onRecovery === 'function') policy.onRecovery(event);
  return { recovered: true, event };
}

function cleanupCreatedLock(policy, paths, ownerDigest) {
  const inspected = inspectCurrent(policy, paths);
  if (!['active', 'stale'].includes(inspected.status) || inspected.owner_digest !== ownerDigest) {
    throw lockError('lock_ownership_changed', 'New lock ownership changed before cleanup.');
  }
  const quarantine = path.join(paths.releaseRoot, quarantineName('failed-acquire', policy));
  fs.renameSync(paths.lockDir, quarantine);
  validatePhysicalDirectory(policy.rootPath, quarantine, 'unsafe_lock_path');
  const moved = readStrictOwner(policy.rootPath, quarantine, { lockName: policy.lockName, purpose: policy.purpose });
  if (moved.digest !== ownerDigest) throw lockError('lock_ownership_changed', 'New lock ownership changed during cleanup.');
  strictRemoveDirectory(policy.rootPath, quarantine);
}

function cleanupEmptyCreatedLock(policy, paths) {
  validatePhysicalDirectory(policy.rootPath, paths.lockDir, 'unsafe_lock_path');
  const entries = fs.readdirSync(paths.lockDir);
  if (entries.length) {
    throw lockError('lock_ownership_changed', 'Uninitialized lock directory gained content before cleanup.');
  }
  strictRemoveDirectory(policy.rootPath, paths.lockDir);
}

function acquireContainedLock(request) {
  const policy = requestPolicy(request);
  const startedAt = Date.now();
  waitForLegacy(policy, startedAt);
  const paths = ensureLayout(policy);
  let owner;
  let ownerDigest;

  while (true) {
    let createdDirectory = false;
    let ownerWritten = false;
    try {
      fs.mkdirSync(paths.lockDir);
      createdDirectory = true;
      validatePhysicalDirectory(policy.rootPath, paths.lockDir, 'unsafe_lock_path');
      owner = createOwner(policy);
      const ownerText = canonicalOwnerText(owner);
      writeFileAtomicContained(path.join(paths.lockDir, 'owner.json'), ownerText, policy.rootPath);
      ownerWritten = true;
      const verified = readStrictOwner(policy.rootPath, paths.lockDir, { lockName: policy.lockName, purpose: policy.purpose });
      ownerDigest = verified.digest;
      break;
    } catch (error) {
      if (error.code !== 'EEXIST') {
        if (createdDirectory && fs.existsSync(paths.lockDir)) {
          try {
            if (ownerWritten) {
              const written = readStrictOwner(policy.rootPath, paths.lockDir, { lockName: policy.lockName, purpose: policy.purpose });
              cleanupCreatedLock(policy, paths, written.digest);
            } else cleanupEmptyCreatedLock(policy, paths);
          }
          catch (cleanupError) { error.lock_cleanup_error = cleanupError.code || 'lock_cleanup_failed'; }
        }
        throw error;
      }
      const inspected = inspectCurrent(policy, paths);
      if (inspected.status === 'missing') continue;
      if (inspected.status === 'stale') {
        recoverCurrent(policy, paths, inspected);
        continue;
      }
      if (Date.now() - startedAt >= policy.timeoutMs) {
        throw timeoutError(policy, inspected.sanitized_owner);
      }
      sleepSync(policy.retryMs);
    }
  }

  let released = false;
  const handle = {
    lock_id: owner.lock_id,
    lock_name: policy.lockName,
    path: paths.lockDir,
    owner_digest: ownerDigest,
    acquired_at: owner.acquired_at,
    release() {
      if (released) return { status: 'already_released' };
      const current = inspectCurrent(policy, paths);
      if (!['active', 'stale'].includes(current.status) ||
          current.owner_digest !== ownerDigest ||
          current.owner.lock_id !== owner.lock_id ||
          current.owner.nonce !== owner.nonce) {
        throw lockError('lock_ownership_changed', `Lock "${policy.lockName}" ownership changed before release.`);
      }
      const releasePath = path.join(paths.releaseRoot, quarantineName('release', policy));
      try { fs.renameSync(paths.lockDir, releasePath); }
      catch (error) {
        if (error.code === 'ENOENT') throw lockError('lock_ownership_changed', `Lock "${policy.lockName}" disappeared before release.`);
        throw mapContainmentFailure(error, 'unsafe_lock_path');
      }
      validatePhysicalDirectory(policy.rootPath, releasePath, 'unsafe_lock_path');
      const moved = readStrictOwner(policy.rootPath, releasePath, { lockName: policy.lockName, purpose: policy.purpose });
      if (moved.digest !== ownerDigest || moved.owner.lock_id !== owner.lock_id || moved.owner.nonce !== owner.nonce) {
        throw lockError('lock_ownership_changed', `Lock "${policy.lockName}" ownership changed during release.`);
      }
      strictRemoveDirectory(policy.rootPath, releasePath);
      released = true;
      return { status: 'released' };
    },
  };
  return handle;
}

function withContainedLock(request, fn) {
  if (typeof fn !== 'function') throw lockError('lock_callback_invalid', 'Contained lock callback must be a function.');
  const handle = acquireContainedLock(request);
  let result;
  let callbackError = null;
  try { result = fn(handle); }
  catch (error) { callbackError = error; }
  try { handle.release(); }
  catch (releaseError) {
    if (!callbackError) throw releaseError;
    callbackError.lock_release_error = releaseError.code || 'lock_release_failed';
  }
  if (callbackError) throw callbackError;
  return result;
}

function inspectLockDirectory(policy, paths) {
  try {
    const current = inspectCurrent(policy, paths);
    if (current.status === 'missing') return { status: 'safe', findings: [] };
    if (current.status === 'initializing') return { status: 'active', findings: [], owner: null };
    return {
      status: current.status,
      findings: [],
      owner: current.sanitized_owner,
      reason: current.disposition.reason,
    };
  } catch (error) {
    return { status: 'unsafe', findings: [{ code: error.code || 'unsafe_lock_path', reason: error.reason || 'unsafe_lock' }] };
  }
}

function inspectLockSafety(request) {
  let policy;
  try { policy = requestPolicy(request); }
  catch (error) {
    return { status: 'unsafe', findings: [{ code: error.code || 'unsafe_lock_parent', reason: 'invalid_lock_request' }] };
  }
  const paths = lockPaths(policy);
  const findings = [];
  const legacy = inspectLegacy(policy);
  findings.push(...legacy.findings.map((finding) => ({ ...finding, layout: 'legacy' })));

  for (const [label, directory] of [['locks', paths.layoutRoot], ['version', paths.versionRoot]]) {
    if (!fs.existsSync(directory)) continue;
    try { validatePhysicalDirectory(policy.rootPath, directory, 'unsafe_lock_parent'); }
    catch (error) { findings.push({ code: error.code || 'unsafe_lock_parent', reason: `${label}_parent_unsafe` }); }
  }
  let current = { status: 'safe', findings: [] };
  if (!findings.length && fs.existsSync(paths.versionRoot)) current = inspectLockDirectory(policy, paths);
  findings.push(...current.findings.map((finding) => ({ ...finding, layout: 'v1', lock_name: policy.lockName })));
  const status = findings.length
    ? 'unsafe'
    : ([legacy.status, current.status].includes('active') ? 'active'
      : ([legacy.status, current.status].includes('stale') ? 'stale' : 'safe'));
  return {
    schema_version: 'knowledge-lock-safety.v1',
    lock_name: policy.lockName,
    resource_id: policy.resourceId,
    root_kind: policy.rootKind,
    status,
    findings,
    legacy: { present: legacy.present, status: legacy.status, owner: legacy.sanitized_owner || null },
    current: { status: current.status, owner: current.owner || null },
  };
}

function inspectAllLockSafety({ rootPath, rootKind = 'state' }) {
  const findings = [];
  const states = [];
  for (const [lockName, definition] of Object.entries(LOCK_POLICY.locks)) {
    if (!definition.root_kinds.includes(rootKind)) continue;
    let resourceIds = [null];
    if (definition.resource_id === 'task_hash_or_index') {
      const versionRoot = path.join(path.resolve(rootPath), 'locks', `v${LOCK_POLICY.layout_version}`);
      resourceIds = [];
      if (fs.existsSync(versionRoot)) {
        try {
          validatePhysicalDirectory(path.resolve(rootPath), versionRoot, 'unsafe_lock_parent');
          resourceIds = fs.readdirSync(versionRoot)
            .map((name) => name.match(/^task-routing--(index|[a-f0-9]{64})\.lock$/)?.[1] || null)
            .filter(Boolean);
        } catch (error) {
          findings.push({ code: error.code || 'unsafe_lock_parent', reason: 'resource_layout_scan_failed' });
        }
      }
    }
    for (const resourceId of resourceIds) {
      const contextRootKey = rootKind === 'state' ? 'stateRoot'
        : (rootKind === 'project' ? 'projectKnowledgeRoot' : 'systemRoot');
      const result = inspectLockSafety({
        rootPath,
        rootKind,
        lockName,
        purpose: definition.purpose,
        resourceId,
        context: { [contextRootKey]: path.resolve(rootPath) }
      });
      states.push(result);
      for (const finding of result.findings) {
        if (!findings.some((item) => item.code === finding.code && item.layout === finding.layout && item.reason === finding.reason)) {
          findings.push(finding);
        }
      }
    }
  }
  let unknownLayout = false;
  try {
    const versionRoot = path.join(path.resolve(rootPath), 'locks', `v${LOCK_POLICY.layout_version}`);
    if (fs.existsSync(versionRoot)) {
      validatePhysicalDirectory(path.resolve(rootPath), versionRoot, 'unsafe_lock_parent');
      const allowed = new Set(['.stale', '.release', ...Object.entries(LOCK_POLICY.locks)
        .filter(([, definition]) => !definition.resource_id)
        .map(([name]) => `${name}.lock`)]);
      unknownLayout = fs.readdirSync(versionRoot).some((name) =>
        !allowed.has(name) && !/^task-routing--(?:index|[a-f0-9]{64})\.lock$/.test(name));
      if (unknownLayout) findings.push({ code: 'lock_layout_unsupported', reason: 'unknown_layout_entry', layout: 'v1' });
    }
  } catch (error) {
    if (!findings.some((item) => item.code === (error.code || 'unsafe_lock_parent'))) {
      findings.push({ code: error.code || 'unsafe_lock_parent', reason: 'layout_scan_failed' });
    }
  }
  const status = findings.length ? 'unsafe'
    : (states.some((item) => item.status === 'active') ? 'active'
      : (states.some((item) => item.status === 'stale') ? 'stale' : 'safe'));
  return {
    schema_version: 'knowledge-lock-safety.v1',
    status,
    findings,
    layout_version: LOCK_POLICY.layout_version,
    locks: states.map((item) => ({ lock_name: item.lock_name, resource_id: item.resource_id || null, status: item.status, legacy: item.legacy, current: item.current })),
  };
}

const CONTEXT_ROOT_KEYS = Object.freeze({
  state: 'stateRoot',
  project: 'projectKnowledgeRoot',
  system: 'systemRoot',
});

function aggregateLockStatus(statuses) {
  const values = Array.from(statuses || []);
  if (values.includes('unsafe')) return 'unsafe';
  if (values.includes('active')) return 'active';
  if (values.includes('stale')) return 'stale';
  return 'safe';
}

function safeRootIdentity(rootKind, rootPath) {
  const lexicalPath = typeof rootPath === 'string' && rootPath.trim() && path.isAbsolute(rootPath)
    ? path.resolve(rootPath)
    : null;
  if (!lexicalPath) {
    return {
      root_kind: rootKind,
      valid: false,
      lexical_path: null,
      canonical_path: null,
      physical_root_id: null,
      finding: { code: 'unsafe_lock_root', reason: 'context_root_missing_or_relative' }
    };
  }
  try {
    const root = assertSafeContainmentRoot(lexicalPath);
    const canonicalPath = fs.realpathSync.native ? fs.realpathSync.native(root) : fs.realpathSync(root);
    const stat = fs.statSync(root, { bigint: true });
    const inode = stat.ino === 0n ? samePhysicalPath(canonicalPath, root) ? path.resolve(canonicalPath) : root : `${stat.dev}:${stat.ino}`;
    return {
      root_kind: rootKind,
      valid: true,
      lexical_path: lexicalPath,
      canonical_path: path.resolve(canonicalPath),
      physical_root_id: hash(`knowledge-lock-root.v1:${inode}`),
    };
  } catch (error) {
    return {
      root_kind: rootKind,
      valid: false,
      lexical_path: lexicalPath,
      canonical_path: null,
      physical_root_id: null,
      finding: { code: 'unsafe_lock_root', reason: error.code || 'context_root_unsafe' }
    };
  }
}

function contextRootKinds(options = {}) {
  const roots = ['state', 'project'];
  if (options.maintainer === true && options.includeSystem === true) roots.push('system');
  return roots;
}

function definitionsForRootKinds(rootKinds) {
  return Object.entries(LOCK_POLICY.locks)
    .filter(([, definition]) => definition.root_kinds.some((kind) => rootKinds.includes(kind)))
    .map(([lockName, definition]) => ({ lockName, definition }))
    .sort((left, right) => left.lockName.localeCompare(right.lockName));
}

function requestForDefinition(rootPath, rootKinds, context, lockName, definition, resourceId = null, options = {}) {
  const rootKind = definition.root_kinds.find((kind) => rootKinds.includes(kind));
  const key = CONTEXT_ROOT_KEYS[rootKind];
  return {
    context,
    rootKind,
    rootPath,
    lockName,
    purpose: definition.purpose,
    resourceId,
    ...(rootKind === 'system' && options.maintainer === true ? { maintainer: true } : {}),
    [key]: context[key]
  };
}

function resourceIdsForDefinition(rootPath, definition, versionRoot) {
  if (definition.resource_id !== 'task_hash_or_index') return [null];
  if (!fs.existsSync(versionRoot)) return [];
  validatePhysicalDirectory(rootPath, versionRoot, 'unsafe_lock_parent');
  return fs.readdirSync(versionRoot)
    .map((name) => name.match(/^task-routing--(index|[a-f0-9]{64})\.lock$/)?.[1] || null)
    .filter(Boolean);
}

function inspectPhysicalRootLockSafety(rootGroup, context, options = {}) {
  const rootKinds = rootGroup.root_kinds;
  const rootPath = rootGroup.canonical_path;
  const definitions = definitionsForRootKinds(rootKinds);
  const rootFindings = [];
  const states = [];
  const seenFindings = new Set();
  const baseRequest = requestForDefinition(rootPath, rootKinds, context, definitions[0].lockName, definitions[0].definition, null, options);
  const basePolicy = requestPolicy(baseRequest);
  const paths = lockPaths(basePolicy);
  const addFinding = (finding, metadata = {}) => {
    const output = {
      code: finding.code || 'unsafe_lock_path',
      reason: finding.reason || 'unsafe_lock',
      ...(finding.layout ? { layout: finding.layout } : {}),
      ...(metadata.lock_name ? { lock_name: metadata.lock_name } : {}),
      ...(metadata.resource_id ? { resource_id: metadata.resource_id } : {}),
      root_kinds: rootKinds,
      physical_root_id: rootGroup.physical_root_id,
    };
    const key = JSON.stringify([output.code, output.reason, output.layout || null, output.lock_name || null, output.resource_id || null, output.physical_root_id]);
    if (!seenFindings.has(key)) {
      seenFindings.add(key);
      rootFindings.push(output);
    }
  };

  const legacy = inspectLegacy(basePolicy);
  for (const finding of legacy.findings) addFinding({ ...finding, layout: 'legacy' });

  let layoutSafe = true;
  for (const [label, directory] of [['locks', paths.layoutRoot], ['version', paths.versionRoot]]) {
    if (!fs.existsSync(directory)) continue;
    try { validatePhysicalDirectory(rootPath, directory, 'unsafe_lock_parent'); }
    catch (error) {
      layoutSafe = false;
      addFinding({ code: error.code || 'unsafe_lock_parent', reason: `${label}_parent_unsafe`, layout: 'v1' });
    }
  }

  if (layoutSafe && fs.existsSync(paths.versionRoot)) {
    try {
      const allowed = new Set(['.stale', '.release', ...definitions
        .filter(({ definition }) => !definition.resource_id)
        .map(({ lockName }) => `${lockName}.lock`)]);
      const unsupported = fs.readdirSync(paths.versionRoot).some((name) =>
        !allowed.has(name) && !/^task-routing--(?:index|[a-f0-9]{64})\.lock$/.test(name));
      if (unsupported) addFinding({ code: 'lock_layout_unsupported', reason: 'unknown_layout_entry', layout: 'v1' });
    } catch (error) {
      layoutSafe = false;
      addFinding({ code: error.code || 'unsafe_lock_parent', reason: 'layout_scan_failed', layout: 'v1' });
    }
  }

  if (layoutSafe) {
    for (const { lockName, definition } of definitions) {
      let resourceIds;
      try { resourceIds = resourceIdsForDefinition(rootPath, definition, paths.versionRoot); }
      catch (error) {
        addFinding({ code: error.code || 'unsafe_lock_parent', reason: 'resource_layout_scan_failed', layout: 'v1' }, { lock_name: lockName });
        continue;
      }
      for (const resourceId of resourceIds) {
        let policy;
        try {
          policy = requestPolicy(requestForDefinition(rootPath, rootKinds, context, lockName, definition, resourceId, options));
        } catch (error) {
          addFinding({ code: error.code || 'unsafe_lock_parent', reason: 'invalid_lock_request', layout: 'v1' }, { lock_name: lockName, resource_id: resourceId });
          continue;
        }
        const inspected = inspectLockDirectory(policy, lockPaths(policy));
        for (const finding of inspected.findings) addFinding({ ...finding, layout: 'v1' }, { lock_name: lockName, resource_id: resourceId });
        states.push({
          lock_name: lockName,
          resource_id: resourceId,
          root_kind: policy.rootKind,
          status: inspected.status,
          current: { status: inspected.status, owner: inspected.owner || null },
        });
      }
    }
  }

  const status = aggregateLockStatus([
    rootFindings.length ? 'unsafe' : 'safe',
    legacy.status,
    ...states.map((item) => item.status)
  ]);
  return {
    root_kind: rootKinds.length === 1 ? rootKinds[0] : 'shared',
    root_kinds: rootKinds,
    lexical_paths: rootGroup.lexical_paths,
    canonical_path: rootGroup.canonical_path,
    physical_root_id: rootGroup.physical_root_id,
    definitions: definitions.map(({ lockName }) => lockName),
    status,
    findings: rootFindings,
    legacy: {
      present: legacy.present,
      status: legacy.status,
      owner: legacy.sanitized_owner || null,
    },
    locks: states,
    summary: {
      definitions_checked: definitions.length,
      physical_locks_checked: states.length + (legacy.present ? 1 : 0),
    }
  };
}

// Inspect the only public lock roots selected by a fully resolved context.
// Callers cannot supply lock names or arbitrary lock paths; the policy registry
// remains the sole definition selector.
function inspectContextLockSafety(context, options = {}) {
  const sourceContext = context && typeof context === 'object' && !Array.isArray(context) ? context : {};
  const roots = [];
  const groups = new Map();
  for (const rootKind of contextRootKinds(options)) {
    const identity = safeRootIdentity(rootKind, sourceContext[CONTEXT_ROOT_KEYS[rootKind]]);
    if (!identity.valid) {
      roots.push({
        root_kind: rootKind,
        root_kinds: [rootKind],
        lexical_paths: [{ root_kind: rootKind, path: identity.lexical_path }],
        canonical_path: null,
        physical_root_id: null,
        definitions: definitionsForRootKinds([rootKind]).map(({ lockName }) => lockName),
        status: 'unsafe',
        findings: [{ ...identity.finding, root_kinds: [rootKind], physical_root_id: null }],
        legacy: { present: false, status: 'safe', owner: null },
        locks: [],
        summary: { definitions_checked: 0, physical_locks_checked: 0 }
      });
      continue;
    }
    let group = groups.get(identity.physical_root_id);
    if (!group) {
      group = {
        root_kinds: [],
        lexical_paths: [],
        canonical_path: identity.canonical_path,
        physical_root_id: identity.physical_root_id,
      };
      groups.set(identity.physical_root_id, group);
    }
    group.root_kinds.push(rootKind);
    group.lexical_paths.push({ root_kind: rootKind, path: identity.lexical_path });
  }

  for (const group of groups.values()) roots.push(inspectPhysicalRootLockSafety(group, sourceContext, options));
  const findings = roots.flatMap((item) => item.findings);
  const status = aggregateLockStatus(roots.map((item) => item.status));
  const duplicatesAvoided = Array.from(groups.values()).reduce((total, group) => total + Math.max(0, group.root_kinds.length - 1), 0);
  return {
    schema_version: 'knowledge-context-lock-safety.v1',
    status,
    roots,
    findings,
    summary: {
      roots_checked: roots.length,
      definitions_checked: roots.reduce((total, item) => total + item.summary.definitions_checked, 0),
      physical_locks_checked: roots.reduce((total, item) => total + item.summary.physical_locks_checked, 0),
      duplicates_avoided: duplicatesAvoided,
    },
    layout_version: LOCK_POLICY.layout_version,
    // Retained for consumers of the RC39 single-root shape.
    locks: roots.flatMap((item) => item.locks.map((lock) => ({
      ...lock,
      root_kinds: item.root_kinds,
      physical_root_id: item.physical_root_id,
    }))),
  };
}

module.exports = {
  acquireContainedLock,
  withContainedLock,
  inspectLockSafety,
  inspectAllLockSafety,
  inspectContextLockSafety,
  lockPaths,
  __test: {
    boundedPhysicalRead,
    createOwner,
    inspectLegacy,
    inspectCurrent,
    ownerDisposition,
    readLegacyOwner,
    readStrictOwner,
    requestPolicy,
    cleanupEmptyCreatedLock,
  },
};
