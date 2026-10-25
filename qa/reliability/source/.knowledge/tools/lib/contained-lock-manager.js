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
const { LOCK_POLICY, lockDefinition, validNativeOwnerIdentity } = require('./lock-policy');
const { canonicalOwnerText, sanitizedOwner, validateOwner } = require('./lock-owner-schema');
const { qualifyNativePublication, publishPreparedLock, probeOwnerLease, closeOwnerLease } = require('./lock-publication');

function lockError(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  for (const [key, value] of Object.entries(details)) error[key] = value;
  return error;
}

function elapsedBudgetMs(startedAt) {
  // Elapsed waiting must survive wall-clock steps. Keep wall timestamps and
  // stale-age observations separate; policy durations may include fractions.
  return Number(process.hrtime.bigint() - startedAt) / 1e6;
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

function validatePhysicalDirectory(root, directory, code = 'unsafe_lock_path', statOptions, namespaceTransition) {
  let stat;
  try { stat = fs.lstatSync(directory, statOptions); }
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
      // Windows can resolve an open directory handle at its new release name.
      // Acquisition may discard this observation only after a separate strict
      // walk proves the original physical directory disappeared or changed.
      if (namespaceTransition && namespaceTransition(stat)) return null;
      throw lockError(code, 'Lock directory resolves through a reparse point.');
    }
  } catch (error) {
    if (process.platform === 'win32' && error.code === 'EBADF' &&
        namespaceTransition && namespaceTransition(stat)) return null;
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
    // Owner bytes are immutable after publication. A same-length write must
    // not pass merely because device/inode/length stayed the same. Exclude
    // atime: the read itself may legitimately update it.
    mtime: String(stat.mtimeNs ?? stat.mtimeMs),
    ctime: String(stat.ctimeNs ?? stat.ctimeMs),
  };
}

function sameIdentity(left, right) {
  const a = statIdentity(left);
  const b = statIdentity(right);
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.nlink === b.nlink &&
    a.mtime === b.mtime && a.ctime === b.ctime;
}

function sameDirectoryIdentity(left, right) {
  // Publishing or removing owner.json changes directory size/link metadata.
  // Only physical device/inode identity proves directory replacement.
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}

function boundedPhysicalRead(root, ownerPath, maximum = LOCK_POLICY.owner_max_bytes) {
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
  if (before.size > BigInt(maximum)) {
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
  // The path can become a FIFO after lstat. Nonblocking open reaches the
  // descriptor type check without waiting for a writer. It does not claim to
  // place a deadline on slow regular-file I/O or on Windows reparse handling.
  const nonblock = process.platform === 'win32' ? 0 : (fs.constants.O_NONBLOCK || 0);
  try { descriptor = fs.openSync(ownerPath, fs.constants.O_RDONLY | noFollow | nonblock); }
  catch (error) {
    if (error?.code === 'ENOENT') {
      throw lockError('lock_owner_invalid', 'Lock owner metadata is missing.', { reason: 'missing' });
    }
    throw mapContainmentFailure(error, 'unsafe_lock_owner');
  }
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || opened.size > BigInt(maximum) || !sameIdentity(before, opened)) {
      throw lockError(opened.nlink !== 1n ? 'lock_owner_hardlinked' : 'unsafe_lock_owner', 'Lock owner identity changed before read.');
    }
    // Bound allocation and actual reads, including growth after fstat. The
    // extra byte distinguishes the exact maximum from an oversized stream.
    const buffer = Buffer.alloc(maximum + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = fs.readSync(descriptor, buffer, used, buffer.length - used, null);
      if (!count) break;
      used += count;
    }
    if (used > maximum) {
      throw lockError('lock_owner_oversized', 'Lock owner metadata exceeds the policy size limit.');
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(opened, after) || BigInt(used) !== opened.size) {
      throw lockError('unsafe_lock_owner', 'Lock owner identity changed or its read ended prematurely.');
    }
    let current;
    try { current = fs.lstatSync(ownerPath, { bigint: true }); }
    catch (error) {
      if (error.code === 'ENOENT') throw lockError('lock_owner_invalid', 'Lock owner metadata is missing.', { reason: 'missing' });
      throw mapContainmentFailure(error, 'unsafe_lock_owner');
    }
    if (!current.isFile() || current.isSymbolicLink() || !sameIdentity(after, current)) {
      throw lockError(current.nlink !== 1n ? 'lock_owner_hardlinked' : 'unsafe_lock_owner', 'Lock owner path identity changed after read.');
    }
    // Renaming a parent and replacing it with a symlink can leave the exact
    // owner inode and all its metadata unchanged. Recheck the full physical
    // path after reading, not only the final component. This is a conservative
    // observation check, not an atomic openat walk of every ancestor.
    try {
      assertSafeContainedPath(root, ownerPath);
      const real = fs.realpathSync.native ? fs.realpathSync.native(ownerPath) : fs.realpathSync(ownerPath);
      if (!samePhysicalPath(real, ownerPath) || !containedPath(root, real)) {
        throw lockError('unsafe_lock_owner', 'Lock owner metadata resolves through a reparse point after read.');
      }
    } catch (error) {
      if (error?.code === 'ENOENT') {
        throw lockError('lock_owner_invalid', 'Lock owner metadata is missing.', { reason: 'missing' });
      }
      throw mapContainmentFailure(error, 'unsafe_lock_owner');
    }
    const bytes = buffer.subarray(0, used);
    const raw = bytes.toString('utf8');
    if (!Buffer.from(raw, 'utf8').equals(bytes)) {
      throw lockError('lock_owner_invalid', 'Lock owner metadata is invalid (invalid_utf8).', { reason: 'invalid_utf8' });
    }
    return { raw, digest: hash(bytes), stat: after };
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readStrictOwner(root, lockDir, expected) {
  const directory = validatePhysicalDirectory(root, lockDir, 'unsafe_lock_path', { bigint: true });
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
  if (owner.schema_version === 'knowledge-lock-owner.v3') {
    const binding = owner.kernel_lease;
    // A byte-identical copy has no lease held by the original writer. Bind
    // authority to the original inode and directory recorded before their
    // publication, not only to the bytes found by this particular reader.
    if (!directory || binding.owner_dev !== String(read.stat.dev) || binding.owner_ino !== String(read.stat.ino) ||
        binding.directory_dev !== String(directory.dev) || binding.directory_ino !== String(directory.ino)) {
      throw lockError('lock_owner_identity_mismatch', 'Lock owner metadata does not bind its original physical owner and directory.');
    }
  }
  let executionScope = null;
  if (owner.schema_version === 'knowledge-lock-owner.v3' && owner.execution_scope !== null) {
    const scope = boundedPhysicalRead(root, path.join(lockDir, 'execution-scope.json'), LOCK_POLICY.execution_scope_max_bytes);
    try {
      executionScope = JSON.parse(scope.raw);
      if (scope.digest !== owner.execution_scope.sha256 || executionScope.backend !== owner.execution_scope.backend ||
          `${JSON.stringify(executionScope, null, 2)}\n` !== scope.raw ||
          !require('./command-scope-proof').validateExecutionScope(executionScope)) throw new Error('Scope binding mismatch');
    } catch {
      throw lockError('lock_execution_scope_invalid', 'The immutable execution scope is invalid or does not match its owner.');
    }
  }
  const finalDirectory = validatePhysicalDirectory(root, lockDir, 'unsafe_lock_path', { bigint: true });
  if (!directory || !finalDirectory || !sameDirectoryIdentity(directory, finalDirectory)) {
    throw lockError('lock_ownership_changed', 'Lock directory changed while reading immutable ownership.');
  }
  return { owner, digest: read.digest, stat: read.stat, executionScope };
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

function kernelText(file, maximum) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY);
  try {
    const buffer = Buffer.alloc(maximum + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = fs.readSync(descriptor, buffer, used, buffer.length - used, null);
      if (!count) break;
      used += count;
    }
    if (!used || used > maximum) throw new Error('Unbounded kernel identity');
    const bytes = buffer.subarray(0, used), text = bytes.toString('utf8');
    if (text.includes('\0') || !Buffer.from(text, 'utf8').equals(bytes)) throw new Error('Invalid kernel identity text');
    return text;
  } finally { fs.closeSync(descriptor); }
}

function nativePidNamespace(file) {
  if (fs.statfsSync(file, { bigint: true }).type !== 0x6e736673n) throw new Error('Expected nsfs');
  const stat = fs.statSync(file, { bigint: true });
  if (!stat.isFile() || stat.ino <= 0n || fs.readlinkSync(file) !== `pid:[${stat.ino}]`) throw new Error('Invalid PID namespace');
  return { dev: String(stat.dev), ino: String(stat.ino) };
}

function parseKernelProcessStat(text) {
  const opening = text.indexOf(' ('), end = text.lastIndexOf(')');
  if (opening <= 0 || end <= opening || text[end + 1] !== ' ') throw new Error('Invalid process stat');
  const pidText = text.slice(0, opening), fields = text.slice(end + 2).trim().split(/\s+/);
  if (!/^[1-9][0-9]{0,9}$/.test(pidText) || fields.length < 20 || !/^[A-Za-z]$/.test(fields[0]) ||
      !/^(?:0|[1-9][0-9]{0,9})$/.test(fields[1]) || !/^(?:0|[1-9][0-9]{0,19})$/.test(fields[19])) throw new Error('Invalid process stat fields');
  const pid = Number(pidText), ppid = Number(fields[1]);
  if (pid > 2147483647 || ppid > 2147483647) throw new Error('Invalid kernel PID');
  return { pid, ppid, start_ticks: fields[19] };
}

function kernelNSpid(text, pid) {
  const rows = text.split('\n').filter(line => line.startsWith('NSpid:'));
  if (rows.length !== 1 || !/^NSpid:\s+[1-9][0-9]*(?:[ \t]+[1-9][0-9]*)*[ \t]*$/.test(rows[0])) throw new Error('Missing native PID coordinates');
  const ids = rows[0].slice('NSpid:'.length).trim().split(/[ \t]+/).map(Number);
  if (ids.length > 32 || ids[0] !== pid || ids.some(id => !Number.isSafeInteger(id) || id <= 0 || id > 2147483647)) throw new Error('Invalid native PID coordinates');
  return ids;
}

function nativeProcRecord(procRoot, pid) {
  // An opened proc PID directory stays bound to that process incarnation;
  // reads cannot be redirected to a later reuse of its numerical PID.
  const fd = fs.openSync(`${procRoot}/${pid}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isDirectory()) throw new Error('Expected proc PID directory');
    const base = `/proc/self/fd/${fd}`;
    const first = parseKernelProcessStat(kernelText(`${base}/stat`, 16384));
    const ids = kernelNSpid(kernelText(`${base}/status`, 65536), pid);
    let namespace = null;
    try { namespace = nativePidNamespace(`${base}/ns/pid`); } catch { /* inaccessible ancestor is not a witness */ }
    const last = parseKernelProcessStat(kernelText(`${base}/stat`, 16384));
    const lastIds = kernelNSpid(kernelText(`${base}/status`, 65536), pid);
    const after = fs.fstatSync(fd, { bigint: true });
    if (first.pid !== pid || JSON.stringify(first) !== JSON.stringify(last) || JSON.stringify(ids) !== JSON.stringify(lastIds) ||
        before.dev !== after.dev || before.ino !== after.ino || !after.isDirectory()) throw new Error('Process identity changed during observation');
    if (namespace) {
      const lastNamespace = nativePidNamespace(`${base}/ns/pid`);
      if (namespace.dev !== lastNamespace.dev || namespace.ino !== lastNamespace.ino) throw new Error('Namespace changed during observation');
    }
    return { ...first, nspid: ids, namespace };
  } finally { fs.closeSync(fd); }
}

// One private descriptor per process intentionally survives every lock release.
// A live cooperating writer therefore keeps the procfs superblock incarnation
// referenced for every published linux_procfs_held_v1 owner. Never replace this
// anchor on remount, and never expose its descriptor through owner metadata.
// Exec-in-place/CLOEXEC after acquiring a lock is outside this writer protocol.
let nativeProcfsAnchor = null;

function procMountId(descriptor) {
  const rows = kernelText(`/proc/self/fdinfo/${descriptor}`, 4096).split('\n').filter(line => line.startsWith('mnt_id:'));
  if (rows.length !== 1 || !/^mnt_id:\s+[1-9][0-9]*[ \t]*$/.test(rows[0])) throw new Error('Unconfirmed procfs mount identity');
  return rows[0].slice('mnt_id:'.length).trim();
}

function heldProcfsRoot() {
  if (!nativeProcfsAnchor) {
    const before = fs.lstatSync('/proc', { bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink()) throw new Error('Expected physical procfs root');
    const descriptor = fs.openSync('/proc', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      const opened = fs.fstatSync(descriptor, { bigint: true });
      if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino ||
          fs.statfsSync(`/proc/self/fd/${descriptor}`, { bigint: true }).type !== 0x9fa0n) throw new Error('Unconfirmed procfs anchor');
      nativeProcfsAnchor = { descriptor, dev: opened.dev, ino: opened.ino, mountId: procMountId(descriptor) };
    } catch (error) { fs.closeSync(descriptor); throw error; }
  }
  const held = fs.fstatSync(nativeProcfsAnchor.descriptor, { bigint: true });
  if (!held.isDirectory() || held.dev !== nativeProcfsAnchor.dev || held.ino !== nativeProcfsAnchor.ino ||
      procMountId(nativeProcfsAnchor.descriptor) !== nativeProcfsAnchor.mountId) throw new Error('Native procfs anchor changed');
  return nativeProcfsAnchor;
}

function linuxOwnerIdentitySnapshot() {
  const anchor = heldProcfsRoot();
  const fixedRoot = fs.lstatSync('/proc', { bigint: true });
  if (!fixedRoot.isDirectory() || fixedRoot.isSymbolicLink()) throw new Error('Expected physical procfs root');
  const fd = fs.openSync('/proc', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try {
    const root = `/proc/self/fd/${fd}`, opened = fs.fstatSync(fd, { bigint: true });
    if (opened.dev !== fixedRoot.dev || opened.ino !== fixedRoot.ino || opened.dev !== anchor.dev || opened.ino !== anchor.ino ||
        procMountId(fd) !== anchor.mountId || fs.statfsSync(root, { bigint: true }).type !== 0x9fa0n) throw new Error('Unconfirmed procfs root');
    const pidText = fs.readlinkSync(`${root}/self`);
    if (!/^[1-9][0-9]{0,9}$/.test(pidText)) throw new Error('Invalid procfs self PID');
    const procPid = Number(pidText), self = nativeProcRecord(root, procPid);
    if (!self.namespace || self.nspid.at(-1) !== process.pid) throw new Error('Unconfirmed native self coordinates');
    // One NSpid component proves that self is in the proc-view namespace.
    // Restricted native authorities cannot inspect ancestor nsfs objects.
    // Their shared, lifetime-held procfs object binds the outer coordinate;
    // no parent scan, caller-supplied identity, or privilege increase is needed.
    const view = self.nspid.length === 1 ? self.namespace : null;
    const boot = kernelText(`${root}/sys/kernel/random/boot_id`, 64).trim();
    const identity = {
      method: 'linux_procfs_held_v1', boot_id: boot,
      pid_namespace_dev: self.namespace.dev, pid_namespace_ino: self.namespace.ino,
      procfs_dev: String(opened.dev), procfs_ino: String(opened.ino),
      procfs_pid_namespace_dev: view?.dev ?? null, procfs_pid_namespace_ino: view?.ino ?? null,
      proc_pid: procPid, nspid: self.nspid, start_ticks: self.start_ticks
    };
    const after = fs.lstatSync('/proc', { bigint: true });
    if (!after.isDirectory() || after.isSymbolicLink() || after.dev !== opened.dev || after.ino !== opened.ino ||
        fs.statfsSync(root, { bigint: true }).type !== 0x9fa0n || !validNativeOwnerIdentity(identity, process.pid)) throw new Error('Native identity is unconfirmed');
    return identity;
  } finally { fs.closeSync(fd); }
}

function procVisibility() {
  const anchor = heldProcfsRoot(), root = `/proc/self/fd/${anchor.descriptor}`;
  const rows = kernelText(`${root}/self/mountinfo`, 1024 * 1024).trim().split('\n')
    .filter(line => line.split(' ', 1)[0] === anchor.mountId);
  if (rows.length !== 1) throw new Error('Unconfirmed procfs visibility');
  const separator = rows[0].indexOf(' - '), left = rows[0].slice(0, separator).split(' '), right = rows[0].slice(separator + 3).split(' ');
  if (separator < 0 || left.length < 6 || left[0] !== anchor.mountId || left[3] !== '/' || left[4] !== '/proc' ||
      right.length !== 3 || right[0] !== 'proc') throw new Error('Unconfirmed procfs mount');
  const hiding = right[2].split(',').filter(option => option.startsWith('hidepid='));
  if (hiding.length > 1 || (hiding.length === 1 && !['hidepid=0', 'hidepid=off'].includes(hiding[0]))) throw new Error('Procfs may hide live processes');
  return rows[0];
}

function procTargetPresent(procPid) {
  const anchor = heldProcfsRoot(), target = `/proc/self/fd/${anchor.descriptor}/${procPid}`;
  let descriptor;
  try { descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  try {
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isDirectory() || stat.dev !== anchor.dev || fs.statfsSync(`/proc/self/fd/${descriptor}`, { bigint: true }).type !== 0x9fa0n) throw new Error('Unconfirmed target proc directory');
    // Any occupied native proc coordinate vetoes ESRCH, including a reused
    // PID or an exiting process. Absence alone never authorizes recovery.
    return true;
  } finally { fs.closeSync(descriptor); }
}

function captureNativeOwnerIdentity() {
  if (process.platform !== 'linux' || typeof fs.statfsSync !== 'function') return null;
  try {
    const first = linuxOwnerIdentitySnapshot(), last = linuxOwnerIdentitySnapshot();
    return JSON.stringify(first) === JSON.stringify(last) ? last : null;
  } catch { return null; }
}

function processAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) {
    // Only the kernel's explicit "no such process" observation is absence.
    // Permission denial preserves the live-owner contract; transport/resource
    // errors and unsupported probes remain unknown and never grant eviction.
    if (error?.code === 'ESRCH') return false;
    if (error?.code === 'EPERM') return true;
    return null;
  }
}

function ownerDisposition(owner, ageMs, policy, executionScope = null) {
  const unknown = reason => ({ local: null, alive: null, stale: false, reason, recovery_required: 'native_scope_evidence' });
  // Revalidate in the authority-pinned manager/policy even if the additive
  // canonical owner reader was replaced or a caller invokes the test hook.
  if (owner.schema_version === 'knowledge-lock-owner.v3') return unknown('kernel_owner_lease_evidence_required');
  if (owner.schema_version !== 'knowledge-lock-owner.v2') return unknown('legacy_owner_scope_unverified');
  if (!validNativeOwnerIdentity(owner.native_identity, owner.pid)) return unknown('owner_native_scope_unverified');
  const before = captureNativeOwnerIdentity();
  if (!before) return unknown('observer_native_scope_unverified');
  const recorded = owner.native_identity;
  if (before.boot_id !== recorded.boot_id) return unknown('owner_boot_scope_mismatch');
  if (before.procfs_dev !== recorded.procfs_dev || before.procfs_ino !== recorded.procfs_ino) return unknown('owner_proc_view_mismatch');
  let target;
  if (before.pid_namespace_dev === recorded.pid_namespace_dev && before.pid_namespace_ino === recorded.pid_namespace_ino) {
    target = owner.pid;
  } else if (before.nspid.length === 1 && recorded.nspid.length > 1) {
    target = recorded.proc_pid;
  } else return unknown('owner_pid_scope_mismatch');
  let visibility;
  try { visibility = procVisibility(); } catch { return unknown('observer_proc_visibility_unverified'); }
  const alive = processAlive(target);
  let present = null;
  if (alive === false) {
    try { present = procTargetPresent(recorded.proc_pid); } catch { return unknown('owner_proc_presence_unverified'); }
  }
  const after = captureNativeOwnerIdentity();
  if (!after || JSON.stringify(before) !== JSON.stringify(after)) return unknown('observer_native_scope_changed');
  try { if (procVisibility() !== visibility) return unknown('observer_proc_visibility_changed'); }
  catch { return unknown('observer_proc_visibility_unverified'); }
  if (alive === false && present !== false) return unknown('contradictory_process_observation');
  if (alive === null) return unknown('local_owner_liveness_unverifiable');
  // Occupied/reused PIDs stay blocked. Neither proc ENOENT nor a start-tick
  // mismatch grants recovery; only ESRCH in a proven coordinate can do so.
  return { local: true, alive, stale: alive === false && ageMs >= policy.staleMs,
    reason: alive ? 'occupied_scoped_owner_pid' : (ageMs >= policy.staleMs ? 'dead_scoped_owner' : 'dead_scoped_owner_not_old_enough'),
    recovery_required: null };
}

function queryExecutionClosure(scope, timeoutMs) {
  try { return require('./command-scope-proof').queryScopeClosure(scope, { timeoutMs }); }
  catch { return { status: 'unconfirmed', reason: 'scope_provider_failed' }; }
}

function requireExecutionClosure(read, timeoutMs) {
  if (read.owner.schema_version !== 'knowledge-lock-owner.v3' || read.owner.execution_scope === null) return;
  const result = read.executionScope ? queryExecutionClosure(read.executionScope, timeoutMs) : { status: 'unconfirmed' };
  if (result.status !== 'completed') throw lockError(
    result.status === 'active' ? 'lock_execution_scope_active' : 'lock_execution_scope_unconfirmed',
    'Lock release requires proof that every writer in its immutable execution scope has stopped.',
    { recovery_required: 'execution_scope_closure_evidence' }
  );
}

function kernelLeaseDisposition(policy, paths, read, directory, holdLease) {
  const unknown = reason => ({ disposition: { local: null, alive: null, stale: false, reason, recovery_required: 'kernel_owner_lease_evidence' } });
  if (read.owner.kernel_lease?.method !== 'owner-inode-lease.v1' || read.owner.publication !== 'atomic-directory-noreplace.v1' ||
      (read.owner.native_identity !== null && !validNativeOwnerIdentity(read.owner.native_identity, read.owner.pid))) return unknown('kernel_owner_protocol_invalid');
  let proof;
  try { proof = probeOwnerLease(policy.rootPath, path.basename(paths.lockDir)); }
  catch { return unknown('kernel_owner_lease_provider_unavailable'); }
  if (proof.status === 'busy') return { disposition: { local: true, alive: true, stale: false, reason: 'kernel_owner_lease_held', recovery_required: null } };
  if (proof.status !== 'acquired' || !Number.isSafeInteger(proof.lease_id) || proof.lease_id < 1) return unknown('kernel_owner_lease_unconfirmed');
  let retained = false;
  try {
    if (!Buffer.isBuffer(proof.owner_bytes) || hash(proof.owner_bytes) !== read.digest ||
        proof.owner_identity?.dev !== String(read.stat.dev) || proof.owner_identity?.ino !== String(read.stat.ino) ||
        proof.directory_identity?.dev !== String(directory.dev) || proof.directory_identity?.ino !== String(directory.ino)) {
      throw lockError('lock_ownership_changed', 'The native lease does not bind the exact observed immutable owner inode.');
    }
    if (read.owner.execution_scope !== null) {
      const closure = read.executionScope ? queryExecutionClosure(read.executionScope, policy.timeoutMs) : { status: 'unconfirmed' };
      if (closure.status !== 'completed') return { disposition: { local: true, alive: false, stale: false,
        reason: closure.status === 'active' ? 'owner_lease_free_execution_scope_active' : 'owner_lease_free_execution_scope_unconfirmed',
        recovery_required: 'execution_scope_closure_evidence' } };
    }
    // The writer took this lease before publication and may close it only
    // after removing its public generation. This kernel proof survives PID
    // namespaces, PID reuse and wall-clock changes; it is NOT inferred from
    // a lease timeout or an absent process. Legacy metadata never uses it.
    retained = holdLease === true;
    return { disposition: { local: true, alive: false, stale: true, reason: 'abandoned_kernel_owner_lease', recovery_required: null },
      ...(retained ? { native_lease: proof.lease_id } : {}) };
  } finally { if (!retained) closeOwnerLease(proof.lease_id); }
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

function inspectLayoutParents(rootPath, paths) {
  const findings = [];
  // lstat distinguishes an absent path from a dangling symlink. Stop at an
  // absent or unsafe ancestor rather than walking through it to its children.
  for (const [label, directory] of [['locks', paths.layoutRoot], ['version', paths.versionRoot]]) {
    try {
      if (!validatePhysicalDirectory(rootPath, directory, 'unsafe_lock_parent')) {
        return { findings, versionPresent: false };
      }
    } catch (error) {
      findings.push({ code: error.code || 'unsafe_lock_parent', reason: `${label}_parent_unsafe` });
      return { findings, versionPresent: false };
    }
  }
  // These names are permitted layout entries, but acquisition requires every
  // existing entry to be a physical contained directory. Inspection applies
  // the same requirement without creating or repairing any missing directory.
  for (const [label, directory] of [['stale', paths.staleRoot], ['release', paths.releaseRoot]]) {
    try { validatePhysicalDirectory(rootPath, directory, 'unsafe_lock_parent'); }
    catch (error) {
      findings.push({ code: error.code || 'unsafe_lock_parent', reason: `${label}_parent_unsafe` });
    }
  }
  return { findings, versionPresent: true };
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

function timeoutError(policy, owner, disposition) {
  const safe = owner || {};
  const pid = Number.isSafeInteger(safe.pid) && safe.pid > 0 ? safe.pid : 'unknown';
  const hostname = typeof safe.hostname === 'string' && safe.hostname ? safe.hostname : 'unknown';
  const since = typeof safe.acquired_at === 'string' && safe.acquired_at ? ` since ${safe.acquired_at}` : '';
  const details = disposition ? { owner_disposition: disposition.reason, recovery_required: disposition.recovery_required || null } : {};
  if (!owner && disposition?.reason === 'owner_initialization_unconfirmed') {
    return lockError('lock_timeout', `Lock "${policy.lockName}" owner metadata is missing; acquisition budget expired with ownership unconfirmed.`, details);
  }
  return lockError('lock_timeout', `Lock "${policy.lockName}" is held by pid ${pid} on host "${hostname}"${since}.`, details);
}

function recoveryTimeoutError(policy) {
  // Recovery may already have removed the old public owner. Do not describe
  // that historical observation as a currently held lock after the budget.
  return lockError('lock_timeout', `Lock "${policy.lockName}" acquisition budget expired during stale recovery.`, {
    owner_disposition: 'recovery_budget_exhausted', recovery_required: null,
  });
}

function retryTimeoutError(policy, prior) {
  if (prior?.afterRecovery) return recoveryTimeoutError(policy);
  const observed = prior?.observation;
  const error = timeoutError(policy, observed?.sanitized_owner, observed?.disposition);
  if (observed?.disposition?.reason === 'owner_initialization_unconfirmed') return error;
  const owner = observed?.sanitized_owner;
  const previous = owner ? ` Last observed owner: pid ${owner.pid || 'unknown'} on host "${owner.hostname || 'unknown'}".` : '';
  // The owner may have released during the final wait. Do not present the
  // last observation as current liveness merely to report an expired budget.
  error.message = `Lock "${policy.lockName}" acquisition budget expired before retry.${previous}`;
  return error;
}

function waitForLegacy(policy, startedAt) {
  let prior = null;
  while (true) {
    if (prior && elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw retryTimeoutError(policy, prior);
    const inspected = inspectLegacy(policy);
    if (!inspected.present) return prior;
    if (inspected.status === 'unsafe') {
      const finding = inspected.findings[0] || { code: 'unsafe_lock_path' };
      throw lockError(finding.code, 'Legacy lock storage is unsafe.', { reason: finding.reason || null });
    }
    prior = { observation: inspected, afterRecovery: false };
    if (inspected.status === 'stale') {
      if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw retryTimeoutError(policy, prior);
      recoverLegacy(policy, inspected);
      prior.afterRecovery = true;
      if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw recoveryTimeoutError(policy);
      continue;
    }
    if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw timeoutError(policy, inspected.sanitized_owner, inspected.disposition);
    sleepSync(policy.retryMs);
  }
}

function createOwner(policy, scopeBinding = null, inodeBinding = null) {
  const now = new Date().toISOString();
  return {
    schema_version: LOCK_POLICY.owner_schema_version,
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
    native_identity: captureNativeOwnerIdentity(),
    publication: 'atomic-directory-noreplace.v1',
    kernel_lease: inodeBinding,
    execution_scope: scopeBinding,
  };
}

function inspectCurrent(policy, paths, options = {}) {
  const provenNamespaceTransition = options.retryDirectoryTransitions === true
    ? observed => {
      const latest = validatePhysicalDirectory(policy.rootPath, paths.lockDir, 'unsafe_lock_path', { bigint: true });
      return !latest || !sameDirectoryIdentity(observed, latest);
    }
    : null;
  const currentDirectory = () => {
    try {
      // A releasing owner may rename its physical directory between lstat
      // and the containment walk. ENOENT is a normal namespace transition.
      return validatePhysicalDirectory(policy.rootPath, paths.lockDir, 'unsafe_lock_path', { bigint: true }, provenNamespaceTransition);
    } catch (error) {
      if (error?.os_code === 'ENOENT') return null;
      throw error;
    }
  };
  const directory = currentDirectory();
  if (!directory) return { status: 'missing' };
  const acquisitionTransition = () => {
    if (options.retryDirectoryTransitions !== true) return null;
    // Never reinterpret an owner-file failure on the same directory as
    // contention. Revalidate physical containment and prove disappearance or
    // replacement of the entire directory before discarding an observation.
    const refreshed = currentDirectory();
    if (!refreshed) return { status: 'missing' };
    if (!sameDirectoryIdentity(directory, refreshed)) return { status: 'replaced' };
    return null;
  };
  let read;
  try { read = readStrictOwner(policy.rootPath, paths.lockDir, { lockName: policy.lockName, purpose: policy.purpose }); }
  catch (error) {
    const transition = acquisitionTransition();
    if (transition) return transition;
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
      const ageMs = Math.max(0, Date.now() - Number(refreshed.mtimeMs));
      if (options.waitForOwnerInitialization === true) {
        // Publication may pause after mkdir while its writer remains alive.
        // Only acquisition waits for this safe, missing-owner state, using
        // its original request budget. Age never authorizes removal, and
        // read-only diagnostics retain their separate initialization grace.
        return { status: 'initializing', age_ms: ageMs, disposition: {
          local: null, alive: null, stale: false,
          reason: 'owner_initialization_unconfirmed', recovery_required: 'owner_metadata_evidence'
        } };
      }
      if (ageMs < LOCK_POLICY.owner_initialization_grace_ms) {
        return { status: 'initializing', age_ms: ageMs };
      }
    }
    throw error;
  }
  const transition = acquisitionTransition();
  if (transition) return transition;
  const ageMs = Math.max(0, Date.now() - Number(directory.mtimeMs));
  const native = read.owner.schema_version === 'knowledge-lock-owner.v3'
    ? kernelLeaseDisposition(policy, paths, read, directory, options.holdKernelLease)
    : { disposition: ownerDisposition(read.owner, ageMs, policy) };
  const disposition = native.disposition;
  let finalTransition;
  try { finalTransition = acquisitionTransition(); }
  catch (error) { if (native.native_lease) closeOwnerLease(native.native_lease); throw error; }
  if (finalTransition) {
    if (native.native_lease) closeOwnerLease(native.native_lease);
    return finalTransition;
  }
  return {
    status: disposition.stale ? 'stale' : 'active',
    owner: read.owner,
    owner_digest: read.digest,
    sanitized_owner: sanitizedOwner(read.owner),
    directory_identity: directory,
    disposition,
    executionScope: read.executionScope,
    native_lease: native.native_lease || null,
    age_ms: ageMs,
  };
}

function recoveryGenerationPath(policy, paths, ownerDigest) {
  // All contenders for the same observed owner must choose ONE destination.
  // A random destination lets a delayed reclaimer move a later live owner
  // after another contender has already recovered this generation.
  const coordinate = JSON.stringify([path.basename(paths.lockDir), ownerDigest]);
  return path.join(paths.staleRoot, `generation-${policy.lockName}-${hash(coordinate)}.lock`);
}

function readRecoveredGeneration(policy, quarantine, ownerDigest) {
  const directory = validatePhysicalDirectory(policy.rootPath, quarantine, 'unsafe_lock_path', { bigint: true });
  if (!directory) return null;
  let retained;
  try {
    retained = readStrictOwner(policy.rootPath, quarantine, { lockName: policy.lockName, purpose: policy.purpose });
  } catch (error) {
    if (error.code !== 'lock_owner_invalid') throw error;
    throw lockError('lock_recovery_history_invalid', 'Retained lock recovery evidence is incomplete or invalid.', {
      reason: error.reason || 'invalid_recovered_owner', recovery_required: 'recovery_history_evidence',
    });
  }
  if (retained.digest !== ownerDigest) {
    throw lockError('lock_recovery_history_invalid', 'Retained lock recovery evidence belongs to another owner.', {
      reason: 'recovered_owner_mismatch', recovery_required: 'recovery_history_evidence',
    });
  }
  const verified = validatePhysicalDirectory(policy.rootPath, quarantine, 'unsafe_lock_path', { bigint: true });
  if (!verified || !sameDirectoryIdentity(directory, verified)) {
    throw lockError('lock_ownership_changed', 'Retained lock recovery evidence changed while being read.');
  }
  return { directory, retained };
}

function observeRecoveredGeneration(policy, paths, inspected) {
  const current = inspectCurrent(policy, paths, {
    retryDirectoryTransitions: true, waitForOwnerInitialization: true,
  });
  if (current.owner_digest === inspected.owner_digest) {
    // A restored/copied old generation must not be recovered a second time.
    // In particular, do not busy-loop forever while a retained destination
    // intentionally blocks another rename of that generation.
    throw lockError('lock_ownership_changed', 'A previously recovered lock generation is present again.', {
      reason: 'recovered_generation_reappeared', recovery_required: 'recovery_history_evidence',
    });
  }
  return { recovered: false, reason: 'generation_already_recovered' };
}

function recoverCurrent(policy, paths, inspected, startedAt) {
  const latest = inspectCurrent(policy, paths, {
    retryDirectoryTransitions: true, waitForOwnerInitialization: true, holdKernelLease: true,
  });
  try {
  if (latest.status !== 'stale' || latest.owner_digest !== inspected.owner_digest) {
    return { recovered: false, reason: 'ownership_changed_before_recovery' };
  }
  const quarantine = recoveryGenerationPath(policy, paths, inspected.owner_digest);
  if (readRecoveredGeneration(policy, quarantine, inspected.owner_digest)) {
    return observeRecoveredGeneration(policy, paths, inspected);
  }
  // Scope closure and history inspection may perform slow I/O. The retained
  // native lease still protects the original inode, so revalidate that the
  // public name has not been replaced with a different owner or directory.
  requireCreatedDirectory(policy, paths.lockDir, latest.directory_identity);
  const immediatelyBeforeMove = readStrictOwner(policy.rootPath, paths.lockDir, { lockName: policy.lockName, purpose: policy.purpose });
  requireCreatedOwner(immediatelyBeforeMove, { owner: latest.owner, digest: latest.owner_digest });
  requireCreatedDirectory(policy, paths.lockDir, latest.directory_identity);
  if (startedAt && elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw retryTimeoutError(policy, { observation: latest });
  try { fs.renameSync(paths.lockDir, quarantine); }
  catch (error) {
    if (error.code === 'ENOENT') return { recovered: false, reason: 'lock_disappeared' };
    // POSIX cannot replace a nonempty directory; Windows also refuses an
    // existing directory target. Confirm the exact retained generation before
    // interpreting a destination collision as another contender's progress.
    if (['EEXIST', 'ENOTEMPTY', 'EPERM', 'EACCES'].includes(error.code) &&
        readRecoveredGeneration(policy, quarantine, inspected.owner_digest)) {
      return observeRecoveredGeneration(policy, paths, inspected);
    }
    throw mapContainmentFailure(error, 'unsafe_lock_path');
  }
  const moved = readRecoveredGeneration(policy, quarantine, inspected.owner_digest);
  if (!moved || !sameDirectoryIdentity(moved.directory, latest.directory_identity)) {
    throw lockError('lock_ownership_changed', 'Lock ownership changed during stale recovery.');
  }
  // Retain this NONEMPTY generation tombstone. A paused contender may resume
  // arbitrarily late, so ordinary cleanup/TTL must never delete or empty it.
  // This is a safety fence, not disposable temporary storage. Mixed old/new
  // recovery writers are not supported; upgrade only after draining writers.
  const event = {
    schema_version: 'knowledge-lock-recovery.v1',
    recovery_id: crypto.randomUUID(),
    lock_name: policy.lockName,
    reason: inspected.disposition.reason,
    owner: inspected.sanitized_owner,
  };
  if (typeof policy.onRecovery === 'function') policy.onRecovery(event);
  return { recovered: true, event };
  } finally { if (latest.native_lease) closeOwnerLease(latest.native_lease); }
}

function requireCreatedDirectory(policy, directory, expectedDirectory) {
  const current = validatePhysicalDirectory(policy.rootPath, directory, 'unsafe_lock_path', { bigint: true });
  if (!expectedDirectory || !current || !sameDirectoryIdentity(expectedDirectory, current)) {
    throw lockError('lock_ownership_changed', 'The directory created by this acquisition changed.');
  }
  return current;
}

function requireCreatedOwner(read, expected) {
  if (!expected.owner || read.digest !== expected.digest ||
      read.owner.lock_id !== expected.owner.lock_id || read.owner.nonce !== expected.owner.nonce) {
    throw lockError('lock_ownership_changed', 'The owner published by this acquisition changed.');
  }
}

function cleanupCreatedLock(policy, paths, expected) {
  // A read may confirm our authority, but must never supply new authority.
  requireCreatedDirectory(policy, paths.lockDir, expected.directory);
  const inspected = readStrictOwner(policy.rootPath, paths.lockDir, { lockName: policy.lockName, purpose: policy.purpose });
  requireCreatedOwner(inspected, expected);
  requireExecutionClosure(inspected, policy.timeoutMs);
  requireCreatedDirectory(policy, paths.lockDir, expected.directory);
  const quarantine = path.join(paths.releaseRoot, quarantineName('failed-acquire', policy));
  fs.renameSync(paths.lockDir, quarantine);
  requireCreatedDirectory(policy, quarantine, expected.directory);
  const moved = readStrictOwner(policy.rootPath, quarantine, { lockName: policy.lockName, purpose: policy.purpose });
  requireCreatedOwner(moved, expected);
  requireCreatedDirectory(policy, quarantine, expected.directory);
  strictRemoveDirectory(policy.rootPath, quarantine);
}

function cleanupEmptyCreatedLock(policy, paths, createdDirectory) {
  requireCreatedDirectory(policy, paths.lockDir, createdDirectory);
  const entries = fs.readdirSync(paths.lockDir);
  if (entries.length) {
    throw lockError('lock_ownership_changed', 'Uninitialized lock directory gained content before cleanup.');
  }
  requireCreatedDirectory(policy, paths.lockDir, createdDirectory);
  // Content may appear after the last read. Never recursively delete a
  // directory for which this acquisition has not published an owner.
  fs.rmdirSync(paths.lockDir);
}

function prepareExecutionScope(policy) {
  if (policy.executionScope === undefined || policy.executionScope === null) return { text: null, binding: null };
  try {
    const scope = JSON.parse(JSON.stringify(policy.executionScope));
    const text = `${JSON.stringify(scope, null, 2)}\n`;
    if (Buffer.byteLength(text) > LOCK_POLICY.execution_scope_max_bytes || !require('./command-scope-proof').validateExecutionScope(scope)) throw new Error('Invalid scope');
    return { text, binding: { schema_version: 'knowledge-command-scope-binding.v1', backend: scope.backend, sha256: hash(Buffer.from(text, 'utf8')) } };
  } catch {
    throw lockError('lock_execution_scope_invalid', 'A requested execution scope must be a complete supported native descriptor before acquisition.');
  }
}

function requirePreparedEntries(directory, owner) {
  const expected = owner.execution_scope ? ['execution-scope.json', 'owner.json'] : ['owner.json'];
  const current = fs.readdirSync(directory).sort();
  if (JSON.stringify(current) !== JSON.stringify(expected)) throw lockError('lock_ownership_changed', 'Immutable lock directory gained or lost an entry.');
}

function prepareLockDirectory(policy, paths, scope) {
  const directory = path.join(paths.releaseRoot, quarantineName('publish', policy));
  // Retain the original caller umask / inherited group-access contract.
  // "Private" denotes an unpublished namespace, not a new permission policy.
  fs.mkdirSync(directory);
  const identity = validatePhysicalDirectory(policy.rootPath, directory, 'unsafe_lock_path', { bigint: true });
  requireCreatedDirectory(policy, directory, identity);
  // Only this private, never-reused directory exists until all immutable
  // evidence is flushed. Crashing here cannot create a public ownerless lock.
  if (scope.text !== null) writeFileAtomicContained(path.join(directory, 'execution-scope.json'), scope.text, policy.rootPath);
  requireCreatedDirectory(policy, directory, identity);
  const ownerPath = path.join(directory, 'owner.json');
  const descriptor = fs.openSync(ownerPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
    (process.platform === 'win32' ? 0 : (fs.constants.O_NOFOLLOW || 0)));
  let owner, digest;
  try {
    const original = fs.fstatSync(descriptor, { bigint: true });
    if (!original.isFile() || original.nlink !== 1n || original.size !== 0n) {
      throw lockError('lock_owner_identity_mismatch', 'The newly created private owner is not a unique empty regular file.');
    }
    requireCreatedDirectory(policy, directory, identity);
    owner = createOwner(policy, scope.binding, {
      method: 'owner-inode-lease.v1',
      owner_dev: String(original.dev),
      owner_ino: String(original.ino),
      directory_dev: String(identity.dev),
      directory_ino: String(identity.ino),
    });
    const ownerText = canonicalOwnerText(owner);
    digest = hash(Buffer.from(ownerText, 'utf8'));
    // Writing through this exact O_EXCL descriptor preserves the identity
    // serialized into the owner. A temporary-file rename would change it.
    fs.writeFileSync(descriptor, ownerText);
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  requireCreatedDirectory(policy, directory, identity);
  const verified = readStrictOwner(policy.rootPath, directory, { lockName: policy.lockName, purpose: policy.purpose });
  requireCreatedOwner(verified, { owner, digest });
  requirePreparedEntries(directory, owner);
  return { directory, identity, owner, digest };
}

function cleanupPreparedDirectory(policy, prepared) {
  let current;
  try { current = fs.lstatSync(prepared.directory, { bigint: true }); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!current.isDirectory() || current.isSymbolicLink() || !sameDirectoryIdentity(current, prepared.identity)) throw lockError('lock_ownership_changed', 'Private publication stage changed before cleanup.');
  requireCreatedDirectory(policy, prepared.directory, prepared.identity);
  requireCreatedOwner(readStrictOwner(policy.rootPath, prepared.directory, { lockName: policy.lockName, purpose: policy.purpose }), prepared);
  requirePreparedEntries(prepared.directory, prepared.owner);
  requireCreatedDirectory(policy, prepared.directory, prepared.identity);
  strictRemoveDirectory(policy.rootPath, prepared.directory);
}

function acquireContainedLock(request) {
  const policy = requestPolicy(request);
  const startedAt = process.hrtime.bigint();
  const scope = prepareExecutionScope(policy);
  // Fail before creating a public name when this installation has no pinned
  // native no-replace primitive. Runtime does not invoke a compiler/helper.
  qualifyNativePublication();
  let prior = waitForLegacy(policy, startedAt);
  const paths = ensureLayout(policy);
  const prepared = prepareLockDirectory(policy, paths, scope);
  const owner = prepared.owner, ownerDigest = prepared.digest, acquiredDirectoryIdentity = prepared.identity;
  let published = false;
  let publishedLease = null;
  try {
    while (true) {
      // Preparation and every contender retry share the original admission
      // budget. Completing an already-started kernel operation is separately
      // reconciled below; no later retry receives a fresh timeout.
      if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw retryTimeoutError(policy, prior);
      requireCreatedDirectory(policy, prepared.directory, prepared.identity);
      requireCreatedOwner(readStrictOwner(policy.rootPath, prepared.directory, { lockName: policy.lockName, purpose: policy.purpose }), prepared);
      requirePreparedEntries(prepared.directory, owner);
      const remaining = policy.timeoutMs - elapsedBudgetMs(startedAt);
      if (remaining <= 0) throw retryTimeoutError(policy, prior);
      const result = publishPreparedLock(policy.rootPath, path.basename(prepared.directory), path.basename(paths.lockDir), remaining);
      if (Number.isSafeInteger(result.lease_id) && result.lease_id > 0) publishedLease = result.lease_id;
      if (result.status !== 'exists') {
        // A filesystem error can report failure after its namespace mutation.
        // Reconcile exact owned identity, never assume error means no move.
        const current = validatePhysicalDirectory(policy.rootPath, paths.lockDir, 'unsafe_lock_path', { bigint: true });
        published = result.published === true || !!(current && sameDirectoryIdentity(current, prepared.identity));
        if (result.status === 'budget_exhausted') throw retryTimeoutError(policy, prior);
        if (result.status !== 'published') throw lockError('lock_native_publication_failed', 'Exclusive lock publication did not confirm its complete transaction.', {
          native_error: result.native_error, publication_may_have_completed: published,
        });
        if (!publishedLease || !Buffer.isBuffer(result.owner_bytes) || hash(result.owner_bytes) !== ownerDigest ||
            result.directory_identity?.dev !== String(prepared.identity.dev) || result.directory_identity?.ino !== String(prepared.identity.ino)) {
          throw lockError('lock_ownership_changed', 'The published native lease does not bind this prepared owner.');
        }
        requireCreatedDirectory(policy, paths.lockDir, prepared.identity);
        const acknowledged = readStrictOwner(policy.rootPath, paths.lockDir, { lockName: policy.lockName, purpose: policy.purpose });
        requireCreatedOwner(acknowledged, prepared);
        if (result.owner_identity?.dev !== String(acknowledged.stat.dev) || result.owner_identity?.ino !== String(acknowledged.stat.ino)) {
          throw lockError('lock_owner_identity_mismatch', 'The acquisition acknowledgment does not bind its original leased owner inode.');
        }
        requirePreparedEntries(paths.lockDir, owner);
        break;
      }
      const inspected = inspectCurrent(policy, paths, { retryDirectoryTransitions: true, waitForOwnerInitialization: true });
      prior = { observation: inspected, afterRecovery: false };
      if (inspected.status === 'missing' || inspected.status === 'replaced') {
        if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw timeoutError(policy, null);
        continue;
      }
      if (inspected.status === 'stale') {
        if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw retryTimeoutError(policy, prior);
        recoverCurrent(policy, paths, inspected, startedAt);
        prior.afterRecovery = true;
        if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) throw recoveryTimeoutError(policy);
        continue;
      }
      if (elapsedBudgetMs(startedAt) >= policy.timeoutMs) {
        throw timeoutError(policy, inspected.sanitized_owner, inspected.disposition);
      }
      sleepSync(policy.retryMs);
    }
  } catch (error) {
    try {
      if (published) cleanupCreatedLock(policy, paths, { directory: prepared.identity, owner, digest: ownerDigest });
      else cleanupPreparedDirectory(policy, prepared);
      if (publishedLease) closeOwnerLease(publishedLease);
    } catch (cleanupError) { error.lock_cleanup_error = cleanupError.code || 'lock_cleanup_failed'; }
    throw error;
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
      const releasePath = path.join(paths.releaseRoot, quarantineName('release', policy));
      const releaseStarted = process.hrtime.bigint();
      const directoryIdentity = acquiredDirectoryIdentity;
      let sharingRetryError = null;
      for (;;) {
        if (sharingRetryError && elapsedBudgetMs(releaseStarted) >= policy.timeoutMs) {
          throw mapContainmentFailure(sharingRetryError, 'unsafe_lock_path');
        }
        requireCreatedDirectory(policy, paths.lockDir, directoryIdentity);
        const current = inspectCurrent(policy, paths);
        if (!['active', 'stale'].includes(current.status) ||
            current.owner_digest !== ownerDigest ||
            current.owner.lock_id !== owner.lock_id ||
            current.owner.nonce !== owner.nonce ||
            (directoryIdentity && !sameDirectoryIdentity(directoryIdentity, current.directory_identity))) {
          throw lockError('lock_ownership_changed', `Lock "${policy.lockName}" ownership changed before release.`);
        }
        requireExecutionClosure(current, Math.max(1, policy.timeoutMs - elapsedBudgetMs(releaseStarted)));
        requirePreparedEntries(paths.lockDir, owner);
        requireCreatedDirectory(policy, paths.lockDir, directoryIdentity);
        try { fs.renameSync(paths.lockDir, releasePath); break; }
        catch (error) {
          if (error.code === 'ENOENT') throw lockError('lock_ownership_changed', `Lock "${policy.lockName}" disappeared before release.`);
          // Windows forbids directory rename while another contender has its
          // owner open. Retry only that sharing failure, within the policy
          // deadline, rechecking physical identity and exact ownership first.
          if (process.platform === 'win32' && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code) &&
              elapsedBudgetMs(releaseStarted) < policy.timeoutMs) {
            sharingRetryError = error;
            sleepSync(Math.min(policy.retryMs, Math.max(1, policy.timeoutMs - elapsedBudgetMs(releaseStarted))));
            continue;
          }
          throw mapContainmentFailure(error, 'unsafe_lock_path');
        }
      }
      const movedDirectory = validatePhysicalDirectory(policy.rootPath, releasePath, 'unsafe_lock_path', { bigint: true });
      if (!movedDirectory || !sameDirectoryIdentity(directoryIdentity, movedDirectory)) {
        throw lockError('lock_ownership_changed', `Lock "${policy.lockName}" physical directory changed during release.`);
      }
      const moved = readStrictOwner(policy.rootPath, releasePath, { lockName: policy.lockName, purpose: policy.purpose });
      if (moved.digest !== ownerDigest || moved.owner.lock_id !== owner.lock_id || moved.owner.nonce !== owner.nonce) {
        throw lockError('lock_ownership_changed', `Lock "${policy.lockName}" ownership changed during release.`);
      }
      requireCreatedDirectory(policy, releasePath, directoryIdentity);
      strictRemoveDirectory(policy.rootPath, releasePath);
      if (!closeOwnerLease(publishedLease)) throw lockError('lock_native_lease_missing', 'Released owner lost its lifetime native lease unexpectedly.');
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
      recovery_required: current.disposition.recovery_required || null,
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

  const layout = inspectLayoutParents(policy.rootPath, paths);
  findings.push(...layout.findings);
  let current = { status: 'safe', findings: [] };
  if (!findings.length && layout.versionPresent) current = inspectLockDirectory(policy, paths);
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
    legacy: { present: legacy.present, status: legacy.status, owner: legacy.sanitized_owner || null,
      reason: legacy.disposition?.reason || null, recovery_required: legacy.disposition?.recovery_required || null },
    current: { status: current.status, owner: current.owner || null,
      reason: current.reason || null, recovery_required: current.recovery_required || null },
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

  const layout = inspectLayoutParents(rootPath, paths);
  let layoutSafe = layout.findings.length === 0;
  for (const finding of layout.findings) addFinding({ ...finding, layout: 'v1' });

  if (layoutSafe && layout.versionPresent) {
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
          current: { status: inspected.status, owner: inspected.owner || null,
            reason: inspected.reason || null, recovery_required: inspected.recovery_required || null },
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
      reason: legacy.disposition?.reason || null,
      recovery_required: legacy.disposition?.recovery_required || null,
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
    captureNativeOwnerIdentity,
    parseKernelProcessStat,
    kernelNSpid,
  },
};
