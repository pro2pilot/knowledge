#!/usr/bin/env node
'use strict';

// Portable, isolated authority regressions for the contained lock manager.
// Current-v3 authority checks use --source. Three obsolete publication fault points
// explicitly exercise the retained v2 compatibility fixture; each result names its protocol.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function usage() {
  return 'Usage: node manager-authority-regressions.cjs --source=<physical .knowledge directory>';
}

function readSourceArg(argv) {
  const item = argv.find((value) => value.startsWith('--source='));
  if (!item || !item.slice('--source='.length)) throw new Error(usage());
  return item.slice('--source='.length);
}

const sourceInput = readSourceArg(process.argv.slice(2));
const source = fs.realpathSync(path.resolve(sourceInput));
if (path.basename(source).toLowerCase() !== '.knowledge' || !fs.statSync(source).isDirectory()) {
  throw new Error(`--source must resolve to a physical .knowledge directory: ${source}`);
}
let manager, currentManager, legacyManager;
const legacyPublicationCases = new Set(['owner-publication-eexist', 'primary-and-secondary-cleanup-errors', 'empty-cleanup-race-after-readdir']);
let LOCKS;
let canonicalOwnerText;

const native = Object.fromEntries(
  ['openSync', 'writeFileSync', 'appendFileSync', 'mkdirSync', 'mkdtempSync', 'renameSync', 'rmSync',
    'rmdirSync', 'unlinkSync', 'linkSync', 'symlinkSync', 'copyFileSync', 'chmodSync', 'chownSync',
    'utimesSync', 'truncateSync', 'fsyncSync', 'fchmodSync', 'fchownSync', 'createWriteStream']
    .filter((name) => typeof fs[name] === 'function').map((name) => [name, fs[name]])
);
const blocked = [];
const permitted = [];
const checks = [];
let fixtureBoundary = null;
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
const identity = (file) => {
  const stat = fs.lstatSync(file, { bigint: true });
  return `${stat.dev}:${stat.ino}`;
};
const controlledError = (code) => Object.assign(new Error(`controlled ${code}`), { code });
const pathArg = (value) => {
  if (typeof value === 'string' || Buffer.isBuffer(value)) return path.resolve(value.toString());
  if (value instanceof URL) return path.resolve(require('node:url').fileURLToPath(value));
  return null;
};

function isInsideFixture(value) {
  const candidate = pathArg(value);
  if (!candidate || !fixtureBoundary) return false;
  const relative = path.relative(fixtureBoundary, candidate);
  if (!(relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)))) return false;
  const rootStat = fs.lstatSync(fixtureBoundary, { bigint: true });
  if (rootStat.isSymbolicLink() || String(rootStat.dev) !== fixtureRootIdentity.dev || String(rootStat.ino) !== fixtureRootIdentity.ino) return false;
  let existing = candidate;
  while (true) {
    try {
      fs.lstatSync(existing);
      break;
    } catch (error) {
      if (error.code !== 'ENOENT') return false;
      const parent = path.dirname(existing);
      if (parent === existing) return false;
      existing = parent;
    }
  }
  while (true) {
    const stat = fs.lstatSync(existing, { bigint: true });
    if (stat.isSymbolicLink()) return false;
    const real = fs.realpathSync(existing);
    const samePath = process.platform === 'win32'
      ? path.resolve(real).toLowerCase() === path.resolve(existing).toLowerCase()
      : path.resolve(real) === path.resolve(existing);
    if (!samePath) return false;
    const realRelative = path.relative(fixtureBoundary, real);
    if (!(realRelative === '' || (realRelative !== '..' && !realRelative.startsWith(`..${path.sep}`) && !path.isAbsolute(realRelative)))) return false;
    if (existing === fixtureBoundary) break;
    const parent = path.dirname(existing);
    if (parent === existing) return false;
    existing = parent;
  }
  return true;
}

function assertFixturePath(value, operation) {
  if (!isInsideFixture(value)) {
    const error = controlledError('TEST_GUARD_REFUSED_OUTSIDE_FIXTURE_MUTATION');
    blocked.push({ method: operation, path: pathArg(value), code: error.code });
    throw error;
  }
}

function installMutationFence() {
  const restorers = [];
  const trackedDescriptors = new Set();
  const wrapPath = (name, indexes) => {
    const original = fs[name];
    if (typeof original !== 'function') return;
    fs[name] = function fixtureOnlyMutation(...args) {
      for (const index of indexes) assertFixturePath(args[index], name);
      return original.apply(this, args);
    };
    restorers.push(() => { fs[name] = original; });
  };
  const originalOpen = fs.openSync;
  fs.openSync = function fixtureOnlyOpen(file, flags, ...rest) {
    const writes = typeof flags === 'string'
      ? /[wax+]/.test(flags)
      : typeof flags === 'number' && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND)) !== 0;
    if (writes) assertFixturePath(file, 'openSync');
    const descriptor = originalOpen.call(this, file, flags, ...rest);
    if (writes) trackedDescriptors.add(descriptor);
    return descriptor;
  };
  restorers.push(() => { fs.openSync = originalOpen; });
  for (const name of ['writeFileSync', 'appendFileSync']) {
    const original = fs[name];
    fs[name] = function fixtureOnlyWrite(target, ...rest) {
      if (typeof target === 'number') {
        if (!trackedDescriptors.has(target)) assertFixturePath(null, name);
      } else assertFixturePath(target, name);
      return original.call(this, target, ...rest);
    };
    restorers.push(() => { fs[name] = original; });
  }
  for (const [name, indexes] of Object.entries({
    mkdirSync: [0], mkdtempSync: [0], renameSync: [0, 1], rmSync: [0], rmdirSync: [0],
    unlinkSync: [0], copyFileSync: [0, 1],
    chmodSync: [0], chownSync: [0], utimesSync: [0], truncateSync: [0], createWriteStream: [0],
  })) wrapPath(name, indexes);
  for (const name of ['linkSync', 'symlinkSync']) {
    const original = fs[name];
    fs[name] = function rejectLinkCreation(...args) {
      const error = controlledError('TEST_GUARD_REFUSED_LINK_CREATION');
      blocked.push({ method: name, path: pathArg(args[1]), code: error.code });
      throw error;
    };
    restorers.push(() => { fs[name] = original; });
  }
  for (const name of ['fsyncSync', 'fchmodSync', 'fchownSync']) {
    const original = fs[name];
    if (typeof original !== 'function') continue;
    fs[name] = function fixtureOnlyDescriptorMutation(descriptor, ...rest) {
      if (!trackedDescriptors.has(descriptor)) assertFixturePath(null, name);
      return original.call(this, descriptor, ...rest);
    };
    restorers.push(() => { fs[name] = original; });
  }
  const writeFlags = (flags) => typeof flags === 'string'
    ? /[wax+]/.test(flags)
    : typeof flags === 'number' && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND)) !== 0;
  for (const name of ['open']) {
    const original = fs[name];
    if (typeof original !== 'function') continue;
    fs[name] = function fixtureOnlyAsyncOpen(file, flags, ...rest) {
      if (writeFlags(flags)) assertFixturePath(file, name);
      return original.call(this, file, flags, ...rest);
    };
    restorers.push(() => { fs[name] = original; });
  }
  for (const name of ['writeFile', 'appendFile']) {
    const original = fs[name];
    if (typeof original !== 'function') continue;
    fs[name] = function fixtureOnlyAsyncWrite(target, ...rest) {
      assertFixturePath(target, name);
      return original.call(this, target, ...rest);
    };
    restorers.push(() => { fs[name] = original; });
  }
  const promiseApi = fs.promises;
  for (const [name, indexes] of Object.entries({
    open: [0], writeFile: [0], appendFile: [0], mkdir: [0], mkdtemp: [0], rename: [0, 1],
    rm: [0], rmdir: [0], unlink: [0], copyFile: [0, 1],
    chmod: [0], chown: [0], utimes: [0], truncate: [0],
  })) {
    const original = promiseApi[name];
    if (typeof original !== 'function') continue;
    promiseApi[name] = function fixtureOnlyPromiseMutation(...args) {
      if (name !== 'open' || writeFlags(args[1])) {
        for (const index of indexes) assertFixturePath(args[index], `promises.${name}`);
      }
      return original.apply(this, args);
    };
    restorers.push(() => { promiseApi[name] = original; });
  }
  return () => { for (const restore of restorers.reverse()) restore(); };
}

// Install this guard before any scenario-specific interception. It blocks
// destructive calls only when their named source or target is one of the
// exact fixture paths registered by the scenario. The native operation is
// never reached for a blocked call.
function installDestructiveGuard(exactFixturePaths, allowedNonrecursiveRmdir = []) {
  const exact = new Set([...exactFixturePaths].map((item) => path.resolve(item)));
  const allowedRmdir = new Set(allowedNonrecursiveRmdir.map((item) => path.resolve(item)));
  const restorers = [];
  const intercept = (name, indexes) => {
    const original = fs[name];
    fs[name] = function guardedDestructiveCall(...args) {
      const named = indexes.map((index) => pathArg(args[index])).filter(Boolean);
      const matched = named.find((candidate) => exact.has(candidate));
      if (matched) {
        if (name === 'rmdirSync' && allowedRmdir.has(matched)) {
          permitted.push({ method: name, path: matched });
          return original.apply(this, args);
        }
        const error = controlledError('TEST_GUARD_REFUSED_DESTRUCTIVE_CALL');
        blocked.push({ method: name, path: matched, code: error.code });
        throw error;
      }
      return original.apply(this, args);
    };
    restorers.push(() => { fs[name] = original; });
  };
  intercept('renameSync', [0, 1]);
  intercept('rmSync', [0]);
  intercept('rmdirSync', [0]);
  intercept('unlinkSync', [0]);
  return () => { for (const restore of restorers.reverse()) restore(); };
}

function fixture(name, run) {
  const root = path.join(tempRoot, name);
  fs.mkdirSync(root);
  const stateRoot = path.join(root, 'state');
  const request = {
    rootKind: 'state', rootPath: stateRoot, lockName: 'sync',
    purpose: LOCKS.sync.purpose, context: { stateRoot }, timeoutMs: 1000,
  };
  const historical = legacyPublicationCases.has(name);
  manager = historical ? legacyManager : currentManager;
  const protocol_under_test = historical ? 'retained_v2_writer_compatibility' : 'current_v3_atomic_publication';
  try {
    const evidence = run({ root, stateRoot, request }) || {};
    checks.push({ name, status: 'pass', protocol_under_test, evidence });
  } catch (error) {
    checks.push({ name, status: 'fail', protocol_under_test, error: error.stack || error.message });
  } finally { manager = currentManager; }
}

const tempParent = fs.realpathSync(os.tmpdir());
const tempParentStat = fs.lstatSync(tempParent, { bigint: true });
if (tempParentStat.isSymbolicLink() || fs.realpathSync(tempParent) !== tempParent) {
  throw new Error('The OS temporary directory is not a stable physical directory.');
}
const tempParentIdentity = { dev: String(tempParentStat.dev), ino: String(tempParentStat.ino) };
const tempRoot = fs.mkdtempSync(path.join(tempParent, 'knowledge-lock-authority-'));
const physicalTempRoot = fs.realpathSync(tempRoot);
const fixtureRootStat = fs.lstatSync(physicalTempRoot, { bigint: true });
const fixtureRootIdentity = { dev: String(fixtureRootStat.dev), ino: String(fixtureRootStat.ino) };
const relativeTemp = path.relative(tempParent, physicalTempRoot);
if (!relativeTemp || relativeTemp === '..' || relativeTemp.startsWith(`..${path.sep}`) || path.isAbsolute(relativeTemp)) {
  throw new Error('The fixture root is not physically contained by the OS-created temporary directory.');
}
fixtureBoundary = physicalTempRoot;
const restoreMutationFence = installMutationFence();

try {
  currentManager = manager = require(path.join(source, 'tools/lib/contained-lock-manager.js'));
  // These three fault points existed only in the retained v2 writer's public
  // mkdir→owner-rename protocol. Keep their exact assertions on that pinned
  // compatibility fixture. V3's staged native transaction has its own physical
  // publication/crash/inode suites; it never enters the old empty-owner branch.
  legacyManager = require(path.join(source, 'tests/fixtures/lock-v2-runtime/tools/lib/contained-lock-manager.js'));
  ({ LOCKS } = require(path.join(source, 'tools/lib/lock-policy.js')));
  ({ canonicalOwnerText } = require(path.join(source, 'tools/lib/lock-owner-schema.js')));
  assert.equal(typeof manager.acquireContainedLock, 'function');
  assert.equal(typeof manager.withContainedLock, 'function');

  fixture('replacement-directory', ({ root, request }) => {
    const handle = manager.acquireContainedLock(request);
    const lockDir = path.resolve(handle.path);
    const ownerPath = path.join(lockDir, 'owner.json');
    const originalOwner = fs.readFileSync(ownerPath);
    const retired = path.join(root, 'retired-original-lock');
    const sentinel = path.join(lockDir, 'successor-sentinel.txt');

    // These are intentional fixture setup operations, completed before the
    // guard is installed. The subsequent release attempt is fully guarded.
    fs.renameSync(lockDir, retired);
    fs.mkdirSync(lockDir);
    fs.writeFileSync(ownerPath, originalOwner, { flag: 'wx' });
    fs.writeFileSync(sentinel, 'replacement data must survive\n', { flag: 'wx' });
    const retiredOwnerIdentity = identity(path.join(retired, 'owner.json'));
    const before = {
      directory: identity(lockDir), owner: identity(ownerPath),
      owner_sha256: sha(fs.readFileSync(ownerPath)), sentinel: identity(sentinel),
      sentinel_sha256: sha(fs.readFileSync(sentinel)),
    };

    const restoreGuard = installDestructiveGuard([lockDir, ownerPath, sentinel, retired]);
    let caught;
    try { handle.release(); } catch (error) { caught = error; }
    finally { restoreGuard(); }

    assert.equal(caught?.code, 'lock_ownership_changed');
    assert.deepEqual(blocked, []);
    assert.deepEqual({
      directory: identity(lockDir), owner: identity(ownerPath),
      owner_sha256: sha(fs.readFileSync(ownerPath)), sentinel: identity(sentinel),
      sentinel_sha256: sha(fs.readFileSync(sentinel)),
    }, before);
    assert.equal(identity(path.join(retired, 'owner.json')), retiredOwnerIdentity);
    return { result: caught.code, replacement_preserved: true, destructive_attempts: blocked.length };
  });

  fixture('owner-publication-eexist', ({ root, request }) => {
    const stateRoot = request.rootPath;
    const lockDir = path.join(stateRoot, 'locks', 'v1', 'sync.lock');
    const ownerPath = path.join(lockDir, 'owner.json');
    const primary = controlledError('EEXIST');
    let publicationAttempts = 0;
    const blockedBefore = blocked.length;
    const restoreGuard = installDestructiveGuard([lockDir, ownerPath]);
    const guardedRename = fs.renameSync;
    fs.renameSync = function forceOwnerPublicationConflict(from, to, ...rest) {
      if (typeof to === 'string' && path.resolve(to) === path.resolve(ownerPath)) {
        publicationAttempts += 1;
        throw primary;
      }
      return guardedRename.call(this, from, to, ...rest);
    };
    let caught;
    try { manager.acquireContainedLock(request); } catch (error) { caught = error; }
    finally { fs.renameSync = guardedRename; restoreGuard(); }

    assert.strictEqual(caught, primary, 'the publication EEXIST remains the primary error');
    assert.equal(publicationAttempts, 1);
    assert.equal(caught.lock_cleanup_error, 'TEST_GUARD_REFUSED_DESTRUCTIVE_CALL');
    const caseBlocked = blocked.slice(blockedBefore);
    assert.equal(caseBlocked.length, 1);
    assert.equal(caseBlocked[0].method, 'rmdirSync');
    assert.equal(caseBlocked[0].path, path.resolve(lockDir));
    assert.equal(fs.existsSync(lockDir), true);
    assert.deepEqual(fs.readdirSync(lockDir), []);
    return { primary_error: caught.code, secondary_cleanup_error: caught.lock_cleanup_error,
      publication_attempts: publicationAttempts, refused_cleanup_calls: caseBlocked.length,
      fixture_directory_retained: true,
      fixture_directory: path.relative(tempRoot, root) };
  });

  fixture('primary-and-secondary-cleanup-errors', ({ request }) => {
    const lockDir = path.join(request.rootPath, 'locks', 'v1', 'sync.lock');
    const primary = controlledError('EIO');
    let publicationAttempts = 0;
    const blockedBefore = blocked.length;
    const restoreGuard = installDestructiveGuard([lockDir]);
    const originalOpen = fs.openSync;
    fs.openSync = function forceOwnerPublicationIoFailure(...args) {
      const candidate = typeof args[0] === 'string' ? path.resolve(args[0]) : '';
      if (candidate.startsWith(`${lockDir}${path.sep}.owner.json.tmp-`)) {
        publicationAttempts += 1;
        throw primary;
      }
      return originalOpen.apply(this, args);
    };
    let caught;
    try { manager.acquireContainedLock(request); } catch (error) { caught = error; }
    finally { fs.openSync = originalOpen; restoreGuard(); }

    assert.strictEqual(caught, primary);
    assert.equal(publicationAttempts, 1);
    assert.equal(caught.lock_cleanup_error, 'TEST_GUARD_REFUSED_DESTRUCTIVE_CALL');
    const caseBlocked = blocked.slice(blockedBefore);
    assert.equal(caseBlocked.length, 1);
    assert.equal(caseBlocked[0].method, 'rmdirSync');
    assert.equal(fs.existsSync(lockDir), true);
    return { primary_error: caught.code, secondary_cleanup_error: caught.lock_cleanup_error,
      fixture_directory_retained: true };
  });

  fixture('callback-error-remains-primary', ({ request }) => {
    const lockDir = path.join(request.rootPath, 'locks', 'v1', 'sync.lock');
    const callbackError = controlledError('CONTROLLED_CALLBACK_FAILURE');
    const releaseIoError = controlledError('EIO');
    const blockedBefore = blocked.length;
    const restoreGuard = installDestructiveGuard([lockDir]);
    const guardedRename = fs.renameSync;
    fs.renameSync = function forceReleaseRenameFailure(...args) {
      if (typeof args[0] === 'string' && path.resolve(args[0]) === path.resolve(lockDir)) throw releaseIoError;
      return guardedRename.apply(this, args);
    };
    let caught;
    try { manager.withContainedLock(request, () => { throw callbackError; }); }
    catch (error) { caught = error; }
    finally { fs.renameSync = guardedRename; restoreGuard(); }

    assert.strictEqual(caught, callbackError);
    assert.equal(caught.lock_release_error, 'unsafe_lock_path');
    assert.equal(blocked.length - blockedBefore, 0);
    assert.equal(fs.existsSync(lockDir), true);
    return { primary_error: caught.code, secondary_release_error: caught.lock_release_error,
      destructive_attempts: blocked.length };
  });

  fixture('owner-digest-replacement-during-acquisition', ({ request }) => {
    const lockDir = path.join(request.rootPath, 'locks', 'v1', 'sync.lock');
    const ownerPath = path.join(lockDir, 'owner.json');
    const backupPath = path.join(lockDir, 'retired-owner.json');
    const stagedPath = path.join(lockDir, 'replacement-owner.tmp');
    const blockedBefore = blocked.length;
    let restoreGuard = null;
    const originalLstat = fs.lstatSync;
    let injected = false;
    let replacementBytes;
    fs.lstatSync = function replacePublishedOwnerBeforeSnapshot(file, ...rest) {
      if (!injected && typeof file === 'string' && path.resolve(file) === path.resolve(ownerPath) && fs.existsSync(ownerPath)) {
        // The manager has completed its legitimate initial atomic publication.
        // Arm the destructive guard before test-controlled owner replacement
        // and leave it armed for the manager's subsequent acquisition cleanup.
        restoreGuard = installDestructiveGuard([lockDir, ownerPath, backupPath, stagedPath]);
        injected = true;
        const originalBytes = fs.readFileSync(ownerPath);
        const replacement = JSON.parse(originalBytes.toString('utf8'));
        replacement.nonce = `${replacement.nonce[0] === '0' ? '1' : '0'}${replacement.nonce.slice(1)}`;
        replacementBytes = Buffer.from(canonicalOwnerText(replacement), 'utf8');
        for (const target of [ownerPath, backupPath, stagedPath]) assertFixturePath(target, 'controlled-owner-replacement');
        fs.writeFileSync(stagedPath, replacementBytes, { flag: 'wx' });
        native.renameSync(ownerPath, backupPath);
        native.renameSync(stagedPath, ownerPath);
      }
      return originalLstat.call(this, file, ...rest);
    };
    let caught;
    try { manager.acquireContainedLock(request); } catch (error) { caught = error; }
    finally { fs.lstatSync = originalLstat; if (restoreGuard) restoreGuard(); }

    assert.equal(injected, true);
    assert.equal(caught?.code, 'lock_owner_identity_mismatch');
    assert.equal(caught.lock_cleanup_error, 'lock_owner_identity_mismatch');
    assert.equal(blocked.length - blockedBefore, 0);
    assert.deepEqual(fs.readFileSync(ownerPath), replacementBytes);
    assert(fs.existsSync(backupPath), 'the original owner was retained in the fixture');
    return { result: caught.code, cleanup_error: caught.lock_cleanup_error,
      replacement_digest: sha(replacementBytes), replacement_preserved: true };
  });

  fixture('empty-cleanup-race-after-readdir', ({ request }) => {
    const lockDir = path.join(request.rootPath, 'locks', 'v1', 'sync.lock');
    const sentinel = path.join(lockDir, 'raced-in-content.txt');
    const primary = controlledError('EIO');
    let publicationAttempts = 0;
    let raced = false;
    let originalDirectoryIdentity;
    const blockedBefore = blocked.length;
    const permittedBefore = permitted.length;
    const restoreGuard = installDestructiveGuard([lockDir, sentinel], [lockDir]);
    const originalOpen = fs.openSync;
    const originalReaddir = fs.readdirSync;
    fs.openSync = function failOwnerPublication(...args) {
      const candidate = typeof args[0] === 'string' ? path.resolve(args[0]) : '';
      if (candidate.startsWith(`${lockDir}${path.sep}.owner.json.tmp-`)) {
        publicationAttempts += 1;
        throw primary;
      }
      return originalOpen.apply(this, args);
    };
    fs.readdirSync = function raceAfterEmptyRead(...args) {
      const entries = originalReaddir.apply(this, args);
      if (!raced && typeof args[0] === 'string' && path.resolve(args[0]) === path.resolve(lockDir) && entries.length === 0) {
        raced = true;
        originalDirectoryIdentity = identity(lockDir);
        assertFixturePath(sentinel, 'controlled-cleanup-race');
        fs.writeFileSync(sentinel, 'content arrived after the empty read\n', { flag: 'wx' });
      }
      return entries;
    };
    let caught;
    try { manager.acquireContainedLock(request); } catch (error) { caught = error; }
    finally {
      fs.openSync = originalOpen;
      fs.readdirSync = originalReaddir;
      restoreGuard();
    }

    const casePermitted = permitted.slice(permittedBefore);
    assert.strictEqual(caught, primary);
    assert.equal(publicationAttempts, 1);
    assert.equal(raced, true);
    assert(['ENOTEMPTY', 'EEXIST'].includes(caught.lock_cleanup_error));
    assert.deepEqual(casePermitted, [{ method: 'rmdirSync', path: path.resolve(lockDir) }]);
    assert.equal(blocked.length - blockedBefore, 0);
    assert.equal(identity(lockDir), originalDirectoryIdentity);
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'content arrived after the empty read\n');
    return { primary_error: caught.code, cleanup_error: caught.lock_cleanup_error,
      nonrecursive_rmdir_attempts: casePermitted.length, raced_content_preserved: true };
  });
} finally {
  // All interception is restored before cleanup. Revalidate the fixture and
  // OS temp parent immediately before recursive removal; refuse cleanup if
  // either physical identity or containment has changed.
  restoreMutationFence();
  let cleanupRefusal = null;
  try {
    const parentStat = fs.lstatSync(tempParent, { bigint: true });
    const rootStat = fs.lstatSync(physicalTempRoot, { bigint: true });
    const currentParent = fs.realpathSync(tempParent);
    const currentRoot = fs.realpathSync(physicalTempRoot);
    const relative = path.relative(currentParent, currentRoot);
    const contained = relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`)
      && !path.isAbsolute(relative);
    if (parentStat.isSymbolicLink() || rootStat.isSymbolicLink()
      || String(parentStat.dev) !== tempParentIdentity.dev || String(parentStat.ino) !== tempParentIdentity.ino
      || String(rootStat.dev) !== fixtureRootIdentity.dev || String(rootStat.ino) !== fixtureRootIdentity.ino
      || currentParent !== tempParent || currentRoot !== physicalTempRoot || !contained) {
      throw new Error('physical temp root or OS temp parent identity/containment changed');
    }
  } catch (error) {
    cleanupRefusal = error;
  }
  if (cleanupRefusal) {
    const refusal = `Fixture cleanup refused; no recursive removal attempted: ${cleanupRefusal.message}`;
    checks.push({ name: 'fixture-cleanup', status: 'fail', error: refusal });
    throw new Error(refusal, { cause: cleanupRefusal });
  }
  fs.rmSync(physicalTempRoot, { recursive: true, force: true });
}

const summary = {
  schema: 'manager-authority-regressions.v1',
  status: checks.every((check) => check.status === 'pass') ? 'pass' : 'fail',
  passed: checks.filter((check) => check.status === 'pass').length,
  total: checks.length,
  source,
  fixture_root: physicalTempRoot,
  fixture_root_was_os_mkdtemp: true,
  destructive_guard_attempts: blocked,
  permitted_nonrecursive_cleanup_attempts: permitted,
  checks,
  scope: 'Current v3 release/replacement assertions plus three explicitly named retained-v2 publication compatibility cases; no product source writes.',
};
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
process.exitCode = summary.status === 'pass' ? 0 : 1;
