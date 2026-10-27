'use strict';

// Real filesystem operations with a deterministic, single-process scheduling
// boundary. The only other process creates its own owner record and exits;
// no PID/native identity is fabricated and no process is signalled.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const managerPath = path.resolve(__dirname, '../tools/lib/contained-lock-manager.js');
const legacyManagerPath = path.resolve(__dirname, 'fixtures/lock-v2-runtime/tools/lib/contained-lock-manager.js');
const manager = require(managerPath);
const { LOCKS } = require('../tools/lib/lock-policy');
const native = { skip: process.platform !== 'linux', timeout: 30000 };

function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-generation-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const request = { rootKind: 'state', rootPath: root, context: { stateRoot: root },
    lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose, timeoutMs: 1000 };
  const publicPath = path.join(root, 'locks/v1/team-flow.lock');
  const history = path.join(root, 'locks/v1/.stale');
  const child = spawnSync(process.execPath, ['-e',
    'require(process.argv[1]).acquireContainedLock(JSON.parse(process.argv[2]));',
    options.legacyV2 ? legacyManagerPath : managerPath, JSON.stringify(request)], {
    env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' }, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.signal, null);
  // A legacy v2 writer has no kernel lease. Keep this exact mixed-version
  // scheduling case: its delayed reclaimer may resume after a v3 successor.
  // V3 reclaimers separately hold an owner-inode lease across this boundary,
  // so a second reclaimer cannot enter this old interleaving at all.
  const owner = fs.readFileSync(path.join(publicPath, 'owner.json'));
  if (!JSON.parse(owner).native_identity) {
    t.skip('Qualified Linux owner provider is unavailable; no native recovery claim.');
    return null;
  }
  function agePublic() {
    const old = new Date(Date.now() - 3 * 86400000);
    fs.utimesSync(publicPath, old, old);
  }
  agePublic();
  assert.equal(manager.inspectLockSafety(request).current.status, 'stale');
  return { root, request, publicPath, history, owner, agePublic };
}

function recovered(t) {
  // Legacy owners do not self-bind physical inode identity. Their restored
  // byte copies must still be rejected by the retained generation fence.
  // V3 copies are rejected earlier by reliability-lock-inode-binding.test.
  const f = fixture(t, { legacyV2: true });
  if (!f) return null;
  const held = manager.acquireContainedLock(f.request);
  held.release();
  const entries = fs.readdirSync(f.history);
  assert.equal(entries.length, 1, 'Recovery must retain exactly one nonempty generation fence.');
  const retained = path.join(f.history, entries[0]);
  assert.deepEqual(fs.readFileSync(path.join(retained, 'owner.json')), f.owner);
  assert.equal(manager.inspectLockSafety(f.request).status, 'safe',
    'Retained recovery history must not look like a current unsafe owner.');
  assert.deepEqual(manager.inspectAllLockSafety({ rootPath: f.root, rootKind: 'state' }).findings, [],
    'Doctor lock inventory must accept valid retained generation history.');
  return { ...f, retained };
}

function restoreOldGeneration(f) {
  fs.mkdirSync(f.publicPath);
  fs.writeFileSync(path.join(f.publicPath, 'owner.json'), f.owner);
  f.agePublic();
}

test('a delayed legacy v2 stale reclaimer cannot move a newer live owner', native, t => {
  const f = fixture(t, { legacyV2: true });
  if (!f) return;
  const rename = fs.renameSync;
  let injected = false, live = null, originalIdentity = null, originalOwner = null;
  fs.renameSync = function scheduleAfterStaleValidation(from, to) {
    if (!injected && from === f.publicPath && path.dirname(to) === f.history) {
      injected = true;
      fs.renameSync = rename;
      // A second logical contender completes recovery and publishes its own
      // real live owner while the first is paused immediately before rename.
      live = manager.acquireContainedLock(f.request);
      originalIdentity = fs.statSync(f.publicPath, { bigint: true });
      originalOwner = fs.readFileSync(path.join(f.publicPath, 'owner.json'));
    }
    return rename.apply(this, arguments);
  };
  t.after(() => {
    fs.renameSync = rename;
    if (live) { try { live.release(); } catch {} }
  });
  let result;
  try { manager.acquireContainedLock(f.request); }
  catch (error) { result = error; }
  finally { fs.renameSync = rename; }
  assert.equal(injected, true, 'The actual stale rename boundary must be reached.');
  assert.equal(result?.code, 'lock_timeout', result?.stack);
  const after = fs.statSync(f.publicPath, { bigint: true });
  assert.equal(after.dev, originalIdentity.dev);
  assert.equal(after.ino, originalIdentity.ino);
  assert.deepEqual(fs.readFileSync(path.join(f.publicPath, 'owner.json')), originalOwner);
  assert.throws(() => manager.acquireContainedLock({ ...f.request, timeoutMs: 100 }),
    error => error.code === 'lock_timeout');
  assert.equal(live.release().status, 'released');
  live = null;
  const history = fs.readdirSync(f.history);
  assert.equal(history.length, 1);
  assert.deepEqual(fs.readFileSync(path.join(f.history, history[0], 'owner.json')), f.owner);
});

test('a previously recovered generation reappearing is refused without mutation', native, t => {
  const f = recovered(t);
  if (!f) return;
  restoreOldGeneration(f);
  const identity = fs.statSync(f.publicPath, { bigint: true });
  assert.throws(() => manager.acquireContainedLock(f.request), error =>
    error.code === 'lock_ownership_changed' && error.reason === 'recovered_generation_reappeared');
  assert.equal(fs.statSync(f.publicPath, { bigint: true }).ino, identity.ino);
  assert.deepEqual(fs.readFileSync(path.join(f.publicPath, 'owner.json')), f.owner);
  assert.deepEqual(fs.readFileSync(path.join(f.retained, 'owner.json')), f.owner);
});

test('an empty retained generation is not replaced by a public directory', native, t => {
  const f = recovered(t);
  if (!f) return;
  fs.unlinkSync(path.join(f.retained, 'owner.json'));
  restoreOldGeneration(f);
  const identity = fs.statSync(f.publicPath, { bigint: true });
  assert.throws(() => manager.acquireContainedLock(f.request), error =>
    error.code === 'lock_recovery_history_invalid' && error.recovery_required === 'recovery_history_evidence');
  assert.equal(fs.statSync(f.publicPath, { bigint: true }).ino, identity.ino);
  assert.deepEqual(fs.readFileSync(path.join(f.publicPath, 'owner.json')), f.owner);
  assert.deepEqual(fs.readdirSync(f.retained), []);
});

test('a retained generation alias cannot redirect or authorize recovery', native, t => {
  const f = recovered(t);
  if (!f) return;
  const parked = path.join(f.root, 'retained-physical-evidence');
  fs.renameSync(f.retained, parked);
  fs.symlinkSync(parked, f.retained, 'dir');
  restoreOldGeneration(f);
  assert.throws(() => manager.acquireContainedLock(f.request), error =>
    error.code === 'unsafe_lock_path');
  assert.deepEqual(fs.readFileSync(path.join(f.publicPath, 'owner.json')), f.owner);
  assert.deepEqual(fs.readFileSync(path.join(parked, 'owner.json')), f.owner);
  assert.equal(fs.lstatSync(f.retained).isSymbolicLink(), true);
});

test('an interruption after recovery leaves a fence and permits a later fresh acquire', native, t => {
  const f = fixture(t);
  if (!f) return;
  const interrupted = new Error('Owned fixture interruption after completed recovery');
  assert.throws(() => manager.acquireContainedLock({ ...f.request, onRecovery() { throw interrupted; } }),
    error => error === interrupted);
  assert.equal(fs.existsSync(f.publicPath), false);
  const names = fs.readdirSync(f.history);
  assert.equal(names.length, 1);
  const retained = path.join(f.history, names[0], 'owner.json');
  assert.deepEqual(fs.readFileSync(retained), f.owner);
  const held = manager.acquireContainedLock(f.request);
  assert.equal(held.release().status, 'released');
  assert.deepEqual(fs.readFileSync(retained), f.owner);
});
