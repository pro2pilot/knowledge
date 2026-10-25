'use strict';

// All clock changes are confined to an owned child process. The OS clock is
// never changed. Windows sharing denial is a modelled branch, not a claim of
// native Windows acceptance when this test is run on another host.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const SOURCE = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));

function clockWorker() {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const crypto = require('node:crypto');
  const [source, mechanism, mode] = process.argv.slice(1);
  const manager = require(path.join(source, 'tools/lib/contained-lock-manager'));
  const { LOCKS } = require(path.join(source, 'tools/lib/lock-policy'));
  const hostPlatform = process.platform;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-monotonic-lock-'));
  // Deliberately fractional: the existing public duration policy allows it.
  // These short explicit fixture budgets do not change production defaults.
  const budgetMs = 1000.5;
  const guardMs = 5000;
  const request = { rootKind: 'state', rootPath: root, context: { stateRoot: root },
    lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose, timeoutMs: budgetMs };
  let held = null, unexpected = null;
  let directory, ownerFile;
  if (mechanism === 'legacy') {
    // A valid legacy-format record belongs to this actual live child. It is
    // retained as unknown by the product; only this fixture removes it later.
    directory = path.join(root, '.lock');
    fs.mkdirSync(directory);
    ownerFile = path.join(directory, 'owner.json');
    fs.writeFileSync(ownerFile, JSON.stringify({ lock_id: crypto.randomUUID(),
      pid: process.pid, hostname: os.hostname(), started_at: new Date().toISOString() }) + '\n');
  } else {
    held = manager.acquireContainedLock(request);
    directory = held.path;
    ownerFile = path.join(directory, 'owner.json');
  }
  const snapshot = () => {
    const stat = fs.lstatSync(directory, { bigint: true });
    return { dev: String(stat.dev), ino: String(stat.ino), owner: fs.readFileSync(ownerFile, 'utf8') };
  };
  const before = snapshot();
  const originalNow = Date.now;
  const originalRename = fs.renameSync;
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  const wallStart = originalNow();
  const startedAt = process.hrtime.bigint();
  const elapsed = () => Number(process.hrtime.bigint() - startedAt) / 1e6;
  let wallReads = 0, sharingDenials = 0, sharingBranch = false;
  Date.now = () => {
    if (elapsed() >= guardMs) {
      const error = new Error('Owned clock probe exceeded its independent monotonic guard.');
      error.code = 'clock_probe_guard';
      throw error;
    }
    wallReads += 1;
    if (mode === 'frozen' || wallReads === 1) return wallStart;
    return originalNow() + (mode === 'rollback' ? -3600000 : 3600000);
  };
  if (mechanism === 'windows_release_model') {
    // Expose win32 only at the sharing-error retry decision. Native path and
    // owner observations still execute under the actual host platform.
    Object.defineProperty(process, 'platform', { configurable: true,
      enumerable: platformDescriptor.enumerable, get() {
        if (sharingBranch) { sharingBranch = false; return 'win32'; }
        return hostPlatform;
      } });
    fs.renameSync = function modelPersistentSharingDenial(from, to) {
      if (from === directory) {
        sharingDenials += 1;
        sharingBranch = true;
        const error = new Error('Owned fixture models a Windows owner-file sharing denial.');
        error.code = 'EPERM';
        throw error;
      }
      return originalRename.apply(this, arguments);
    };
  }
  let failure = null, returned = null, elapsedMs;
  try {
    if (mechanism === 'windows_release_model') returned = held.release();
    else unexpected = manager.acquireContainedLock(request);
  } catch (error) {
    failure = { code: error.code || null, os_code: error.os_code || null,
      message: error.message, owner_disposition: error.owner_disposition || null };
  } finally {
    elapsedMs = elapsed();
    Date.now = originalNow;
    fs.renameSync = originalRename;
    Object.defineProperty(process, 'platform', platformDescriptor);
  }
  let after = null, finalRelease = null, cleanupError = null;
  try {
    after = snapshot();
    if (unexpected) unexpected.release();
    if (held) finalRelease = held.release();
    else {
      fs.unlinkSync(ownerFile);
      fs.rmdirSync(directory);
      finalRelease = { status: 'owned_legacy_fixture_removed' };
    }
  } catch (error) { cleanupError = { code: error.code || null, message: error.message }; }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
  process.stdout.write(JSON.stringify({ mechanism, mode, host_platform: hostPlatform,
    native_windows_qualification: false, budget_ms: budgetMs, guard_ms: guardMs,
    elapsed_ms: elapsedMs, wall_reads: wallReads, sharing_denials: sharingDenials,
    failure, unexpected_acquire: unexpected !== null, returned,
    owner_unchanged: JSON.stringify(after) === JSON.stringify(before), final_release: finalRelease,
    cleanup_error: cleanupError, node_version: process.version }));
}

for (const mechanism of ['current', 'legacy', 'windows_release_model']) {
  for (const mode of ['rollback', 'frozen', 'forward']) {
    test(`${mechanism} elapsed budget survives ${mode} wall clock (owned process)`, { timeout: 20000 }, t => {
      const child = spawnSync(process.execPath, ['-e', `(${clockWorker.toString()})()`, SOURCE, mechanism, mode], {
        env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' },
        encoding: 'utf8', windowsHide: true, timeout: 15000,
      });
      assert.ifError(child.error);
      assert.equal(child.signal, null);
      assert.equal(child.status, 0, child.stderr);
      assert.equal(child.stderr, '');
      const result = JSON.parse(child.stdout);
      t.diagnostic(JSON.stringify(result));
      assert.equal(result.owner_unchanged, true, 'A clock step must not replace or erase the held owner');
      assert.equal(result.unexpected_acquire, false);
      assert.equal(result.cleanup_error, null);
      assert.equal(result.final_release.status,
        mechanism === 'legacy' ? 'owned_legacy_fixture_removed' : 'released');
      if (mechanism === 'windows_release_model') {
        assert.ok(result.sharing_denials > 0, 'The sharing retry decision must actually be reached');
        assert.equal(result.failure?.code, 'unsafe_lock_path');
        assert.equal(result.failure?.os_code, 'EPERM');
      } else assert.equal(result.failure?.code, 'lock_timeout');
      assert.ok(result.elapsed_ms >= result.budget_ms - 10,
        `A forward clock step shortened the waiting budget: ${result.elapsed_ms} ms`);
      assert.ok(result.elapsed_ms < result.guard_ms,
        'Rollback/frozen wall time must not consume the independent five-second guard');
    });
  }
}

function finalSleepWorker() {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const crypto = require('node:crypto');
  const [source, mechanism] = process.argv.slice(1);
  const managerPath = require.resolve(path.join(source, 'tools/lib/contained-lock-manager'));
  const manager = require(managerPath);
  const store = require(path.join(source, 'tools/lib/json-store'));
  const { LOCKS } = require(path.join(source, 'tools/lib/lock-policy'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-final-lock-wait-'));
  const budgetMs = 1000;
  const request = { rootKind: 'state', rootPath: root, context: { stateRoot: root },
    lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose, timeoutMs: budgetMs };
  const publicPath = path.join(root, 'locks/v1/team-flow.lock');
  const legacyPath = path.join(root, '.lock');
  let held = null;
  if (mechanism === 'current') held = manager.acquireContainedLock(request);
  if (mechanism === 'legacy') {
    fs.mkdirSync(legacyPath);
    fs.writeFileSync(path.join(legacyPath, 'owner.json'), JSON.stringify({ lock_id: crypto.randomUUID(),
      pid: process.pid, hostname: os.hostname(), started_at: new Date().toISOString() }) + '\n');
  }
  const originalSleep = store.sleepSync;
  const originalRename = fs.renameSync;
  const originalCached = require.cache[managerPath];
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  const hostPlatform = process.platform;
  let sleeps = 0, releasedDuringSleep = false, renameAttempts = 0, sharingBranch = false;
  store.sleepSync = function modelSchedulerDelay() {
    sleeps += 1;
    if (sleeps !== 1) throw new Error('An expired acquisition unexpectedly started another sleep.');
    // Real elapsed time crosses the request budget before the exact holder
    // releases. Only scheduling is controlled; owner validation is unchanged.
    originalSleep(budgetMs + 500);
    if (mechanism === 'current') {
      if (held.release().status !== 'released') throw new Error('The exact holder did not release.');
      held = null;
      releasedDuringSleep = true;
    } else if (mechanism === 'legacy') {
      fs.unlinkSync(path.join(legacyPath, 'owner.json'));
      fs.rmdirSync(legacyPath);
      releasedDuringSleep = true;
    }
  };
  // A second loaded manager captures the scoped scheduling wrapper. Both
  // instances run unchanged product source; this test process owns them.
  delete require.cache[managerPath];
  const contender = require(managerPath);
  let originalOwner = null, originalIdentity = null;
  if (mechanism === 'windows_release_model') {
    held = contender.acquireContainedLock(request);
    originalOwner = fs.readFileSync(path.join(publicPath, 'owner.json'), 'utf8');
    const stat = fs.lstatSync(publicPath, { bigint: true });
    originalIdentity = `${stat.dev}:${stat.ino}`;
    Object.defineProperty(process, 'platform', { configurable: true,
      enumerable: platformDescriptor.enumerable, get() {
        if (sharingBranch) { sharingBranch = false; return 'win32'; }
        return hostPlatform;
      } });
    fs.renameSync = function modelSharingReleasedDuringFinalWait(from, to) {
      if (from === publicPath) {
        renameAttempts += 1;
        if (renameAttempts === 1) {
          sharingBranch = true;
          const error = new Error('Owned modelled sharing denial before a delayed final wait.');
          error.code = 'EPERM';
          throw error;
        }
      }
      return originalRename.apply(this, arguments);
    };
  }
  let unexpected = null, returned = null, failure = null;
  const startedAt = process.hrtime.bigint();
  try {
    if (mechanism === 'windows_release_model') returned = held.release();
    else unexpected = contender.acquireContainedLock(request);
  } catch (error) {
    failure = { code: error.code || null, os_code: error.os_code || null,
      message: error.message, owner_disposition: error.owner_disposition || null };
  } finally {
    store.sleepSync = originalSleep;
    fs.renameSync = originalRename;
    Object.defineProperty(process, 'platform', platformDescriptor);
    require.cache[managerPath] = originalCached;
  }
  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
  const publicExists = fs.existsSync(publicPath);
  let ownerUnchanged = null;
  if (mechanism === 'windows_release_model') {
    if (publicExists) {
      const stat = fs.lstatSync(publicPath, { bigint: true });
      ownerUnchanged = `${stat.dev}:${stat.ino}` === originalIdentity &&
        fs.readFileSync(path.join(publicPath, 'owner.json'), 'utf8') === originalOwner;
    } else ownerUnchanged = false;
  }
  let cleanupError = null;
  try {
    if (unexpected) unexpected.release();
    if (held) held.release();
  } catch (error) { cleanupError = { code: error.code || null, message: error.message }; }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
  process.stdout.write(JSON.stringify({ mechanism, elapsed_ms: elapsedMs, budget_ms: budgetMs,
    sleeps, released_during_sleep: releasedDuringSleep, rename_attempts: renameAttempts,
    failure, returned, unexpected_acquire: unexpected !== null,
    public_exists_before_fixture_cleanup: publicExists, owner_unchanged: ownerUnchanged,
    cleanup_error: cleanupError, host_platform: hostPlatform, native_windows_qualification: false }));
}

for (const mechanism of ['current', 'legacy', 'windows_release_model']) {
  test(`${mechanism} starts no new operation after its final retry sleep crosses the budget`, { timeout: 20000 }, t => {
    const child = spawnSync(process.execPath, ['-e', `(${finalSleepWorker.toString()})()`, SOURCE, mechanism], {
      env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' },
      encoding: 'utf8', windowsHide: true, timeout: 15000,
    });
    assert.ifError(child.error);
    assert.equal(child.signal, null);
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stderr, '');
    const result = JSON.parse(child.stdout);
    t.diagnostic(JSON.stringify(result));
    assert.equal(result.sleeps, 1);
    assert.ok(result.elapsed_ms >= result.budget_ms);
    assert.equal(result.cleanup_error, null);
    assert.equal(result.unexpected_acquire, false,
      'A released path must not admit a new owner after the original request has expired');
    if (mechanism === 'windows_release_model') {
      assert.equal(result.returned, null);
      assert.equal(result.failure?.code, 'unsafe_lock_path');
      assert.equal(result.failure?.os_code, 'EPERM');
      assert.equal(result.rename_attempts, 1, 'An expired release must not start another rename attempt');
      assert.equal(result.owner_unchanged, true);
    } else {
      assert.equal(result.released_during_sleep, true);
      assert.equal(result.failure?.code, 'lock_timeout');
      assert.equal(result.public_exists_before_fixture_cleanup, false);
      assert.match(result.failure.message, /expired before retry;?\./);
      assert.match(result.failure.message, /Last observed owner:/);
    }
  });
}
