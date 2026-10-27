'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const current = require('../tools/lib/contained-lock-manager');
const legacy = require('./fixtures/lock-v2-runtime/tools/lib/contained-lock-manager');
const { LOCKS } = require('../tools/lib/lock-policy');

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-lock-compatibility-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, request: { rootKind: 'state', rootPath: root, context: { stateRoot: root },
    lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose } };
}

function snapshot(directory) {
  const stat = fs.lstatSync(directory, { bigint: true });
  return { dev: stat.dev, ino: stat.ino, owner: fs.readFileSync(path.join(directory, 'owner.json')) };
}

test('the exact audit2 reader preserves a held v3 owner it cannot interpret', t => {
  const f = fixture(t), held = current.acquireContainedLock(f.request), before = snapshot(held.path);
  assert.throws(() => legacy.acquireContainedLock({ ...f.request, timeoutMs: 1000 }),
    error => error.code === 'lock_owner_invalid' && error.reason === 'unknown_fields');
  assert.deepEqual(snapshot(held.path), before);
  assert.equal(held.release().status, 'released');
  // New and old writers retain the same namespace. After the generation is
  // released, the old installed runtime can acquire it without a migration.
  const old = legacy.acquireContainedLock(f.request);
  assert.equal(JSON.parse(fs.readFileSync(path.join(old.path, 'owner.json'))).schema_version, 'knowledge-lock-owner.v2');
  assert.equal(old.release().status, 'released');
});

test('a current contender preserves a live audit2 writer and can acquire after its release', t => {
  const f = fixture(t), old = legacy.acquireContainedLock(f.request), before = snapshot(old.path);
  assert.throws(() => current.acquireContainedLock({ ...f.request, timeoutMs: 1000 }),
    error => error.code === 'lock_timeout');
  assert.deepEqual(snapshot(old.path), before);
  assert.equal(old.release().status, 'released');
  const fresh = current.acquireContainedLock(f.request);
  assert.equal(fresh.release().status, 'released');
});

test('legacy ownerless publication remains unknown to the current writer regardless of age', t => {
  const f = fixture(t), policy = current.__test.requestPolicy(f.request), paths = current.lockPaths(policy);
  fs.mkdirSync(paths.lockDir, { recursive: true });
  const old = new Date(Date.now() - 30 * 86400000);
  fs.utimesSync(paths.lockDir, old, old);
  const before = fs.statSync(paths.lockDir, { bigint: true });
  assert.throws(() => current.acquireContainedLock({ ...f.request, timeoutMs: 1000 }),
    error => error.code === 'lock_timeout' && error.owner_disposition === 'owner_initialization_unconfirmed');
  const after = fs.statSync(paths.lockDir, { bigint: true });
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  assert.deepEqual(fs.readdirSync(paths.lockDir), []);
});
