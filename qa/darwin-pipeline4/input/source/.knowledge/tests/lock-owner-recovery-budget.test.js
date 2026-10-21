'use strict';

// A completed stale cleanup does not renew the caller's acquisition budget.
// The short budget and deliberate callback pause are confined to this fixture.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const SOURCE = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));
const manager = require(path.join(SOURCE, 'tools/lib/contained-lock-manager'));
const { LOCKS } = require(path.join(SOURCE, 'tools/lib/lock-policy'));

test('a delayed recovery callback cannot create a new owner after the original budget', t => {
  if (process.platform !== 'linux' || !manager.__test.captureNativeOwnerIdentity()) {
    t.skip('This positive crash-recovery test requires real qualified Linux owner coordinates');
    return;
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-recovery-budget-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const state = path.join(root, 'state');
  const request = { context: { stateRoot: state }, rootKind: 'state', rootPath: state,
    lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose, timeoutMs: 5000, staleMs: 1 };
  const code = `const path=require('node:path');const fs=require('node:fs');
const manager=require(path.join(process.argv[1],'tools/lib/contained-lock-manager'));
const h=manager.acquireContainedLock(JSON.parse(process.argv[2]));
process.stdout.write(JSON.stringify({pid:process.pid,path:h.path,lock_id:h.lock_id}));`;
  const child = spawnSync(process.execPath, ['-e', code, SOURCE, JSON.stringify(request)], {
    encoding: 'utf8', timeout: 30000, windowsHide: true
  });
  assert.ifError(child.error); assert.equal(child.status, 0, child.stderr);
  const departed = JSON.parse(child.stdout);
  assert.equal(departed.pid, child.pid, 'The recorded holder must be the awaited own child');
  const owner = JSON.parse(fs.readFileSync(path.join(departed.path, 'owner.json'), 'utf8'));
  assert.equal(owner.pid, departed.pid); assert.equal(owner.lock_id, departed.lock_id);
  assert.ok(owner.native_identity, 'Positive recovery must not substitute an unqualified identity');
  assert.throws(() => process.kill(departed.pid, 0), error => error.code === 'ESRCH');
  const old = new Date(Date.now() - 60000); fs.utimesSync(departed.path, old, old);
  const inspected = manager.inspectLockSafety(request);
  assert.equal(inspected.current.status, 'stale');
  assert.equal(inspected.current.reason, 'dead_scoped_owner');

  let recoveryCalls = 0, successor = null, failure = null;
  try {
    successor = manager.acquireContainedLock({ ...request, timeoutMs: 500,
      onRecovery(event) {
        assert.equal(event.lock_name, request.lockName);
        recoveryCalls += 1;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
      }
    });
  } catch (error) { failure = error; }
  if (successor) successor.release();
  assert.equal(recoveryCalls, 1, 'The real stale cleanup must have completed before expiry');
  assert.ok(failure, 'A recovery retry incorrectly admitted a new owner after its original budget');
  assert.equal(failure.code, 'lock_timeout');
  assert.equal(failure.owner_disposition, 'recovery_budget_exhausted');
  assert.equal(failure.recovery_required, null);
  assert.equal(successor, null);
  assert.equal(fs.existsSync(departed.path), false, 'Expired acquisition must not publish a new owner');

  // A later, independent request receives its own budget and can proceed.
  // Retained recovery history is allowed; only the public lock path is tested.
  const fresh = manager.acquireContainedLock(request);
  assert.notEqual(fresh.lock_id, departed.lock_id);
  assert.equal(fresh.release().status, 'released');
});
