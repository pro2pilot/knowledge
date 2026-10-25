'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const SOURCE = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));
const { removeTempDirStrict, captureTempDirIdentity } = require(path.join(SOURCE, 'tools/lib/strict-temp-cleanup'));
const pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-cleanup-admission-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'owned');
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'evidence.txt'), 'must survive an expired retry');
  return { root, target, expectedIdentity: captureTempDirIdentity(target) };
}

test('a cleanup retry is not admitted after a delayed wait exhausts its original budget', { timeout: 15000 }, t => {
  const f = fixture(t);
  const budget = 1000;
  let attempts = 0, sleeps = 0, result = null, failure = null;
  const start = process.hrtime.bigint();
  try {
    result = removeTempDirStrict(f.target, { expectedIdentity: f.expectedIdentity,
      attempts: 3, maxElapsedMs: budget, initialDelayMs: 10, maxDelayMs: 10,
      remove(target) {
        attempts += 1;
        if (attempts === 1) throw Object.assign(new Error('owned sharing-error fixture'), { code: 'EBUSY' });
        fs.rmSync(target, { recursive: true, force: false });
      },
      sleep() { sleeps += 1; pause(budget + 500); },
    });
  } catch (error) { failure = error; }
  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
  t.diagnostic(JSON.stringify({ attempts, sleeps, elapsed_ms: elapsed, result,
    failure: failure && { code: failure.code, reason: failure.reason, attempts: failure.attempts, elapsed_ms: failure.elapsed_ms },
    target_retained: fs.existsSync(f.target) }));
  assert.equal(sleeps, 1, 'The test must reach the exact delayed retry boundary');
  assert.ok(elapsed >= budget);
  assert.equal(attempts, 1, 'Expired cleanup admitted a new destructive remove operation');
  assert.equal(result, null);
  assert.equal(failure?.code, 'TEMP_FIXTURE_CLEANUP_FAILED');
  assert.equal(failure?.reason, 'persistent_resource_lock');
  assert.equal(failure?.attempts, 1);
  assert.equal(fs.readFileSync(path.join(f.target, 'evidence.txt'), 'utf8'), 'must survive an expired retry');
});

test('a successful remove admitted within budget may complete after that budget', { timeout: 15000 }, t => {
  const f = fixture(t);
  let attempts = 0;
  const result = removeTempDirStrict(f.target, { expectedIdentity: f.expectedIdentity,
    maxElapsedMs: 1000,
    remove(target) { attempts += 1; pause(1500); fs.rmSync(target, { recursive: true, force: false }); },
  });
  assert.equal(attempts, 1);
  assert.equal(result.status, 'removed');
  assert.equal(result.attempts, 1);
  assert.ok(result.elapsed_ms >= 1000);
  assert.equal(fs.existsSync(f.target), false);
});

test('a retry within the original cleanup budget still succeeds', { timeout: 15000 }, t => {
  const f = fixture(t);
  let attempts = 0, sleeps = 0;
  const result = removeTempDirStrict(f.target, { expectedIdentity: f.expectedIdentity,
    maxElapsedMs: 5000, initialDelayMs: 10,
    remove(target) {
      attempts += 1;
      if (attempts === 1) throw Object.assign(new Error('owned transient error'), { code: 'EBUSY' });
      fs.rmSync(target, { recursive: true, force: false });
    },
    sleep(ms) { sleeps += 1; pause(ms); },
  });
  assert.equal(sleeps, 1);
  assert.equal(attempts, 2);
  assert.equal(result.status, 'removed');
  assert.equal(fs.existsSync(f.target), false);
});
