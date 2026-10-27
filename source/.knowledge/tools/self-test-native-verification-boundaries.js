#!/usr/bin/env node
'use strict';

// These boundary checks execute no child process. The same script can also be
// run against a supplied prior tree to show the regression, in a fresh Node.
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');
const sourceRoot = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const productFiles = ['tools/lib/repair-on-touch.js', 'tools/lib/verification-supervisor.js',
  'tools/lib/verification-worker.js', 'tools/lib/inert-data.js'];
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const sourceHashes = () => Object.fromEntries(productFiles.map(file => [file, hash(fs.readFileSync(path.join(sourceRoot, file)))]));
const sourceBefore = sourceHashes();
const absentFixture = path.join(__dirname, 'native-boundary-fixture-must-not-be-created');
assert(!fs.existsSync(absentFixture), 'Use a fresh tree; this test does not create or remove fixtures');
const checks = [];
let spawnAttempts = 0;
const originalSpawn = childProcess.spawn, originalSpawnSync = childProcess.spawnSync;
const blockSpawn = () => {
  spawnAttempts++;
  throw Object.assign(new Error('A boundary test reached process creation'), { code: 'AUDIT_UNEXPECTED_SPAWN' });
};
childProcess.spawn = blockSpawn;
childProcess.spawnSync = blockSpawn;
const options = () => ({
  stateRoot: path.join(absentFixture, '.knowledge'), repoRoot: absentFixture,
  taskId: 'native-boundary-test', sessionId: 'native-boundary-test', checkedBy: 'native-boundary-test',
  tests: [{ argv: ['node', 'probe.js'], cwd: '.', timeout_ms: 1000 }],
  sourceFiles: ['probe.js'], timeoutMs: 2000
});
async function observedError(fn) {
  try { await fn(); return null; } catch (error) { return error; }
}
async function check(name, fn) {
  const evidence = {};
  try {
    await fn(evidence);
    checks.push({ name, status: 'pass', evidence });
  } catch (error) {
    checks.push({ name, status: 'fail', error: error.stack, evidence });
  }
}

(async () => {
  try {
    const native = require(path.join(sourceRoot, 'tools/lib/repair-on-touch.js'));
    const transport = require(path.join(sourceRoot, 'tools/lib/verification-supervisor.js'));
    async function active(name, make, invoke = value => native.runVerificationTests(value), expectedCode = 'verification_input_invalid') {
      await check(name, async evidence => {
        let hooks = 0;
        const hook = () => { hooks++; throw Object.assign(new Error('Caller hook executed'), { code: 'AUDIT_ACTIVE_INPUT_CALLED' }); };
        const value = make(hook);
        const error = await observedError(() => invoke(value));
        evidence.hook_executions = hooks;
        evidence.error_code = error?.code;
        assert.equal(error?.code, expectedCode);
        assert.equal(hooks, 0);
      });
    }
    await active('public runner rejects a top-level getter without invocation', hook => {
      const value = options(); Object.defineProperty(value, 'tests', { enumerable: true, get: hook }); return value;
    });
    await active('public runner rejects a nested timeout getter without invocation', hook => {
      const value = options(); Object.defineProperty(value.tests[0], 'timeout_ms', { enumerable: true, get: hook }); return value;
    });
    await active('public runner rejects a serialization hook without invocation', hook => ({ ...options(), toJSON: hook }));
    await active('public runner rejects a proxy without traps', hook => new Proxy(options(), { get: hook, ownKeys: hook, getOwnPropertyDescriptor: hook, getPrototypeOf: hook }));
    await active('public runner rejects an inherited getter without invocation', hook => Object.create({ get tests() { return hook(); } }));
    await active('transport rejects a serialization hook before stringify', hook => ({ toJSON: hook }), value => transport.runSupervised(value, 1000));
    await active('transport rejects timeout scalar coercion without invocation', hook => ({ valueOf: hook }),
      value => transport.runSupervised(options(), value), 'verification_timeout_invalid');
    await active('transport rejects start scalar coercion without invocation', hook => ({ [Symbol.toPrimitive]: hook }),
      value => transport.runSupervised(options(), 1000, value), 'verification_clock_invalid');
    await active('direct supervisor rejects a control getter without invocation', hook => {
      const value = {}; Object.defineProperty(value, 'protocol', { enumerable: true, get: hook }); return value;
    }, value => transport.__test.supervise(value));
    await active('exported core rejects a request getter without invocation', hook => {
      const value = options(); Object.defineProperty(value, 'stateRoot', { enumerable: true, get: hook }); return value;
    }, value => native.__runVerificationTestsCore(value, {}));
    const payload = timeout => {
      const now = process.hrtime.bigint();
      return { protocol: transport.__test.PROTOCOL, started_ns: String(now),
        deadline_ns: String(now + BigInt(timeout) * 1000000n), timeout_ms: timeout, request: options() };
    };
    await active('direct supervisor rejects worker-path coercion without invocation', hook => ({ toString: hook }),
      value => transport.__test.supervise(payload(2000), value), 'verification_worker_invalid');
    await check('direct supervisor validates scalar clock and budget fields before arithmetic', async evidence => {
      const cases = [];
      for (const invalid of [null, true, '2000', 0, -1, 1.5]) {
        const value = payload(2000); value.timeout_ms = invalid;
        const error = await observedError(() => transport.__test.supervise(value));
        cases.push({ value: String(invalid), code: error?.code });
        assert.equal(error?.code, 'verification_timeout_invalid');
      }
      const wrongDeadline = payload(2000); wrongDeadline.deadline_ns = String(BigInt(wrongDeadline.deadline_ns) + 1n);
      assert.equal((await observedError(() => transport.__test.supervise(wrongDeadline)))?.code, 'verification_clock_invalid');
      const longClock = payload(2000); longClock.started_ns = '1'.repeat(33);
      assert.equal((await observedError(() => transport.__test.supervise(longClock)))?.code, 'verification_protocol_invalid');
      assert.equal((await observedError(() => transport.runSupervised(options(), 1000, process.hrtime.bigint() + 1000000000n)))?.code,
        'verification_clock_invalid');
      evidence.invalid_budget_cases = cases;
    });

    await check('revoked proxy is rejected with the typed input error', async evidence => {
      const pair = Proxy.revocable({}, {}); pair.revoke();
      const error = await observedError(() => native.runVerificationTests(pair.proxy));
      evidence.error_code = error?.code;
      assert.equal(error?.code, 'verification_input_invalid');
    });
    await check('oversized inert input is rejected before children', async evidence => {
      const error = await observedError(() => native.runVerificationTests({ ...options(), extra: 'x'.repeat(17 * 1024 * 1024) }));
      evidence.error_code = error?.code;
      assert.equal(error?.code, 'verification_input_invalid');
    });
    await check('excessively deep inert input is rejected before children', async evidence => {
      const value = options(); let current = value;
      for (let i = 0; i < 70; i++) current = current.extra = {};
      const error = await observedError(() => native.runVerificationTests(value));
      evidence.error_code = error?.code;
      assert.equal(error?.code, 'verification_input_invalid');
    });
    await check('oversized property keys are rejected before serialization or children', async evidence => {
      const value = options(); value['x'.repeat(6 * 1024 * 1024)] = 1;
      const error = await observedError(() => native.runVerificationTests(value));
      evidence.error_code = error?.code;
      assert.equal(error?.code, 'verification_input_invalid');
    });
    await check('escape-heavy strings are bounded before JSON serialization', async evidence => {
      const error = await observedError(() => native.runVerificationTests({ ...options(), extra: '\u0001'.repeat(6 * 1024 * 1024) }));
      evidence.error_code = error?.code;
      assert.equal(error?.code, 'verification_input_invalid');
    });
    await check('dense over-limit arrays are rejected before children', async evidence => {
      const error = await observedError(() => native.runVerificationTests({ ...options(), extra: Array(100001).fill(0) }));
      evidence.error_code = error?.code;
      assert.equal(error?.code, 'verification_input_invalid');
    });
    await check('invalid numeric and typed timeouts retain their timeout error code', async evidence => {
      const values = [null, true, false, {}, '1000', 0, -1, 1.5, NaN, Infinity, -Infinity, 600001];
      const results = [];
      for (const value of values) {
        for (const location of ['batch', 'test']) {
          const request = options();
          if (location === 'batch') request.timeoutMs = value;
          else request.tests[0].timeout_ms = value;
          const error = await observedError(() => native.runVerificationTests(request));
          results.push({ location, value: String(value), code: error?.code });
          assert.equal(error?.code, 'verification_timeout_invalid');
        }
      }
      evidence.cases = results;
    });
    await check('timeout validation retains exact values and the existing default', evidence => {
      for (const value of [1, 17, 300001, 600000]) assert.equal(native.verificationTimeoutMs(value), value);
      assert.equal(native.verificationTimeoutMs(undefined), 120000);
      evidence.valid_values = [1, 17, 300001, 600000];
      evidence.default_ms = 120000;
    });
    await check('capability describes an implemented backend without claiming runtime setup', evidence => {
      const value = transport.containmentCapability(); evidence.capability = value;
      assert.equal(value.platform, process.platform);
      assert.equal(value.status, ['win32','linux'].includes(process.platform) ? 'requires_runtime_setup' : 'unavailable');
      assert.equal(value.backend, process.platform === 'win32' ? 'windows_job_object' : process.platform === 'linux' ? 'linux_pid_namespace' : null);
    });
    if (!['win32','linux'].includes(process.platform)) {
      function assertUnavailable(error) {
        assert.equal(error?.code, 'verification_containment_unavailable');
        assert.equal(error?.execution?.status, 'not_started');
        assert.equal(error?.teardown?.status, 'not_required');
        assert.equal(error?.containment?.status, 'unavailable');
      }
      await check('public runner refuses unsupported containment before children or stores', async evidence => {
        const value = options(); const before = JSON.stringify(value);
        const error = await observedError(() => native.runVerificationTests(value));
        evidence.error_code = error?.code; evidence.execution = error?.execution; evidence.teardown = error?.teardown;
        assertUnavailable(error); assert.deepEqual(error.completed_executions, []);
        assert.equal(JSON.stringify(value), before, 'Caller request remains unchanged');
      });
      await check('transport entry refuses unsupported containment before supervisor spawn', async evidence => {
        // Summed batch budgets may exceed the individual 600000ms maximum.
        const error = await observedError(() => transport.runSupervised(options(), 1200000));
        evidence.error_code = error?.code; assertUnavailable(error);
        assert.deepEqual(error.completed_executions, []);
      });
      await check('direct supervisor and custom-worker path cannot bypass the capability', async evidence => {
        const started = process.hrtime.bigint();
        const payload = { protocol: transport.__test.PROTOCOL, started_ns: String(started),
          deadline_ns: String(started + 2000000000n), timeout_ms: 2000, request: options() };
        const result = await transport.__test.supervise(payload, path.join(absentFixture, 'worker.js'));
        evidence.result = result;
        assert.equal(result.status, 'failed'); assert.equal(result.error.code, 'verification_containment_unavailable');
        assert.equal(result.error.execution.status, 'not_started'); assert.equal(result.teardown.status, 'not_required');
        assert.deepEqual(result.completed_executions, []);
      });
      await check('exported worker core cannot start a probe or commit without containment', async evidence => {
        let callbacks = 0;
        const callback = () => { callbacks++; throw new Error('Supervisor callback must not run'); };
        const error = await observedError(() => native.__runVerificationTestsCore(options(), {
          deadline: process.hrtime.bigint() + 2000000000n, phase: callback, committed: callback
        }));
        evidence.error_code = error?.code; evidence.supervisor_callbacks = callbacks;
        assertUnavailable(error); assert.equal(callbacks, 0);
      });
    }
    await check('all rejected paths left process creation and fixtures untouched', evidence => {
      evidence.spawn_attempts = spawnAttempts;
      evidence.fixture_exists = fs.existsSync(absentFixture);
      assert.equal(spawnAttempts, 0); assert.equal(evidence.fixture_exists, false);
    });
    await check('reviewed source bytes remain unchanged during the checks', evidence => {
      const sourceAfter = sourceHashes(); evidence.source_before = sourceBefore; evidence.source_after = sourceAfter;
      assert.deepEqual(sourceAfter, sourceBefore);
    });
  } finally {
    childProcess.spawn = originalSpawn; childProcess.spawnSync = originalSpawnSync;
  }
  const failed = checks.filter(item => item.status !== 'pass').length;
  console.log(JSON.stringify({ status: failed ? 'fail' : 'pass', total: checks.length, passed: checks.length - failed,
    platform: process.platform, native_execution_capability: ['win32','linux'].includes(process.platform) ? 'not_exercised_here' : 'unavailable',
    child_processes_executed: 0, process_spawn_attempts_blocked_by_harness: spawnAttempts, checks }, null, 2));
  process.exitCode = failed ? 1 : 0;
})().catch(error => {
  childProcess.spawn = originalSpawn; childProcess.spawnSync = originalSpawnSync;
  console.error(error.stack); process.exitCode = 1;
});
