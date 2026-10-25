'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const cp = require('node:child_process');
const { withFixture } = require('./helpers/reliability-darwin-preparation-fixture');
const { prepareInputs } = require('../tools/lib/verification-darwin-preparation');
const available = cp.spawnSync(process.execPath, ['--version']).status === 0;
const options = { skip: !available ? 'Real local child process support is required' : false };
const config = { broker_path: '/protected/unexecuted-fixture' };
test('readonly setup result is accepted only after exact local child and streams close', options, t =>
  withFixture(t, 'success', async () => {
    const result = await prepareInputs(config, { limitMs: 5000 });
    assert.equal(result.helper.exit_observed, true);assert.equal(result.helper.streams_closed, true);
    assert.equal(result.helper.exit_code, 0);assert.equal(result.helper.readonly, true);
    assert.equal(result.helper.admission_possible, false);assert.ok(Object.isFrozen(result.pins));
  }));
test('a valid setup result with a live child cannot pass its original work budget', options, t =>
  withFixture(t, 'result-without-exit', async () => {
    await assert.rejects(prepareInputs(config, { limitMs: 500 }), error => {
      assert.equal(error.code, 'verification_darwin_setup_budget_exceeded');
      assert.equal(error.helper.exit_observed, true);assert.equal(error.helper.admission_possible, false);return true;
    });
  }));
test('cancel stops a real child while its event loop is held', options, t =>
  withFixture(t, 'hold', async ({ ready }) => {
    const controller = new AbortController();
    const result = prepareInputs(config, { limitMs: 10000, signal: controller.signal }).then(value => ({ value }), error => ({ error }));
    await ready;controller.abort();const observed = await result;
    assert.equal(observed.error?.code, 'verification_darwin_cancelled');
    assert.equal(observed.error.helper.exit_observed, true);assert.equal(observed.error.helper.streams_closed, true);
  }));
test('a late successful setup reply after cancellation never becomes admission', options, t =>
  withFixture(t, 'late-success', async ({ ready }) => {
    const controller = new AbortController();
    const result = prepareInputs(config, { limitMs: 5000, signal: controller.signal }).then(value => ({ value }), error => ({ error }));
    await ready;controller.abort();const observed = await result;
    assert.equal(observed.error?.code, 'verification_darwin_cancelled');assert.equal(observed.error.helper.exit_observed, true);
    assert.equal(observed.error.helper.exit_code, 0);
  }));
for (const mode of ['duplicate', 'wrong-nonce', 'oversized']) {
  test(`readonly setup rejects ${mode} IPC despite a success-shaped receipt`, options, t =>
    withFixture(t, mode, async () => {
      await assert.rejects(prepareInputs(config, { limitMs: 5000 }), error => {
        assert.equal(error.code, 'verification_darwin_preparer_protocol_invalid');assert.equal(error.helper.exit_observed, true);return true;
      });
    }));
}
test('late final child event cannot extend the original setup budget', options, t =>
  withFixture(t, 'success', async () => {
    await assert.rejects(prepareInputs(config, { limitMs: 200 }), error =>
      error.code === 'verification_darwin_setup_budget_exceeded' && error.helper.exit_observed === true);
  }, { onMessage() { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250); } }));
test('unobserved child death is reported as cleanup unconfirmed, then test controller reaps its own child', options, t =>
  withFixture(t, 'hold', async ({ ready }) => {
    const controller = new AbortController();
    const result = prepareInputs(config, { limitMs: 10000, signal: controller.signal }).then(value => ({ value }), error => ({ error }));
    await ready;controller.abort();const observed = await result;
    assert.equal(observed.error?.code, 'verification_darwin_preparer_cleanup_unconfirmed');
    assert.equal(observed.error.helper.exit_observed, false);assert.equal(observed.error.helper.admission_possible, false);
  }, { suppressKill: true }));
test('already cancelled setup creates no helper process', t => {
  let calls = 0;t.mock.method(cp, 'fork', () => { calls++;throw new Error('must not spawn'); });
  const controller = new AbortController();controller.abort();
  return assert.rejects(prepareInputs(config, { limitMs: 5000, signal: controller.signal }),
    { code: 'verification_darwin_cancelled' }).then(() => { assert.equal(calls, 0); });
});
