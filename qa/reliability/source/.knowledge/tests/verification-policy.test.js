'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolvePolicy, createProgress, timerDelay } = require('../tools/lib/verification-policy');
const ms = value => BigInt(value) * 1000000n;

test('profiles separate work, silence and cleanup; explicit legacy work stays exact', () => {
  assert.equal(resolvePolicy(undefined, 5000).work_budget_ms, 5000);
  assert.equal(resolvePolicy(undefined, 5000).cleanup_budget_ms, 30000);
  assert.equal(resolvePolicy({ profile: 'suite' }, 5000).work_budget_ms, 1800000);
  const value = resolvePolicy({ profile: 'external', work_budget_ms: 800000, cleanup_budget_ms: 45000, no_progress_ms: 90000 });
  assert.equal(value.work_budget_ms, 800000);
  assert.equal(value.cleanup_budget_ms, 45000);
  assert.equal(value.no_progress_ms, 90000);
  assert.equal(value.automatic_work_budget_extension, false);
});

test('invalid policy and active caller data cannot execute hooks', () => {
  let called = 0;
  assert.throws(() => resolvePolicy({ get profile() { called++; return 'local'; } }));
  assert.equal(called, 0);
  for (const value of [{ profile: '__proto__' }, { work_budget_ms: NaN },
    { cleanup_budget_ms: 0 }, { no_progress_ms: -1 }, { extend_on_heartbeat: true },
    { work_budget_ms: null }, { cleanup_budget_ms: null }]) {
    assert.throws(() => resolvePolicy(value));
  }
});

test('large work budgets chunk timers without signed integer overflow', () => {
  assert.equal(resolvePolicy(undefined, 3000000000).work_budget_ms, 3000000000);
  assert.equal(timerDelay(3000000000), 2147483647);
  assert.equal(timerDelay(0.1), 1);
  assert.throws(() => timerDelay(Infinity));
});

test('heartbeat, repeated messages and skipped phases are not meaningful progress', () => {
  const state = createProgress(resolvePolicy({ no_progress_ms: 50 }), 0n);
  assert.equal(state.advance({ type: 'heartbeat', id: 1 }, ms(20)), false);
  assert.equal(state.advance({ type: 'phase', ordinal: 0, phase: 'receipt_commit' }, ms(30)), false);
  assert.equal(state.advance({ type: 'phase', ordinal: 0, phase: 'test_setup' }, ms(40)), true);
  assert.equal(state.advance({ type: 'phase', ordinal: 0, phase: 'test_setup', id: 99 }, ms(80)), false);
  assert.equal(state.isStalled(ms(89)), false);
  assert.equal(state.isStalled(ms(90)), true);
  assert.equal(state.snapshot(ms(90)).last_meaningful_progress_elapsed_ms, 40);
});

test('silent command uses the work budget; stdout is never a hang detector', () => {
  const state = createProgress(resolvePolicy({ no_progress_ms: 20 }), 0n);
  state.advance({ type: 'phase', ordinal: 0, phase: 'test_setup' }, ms(1));
  state.advance({ type: 'phase', ordinal: 0, phase: 'command' }, ms(2));
  assert.equal(state.isStalled(ms(100000)), false);
  assert.equal(state.snapshot(ms(100000)).progress_signal_available, false);
  assert.equal(state.advance({ type: 'stdout', text: 'progress' }, ms(100001)), false);
  assert.equal(state.snapshot(ms(100001)).last_meaningful_progress_elapsed_ms, 2);
});

test('only distinct committed KVE opens the next command ordinal', () => {
  const state = createProgress(resolvePolicy(), 0n);
  for (const [index, phase] of ['test_setup', 'command', 'finalization', 'receipt_commit'].entries()) {
    assert.equal(state.advance({ type: 'phase', ordinal: 0, phase }, ms(index + 1)), true);
  }
  assert.equal(state.advance({ type: 'phase', ordinal: 1, phase: 'test_setup' }, ms(5)), false);
  const event = { type: 'committed', ordinal: 0, execution_id: 'KVE-' + 'a'.repeat(64) };
  assert.equal(state.advance(event, ms(6)), true);
  assert.equal(state.advance(event, ms(7)), false);
  assert.equal(state.advance({ type: 'phase', ordinal: 1, phase: 'test_setup' }, ms(8)), true);
  assert.equal(state.snapshot(ms(8)).committed, 1);
  for (const [index, phase] of ['command', 'finalization', 'receipt_commit'].entries()) {
    assert.equal(state.advance({ type: 'phase', ordinal: 1, phase }, ms(index + 9)), true);
  }
  assert.equal(state.advance({ ...event, ordinal: 1 }, ms(12)), false);
  assert.equal(state.snapshot(ms(12)).committed, 1);
});
