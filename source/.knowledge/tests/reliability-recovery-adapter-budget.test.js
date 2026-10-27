'use strict';

// Deterministic adapter boundary tests. Native observations are synthetic;
// these tests exercise deadline admission, not kernel process-tree closure.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const recovery = require('../tools/lib/verification-recovery');
const native = process.platform === 'linux'
  ? require('../tools/lib/verification-linux-namespace')
  : process.platform === 'win32' ? require('../tools/lib/verification-windows-recovery') : null;
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const budgetError = { code: 'verification_recovery_budget_exceeded' };

function fixture(t, overrides = {}) {
  let left = 750;
  const calls = [];
  const backend = process.platform === 'win32' ? 'windows_job_object' : 'linux_pid_namespace';
  const descriptor = { backend };
  const attempt = { attempt_id: 'VAT-' + 'a'.repeat(32), generation: 'b'.repeat(32),
    profile: { cleanup_budget_ms: 30000 }, recovery: { status: 'active' }, stop_reason: 'failure',
    containment: { backend, descriptor, descriptor_sha256: digest(descriptor), spawn_ids: [], cleanup_receipt: null },
    processes: [] };
  const proof = { status: 'completed', method: backend, active_processes: 0,
    keeper_exited: true, worker_exited: true, controller_exited: true,
    init_exit_observed: true, init_reaped: true, namespace_drained: true,
    descriptor_sha256: digest(descriptor), process_exits: [] };
  const state = { attempt, proof, calls, get left() { return left; }, set left(value) { left = value; } };
  for (const [name, fallback] of Object.entries({
    currentProcessIdentity: options => { calls.push(['identity', options]); return { pid: 1234 }; },
    verifyProcessExit: (identity, options) => { calls.push(['exit', options]); return { status: 'exited' }; },
    recoverContainer: (value, options) => { calls.push(['cleanup', options]); return proof; }
  })) t.mock.method(native, name, (...args) => overrides[name] ? overrides[name](state, ...args) : fallback(...args));
  state.create = () => recovery.createNativeRecovery(attempt, { remainingMs: () => left });
  return state;
}

test('all recovery observations consume the existing cleanup allowance', { skip: !native }, t => {
  const f = fixture(t);
  const adapter = f.create();
  assert(f.calls[0][1]?.timeoutMs > 0 && f.calls[0][1].timeoutMs <= 750);
  f.left = 420;
  assert.equal(adapter.verify_recoverer_exit({ pid: 5678 }).status, 'exited');
  assert(f.calls[1][1]?.timeoutMs > 0 && f.calls[1][1].timeoutMs <= 420);
  f.left = 210;
  assert.equal(adapter(f.attempt).status, 'completed');
  assert(f.calls[2][1].cleanup_timeout_ms > 0 && f.calls[2][1].cleanup_timeout_ms <= 210);
});

test('expired cleanup epoch prevents even recovery-owner observation', { skip: !native }, t => {
  const f = fixture(t); f.left = 0;
  assert.throws(f.create, budgetError);
  assert.deepEqual(f.calls, []);
});

test('a late recovery-owner identity cannot authorize a new recovery adapter', { skip: !native }, t => {
  const f = fixture(t, { currentProcessIdentity: state => { state.left = 0; return { pid: 1234 }; } });
  assert.throws(f.create, budgetError);
});

test('expiry after reservation prevents native cleanup side effects', { skip: !native }, t => {
  const f = fixture(t), adapter = f.create();
  f.left = 0;
  assert.throws(() => adapter(f.attempt), budgetError);
  assert.equal(f.calls.filter(row => row[0] === 'cleanup').length, 0);
});

test('late valid native closure is rejected at the recovery adapter boundary', { skip: !native }, t => {
  const f = fixture(t, { recoverContainer: state => { state.left = 0; return state.proof; } });
  const adapter = f.create();
  assert.throws(() => adapter(f.attempt), budgetError);
});

test('late former-recoverer exit cannot authorize reservation takeover', { skip: !native }, t => {
  const f = fixture(t, { verifyProcessExit: state => { state.left = 0; return { status: 'exited' }; } });
  const adapter = f.create();
  assert.throws(() => adapter.verify_recoverer_exit({ pid: 5678 }), budgetError);
});

test('unknown former-owner exit remains unconfirmed within the original allowance', { skip: !native }, t => {
  const f = fixture(t, { verifyProcessExit: () => ({ status: 'unconfirmed' }) });
  assert.deepEqual(f.create().verify_recoverer_exit({ pid: 5678 }), { status: 'unconfirmed' });
});

test('an outer budget cannot enlarge the configured cleanup interval', { skip: !native }, t => {
  const f = fixture(t); f.attempt.profile.cleanup_budget_ms = 800; f.left = 10000;
  const adapter = f.create();
  adapter(f.attempt);
  const cleanup = f.calls.find(row => row[0] === 'cleanup');
  assert(cleanup[1].cleanup_timeout_ms > 0 && cleanup[1].cleanup_timeout_ms <= 800);
});
