'use strict';

// The record writer is an actual descendant of the immutable scope stored in
// its first begin. Native namespace/exit observations and the control files
// are real. One case intentionally corrupts only the recorded binary pin to
// exercise an unavailable proof; no native result is mocked.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const source = process.env.KNOWLEDGE_INVOCATION_TEST_SOURCE || path.resolve(__dirname, '..');
const control = require(path.join(source, 'tools/lib/verification-control.js'));
const recovery = require(path.join(source, 'tools/lib/verification-recovery.js'));
const runner = require(path.join(source, 'tools/lib/command-runner.js'));
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const worker = path.join(__dirname, 'helpers/reliability-invocation-control-worker.cjs');

async function fixture(t, { intent = false, wrongPin = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-invocation-recovery-'));
  const stateRoot = path.join(root, '.knowledge'); fs.mkdirSync(stateRoot);
  const context = { stateRoot, projectKnowledgeRoot: stateRoot, targetRoot: root, systemRoot: source };
  const sessions = [];
  t.after(async () => {
    let complete = true;
    for (const session of sessions) {
      try { const proof = await session.finish(); complete = complete && proof.status === 'completed'; }
      catch { complete = false; }
    }
    if (complete) fs.rmSync(root, { recursive: true, force: true });
    else t.diagnostic(JSON.stringify({ fixture_retained_unconfirmed: root }));
  });
  async function admit({ intent = false, wrongPin = false } = {}) {
    const session = await runner.createCommandSession({ budgets: { setupMs: 30000, workMs: 60000, cleanupMs: 5000, progressMs: 0 } });
    sessions.push(session);
    const scope = JSON.parse(JSON.stringify(session.scope));
    if (wrongPin) scope.descriptor.helper.binary_sha256 = 'f'.repeat(64);
    const invocation = { schema_version: 'knowledge-verification-invocation.v1',
      nonce_sha256: crypto.randomBytes(32).toString('hex'), scope_sha256: digest(scope), scope };
    const result = await session.run({ executable: process.execPath,
      args: [worker, source, JSON.stringify({ context, invocation, intent })], cwd: root });
    assert.equal(result.status, 0, JSON.stringify({ error: result.error, stderr: result.stderr, cleanup: result.cleanup }));
    assert.equal(result.cleanup.status, 'completed');
    const created = JSON.parse(result.stdout);
    assert(created.creator_namespace_pid > 0);
    return { session, invocation, attempt: created.attempt,
      selector: { invocation_nonce_sha256: invocation.nonce_sha256, invocation_scope_sha256: invocation.scope_sha256 } };
  }
  return { root, context, admit, ...await admit({ intent, wrongPin }) };
}

test('a live invocation cannot be reclaimed before any inner spawn intent', { skip: process.platform !== 'linux', timeout: 45000 }, async t => {
  const f = await fixture(t);
  assert.deepEqual(f.attempt.processes, []);
  const returned = control.recoverAttempt(f.context, { attempt_id: f.attempt.attempt_id, generation: f.attempt.generation });
  t.diagnostic(JSON.stringify({ observation: returned.status, reason: returned.reason, actual_scope_backend: f.session.scope.backend }));
  assert.equal(returned.status, 'requires_native_recovery');
  assert.equal(returned.reason, 'verification_invocation_scope_active');
  const current = control.readStatus(f.context).attempt;
  assert.equal(current.claimed, true);
  // Public control views deliberately use inert null-prototype objects. The
  // immutable wire bytes, including every binding field, must be identical.
  assert.equal(JSON.stringify(current.invocation), JSON.stringify(f.invocation));
});

test('actual outer closure recovers an unknown inner spawn without inventing an exit', { skip: process.platform !== 'linux', timeout: 45000 }, async t => {
  const f = await fixture(t, { intent: true });
  assert.equal(f.attempt.processes.length, 1); assert.equal(f.attempt.processes[0].pid, null);
  control.requestCancel(f.context, { attempt_id: f.attempt.attempt_id, generation: f.attempt.generation });
  assert.equal((await f.session.finish()).status, 'completed');
  const result = recovery.recoverAttempt(f.context, { attempt_id: f.attempt.attempt_id, generation: f.attempt.generation });
  t.diagnostic(JSON.stringify({ recovery: result.status, ack_released: result.ack_released,
    observation: result.attempt?.cleanup.invocation_transcript?.payload.native_return }));
  assert.equal(result.status, 'cancelled'); assert.equal(result.ack_released, false);
  const current = control.readStatus(f.context).attempt;
  assert.equal(current.claimed, false); assert.equal(current.terminal.ack_sha256, null);
  assert.equal(current.processes[0].pid, null); assert.equal(current.processes[0].exit_observed, false);
  assert.equal(current.cleanup.invocation_transcript.scope_sha256, f.invocation.scope_sha256);
  assert.equal(current.cleanup.invocation_transcript.payload.native_return.namespace_drained, true);
});

test('lost startup ACK selection binds nonce, scope and the current generation', { skip: process.platform !== 'linux', timeout: 45000 }, async t => {
  const f = await fixture(t);
  assert.equal((await f.session.finish()).status, 'completed');
  assert.throws(() => recovery.recoverAttempt(f.context, { ...f.selector, invocation_nonce_sha256: 'b'.repeat(64) }), { code: 'verification_attempt_mismatch' });
  assert.throws(() => recovery.recoverAttempt(f.context, { ...f.selector, invocation_scope_sha256: 'c'.repeat(64) }), { code: 'verification_attempt_mismatch' });
  const result = recovery.recoverAttempt(f.context, f.selector);
  assert.equal(result.status, 'failed'); assert.equal(result.ack_released, false);
  const next = await f.admit();
  assert.notEqual(next.attempt.generation, f.attempt.generation);
  assert.throws(() => recovery.recoverAttempt(f.context, f.selector), { code: 'verification_attempt_mismatch' });
  assert.throws(() => recovery.recoverAttempt(f.context, { ...next.selector, attempt_id: f.attempt.attempt_id, generation: f.attempt.generation }), { code: 'verification_attempt_mismatch' });
  assert.equal(control.readStatus(f.context).attempt.claimed, true);
});

test('unavailable scope proof and an expired original budget retain the claim', { skip: process.platform !== 'linux', timeout: 45000 }, async t => {
  const f = await fixture(t, { wrongPin: true });
  assert.equal((await f.session.finish()).status, 'completed');
  const selected = { attempt_id: f.attempt.attempt_id, generation: f.attempt.generation };
  assert.throws(() => recovery.recoverAttempt(f.context, { ...selected, deadline_ns: String(process.hrtime.bigint() - 1n) }), { code: 'verification_recovery_budget_exceeded' });
  assert.equal(control.readStatus(f.context).attempt.claimed, true);
  const result = recovery.recoverAttempt(f.context, selected);
  t.diagnostic(JSON.stringify({ deliberately_invalid_recorded_pin: true, result: result.status, reason: result.reason }));
  assert.equal(result.status, 'requires_native_recovery');
  assert.equal(result.reason, 'native_helper_pin_mismatch');
  assert.equal(control.readStatus(f.context).attempt.claimed, true);
});
