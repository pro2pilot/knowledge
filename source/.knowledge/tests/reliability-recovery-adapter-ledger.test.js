'use strict';

// Actual durable ledger and lock publication with synthetic native adapter
// observations. This proves quarantine/epoch behavior, not physical cleanup.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const control = require('../tools/lib/verification-control');
const recovery = require('../tools/lib/verification-recovery');
const native = process.platform === 'linux' ? require('../tools/lib/verification-linux-namespace') : null;
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const H = 'a'.repeat(64), birth = '2026-10-27T00:00:00.000Z';

function fixture(t, late) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-adapter-ledger-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const context = { stateRoot: root }, { owner } = control.beginAttempt(context, { request_sha256: H });
  const descriptor = { schema_version: 'knowledge-linux-pid-namespace.v1', backend: 'linux_pid_namespace',
    worker: { pid: 1234, start_ticks: '9001', os_creation_time: birth } };
  control.updateAttempt(context, owner, { type: 'spawn_intent', role: 'authority' });
  control.updateAttempt(context, owner, { type: 'spawn_observed', spawn_id: 1, pid: 1234,
    os_creation_time: birth, executable_sha256: H });
  control.updateAttempt(context, owner, { type: 'containment_bound', descriptor, spawn_ids: [1] });
  let left = 5000, calls = 0;
  t.mock.method(native, 'currentProcessIdentity', () => ({ pid: 4321 }));
  t.mock.method(native, 'verifyProcessExit', () => ({ status: 'unconfirmed' }));
  t.mock.method(native, 'recoverContainer', () => {
    calls++;
    if (late) left = 0;
    return { status: 'completed', method: 'linux_pid_namespace', active_processes: 0,
      keeper_exited: true, worker_exited: true, controller_exited: true,
      init_exit_observed: true, init_reaped: true, namespace_drained: true,
      descriptor_sha256: digest(descriptor), process_exits: [
        { pid: 1234, start_ticks: '9001', os_creation_time: birth, method: 'linux_pidfd_exit' }
      ] };
  });
  const adapter = recovery.createNativeRecovery(control.readStatus(context).attempt, { remainingMs: () => left });
  return { context, owner, adapter, id: { attempt_id: owner.attempt_id, generation: owner.generation },
    expire() { left = 0; }, get calls() { return calls; } };
}

test('late native recovery retains the durable claim and records unconfirmed cleanup', { skip: !native }, t => {
  const f = fixture(t, true);
  assert.throws(() => control.recoverAttempt(f.context, f.id, f.adapter), { code: 'verification_recovery_budget_exceeded' });
  const attempt = control.readStatus(f.context).attempt;
  assert.equal(f.calls, 1);
  assert.equal(attempt.claimed, true);
  assert.equal(attempt.phase, 'cleanup_unconfirmed');
  assert.equal(attempt.cleanup.status, 'unconfirmed');
  assert.equal(attempt.recovery.reason_code, 'verification_recovery_budget_exceeded');
  assert.equal(attempt.terminal, null);
  assert.throws(() => control.beginAttempt(f.context, { request_sha256: H }), { code: 'verification_recovery_required' });
});

test('timely recovery releases only the failed attempt and never produces a success ACK', { skip: !native }, t => {
  const f = fixture(t, false);
  const result = control.recoverAttempt(f.context, f.id, f.adapter);
  assert.equal(result.status, 'failed');
  assert.equal(result.ack_released, false);
  const attempt = control.readStatus(f.context).attempt;
  assert.equal(attempt.claimed, false);
  assert.equal(attempt.cleanup.status, 'confirmed');
  assert.equal(attempt.terminal.ack_sha256, null);
  assert.equal(attempt.cleanup.native_transcript.payload.native_return.namespace_drained, true);
});

test('deadline expiry during final ledger read keeps the exact recovery claim fenced', { skip: !native }, t => {
  const f = fixture(t, false);
  const active = path.join(f.context.stateRoot, 'maintenance/verification-control/active.json');
  const original = fs.readSync;
  let boundary = 0;
  t.mock.method(fs, 'readSync', function(fd, ...args) {
    const result = original.call(fs, fd, ...args);
    if (f.calls === 1 && boundary === 0 && fs.fstatSync(fd, { bigint: true }).ino === fs.statSync(active, { bigint: true }).ino) {
      boundary++;
      f.expire();
    }
    return result;
  });
  assert.throws(() => control.recoverAttempt(f.context, f.id, f.adapter), { code: 'verification_recovery_budget_exceeded' });
  assert.equal(boundary, 1, 'the fault must occur after native proof at the actual ledger read');
  const attempt = control.readStatus(f.context).attempt;
  assert.equal(attempt.claimed, true);
  assert.equal(attempt.phase, 'cleanup_unconfirmed');
  assert.equal(attempt.recovery.reason_code, 'verification_recovery_budget_exceeded');
  assert.equal(attempt.terminal, null);
  assert.throws(() => control.beginAttempt(f.context, { request_sha256: H }), { code: 'verification_recovery_required' });
});

test('a late durable ledger write cannot return a timely recovery result or success ACK', { skip: !native }, t => {
  const f = fixture(t, false);
  const active = path.join(f.context.stateRoot, 'maintenance/verification-control/active.json');
  const original = fs.renameSync;
  let boundary = 0;
  t.mock.method(fs, 'renameSync', function(from, to, ...args) {
    const result = original.call(fs, from, to, ...args);
    if (f.calls === 1 && boundary === 0 && path.resolve(to) === active) {
      boundary++;
      f.expire();
    }
    return result;
  });
  assert.throws(() => control.recoverAttempt(f.context, f.id, f.adapter), { code: 'verification_recovery_budget_exceeded' });
  assert.equal(boundary, 1, 'the fault must occur at the actual terminal rename');
  const attempt = control.readStatus(f.context).attempt;
  // The exact native closure was already proven and its failed terminal row
  // became durable. Do not rewrite it to pretend the filesystem write vanished.
  assert.equal(attempt.claimed, false);
  assert.equal(attempt.cleanup.status, 'confirmed');
  assert.equal(attempt.terminal.outcome, 'failed');
  assert.equal(attempt.terminal.ack_sha256, null);
});
