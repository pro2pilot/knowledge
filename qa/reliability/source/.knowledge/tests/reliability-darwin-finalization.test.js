'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const final = require('../tools/lib/verification-darwin-finalization');
const wire = require('../tools/lib/verification-darwin-session-protocol');
const { model } = require('./fixtures/darwin-finality-model');
const clone = value => JSON.parse(JSON.stringify(value));
const rejects = action => assert.throws(action, { code: 'verification_finalization_required' });
function resignReadback(row) { const { ok, readback_sha256, ...body } = row;row.readback_sha256 = wire.digest(body); }

test('Darwin finality protocol model accepts a complete internally bound receipt', () => {
  const f = model();assert.doesNotThrow(() => final.validate(f.record));
  assert.doesNotThrow(() => final.validateExecution(f.record, f.execution, 0));
});
test('same native zero exit cannot accept a different command, cwd, runtime or output', () => {
  for (const patch of [{ command_argv: ['node', 'other.js'] }, { cwd: 'nested' },
    { runtime_sha256: '0'.repeat(64) }, { stdout_bytes: 1 }, { stderr_sha256: 'f'.repeat(64) },
    { environment_profile: 'inherited_command' }, { status: 'fail' }, { timed_out: true }]) {
    const f = model();rejects(() => final.validateExecution(f.record, { ...f.execution, ...patch }, 0));
  }
});
test('changed source snapshot or an incomplete sibling set cannot reuse native completion', () => {
  for (const key of ['source_snapshot', 'source_snapshot_before']) {
    const f = model();const bad = clone(f.execution);bad[key][0].sha256 = '0'.repeat(64);
    rejects(() => final.validateExecution(f.record, bad, 0));
  }
  const f = model();f.record.executions.push({ execution_id: 'KVE-' + '9'.repeat(64) });rejects(() => final.validate(f.record));
});
test('copy readbacks must refer to one physical workspace and all three ordered phases', () => {
  const changed = model();changed.record.darwin.readbacks[1].workspace_identity.inode = '3';
  resignReadback(changed.record.darwin.readbacks[1]);rejects(() => final.validate(changed.record));
  const duplicate = model();duplicate.record.darwin.readbacks[2] = clone(duplicate.record.darwin.readbacks[1]);
  rejects(() => final.validate(duplicate.record));
  const missing = model();missing.record.darwin.readbacks.pop();rejects(() => final.validate(missing.record));
});
test('native drain and terminal receipts are one chain, including exact authority exit', () => {
  for (const patch of [r => { r.darwin.authority_exit.pid++; }, r => { r.darwin.authority_exit.exit_observed = false; },
    r => { r.darwin.authority_exit.signal = null; }, r => { r.darwin.terminal_reply.proof.command_drain_sha256 = '0'.repeat(64);
      r.darwin.terminal_reply.proof_sha256 = wire.digest(r.darwin.terminal_reply.proof); },
    r => { r.teardown.native_terminal_sha256 = '0'.repeat(64); }]) {
    const f = model();patch(f.record);rejects(() => final.validate(f.record));
  }
});
test('old epochs, cleanup-only observations and incomplete native scope cannot authorize ACK', () => {
  for (const patch of [r => { r.darwin.terminal_reply.cleanup_only = true; },
    r => { r.darwin.terminal_reply.proof_current = false; }, r => { r.darwin.capability.daemon_epoch = '0'.repeat(64); },
    r => { r.darwin.scope.binding.descriptor_sha256 = '0'.repeat(64); },
    r => { r.darwin.terminal_reply.proof.kernel_membership_zero = false;
      r.darwin.terminal_reply.proof_sha256 = wire.digest(r.darwin.terminal_reply.proof); }]) {
    const f = model();patch(f.record);rejects(() => final.validate(f.record));
  }
});
test('late or unobserved output helpers cannot supply accepted stream hashes', () => {
  for (const patch of [{ exit_observed: false }, { exit_code: 1 }, { signal: 'SIGKILL' }]) {
    const f = model();Object.assign(f.record.darwin.streams[0].helper, patch);rejects(() => final.validate(f.record));
  }
});
test('large copy manifests are summarized by bounds and hashes, not embedded file arrays', () => {
  const f = model();f.plan.files = Array.from({ length: 20000 }, (_, n) => ({ path: 'f' + n, sha256: 'a'.repeat(64) }));
  const summary = final.planSummary(f.plan);
  assert.equal(summary.files, 20000);assert.ok(Buffer.byteLength(JSON.stringify(summary)) < 400);
  f.record.darwin.plan_summary.files = 50001;rejects(() => final.validate(f.record));
});
test('readback order and cleanup deadline are enforced in the native clock domain', () => {
  for (const [index, timestamp] of [[0, 99], [0, 1200], [1, 1000], [1, 1350], [2, 1250], [2, 61000]]) {
    const f = model();f.record.darwin.readbacks[index].observed_monotonic_ms = timestamp;
    resignReadback(f.record.darwin.readbacks[index]);rejects(() => final.validate(f.record));
  }
});
