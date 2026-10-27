'use strict';
// Portable cryptographic/protocol tests. No Windows kernel qualification is
// claimed by these synthetic descriptors or terminal input observations.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const p = require('../tools/lib/command-windows-protocol');
function fixture() {
  const keys = { primary: p.keyPair(), secondary: p.keyPair() }, id = crypto.randomBytes(32).toString('hex');
  const identity = pid => ({ pid, birth_filetime: String(133000000000000000n + BigInt(pid)) });
  const descriptor = { schema_version: 'knowledge-windows-command-job.v2', backend: 'windows_job_object', scope_id: id,
    job_name: `Local\\KnowledgeCommand-${id}`, native: { schema_version: 'knowledge-command-windows-native.v1', source_sha256: 'a'.repeat(64),
      binary_sha256: 'b'.repeat(64), architecture: 'x64', assignment: p.ASSIGNMENT, watchdog: 'native-pipe-process-handles.v1' },
    host: { machine_guid_sha256: 'c'.repeat(64), computer_name_sha256: 'd'.repeat(64), user_sid_sha256: 'e'.repeat(64), session_id: 1 },
    controller: identity(100), root: identity(101), primary: { identity: identity(102), public_key: keys.primary.publicKey },
    secondary: { identity: identity(103), controller: identity(104), public_key: keys.secondary.publicKey },
    receipt_store: { directory: `C:\\Users\\fixture\\AppData\\Local\\Temp\\knowledge-command-receipt-${id}`, dev: '1', ino: '2', scope_id: id } };
  const scope = p.commandScope(descriptor);
  const observed = { drained: true, stop_latched: true, kernel_query_ok: true, active_processes: 0, root_exited: true };
  return { scope, keys, observed, receipt: p.signTerminal(scope, 'primary', observed, keys.primary.privateKey) };
}
const clone = value => JSON.parse(JSON.stringify(value));
test('portable protocol: each exact holder can issue an idempotent terminal proof', () => {
  const f = fixture(); assert.equal(p.validateScope(f.scope), true); assert.equal(p.validateTerminal(f.receipt, f.scope), true);
  assert.equal(p.validateTerminal(clone(f.receipt), clone(f.scope)), true);
  assert.equal(p.validateTerminal(p.signTerminal(f.scope, 'secondary', f.observed, f.keys.secondary.privateKey), f.scope), true);
});
test('portable protocol: forged signatures and unrelated signing keys are rejected', () => {
  const f = fixture(), forged = clone(f.receipt); forged.signature = crypto.randomBytes(64).toString('base64');
  assert.equal(p.validateTerminal(forged, f.scope), false);
  assert.equal(p.validateTerminal(p.signTerminal(f.scope, 'primary', f.observed, p.keyPair().privateKey), f.scope), false);
});
test('portable protocol: a terminal receipt cannot be replayed into another generation', () => {
  const a = fixture(), b = fixture(); assert.equal(p.validateTerminal(a.receipt, b.scope), false);
  const wrong = clone(a.scope); wrong.descriptor.scope_id = b.scope.descriptor.scope_id;
  wrong.descriptor.job_name = b.scope.descriptor.job_name; wrong.descriptor.receipt_store = b.scope.descriptor.receipt_store;
  assert.equal(p.validateScope(wrong), true); assert.equal(p.validateTerminal(a.receipt, wrong), false);
});
test('portable protocol: a matching scope with the wrong exact root birth is rejected', () => {
  const f = fixture(), forged = clone(f.receipt); forged.body.root.birth_filetime = String(BigInt(forged.body.root.birth_filetime) + 1n);
  forged.signature = crypto.sign(null, Buffer.from(p.canonical(forged.body)), f.keys.primary.privateKey).toString('base64');
  assert.equal(p.validateTerminal(forged, f.scope), false);
});
test('portable protocol: every kernel closure predicate is mandatory', () => {
  for (const [key, value] of [['drained', false], ['stop_latched', false], ['kernel_query_ok', false], ['active_processes', 1], ['root_exited', false]]) {
    const f = fixture(); assert.throws(() => p.signTerminal(f.scope, 'primary', { ...f.observed, [key]: value }, f.keys.primary.privateKey), { code: 'command_windows_receipt_precondition' });
  }
});
test('portable protocol: JSON coercions and unknown result fields cannot become closure', () => {
  const f = fixture();
  for (const change of [b => { b.active_processes = '0'; }, b => { b.root_exited = 1; }, b => { b.admission_sealed = 'true'; },
    b => { b.extra = true; }, b => { delete b.kernel_membership_zero; }]) {
    const value = clone(f.receipt); change(value.body);
    value.signature = crypto.sign(null, Buffer.from(p.canonical(value.body)), f.keys.primary.privateKey).toString('base64');
    assert.equal(p.validateTerminal(value, f.scope), false);
  }
});
test('portable protocol: host, native pins and holder role are signed bindings', () => {
  const f = fixture();
  for (const change of [b => { b.host.session_id++; }, b => { b.native.source_sha256 = 'f'.repeat(64); }, b => { b.role = 'secondary'; }]) {
    const value = clone(f.receipt); change(value.body); assert.equal(p.validateTerminal(value, f.scope), false);
  }
});
test('portable protocol: receipt-directory aliases and shared holder identities are invalid', () => {
  const f = fixture();
  for (const change of [d => { d.receipt_store.directory += '\\..'; }, d => { d.receipt_store.directory += ':alternate'; },
    d => { d.secondary.identity = d.primary.identity; }, d => { d.secondary.public_key = d.primary.public_key; },
    d => { d.root.birth_filetime = '01'; }]) {
    const scope = clone(f.scope); change(scope.descriptor); assert.equal(p.validateScope(scope), false);
  }
});
test('portable protocol: wall-clock rollback cannot expire or renew immutable terminal truth', () => {
  const f = fixture(), original = Date.now;
  try { Date.now = () => -1000000; assert.equal(p.validateTerminal(f.receipt, f.scope), true); }
  finally { Date.now = original; }
});
test('portable protocol: a transient one-holder descriptor never authorizes durable lock recovery', () => {
  const f = fixture(), scope = clone(f.scope); scope.descriptor.secondary = null; scope.descriptor.receipt_store = null;
  assert.equal(p.validateScope(scope), true); assert.equal(p.validateTerminal(f.receipt, scope), false);
  assert.throws(() => p.signTerminal(scope, 'primary', f.observed, f.keys.primary.privateKey), { code: 'command_windows_receipt_precondition' });
});
