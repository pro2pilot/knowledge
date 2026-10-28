'use strict';
// Synthetic reader/control fixtures. These verify rejection and signing
// contracts; they are not physical Linux service or cgroup qualification.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const finalization = require('../tools/lib/verification-finalization');
const linux = require('../tools/lib/verification-linux-service-finalization');
const bridge = require('../tools/lib/verification-linux-service-control');
const execution = require('../tools/lib/verification-execution');
const control = require('../tools/lib/verification-control');
const H = 'a'.repeat(64), REQUEST = 'b'.repeat(64), NONCE = 'c'.repeat(64);
const clone = value => JSON.parse(JSON.stringify(value));
const refused = fn => assert.throws(fn, { code: 'verification_finalization_required' });
function terminalRaw(value) {
  const unsigned = { ...value }; delete unsigned.proof_sha256;
  value.proof_sha256 = linux.hash(JSON.stringify(unsigned));
  return JSON.stringify(value);
}
function model(members = 1) {
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const batch = 'KVB-' + crypto.randomBytes(16).toString('hex');
  const source = [{ path: 'probe.js', sha256: H }];
  const capability = { schema_version: linux.NATIVE_SCHEMA, event: 'capability', status: 'ready',
    installation_id: '1'.repeat(32), host_id: '2'.repeat(32), boot_id: '3'.repeat(32), daemon_epoch: '4'.repeat(64),
    source_sha256: H, runtime_sha256: H, native_source_sha256: H, trusted_runtime_manifest_sha256: H, trusted_source_manifest_sha256: H,
    node_sha256: H, broker_binary_sha256: H, client_pid: 42, controller_pid: 41, controller_uid: 1000,
    controller_birth_ticks: '1234', busy: false };
  const opened = { schema_version: linux.NATIVE_SCHEMA, event: 'opened', status: 'starting', nonce: NONCE,
    allocation_sequence: 1, authority_uid: 70000, worker_uid: 70001, keeper_pid: 50, init_pid: 51,
    work_deadline_ns: '1000000000', cleanup_budget_ms: 100 };
  const records = Array.from({ length: members }, (_, index) => {
    const record = { schema_version: 'knowledge-verification-execution.v2', task_id: 'synthetic-task', session_id: 'synthetic-session',
      command_argv: ['node', 'probe.js'], command: 'node probe.js', cwd: '.', status: 'pass', exit_code: 0, signal: null,
      timed_out: false, duration_ms: 1, executed_at: '2026-10-28T00:00:00.000Z', executed_by: 'synthetic-reader-fixture',
      runtime_binding: 'process_exec_path', runtime_sha256: H, environment_profile: 'sanitized_node',
      stdout_sha256: linux.hash(''), stderr_sha256: linux.hash(''), stdout_bytes: 0, stderr_bytes: 0,
      source_snapshot_before: source, source_snapshot: source, batch_id: batch, batch_ordinal: index,
      batch_public_key: publicKey, batch_request_sha256: REQUEST };
    record.content_sha256 = execution.executionDigest(record); record.execution_id = 'KVE-' + record.content_sha256;
    assert.equal(execution.validateExecutionRecord(record).ok, true);
    return record;
  });
  const authority = { schema_version: linux.AUTHORITY_SCHEMA, nonce: NONCE, batch_id: batch, request_sha256: REQUEST,
    public_key: publicKey, authority_uid: 70000, worker_uid: 70001, manifest_sha256: H, directories_sha256: H,
    runtime_sha256: H, result: records.map(record => ({ record,
      relative_path: 'maintenance/verification_executions/' + record.content_sha256 + '.json', idempotent: false })),
    commands: records.map((record, index) => ({ ordinal: index + 1, script: 'probe.js', mode: 'script', args: [], cwd: '.',
      deadline_ns: '950000000', status: 0, signal: null, stdout_bytes: 0, stderr_bytes: 0,
      stdout_sha256: record.stdout_sha256, stderr_sha256: record.stderr_sha256 })) };
  const authority_raw = JSON.stringify(authority);
  const terminal = { ...opened, event: 'terminal', status: 'completed',
    ...Object.fromEntries(['installation_id', 'host_id', 'boot_id', 'daemon_epoch', 'native_source_sha256',
      'trusted_runtime_manifest_sha256', 'trusted_source_manifest_sha256', 'node_sha256', 'broker_binary_sha256'].map(key => [key, capability[key]])),
    authority_namespace_pid: 3, authority_pid: 52, authority_birth_ticks: '1235', authority_pidfd_exit_observed: true,
    cleanup_started_ns: '900000000', cleanup_deadline_ns: '1000000000', observed_ns: '920000000',
    importer_drained: true, source_readonly: true, authority_readback: true, manifest_sha256: H, directories_sha256: H,
    files: 1, directories: 0, source_bytes: 42, commands: members, commands_drained: members,
    authority_exited: true, authority_status: 0, init_exit_observed: true, init_reaped: true, keeper_exited: true,
    output_eof: true, cgroup_empty: true, cgroup_scope: 'private_authority_and_workers', journal_closed: true,
    cleanup_confirmed: true, result_bytes: Buffer.byteLength(authority_raw), result_sha256: linux.hash(authority_raw) };
  const raw = terminalRaw(terminal);
  const descriptor = bridge.descriptor({ capability, opened });
  const teardown = bridge.normalProof({ descriptor, terminalReply: terminal, terminalRaw: raw, capability });
  const record = { schema_version: linux.SCHEMA, backend: linux.METHOD, batch_id: batch, public_key: publicKey,
    request_sha256: REQUEST, task_id: 'synthetic-task', session_id: 'synthetic-session', runtime_sha256: H,
    status: 'commands_and_teardown_observed', timeout_ms: 100, work_elapsed_ms: 90, cleanup_budget_ms: 100,
    observed_elapsed_ms: 120, teardown, implementation: linux.IMPLEMENTATION_PATHS.map(name => ({ path: name, sha256: H })),
    executions: records.map(record => ({ execution_id: record.execution_id, physical_sha256: linux.hash(JSON.stringify(record, null, 2) + '\n') })),
    linux: { capability, terminal_reply: terminal, terminal_raw: raw, authority_raw,
      plan_summary: { manifest_sha256: H, directories_sha256: H, physical_binding_sha256: H,
        files: 1, directories: 0, total_bytes: 42, no_writeback: true }, source_snapshot: source } };
  return { keys, records, capability, opened, authority, terminal, descriptor, record };
}
function temp(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'linux-service-reader-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); return root;
}
async function persist(t, fixture) {
  const root = temp(t), directory = path.join(root, 'maintenance/verification_executions'); fs.mkdirSync(directory, { recursive: true });
  for (const record of fixture.records) fs.writeFileSync(path.join(directory, record.content_sha256 + '.json'), JSON.stringify(record, null, 2) + '\n');
  const reference = await finalization.persistFinalization(root, fixture.record);
  const ack = finalization.acceptFinalization(reference, 100, 130, fixture.keys.privateKey);
  return { root, ack, read: ids => finalization.requireFinalizedExecutions(root, ids || fixture.records.map(x => x.execution_id), [ack]) };
}
function resignTerminal(fixture, change) {
  change(fixture.record.linux.terminal_reply);
  fixture.record.linux.terminal_raw = terminalRaw(fixture.record.linux.terminal_reply);
  fixture.record.teardown.native_terminal_sha256 = fixture.record.linux.terminal_reply.proof_sha256;
}
test('Linux service signed KVE/KVF/ACK reader accepts a bound complete batch and verifies every sibling', async t => {
  const fixture = model(2); assert.equal(linux.validate(fixture.record).authority.result.length, 2);
  const saved = await persist(t, fixture);
  assert.equal(saved.ack.schema_version, linux.ACK_SCHEMA);
  assert.equal(saved.read([fixture.records[0].execution_id]).execution_records.length, 2);
  fs.appendFileSync(path.join(saved.root, 'maintenance/verification_executions', fixture.records[1].content_sha256 + '.json'), '\n');
  refused(() => saved.read([fixture.records[0].execution_id]));
});
test('Linux service reader rejects coherently rehashed native, stream, source and batch substitutions', async t => {
  const cases = [
    ['incomplete namespace', f => resignTerminal(f, x => { x.init_reaped = false; })],
    ['unclosed UID journal', f => resignTerminal(f, x => { x.journal_closed = false; })],
    ['readback missing', f => resignTerminal(f, x => { x.authority_readback = false; })],
    ['late native observation', f => resignTerminal(f, x => { x.observed_ns = x.cleanup_deadline_ns; })],
    ['expanded cleanup endpoint', f => resignTerminal(f, x => { x.cleanup_deadline_ns = '1100000001'; })],
    ['different worker UID', f => resignTerminal(f, x => { x.worker_uid++; })],
    ['different daemon epoch', f => resignTerminal(f, x => { x.daemon_epoch = 'f'.repeat(64); })],
    ['missing exact A exit', f => resignTerminal(f, x => { x.authority_pidfd_exit_observed = false; })],
    ['incomplete command drain', f => resignTerminal(f, x => { x.commands_drained = 0; })],
    ['different A bytes', f => { f.record.linux.authority_raw += '\n'; }],
    ['duplicate terminal key', f => { f.record.linux.terminal_raw = f.record.linux.terminal_raw.replace('{', '{"status":"failed",'); }],
    ['different source snapshot', f => { f.record.linux.source_snapshot[0].sha256 = 'd'.repeat(64); }],
    ['different plan counts', f => { f.record.linux.plan_summary.files++; }],
    ['different Node provenance', f => { f.record.linux.capability.node_sha256 = 'e'.repeat(64); }],
    ['wrong native scope claim', f => resignTerminal(f, x => { x.cgroup_scope = 'all_storage_and_workers'; })],
    ['wrong KVF cleanup budget', f => { f.record.cleanup_budget_ms++; }],
    ['stream mismatch with rehashed A', f => {
      const a = JSON.parse(f.record.linux.authority_raw); a.commands[0].stdout_bytes++;
      f.record.linux.authority_raw = JSON.stringify(a);
      resignTerminal(f, x => { x.result_bytes = Buffer.byteLength(f.record.linux.authority_raw); x.result_sha256 = linux.hash(f.record.linux.authority_raw); });
    }]
  ];
  for (const [name, mutate] of cases) await t.test(name, async t => {
    const fixture = model(); mutate(fixture); refused(() => linux.validate(fixture.record));
    const saved = await persist(t, fixture); refused(() => saved.read());
  });
});
test('Linux service control binds the exact allocation without fabricated host process rows', t => {
  const fixture = model(), root = temp(t), context = { stateRoot: root };
  control.withStorageLease(context, () => {
    const opened = control.beginAttempt(context, { request_sha256: REQUEST,
      storage_protocol: bridge.STORAGE_PROTOCOL, startup_nonce_sha256: linux.hash(NONCE),
      profile: { work_budget_ms: 100, cleanup_budget_ms: 100, no_progress_ms: 0 } });
    const bound = control.updateAttempt(context, opened.owner, { type: 'containment_bound', descriptor: fixture.descriptor, spawn_ids: [] });
    assert.equal(bridge.validateAttemptBinding(bound.attempt), true); assert.deepEqual(bound.attempt.processes, []);
    assert.throws(() => control.updateAttempt(context, opened.owner, { type: 'spawn_intent', role: 'authority' }), { code: 'verification_spawn_invalid' });
    control.updateAttempt(context, opened.owner, { type: 'cleanup_started' });
    const proof = control.bindCleanupProof(opened.owner, fixture.record.teardown);
    const finished = control.commitFinish(context, opened.owner, { outcome: 'passed', ack_sha256: H, cleanup_proof: proof });
    assert.equal(finished.status, 'passed'); assert.deepEqual(finished.attempt.processes, []);
  });
});
test('Linux service cleanup-only terminals release a failed claim but never a successful ACK', t => {
  const fixture = model(), root = temp(t), context = { stateRoot: root };
  // A may never have been admitted. Native namespace closure must not invent
  // an A exit; it may still clear a failed claim without authorizing any ACK.
  Object.assign(fixture.terminal, { status: 'cancelled', authority_status: -1,
    authority_pid: 0, authority_namespace_pid: 0, authority_birth_ticks: '0',
    authority_pidfd_exit_observed: false, authority_exited: false,
    importer_drained: false, source_readonly: false, authority_readback: false,
    commands: 0, commands_drained: 0, result_bytes: 0, result_sha256: linux.hash('') });
  const proof = bridge.normalProof({ descriptor: fixture.descriptor, capability: fixture.capability,
    terminalReply: fixture.terminal, terminalRaw: terminalRaw(fixture.terminal) });
  assert.equal(proof.cleanup_only, true);
  control.withStorageLease(context, () => {
    const opened = control.beginAttempt(context, { request_sha256: REQUEST,
      storage_protocol: bridge.STORAGE_PROTOCOL, startup_nonce_sha256: linux.hash(NONCE),
      profile: { work_budget_ms: 100, cleanup_budget_ms: 100, no_progress_ms: 0 } });
    control.updateAttempt(context, opened.owner, { type: 'containment_bound', descriptor: fixture.descriptor, spawn_ids: [] });
    control.updateAttempt(context, opened.owner, { type: 'cleanup_started' });
    const bound = control.bindCleanupProof(opened.owner, proof);
    assert.throws(() => control.commitFinish(context, opened.owner, { outcome: 'passed', ack_sha256: H, cleanup_proof: bound }), { code: 'verification_cleanup_unconfirmed' });
    assert.equal(control.commitFinish(context, opened.owner, { outcome: 'failed', cleanup_proof: bound }).ack_released, false);
  });
});
test('Linux service opened identity and lost custody cannot become no-process recovery', t => {
  const fixture = model();
  const wrong = clone(fixture.descriptor); wrong.opened.nonce = 'd'.repeat(64);
  assert.throws(() => bridge.normalProof({ descriptor: wrong, capability: fixture.capability,
    terminalReply: fixture.terminal, terminalRaw: fixture.record.linux.terminal_raw }));
  const root = temp(t), context = { stateRoot: root };
  control.withStorageLease(context, () => {
    const opened = control.beginAttempt(context, { request_sha256: REQUEST,
      storage_protocol: bridge.STORAGE_PROTOCOL, startup_nonce_sha256: linux.hash(NONCE),
      profile: { work_budget_ms: 100, cleanup_budget_ms: 100, no_progress_ms: 0 } });
    control.updateAttempt(context, opened.owner, { type: 'containment_bound', descriptor: fixture.descriptor, spawn_ids: [] });
    const recovered = require('../tools/lib/verification-recovery').recoverAttempt(context, { attempt_id: opened.owner.attempt_id, generation: opened.owner.generation });
    assert.equal(recovered.status, 'requires_native_recovery'); assert.equal(control.readStatus(context).attempt.claimed, true);
  });
});
