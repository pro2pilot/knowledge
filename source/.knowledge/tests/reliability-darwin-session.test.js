'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const protocol = require('../tools/lib/verification-darwin-session-protocol');
const session = require('../tools/lib/verification-darwin-session');

function fixture() {
  const hex = n => String(n).repeat(64), epoch = hex(3), id = hex(4);
  const capability = { source_sha256: hex(1), binary_sha256: hex(2), stub_source_sha256: hex(5),
    stub_binary_sha256: hex(6), transport_header_sha256: hex(7), uid_history_header_sha256: hex(8),
    uid_history_source_sha256: hex(9), installation_id: hex('a'), account_policy_id: 'admin_reserved_interval_no_runtime_nss.v1',
    account_policy_sha256: hex('b'), host_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    boot_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', daemon_epoch: epoch,
    runtime_path: '/protected/node', runtime_sha256: hex('c') };
  const d = { ...capability, schema: 'knowledge-darwin-private-ruid-descriptor.v2', backend: 'darwin_private_ruid',
    broker_binary_sha256: capability.binary_sha256, mode: 'isolated_copy', attempt_id: id, boundary_id: id,
    attempt_nonce: hex('d'), task_ruid: 1000000000, task_gid: 1000000000, owner_uid: 501,
    stub_wire_version: 'KVS2', guardian_protocol: 'KVR2', capability_qualified: true, qualification_mode: false,
    allocation_seq: '1', allocation_sha256: hex('e'), workspace_path: '/protected/work/' + id,
    scratch_policy: 'private_uid_sibling.v1', scratch_path: '/protected/work/' + id + '.scratch',
    allowed_runtimes: { '/protected/node': capability.runtime_sha256 }, work_started_monotonic_ms: 100,
    work_budget_ms: 100000, work_deadline_ms: 100100, cleanup_budget_ms: 60000 };
  const prepare = { ok: true, attempt_id: id, descriptor: d, descriptor_sha256: protocol.digest(d),
    workspace_path: d.workspace_path, token: hex('f') };
  const binding = { attempt_id: id, descriptor: d, descriptor_sha256: prepare.descriptor_sha256 };
  const command = { argv: ['/protected/node', 'run.js'], env: {}, cwd: '.', timeout_ms: 90000 };
  const common = { attempt_id: id, descriptor_sha256: prepare.descriptor_sha256,
    daemon_epoch: epoch, writer_generation: 7, proof_current: true, capability_qualified: true };
  const run = { ...common, ok: true, schema: 'knowledge-darwin-command-result.v1', command_ordinal: 1,
    command_sha256: protocol.digest(command), guardian_protocol: 'KVR2', guardian_reaped: true, permit_observed: true,
    timed_out: false, stop_latched: false, admission_closed: false, exit_code: 0, signal: null };
  for (const key of ['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq',
    'allocation_sha256', 'host_id', 'boot_id']) run[key] = d[key];
  const proof = { ...common, schema: 'knowledge-darwin-private-ruid-proof.v1', uid_history_tuple_verified: true,
    terminal_cleanup: true, kernel_membership_zero: true, admission_closed: true, spawn_exclusion_acquired: true,
    spawn_intents_resolved: true, guardian_exit_confirmed: true, root_child_exit_confirmed: true,
    cleanup_started_monotonic_ms: 1000, cleanup_deadline_monotonic_ms: 61000, observed_monotonic_ms: 1100,
    native_cleanup_facts_confirmed: true, cleanup_confirmed: true, registered_authority_exited: true,
    cleanup_budget_exceeded: false, abort_latched: false, planned_terminal: true };
  for (const key of ['source_sha256', 'transport_header_sha256', 'installation_id', 'allocation_seq',
    'allocation_sha256', 'host_id', 'boot_id', 'account_policy_id', 'account_policy_sha256', 'task_ruid']) proof[key] = d[key];
  const reply = { ...common, ok: true, state: 'closed', cleanup_only: false,
    allocation_tuple_verified_current: true, registry_healthy: true, cleanup_budget_exceeded: false,
    abort_latched: false, planned_terminal: true, stop_reason: 'close_requested', proof, proof_sha256: protocol.digest(proof) };
  return { capability, prepare, binding, command, run, reply };
}
const clone = value => JSON.parse(JSON.stringify(value));

test('production descriptor predicates require qualified exact source and daemon epoch', () => {
  const f = fixture();const value = protocol.validateDescriptor(f.prepare, f.capability, f.prepare.descriptor.attempt_nonce);
  assert.ok(Object.isFrozen(value.descriptor.allowed_runtimes));
  const mutations = [d => { d.schema = 'knowledge-darwin-private-ruid-descriptor.v1'; },
    d => { d.daemon_epoch = '0'.repeat(64); }, d => { d.capability_qualified = false; },
    d => { d.qualification_mode = true; }, d => { d.allocation_seq = '2'; },
    d => { d.source_sha256 = '0'.repeat(64); }, d => { d.workspace_path = 'relative'; },
    d => { d.task_ruid = true; }, d => { d.work_deadline_ms++; }, d => { d.stub_wire_version = 'KVS1'; }];
  for (const mutate of mutations) {
    const altered = clone(f.prepare);mutate(altered.descriptor);altered.descriptor_sha256 = protocol.digest(altered.descriptor);
    assert.throws(() => protocol.validateDescriptor(altered, f.capability, f.prepare.descriptor.attempt_nonce),
      { code: 'verification_darwin_descriptor_invalid' });
  }
});
test('current command cannot be replayed across epoch, generation, command or permit', () => {
  const f = fixture();const validated = protocol.validateCommand(f.run, f.binding, f.capability, f.command, 1);
  assert.equal(Object.getPrototypeOf(validated), null);assert.equal(protocol.canonical(validated), protocol.canonical(f.run));
  for (const patch of [{ daemon_epoch: '0'.repeat(64) }, { proof_current: false }, { writer_generation: 0 },
    { guardian_reaped: false }, { permit_observed: false }, { command_ordinal: 2 }, { command_sha256: '0'.repeat(64) },
    { capability_qualified: false }, { exit_code: null, signal: null }]) {
    assert.throws(() => protocol.validateCommand({ ...f.run, ...patch }, f.binding, f.capability, f.command, 1),
      { code: 'verification_darwin_command_receipt_invalid' });
  }
});
test('a zero exit cannot hide native cancellation, timeout or closed admission', () => {
  const f = fixture();
  for (const field of ['timed_out', 'stop_latched', 'admission_closed']) {
    assert.throws(() => protocol.validateCommand({ ...f.run, [field]: true },
      f.binding, f.capability, f.command, 1),
      { code: 'verification_darwin_command_receipt_invalid' }, field + ' must revoke execution acceptance');
  }
});
test('terminal proof requires actual guardian, root-child and UID closure with a current epoch', () => {
  const f = fixture();const validated = protocol.validateProof(f.reply, f.binding, f.capability, true);
  assert.equal(Object.getPrototypeOf(validated), null);assert.equal(protocol.canonical(validated), protocol.canonical(f.reply.proof));
  for (const patch of [{ guardian_exit_confirmed: false }, { root_child_exit_confirmed: false },
    { kernel_membership_zero: false }, { spawn_intents_resolved: false }, { uid_history_tuple_verified: false },
    { abort_latched: true }, { planned_terminal: false }, { cleanup_budget_exceeded: true },
    { observed_monotonic_ms: 61000 }, { daemon_epoch: '0'.repeat(64) }, { writer_generation: 8 },
    { capability_qualified: false }, { proof_current: false }]) {
    const altered = clone(f.reply);Object.assign(altered.proof, patch);altered.proof_sha256 = protocol.digest(altered.proof);
    assert.throws(() => protocol.validateProof(altered, f.binding, f.capability, true), { code: 'verification_darwin_current_proof_invalid' });
  }
  for (const patch of [{ cleanup_only: true }, { proof_current: false }, { allocation_tuple_verified_current: false },
    { registry_healthy: false }, { observation_cached: true }, { abort_latched: true }, { proof_sha256: '0'.repeat(64) }]) {
    assert.throws(() => protocol.validateProof({ ...f.reply, ...patch }, f.binding, f.capability, true),
      { code: 'verification_darwin_current_proof_invalid' });
  }
});
test('a correctly hashed proof cannot predate its cleanup epoch', () => {
  const f = fixture();const altered = clone(f.reply);
  altered.proof.observed_monotonic_ms = altered.proof.cleanup_started_monotonic_ms - 1;
  altered.proof_sha256 = protocol.digest(altered.proof);
  assert.throws(() => protocol.validateProof(altered, f.binding, f.capability, true),
    { code: 'verification_darwin_current_proof_invalid' });
});

test('cancel during held readonly setup waits for real helper exit before reporting cancellation', async tc => {
  // Real process lifetime, modeled read/ACL implementation; no native macOS claim.
  const { withFixture } = require('./helpers/reliability-darwin-preparation-fixture');
  const originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { ...originalPlatform, value: 'darwin' });
  try {
    await withFixture(tc, 'hold', async ({ ready }) => {
      const abort = new AbortController();
      const observed = session.probeSession({ enabled: true, mode: 'isolated_copy',
        broker_path: '/protected/unexecuted-broker', broker_socket: '/private/tmp/unused.sock', copy: {} },
        { signal: abort.signal, setupBudgetMs: 10000 }).then(value => ({ value }), error => ({ error }));
      await ready;abort.abort();const result = await observed;
      assert.equal(result.error?.code, 'verification_darwin_cancelled');
      assert.equal(result.error.helper.exit_observed, true);assert.equal(result.error.helper.admission_possible, false);
    });
  } finally { Object.defineProperty(process, 'platform', originalPlatform); }
});

const hasChildren = (() => { try { return require('node:child_process').spawnSync(process.execPath, ['--version']).status === 0; } catch { return false; } })();
test('real local helper transport drains streams, fences late success and observes cancellation exit',
  { skip: process.platform === 'win32' || !hasChildren ? 'Executable fixture requires POSIX local child process support' : false }, async t => {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-session-rpc-'));
    const file = path.join(root, 'fake-native');
    fs.writeFileSync(file, `#!${process.execPath}
'use strict';const fs=require('node:fs');let text='';process.stdin.on('data',b=>text+=b);process.stdin.on('end',()=>{const q=JSON.parse(text);const run=process.argv.includes('--run');const fd=run?3:1;
const done=()=>{if(run){fs.writeSync(1,'{"ok":false,"spoof":true}');fs.writeSync(2,'stderr-data');}fs.writeSync(fd,JSON.stringify({ok:true,value:q.op})+'\\n');process.exit(0);};
if(q.op==='late'){process.on('SIGTERM',()=>{});fs.writeSync(2,'fixture-ready\\n');setTimeout(done,100);}
else if(q.op==='hang'){process.on('SIGTERM',()=>{});fs.writeSync(2,'fixture-ready\\n');setInterval(()=>{},1000);}
else if(q.op==='oversized'){fs.writeSync(fd,'x'.repeat(65537));setInterval(()=>{},1000);}
else if(q.op==='consumer'){fs.writeSync(1,'stream');setInterval(()=>{},1000);}
else done();});
`, { mode: 0o755 });
    // The executable fixture ignores this name. Keep the real Darwin AF_UNIX
    // 104-byte validation even when the local evidence directory is long.
    const config = { enabled: true, mode: 'isolated_copy', broker_path: file, broker_socket: '/private/tmp/knowledge-fixture-unused.sock', copy: {} };
    try {
      await t.test('data stdout cannot impersonate typed fd3 result', async () => {
        let stdout = '', stderr = '';
        const value = await session.rpc(config, { op: 'normal' }, { run: true, limitMs: 10000,
          onStdout: bytes => { stdout += bytes; }, onStderr: bytes => { stderr += bytes; } });
        assert.equal(value.reply.ok, true);assert.match(stdout, /spoof/);assert.equal(stderr, 'stderr-data');
        assert.equal(value.helper.stdout_sha256, protocol.sha(stdout));assert.equal(value.helper.stderr_sha256, protocol.sha(stderr));
        assert.equal(value.helper.exit_observed, true);
      });
      await t.test('positive bytes arriving after cancel do not resurrect result', async () => {
        const signal = new AbortController();const promise = session.rpc(config, { op: 'late' }, { signal: signal.signal, limitMs: 10000,
          onStderr(bytes) { if (bytes.toString().includes('fixture-ready')) signal.abort(); } });
        await assert.rejects(promise, error => error.code === 'verification_darwin_cancelled' && error.helper.exit_observed === true);
      });
      await t.test('SIGTERM-resistant helper is killed and real exit is observed', async () => {
        const signal = new AbortController();const promise = session.rpc(config, { op: 'hang' }, { signal: signal.signal, limitMs: 10000,
          onStderr(bytes) { if (bytes.toString().includes('fixture-ready')) signal.abort(); } });
        await assert.rejects(promise, error => error.code === 'verification_darwin_cancelled' && error.helper.exit_observed === true && error.helper.signal === 'SIGKILL');
      });
      await t.test('oversized control fails closed with cleanup', async () => {
        await assert.rejects(session.rpc(config, { op: 'oversized' }, { limitMs: 10000 }),
          error => error.code === 'verification_darwin_reply_oversized' && error.helper.exit_observed === true);
      });
      await t.test('output consumer exception cannot strand helper', async () => {
        await assert.rejects(session.rpc(config, { op: 'consumer' }, { run: true, limitMs: 10000,
          onStdout() { throw new Error('consumer'); } }), error => error.code === 'verification_darwin_output_consumer_failed' && error.helper.exit_observed === true);
      });
      await t.test('actual helper exit after a logical deadline is rejected even before the timer callback', async tc => {
        // The child and its observed exit are real. Only the parent monotonic
        // clock is advanced to model a suspended monitor resuming in an I/O
        // callback before its expired timer has been dispatched.
        const original = process.hrtime.bigint;let offset = 0n;
        tc.mock.method(process.hrtime, 'bigint', () => original() + offset);
        await assert.rejects(session.rpc(config, { op: 'normal' }, { run: true, limitMs: 10000,
          onStderr() { offset = 11000000000n; } }), error =>
          error.code === 'verification_darwin_helper_budget_exceeded' && error.helper.exit_observed === true &&
          error.helper.elapsed_ms >= 10000);
      });
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
