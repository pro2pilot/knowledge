'use strict';
// Real bounded filesystem reads and owner inode bindings, modeled macOS
// descriptor facts. This suite performs no native observation or recovery.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const { readTeamFlowScope } = require('../tools/lib/macos-lock-preflight');
const { LOCK_POLICY, LOCKS } = require('../tools/lib/lock-policy');
const ownerSchema = require('../tools/lib/lock-owner-schema');
const wire = require('../tools/lib/verification-darwin-session-protocol');
const { captureTempDirIdentity, removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex'), hex = x => x.repeat(64);
function scopeFixture() {
  const d = { schema: 'knowledge-macos-writable-descriptor.v1', backend: 'darwin_private_ruid',
    mode: 'admin_writable_workspace.v1', stub_wire_version: 'KVS3', guardian_protocol: 'KVR2',
    capability_qualified: true, qualification_mode: false, source_sha256: hex('1'), stub_source_sha256: hex('2'),
    stub_binary_sha256: hex('3'), transport_header_sha256: hex('4'), uid_history_header_sha256: hex('5'),
    uid_history_source_sha256: hex('6'), broker_binary_sha256: hex('7'), daemon_epoch: hex('8'),
    installation_id: hex('9'), allocation_sha256: hex('a'), account_policy_sha256: hex('b'),
    workspace_id: hex('c'), workspace_capability_sha256: hex('d'), attempt_id: hex('e'), attempt_nonce: hex('f'),
    boundary_id: hex('e'), host_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', boot_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    account_policy_id: 'admin_reserved_interval_no_runtime_nss.v1', owner_uid: 501, task_ruid: 1000000000,
    task_gid: 2000000000, allocation_seq: '1', workspace_path: '/protected/work/' + hex('e'),
    scratch_path: '/protected/work/' + hex('e') + '.scratch', scratch_policy: 'admin_workspace_acl_sibling.v1',
    writable_root: '/project', protected_worker_root: '/protected/package',
    writable_identity: { device: '1', inode: '2', owner_uid: 501, group_gid: 2000000000, mode: 0o770 },
    work_started_monotonic_ms: 1000, work_budget_ms: 10000, work_deadline_ms: 11000, cleanup_budget_ms: 5000,
    allowed_runtimes: { '/protected/node': hex('0') } };
  return { schema_version: 'knowledge-command-scope.v1', backend: 'macos_uid_guardian',
    binding: { attempt_id: d.attempt_id, descriptor_sha256: wire.digest(d), descriptor: d },
    broker_path: '/protected/broker', broker_socket: '/protected/socket' };
}
function fixture(t, present = true) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-preflight-')), identity = captureTempDirIdentity(root);
  t.after(() => removeTempDirStrict(root, { expectedIdentity: identity }));
  const context = { mode: 'team', teamRoot: root, repoId: 'sample' };
  const directory = path.join(root, 'repos', 'sample', 'locks', 'v' + LOCK_POLICY.layout_version, 'team-flow.lock');
  const ownerPath = path.join(directory, 'owner.json'), scopePath = path.join(directory, 'execution-scope.json');
  const scope = scopeFixture();
  const f = { root, context, directory, ownerPath, scopePath, scope };
  if (!present) return f;
  fs.mkdirSync(directory, { recursive: true });fs.writeFileSync(ownerPath, '');
  const own = fs.lstatSync(ownerPath, { bigint: true }), dir = fs.lstatSync(directory, { bigint: true });
  const scopeBytes = JSON.stringify(scope, null, 2) + '\n';fs.writeFileSync(scopePath, scopeBytes);
  f.owner = { schema_version: 'knowledge-lock-owner.v3', lock_id: crypto.randomUUID(), lock_name: 'team-flow',
    purpose: LOCKS['team-flow'].purpose, pid: process.pid, hostname: os.hostname(), agent_id: 'preflight-test', workspace_id: 'sample',
    process_started_at: '2026-10-26T12:00:00.000Z', acquired_at: '2026-10-26T12:00:00.000Z',
    nonce: crypto.randomBytes(32).toString('hex'), native_identity: null, publication: 'atomic-directory-noreplace.v1',
    kernel_lease: { method: process.platform === 'win32' ? 'windows-owner-event.v1' : 'owner-inode-lease.v1',
      owner_dev: String(own.dev), owner_ino: String(own.ino), directory_dev: String(dir.dev), directory_ino: String(dir.ino) },
    execution_scope: { schema_version: 'knowledge-command-scope-binding.v1', backend: 'macos_uid_guardian', sha256: digest(scopeBytes) } };
  fs.writeFileSync(ownerPath, ownerSchema.canonicalOwnerText(f.owner));return f;
}
test('absent Team lock discovery returns null without creating any storage', t => {
  const f = fixture(t, false);assert.equal(readTeamFlowScope(f.context), null);assert.deepEqual(fs.readdirSync(f.root), []);
});
test('preflight returns immutable token-free exact scope without changing owner or native state', t => {
  const f = fixture(t), owner = fs.readFileSync(f.ownerPath), scope = fs.readFileSync(f.scopePath);
  const cp = require('node:child_process'), spawn = cp.spawn, spawnSync = cp.spawnSync;
  cp.spawn = cp.spawnSync = () => { throw new Error('Forbidden native query during discovery'); };
  let value;
  try { value = readTeamFlowScope(f.context); } finally { cp.spawn = spawn;cp.spawnSync = spawnSync; }
  assert.deepEqual(value, f.scope);assert(Object.isFrozen(value.binding.descriptor));
  assert.deepEqual(fs.readFileSync(f.ownerPath), owner);assert.deepEqual(fs.readFileSync(f.scopePath), scope);
});
test('path traversal or non-Team input is rejected before discovery', t => {
  const f = fixture(t, false);
  for (const value of [{ ...f.context, repoId: '../other' }, { ...f.context, teamRoot: 'relative' }, { ...f.context, mode: 'repo' }]) {
    assert.throws(() => readTeamFlowScope(value), { code: 'macos_lock_preflight_context_invalid' });
  }
  assert.deepEqual(fs.readdirSync(f.root), []);
});
test('a mismatched owner scope digest never becomes a parent observation request', t => {
  const f = fixture(t);f.owner.execution_scope.sha256 = '0'.repeat(64);fs.writeFileSync(f.ownerPath, ownerSchema.canonicalOwnerText(f.owner));
  assert.throws(() => readTeamFlowScope(f.context), { code: 'macos_lock_preflight_scope_invalid' });
});
test('byte-identical owner replacement is rejected by original inode binding', t => {
  const f = fixture(t), bytes = fs.readFileSync(f.ownerPath);
  fs.renameSync(f.ownerPath, f.ownerPath + '.retired');fs.writeFileSync(f.ownerPath, bytes);
  assert.throws(() => readTeamFlowScope(f.context), { code: 'macos_lock_preflight_owner_binding_invalid' });
  assert.deepEqual(fs.readFileSync(f.ownerPath), bytes);
});
test('oversized scope data is rejected by the admitted bounded reader', t => {
  const f = fixture(t);fs.writeFileSync(f.scopePath, 'x'.repeat(LOCK_POLICY.execution_scope_max_bytes + 1));
  assert.throws(() => readTeamFlowScope(f.context), error => error.code === 'macos_lock_preflight_scope_invalid' && error.cause.code === 'stable_file_too_large');
});
test('scope metadata cannot carry an embedded authorization token', t => {
  const f = fixture(t);f.scope.binding.descriptor.token = hex('a');
  f.scope.binding.descriptor_sha256 = wire.digest(f.scope.binding.descriptor);
  const bytes = JSON.stringify(f.scope, null, 2) + '\n';fs.writeFileSync(f.scopePath, bytes);
  f.owner.execution_scope.sha256 = digest(bytes);fs.writeFileSync(f.ownerPath, ownerSchema.canonicalOwnerText(f.owner));
  assert.throws(() => readTeamFlowScope(f.context), { code: 'macos_lock_preflight_scope_invalid' });
});
test('owner mutation while scope bytes are read cannot be cached for a successor', t => {
  const f = fixture(t), read = fs.readSync;let injected = false;
  fs.readSync = function(fd, buffer, offset, length, position) {
    const n = read.apply(this, arguments);
    if (!injected && buffer.subarray(offset, offset + n).includes(Buffer.from('knowledge-command-scope.v1'))) {
      injected = true;f.owner.acquired_at = '2026-10-26T12:00:01.000Z';fs.writeFileSync(f.ownerPath, ownerSchema.canonicalOwnerText(f.owner));
    }
    return n;
  };
  try { assert.throws(() => readTeamFlowScope(f.context), { code: 'macos_lock_preflight_owner_changed' }); }
  finally { fs.readSync = read; }
  assert.equal(injected, true);
});
