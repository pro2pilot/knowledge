'use strict';

// Canonical owner migration and conservative automatic recovery. Real child
// exit tests are separate from injected observation failures and parser cases.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const SOURCE = path.resolve(__dirname, '..');
const LEGACY_SOURCE = path.join(__dirname, 'fixtures', 'lock-v2-runtime');
const manager = require(path.join(SOURCE, 'tools/lib/contained-lock-manager'));
const legacyManager = require(path.join(LEGACY_SOURCE, 'tools/lib/contained-lock-manager'));
const policy = require(path.join(SOURCE, 'tools/lib/lock-policy'));
const schema = require(path.join(SOURCE, 'tools/lib/lock-owner-schema'));

function fixture(t, extra = {}, currentOwner = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-owner-scope-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const state = path.join(root, 'state');
  const request = { rootKind: 'state', rootPath: state, context: { stateRoot: state },
    lockName: 'team-flow', purpose: policy.LOCKS['team-flow'].purpose,
    timeoutMs: 1000, ...extra };
  // These are ownership/observation tests, not 25ms startup performance
  // tests. The v3 path includes durable staging in its admission deadline.
  // Keep the genuine v2 writer/release implementation for legacy assertions;
  // bootstrap with the normal budget and bound only the tested contention.
  const handle = (currentOwner ? manager : legacyManager).acquireContainedLock({ ...request, timeoutMs: 30000 });
  const ownerPath = path.join(handle.path, 'owner.json');
  const owner = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
  function write(value = owner) { fs.writeFileSync(ownerPath, schema.canonicalOwnerText(value)); }
  function age() { const old = new Date(Date.now() - 3 * 86400000); fs.utimesSync(handle.path, old, old); }
  function snapshot() { const s = fs.lstatSync(handle.path, { bigint: true });
    return { dev: String(s.dev), ino: String(s.ino), bytes: fs.readFileSync(ownerPath, 'utf8') }; }
  function refuse(reason) {
    const before = snapshot(); let successor, failure;
    try { successor = manager.acquireContainedLock(request); } catch (error) { failure = error; }
    if (successor) successor.release();
    assert.ok(failure, 'A contender acquired an owner whose exit was not proven in its native PID scope');
    assert.equal(failure.code, 'lock_timeout');
    if (reason) assert.equal(failure.owner_disposition, reason);
    assert.deepEqual(snapshot(), before, 'Unknown ownership must remain byte-for-byte and physically unchanged');
    return failure;
  }
  return { root, state, request, handle, owner, ownerPath, write, age, snapshot, refuse };
}

function nativeIdentity(t) {
  if (process.platform !== 'linux') { t.skip('Real Linux procfs/native PID scope requires Linux'); return null; }
  const identity = manager.__test.captureNativeOwnerIdentity();
  if (!identity) { t.skip('Current Linux procfs/native scope is unavailable; automatic recovery is unqualified'); return null; }
  assert.equal(policy.validNativeOwnerIdentity(identity, process.pid), true);
  return identity;
}

function withMountinfoText(transform, action) {
  const originalOpen = fs.openSync, originalRead = fs.readSync, originalClose = fs.closeSync, replacements = new Map();
  fs.openSync = function(file, ...args) {
    const fd = originalOpen.call(fs, file, ...args);
    if (typeof file === 'string' && file.endsWith('/self/mountinfo')) {
      try { replacements.set(fd, { bytes: Buffer.from(transform(fs.readFileSync(fd, 'utf8'))), offset: 0 }); }
      catch (error) { originalClose.call(fs, fd); throw error; }
    }
    return fd;
  };
  fs.readSync = function(fd, buffer, offset, length, position) {
    const replacement = replacements.get(fd);
    if (!replacement) return originalRead.call(fs, fd, buffer, offset, length, position);
    const count = Math.min(length, replacement.bytes.length - replacement.offset);
    replacement.bytes.copy(buffer, offset, replacement.offset, replacement.offset + count); replacement.offset += count;
    return count;
  };
  fs.closeSync = function(fd) { replacements.delete(fd); return originalClose.call(fs, fd); };
  try { return action(); } finally { fs.openSync = originalOpen; fs.readSync = originalRead; fs.closeSync = originalClose; }
}

test('new owners use v3 and a kernel lease in the existing v1 layout and release by exact ownership', t => {
  const f = fixture(t, {}, true);
  assert.equal(f.owner.schema_version, 'knowledge-lock-owner.v3');
  assert.equal(path.basename(path.dirname(f.handle.path)), 'v1');
  assert.deepEqual(Object.keys(f.owner), schema.V3_OWNER_FIELDS);
  assert.equal(f.owner.kernel_lease.method, 'owner-inode-lease.v1');
  assert.equal(schema.canonicalOwnerText(f.owner), fs.readFileSync(f.ownerPath, 'utf8'));
  assert.ok(f.owner.native_identity === null || policy.validNativeOwnerIdentity(f.owner.native_identity, process.pid));
  assert.equal(policy.LOCK_POLICY.default_stale_ms, 120000);
  assert.equal(f.handle.release().status, 'released');
});

test('canonical v1 owners remain readable but absent-PID and age do not authorize recovery', t => {
  const f = fixture(t); const v1 = { ...f.owner, schema_version: 'knowledge-lock-owner.v1', pid: 2147483647 };
  delete v1.native_identity; f.write(v1); f.age();
  assert.deepEqual(schema.validateOwner(v1), v1);
  const failure = f.refuse('legacy_owner_scope_unverified');
  assert.equal(failure.recovery_required, 'native_scope_evidence');
  const inspected = manager.inspectLockSafety(f.request);
  assert.equal(inspected.current.status, 'active');
  assert.equal(inspected.current.reason, 'legacy_owner_scope_unverified');
  assert.equal(inspected.current.recovery_required, 'native_scope_evidence');
  const diagnostic = manager.inspectContextLockSafety({ stateRoot: f.state, projectKnowledgeRoot: f.state });
  const lock = diagnostic.locks.find(item => item.lock_name === 'team-flow');
  assert.equal(lock.current.reason, 'legacy_owner_scope_unverified');
  assert.equal(lock.current.recovery_required, 'native_scope_evidence');
  const publicText = JSON.stringify({ failure: { ...failure }, inspected, diagnostic });
  assert.ok(!publicText.includes(f.owner.nonce));
  assert.ok(!publicText.includes('boot_id'));
});

test('a pre-v1 legacy .lock never gains a host/PID scope from its hostname', t => {
  const f = fixture(t); assert.equal(f.handle.release().status, 'released');
  const legacy = manager.lockPaths(manager.__test.requestPolicy(f.request)).legacy;
  fs.mkdirSync(legacy);
  const bytes = JSON.stringify({ lock_id: 'legacy', pid: 2147483647, hostname: os.hostname(), started_at: '2000-01-01T00:00:00.000Z' }) + '\n';
  fs.writeFileSync(path.join(legacy, 'owner.json'), bytes);
  const old = new Date('2000-01-01T00:00:00.000Z'); fs.utimesSync(legacy, old, old);
  assert.throws(() => manager.acquireContainedLock(f.request), error =>
    error.code === 'lock_timeout' && error.owner_disposition === 'legacy_owner_scope_unverified');
  assert.equal(fs.readFileSync(path.join(legacy, 'owner.json'), 'utf8'), bytes);
});

test('null v2 native scope is retained even when the recorded PID is absent', t => {
  const f = fixture(t); f.owner.pid = 2147483647; f.owner.native_identity = null; f.write(); f.age();
  const failure = f.refuse('owner_native_scope_unverified');
  assert.equal(failure.recovery_required, 'native_scope_evidence');
});

test('a kernel-derived scope cannot be supplied through the acquisition request', t => {
  const injected = { method: 'not-kernel-evidence', boot_id: 'caller-value' };
  let calls = 0;
  const f = fixture(t, { native_identity: injected, nativeIdentity: injected,
    nativeIdentityProvider() { calls++; return injected; } }, true);
  assert.equal(calls, 0); assert.notDeepEqual(f.owner.native_identity, injected);
  assert.ok(f.owner.native_identity === null || policy.validNativeOwnerIdentity(f.owner.native_identity, process.pid));
  assert.equal(f.handle.release().status, 'released');
});

test('foreign boot scope cannot invoke the PID probe', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.owner.native_identity.boot_id = f.owner.native_identity.boot_id === '00000000-0000-0000-0000-000000000000'
    ? '11111111-1111-1111-1111-111111111111' : '00000000-0000-0000-0000-000000000000';
  f.write(); f.age(); let probes = 0; const previous = process.kill;
  process.kill = () => { probes++; throw Object.assign(new Error('must not probe foreign boot'), { code: 'ESRCH' }); };
  try { f.refuse('owner_boot_scope_mismatch'); } finally { process.kill = previous; }
  assert.equal(probes, 0);
});

test('same hostname and unrelated PID namespace cannot invoke the PID probe', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); const id = f.owner.native_identity;
  id.pid_namespace_ino = String(BigInt(id.pid_namespace_ino) + 123456n);
  if (id.nspid.length === 1) id.procfs_pid_namespace_ino = id.pid_namespace_ino;
  f.write(); f.age(); let probes = 0; const previous = process.kill;
  process.kill = () => { probes++; throw Object.assign(new Error('must not probe unrelated scope'), { code: 'ESRCH' }); };
  try { f.refuse('owner_pid_scope_mismatch'); } finally { process.kill = previous; }
  assert.equal(probes, 0);
});

test('an occupied scoped PID is retained despite a different recorded start tick', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.owner.native_identity.start_ticks = String(BigInt(f.owner.native_identity.start_ticks) + 1n);
  f.write(); f.age(); f.refuse('occupied_scoped_owner_pid');
});

test('invalid procfs magic prevents automatic recovery and does not prevent exact-owner release', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.age(); const originalStatfs = fs.statfsSync, previous = process.kill; let probes = 0;
  fs.statfsSync = function(file, options) { const stat = originalStatfs.call(fs, file, options); return { ...stat, type: options?.bigint ? 0n : 0 }; };
  process.kill = () => { probes++; throw Object.assign(new Error('must not probe without native observer scope'), { code: 'ESRCH' }); };
  try { f.refuse('observer_native_scope_unverified'); assert.equal(f.handle.release().status, 'released'); }
  finally { fs.statfsSync = originalStatfs; process.kill = previous; }
  assert.equal(probes, 0);
});

test('lost native scope after ESRCH cannot authorize recovery', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.age(); const originalStatfs = fs.statfsSync, previous = process.kill; let probes = 0;
  process.kill = () => {
    probes++;
    fs.statfsSync = () => { throw Object.assign(new Error('injected observer loss after the probe'), { code: 'EIO' }); };
    throw Object.assign(new Error('injected ESRCH'), { code: 'ESRCH' });
  };
  try { f.refuse(); }
  finally { fs.statfsSync = originalStatfs; process.kill = previous; }
  assert.ok(probes > 0); assert.equal(f.handle.release().status, 'released');
});

test('strict native identity parser rejects missing, extra, reordered and mistyped coordinates', t => {
  const id = nativeIdentity(t); if (!id) return;
  const variants = [];
  const missing = { ...id }; delete missing.boot_id; variants.push(missing);
  variants.push({ ...id, extra: true }, Object.fromEntries(Object.entries(id).reverse()));
  variants.push({ ...id, proc_pid: String(id.proc_pid) }, { ...id, nspid: [String(process.pid)] },
    { ...id, start_ticks: '01' }, { ...id, start_ticks: '18446744073709551616' },
    { ...id, pid_namespace_ino: '0' }, { ...id, boot_id: 'A0000000-0000-0000-0000-000000000000' },
    { ...id, method: 'linux_procfs_v1' }, id.nspid.length === 1
      ? { ...id, procfs_pid_namespace_dev: null, procfs_pid_namespace_ino: null }
      : { ...id, procfs_pid_namespace_dev: id.pid_namespace_dev, procfs_pid_namespace_ino: id.pid_namespace_ino });
  for (const value of variants) assert.equal(policy.validNativeOwnerIdentity(value, process.pid), false);
});

test('pinned manager rejects malformed identity even if the canonical reader is replaced', t => {
  const f = fixture(t); f.owner.pid = 2147483647;
  f.owner.native_identity = { method: 'linux_procfs_held_v1', nspid: ['2147483647'] };
  fs.writeFileSync(f.ownerPath, JSON.stringify(f.owner, null, 2) + '\n'); f.age();
  const before = f.snapshot();
  const code = `const path=require('node:path');const root=process.argv[1];
const reader=require(path.join(root,'tools/lib/lock-owner-schema'));
reader.validateOwner=owner=>owner;reader.canonicalOwnerText=owner=>JSON.stringify(owner,null,2)+'\\n';
const manager=require(path.join(root,'tools/lib/contained-lock-manager'));
let probes=0;process.kill=()=>{probes++;throw Object.assign(new Error('injected'),{code:'ESRCH'})};
try{const h=manager.acquireContainedLock(JSON.parse(process.argv[2]));h.release();process.stdout.write(JSON.stringify({acquired:true,probes}));}
catch(e){process.stdout.write(JSON.stringify({code:e.code,reason:e.owner_disposition,probes}));}`;
  const child = spawnSync(process.execPath, ['-e', code, SOURCE, JSON.stringify(f.request)], { encoding: 'utf8', timeout: 30000 });
  assert.ifError(child.error); assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), { code: 'lock_timeout', reason: 'owner_native_scope_unverified', probes: 0 });
  assert.deepEqual(f.snapshot(), before);
});

test('real exited Linux child permits recovery in its proven native coordinate', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); assert.equal(f.handle.release().status, 'released');
  const code = `const path=require('node:path');const manager=require(path.join(process.argv[1],'tools/lib/contained-lock-manager'));
const h=manager.acquireContainedLock(JSON.parse(process.argv[2]));const fs=require('node:fs');
process.stdout.write(fs.readFileSync(path.join(h.path,'owner.json'),'utf8'));`;
  const child = spawnSync(process.execPath, ['-e', code, LEGACY_SOURCE, JSON.stringify(f.request)], { encoding: 'utf8', timeout: 30000 });
  assert.ifError(child.error); assert.equal(child.status, 0, child.stderr);
  const departed = JSON.parse(child.stdout);
  assert.equal(departed.schema_version, 'knowledge-lock-owner.v2');
  assert.ok(departed.native_identity, 'This native positive test requires a recorded scope');
  assert.throws(() => process.kill(departed.pid, 0), error => error.code === 'ESRCH');
  f.age(); const inspected = manager.inspectLockSafety(f.request);
  assert.equal(inspected.current.status, 'stale');
  assert.equal(inspected.current.reason, 'dead_scoped_owner');
  const next = manager.acquireContainedLock(f.request);
  assert.notEqual(next.lock_id, departed.lock_id); assert.equal(next.release().status, 'released');
});

test('process stat and NSpid parsers bind exact native coordinates, including parentheses in comm', () => {
  const tail = ['R', '7', ...Array(17).fill('0'), '123456', ...Array(5).fill('0')].join(' ');
  assert.deepEqual(manager.__test.parseKernelProcessStat(`23 (worker ) name) ${tail}\n`), { pid: 23, ppid: 7, start_ticks: '123456' });
  assert.deepEqual(manager.__test.kernelNSpid('Name:\tx\nNSpid:\t23\t2\n', 23), [23, 2]);
  for (const value of ['NSpid:\t23\t02\n', 'NSpid:\t23\t0\n', 'NSpid:\t22\t2\n', 'NSpid:\t23\nNSpid:\t23\n']) {
    assert.throws(() => manager.__test.kernelNSpid(value, 23));
  }
});

test('the non-Linux native-observer branch returns an unqualified owner (branch simulation)', t => {
  const f = fixture(t); assert.equal(f.handle.release().status, 'released');
  const code = `const path=require('node:path');const manager=require(path.join(process.argv[1],'tools/lib/contained-lock-manager'));
const policy=manager.__test.requestPolicy(JSON.parse(process.argv[2]));
Object.defineProperty(process,'platform',{value:'darwin'});
const owner=manager.__test.createOwner(policy);
process.stdout.write(JSON.stringify({schema:owner.schema_version,native_identity:owner.native_identity}));`;
  const child = spawnSync(process.execPath, ['-e', code, SOURCE, JSON.stringify(f.request)], { encoding: 'utf8', timeout: 30000 });
  assert.ifError(child.error); assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), { schema: 'knowledge-lock-owner.v3', native_identity: null });
});

test('an owner created without native observation still acquires and releases normally', t => {
  const previous = fs.statfsSync;
  fs.statfsSync = () => { throw Object.assign(new Error('injected unavailable native observer'), { code: 'EACCES' }); };
  try {
    const f = fixture(t, {}, true); assert.equal(f.owner.native_identity, null);
    assert.equal(f.handle.release().status, 'released');
  } finally { fs.statfsSync = previous; }
});

test('contradictory ESRCH cannot evict a still-present scoped process', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.age(); const previous = process.kill;
  process.kill = () => { throw Object.assign(new Error('injected errno without process exit'), { code: 'ESRCH' }); };
  try { f.refuse('contradictory_process_observation'); }
  finally { process.kill = previous; }
  assert.equal(f.handle.release().status, 'released');
});

test('hidepid visibility prevents automatic death inference even with ESRCH', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.age(); let probes = 0; const previous = process.kill;
  process.kill = () => { probes++; throw Object.assign(new Error('injected ESRCH'), { code: 'ESRCH' }); };
  try {
    withMountinfoText(text => text.split('\n').map(line => line.includes(' - proc ') ? line + ',hidepid=2' : line).join('\n'),
      () => f.refuse('observer_proc_visibility_unverified'));
  } finally { process.kill = previous; }
  assert.equal(probes, 0); assert.equal(f.handle.release().status, 'released');
});

test('missing anchored proc mount identity prevents automatic death inference', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.age(); let probes = 0; const previous = process.kill;
  process.kill = () => { probes++; throw Object.assign(new Error('injected ESRCH'), { code: 'ESRCH' }); };
  try {
    withMountinfoText(text => text.split('\n').map(line => line.includes(' - proc ') ? line.replace(/^[0-9]+/, '999999999999') : line).join('\n'),
      () => f.refuse('observer_proc_visibility_unverified'));
  } finally { process.kill = previous; }
  assert.equal(probes, 0); assert.equal(f.handle.release().status, 'released');
});

test('proc mount visibility change during a death probe remains unknown', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); let probed = false; const previous = process.kill;
  process.kill = () => { probed = true; throw Object.assign(new Error('injected ESRCH'), { code: 'ESRCH' }); };
  let result;
  try {
    withMountinfoText(text => probed ? text.split('\n').map(line => line.includes(' - proc ') ? line + ',gid=12345' : line).join('\n') : text,
      () => { result = manager.__test.ownerDisposition(f.owner, 3 * 86400000, manager.__test.requestPolicy(f.request)); });
  } finally { process.kill = previous; }
  assert.equal(result.stale, false); assert.equal(result.reason, 'observer_proc_visibility_changed');
  assert.equal(f.handle.release().status, 'released');
});

test('target proc visibility denied after ESRCH remains unknown', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); const originalOpen = fs.openSync, previous = process.kill; let probed = false;
  process.kill = () => { probed = true; throw Object.assign(new Error('injected ESRCH'), { code: 'ESRCH' }); };
  fs.openSync = function(file, ...args) {
    if (probed && typeof file === 'string' && file.endsWith('/' + f.owner.native_identity.proc_pid)) {
      throw Object.assign(new Error('injected proc record denial'), { code: 'EACCES' });
    }
    return originalOpen.call(fs, file, ...args);
  };
  let result;
  try { result = manager.__test.ownerDisposition(f.owner, 3 * 86400000, manager.__test.requestPolicy(f.request)); }
  finally { fs.openSync = originalOpen; process.kill = previous; }
  assert.equal(result.stale, false); assert.equal(result.reason, 'owner_proc_presence_unverified');
  assert.equal(f.handle.release().status, 'released');
});

test('the native procfs anchor is one bounded process-lifetime descriptor across lock releases', t => {
  if (!nativeIdentity(t)) return;
  const f = fixture(t); f.handle.release();
  const code = `const fs=require('node:fs'),path=require('node:path');
const roots=()=>fs.readdirSync('/proc/self/fd').filter(n=>{try{return fs.readlinkSync('/proc/self/fd/'+n)==='/proc'}catch{return false}});
const before=roots();const manager=require(path.join(process.argv[1],'tools/lib/contained-lock-manager'));
const request=JSON.parse(process.argv[2]);for(let i=0;i<20;i++){const h=manager.acquireContainedLock(request);h.release();}
const after=roots();process.stdout.write(JSON.stringify({before,after,identity:manager.__test.captureNativeOwnerIdentity()}));`;
  const child = spawnSync(process.execPath, ['-e', code, SOURCE, JSON.stringify(f.request)], { encoding: 'utf8', timeout: 30000 });
  assert.ifError(child.error); assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.after.length - result.before.length, 1);
  assert.equal(result.identity.method, 'linux_procfs_held_v1');
});
