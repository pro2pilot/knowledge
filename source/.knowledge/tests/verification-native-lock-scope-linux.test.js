'use strict';

// Actual bundled Linux authority namespace, actual short control mutex, and
// SIGKILL after ownership publication. This is not a full verification pass.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const SOURCE = path.resolve(process.env.KNOWLEDGE_NATIVE_TEST_SOURCE || path.join(__dirname, '..'));
const native = require(path.join(SOURCE, 'tools/lib/verification-linux-namespace'));
const locks = require(path.join(SOURCE, 'tools/lib/contained-lock-manager'));
const control = require(path.join(SOURCE, 'tools/lib/verification-control'));
const { LOCKS, LOCK_POLICY } = require(path.join(SOURCE, 'tools/lib/lock-policy'));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitReady(file, worker, milliseconds) {
  const start = performance.now();
  while (performance.now() - start < milliseconds) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (worker.exitCode !== null || worker.signalCode !== null) throw new Error('Native holder exited before publishing the mutex-ready marker');
    await delay(25);
  }
  throw new Error('Native holder did not publish its mutex-ready marker');
}

test('parent reclaims a crashed legacy v2 authority control mutex using its proc-view PID while preserving the durable claim', { timeout: 150000 }, async t => {
  if (process.platform !== 'linux') { t.skip('Actual Linux authority namespace requires Linux'); return; }
  const capability = native.containmentCapability();
  if (capability.status === 'unavailable') { t.skip(`Native namespace unavailable: ${capability.reason}`); return; }
  assert.ok(locks.__test.captureNativeOwnerIdentity(), 'The native positive fixture requires a qualified parent scope');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-native-lock-scope-'));
  const state = path.join(root, 'state'); fs.mkdirSync(state);
  const context = { stateRoot: state };
  const attempt = control.beginAttempt(context, { request_sha256: 'a'.repeat(64) });
  const input = { attempt_id: attempt.owner.attempt_id, generation: attempt.owner.generation, reason_code: 'operator_recovery' };
  const active = path.join(state, 'maintenance/verification-control/active.json');
  const originalClaim = fs.readFileSync(active, 'utf8');
  const readyFile = path.join(root, 'ready.json'), crashFile = path.join(root, 'crash');
  const workerScript = path.join(root, 'holder.cjs');
  fs.writeFileSync(workerScript, `
'use strict';
const fs=require('node:fs'),path=require('node:path');
const source=${JSON.stringify(SOURCE)},context=${JSON.stringify(context)},input=${JSON.stringify(input)};
const locks=require(path.join(source,'tools/lib/contained-lock-manager'));
const original=locks.withContainedLock;
const legacy=require(path.join(source,'tests/fixtures/lock-v2-runtime/tools/lib/contained-lock-manager'));
// Exercise the retained v2 writer explicitly; new v3 writers use inode leases.
locks.withContainedLock=(request,fn)=>(request.lockName==='verification-control'?legacy.withContainedLock:original)(request,handle=>{
  if(request.lockName!=='verification-control')return fn(handle);
  const owner=JSON.parse(fs.readFileSync(path.join(handle.path,'owner.json'),'utf8'));
  const value={logical_pid:process.pid,owner,lock_path:handle.path,pid_namespace:fs.readlinkSync('/proc/self/ns/pid')};
  const ready=${JSON.stringify(readyFile)};fs.writeFileSync(ready+'.writing',JSON.stringify(value));fs.renameSync(ready+'.writing',ready);
  const start=Date.now();while(!fs.existsSync(${JSON.stringify(crashFile)})){
    if(Date.now()-start>90000)throw new Error('Owned native mutex crash fixture not released by parent');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,25);
  }
  process.kill(process.pid,'SIGKILL');throw new Error('SIGKILL did not terminate the owned holder');
});
require(path.join(source,'tools/lib/verification-control')).requestCancel(context,input);
`, { mode: 0o600 });
  let pair, cleanup = null, ready, descriptor, stderr = '', observations = {}, workerExitResolve;
  const nativeEvents = [];
  const workerExited = new Promise(resolve => { workerExitResolve = resolve; });
  try {
    pair = native.spawnLinuxContainedWorker(process.execPath, [workerScript],
      { cwd: root, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] },
      { trustedAuthority: true, lifetimeMs: 120000, onFailure(error) {
        nativeEvents.push(error.code); if (error.code === 'verification_worker_exited') workerExitResolve();
      } });
    pair.worker.stderr.on('data', chunk => { if (stderr.length < 65536) stderr += chunk.toString(); });
    descriptor = await pair.job.ready; assert.equal(descriptor.capability_profile, process.getuid() === 0 ? 'authority_setfcap' : 'authority_none');
    pair.job.permit(); await pair.job.started;
    ready = await waitReady(readyFile, pair.worker, 45000);
    assert.equal(ready.logical_pid, 2);
    assert.equal(ready.owner.schema_version, 'knowledge-lock-owner.v2');
    assert.ok(ready.owner.native_identity, `Native authority did not record its scoped identity: ${stderr}`);
    assert.equal(ready.owner.native_identity.proc_pid, descriptor.worker.proc_pid);
    assert.equal(ready.owner.native_identity.nspid.at(-1), ready.logical_pid);
    assert.notEqual(ready.owner.native_identity.proc_pid, ready.logical_pid);
    assert.equal(ready.owner.native_identity.pid_namespace_ino, descriptor.worker.pid_namespace.ino);
    assert.equal(fs.readFileSync(active, 'utf8'), originalClaim, 'Injected pre-mutation crash must not modify the durable attempt');
    let logicalProbe = 'occupied';
    try { process.kill(ready.logical_pid, 0); } catch (error) { logicalProbe = error.code || 'unknown'; }
    fs.writeFileSync(crashFile, 'self-SIGKILL after the mutex is acquired\n');
    let crashTimer;
    try { await Promise.race([workerExited, new Promise((_, reject) => {
      crashTimer = setTimeout(() => reject(new Error('Owned holder did not exit after the self-crash trigger')), 30000);
    })]); } finally { clearTimeout(crashTimer); }
    // The bundled helper closes its exact owned namespace and observes init
    // final exit. No unbound PID or process-group termination is used.
    cleanup = await pair.job.close(30000);
    assert.equal(cleanup.status, 'completed', JSON.stringify({ cleanup, stderr }));
    assert.equal(cleanup.namespace_drained, true); assert.equal(cleanup.init_reaped, true);
    assert.throws(() => process.kill(ready.owner.native_identity.proc_pid, 0), error => error.code === 'ESRCH');
    assert.equal(fs.readFileSync(active, 'utf8'), originalClaim);
    const old = new Date(Date.now() - 3 * 86400000); fs.utimesSync(ready.lock_path, old, old);
    assert.equal(LOCK_POLICY.default_stale_ms, 120000);
    const request = { rootKind: 'state', rootPath: state, context, lockName: 'verification-control', purpose: LOCKS['verification-control'].purpose };
    const probePids = [], previousKill = process.kill;
    let probePhase = 'stale_inspection';
    process.kill = function(pid, signal) { probePids.push({ pid, signal, phase: probePhase }); return previousKill.call(process, pid, signal); };
    let inspected, cancelled;
    try {
      inspected = locks.inspectLockSafety(request);
      assert.equal(inspected.current.status, 'stale'); assert.equal(inspected.current.reason, 'dead_scoped_owner');
      probePhase = 'recovery_and_successor_release';
      cancelled = control.requestCancel(context, input);
    } finally { process.kill = previousKill; }
    assert.ok(probePids.length > 0);
    assert.ok(probePids.filter(p => p.phase === 'stale_inspection').every(p => p.pid === ready.owner.native_identity.proc_pid && p.signal === 0), 'Parent must inspect the mapped native proc-view PID, never the nested logical PID');
    assert.ok(probePids.every(p => [ready.owner.native_identity.proc_pid, process.pid].includes(p.pid) && p.signal === 0), 'Recovery may inspect the old holder and then its own new lock during release');
    assert.equal(cancelled.status, 'cancel_requested'); assert.equal(cancelled.attempt.claimed, true);
    assert.equal(cancelled.attempt.attempt_id, attempt.owner.attempt_id);
    assert.equal(fs.existsSync(ready.lock_path), false);
    const recovered = control.recoverAttempt(context, input);
    assert.equal(recovered.attempt.claimed, false);
    assert.equal(recovered.attempt.terminal.outcome, 'cancelled');
    assert.equal(recovered.attempt.terminal.ack_sha256, null);
    observations = { status: 'PASS', owner_pid: ready.logical_pid, owner_proc_pid: ready.owner.native_identity.proc_pid,
      caller_logical_pid_probe: logicalProbe, selected_stale_probe_pid: [...new Set(probePids.filter(p => p.phase === 'stale_inspection').map(x => x.pid))],
      procfs_mode: descriptor.procfs_mode, capability_profile: descriptor.capability_profile,
      default_stale_ms: LOCK_POLICY.default_stale_ms, staged_mtime_only: true,
      durable_claim_preserved_until_explicit_recovery: true, verification_ack_created: false };
  } finally {
    if (pair && cleanup === null) cleanup = await pair.job.close(30000);
    t.diagnostic(JSON.stringify({ observations, cleanup, stderr, native_events: nativeEvents,
      helper_source_sha256: descriptor?.helper.source_sha256 || null,
      owner_manager_sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(SOURCE, 'tools/lib/contained-lock-manager.js'))).digest('hex'),
      fixture: root, semantics: 'Actual native authority PID namespace; synchronous control-mutex crash injection before mutation. Work commands were never started in the control record.' }));
    if (!pair || cleanup?.status === 'completed') fs.rmSync(root, { recursive: true, force: true });
    else t.diagnostic(`Cleanup unconfirmed; preserved owned fixture: ${root}`);
  }
});
