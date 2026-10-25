#!/usr/bin/env node
'use strict';
// Physical Linux acceptance. An unavailable native backend is NOT a PASS.
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const backend = require('./lib/verification-linux-namespace');
const modulePath = require.resolve('./lib/verification-linux-namespace');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const bounded = (promise, ms = 15000) => { let timer; return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('test_wait_timeout')), ms); })]).finally(() => clearTimeout(timer)); };
const waitFor = async (test, ms = 10000) => { const end = Date.now() + ms; while (!test()) { if (Date.now() >= end) throw new Error('test_condition_timeout'); await delay(25); } };
const read = file => { try { return fs.readFileSync(file, 'utf8'); } catch { return ''; } };
const childCode = `const fs=require('fs'); const file=process.argv[1]; fs.writeFileSync(file+'.pid',fs.readlinkSync('/proc/self')); setInterval(()=>fs.appendFileSync(file,'x'),40);`;
const rows = [], ownedJobs = new Set(), ownedChildren = new Set();
let root;
async function check(name, fn) { const started = Date.now(); try { const details = await fn(); rows.push({ name, status: 'PASS', elapsed_ms: Date.now() - started, ...(details ? { details } : {}) }); } catch (e) { rows.push({ name, status: 'FAIL', elapsed_ms: Date.now() - started, error: e.stack }); } }
function worker(code, args = [], settings = {}) {
  const failures = [];
  const pair = backend.spawnLinuxContainedWorker(process.execPath, ['-e', code, ...args], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }, { ...settings, lifetimeMs: 60000, onFailure: e => failures.push(e.code) });
  ownedJobs.add(pair.job); return { ...pair, failures };
}
async function start(pair) { await bounded(pair.job.ready); pair.job.permit(); await bounded(pair.job.started); }
async function close(pair) { const proof = await pair.job.close(10000); ownedJobs.delete(pair.job); return proof; }
function message(child) { return bounded(new Promise(resolve => child.once('message', resolve))); }
async function controller(file) {
  const script = `const fs=require('fs');const b=require(${JSON.stringify(modulePath)});const p=b.spawnLinuxContainedWorker(process.execPath,['-e',${JSON.stringify(`const fs=require('fs'),cp=require('child_process');const c=cp.spawn(process.execPath,['-e',${JSON.stringify(childCode)},${JSON.stringify(file)}],{stdio:'ignore',detached:true});c.unref();setInterval(()=>{},1000);`)}],{stdio:['ignore','ignore','ignore','ipc']},{lifetimeMs:60000,onFailure:()=>{}});p.job.ready.then(()=>{fs.writeFileSync(${JSON.stringify(file + '.descriptor')},JSON.stringify(p.job.descriptor));p.job.permit();});setInterval(()=>{},1000);`;
  const child = spawn(process.execPath, ['-e', script], { stdio: 'ignore' }); ownedChildren.add(child);
  await waitFor(() => !!read(file + '.descriptor') && !!read(file));
  return { child, descriptor: JSON.parse(read(file + '.descriptor')) };
}

async function main() {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-linux-acceptance-'));
  const capability = backend.containmentCapability();
  if (capability.status === 'unavailable') { rows.push({ name: 'physical_linux_capability', status: 'BLOCKED', capability }); return; }
  rows.push({ name: 'physical_linux_capability', status: 'PASS', capability });
  await check('work_cannot_start_before_permit_and_close_before_permit_is_safe', async () => {
    const file = path.join(root, 'pre-permit'); const pair = worker(`require('fs').writeFileSync(process.argv[1],'ran');setInterval(()=>{},1000)`, [file]);
    await bounded(pair.job.ready); await delay(150); assert.equal(fs.existsSync(file), false);
    const proof = await close(pair); assert.equal(proof.status, 'completed'); assert.equal(proof.init_reaped, true); assert.equal(proof.namespace_drained, true); assert.equal(fs.existsSync(file), false);
    assert.throws(() => pair.job.permit(), /permit_invalid/);
  });
  await check('ordinary_ipc_worker_has_private_pid_namespace_and_exact_birth', async () => {
    const pair = worker(`process.on('message',()=>process.send({pid:process.pid,proc_pid:Number(require('fs').readlinkSync('/proc/self'))}));setInterval(()=>{},1000)`);
    await start(pair); const reply = message(pair.worker); pair.worker.send({ go: true }); const value = await reply;
    assert.equal(value.pid, 2); assert.equal(value.proc_pid, pair.job.descriptor.worker.proc_pid); assert.notEqual(pair.job.descriptor.init.pid_namespace.ino, pair.job.descriptor.observer_pid_namespace.ino);
    assert.equal((await close(pair)).status, 'completed');
  });
  await check('worker_cannot_open_init_or_ancestor_private_handles', async () => {
    const code = `const fs=require('fs');process.on('message',m=>{const result={};for(const pid of [m.init,m.keeper,m.controller])for(const suffix of ['mem','environ','root','ns/pid','fd/4']){const p='/proc/'+pid+'/'+suffix;try{const f=fs.openSync(p,fs.constants.O_RDONLY);fs.closeSync(f);result[p]='OPENED';}catch(e){result[p]=e.code;}}process.send(result)});setInterval(()=>{},1000)`;
    const pair = worker(code); await start(pair); const d = pair.job.descriptor; const reply = message(pair.worker); pair.worker.send({ init: d.init.proc_pid, keeper: d.keeper.proc_pid, controller: d.controller.proc_pid });
    const result = await reply;
    for (const [file, value] of Object.entries(result)) assert.ok(['EACCES', 'EPERM', 'ENOENT'].includes(value), `${file} unexpectedly ${value}`);
    assert.equal((await close(pair)).status, 'completed'); return result;
  });
  await check('setsid_and_reparented_descendant_are_killed_after_worker_exit', async () => {
    const file = path.join(root, 'detached');
    const pair = worker(`const cp=require('child_process');const c=cp.spawn(process.execPath,['-e',${JSON.stringify(childCode)},process.argv[1]],{detached:true,stdio:'ignore'});c.unref();setTimeout(()=>process.exit(0),250);`, [file]);
    await start(pair); await waitFor(() => read(file).length > 1); await waitFor(() => pair.failures.includes('verification_worker_exited'));
    const proof = await close(pair); assert.equal(proof.status, 'completed');
    const before = read(file); await delay(200); assert.equal(read(file), before); assert.equal(fs.existsSync('/proc/' + read(file + '.pid')), false);
  });
  await check('nested_factory_keeps_local_and_ancestor_proc_pids_distinct', async () => {
    const injection = path.join(root, 'untrusted-compiler-env'); fs.mkdirSync(injection); fs.writeFileSync(path.join(injection, 'unistd.h'), '#error forbidden compiler environment injection\n');
    const code = `process.env.GCC_EXEC_PREFIX=${JSON.stringify(injection + '/')};process.env.COMPILER_PATH=${JSON.stringify(injection)};process.env.CPATH=${JSON.stringify(injection)};const b=require(${JSON.stringify(modulePath)});(async()=>{const x=b.spawnLinuxContainedWorker(process.execPath,['-e',"process.send(require('fs').readFileSync('/proc/self/status','utf8'));setInterval(()=>{},1000)"],{stdio:['ignore','ignore','ignore','ipc']},{lifetimeMs:30000,onFailure:()=>{}});const inner=new Promise(r=>x.worker.once('message',r));await x.job.ready;x.job.permit();await x.job.started;const innerStatus=await inner;const proof=await x.job.close(10000);process.send({pid:process.pid,controller:x.job.descriptor.controller,proof,innerStatus,outerStatus:require('fs').readFileSync('/proc/self/status','utf8')});setInterval(()=>{},1000)})().catch(e=>{process.send({error:e.stack});setInterval(()=>{},1000)});`;
    const pair = worker(code, [], { trustedAuthority: true }); const reply = message(pair.worker); await start(pair); const result = await reply;
    assert.equal(result.error, undefined); assert.equal(result.controller.pid, result.pid); assert.notEqual(result.controller.proc_pid, result.controller.pid); assert.equal(result.proof.status, 'completed');
    for (const cap of ['CapPrm', 'CapEff', 'CapAmb']) { assert.match(result.innerStatus, new RegExp(`${cap}:\\s+0000000000000000`)); assert.match(result.outerStatus, new RegExp(`${cap}:\\s+0000000080000000`)); }
    assert.match(result.innerStatus, /NoNewPrivs:\s+1/); assert.equal((await close(pair)).status, 'completed');
  });
  await check('double_fork_and_nested_pid_namespace_cannot_escape_init_cleanup', async () => {
    const file = path.join(root, 'nested-descendant');
    const middle = `const cp=require('child_process');const p=cp.spawn('/usr/bin/unshare',['--user','--pid','--fork','--kill-child=KILL','--',process.execPath,'-e',${JSON.stringify(childCode)},process.argv[1]],{stdio:'ignore',detached:true});p.unref();`;
    const pair = worker(`const cp=require('child_process');const p=cp.spawn(process.execPath,['-e',${JSON.stringify(middle)},process.argv[1]],{stdio:'ignore',detached:true});p.unref();setInterval(()=>{},1000)`, [file]);
    await start(pair); await waitFor(() => read(file).length > 1); assert.equal((await close(pair)).status, 'completed');
    const before = read(file); await delay(200); assert.equal(read(file), before); assert.equal(fs.existsSync('/proc/' + read(file + '.pid')), false);
  });
  await check('keeper_crash_kills_detached_descendant_but_does_not_forge_close_proof', async () => {
    const file = path.join(root, 'keeper-crash');
    const pair = worker(`const cp=require('child_process');const c=cp.spawn(process.execPath,['-e',${JSON.stringify(childCode)},process.argv[1]],{detached:true,stdio:'ignore'});c.unref();setInterval(()=>{},1000)`, [file]);
    await start(pair); await waitFor(() => read(file).length > 1); pair.worker.kill('SIGKILL'); await waitFor(() => pair.worker.signalCode === 'SIGKILL');
    await waitFor(() => !fs.existsSync('/proc/' + read(file + '.pid'))); const before = read(file); await delay(150); assert.equal(read(file), before); assert.equal((await close(pair)).status, 'unconfirmed');
  });
  await check('stopped_keeper_exhausts_cleanup_without_late_success', async () => {
    const pair = worker('setInterval(()=>{},1000)'); await start(pair); pair.worker.kill('SIGSTOP');
    const proof = await pair.job.close(300); assert.equal(proof.status, 'unconfirmed'); assert.equal(proof.code, 'namespace_cleanup_timeout');
    await waitFor(() => pair.worker.signalCode === 'SIGKILL'); assert.deepEqual(await pair.job.close(10000), proof); ownedJobs.delete(pair.job);
    return { fixture: 'explicit fault injection; 300 ms is not a product default or caller-return guarantee' };
  });
  await check('readonly_identity_observer_does_not_clear_live_process', async () => {
    const identity = backend.currentProcessIdentity(); assert.equal(identity.identity.pid, process.pid); assert.equal(backend.verifyProcessExit(identity).status, 'active');
    const wrong = structuredClone(identity); wrong.observer_pid_namespace.ino = String(BigInt(wrong.observer_pid_namespace.ino) + 1n); assert.equal(backend.verifyProcessExit(wrong).status, 'unconfirmed');
  });
  await check('old_birth_fixture_never_signals_current_owned_process', async () => {
    const helper = backend.prepareHelper(), context = backend.currentProcessIdentity(), i = context.identity;
    const args = ['--stop', context.boot_id, context.observer_pid_namespace.dev, context.observer_pid_namespace.ino, context.procfs_dev,
      String(i.pid), String(i.proc_pid), String(BigInt(i.start_ticks) - 1n), i.pid_namespace.dev, i.pid_namespace.ino, String(i.namespace_pid), '5000'];
    const result = spawnSync(helper.executable, args, { encoding: 'utf8', timeout: 7000 }); assert.equal(result.status, 0); const evidence = JSON.parse(result.stdout);
    assert.equal(evidence.method, 'linux_boot_birth_replaced'); assert.equal(evidence.release_inferred, true); assert.equal(backend.verifyProcessExit(context).status, 'active');
    return { fixture: 'synthetic older birth against a real current PID; no forced kernel PID reuse' };
  });
  await check('recovery_stops_exact_live_container_and_outside_helpers', async () => {
    const file = path.join(root, 'recover-live'); const x = await controller(file);
    const proof = backend.recoverContainer(x.descriptor, { cleanup_timeout_ms: 15000 });
    assert.equal(proof.status, 'completed', JSON.stringify(proof)); assert.equal(proof.init_exit_observed, true); assert.equal(proof.init_exit_basis, 'linux_pidfd_exit'); assert.equal(proof.controller_exited, true); assert.equal(proof.ack_released, false);
    const before = read(file); await delay(200); assert.equal(read(file), before); await waitFor(() => x.child.exitCode !== null || x.child.signalCode !== null); ownedChildren.delete(x.child);
  });
  await check('recovery_after_controller_crash_uses_explicit_finality_inference', async () => {
    const file = path.join(root, 'recover-crash'); const x = await controller(file); x.child.kill('SIGKILL'); await waitFor(() => x.child.signalCode === 'SIGKILL'); ownedChildren.delete(x.child);
    await waitFor(() => !fs.existsSync('/proc/' + read(file + '.pid')));
    const proof = backend.recoverContainer(x.descriptor, { cleanup_timeout_ms: 15000 });
    assert.equal(proof.status, 'completed', JSON.stringify(proof)); assert.equal(proof.namespace_drained, true); assert.equal(proof.ack_released, false);
    assert.ok(proof.init_exit_observed || proof.init_exit_inferred); if (proof.init_exit_inferred) assert.ok(['linux_boot_birth_absent', 'linux_boot_birth_replaced'].includes(proof.init_exit_basis));
  });
  await check('boot_and_namespace_mismatch_never_signal_live_workload', async () => {
    const file = path.join(root, 'recover-mismatch'); const x = await controller(file);
    const wrongBoot = structuredClone(x.descriptor); wrongBoot.boot_id = '00000000-0000-0000-0000-000000000000'; assert.equal(backend.recoverContainer(wrongBoot).status, 'unconfirmed');
    const wrongNs = structuredClone(x.descriptor); wrongNs.init.pid_namespace.ino = String(BigInt(wrongNs.init.pid_namespace.ino) + 1n); wrongNs.worker.pid_namespace.ino = wrongNs.init.pid_namespace.ino; assert.equal(backend.recoverContainer(wrongNs).status, 'unconfirmed');
    const before = read(file).length; await waitFor(() => read(file).length > before); assert.equal(backend.recoverContainer(x.descriptor, { cleanup_timeout_ms: 15000 }).status, 'completed'); ownedChildren.delete(x.child);
  });
}
main().catch(e => rows.push({ name: 'harness', status: 'FAIL', error: e.stack })).finally(async () => {
  for (const job of ownedJobs) { try { await job.close(10000); } catch {} }
  for (const child of ownedChildren) { try { child.kill('SIGKILL'); } catch {} }
  const report = { schema_version: 'knowledge-linux-namespace-selftest.v1', platform: process.platform, architecture: process.arch, results: rows,
    pass: rows.filter(x => x.status === 'PASS').length, fail: rows.filter(x => x.status === 'FAIL').length, blocked: rows.filter(x => x.status === 'BLOCKED').length };
  const reportIndex = process.argv.indexOf('--report'); if (reportIndex >= 0 && process.argv[reportIndex + 1]) fs.writeFileSync(path.resolve(process.argv[reportIndex + 1]), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
  if (root) fs.rmSync(root, { recursive: true, force: true });
  process.exitCode = report.fail ? 1 : report.blocked ? 3 : 0;
});
