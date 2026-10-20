'use strict';
// Physical Windows tests. Timing adapters call the unchanged native backend;
// they never fabricate process identity, cleanup proof or a successful receipt.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');
const crypto = require('crypto');
const control = require('../tools/lib/verification-control');
const recovery = require('../tools/lib/verification-recovery');
const backend = require('../tools/lib/verification-windows-recovery');
const controlPath = require.resolve('../tools/lib/verification-control');
const recoveryPath = require.resolve('../tools/lib/verification-recovery');
const backendPath = require.resolve('../tools/lib/verification-windows-recovery');
const jobPath = require.resolve('../tools/lib/verification-windows-job');
const H = 'a'.repeat(64);
const hash = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const options = { skip: process.platform !== 'win32', timeout: 210000 };
function waitExit(child, allowance = 30000) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('owned_child_exit_unconfirmed')), allowance);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
  });
}
function adapterWith(native, body) {
  const fn = snapshot => body(snapshot, native);
  fn.owner_identity = native.owner_identity;
  fn.verify_recoverer_exit = native.verify_recoverer_exit;
  return fn;
}
function runChild(code, args = [], input) {
  const r = cp.spawnSync(process.execPath, ['-e', code, ...args], {
    input: input === undefined ? undefined : JSON.stringify(input), encoding: 'utf8',
    windowsHide: true, timeout: 90000
  });
  assert.ifError(r.error);
  return r;
}
async function ownedTree(t) {
  const parent = process.env.KNOWLEDGE_NATIVE_RECOVERY_EVIDENCE_ROOT || os.tmpdir();
  fs.mkdirSync(parent, { recursive: true });
  const root = fs.mkdtempSync(path.join(parent, 'windows-recovery-'));
  const context = { stateRoot: path.join(root, 'state') };
  fs.mkdirSync(context.stateRoot);
  const begun = control.beginAttempt(context, { request_sha256: H,
    profile: { work_budget_ms: 120000, no_progress_ms: 60000, cleanup_budget_ms: 30000 } });
  const marker = path.join(root, 'descendant-heartbeat.txt');
  const write = (name, value) => fs.writeFileSync(path.join(root, name + '.json'), JSON.stringify(value, null, 2));
  const pins = {};
  for (const file of [controlPath, recoveryPath, backendPath, jobPath, backendPath.replace(/\.js$/, '.ps1'), jobPath.replace(/\.js$/, '.ps1')])
    pins[path.basename(file)] = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  write('environment', { node: process.version, execPath: process.execPath, platform: process.platform,
    arch: process.arch, node_sha256: crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'), pins });
  const code = `
    const fs=require('fs'),cp=require('child_process'),crypto=require('crypto'),c=require(${JSON.stringify(controlPath)});
    const originalSpawn=cp.spawn;let keeper;
    cp.spawn=(exe,args,opts)=>{const child=originalSpawn(exe,args,opts);if(args.some(a=>typeof a==='string'&&a.endsWith('verification-windows-job.ps1')))keeper=child;return child;};
    const b=require(${JSON.stringify(jobPath)});
    let context,owner,worker,job,proof;
    const wait=child=>child.exitCode!==null||child.signalCode!==null?Promise.resolve():new Promise(r=>child.once('exit',r));
    async function close(){
      if(proof)return proof;
      c.updateAttempt(context,owner,{type:'cleanup_started'});
      proof=await job.close(30000);await wait(worker);await wait(keeper);
      if(proof.status!=='completed')throw new Error('normal_close_unconfirmed:'+JSON.stringify(proof));
      for(const [spawn_id,role]of [[2,'worker'],[3,'keeper']]){const id=job.identities[role];c.updateAttempt(context,owner,{type:'process_exit',spawn_id,pid:id.pid,os_creation_time:id.os_creation_time,method:'process_handle_signaled'});}
      return proof;
    }
    process.on('message',async m=>{try{
      if(m.action==='start'){
        ({context,owner}=m);
        for(const role of ['watchdog','authority','keeper'])c.updateAttempt(context,owner,{type:'spawn_intent',role});
        const leaf="const fs=require('fs');fs.writeFileSync(process.argv[1],'started');setInterval(()=>fs.writeFileSync(process.argv[1],String(Date.now())),75);";
        const work="const cp=require('child_process');process.send({idle:true});process.once('message',m=>{if(m!=='permit')throw Error('bad_gate');const leaf=cp.spawn(process.execPath,['-e',"+JSON.stringify(leaf)+",process.argv[1]],{detached:true,stdio:'ignore',windowsHide:true});leaf.unref();process.send({started:true,leaf_pid:leaf.pid});});setInterval(()=>{},1000);";
        worker=cp.spawn(process.execPath,['-e',work,m.marker],{stdio:['ignore','ignore','pipe','ipc'],windowsHide:true});worker.stderr.on('data',()=>{});
        const idle=new Promise(r=>worker.once('message',r));
        job=b.createWindowsJob(worker,()=>{},180000);await job.ready;await idle;
        const ids=job.identities;
        for(const [i,role]of ['controller','worker','keeper'].entries())c.updateAttempt(context,owner,{type:'spawn_observed',spawn_id:i+1,pid:ids[role].pid,os_creation_time:ids[role].os_creation_time,executable_sha256:crypto.createHash('sha256').update(fs.readFileSync(role==='keeper'?process.env.SystemRoot+'/System32/WindowsPowerShell/v1.0/powershell.exe':process.execPath)).digest('hex')});
        c.updateAttempt(context,owner,{type:'containment_bound',descriptor:job.descriptor,spawn_ids:[1,2,3]});
        c.assertResourceAvailable(context,owner);
        const started=new Promise(r=>worker.once('message',r));worker.send('permit');const observed=await started;
        process.send({seq:m.seq,ready:true,descriptor:job.descriptor,leaf_pid:observed.leaf_pid});
      }else if(m.action==='close'){process.send({seq:m.seq,proof:await close()});}
      else if(m.action==='publish'){if(!proof)throw Error('receipt_not_observed');c.updateAttempt(context,owner,{type:'cleanup_proven',proof});process.send({seq:m.seq,published:true});}
      else if(m.action==='kill_keeper'){keeper.kill('SIGKILL');await wait(keeper);await wait(worker);process.send({seq:m.seq,killed:true});}
    }catch(error){process.send({seq:m.seq,error:error.code||error.message,stack:error.stack});}});`;
  const controller = cp.spawn(process.execPath, ['-e', code], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], windowsHide: true });
  let stderr = '', sequence = 0;
  controller.stderr.on('data', data => { stderr += data; });
  const command = message => new Promise((resolve, reject) => {
    const seq = ++sequence;
    const clear = () => { clearTimeout(timer); controller.off('message', receive); controller.off('exit', exited); };
    const exited = () => { clear(); reject(new Error('controller_exited_during_command')); };
    const timer = setTimeout(() => { clear(); reject(new Error('controller_command_timeout:' + stderr)); }, 90000);
    const receive = answer => { if (answer.seq !== seq) return; clear(); answer.error ? reject(new Error(JSON.stringify(answer))) : resolve(answer); };
    controller.on('message', receive); controller.once('exit', exited);
    controller.send({ ...message, seq }, error => { if (error) { clear(); reject(error); } });
  });
  const f = { root, context, marker, controller, command, write, ...begun,
    id: { attempt_id: begun.owner.attempt_id, generation: begun.owner.generation }, started: Date.now() };
  f.state = label => { const a = control.readStatus(context).attempt; write(label, a); return a; };
  t.after(async () => {
    f.state('state-before-guardian');
    try { if (controller.exitCode === null && controller.signalCode === null) await command({ action: 'close' }); } catch {}
    try { const a = control.readStatus(context).attempt; if (a.claimed && a.containment) backend.recoverContainer(a.containment.descriptor, { cleanup_timeout_ms: 30000, cleanup_receipt: a.containment.cleanup_receipt }); } catch (error) { write('guardian-native-error', { code: error.code, message: error.message }); }
    if (controller.exitCode === null && controller.signalCode === null) controller.kill('SIGKILL');
    await waitExit(controller).catch(error => write('guardian-exit-error', { message: error.message }));
    write('timing', { elapsed_ms: Date.now() - f.started, work_budget_ms: 120000, no_progress_ms: 60000, cleanup_budget_ms: 30000 });
    fs.writeFileSync(path.join(root, 'controller.stderr.log'), stderr);
    console.log(JSON.stringify({ native_fixture: root, test: t.name, descriptor_sha256: f.descriptor && hash(f.descriptor) }));
    if (!process.env.KNOWLEDGE_NATIVE_RECOVERY_EVIDENCE_ROOT) fs.rmSync(root, { recursive: true, force: true });
  });
  const answer = await command({ action: 'start', context, owner: begun.owner, marker });
  f.descriptor = answer.descriptor; f.leaf_pid = answer.leaf_pid;
  const until = Date.now() + 10000;
  while (!fs.existsSync(marker) && Date.now() < until) await delay(25);
  assert(fs.existsSync(marker), 'actual detached descendant reached heartbeat');
  f.state('state-ready');
  return f;
}
async function settled(f, result, outcome = 'failed') {
  f.write('result', result);
  assert.equal(result.status, outcome); assert.equal(result.ack_released, false);
  assert.equal(result.attempt.cleanup.status, 'confirmed'); assert.equal(result.attempt.claimed, false);
  assert.equal(result.attempt.terminal.ack_sha256, null);
  assert(result.attempt.processes.every(p => p.exit_observed));
  const transcript = result.attempt.cleanup.native_transcript;
  assert.equal(transcript.schema_version, 'knowledge-native-cleanup-transcript.v1');
  assert.equal(transcript.attempt_id, f.id.attempt_id); assert.equal(transcript.generation, f.id.generation);
  assert.equal(transcript.descriptor_sha256, hash(f.descriptor));
  assert.equal(transcript.recovery_id, result.attempt.recovery.recovery_id);
  assert.equal(transcript.payload_sha256, hash(transcript.payload));
  assert.deepEqual(transcript.payload.native_return, transcript.payload.bound_proof.native_return);
  assert.equal(transcript.payload.native_return.active_processes, 0);
  await waitExit(f.controller);
  const content = fs.readFileSync(f.marker, 'utf8'); await delay(300);
  assert.equal(fs.readFileSync(f.marker, 'utf8'), content, 'detached descendant stopped writing');
  f.state('state-terminal');
}

test('Windows real observer, live named Job recovery, detached descendant and replay', options, async t => {
  const f = await ownedTree(t), identity = backend.currentProcessIdentity();
  assert.equal(backend.verifyProcessExit(identity).status, 'active');
  const native = recovery.createNativeRecovery(f.state('state-before-recovery'));
  const result = control.recoverAttempt(f.context, f.id, adapterWith(native, (snapshot, actual) => {
    assert.equal(f.state('state-fence').recovery.status, 'active');
    assert.throws(() => control.beginAttempt(f.context, { request_sha256: H }), { code: 'verification_recovery_required' });
    const proof = actual(snapshot); f.write('native-proof', proof);
    assert.equal(proof.container_proof_basis, 'reopened_named_job');
    assert.equal(proof.descriptor_sha256, hash(f.descriptor));
    return proof;
  }));
  await settled(f, result);
  assert.equal(recovery.recoverAttempt(f.context, f.id).status, 'already_terminal');
  const next = control.beginAttempt(f.context, { request_sha256: H });
  assert.notEqual(next.owner.generation, f.owner.generation);
  assert.throws(() => recovery.recoverAttempt(f.context, f.id), { code: 'verification_attempt_mismatch' });
  control.recoverAttempt(f.context, { attempt_id: next.owner.attempt_id, generation: next.owner.generation });
});

test('Windows wrong host is rejected before native stop and wrong birth does not kill the live PID', options, async t => {
  const f = await ownedTree(t), bad = structuredClone(f.descriptor);
  bad.host.session_id++;
  assert.throws(() => backend.recoverContainer(bad), { code: 'native_observer_identity_mismatch' });
  for (const role of ['controller', 'keeper', 'worker']) {
    const id = { ...f.descriptor.identities[role], host: f.descriptor.host };
    assert.equal(backend.verifyProcessExit(id).status, 'active');
    const replaced = { ...id, os_creation_time: '2000-01-01T00:00:00.0000000Z' };
    assert.equal(backend.verifyProcessExit(replaced).status, 'exited');
    assert.equal(backend.verifyProcessExit(id).status, 'active');
  }
  await settled(f, recovery.recoverAttempt(f.context, f.id));
});

test('Windows controller death destroys Job without receipt and stays unconfirmed', options, async t => {
  const f = await ownedTree(t);
  f.controller.kill('SIGKILL'); await waitExit(f.controller); await delay(600);
  assert.throws(() => recovery.recoverAttempt(f.context, f.id), { code: 'recovery_job_reopen_unconfirmed' });
  const a = f.state('state-missing-job');
  assert.equal(a.claimed, true); assert.equal(a.cleanup.status, 'unconfirmed'); assert.equal(a.terminal, null);
  assert.throws(() => control.beginAttempt(f.context, { request_sha256: H }), { code: 'verification_recovery_required' });
});

test('Windows keeper death loses Job name and cannot substitute PID absence for cleanup', options, async t => {
  const f = await ownedTree(t);
  await f.command({ action: 'kill_keeper' });
  assert.throws(() => recovery.recoverAttempt(f.context, f.id), { code: 'recovery_job_reopen_unconfirmed' });
  const a = f.state('state-keeper-dead');
  assert.equal(a.claimed, true); assert.equal(a.cleanup.status, 'unconfirmed'); assert.equal(a.terminal, null);
});

test('Windows actual normal close receipt permits missing Job recovery', options, async t => {
  const f = await ownedTree(t), closed = await f.command({ action: 'close' });
  assert.equal(closed.proof.status, 'completed'); f.write('normal-close-observation', closed.proof);
  await f.command({ action: 'publish' });
  const a = f.state('state-persisted-receipt'), native = recovery.createNativeRecovery(a);
  const result = control.recoverAttempt(f.context, f.id, adapterWith(native, (snapshot, actual) => {
    const proof = actual(snapshot); f.write('native-proof', proof);
    assert.equal(proof.container_proof_basis, 'persisted_native_cleanup_receipt');
    assert.equal(proof.cleanup_receipt_sha256, hash(a.containment.cleanup_receipt)); return proof;
  }));
  await settled(f, result);
});

test('Windows late real receipt after fence preserves reservation and stale native failure', options, async t => {
  const f = await ownedTree(t); await f.command({ action: 'close' });
  const writerCode = `const fs=require('fs'),c=require(${JSON.stringify(controlPath)});const i=JSON.parse(fs.readFileSync(0,'utf8'));c.updateAttempt(i.context,i.owner,{type:'cleanup_proven',proof:i.proof});`;
  // Request proof already observed by the real controller; publication is delayed.
  const closed = await f.command({ action: 'close' });
  const native = recovery.createNativeRecovery(f.state('state-before-fence'));
  assert.throws(() => control.recoverAttempt(f.context, f.id, adapterWith(native, (snapshot, actual) => {
    const before = f.state('state-fence-before-receipt');
    const writer = runChild(writerCode, [], { context: f.context, owner: f.owner, proof: closed.proof });
    f.write('late-writer', { status: writer.status, stdout: writer.stdout, stderr: writer.stderr }); assert.equal(writer.status, 0, writer.stderr);
    const after = f.state('state-fence-after-receipt');
    assert.deepEqual(after.recovery, before.recovery); assert.equal(after.phase, before.phase); assert.equal(after.stop_reason, before.stop_reason);
    assert.throws(() => control.commitFinish(f.context, f.owner, { outcome: 'passed', ack_sha256: H, cleanup_proof: closed.proof }), { code: 'verification_recovery_in_progress' });
    return actual(snapshot); // snapshot has no receipt; genuine OpenJobObject fails.
  })), { code: 'recovery_job_reopen_unconfirmed' });
  assert.equal(f.state('state-stale-callback-failed').cleanup.status, 'unconfirmed');
  await settled(f, recovery.recoverAttempt(f.context, f.id));
});

test('Windows live recovery reservation rejects competitor and concurrent cancel is retained', options, async t => {
  const f = await ownedTree(t), native = recovery.createNativeRecovery(f.state('state-before-race'));
  const code = `const fs=require('fs'),c=require(${JSON.stringify(controlPath)}),r=require(${JSON.stringify(recoveryPath)});const i=JSON.parse(fs.readFileSync(0,'utf8'));const cancel=c.requestCancel(i.context,i.id);let failure;try{r.recoverAttempt(i.context,i.id);}catch(e){failure=e.code;}console.log(JSON.stringify({cancel:cancel.status,failure}));`;
  const result = control.recoverAttempt(f.context, f.id, adapterWith(native, (snapshot, actual) => {
    const child = runChild(code, [], { context: f.context, id: f.id });
    assert.equal(child.status, 0, child.stderr); const observed = JSON.parse(child.stdout); f.write('race-second-process', observed);
    assert.equal(observed.cancel, 'cancel_requested'); assert.equal(observed.failure, 'verification_recovery_in_progress');
    return actual(snapshot);
  }));
  await settled(f, result, 'cancelled'); assert.equal(result.attempt.cancel.requested, true);
});

test('Windows recoverer death before native action permits exact-owner takeover', options, async t => {
  const f = await ownedTree(t);
  const code = `const c=require(${JSON.stringify(controlPath)}),r=require(${JSON.stringify(recoveryPath)});const context={stateRoot:process.argv[1]},id=JSON.parse(process.argv[2]),a=r.createNativeRecovery(c.readStatus(context).attempt);const crash=()=>process.exit(29);crash.owner_identity=a.owner_identity;crash.verify_recoverer_exit=a.verify_recoverer_exit;c.recoverAttempt(context,id,crash);`;
  const child = runChild(code, [f.context.stateRoot, JSON.stringify(f.id)]);
  f.write('recoverer-crash', { status: child.status, stderr: child.stderr }); assert.equal(child.status, 29, child.stderr);
  assert.equal(f.state('state-crashed-reservation').recovery.status, 'active');
  const result = recovery.recoverAttempt(f.context, f.id); assert.equal(result.attempt.recovery.ordinal, 2);
  await settled(f, result);
});

test('Windows recoverer death after real cleanup before CAS stays fenced without durable receipt', options, async t => {
  const f = await ownedTree(t);
  const code = `const fs=require('fs'),c=require(${JSON.stringify(controlPath)}),r=require(${JSON.stringify(recoveryPath)});const context={stateRoot:process.argv[1]},id=JSON.parse(process.argv[2]),a=r.createNativeRecovery(c.readStatus(context).attempt);const crash=s=>{const proof=a(s);fs.writeFileSync(process.argv[3],JSON.stringify(proof,null,2));process.exit(29);};crash.owner_identity=a.owner_identity;crash.verify_recoverer_exit=a.verify_recoverer_exit;c.recoverAttempt(context,id,crash);`;
  const child = runChild(code, [f.context.stateRoot, JSON.stringify(f.id), path.join(f.root, 'actual-proof-before-crash.json')]);
  assert.equal(child.status, 29, child.stderr); assert.equal(JSON.parse(fs.readFileSync(path.join(f.root, 'actual-proof-before-crash.json'))).container_proof_basis, 'reopened_named_job');
  assert.equal(f.state('state-crashed-before-CAS').recovery.status, 'active');
  assert.throws(() => recovery.recoverAttempt(f.context, f.id), { code: 'recovery_job_reopen_unconfirmed' });
  const a = f.state('state-takeover-unconfirmed'); assert.equal(a.recovery.ordinal, 2); assert.equal(a.claimed, true); assert.equal(a.terminal, null);
  await waitExit(f.controller); const marker = fs.readFileSync(f.marker, 'utf8'); await delay(300); assert.equal(fs.readFileSync(f.marker, 'utf8'), marker);
});

test('Windows real helper completed JSON followed by transport timeout cannot release cleanup claim', options, async t => {
  const f = await ownedTree(t);
  // A trusted fault adapter wraps the actual unchanged helper in a PowerShell
  // invocation that delays transport exit after native output. The real
  // spawnSync timeout/error and partial stdout are returned unmodified.
  const code = `
    const cp=require('child_process'),fs=require('fs'),original=cp.spawnSync;
    cp.spawnSync=(exe,args,opts)=>{
      const input=opts?.input&&JSON.parse(opts.input);
      if(input?.action!=='recover')return original(exe,args,opts);
      const helper=args[args.indexOf('-File')+1],cleanup=args[args.indexOf('-CleanupMs')+1],pid=args[args.indexOf('-RecovererPid')+1];
      const command="& '"+helper.replace(/'/g,"''")+"' -CleanupMs "+cleanup+" -RecovererPid "+pid+"; Start-Sleep -Seconds 60";
      const actual=original(exe,['-NoProfile','-NonInteractive','-Command',command],{...opts,timeout:5000});
      fs.writeFileSync(process.argv[3],JSON.stringify({status:actual.status,signal:actual.signal,error:actual.error&&{code:actual.error.code,message:actual.error.message},stdout:actual.stdout,stderr:actual.stderr,fault_transport_timeout_ms:5000},null,2));
      return actual;
    };
    const c=require(${JSON.stringify(controlPath)}),r=require(${JSON.stringify(recoveryPath)}),context={stateRoot:process.argv[1]},id=JSON.parse(process.argv[2]);
    try{r.recoverAttempt(context,id);process.exitCode=2;}catch(e){console.log(JSON.stringify({code:e.code}));}`;
  const transportFile = path.join(f.root, 'actual-helper-transport-timeout.json');
  const child = runChild(code, [f.context.stateRoot, JSON.stringify(f.id), transportFile]);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(child.stdout).code, 'verification_recovery_transport_unconfirmed');
  const actual = JSON.parse(fs.readFileSync(transportFile));
  assert.equal(actual.error.code, 'ETIMEDOUT');
  const partial = JSON.parse(actual.stdout);
  assert.equal(partial.status, 'completed'); assert.equal(partial.active_processes, 0);
  assert.equal(partial.descriptor_sha256, hash(f.descriptor));
  const a = f.state('state-transport-timeout');
  assert.equal(a.claimed, true); assert.equal(a.cleanup.status, 'unconfirmed'); assert.equal(a.terminal, null);
  assert.equal(a.cleanup.native_transcript, null);
  assert.throws(() => control.beginAttempt(f.context, { request_sha256: H }), { code: 'verification_recovery_required' });
  await waitExit(f.controller);
  const marker = fs.readFileSync(f.marker, 'utf8'); await delay(300); assert.equal(fs.readFileSync(f.marker, 'utf8'), marker);
});
