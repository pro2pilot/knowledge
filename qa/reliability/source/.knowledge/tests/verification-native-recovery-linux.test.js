'use strict';
// Real Linux process/namespace integration. The portable state-machine and
// Windows transport suites do not substitute for these kernel observations.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const os=require('os');
const cp=require('child_process');
const crypto=require('crypto');
const control=require('../tools/lib/verification-control');
const recovery=require('../tools/lib/verification-recovery');
const backend=require('../tools/lib/verification-linux-namespace');
const H='a'.repeat(64);
const controlPath=require.resolve('../tools/lib/verification-control');
const backendPath=require.resolve('../tools/lib/verification-linux-namespace');
const recoveryPath=require.resolve('../tools/lib/verification-recovery');
function waitExit(child,allowanceMs=30000) {
  if(child.exitCode!==null || child.signalCode!==null) return Promise.resolve();
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('test_child_exit_unconfirmed')),allowanceMs);
    child.once('exit',()=>{clearTimeout(timer);resolve();});child.once('error',error=>{clearTimeout(timer);reject(error);});
  });
}
async function ownedTree(t) {
  const capability=backend.containmentCapability();
  assert.equal(capability.status,'requires_runtime_setup',JSON.stringify(capability));
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-recovery-native-'));
  const context={stateRoot:root},begun=control.beginAttempt(context,{request_sha256:H,
    profile:{work_budget_ms:180000,no_progress_ms:90000,cleanup_budget_ms:30000}});
  const marker=path.join(root,'descendant-heartbeat.txt');
  const controllerCode=`
    const c=require(${JSON.stringify(controlPath)}),b=require(${JSON.stringify(backendPath)}),fs=require('fs'),crypto=require('crypto');
    process.once('message',async input=>{
      try {
        const {context,owner,marker}=input;
        for(const role of ['watchdog','authority','keeper'])c.updateAttempt(context,owner,{type:'spawn_intent',role});
        const leaf="const fs=require('fs');setInterval(()=>fs.writeFileSync(process.argv[1],String(Date.now())),100);fs.writeFileSync(process.argv[1],'started');";
        const work="const cp=require('child_process');const leaf=cp.spawn(process.execPath,['-e',"+JSON.stringify(leaf)+",process.argv[1]],{detached:true,stdio:'ignore'});leaf.unref();process.send({workerReady:true});setInterval(()=>{},1000);";
        const {worker,job}=b.spawnLinuxContainedWorker(process.execPath,['-e',work,marker],
          {stdio:['ignore','ignore','pipe','ipc']},{lifetimeMs:210000,onFailure:()=>{}});
        worker.stderr.on('data',()=>{});
        await job.ready;
        const ids=job.identities;
        const hash=job.keeper_executable_sha256;
        for(const [index,role]of ['controller','worker','keeper'].entries())
          c.updateAttempt(context,owner,{type:'spawn_observed',spawn_id:index+1,pid:ids[role].pid,os_creation_time:ids[role].os_creation_time,executable_sha256:role==='controller'?crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'):hash});
        c.updateAttempt(context,owner,{type:'containment_bound',descriptor:job.descriptor,spawn_ids:[1,2,3]});
        const workReady=new Promise((resolve,reject)=>{worker.once('message',m=>m.workerReady?resolve():reject(new Error('worker_not_ready')));worker.once('error',reject);});
        c.assertResourceAvailable(context,owner);job.permit();await job.started;await workReady;
        process.send({ready:true,descriptor:job.descriptor});setInterval(()=>{},1000);
      }catch(error){process.send({error:error.code||error.message});process.exitCode=2;}
    });`;
  const controller=cp.spawn(process.execPath,['-e',controllerCode],{stdio:['ignore','ignore','pipe','ipc'],env:{...process.env}});
  let stderr='';controller.stderr.on('data',data=>stderr+=data.toString());
  t.after(async()=>{
    // A test guardian is cleanup only; it never changes the asserted outcome.
    // It targets only this test's persisted native descriptor and child handle.
    try {const a=control.readStatus(context).attempt;if(a?.claimed && a.containment) backend.recoverContainer(a.containment.descriptor,{cleanup_timeout_ms:30000});}catch{}
    if(controller.exitCode===null && controller.signalCode===null)controller.kill('SIGKILL');
    await waitExit(controller).catch(()=>{});fs.rmSync(root,{recursive:true,force:true});
  });
  const ready=new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('native_setup_deadline: '+stderr)),90000);
    controller.once('message',message=>{clearTimeout(timer);message.ready?resolve(message):reject(new Error(JSON.stringify(message)));});
    controller.once('error',error=>{clearTimeout(timer);reject(error);});
    controller.once('exit',(code,signal)=>{clearTimeout(timer);reject(new Error(`controller setup exit ${code}/${signal}: ${stderr}`));});
  });
  controller.send({context,owner:begun.owner,marker});
  const observed=await ready;
  // The descendant is deliberately detached, and remains inside the kernel
  // namespace. Its filesystem heartbeat is a supplementary behavioral check.
  const deadline=Date.now()+5000;
  while(!fs.existsSync(marker) && Date.now()<deadline) await new Promise(resolve=>setTimeout(resolve,25));
  assert(fs.existsSync(marker),'detached descendant started');
  return {context,root,controller,marker,descriptor:observed.descriptor,...begun,
    id:{attempt_id:begun.owner.attempt_id,generation:begun.owner.generation}};
}

test('Linux generic recovery terminates a live controller and detached descendants using exact native ownership',
  {skip:process.platform!=='linux',timeout:150000},async t=>{
    const f=await ownedTree(t);
    const result=recovery.recoverAttempt(f.context,f.id);
    assert.equal(result.status,'failed');assert.equal(result.ack_released,false);
    assert.equal(result.attempt.cleanup.status,'confirmed');assert(result.attempt.processes.every(p=>p.exit_observed));
    await waitExit(f.controller);
    const after=fs.readFileSync(f.marker,'utf8');await new Promise(resolve=>setTimeout(resolve,300));
    assert.equal(fs.readFileSync(f.marker,'utf8'),after,'no detached descendant writes after native cleanup');
    assert.equal(recovery.recoverAttempt(f.context,f.id).status,'already_terminal');
    assert.notEqual(control.beginAttempt(f.context,{request_sha256:H}).owner.generation,f.owner.generation);
  });

test('Linux native recovery resumes after the actual recoverer dies between kernel cleanup and control CAS',
  {skip:process.platform!=='linux',timeout:150000},async t=>{
    const f=await ownedTree(t);
    const code=`const c=require(${JSON.stringify(controlPath)}),r=require(${JSON.stringify(recoveryPath)});const context={stateRoot:process.argv[1]},id=JSON.parse(process.argv[2]),a=r.createNativeRecovery(c.readStatus(context).attempt);const crash=snapshot=>{a(snapshot);process.exit(29);};crash.owner_identity=a.owner_identity;crash.verify_recoverer_exit=a.verify_recoverer_exit;c.recoverAttempt(context,id,crash);`;
    const crashed=cp.spawnSync(process.execPath,['-e',code,f.root,JSON.stringify(f.id)],{encoding:'utf8',timeout:60000});
    assert.ifError(crashed.error);assert.equal(crashed.status,29,crashed.stderr);
    const before=control.readStatus(f.context).attempt;
    assert.equal(before.claimed,true);assert.equal(before.recovery.status,'active');
    assert.throws(()=>control.beginAttempt(f.context,{request_sha256:H}),{code:'verification_recovery_required'});
    const result=recovery.recoverAttempt(f.context,f.id);
    assert.equal(result.status,'failed');assert.equal(result.ack_released,false);assert.equal(result.attempt.recovery.ordinal,2);
    assert.equal(result.attempt.cleanup.status,'confirmed');await waitExit(f.controller);
    const after=fs.readFileSync(f.marker,'utf8');await new Promise(resolve=>setTimeout(resolve,300));
    assert.equal(fs.readFileSync(f.marker,'utf8'),after);
  });
