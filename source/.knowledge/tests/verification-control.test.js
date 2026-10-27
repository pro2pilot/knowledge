'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path'),os=require('os'),cp=require('child_process'),crypto=require('crypto');
const control=require('../tools/lib/verification-control');
const {removeTempDirStrict}=require('../tools/lib/strict-temp-cleanup');
const source=path.resolve(__dirname,'..'),modulePath=path.join(source,'tools/lib/verification-control.js');
const digest=value=>crypto.createHash('sha256').update(value).digest('hex'),H=digest('synthetic verification request');
function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-vctl-'));t.after(()=>removeTempDirStrict(root));return {root,context:{stateRoot:root}};}
const start=f=>control.beginAttempt(f.context,{request_sha256:H,profile:{work_budget_ms:10000,no_progress_ms:3000,cleanup_budget_ms:2000}});
const noSpawn=o=>({method:'no_processes_started',attempt_id:o.attempt_id,generation:o.generation});
function done(f,o,outcome='failed'){return control.commitFinish(f.context,o,{outcome,cleanup_proof:noSpawn(o),...(outcome==='passed'?{ack_sha256:H}:{})});}
function cli(f,...args){return cp.spawnSync(process.execPath,[path.join(source,'tools/verification-control.js'),...args,'--mode=repo','--state-root='+f.root,'--project-knowledge-root='+f.root,'--system-root='+source,'--target-root='+f.root,'--json'],{encoding:'utf8',timeout:10000,windowsHide:true,env:{...process.env,KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1'}});}

test('status is read-only; claim is durable before owner capability is returned',t=>{
 const f=fixture(t);assert.equal(control.readStatus(f.context).status,'idle');assert.deepEqual(fs.readdirSync(f.root),[]);
 const s=start(f),file=path.join(f.root,'maintenance/verification-control/active.json'),raw=fs.readFileSync(file,'utf8');
 assert.equal(JSON.parse(raw).claimed,true);assert(!raw.includes(s.owner.token));assert(!JSON.stringify(control.readStatus(f.context)).includes('owner_token'));
 assert.throws(()=>start(f),{code:'verification_recovery_required'});assert.throws(()=>control.assertResourceAvailable(f.context),{code:'verification_recovery_required'});
 assert.equal(control.assertResourceAvailable(f.context,s.owner).status,'available');done(f,s.owner);assert.equal(control.readStatus(f.context).status,'terminal');
});
test('owner token, generation and revision are required for owner mutation',t=>{
 const f=fixture(t),s=start(f);
 for(const owner of [{...s.owner,token:'0'.repeat(64)},{...s.owner,generation:'0'.repeat(32)}])assert.throws(()=>control.updateAttempt(f.context,owner,{type:'phase',phase:'preparing'}),{code:'verification_owner_invalid'});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'phase',phase:'preparing',expected_revision:900}),{code:'verification_control_conflict'});
 const updated=control.updateAttempt(f.context,s.owner,{type:'phase',phase:'running'});assert.equal(updated.attempt.phase,'running');
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'phase',phase:'preparing'}),{code:'verification_phase_invalid'});
});
test('accepted cancellation serializes with finish, never releases a late ACK',t=>{
 const f=fixture(t),s=start(f),request={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 const first=control.requestCancel(f.context,request),again=control.requestCancel(f.context,request);assert.equal(first.status,'cancel_requested');assert.equal(again.attempt.revision,first.attempt.revision);
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'worker'}),{code:'verification_stopped'});
 const finish=done(f,s.owner,'passed');assert.equal(finish.status,'cancelled');assert.equal(finish.ack_released,false);assert.equal(finish.attempt.terminal.ack_sha256,null);
 assert.equal(control.requestCancel(f.context,request).status,'already_terminal');
});
test('committed ACK wins before cancellation with explicit already_terminal',t=>{
 const f=fixture(t),s=start(f);const result=done(f,s.owner,'passed');assert.equal(result.ack_released,true);assert.equal(result.attempt.terminal.ack_sha256,H);
 const cancel=control.requestCancel(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation});assert.equal(cancel.status,'already_terminal');assert.equal(cancel.attempt.cancel.requested,false);
});
test('timeout latch is irreversible even when a valid late ACK arrives',t=>{
 const f=fixture(t),s=start(f);control.updateAttempt(f.context,s.owner,{type:'stop',reason:'progress_timeout'});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'artifact_verified',ordinal:1,evidence_sha256:H}),{code:'verification_stopped'});
 const result=done(f,s.owner,'passed');assert.equal(result.status,'timed_out');assert.equal(result.ack_released,false);
});
test('only unique trusted milestones advance progress, not stdout or replay',t=>{
 const f=fixture(t),s=start(f);
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'stdout',ordinal:1,evidence_sha256:H}),{code:'verification_progress_invalid'});
 control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'artifact_verified',ordinal:1,evidence_sha256:H});
 control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'artifact_verified',ordinal:2,evidence_sha256:digest('second artifact')});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'artifact_verified',ordinal:3,evidence_sha256:H}),{code:'verification_progress_invalid'});
 control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'readback_complete',ordinal:3,evidence_sha256:H});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'readback_complete',ordinal:4,evidence_sha256:digest('replay')}),{code:'verification_progress_invalid'});
 assert.equal(control.readStatus(f.context).attempt.progress.sequence,3);
});
test('unknown spawn intent quarantines the root and cannot be recovered by PID assumptions',t=>{
 const f=fixture(t),s=start(f);const intent=control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'});assert.equal(intent.spawn_id,1);
 control.updateAttempt(f.context,s.owner,{type:'cleanup_started'});control.updateAttempt(f.context,s.owner,{type:'cleanup_unconfirmed'});
 assert.throws(()=>done(f,s.owner),{code:'verification_cleanup_unconfirmed'});assert.throws(()=>start(f),{code:'verification_recovery_required'});
 assert.equal(control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation}).status,'requires_native_recovery');
 assert.throws(()=>control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation},()=>noSpawn(s.owner)),{code:'verification_cleanup_unconfirmed'});
 assert.equal(control.readStatus(f.context).attempt.claimed,true);
});
test('logical process identity is useful status but insufficient cross-session recovery',t=>{
 const f=fixture(t),s=start(f),nonce='b'.repeat(32);control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'});
 control.updateAttempt(f.context,s.owner,{type:'spawn_observed',spawn_id:1,pid:process.pid,os_creation_time:null,logical_nonce:nonce,executable_sha256:H});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'process_exit',spawn_id:1,pid:process.pid,os_creation_time:null,logical_nonce:'c'.repeat(32),method:'process_handle_signaled'}),{code:'verification_process_identity_mismatch'});
 const p={status:'completed',method:'windows_job_object',active_processes:0,keeper_exited:true,evidence_sha256:H,attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 assert.throws(()=>control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation},()=>p),{code:'verification_cleanup_unconfirmed'});
 control.updateAttempt(f.context,s.owner,{type:'process_exit',spawn_id:1,pid:process.pid,os_creation_time:null,logical_nonce:nonce,method:'process_handle_signaled'});
 assert.throws(()=>control.commitFinish(f.context,s.owner,{outcome:'failed',cleanup_proof:p}),{code:'verification_recovery_in_progress'});
 assert.equal(control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation}).status,'failed');
});
test('Job zero alone is insufficient when a known child handle has not signaled exit',t=>{
 const f=fixture(t),s=start(f),birth='2026-10-20T10:00:00.000Z';control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'keeper'});
 control.updateAttempt(f.context,s.owner,{type:'spawn_observed',spawn_id:1,pid:1234,os_creation_time:birth,executable_sha256:H});
 const p={status:'completed',method:'windows_job_object',active_processes:0,keeper_exited:true,evidence_sha256:H,attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 assert.throws(()=>control.commitFinish(f.context,s.owner,{outcome:'failed',cleanup_proof:p}),{code:'verification_cleanup_unconfirmed'});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'process_exit',spawn_id:1,pid:1234,os_creation_time:'2026-10-20T11:00:00.000Z',method:'process_handle_signaled'}),{code:'verification_process_identity_mismatch'});
 control.updateAttempt(f.context,s.owner,{type:'process_exit',spawn_id:1,pid:1234,os_creation_time:birth,method:'process_handle_signaled'});
 assert.equal(control.commitFinish(f.context,s.owner,{outcome:'failed',cleanup_proof:p}).status,'failed');
});
test('native recovery fences first and preserves cancellation accepted during its external probe',t=>{
 const f=fixture(t),s=start(f),id={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 const recovered=control.recoverAttempt(f.context,id,()=>{control.requestCancel(f.context,id);return noSpawn(s.owner);});
 assert.equal(recovered.status,'cancelled');assert.equal(recovered.ack_released,false);
 assert.equal(control.recoverAttempt(f.context,id).status,'already_terminal');
});
test('CLI status/cancel/recover expose no owner token and never accept a free-form reason/proof',t=>{
 const f=fixture(t),s=start(f),args=['--attempt='+s.owner.attempt_id,'--generation='+s.owner.generation];
 const status=cli(f,'status');assert.equal(status.status,0,status.stderr);assert.equal(JSON.parse(status.stdout).status,'blocked');assert(!status.stdout.includes(s.owner.token));
 control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'});
 const cancel=cli(f,'cancel',...args);assert.equal(cancel.status,0,cancel.stderr);assert.equal(JSON.parse(cancel.stdout).status,'cancel_requested');
 const recover=cli(f,'recover',...args);assert.equal(recover.status,2);assert.equal(JSON.parse(recover.stdout).status,'requires_native_recovery');
 assert.equal(cli(f,'cancel',...args,'--reason-code=private/customer@example.test').status,2);
 assert.equal(cli(f,'recover',...args,'--force=true').status,2);
});
test('empty/malformed/removed active state and hardlinks do not become free admission',t=>{
 const f=fixture(t),s=start(f),file=path.join(f.root,'maintenance/verification-control/active.json'),bytes=fs.readFileSync(file);
 for(const bad of ['', '{}', '{"phase":"terminal"}']){fs.writeFileSync(file,bad);assert.throws(()=>control.readStatus(f.context));assert.throws(()=>start(f));}
 fs.writeFileSync(file,bytes);const link=path.join(f.root,'linked-state.json');fs.linkSync(file,link);assert.throws(()=>control.readStatus(f.context),{code:'verification_control_unsafe'});fs.unlinkSync(link);
 fs.unlinkSync(file);assert.throws(()=>control.readStatus(f.context),{code:'verification_control_missing'});assert.throws(()=>start(f),{code:'verification_control_missing'});
 assert(s.owner.token);
});
test('terminal history is preserved and a different generation cannot cancel the next attempt',t=>{
 const f=fixture(t),first=start(f);done(f,first.owner);const before=fs.readFileSync(path.join(f.root,'maintenance/verification-control/active.json'));
 const second=start(f),archive=path.join(f.root,'maintenance/verification-control/attempts',first.owner.attempt_id+'.json');assert.deepEqual(fs.readFileSync(archive),before);
 assert.throws(()=>control.requestCancel(f.context,{attempt_id:second.owner.attempt_id,generation:first.owner.generation}),{code:'verification_attempt_mismatch'});
});
test('two actual processes contend for one persisted claim; exited coordinator does not release it',t=>{
 const f=fixture(t),code=`const c=require(${JSON.stringify(modulePath)});try{c.beginAttempt({stateRoot:process.argv[1]},{request_sha256:${JSON.stringify(H)}});console.log('claimed')}catch(e){console.log(e.code);process.exitCode=2}`;
 // Both launched before either is awaited. The short mutex protects issuance.
 const children=[0,1].map(()=>cp.spawn(process.execPath,['-e',code,f.root],{stdio:['ignore','pipe','pipe'],windowsHide:true}));
 return Promise.all(children.map(child=>new Promise((resolve,reject)=>{let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);child.on('error',reject);child.on('close',code=>resolve({code,out:out.trim(),err}));}))).then(rows=>{
   assert.equal(rows.filter(r=>r.code===0&&r.out==='claimed').length,1,JSON.stringify(rows));assert.equal(rows.filter(r=>r.code===2&&r.out==='verification_recovery_required').length,1,JSON.stringify(rows));
   assert.equal(control.readStatus(f.context).status,'blocked');assert.throws(()=>start(f),{code:'verification_recovery_required'});
 });
});
test('profile bounds reject disabled, string, boolean, overflow and unknown options',()=>{
 for(const p of [{work_budget_ms:0},{work_budget_ms:'100'},{no_progress_ms:true},{cleanup_budget_ms:Infinity},{cleanup_budget_ms:null},{extra:'heartbeat'}])assert.throws(()=>control.normalizeProfile(p));
 assert.deepEqual(control.normalizeProfile({work_budget_ms:1000}),{work_budget_ms:1000,no_progress_ms:60000,cleanup_budget_ms:30000});
 assert.deepEqual(control.normalizeProfile(),{work_budget_ms:120000,no_progress_ms:60000,cleanup_budget_ms:30000});
 assert.equal(control.normalizeProfile({no_progress_ms:0}).no_progress_ms,0);
 assert.deepEqual(control.normalizeProfile({work_budget_ms:600000*100000,no_progress_ms:600000*100000,cleanup_budget_ms:3600000}),{work_budget_ms:600000*100000,no_progress_ms:600000*100000,cleanup_budget_ms:3600000});
 for(const p of [{work_budget_ms:600000*100000+1},{no_progress_ms:600000*100000+1},{no_progress_ms:-1},{cleanup_budget_ms:3600001}])assert.throws(()=>control.normalizeProfile(p),{code:'verification_profile_invalid'});
});
test('trusted recovery may commit exact OS-handle exit observations but cannot substitute a reused PID',t=>{
 const f=fixture(t),s=start(f),birth='2026-10-20T10:00:00.000Z',id={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'keeper'});
 control.updateAttempt(f.context,s.owner,{type:'spawn_observed',spawn_id:1,pid:1234,os_creation_time:birth,executable_sha256:H});
 control.updateAttempt(f.context,s.owner,{type:'cleanup_started'});control.updateAttempt(f.context,s.owner,{type:'cleanup_unconfirmed'});
 const proof={status:'completed',method:'windows_job_object',active_processes:0,keeper_exited:true,evidence_sha256:H,...id};
 assert.throws(()=>control.recoverAttempt(f.context,id,()=>({...proof,process_exits:[{spawn_id:1,pid:1234,os_creation_time:'2026-10-20T11:00:00.000Z',method:'process_handle_signaled'}]})),{code:'verification_process_identity_mismatch'});
 assert.equal(control.readStatus(f.context).attempt.claimed,true);
 const result=control.recoverAttempt(f.context,id,()=>({...proof,process_exits:[{spawn_id:1,pid:1234,os_creation_time:birth,method:'process_handle_signaled'}]}));
 assert.equal(result.status,'failed');assert.equal(result.ack_released,false);assert.equal(result.attempt.processes[0].exit_observed,true);
});
test('actual coordinator exit during cleanup leaves a live owned child quarantined across processes',async t=>{
 const f=fixture(t),leaf=cp.spawn(process.execPath,['-e',"process.stdout.write('ready');setInterval(()=>{},1000)"],{stdio:['ignore','pipe','pipe'],windowsHide:true});
 try{
  await new Promise((resolve,reject)=>{leaf.stdout.once('data',resolve);leaf.once('error',reject);});
  const actor=`const c=require(${JSON.stringify(modulePath)}),ctx={stateRoot:process.argv[1]},s=c.beginAttempt(ctx,{request_sha256:${JSON.stringify(H)}});c.updateAttempt(ctx,s.owner,{type:'spawn_intent',role:'worker'});c.updateAttempt(ctx,s.owner,{type:'spawn_observed',spawn_id:1,pid:Number(process.argv[2]),logical_nonce:'d'.repeat(32),executable_sha256:${JSON.stringify(H)}});c.updateAttempt(ctx,s.owner,{type:'cleanup_started'});console.log('cleanup-started');`;
  const issued=cp.spawnSync(process.execPath,['-e',actor,f.root,String(leaf.pid)],{encoding:'utf8',timeout:10000,windowsHide:true});assert.equal(issued.status,0,issued.stderr);assert.equal(issued.stdout.trim(),'cleanup-started');assert.equal(leaf.exitCode,null);
  const status=control.readStatus(f.context);assert.equal(status.attempt.phase,'cleanup_pending');assert.equal(status.attempt.processes[0].pid,leaf.pid);assert.throws(()=>start(f),{code:'verification_recovery_required'});
  const result=cli(f,'recover','--attempt='+status.attempt.attempt_id,'--generation='+status.attempt.generation);assert.equal(result.status,2);assert.equal(JSON.parse(result.stdout).status,'requires_native_recovery');assert.equal(leaf.exitCode,null);
 }finally{
  if(leaf.exitCode===null && leaf.signalCode===null){const closed=new Promise(resolve=>leaf.once('close',resolve));leaf.kill('SIGKILL');await closed;}
 }
 assert.equal(control.readStatus(f.context).status,'blocked','Even actual child exit is not automatic recovery authorization');
});
test('trusted runtime observation displays stage/time without advancing progress or changing ownership',t=>{
 const f=fixture(t),s=start(f),observation={type:'observation',stage:'command',elapsed_ms:100.5,last_meaningful_progress_elapsed_ms:40.5,progress_signal_available:false,wait_reason:'work'};
 const snapshot=control.updateAttempt(f.context,s.owner,observation).attempt;assert.equal(snapshot.progress.sequence,0);assert.equal(snapshot.claimed,true);assert.equal(snapshot.terminal,null);
 const before=fs.readFileSync(path.join(f.root,'maintenance/verification-control/active.json')),status=control.readStatus(f.context);assert.equal(status.current_stage,'command');assert.equal(status.timing.observed_elapsed_ms,100.5);assert.equal(status.timing.since_meaningful_progress_ms,null);assert.equal(status.waiting_reason,'work');assert.equal(status.timing.elapsed_source,'wall_clock_estimate');
 assert.deepEqual(fs.readFileSync(path.join(f.root,'maintenance/verification-control/active.json')),before,'status does not persist fresh timestamps');
 control.requestCancel(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation});assert.equal(control.readStatus(f.context).waiting_reason,'cancel');
 control.updateAttempt(f.context,s.owner,{type:'cleanup_started'});assert.equal(control.readStatus(f.context).current_stage,'cleanup');assert.equal(control.readStatus(f.context).attempt.claimed,true);
});
test('observation rejects fabricated stages/types, clock regression and cannot override cancel into ACK',t=>{
 const f=fixture(t),s=start(f),event={type:'observation',stage:'test_setup',elapsed_ms:50,last_meaningful_progress_elapsed_ms:20,progress_signal_available:true,wait_reason:'work'};control.updateAttempt(f.context,s.owner,event);
 for(const change of [{stage:'stdout'},{elapsed_ms:'100'},{progress_signal_available:1},{last_meaningful_progress_elapsed_ms:100}])assert.throws(()=>control.updateAttempt(f.context,s.owner,{...event,...change}),{code:'verification_observation_invalid'});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{...event,elapsed_ms:49}),{code:'verification_observation_stale'});
 control.requestCancel(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation});control.updateAttempt(f.context,s.owner,{...event,elapsed_ms:60});assert.equal(control.readStatus(f.context).waiting_reason,'cancel');assert.equal(done(f,s.owner,'passed').ack_released,false);
});
function trackedController(f,s,role='watchdog',exited=true,pid=process.pid){
 control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role});
 if(pid!==null)control.updateAttempt(f.context,s.owner,{type:'spawn_observed',spawn_id:1,pid,logical_nonce:s.owner.generation,executable_sha256:H});
 if(exited && pid!==null)control.updateAttempt(f.context,s.owner,{type:'process_exit',spawn_id:1,pid,logical_nonce:s.owner.generation,method:'process_handle_signaled'});
 control.updateAttempt(f.context,s.owner,{type:'cleanup_started'});control.updateAttempt(f.context,s.owner,{type:'cleanup_unconfirmed'});
}
test('controller-only cleanup admits exact durably observed watchdog exit without claiming a Job',t=>{
 const f=fixture(t),s=start(f);trackedController(f,s);
 const proof={attempt_id:s.owner.attempt_id,generation:s.owner.generation,status:'completed',method:'controller_only',evidence_sha256:H};
 assert.throws(()=>control.commitFinish(f.context,s.owner,{outcome:'passed',cleanup_proof:proof,ack_sha256:H}),{code:'verification_ack_invalid'});
 control.requestCancel(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation});
 const result=control.commitFinish(f.context,s.owner,{outcome:'failed',cleanup_proof:proof});assert.equal(result.status,'cancelled');assert.equal(result.ack_released,false);
});
test('controller-only CLI recovery terminalizes only existing handle-exit evidence and is idempotent',t=>{
 const f=fixture(t),s=start(f);trackedController(f,s);const args=['--attempt='+s.owner.attempt_id,'--generation='+s.owner.generation];
 const recovered=cli(f,'recover',...args);assert.equal(recovered.status,0,recovered.stderr);assert.equal(JSON.parse(recovered.stdout).status,'failed');assert.equal(JSON.parse(recovered.stdout).ack_released,false);
 assert.equal(JSON.parse(cli(f,'recover',...args).stdout).status,'already_terminal');
});
test('controller-only recovery refuses unknown PID or missing exit instead of testing process liveness',t=>{
 for(const [pid,exited] of [[null,false],[process.pid,false]]){
  const f=fixture(t),s=start(f);trackedController(f,s,'watchdog',exited,pid);const id={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
  assert.equal(control.recoverAttempt(f.context,id).status,'requires_native_recovery');assert.equal(control.readStatus(f.context).attempt.claimed,true);
 }
});
test('controller-only recovery refuses authority/keeper roles, extra intents, and mismatched generation',t=>{
 for(const role of ['authority','keeper']){const f=fixture(t),s=start(f);trackedController(f,s,role);assert.equal(control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation}).status,'requires_native_recovery');}
 const f=fixture(t),s=start(f);control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'});control.updateAttempt(f.context,s.owner,{type:'spawn_observed',spawn_id:1,pid:process.pid,logical_nonce:s.owner.generation,executable_sha256:H});control.updateAttempt(f.context,s.owner,{type:'process_exit',spawn_id:1,pid:process.pid,logical_nonce:s.owner.generation,method:'process_handle_signaled'});control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'authority'});control.updateAttempt(f.context,s.owner,{type:'cleanup_started'});control.updateAttempt(f.context,s.owner,{type:'cleanup_unconfirmed'});
 assert.equal(control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation}).status,'requires_native_recovery');assert.throws(()=>control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:'0'.repeat(32)}),{code:'verification_attempt_mismatch'});
 const g=fixture(t),v=start(g);control.updateAttempt(g.context,v.owner,{type:'spawn_intent',role:'watchdog'});control.updateAttempt(g.context,v.owner,{type:'spawn_observed',spawn_id:1,pid:process.pid,logical_nonce:v.owner.generation,executable_sha256:H});control.updateAttempt(g.context,v.owner,{type:'process_exit',spawn_id:1,pid:process.pid,logical_nonce:v.owner.generation,method:'process_handle_signaled'});control.updateAttempt(g.context,v.owner,{type:'spawn_intent',role:'authority'});control.updateAttempt(g.context,v.owner,{type:'spawn_observed',spawn_id:2,pid:process.pid+1,logical_nonce:v.owner.generation,executable_sha256:H});control.updateAttempt(g.context,v.owner,{type:'process_exit',spawn_id:2,pid:process.pid+1,logical_nonce:v.owner.generation,method:'process_handle_signaled'});control.updateAttempt(g.context,v.owner,{type:'cleanup_started'});control.updateAttempt(g.context,v.owner,{type:'cleanup_unconfirmed'});assert.equal(control.recoverAttempt(g.context,{attempt_id:v.owner.attempt_id,generation:v.owner.generation}).status,'requires_native_recovery');
});


test('empty-list explicit recovery releases no ACK and makes the former owner unable to spawn',t=>{
 for(const cancelled of [false,true]){
  const f=fixture(t),s=start(f),id={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
  control.updateAttempt(f.context,s.owner,{type:'phase',phase:'preparing'});
  if(cancelled)control.requestCancel(f.context,id);
  const result=cli(f,'recover','--attempt='+id.attempt_id,'--generation='+id.generation);assert.equal(result.status,0,result.stderr);
  const terminal=JSON.parse(result.stdout);assert.equal(terminal.status,cancelled?'cancelled':'failed');assert.equal(terminal.ack_released,false);assert.deepEqual(terminal.attempt.processes,[]);assert.equal(terminal.attempt.terminal.ack_sha256,null);
  assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'}),{code:'verification_already_terminal'});
  const next=start(f);assert.notEqual(next.owner.generation,s.owner.generation);
  assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'}),{code:'verification_owner_invalid'});done(f,next.owner);
 }
});

// A fault barrier at the short-mutex boundary: the regular implementation has
// already read its snapshot; a second real writer commits before it acquires
// that mutex. No state bytes or implementation decisions are fabricated.
function beforeMutexOnce(action,invoke){
 const locks=require('../tools/lib/contained-lock-manager'),original=locks.withContainedLock,old=require.cache[modulePath];let fired=false;
 try{
  locks.withContainedLock=(options,callback)=>{if(!fired){fired=true;action();}return original(options,callback);};
  delete require.cache[modulePath];const fresh=require(modulePath);return invoke(fresh);
 }finally{locks.withContainedLock=original;require.cache[modulePath]=old;}
}

test('empty recovery rejects a stale snapshot when another actual process persists a spawn intent',t=>{
 const f=fixture(t),s=start(f),id={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 const actor=`const c=require(${JSON.stringify(modulePath)}),i=JSON.parse(require('fs').readFileSync(0,'utf8'));c.updateAttempt(i.context,i.owner,{type:'spawn_intent',role:'watchdog'});process.stdout.write('intent-persisted');`;
 assert.throws(()=>beforeMutexOnce(()=>{
  const child=cp.spawnSync(process.execPath,['-e',actor],{input:JSON.stringify({context:f.context,owner:s.owner}),encoding:'utf8',timeout:10000,windowsHide:true});assert.equal(child.status,0,child.stderr);assert.equal(child.stdout,'intent-persisted');
 },fresh=>fresh.recoverAttempt(f.context,id)),{code:'verification_control_conflict'});
 assert.equal(control.readStatus(f.context).attempt.processes.length,1);assert.equal(control.recoverAttempt(f.context,id).status,'requires_native_recovery');assert.throws(()=>start(f),{code:'verification_recovery_required'});
});

test('empty recovery conflicts if accepted cancellation changes its snapshot before CAS',t=>{
 const f=fixture(t),s=start(f),id={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 assert.throws(()=>beforeMutexOnce(()=>control.requestCancel(f.context,id),fresh=>fresh.recoverAttempt(f.context,id)),{code:'verification_control_conflict'});
 assert.equal(control.readStatus(f.context).attempt.claimed,true);
 const terminal=control.recoverAttempt(f.context,id);assert.equal(terminal.status,'cancelled');assert.equal(terminal.ack_released,false);
});

test('before-syscall abortion retracts the last unknown watchdog and permits cancelled no-spawn recovery',t=>{
 const f=fixture(t),s=start(f),id={attempt_id:s.owner.attempt_id,generation:s.owner.generation};
 const spawned=control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'});control.requestCancel(f.context,id);
 control.updateAttempt(f.context,s.owner,{type:'spawn_aborted',spawn_id:spawned.spawn_id,reason:'before_spawn_syscall',expected_revision:control.readStatus(f.context).attempt.revision});
 assert.deepEqual(control.readStatus(f.context).attempt.processes,[]);
 const recovered=control.recoverAttempt(f.context,id);assert.equal(recovered.status,'cancelled');assert.equal(recovered.ack_released,false);
});

test('spawn abortion rejects other roles, observed watchdogs, a non-last intent and an unsupported reason',t=>{
 for(const role of ['authority','keeper','worker','command']){
  const f=fixture(t),s=start(f);control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role});
  assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'spawn_aborted',spawn_id:1,reason:'before_spawn_syscall'}),{code:'verification_spawn_invalid'});assert.equal(control.readStatus(f.context).attempt.processes.length,1);
 }
 const f=fixture(t),s=start(f);control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'spawn_aborted',spawn_id:1,reason:'pid_not_found'}),{code:'verification_spawn_invalid'});
 control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'authority'});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{type:'spawn_aborted',spawn_id:1,reason:'before_spawn_syscall'}),{code:'verification_spawn_invalid'});
 const g=fixture(t),v=start(g);control.updateAttempt(g.context,v.owner,{type:'spawn_intent',role:'watchdog'});control.updateAttempt(g.context,v.owner,{type:'spawn_observed',spawn_id:1,pid:process.pid,logical_nonce:v.owner.generation,executable_sha256:H});
 assert.throws(()=>control.updateAttempt(g.context,v.owner,{type:'spawn_aborted',spawn_id:1,reason:'before_spawn_syscall'}),{code:'verification_spawn_invalid'});
 assert.equal(control.recoverAttempt(g.context,{attempt_id:v.owner.attempt_id,generation:v.owner.generation}).status,'requires_native_recovery');
});

test('spawn abortion requires owner generation and expected revision and cannot release earlier unknown authority',t=>{
 const f=fixture(t),s=start(f);control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'authority'});control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'watchdog'});
 const event={type:'spawn_aborted',spawn_id:2,reason:'before_spawn_syscall'};
 assert.throws(()=>control.updateAttempt(f.context,{...s.owner,generation:'0'.repeat(32)},event),{code:'verification_owner_invalid'});
 assert.throws(()=>control.updateAttempt(f.context,s.owner,{...event,expected_revision:1}),{code:'verification_control_conflict'});
 control.updateAttempt(f.context,s.owner,event);assert.equal(control.readStatus(f.context).attempt.processes.length,1);
 assert.equal(control.recoverAttempt(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation}).status,'requires_native_recovery');assert.throws(()=>start(f),{code:'verification_recovery_required'});
});

test('commitFinish checks a valid candidate deadline under CAS and preserves cancellation priority',t=>{
 for(const cancelled of [false,true]){
  const f=fixture(t),s=start(f);if(cancelled)control.requestCancel(f.context,{attempt_id:s.owner.attempt_id,generation:s.owner.generation});
  const terminal=control.commitFinish(f.context,s.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:noSpawn(s.owner),deadline_ns:String(process.hrtime.bigint()-1n)});
  assert.equal(terminal.status,cancelled?'cancelled':'failed');assert.equal(terminal.ack_released,false);assert.equal(terminal.attempt.terminal.ack_sha256,null);
 }
 const f=fixture(t),s=start(f);assert.equal(control.commitFinish(f.context,s.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:noSpawn(s.owner),deadline_ns:String(process.hrtime.bigint()+10000000000n)}).ack_released,true);
});

test('candidate deadline expiring while finish waits for the short mutex releases no ACK',t=>{
 const f=fixture(t),s=start(f),deadline=process.hrtime.bigint()+30000000n;
 const terminal=beforeMutexOnce(()=>{while(process.hrtime.bigint()<=deadline){}},fresh=>fresh.commitFinish(f.context,s.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:noSpawn(s.owner),deadline_ns:String(deadline)}));
 assert.equal(terminal.status,'failed');assert.equal(terminal.ack_released,false);assert.equal(terminal.attempt.stop_reason,'failure');assert.equal(terminal.attempt.terminal.ack_sha256,null);
});


// These barriers belong to the owned supervisor, after native invocation
// admission. The public facade now crosses a process boundary, so patching
// its caller's control module cannot inject cancellation into that worker.
// Stub only the already-tested native admission/preflight here; the durable
// control ledger and the watchdog's actual child-handle wait remain real.
// Public native cancellation is covered in reliability-kve-invocation-public.
function ownedControlBarrier(f,{at,cancel=false,expire=false}){
 const supervisorPath=path.join(source,'tools/lib/verification-supervisor.js'),oldCache=require.cache[supervisorPath],begin=control.beginAttempt,update=control.updateAttempt,spawnSync=cp.spawnSync;
 const invocation=require('../tools/lib/verification-invocation'),admit=invocation.admitWorkerInvocation;
 const linux=process.platform==='linux'?require('../tools/lib/verification-linux-namespace'):null,capability=linux?.containmentCapability;
 const spawned=[],started=process.hrtime.bigint(),timeoutMs=1500;let owner,barrierHits=0,admissions=0;
 const barrier=()=>{barrierHits++;if(cancel)control.requestCancel(f.context,{attempt_id:owner.attempt_id,generation:owner.generation});if(expire)while(process.hrtime.bigint()<started+BigInt(timeoutMs+5)*1000000n){}};
 try{
  invocation.admitWorkerInvocation=()=>{admissions++;return undefined;};
  if(linux)linux.containmentCapability=()=>({status:'requires_runtime_setup'});
  control.beginAttempt=(context,options)=>{const result=begin(context,options);owner=result.owner;if(at==='claimed')barrier();return result;};
  control.updateAttempt=(context,o,event)=>{const result=update(context,o,event);if(at==='intent'&&event.type==='spawn_intent'&&event.role==='watchdog')barrier();return result;};
  cp.spawnSync=(command,args,options)=>{const child=spawnSync(command,args,options);spawned.push({command,args,pid:child.pid,status:child.status,signal:child.signal});return child;};
  delete require.cache[supervisorPath];const supervisor=require(supervisorPath);let error;
  try{supervisor.__owned.runSupervised({stateRoot:f.root,repoRoot:f.root,tests:[{id:'not-run'}],verificationPolicy:{work_budget_ms:timeoutMs,no_progress_ms:0,cleanup_budget_ms:1000}},timeoutMs,started);}catch(e){error=e;}
  assert.equal(admissions,1,'The owned supervisor must reach the isolated admission boundary exactly once');
  assert.equal(barrierHits,1,'The requested durable boundary must actually execute; a caller-side patch is insufficient. Observed: '+String(error?.code)+': '+String(error?.message));
  return {error,spawned,status:control.readStatus(f.context)};
 }finally{invocation.admitWorkerInvocation=admit;if(linux)linux.containmentCapability=capability;control.beginAttempt=begin;control.updateAttempt=update;cp.spawnSync=spawnSync;if(oldCache)require.cache[supervisorPath]=oldCache;else delete require.cache[supervisorPath];}
}

test('owned supervisor observes cancellation after durable claim before any inner process intent or syscall',{skip:!['win32','linux'].includes(process.platform)},t=>{
 const f=fixture(t),r=ownedControlBarrier(f,{at:'claimed',cancel:true});assert.equal(r.error?.code,'verification_cancelled');assert.deepEqual(r.spawned,[]);assert.equal(r.status.attempt.terminal.outcome,'cancelled');assert.deepEqual(r.status.attempt.processes,[]);assert.equal(r.status.attempt.terminal.ack_sha256,null);
});

test('owned supervisor timeout after persisted intent retracts it only before its OS spawn syscall',{skip:!['win32','linux'].includes(process.platform)},t=>{
 const f=fixture(t),r=ownedControlBarrier(f,{at:'intent',expire:true});assert.equal(r.error?.code,'verification_timeout');assert.deepEqual(r.spawned,[]);assert.equal(r.status.attempt.terminal.outcome,'timed_out');assert.deepEqual(r.status.attempt.processes,[]);assert.equal(r.status.attempt.terminal.ack_sha256,null);
});

test('owned supervisor cancellation after intent starts no authority and recovers its actually exited watchdog',{skip:!['win32','linux'].includes(process.platform)},t=>{
 const f=fixture(t),r=ownedControlBarrier(f,{at:'intent',cancel:true});assert.equal(r.error?.code,'verification_cancelled',r.error?.stack);assert.equal(r.spawned.length,1);assert(r.spawned[0].pid>0);assert.equal(r.status.attempt.terminal.outcome,'cancelled');assert.equal(r.status.attempt.terminal.ack_sha256,null);assert.equal(r.status.attempt.processes.length,1);assert.equal(r.status.attempt.processes[0].role,'watchdog');assert.equal(r.status.attempt.processes[0].pid,r.spawned[0].pid);assert.equal(r.status.attempt.processes[0].exit_observed,true);
});

test('owned supervisor preserves accepted cancellation when pre-spawn transport deadline also expires',{skip:!['win32','linux'].includes(process.platform)},t=>{
 const f=fixture(t),r=ownedControlBarrier(f,{at:'intent',cancel:true,expire:true});assert.deepEqual(r.spawned,[]);assert.equal(r.status.attempt.terminal.outcome,'cancelled');assert.equal(r.status.attempt.terminal.ack_sha256,null);assert.equal(r.error?.code,'verification_cancelled');
});

test('public facade delegates before project storage and maps cancelled native delivery without admitting an ACK',{skip:!['win32','linux'].includes(process.platform)},t=>{
 const f=fixture(t),runner=require('../tools/lib/command-runner'),original=runner.runOwnedOperationSync,begin=control.beginAttempt;
 const supervisor=require('../tools/lib/verification-supervisor'),started=process.hrtime.bigint(),calls=[];
 const request={stateRoot:f.root,repoRoot:f.root,tests:[{id:'not-run'}],verificationPolicy:{work_budget_ms:1500,no_progress_ms:0,cleanup_budget_ms:1000}};
 try{
  control.beginAttempt=()=>{assert.fail('Public caller must not claim project storage outside the native invocation');};
  runner.runOwnedOperationSync=(operation,payload,options)=>{calls.push({operation,payload,options});throw Object.assign(new Error('controlled native cancellation'),{code:'command_cancelled',cleanup:{status:'completed'}});};
  assert.throws(()=>supervisor.runSupervised(request,1500,started),error=>{
   assert.equal(error.code,'verification_cancelled');assert.equal(error.primary_error,'command_cancelled');
   assert.equal(error.delivery_teardown.status,'completed');assert.equal(error.result_visibility,'ack_not_delivered');return true;
  });
  assert.equal(calls.length,1);assert.equal(calls[0].operation,'verification-run');
  assert.equal(calls[0].payload.started_ns,String(started));assert.equal(calls[0].payload.timeout_ms,1500);
  assert.equal(calls[0].options.absoluteWorkDeadlineNs,String(started+1500000000n));
  assert.deepEqual(calls[0].options.budgets,{workMs:1500,setupMs:1500,cleanupMs:1000,progressMs:0});
  assert.deepEqual(fs.readdirSync(f.root),[]);
 }finally{runner.runOwnedOperationSync=original;control.beginAttempt=begin;}
});


test('status age uses the latest trusted phase observation rather than the sparse first/last command ledger',t=>{
 const f=fixture(t),s=start(f);control.updateAttempt(f.context,s.owner,{type:'progress',milestone:'admission_complete',ordinal:1,evidence_sha256:H});
 const ledger=control.readStatus(f.context).attempt.progress;Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,200);
 const observed=control.updateAttempt(f.context,s.owner,{type:'observation',stage:'finalization',elapsed_ms:1000,last_meaningful_progress_elapsed_ms:900,progress_signal_available:true,wait_reason:'work'}).attempt;
 assert.deepEqual(observed.progress,ledger);const realNow=Date.now;
 try{
  Date.now=()=>Date.parse(observed.runtime_observation.observed_at)+5000;
  const status=control.readStatus(f.context);assert.equal(status.timing.since_meaningful_progress_ms,5100);assert.equal(status.timing.snapshot_staleness_ms,5000);assert.equal(status.timing.snapshot_staleness_source,'wall_clock_estimate');assert.equal(status.timing.progress_age_source,'persisted_observation_plus_wall_clock_snapshot_staleness_estimate');assert.equal(status.observation,'persisted_snapshot_not_live_liveness');
 }finally{Date.now=realNow;}
 control.updateAttempt(f.context,s.owner,{type:'observation',stage:'command',elapsed_ms:1100,last_meaningful_progress_elapsed_ms:1100,progress_signal_available:false,wait_reason:'work'});
 assert.equal(control.readStatus(f.context).timing.since_meaningful_progress_ms,null);
});
