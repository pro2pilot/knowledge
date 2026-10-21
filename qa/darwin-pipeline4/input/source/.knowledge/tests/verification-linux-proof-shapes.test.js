'use strict';
// Synthetic protocol/reader fixtures only. No process identity or kernel proof
// is manufactured for production use and no native process is started.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const control=require('../tools/lib/verification-control');
const recovery=require('../tools/lib/verification-recovery');
const finalization=require('../tools/lib/verification-finalization');
const execution=require('../tools/lib/verification-execution');
const {removeTempDirStrict}=require('../tools/lib/strict-temp-cleanup');
const H='a'.repeat(64),BIRTH='2026-10-20T00:00:00.000Z';
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function temp(t){const root=fs.mkdtempSync(path.join(__dirname,'.tmp-linux-proof-shapes-'));t.after(()=>removeTempDirStrict(root));return root;}
function controlled(t,patch={}) {
 const root=temp(t),context={stateRoot:root},begun=control.beginAttempt(context,{request_sha256:H}),owner=begun.owner;
 const descriptor={schema_version:'knowledge-linux-pid-namespace.v1',backend:'linux_pid_namespace',worker:{pid:1234,start_ticks:'9001',os_creation_time:BIRTH}};
 control.updateAttempt(context,owner,{type:'spawn_intent',role:'authority'});
 control.updateAttempt(context,owner,{type:'spawn_observed',spawn_id:1,pid:1234,os_creation_time:BIRTH,executable_sha256:H});
 control.updateAttempt(context,owner,{type:'containment_bound',descriptor,spawn_ids:[1]});
 control.updateAttempt(context,owner,{type:'cleanup_started'});
 control.updateAttempt(context,owner,{type:'process_exit',spawn_id:1,pid:1234,os_creation_time:BIRTH,method:'process_handle_signaled'});
 const proof={status:'completed',method:'linux_pid_namespace',active_processes:0,worker_exited:true,keeper_exited:true,controller_exited:true,
 init_exit_observed:true,init_reaped:true,namespace_drained:true,descriptor_sha256:hash(JSON.stringify(descriptor)),process_exits:[],...patch};
 return {root,context,owner,proof,id:{attempt_id:owner.attempt_id,generation:owner.generation}};
}
async function signed(t,patch={}) {
 const root=temp(t),keys=crypto.generateKeyPairSync('ed25519'),publicKey=keys.publicKey.export({type:'spki',format:'der'}).toString('hex');
 const batch='KVB-'+crypto.randomBytes(16).toString('hex'),snapshot=[{path:'probe.js',sha256:H}];
 const record={schema_version:'knowledge-verification-execution.v2',task_id:'synthetic-task',session_id:'synthetic-session',command_argv:['node','probe.js'],command:'node probe.js',cwd:'.',status:'pass',exit_code:0,signal:null,timed_out:false,duration_ms:1,executed_at:'2026-10-20T00:00:00.000Z',executed_by:'synthetic-reader-fixture',runtime_binding:'process_exec_path',runtime_sha256:H,environment_profile:'sanitized_node',stdout_sha256:H,stderr_sha256:H,stdout_bytes:0,stderr_bytes:0,source_snapshot_before:snapshot,source_snapshot:snapshot,batch_id:batch,batch_ordinal:0,batch_public_key:publicKey,batch_request_sha256:H};
 record.content_sha256=execution.executionDigest(record);record.execution_id='KVE-'+record.content_sha256;
 assert.equal(execution.validateExecutionRecord(record).ok,true);
 const dir=path.join(root,'maintenance/verification_executions');fs.mkdirSync(dir,{recursive:true});
 const body=Buffer.from(JSON.stringify(record,null,2)+'\n');fs.writeFileSync(path.join(dir,record.content_sha256+'.json'),body);
 const receipt={schema_version:finalization.SCHEMA,batch_id:batch,public_key:publicKey,request_sha256:H,task_id:record.task_id,session_id:record.session_id,
 status:'commands_and_teardown_observed',backend:'linux_pid_namespace',teardown:{status:'completed',method:'linux_pid_namespace',active_processes:0,keeper_exited:true,worker_exited:true,descriptor_sha256:H,init_exit_observed:true,init_reaped:true,namespace_drained:true,...patch},
 timeout_ms:120000,work_elapsed_ms:1000,cleanup_budget_ms:30000,observed_elapsed_ms:1500,runtime_sha256:H,
 implementation:finalization.IMPLEMENTATION_PATHS.map(p=>({path:p,sha256:H})),executions:[{execution_id:record.execution_id,physical_sha256:hash(body)}]};
 const ref=await finalization.persistFinalization(root,receipt),ack=finalization.acceptFinalization(ref,120000,2000,keys.privateKey);
 return ()=>finalization.requireFinalizedExecutions(root,[record.execution_id],[ack]);
}
const malformed=[
 ['contradictory inferred release',{init_release_inferred:true}],
 ['string inferred exit',{init_exit_inferred:'true'}],
 ['numeric inferred release',{init_release_inferred:1}],
 ['null inferred exit',{init_exit_inferred:null}]
];
for(const [name,patch] of malformed) {
 test('normal cleanup receipt rejects '+name,t=>{
  const f=controlled(t,patch),before=control.readStatus(f.context).attempt;
  assert.throws(()=>control.updateAttempt(f.context,f.owner,{type:'cleanup_proven',proof:f.proof}),{code:'verification_cleanup_unconfirmed'});
  assert.deepEqual(control.readStatus(f.context).attempt,before);
 });
 test('recovery proof binding rejects '+name,t=>{
  const f=controlled(t,patch);
  assert.throws(()=>recovery.bindProof(control.readStatus(f.context).attempt,f.proof),{code:'verification_recovery_proof_invalid'});
  assert.equal(control.readStatus(f.context).attempt.claimed,true);
 });
 test('coherently signed v3 acceptance rejects '+name,async t=>{
  const read=await signed(t,patch);assert.throws(read,{code:'verification_finalization_required'});
 });
}
test('absent legacy inference flags and explicit false flags retain normal cleanup compatibility',async t=>{
 for(const patch of [{},{init_exit_inferred:false,init_release_inferred:false}]) {
  const f=controlled(t,patch);
  control.updateAttempt(f.context,f.owner,{type:'cleanup_proven',proof:f.proof});
  assert.equal(control.readStatus(f.context).attempt.containment.cleanup_receipt.init_exit_observed,true);
  assert.equal(recovery.bindProof(control.readStatus(f.context).attempt,f.proof).status,'completed');
  assert.equal((await signed(t,patch))().status,'accepted');
 }
});
test('explicit recovery-only absent-init inference retains cleanup-only semantics',t=>{
 const f=controlled(t,{init_exit_observed:false,init_exit_inferred:true,init_reaped:false,init_release_inferred:true,
 init_exit_basis:'linux_boot_birth_absent',init_reap_basis:'kernel_namespace_init_final_exit'});
 const result=control.recoverAttempt(f.context,f.id,a=>recovery.bindProof(a,f.proof));
 assert.equal(result.status,'failed');assert.equal(result.ack_released,false);assert.equal(result.attempt.claimed,false);
});
