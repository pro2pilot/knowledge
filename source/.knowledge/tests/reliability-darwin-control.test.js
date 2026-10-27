'use strict';
// Real common-ledger files/locks; explicitly synthetic Darwin native replies.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const control=require('../tools/lib/verification-control'),recovery=require('../tools/lib/verification-recovery');
const bridge=require('../tools/lib/verification-darwin-control'),scopeProof=require('../tools/lib/verification-darwin-scope');
const wire=require('../tools/lib/verification-darwin-session-protocol');
const {fixture:model,clone}=require('./helpers/reliability-darwin-control-fixture.cjs');
const H='1'.repeat(64);
function fixture(t) {
  const f=model(),root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-darwin-control-'))),context={stateRoot:root};
  const lease=control.acquireStorageLease(context);
  t.after(()=>{try{lease.release();}finally{fs.rmSync(root,{recursive:true,force:true});}});
  const begun=control.beginAttempt(context,{request_sha256:H,storage_protocol:control.STORAGE_PROTOCOL,
    startup_nonce_sha256:wire.sha(f.native.attempt_nonce)});
  const pending=bridge.descriptor({scope:f.scope,controller_identity:f.controller_identity,authority_identity:null});
  control.updateAttempt(context,begun.owner,{type:'containment_bound',descriptor:pending,spawn_ids:[]});
  return {...f,...begun,root,context,lease,pending,id:{attempt_id:begun.owner.attempt_id,generation:begun.owner.generation},
    file:path.join(root,'maintenance/verification-control/active.json')};
}
function attach(f) {
  const descriptor=bridge.descriptor({scope:f.scope,controller_identity:f.controller_identity,authority_identity:f.authority_identity});
  control.updateAttempt(f.context,f.owner,{type:'darwin_authority_bound',descriptor,pid:f.authority_identity.birth.pid,
    process_nonce:f.owner.generation,executable_sha256:f.capability.runtime_sha256});
  return descriptor;
}
function normal(f,descriptor) {
  return bridge.normalProof({descriptor,terminalReply:f.terminalReply,capability:f.capability,
    authorityExit:{pid:f.authority_identity.birth.pid,process_nonce:f.owner.generation,method:'process_handle_signaled',exit_observed:true}});
}
function recoveryAdapter(t,f,observation=f.observation) {
  // Replace only native observation at this explicit protocol-model boundary.
  // Real Darwin recovery is separately qualified in the physical CI cohort.
  const native=scopeProof.validateObservation(observation,f.scope,f.capability,observation.observation_nonce);
  assert.equal(native.status,'completed');
  t.mock.method(scopeProof,'recoverCommandScope',()=>native);
  return snapshot=>recovery.bindProof(snapshot,bridge.recoverContainer(snapshot.containment.descriptor));
}
test('pending native containment is durable before any authority process is admitted',t=>{
  const f=fixture(t),a=control.readStatus(f.context).attempt;
  assert.equal(a.schema_version,'knowledge-verification-control.v5');assert.equal(a.storage_protocol,'lifetime_lease.v1');
  assert.equal(a.startup_nonce_sha256,wire.sha(f.native.attempt_nonce));assert.deepEqual(a.processes,[]);
  assert.equal(a.containment.descriptor.authority_identity,null);assert.deepEqual(a.containment.spawn_ids,[]);
  assert.equal(control.recoverAttempt(f.context,f.id).status,'requires_native_recovery');
  assert.equal(control.readStatus(f.context).attempt.claimed,true);
});
test('native authority binding appends one exact process and immutable descriptor in one revision',t=>{
  const f=fixture(t),before=control.readStatus(f.context).attempt;attach(f);const after=control.readStatus(f.context).attempt;
  assert.equal(after.revision,before.revision+1);assert.equal(after.processes.length,1);assert.equal(after.processes[0].pid,1201);
  assert.equal(after.processes[0].process_nonce,f.owner.generation);assert.deepEqual(after.containment.spawn_ids,[1]);
  assert.throws(()=>attach(f),{code:'verification_stopped'});
});
test('foreign native startup nonce or authority parent cannot bind this lifetime reservation',t=>{
  const f=fixture(t),before=fs.readFileSync(f.file),foreign=clone(f.pending);
  foreign.scope.binding.descriptor.attempt_nonce='0'.repeat(64);foreign.scope.binding.descriptor_sha256=wire.digest(foreign.scope.binding.descriptor);
  const otherRoot=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-darwin-nonce-')),context={stateRoot:otherRoot};
  const lease=control.acquireStorageLease(context);
  try {
    const begun=control.beginAttempt(context,{request_sha256:H,storage_protocol:control.STORAGE_PROTOCOL,startup_nonce_sha256:wire.sha(f.native.attempt_nonce)});
    assert.throws(()=>control.updateAttempt(context,begun.owner,{type:'containment_bound',descriptor:foreign,spawn_ids:[]}),{code:'verification_containment_invalid'});
  } finally{lease.release();fs.rmSync(otherRoot,{recursive:true,force:true});}
  const bad=clone(f.authority_identity);bad.birth.parent_unique_id='999';
  assert.throws(()=>bridge.descriptor({scope:f.scope,controller_identity:f.controller_identity,authority_identity:bad}),{code:'verification_darwin_control_descriptor_invalid'});
  assert.deepEqual(fs.readFileSync(f.file),before);
});
test('pending native scope never accepts a fabricated no-processes completion',t=>{
  const f=fixture(t);control.updateAttempt(f.context,f.owner,{type:'cleanup_started'});
  assert.throws(()=>control.commitFinish(f.context,f.owner,{outcome:'failed',cleanup_proof:{...f.id,method:'no_processes_started'}}),
    {code:'verification_cleanup_unconfirmed'});assert.equal(control.readStatus(f.context).attempt.claimed,true);
});
test('current terminal proof keeps the live controller outside the drained authority boundary',t=>{
  const f=fixture(t),descriptor=attach(f),proof=normal(f,descriptor);
  assert.equal(proof.controller_exited,false);assert.equal(proof.controller_excluded_from_boundary,true);
  control.updateAttempt(f.context,f.owner,{type:'cleanup_started'});
  control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:1,pid:1201,process_nonce:f.owner.generation,method:'process_handle_signaled'});
  const completed=control.commitFinish(f.context,f.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:control.bindCleanupProof(f.owner,proof)});
  assert.equal(completed.ack_released,true);assert.equal(completed.attempt.claimed,false);
  assert.equal(control.readStatus(f.context).attempt.cleanup.native_transcript.payload.native_return.controller_exited,false);
});
test('stale epoch and substituted exact birth cannot become a normal terminal proof',t=>{
  const f=fixture(t),descriptor=attach(f);
  for(const patch of [p=>{p.daemon_epoch='0'.repeat(64);},p=>{p.authority_identity.unique_id='999';},p=>{p.controller_identity.pid=1239;},p=>{p.guardian_exit_confirmed=false;}]) {
    const reply=clone(f.terminalReply);patch(reply.proof);reply.proof_sha256=wire.digest(reply.proof);
    assert.throws(()=>bridge.normalProof({descriptor,terminalReply:reply,capability:f.capability,
      authorityExit:{pid:1201,process_nonce:f.owner.generation,method:'process_handle_signaled',exit_observed:true}}));
  }
});
for(const registered of [false,true])test(`recovery of pending descriptor with native authority ${registered?'registered':'never registered'} records no invented ChildProcess exit`,t=>{
  const f=fixture(t),observation=clone(f.observation);if(!registered)observation.authority_identity=null;
  const result=control.recoverAttempt(f.context,f.id,recoveryAdapter(t,f,observation));
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);assert.deepEqual(result.attempt.processes,[]);
  const proof=result.attempt.cleanup.native_transcript.payload.native_return;
  assert.equal(proof.proof_current,false);assert.equal(proof.cleanup_only,true);
  assert.equal(proof.pre_registration_bootstrap_exit,'not_observed');
  assert.equal(proof.resolved_authority_identity?.birth.pid??null,registered?1201:null);
});
test('recovery of a bound authority requires its exact native birth and remains failure only',t=>{
  const f=fixture(t);attach(f);
  const result=control.recoverAttempt(f.context,f.id,recoveryAdapter(t,f));
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);assert.equal(result.attempt.processes[0].exit_observed,true);
  assert.equal(result.attempt.cleanup.native_transcript.payload.bound_proof.process_exits[0].method,'darwin_registered_authority_exit');
});
test('a cleanup-only observation cannot authorize normal passed completion',t=>{
  const f=fixture(t),descriptor=attach(f);recoveryAdapter(t,f);
  const cleanup=bridge.recoverContainer(descriptor);
  assert.equal(bridge.validateProof(cleanup,descriptor),false);
  control.updateAttempt(f.context,f.owner,{type:'cleanup_started'});
  control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:1,pid:1201,process_nonce:f.owner.generation,method:'process_handle_signaled'});
  assert.throws(()=>control.commitFinish(f.context,f.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:control.bindCleanupProof(f.owner,cleanup)}),
    {code:'verification_cleanup_unconfirmed'});assert.equal(control.readStatus(f.context).attempt.claimed,true);
});
