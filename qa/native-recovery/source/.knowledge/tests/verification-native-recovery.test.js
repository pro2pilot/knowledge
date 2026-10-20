'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const os=require('os');
const crypto=require('crypto');
const cp=require('child_process');
const control=require('../tools/lib/verification-control');
const recovery=require('../tools/lib/verification-recovery');
const H='1'.repeat(64),birth='2026-10-20T10:00:00.000Z';
const digest=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-native-recovery-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const context={stateRoot:root},begun=control.beginAttempt(context,{request_sha256:H});
  return {root,context,...begun,id:{attempt_id:begun.owner.attempt_id,generation:begun.owner.generation},
    file:path.join(root,'maintenance/verification-control/active.json')};
}
function emptyProof(f) {return {...f.id,method:'no_processes_started'};}
function bindLinux(f) {
  const descriptor={schema_version:'knowledge-linux-pid-namespace.v1',backend:'linux_pid_namespace',
    worker:{pid:1234,start_ticks:'9001',os_creation_time:birth}};
  control.updateAttempt(f.context,f.owner,{type:'spawn_intent',role:'authority'});
  control.updateAttempt(f.context,f.owner,{type:'spawn_observed',spawn_id:1,pid:1234,os_creation_time:birth,executable_sha256:H});
  control.updateAttempt(f.context,f.owner,{type:'containment_bound',descriptor,spawn_ids:[1]});
  return descriptor;
}
function linuxProof(f,descriptor) {
  return {...f.id,status:'completed',method:'linux_pid_namespace',active_processes:0,
    keeper_exited:true,worker_exited:true,controller_exited:true,init_exit_observed:true,init_reaped:true,namespace_drained:true,
    descriptor_sha256:digest(descriptor),evidence_sha256:H,
    process_exits:[{spawn_id:1,pid:1234,os_creation_time:birth,start_ticks:'9001',method:'linux_pidfd_exit'}]};
}

test('native side effects start only after a durable fence which blocks old owner ACK and spawn',t=>{
  const f=fixture(t);
  const result=control.recoverAttempt(f.context,f.id,attempt=>{
    const persisted=JSON.parse(fs.readFileSync(f.file));
    assert.equal(persisted.stop_reason,'failure');assert.equal(persisted.recovery.status,'active');
    assert.equal(attempt.recovery.recovery_id,persisted.recovery.recovery_id);
    assert.throws(()=>control.commitFinish(f.context,f.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:emptyProof(f)}),{code:'verification_recovery_in_progress'});
    assert.throws(()=>control.updateAttempt(f.context,f.owner,{type:'spawn_intent',role:'authority'}),{code:'verification_recovery_in_progress'});
    assert.throws(()=>control.beginAttempt(f.context,{request_sha256:H}),{code:'verification_recovery_required'});
    return emptyProof(f);
  });
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);
  assert.equal(result.attempt.recovery.status,'completed');
});

test('both native and narrow competing recovery refuse an active reservation before side effects',t=>{
  const f=fixture(t);let competingCalls=0;
  control.recoverAttempt(f.context,f.id,()=>{
    assert.throws(()=>control.recoverAttempt(f.context,f.id),{code:'verification_recovery_in_progress'});
    assert.throws(()=>control.recoverAttempt(f.context,f.id,()=>{competingCalls++;return emptyProof(f);}),{code:'verification_recovery_in_progress'});
    return emptyProof(f);
  });
  assert.equal(competingCalls,0);
});

test('adapter exception retains quarantine and irreversible work fence; explicit retry gets a new reservation',t=>{
  const f=fixture(t);let first;
  assert.throws(()=>control.recoverAttempt(f.context,f.id,a=>{first=a.recovery.recovery_id;throw Object.assign(new Error('native wait failed'),{code:'native_wait_unconfirmed'});}),{code:'native_wait_unconfirmed'});
  let a=control.readStatus(f.context).attempt;
  assert.equal(a.claimed,true);assert.equal(a.phase,'cleanup_unconfirmed');assert.equal(a.recovery.reason_code,'native_wait_unconfirmed');
  assert.throws(()=>control.commitFinish(f.context,f.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:emptyProof(f)}),{code:'verification_recovery_in_progress'});
  const result=control.recoverAttempt(f.context,f.id,a=>{assert.notEqual(a.recovery.recovery_id,first);assert.equal(a.recovery.ordinal,2);return emptyProof(f);});
  assert.equal(result.ack_released,false);assert.equal(result.status,'failed');
});

test('accepted cancellation during native wait remains effective without invalidating recovery ownership',t=>{
  const f=fixture(t);
  const result=control.recoverAttempt(f.context,f.id,()=>{
    assert.equal(control.requestCancel(f.context,f.id).status,'cancel_requested');
    return emptyProof(f);
  });
  assert.equal(result.status,'cancelled');assert.equal(result.ack_released,false);assert.equal(result.attempt.terminal.ack_sha256,null);
});

test('reservation age and unknown recovery-owner liveness never authorize takeover',t=>{
  const f=fixture(t);let calls=0;
  control.recoverAttempt(f.context,f.id,()=>{
    const raw=JSON.parse(fs.readFileSync(f.file));raw.recovery.started_at='2000-01-01T00:00:00.000Z';fs.writeFileSync(f.file,JSON.stringify(raw));
    const candidate=()=>{calls++;return emptyProof(f);};
    candidate.verify_recoverer_exit=()=>({status:'active'});
    assert.throws(()=>control.recoverAttempt(f.context,f.id,candidate),{code:'verification_recovery_in_progress'});
    candidate.verify_recoverer_exit=()=>({status:'exited',owner_identity_sha256:'0'.repeat(64),evidence_sha256:H});
    assert.throws(()=>control.recoverAttempt(f.context,f.id,candidate),{code:'verification_recovery_in_progress'});
    return emptyProof(f);
  });
  assert.equal(calls,0);
});

test('a crashed real recovery process leaves a claim; exact child exit permits a new fenced cleanup only',t=>{
  const f=fixture(t),modulePath=require.resolve('../tools/lib/verification-control');
  const code=`const c=require(${JSON.stringify(modulePath)});const fn=()=>process.exit(23);fn.owner_identity={kind:'test_child_handle',pid:process.pid};c.recoverAttempt({stateRoot:process.argv[1]},JSON.parse(process.argv[2]),fn);`;
  const child=cp.spawnSync(process.execPath,['-e',code,f.root,JSON.stringify(f.id)],{encoding:'utf8',timeout:15000});
  assert.ifError(child.error);assert.equal(child.status,23,child.stderr);
  const stale=control.readStatus(f.context).attempt;
  assert.equal(stale.claimed,true);assert.equal(stale.recovery.status,'active');
  assert.throws(()=>control.recoverAttempt(f.context,f.id),{code:'verification_recovery_in_progress'});
  const retry=()=>emptyProof(f);
  // This is a state-protocol test: the actual ChildProcess wait above, not a
  // PID probe, supplies the test adapter's exact owner-exit observation.
  retry.verify_recoverer_exit=identity=>{assert.equal(identity.pid,child.pid);return {status:'exited',owner_identity_sha256:digest(identity),evidence_sha256:H};};
  const result=control.recoverAttempt(f.context,f.id,retry);
  assert.equal(result.status,'failed');assert.equal(result.attempt.recovery.ordinal,2);assert.equal(result.ack_released,false);
});

test('a late proof from a superseded reservation cannot mutate the next attempt',t=>{
  const f=fixture(t);let next;
  assert.throws(()=>control.recoverAttempt(f.context,f.id,()=>{
    const takeover=()=>emptyProof(f);
    // Controlled protocol fault injection: a native verifier returning an
    // exact former-owner-exit proof allows us to exercise a delayed old result.
    takeover.verify_recoverer_exit=identity=>({status:'exited',owner_identity_sha256:digest(identity),evidence_sha256:H});
    const done=control.recoverAttempt(f.context,f.id,takeover);assert.equal(done.ack_released,false);
    next=control.beginAttempt(f.context,{request_sha256:H});
    return emptyProof(f);
  }),{code:'verification_control_conflict'});
  const current=control.readStatus(f.context).attempt;
  assert.equal(current.attempt_id,next.owner.attempt_id);assert.equal(current.phase,'reserved');assert.equal(current.recovery,null);
});

test('a complete namespace exit barrier is mandatory; malformed proof retains the claim',t=>{
  for(const field of ['init_exit_observed','init_reaped','namespace_drained','worker_exited','keeper_exited']) {
    const f=fixture(t),descriptor=bindLinux(f),proof=linuxProof(f,descriptor);delete proof[field];
    assert.throws(()=>control.recoverAttempt(f.context,f.id,()=>proof),{code:'verification_cleanup_unconfirmed'});
    assert.equal(control.readStatus(f.context).attempt.claimed,true);
  }
});

test('a stale descriptor digest cannot release the current container claim',t=>{
  const f=fixture(t),descriptor=bindLinux(f),proof=linuxProof(f,descriptor);proof.descriptor_sha256='0'.repeat(64);
  assert.throws(()=>control.recoverAttempt(f.context,f.id,()=>proof),{code:'verification_process_identity_mismatch'});
  assert.equal(control.readStatus(f.context).attempt.cleanup.status,'unconfirmed');
  const result=control.recoverAttempt(f.context,f.id,attempt=>recovery.bindProof(attempt,linuxProof(f,descriptor)));
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);
});

test('native proof binding rejects an unobserved or different process birth',t=>{
  const f=fixture(t),descriptor=bindLinux(f),attempt=control.readStatus(f.context).attempt;
  const proof=linuxProof(f,descriptor);proof.process_exits[0].start_ticks='9002';
  assert.throws(()=>recovery.bindProof(attempt,proof),{code:'verification_process_identity_mismatch'});
  proof.process_exits[0].start_ticks='9001';
  const bound=recovery.bindProof(attempt,proof);
  assert.equal(bound.process_exits[0].spawn_id,1);assert.equal(bound.descriptor_sha256,digest(descriptor));
});

test('historical v1 state is read without writes and upgraded without invented ownership',t=>{
  const f=fixture(t),raw=JSON.parse(fs.readFileSync(f.file));delete raw.containment;delete raw.recovery;raw.schema_version='knowledge-verification-control.v1';
  raw.cleanup={status:raw.cleanup.status,attempts:raw.cleanup.attempts,evidence_sha256:raw.cleanup.evidence_sha256};
  fs.writeFileSync(f.file,JSON.stringify(raw));const before=fs.readFileSync(f.file);
  const status=control.readStatus(f.context);assert.equal(status.attempt.schema_version,'knowledge-verification-control.v3');
  assert.equal(status.attempt.cleanup.native_transcript,null);assert.equal(status.attempt.cleanup.transcript_required,false);
  assert.equal(status.attempt.containment,null);assert.deepEqual(fs.readFileSync(f.file),before);
  const result=control.recoverAttempt(f.context,f.id);assert.equal(result.ack_released,false);
  const saved=JSON.parse(fs.readFileSync(f.file));
  assert.equal(saved.schema_version,'knowledge-verification-control.v3');
  assert.equal(saved.cleanup.native_transcript,null);assert.equal(saved.cleanup.transcript_required,false);
});

test('generic recovery leaves legacy unknown ownership explicit and does not invoke a native process guess',t=>{
  const f=fixture(t);control.updateAttempt(f.context,f.owner,{type:'spawn_intent',role:'authority'});
  const result=recovery.recoverAttempt(f.context,f.id);
  assert.equal(result.status,'requires_native_recovery');assert.equal(result.reason,'durable_native_descriptor_missing');
  assert.equal(control.readStatus(f.context).attempt.claimed,true);
});

test('durable native cleanup receipt preserves proven empty tree while the outside controller still owns its exit',t=>{
  const f=fixture(t),identities={controller:{pid:2211,os_creation_time:birth},worker:{pid:2212,os_creation_time:birth},keeper:{pid:2213,os_creation_time:birth}};
  const descriptor={schema_version:'knowledge-windows-job.v1',backend:'windows_job_object',job_name:'Local\\KnowledgeVerification-'+H,identities,source_sha256:H};
  for(const [index,role] of ['watchdog','authority','keeper'].entries()) {
    control.updateAttempt(f.context,f.owner,{type:'spawn_intent',role});
    control.updateAttempt(f.context,f.owner,{type:'spawn_observed',spawn_id:index+1,pid:2211+index,os_creation_time:birth,executable_sha256:H});
  }
  control.updateAttempt(f.context,f.owner,{type:'containment_bound',descriptor,spawn_ids:[1,2,3]});
  control.updateAttempt(f.context,f.owner,{type:'cleanup_started'});
  const observed={status:'completed',method:'windows_job_object',active_processes:0,keeper_exited:true,worker_exited:true,descriptor_sha256:digest(descriptor)};
  assert.throws(()=>control.updateAttempt(f.context,f.owner,{type:'cleanup_proven',proof:observed}),{code:'verification_cleanup_unconfirmed'});
  for(const spawn_id of [2,3]) control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id,pid:2210+spawn_id,os_creation_time:birth,method:'process_handle_signaled'});
  control.updateAttempt(f.context,f.owner,{type:'cleanup_proven',proof:observed});
  let attempt=control.readStatus(f.context).attempt;
  assert.equal(attempt.claimed,true);assert.equal(attempt.processes[0].exit_observed,false);
  assert.equal(attempt.containment.cleanup_receipt.active_processes,0);
  const result=control.recoverAttempt(f.context,f.id,a=>recovery.bindProof(a,{...observed,controller_exited:true,
    container_proof_basis:'persisted_native_cleanup_receipt',cleanup_receipt_sha256:digest(a.containment.cleanup_receipt),
    process_exits:[{pid:2211,os_creation_time:birth,method:'process_handle_signaled'}]}));
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);
});

test('native helper evidence for another descriptor is never relabeled as current ownership',t=>{
  const f=fixture(t),descriptor=bindLinux(f),attempt=control.readStatus(f.context).attempt,proof=linuxProof(f,descriptor);
  proof.descriptor_sha256='0'.repeat(64);
  assert.throws(()=>recovery.bindProof(attempt,proof),{code:'verification_process_identity_mismatch'});
});

test('recovery can truthfully distinguish final namespace exit from an init zombie awaiting its parent',t=>{
  const f=fixture(t),descriptor=bindLinux(f),proof=linuxProof(f,descriptor);
  proof.init_reaped=false;proof.init_exit_basis='linux_pidfd_exit';proof.init_reap_basis='kernel_namespace_init_final_exit';
  const result=control.recoverAttempt(f.context,f.id,attempt=>recovery.bindProof(attempt,proof));
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);
});

test('ordinary passed finalization cannot borrow the recovery-only init-zombie proof',t=>{
  const f=fixture(t),descriptor=bindLinux(f),proof=linuxProof(f,descriptor);
  control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:1,pid:1234,os_creation_time:birth,method:'process_handle_signaled'});
  proof.init_reaped=false;proof.init_exit_basis='linux_pidfd_exit';proof.init_reap_basis='kernel_namespace_init_final_exit';
  assert.throws(()=>control.commitFinish(f.context,f.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:proof}),{code:'verification_cleanup_unconfirmed'});
});

test('a persisted native container cannot be downgraded to a controller-only cleanup shortcut',t=>{
  const f=fixture(t);
  control.updateAttempt(f.context,f.owner,{type:'spawn_intent',role:'watchdog'});
  control.updateAttempt(f.context,f.owner,{type:'spawn_observed',spawn_id:1,pid:1234,os_creation_time:birth,executable_sha256:H});
  control.updateAttempt(f.context,f.owner,{type:'containment_bound',descriptor:{backend:'windows_job_object',job_name:'known-container'},spawn_ids:[1]});
  control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:1,pid:1234,os_creation_time:birth,method:'process_handle_signaled'});
  const result=control.recoverAttempt(f.context,f.id);
  assert.equal(result.status,'requires_native_recovery');assert.equal(result.attempt.claimed,true);
});

test('old native-issued namespace init absence has an explicit recovery-only inference shape',t=>{
  for(const basis of ['linux_boot_birth_absent','linux_boot_birth_replaced']) {
    const f=fixture(t),descriptor=bindLinux(f),proof=linuxProof(f,descriptor);
    Object.assign(proof,{init_exit_observed:false,init_exit_inferred:true,init_reaped:false,init_release_inferred:true,
      init_exit_basis:basis,init_reap_basis:'kernel_namespace_init_final_exit'});
    const result=control.recoverAttempt(f.context,f.id,attempt=>recovery.bindProof(attempt,proof));
    assert.equal(result.status,'failed');assert.equal(result.ack_released,false);
  }
});

test('a real second writer can append late cleanup evidence during recovery without releasing work or ACK',t=>{
  const f=fixture(t),identities={controller:{pid:3211,os_creation_time:birth},worker:{pid:3212,os_creation_time:birth},keeper:{pid:3213,os_creation_time:birth}};
  const descriptor={schema_version:'knowledge-windows-job.v1',backend:'windows_job_object',job_name:'Local\\KnowledgeVerification-'+H,identities,source_sha256:H};
  for(const [index,role] of ['watchdog','authority','keeper'].entries()) {
    control.updateAttempt(f.context,f.owner,{type:'spawn_intent',role});
    control.updateAttempt(f.context,f.owner,{type:'spawn_observed',spawn_id:index+1,pid:3211+index,os_creation_time:birth,executable_sha256:H});
  }
  control.updateAttempt(f.context,f.owner,{type:'containment_bound',descriptor,spawn_ids:[1,2,3]});
  const observed={status:'completed',method:'windows_job_object',active_processes:0,keeper_exited:true,worker_exited:true,descriptor_sha256:digest(descriptor)};
  const code=`const fs=require('fs'),assert=require('assert/strict'),c=require(${JSON.stringify(require.resolve('../tools/lib/verification-control'))});const input=JSON.parse(fs.readFileSync(0,'utf8'));for(const spawn_id of [2,3])c.updateAttempt(input.context,input.owner,{type:'process_exit',spawn_id,pid:3210+spawn_id,os_creation_time:${JSON.stringify(birth)},method:'process_handle_signaled'});c.updateAttempt(input.context,input.owner,{type:'cleanup_proven',proof:input.proof});assert.throws(()=>c.updateAttempt(input.context,input.owner,{type:'phase',phase:'running'}),{code:'verification_recovery_in_progress'});assert.throws(()=>c.commitFinish(input.context,input.owner,{outcome:'passed',ack_sha256:${JSON.stringify(H)},cleanup_proof:input.proof}),{code:'verification_recovery_in_progress'});console.log('late-proof-only');`;
  assert.throws(()=>control.recoverAttempt(f.context,f.id,()=>{
    const writer=cp.spawnSync(process.execPath,['-e',code],{encoding:'utf8',timeout:15000,
      input:JSON.stringify({context:f.context,owner:f.owner,proof:observed})});
    assert.ifError(writer.error);assert.equal(writer.status,0,writer.stderr);assert.equal(writer.stdout.trim(),'late-proof-only');
    // The in-flight native query can already have missed the now-closed Job.
    throw Object.assign(new Error('old snapshot had no receipt'),{code:'recovery_job_reopen_unconfirmed'});
  }),{code:'recovery_job_reopen_unconfirmed'});
  const a=control.readStatus(f.context).attempt;
  assert.equal(a.claimed,true);assert.equal(a.stop_reason,'failure');assert.equal(a.recovery.status,'unconfirmed');
  assert.equal(a.cleanup.status,'unconfirmed');assert(a.containment.cleanup_receipt);
  const result=control.recoverAttempt(f.context,f.id,snapshot=>recovery.bindProof(snapshot,{...observed,controller_exited:true,
    container_proof_basis:'persisted_native_cleanup_receipt',cleanup_receipt_sha256:digest(snapshot.containment.cleanup_receipt),
    process_exits:[{pid:3211,os_creation_time:birth,method:'process_handle_signaled'}]}));
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);
});

test('a late owner receipt cannot borrow recovery-only inferred namespace finality',t=>{
  const f=fixture(t),descriptor=bindLinux(f),proof=linuxProof(f,descriptor);
  control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:1,pid:1234,os_creation_time:birth,method:'process_handle_signaled'});
  control.recoverAttempt(f.context,f.id,()=>{
    const inference={...proof,init_exit_observed:false,init_exit_inferred:true,init_reaped:false,init_release_inferred:true,
      init_exit_basis:'linux_boot_birth_absent',init_reap_basis:'kernel_namespace_init_final_exit'};
    assert.throws(()=>control.updateAttempt(f.context,f.owner,{type:'cleanup_proven',proof:inference}),{code:'verification_cleanup_unconfirmed'});
    return recovery.bindProof(control.readStatus(f.context).attempt,proof);
  });
});
