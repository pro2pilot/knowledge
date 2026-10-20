'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const control=require('../tools/lib/verification-control');
const {removeTempDirStrict}=require('../tools/lib/strict-temp-cleanup');

const H='1'.repeat(64);
const birth='2026-10-20T10:00:00.000Z';
const digest=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
const bytes=value=>crypto.createHash('sha256').update(value).digest('hex');
const assertJsonEqual=(actual,expected)=>assert.equal(JSON.stringify(actual),JSON.stringify(expected));

function fixture(t) {
  const root=fs.mkdtempSync(path.join(__dirname,'.tmp-cleanup-transcript-'));
  t.after(()=>removeTempDirStrict(root));
  const context={stateRoot:root};
  const begun=control.beginAttempt(context,{request_sha256:H});
  return {root,context,...begun,id:{attempt_id:begun.owner.attempt_id,generation:begun.owner.generation},
    file:path.join(root,'maintenance/verification-control/active.json')};
}

function prepareNativeAttempt(f) {
  const identities={
    controller:{pid:2211,os_creation_time:birth},
    worker:{pid:2212,os_creation_time:birth},
    keeper:{pid:2213,os_creation_time:birth}
  };
  const descriptor={schema_version:'knowledge-windows-job.v1',backend:'windows_job_object',
    job_name:'Local\\KnowledgeVerification-'+H,identities,source_sha256:H};
  const roles=['watchdog','authority','keeper'];
  for(const [i,role] of roles.entries()) {
    control.updateAttempt(f.context,f.owner,{type:'spawn_intent',role});
    control.updateAttempt(f.context,f.owner,{type:'spawn_observed',spawn_id:i+1,pid:2211+i,
      os_creation_time:birth,executable_sha256:H});
  }
  control.updateAttempt(f.context,f.owner,{type:'containment_bound',descriptor,spawn_ids:[1,2,3]});
  control.updateAttempt(f.context,f.owner,{type:'cleanup_started'});
  return {descriptor,identities};
}

function nativeReturn(f,descriptor,extra={}) {
  return {status:'completed',method:'windows_job_object',active_processes:0,keeper_exited:true,
    worker_exited:true,controller_exited:true,descriptor_sha256:digest(descriptor),
    process_exits:[2211,2212,2213].map(pid=>({pid,os_creation_time:birth,method:'process_handle_signaled'})),
    ...extra};
}

function finishWithNativeTranscript(f,{outcome='failed',extraNativeReturn={},beforeCommit=()=>{}}={}) {
  const {descriptor}=prepareNativeAttempt(f);
  const returned=nativeReturn(f,descriptor,extraNativeReturn);
  const bound=control.bindCleanupProof(f.owner,returned);
  for(const [i,pid] of [2211,2212,2213].entries())
    control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:i+1,pid,
      os_creation_time:birth,method:'process_handle_signaled'});
  beforeCommit(bound);
  const result=control.commitFinish(f.context,f.owner,{outcome,cleanup_proof:bound,
    ...(outcome==='passed'?{ack_sha256:H}:{})});
  return {returned,bound,result,attempt:control.readStatus(f.context).attempt};
}

function rehashPayload(transcript) {
  transcript.payload_sha256=bytes(JSON.stringify(transcript.payload));
}

test('bindProof native return survives terminal persistence and digest-checked reload',t=>{
  const f=fixture(t),{returned,bound,result,attempt}=finishWithNativeTranscript(f);
  const transcript=attempt.cleanup.native_transcript;
  assert.equal(result.status,'failed');
  assert.equal(attempt.claimed,false);
  assert.equal(transcript.schema_version,'knowledge-native-cleanup-transcript.v1');
  assert.equal(transcript.attempt_id,f.id.attempt_id);
  assert.equal(transcript.generation,f.id.generation);
  assert.equal(transcript.descriptor_sha256,attempt.containment.descriptor_sha256);
  assert.equal(transcript.backend,'windows_job_object');
  assert.equal(transcript.recovery_id,null);
  assertJsonEqual(transcript.payload.native_return,returned);
  assertJsonEqual(transcript.payload.bound_proof,bound);
  assert.equal(transcript.payload_sha256,bytes(JSON.stringify(transcript.payload)));
  const saved=JSON.parse(fs.readFileSync(f.file,'utf8'));
  assertJsonEqual(saved.cleanup.native_transcript,transcript);
  assertJsonEqual(control.readStatus(f.context).attempt.cleanup.native_transcript,transcript);
});

test('payload tampering without a matching payload digest fails closed on reload',t=>{
  const f=fixture(t);finishWithNativeTranscript(f);
  const raw=JSON.parse(fs.readFileSync(f.file,'utf8'));
  raw.cleanup.native_transcript.payload.native_return.process_exits[0].pid++;
  fs.writeFileSync(f.file,JSON.stringify(raw));
  assert.throws(()=>control.readStatus(f.context),{code:'verification_control_corrupt'});
});

test('tampering the canonical bound-proof digest fails even when the payload digest is recomputed',t=>{
  const f=fixture(t);finishWithNativeTranscript(f);
  const raw=JSON.parse(fs.readFileSync(f.file,'utf8'));
  const transcript=raw.cleanup.native_transcript;
  transcript.payload.bound_proof.evidence_sha256='f'.repeat(64);
  rehashPayload(transcript);
  fs.writeFileSync(f.file,JSON.stringify(raw));
  assert.throws(()=>control.readStatus(f.context),{code:'verification_control_corrupt'});
});

test('contained attempts reject a bound proof with no preserved native return',t=>{
  const f=fixture(t),{descriptor}=prepareNativeAttempt(f);
  const bound=control.bindCleanupProof(f.owner,nativeReturn(f,descriptor));
  delete bound.native_return;
  for(const [i,pid] of [2211,2212,2213].entries())
    control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:i+1,pid,
      os_creation_time:birth,method:'process_handle_signaled'});
  const before=fs.readFileSync(f.file);
  assert.throws(()=>control.commitFinish(f.context,f.owner,{outcome:'failed',cleanup_proof:bound}),
    {code:'verification_control_corrupt'});
  assert.deepEqual(fs.readFileSync(f.file),before);
  assert.equal(control.readStatus(f.context).attempt.claimed,true);
});

test('foreign attempt and descriptor bindings fail after the payload digest is recomputed',t=>{
  for(const field of ['attempt_id','descriptor_sha256']) {
    const f=fixture(t);finishWithNativeTranscript(f);
    const raw=JSON.parse(fs.readFileSync(f.file,'utf8'));
    const transcript=raw.cleanup.native_transcript;
    transcript[field]=field==='attempt_id'?'VAT-'+'f'.repeat(32):'f'.repeat(64);
    rehashPayload(transcript);
    fs.writeFileSync(f.file,JSON.stringify(raw));
    assert.throws(()=>control.readStatus(f.context),{code:'verification_control_corrupt'},field);
  }
});

test('oversized native transcript is rejected without releasing the active claim',t=>{
  const f=fixture(t);let before;
  assert.throws(()=>finishWithNativeTranscript(f,{extraNativeReturn:{diagnostic:'x'.repeat(70*1024)},beforeCommit:()=>{before=fs.readFileSync(f.file);}}),
    {code:'verification_control_corrupt'});
  assert.deepEqual(fs.readFileSync(f.file),before);
  const saved=JSON.parse(fs.readFileSync(f.file,'utf8'));
  assert.equal(saved.claimed,true);
  assert.equal(saved.terminal,null);
  assert.equal(saved.cleanup.native_transcript,null);
});

test('sensitive native fields are rejected without redaction or claim release',t=>{
  for(const key of ['owner_token','ownerToken','private_key','privateKey']) {
    const f=fixture(t);let before;
    assert.throws(()=>finishWithNativeTranscript(f,{extraNativeReturn:{[key]:'a'.repeat(64)},beforeCommit:()=>{before=fs.readFileSync(f.file);}}),
      {code:'verification_native_transcript_sensitive'},key);
    assert.deepEqual(fs.readFileSync(f.file),before);
    assert.equal(control.readStatus(f.context).attempt.claimed,true);
    assert.equal(control.readStatus(f.context).attempt.terminal,null);
  }
});

test('a new attempt archives the previous full native transcript',t=>{
  const f=fixture(t),{attempt}=finishWithNativeTranscript(f);
  const archived=path.join(f.root,'maintenance/verification-control/attempts',f.id.attempt_id+'.json');
  assert.equal(fs.existsSync(archived),false);
  const next=control.beginAttempt(f.context,{request_sha256:H});
  const saved=JSON.parse(fs.readFileSync(archived,'utf8'));
  assertJsonEqual(saved.cleanup.native_transcript,attempt.cleanup.native_transcript);
  assertJsonEqual(saved.cleanup.native_transcript.payload,attempt.cleanup.native_transcript.payload);
  assert.notEqual(next.owner.attempt_id,f.id.attempt_id);
  assert.deepEqual(control.readStatus(f.context).attempt.cleanup.native_transcript,null);
});

test('legacy v2 cleanup reads and mutates without inventing a native transcript',t=>{
  const f=fixture(t),legacy=JSON.parse(fs.readFileSync(f.file,'utf8'));
  legacy.schema_version='knowledge-verification-control.v2';
  legacy.cleanup={status:legacy.cleanup.status,attempts:legacy.cleanup.attempts,
    evidence_sha256:legacy.cleanup.evidence_sha256};
  fs.writeFileSync(f.file,JSON.stringify(legacy));
  const before=fs.readFileSync(f.file);
  const read=control.readStatus(f.context).attempt;
  assert.equal(read.schema_version,'knowledge-verification-control.v3');
  assert.equal(read.cleanup.native_transcript,null);
  assert.equal(read.cleanup.transcript_required,false);
  assert.deepEqual(fs.readFileSync(f.file),before);
  control.updateAttempt(f.context,f.owner,{type:'phase',phase:'preparing'});
  const saved=JSON.parse(fs.readFileSync(f.file,'utf8'));
  assert.equal(saved.schema_version,'knowledge-verification-control.v3');
  assert.equal(saved.cleanup.native_transcript,null);
  assert.equal(saved.cleanup.transcript_required,false);
  assert.equal(saved.containment,null);
});

test('accepted cancellation keeps its transcript and cannot release an ACK',t=>{
  const f=fixture(t),{descriptor}=prepareNativeAttempt(f),returned=nativeReturn(f,descriptor);
  const bound=control.bindCleanupProof(f.owner,returned);
  for(const [i,pid] of [2211,2212,2213].entries())
    control.updateAttempt(f.context,f.owner,{type:'process_exit',spawn_id:i+1,pid,
      os_creation_time:birth,method:'process_handle_signaled'});
  control.requestCancel(f.context,f.id);
  const result=control.commitFinish(f.context,f.owner,{outcome:'passed',ack_sha256:H,cleanup_proof:bound});
  assert.equal(result.status,'cancelled');
  assert.equal(result.ack_released,false);
  assert.equal(result.attempt.terminal.ack_sha256,null);
  assertJsonEqual(result.attempt.cleanup.native_transcript.payload.native_return,returned);
  assertJsonEqual(control.readStatus(f.context).attempt.cleanup.native_transcript,
    result.attempt.cleanup.native_transcript);
});
