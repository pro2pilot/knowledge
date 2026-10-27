'use strict';

// Actual filesystem and Linux namespaces. Fault hooks pause one existing
// publication call; they do not replace native process/closure observations.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const source=process.env.KNOWLEDGE_CONTROL_INITIAL_SOURCE||path.resolve(__dirname,'..'),control=require(path.join(source,'tools/lib/verification-control.js'));
const recovery=require(path.join(source,'tools/lib/verification-recovery.js'));
const runner=require(path.join(source,'tools/lib/command-runner.js'));
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const hash=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function state(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-control-initial-')),stateRoot=path.join(root,'.knowledge');fs.mkdirSync(stateRoot);
  const context={stateRoot,projectKnowledgeRoot:stateRoot,targetRoot:root,systemRoot:source};
  return {root,context,active:path.join(stateRoot,'maintenance','verification-control','active.json'),
    initial:path.join(stateRoot,'maintenance','verification-control-initial.json')};
}
async function stoppedPublication(t,mode) {
  const f=state(t),marker=path.join(f.root,'boundary.json'),worker=path.join(f.root,'writer.cjs');
  let complete=false;
  const session=await runner.createCommandSession({budgets:{setupMs:30000,workMs:60000,cleanupMs:10000,progressMs:0}});
  t.after(async()=>{
    try {complete=(await session.finish()).status==='completed';} catch {complete=false;}
    if(complete)fs.rmSync(f.root,{recursive:true,force:true});else t.diagnostic(JSON.stringify({fixture_retained_unconfirmed:f.root}));
  });
  const invocation={schema_version:'knowledge-verification-invocation.v1',nonce_sha256:crypto.randomBytes(32).toString('hex'),
    scope_sha256:hash(session.scope),scope:session.scope};
  fs.writeFileSync(worker,`const fs=require('fs'),path=require('path');const input=JSON.parse(process.argv[2]);
    const store=require(${JSON.stringify(path.join(source,'tools/lib/json-store.js'))});
    const pause=()=>{fs.writeFileSync(${JSON.stringify(marker)},JSON.stringify({pid:process.pid,mode:${JSON.stringify(mode)}}));Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);};
    if(${JSON.stringify(mode)}==='before_directory') {const original=store.ensureContainedDir;store.ensureContainedDir=function(root,target){if(target===path.dirname(${JSON.stringify(f.active)})&&!fs.existsSync(${JSON.stringify(marker)}))pause();return original.apply(this,arguments);};}
    else {const original=store.writeJsonAtomicContained;store.writeJsonAtomicContained=function(file){if(file===${JSON.stringify(f.active)}&&!fs.existsSync(file)&&!fs.existsSync(${JSON.stringify(marker)}))pause();return original.apply(this,arguments);};}
    const result=require(${JSON.stringify(path.join(source,'tools/lib/verification-control.js'))}).beginAttempt(input.context,
      {request_sha256:'a'.repeat(64),profile:{work_budget_ms:60000,no_progress_ms:0,cleanup_budget_ms:10000},invocation:input.invocation});
    process.stdout.write(JSON.stringify(result.attempt));\n`);
  let outcome;
  const running=session.run({executable:process.execPath,args:[worker,JSON.stringify({context:f.context,invocation})],cwd:f.root})
    .then(value=>{outcome={returned:value};},error=>{outcome={error:{code:error.code,cleanup:error.cleanup}};});
  const end=process.hrtime.bigint()+10000000000n;
  while(!fs.existsSync(marker)&&!outcome&&process.hrtime.bigint()<end)await delay(10);
  assert(fs.existsSync(marker),'Exact initial publication boundary must be reached');
  assert.equal(fs.existsSync(f.active),false);
  let observed,error;
  try{observed=control.readStatus(f.context).attempt;}catch(e){error=e;}
  t.diagnostic(JSON.stringify({boundary:mode,read_error:error?.code,claimed:observed?.claimed,
    exact_invocation:observed?.invocation?.scope_sha256===invocation.scope_sha256}));
  // The external native controller closes the real entire recorded scope.
  const closed=await session.finish();complete=closed.status==='completed';await running;
  assert.equal(closed.status,'completed',JSON.stringify(closed));
  if(error)throw error;
  assert(observed?.claimed,'Ownership must be visible before active.json exists');
  assert.equal(JSON.stringify(observed.invocation),JSON.stringify(invocation));
  const result=recovery.recoverAttempt(f.context,{attempt_id:observed.attempt_id,generation:observed.generation});
  assert.equal(result.status,'failed');assert.equal(result.ack_released,false);assert.equal(result.attempt.claimed,false);
  assert.equal(result.attempt.cleanup.invocation_transcript.scope_sha256,invocation.scope_sha256);
  assert.equal(result.attempt.processes.length,0);
  assert.equal(fs.existsSync(f.initial),false,'Only the matching journal retires after active readback');
  const next=control.beginAttempt(f.context,{request_sha256:'b'.repeat(64)});
  assert.notEqual(next.attempt.generation,observed.generation);
  assert.equal(control.recoverAttempt(f.context,{attempt_id:next.attempt.attempt_id,generation:next.attempt.generation}).ack_released,false);
}

test('a crash before the first control directory leaves the exact native claim recoverable',
  {skip:process.platform!=='linux',timeout:45000},t=>stoppedPublication(t,'before_directory'));
test('a crash after directory creation but before active publication leaves the exact native claim recoverable',
  {skip:process.platform!=='linux',timeout:45000},t=>stoppedPublication(t,'before_active'));

test('a matching initial journal allows advanced cancellation state and is retired without losing it',()=>{
  const f=state();try{
    const begun=control.beginAttempt(f.context,{request_sha256:'c'.repeat(64)});
    const initial=fs.readFileSync(f.active);
    control.requestCancel(f.context,{attempt_id:begun.attempt.attempt_id,generation:begun.attempt.generation});
    fs.writeFileSync(f.initial,initial);
    assert.equal(control.readStatus(f.context).attempt.cancel.requested,true);
    const done=control.recoverAttempt(f.context,{attempt_id:begun.attempt.attempt_id,generation:begun.attempt.generation});
    assert.equal(done.status,'cancelled');assert.equal(done.ack_released,false);
    assert.equal(fs.existsSync(f.initial),false);
  }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});
test('an initial journal and a different active generation remain an explicit conflict',()=>{
  const f=state();try{
    const a=control.beginAttempt(f.context,{request_sha256:'d'.repeat(64)}),journal=fs.readFileSync(f.active);
    control.recoverAttempt(f.context,{attempt_id:a.attempt.attempt_id,generation:a.attempt.generation});
    control.beginAttempt(f.context,{request_sha256:'e'.repeat(64)});
    fs.writeFileSync(f.initial,journal);const active=fs.readFileSync(f.active);
    assert.throws(()=>control.readStatus(f.context),{code:'verification_control_initial_conflict'});
    assert.throws(()=>control.beginAttempt(f.context,{request_sha256:'f'.repeat(64)}),{code:'verification_control_initial_conflict'});
    assert.deepEqual(fs.readFileSync(f.active),active);assert.deepEqual(fs.readFileSync(f.initial),journal);
  }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});
test('malformed initial state cannot be ignored beside a valid active owner',()=>{
  const f=state();try{
    control.beginAttempt(f.context,{request_sha256:'a'.repeat(64)});const active=fs.readFileSync(f.active);
    fs.writeFileSync(f.initial,'{}\n');
    assert.throws(()=>control.readStatus(f.context),error=>/^verification_control_/.test(error.code));
    assert.deepEqual(fs.readFileSync(f.active),active);assert.equal(fs.readFileSync(f.initial,'utf8'),'{}\n');
  }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});
test('loss of active.json after journal retirement still fails closed',()=>{
  const f=state();try{
    control.beginAttempt(f.context,{request_sha256:'a'.repeat(64)});assert.equal(fs.existsSync(f.initial),false);
    fs.unlinkSync(f.active);
    assert.throws(()=>control.readStatus(f.context),{code:'verification_control_missing'});
  }finally{fs.rmSync(f.root,{recursive:true,force:true});}
});
