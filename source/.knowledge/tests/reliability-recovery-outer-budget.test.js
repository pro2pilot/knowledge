'use strict';
// Real ledger and storage lease; deterministic monotonic scheduling delays.
// These tests do not claim native process closure or kernel I/O-stall coverage.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const control=require('../tools/lib/verification-control');
const recovery=require('../tools/lib/verification-recovery');

function fixture(t){
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-recovery-outer-budget-')));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const context={stateRoot:root},lease=control.acquireStorageLease(context);
  const {owner}=control.beginAttempt(context,{request_sha256:'1'.repeat(64),
    storage_protocol:control.STORAGE_PROTOCOL,startup_nonce_sha256:'2'.repeat(64),
    profile:{cleanup_budget_ms:10000}});
  lease.release();
  const clock=process.hrtime.bigint;let offset=0n;
  t.mock.method(process.hrtime,'bigint',()=>clock()+offset);
  return {context,id:{attempt_id:owner.attempt_id,generation:owner.generation},
    active:path.join(root,'maintenance/verification-control/active.json'),
    delay(ms){offset+=BigInt(ms)*1000000n;}};
}
function failedTerminal(f){
  const attempt=control.readStatus(f.context).attempt;
  assert.equal(attempt.claimed,false);
  assert.equal(attempt.cleanup.status,'confirmed');
  assert.equal(attempt.terminal.outcome,'failed');
  assert.equal(attempt.terminal.ack_sha256,null);
}

test('narrow recovery preserves the original profile epoch across lease admission and final ledger write',t=>{
  const f=fixture(t),withLease=control.withStorageLease,rename=fs.renameSync;
  let admissions=0,terminalWrites=0;
  t.mock.method(control,'withStorageLease',(context,action,options)=>withLease(context,()=>{
    admissions++;f.delay(9000);return action();
  },options));
  t.mock.method(fs,'renameSync',function(from,to,...args){
    const result=rename.call(fs,from,to,...args);
    if(admissions===1 && path.resolve(to)===f.active && terminalWrites===0){terminalWrites++;f.delay(2000);}
    return result;
  });
  const started=process.hrtime.bigint();
  assert.throws(()=>recovery.recoverAttempt(f.context,f.id),{code:'verification_recovery_budget_exceeded'});
  assert.equal(admissions,1);assert.equal(terminalWrites,1);
  assert(process.hrtime.bigint()-started>10000000000n);
  // The closure was valid and became durable before the late response.
  failedTerminal(f);
});

test('a late storage-lease return cannot report timely recovery after a durable terminal write',t=>{
  const f=fixture(t),withLease=control.withStorageLease;
  let releaseReturns=0;
  t.mock.method(control,'withStorageLease',(context,action,options)=>{
    const result=withLease(context,action,options);
    releaseReturns++;f.delay(11000);return result;
  });
  const started=process.hrtime.bigint();
  assert.throws(()=>recovery.recoverAttempt(f.context,f.id),{code:'verification_recovery_budget_exceeded'});
  assert.equal(releaseReturns,1);
  assert(process.hrtime.bigint()-started>10000000000n);
  failedTerminal(f);
});
