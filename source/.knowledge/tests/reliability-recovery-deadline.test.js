'use strict';
// Actual ledger/leases. A deterministic delay at the lease callback models
// slow admission; it does not fabricate any native process-death observation.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const control=require('../tools/lib/verification-control'),recovery=require('../tools/lib/verification-recovery');
const H='1'.repeat(64),N='2'.repeat(64);
function fixture(t){
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-recovery-deadline-'))),context={stateRoot:root};
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const lease=control.acquireStorageLease(context);
  const opened=control.beginAttempt(context,{request_sha256:H,storage_protocol:control.STORAGE_PROTOCOL,startup_nonce_sha256:N});
  lease.release();
  return {root,context,owner:opened.owner,id:{attempt_id:opened.owner.attempt_id,generation:opened.owner.generation},
    file:path.join(root,'maintenance/verification-control/active.json')};
}
test('an expired outer cleanup deadline cannot terminalize a reserved no-process attempt',t=>{
  const f=fixture(t),bytes=fs.readFileSync(f.file);
  assert.throws(()=>recovery.recoverAttempt(f.context,{...f.id,deadline_ns:String(process.hrtime.bigint()-1n)}),
    {code:'verification_recovery_budget_exceeded'});
  assert.deepEqual(fs.readFileSync(f.file),bytes);
});
test('a malformed outer cleanup deadline cannot silently start a fresh profile budget',t=>{
  const f=fixture(t),bytes=fs.readFileSync(f.file);
  assert.throws(()=>recovery.recoverAttempt(f.context,{...f.id,deadline_ns:'not-a-monotonic-deadline'}),
    {code:'verification_clock_invalid'});
  assert.deepEqual(fs.readFileSync(f.file),bytes);
});
test('storage admission delay consumes the existing outer cleanup epoch before narrow recovery',t=>{
  const f=fixture(t),bytes=fs.readFileSync(f.file),original=control.withStorageLease;
  const deadline=process.hrtime.bigint()+1000000000n;
  let observedTimeout;
  t.mock.method(control,'withStorageLease',(context,action,options)=>{
    observedTimeout=options.timeoutMs;
    return original(context,()=>{
      const left=Number(deadline-process.hrtime.bigint())/1e6;
      if(left>0)Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,left+20);
      return action();
    },options);
  });
  assert.throws(()=>recovery.recoverAttempt(f.context,{...f.id,deadline_ns:String(deadline)}),
    {code:'verification_recovery_budget_exceeded'});
  assert(observedTimeout>0 && observedTimeout<=1000);
  assert.deepEqual(fs.readFileSync(f.file),bytes);
});
test('a later caller deadline cannot enlarge the configured cleanup admission budget',t=>{
  const f=fixture(t),stop=Object.assign(new Error('owned observation boundary'),{code:'test_boundary'});
  let observed;
  t.mock.method(control,'withStorageLease',(_context,_action,options)=>{observed=options.timeoutMs;throw stop;});
  assert.throws(()=>recovery.recoverAttempt(f.context,{...f.id,deadline_ns:String(process.hrtime.bigint()+3600000000000n)}),
    error=>error===stop);
  assert(observed>0 && observed<=30000);assert.equal(control.readStatus(f.context).attempt.claimed,true);
});
