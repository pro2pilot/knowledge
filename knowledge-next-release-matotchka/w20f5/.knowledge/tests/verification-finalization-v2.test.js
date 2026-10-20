'use strict';
// Synthetic signed reader fixtures only. These do not execute or attest a
// Windows producer, a Job, a deadline controller or application verification.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const finalization=require('../tools/lib/verification-finalization');
const execution=require('../tools/lib/verification-execution');
const HASH='a'.repeat(64),REQUEST='b'.repeat(64);
const stable=value=>JSON.stringify(value,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);
const sign=(value,key)=>({...value,signature:crypto.sign(null,Buffer.from(stable(value)),key).toString('hex')});
function temp(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-ack-v2-'));t.after(()=>{if(process.env.KNOWLEDGE_AUDIT_RETAIN_FIXTURES==='1')return;assert.equal(path.dirname(root),path.resolve(os.tmpdir()));assert(path.basename(root).startsWith('k-ack-v2-'));assert(!fs.lstatSync(root).isSymbolicLink());fs.rmSync(root,{recursive:true,force:true});});return root;}
async function fixture(t,options={}){
 const root=temp(t),keys=crypto.generateKeyPairSync('ed25519'),publicKey=keys.publicKey.export({type:'spki',format:'der'}).toString('hex');
 const batch='KVB-'+crypto.randomBytes(16).toString('hex'),records=[];
 for(let ordinal=0;ordinal<(options.members||1);ordinal++){
  const snapshot=[{path:'probe.js',sha256:HASH}];
  const record={schema_version:'knowledge-verification-execution.v2',task_id:'synthetic-task',session_id:'synthetic-session',command_argv:['node','probe.js'],command:'node probe.js',cwd:'.',status:'pass',exit_code:0,signal:null,timed_out:false,duration_ms:1,executed_at:'2026-10-20T00:00:00.000Z',executed_by:'synthetic-reader-fixture',runtime_binding:'process_exec_path',runtime_sha256:HASH,environment_profile:'sanitized_node',stdout_sha256:HASH,stderr_sha256:HASH,stdout_bytes:0,stderr_bytes:0,source_snapshot_before:snapshot,source_snapshot:snapshot,batch_id:batch,batch_ordinal:ordinal,batch_public_key:publicKey,batch_request_sha256:REQUEST};
  record.content_sha256=execution.executionDigest(record);record.execution_id='KVE-'+record.content_sha256;
  const validation=execution.validateExecutionRecord(record);assert.equal(validation.ok,true,JSON.stringify(validation.errors));
  const dir=path.join(root,'maintenance/verification_executions');fs.mkdirSync(dir,{recursive:true});const file=path.join(dir,record.content_sha256+'.json'),body=Buffer.from(JSON.stringify(record,null,2)+'\n');fs.writeFileSync(file,body);records.push({record,file,physical_sha256:finalization.hash(body)});
 }
 const modern=options.modern!==false;
 const receipt={schema_version:modern?finalization.SCHEMA:finalization.LEGACY_SCHEMA,batch_id:batch,public_key:publicKey,request_sha256:REQUEST,task_id:'synthetic-task',session_id:'synthetic-session',status:'commands_and_teardown_observed',backend:'windows_job_object',teardown:{status:'completed',method:'windows_job_object',active_processes:0,...(modern?{keeper_exited:true}:{})},timeout_ms:modern?100:1000,observed_elapsed_ms:modern?120:10,runtime_sha256:HASH,implementation:(options.paths||(modern?finalization.IMPLEMENTATION_PATHS:finalization.PREVIOUS_IMPLEMENTATION_PATHS)).map(p=>({path:p,sha256:HASH})),executions:records.map(x=>({execution_id:x.record.execution_id,physical_sha256:x.physical_sha256})),...(modern?{work_elapsed_ms:90,cleanup_budget_ms:100}:{})};
 if(options.receipt)options.receipt(receipt);
 const reference=await finalization.persistFinalization(root,receipt);
 let unsigned={schema_version:modern?finalization.ACK_SCHEMA:finalization.LEGACY_ACK_SCHEMA,receipt_id:reference.receipt_id,physical_sha256:reference.physical_sha256,batch_id:batch,timeout_ms:receipt.timeout_ms,accepted_elapsed_ms:modern?130:20,...(modern?{work_elapsed_ms:receipt.work_elapsed_ms,cleanup_budget_ms:receipt.cleanup_budget_ms}:{})};
 if(options.ack)options.ack(unsigned);
 const ack=sign(unsigned,options.wrongKey?crypto.generateKeyPairSync('ed25519').privateKey:keys.privateKey);
 return {root,keys,receipt,reference,ack,records,ids:records.map(x=>x.record.execution_id),read(ids=records.map(x=>x.record.execution_id),acceptances=[ack]){return finalization.requireFinalizedExecutions(root,ids,acceptances);}};
}
const refused=fn=>assert.throws(fn,{code:'verification_finalization_required'});

test('v2 accepts timely work and confirmed cleanup after the work budget; exact signed shape',async t=>{
 const f=await fixture(t);assert.equal(f.read().status,'accepted');assert(f.ack.accepted_elapsed_ms>f.ack.timeout_ms);
 const ack=finalization.acceptFinalization(f.reference,100,130,f.keys.privateKey);
 assert.deepEqual(ack,f.ack);assert.equal(Object.keys(ack).sort().join(','),'accepted_elapsed_ms,batch_id,cleanup_budget_ms,physical_sha256,receipt_id,schema_version,signature,timeout_ms,work_elapsed_ms');
 assert(!('observed_elapsed_ms' in ack));assert.equal(f.read(f.ids,[ack]).status,'accepted');
 const bare={receipt_id:f.reference.receipt_id,physical_sha256:f.reference.physical_sha256,batch_id:f.reference.batch_id};
 assert.deepEqual(finalization.acceptFinalization(bare,100,130,f.keys.privateKey,{work_elapsed_ms:90,cleanup_budget_ms:100}),ack);
});

test('legacy actual formats remain reader-compatible for exact8 and exact10 pins',async t=>{
 for(const paths of [finalization.LEGACY_IMPLEMENTATION_PATHS,finalization.PREVIOUS_IMPLEMENTATION_PATHS]){const f=await fixture(t,{modern:false,paths});assert.equal(f.read().status,'accepted');}
});

test('new schema/pin/proof guards reject coherent signed but invalid fixtures',async t=>{
 const cases=[
  ['v2 legacy8 pins',{paths:finalization.LEGACY_IMPLEMENTATION_PATHS}],
  ['v2 legacy10 pins',{paths:finalization.PREVIOUS_IMPLEMENTATION_PATHS}],
  ['v1 new pins',{modern:false,paths:finalization.IMPLEMENTATION_PATHS}],
  ['v2 missing current pin',{paths:finalization.IMPLEMENTATION_PATHS.slice(0,-1)}],
  ['v2 reordered current pins',{paths:[...finalization.IMPLEMENTATION_PATHS].reverse()}],
  ['v2 keeper missing',{receipt:r=>delete r.teardown.keeper_exited}],
  ['v2 keeper false',{receipt:r=>r.teardown.keeper_exited=false}],
  ['v2 keeper nonboolean',{receipt:r=>r.teardown.keeper_exited=1}],
  ['ACK schema mismatch',{ack:a=>a.schema_version=finalization.LEGACY_ACK_SCHEMA}],
  ['KVF schema mismatch',{receipt:r=>r.schema_version=finalization.LEGACY_SCHEMA}],
  ['extra signed ACK field',{ack:a=>a.heartbeat=true}],
  ['wrong signing key',{wrongKey:true}],
 ];
 for(const [name,opts] of cases)await t.test(name,async t=>{const f=await fixture(t,opts);refused(()=>f.read());});
});

test('coherent signed timing boundaries never turn late work or late cleanup into acceptance',async t=>{
 const cases=[
  ['work at deadline',{receipt:r=>r.work_elapsed_ms=100}],
  ['work beyond deadline',{receipt:r=>r.work_elapsed_ms=101}],
  ['negative work',{receipt:r=>r.work_elapsed_ms=-1}],
  ['cleanup zero',{receipt:r=>r.cleanup_budget_ms=0}],
  ['cleanup fractional',{receipt:r=>r.cleanup_budget_ms=1.5}],
  ['cleanup over max',{receipt:r=>r.cleanup_budget_ms=3600001}],
  ['observed before work',{receipt:r=>r.observed_elapsed_ms=89}],
  ['accepted before observed',{ack:a=>a.accepted_elapsed_ms=119}],
  ['accepted at cleanup deadline',{ack:a=>a.accepted_elapsed_ms=190}],
  ['accepted beyond cleanup deadline',{ack:a=>a.accepted_elapsed_ms=191}],
  ['ACK work differs from KVF',{ack:a=>a.work_elapsed_ms=89}],
  ['ACK cleanup differs from KVF',{ack:a=>a.cleanup_budget_ms=101}],
  ['ACK timeout differs from KVF',{ack:a=>a.timeout_ms=101}],
 ];
 for(const [name,opts] of cases)await t.test(name,async t=>{const f=await fixture(t,opts);refused(()=>f.read());});
});

test('signer rejects invalid, active and inconsistent timing before signing',async t=>{
 const f=await fixture(t);
 for(const timing of [{work_elapsed_ms:100,cleanup_budget_ms:100},{work_elapsed_ms:90,cleanup_budget_ms:0},{work_elapsed_ms:89,cleanup_budget_ms:100},{work_elapsed_ms:90,cleanup_budget_ms:101},{work_elapsed_ms:null,cleanup_budget_ms:100},{work_elapsed_ms:NaN,cleanup_budget_ms:100},{work_elapsed_ms:90,cleanup_budget_ms:100,heartbeat:true},null,true])refused(()=>finalization.acceptFinalization(f.reference,100,130,f.keys.privateKey,timing));
 refused(()=>finalization.acceptFinalization(f.reference,100,119,f.keys.privateKey));refused(()=>finalization.acceptFinalization(f.reference,100,190,f.keys.privateKey));
 let called=0;refused(()=>finalization.acceptFinalization(f.reference,100,130,f.keys.privateKey,{get work_elapsed_ms(){called++;return 90;},cleanup_budget_ms:100}));assert.equal(called,0);
 refused(()=>finalization.acceptFinalization(null,100,130,f.keys.privateKey));
});

test('v1 retains its original total-budget boundary and cannot mix new fields',async t=>{
 const f=await fixture(t,{modern:false,ack:a=>a.accepted_elapsed_ms=1000});refused(()=>f.read());
 const mixed=await fixture(t,{modern:false,ack:a=>a.cleanup_budget_ms=100});refused(()=>mixed.read());
});

test('all-sibling physical bindings and signature tampering still fail closed',async t=>{
 const f=await fixture(t,{members:2});assert.equal(f.read([f.ids[0]]).execution_records.length,2);
 const signatureTamper={...f.ack,accepted_elapsed_ms:131};refused(()=>f.read(f.ids,[signatureTamper]));
 refused(()=>f.read([f.ids[0],f.ids[0]]));refused(()=>f.read(f.ids,[f.ack,f.ack]));
 fs.appendFileSync(f.records[1].file,'\n');refused(()=>f.read([f.ids[0]]));
});
