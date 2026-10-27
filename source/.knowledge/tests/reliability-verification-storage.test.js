'use strict';
// Actual fixed storage worker, ledger, common native lease and child exits.
// No Darwin broker replies are simulated here; these cases stop before prepare.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process'),crypto=require('node:crypto');
const control=require('../tools/lib/verification-control'),recovery=require('../tools/lib/verification-recovery');
const H='1'.repeat(64),N='2'.repeat(64),hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const worker=path.resolve(__dirname,'../tools/lib/verification-darwin-store.js');
const fault=path.join(__dirname,'helpers/reliability-storage-init-ack-fault.cjs');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const proof=owner=>({method:'no_processes_started',attempt_id:owner.attempt_id,generation:owner.generation});
function fixture(t){
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-storage-lifetime-')));
  const f={root,context:{stateRoot:root},request:{stateRoot:root,repoRoot:root,tests:[]},actors:[],file:path.join(root,'maintenance/verification-control/active.json')};
  t.after(async()=>{
    for(const actor of f.actors){if(actor.child.exitCode===null && actor.child.signalCode===null)actor.child.kill('SIGKILL');
      await actor.closed;}
    fs.rmSync(root,{recursive:true,force:true});
  });return f;
}
function actor(f,file=worker,{faulted=false,fifo=null}={}){
  const child=cp.fork(file,file===worker?[]:[f.root],{execArgv:faulted?['--require',fault]:[],
    env:{...process.env,NODE_OPTIONS:'',NODE_PATH:'',...(fifo?{KNOWLEDGE_TEST_STORAGE_ACK_FIFO:fifo}:{})},
    stdio:file===worker?['ignore','pipe','pipe','pipe','ipc']:['ignore','pipe','pipe','ipc']});
  const messages=[],pending=new Map();let stdout='',stderr='',sequence=0,exit=null;
  child.stdout.on('data',b=>{stdout+=b;assert(stdout.length<65536);});
  child.stderr.on('data',b=>{stderr+=b;assert(stderr.length<65536);});
  child.on('message',message=>{
    messages.push(message);const waiting=pending.get(message.id);
    if(waiting){pending.delete(message.id);message.ok?waiting.resolve(message.value):waiting.reject(Object.assign(new Error(message.code),{code:message.code}));}
  });
  const closed=new Promise(resolve=>child.once('close',(code,signal)=>{
    exit={code,signal,ipc_closed:!child.connected};
    for(const waiting of pending.values())waiting.reject(Object.assign(new Error('child exited'),{code:'test_child_exited'}));
    pending.clear();resolve(exit);
  }));
  const value={child,closed,messages,get stdout(){return stdout;},get stderr(){return stderr;},
    async waitFor(predicate){const end=Date.now()+10000;while(!predicate()){if(exit)throw new Error('Child exited: '+JSON.stringify({exit,stderr}));
      if(Date.now()>end)throw new Error('Owned child observation timeout: '+JSON.stringify({messages,stdout,stderr}));await delay(10);}},
    request(op,fields={}){const id=++sequence;return new Promise((resolve,reject)=>{
      pending.set(id,{resolve,reject});child.send({protocol:'knowledge-darwin-storage.v1',id,op,...fields},error=>{if(error){pending.delete(id);reject(error);}});
    });},
    async finish(){child.send({protocol:'knowledge-darwin-storage.v1',id:++sequence,op:'exit'});const result=await closed;
      assert.deepEqual(result,{code:0,signal:null,ipc_closed:true},stderr);return result;},
    async kill(){if(!exit)child.kill('SIGKILL');return closed;}
  };f.actors.push(value);return value;
}
function init(f,s,nonce=N){return s.request('init',{request:f.request,nonce,config:{enabled:false},
  profile:{work_budget_ms:120000,no_progress_ms:60000,cleanup_budget_ms:30000},
  deadline_ns:String(process.hrtime.bigint()+120000000000n)});}
test('lifetime admission requires the actual held storage lease and a complete startup nonce binding',t=>{
  const f=fixture(t);
  assert.throws(()=>control.beginAttempt(f.context,{request_sha256:H,storage_protocol:control.STORAGE_PROTOCOL,startup_nonce_sha256:hash(N)}),
    {code:'verification_storage_lease_required'});
  assert.equal(fs.existsSync(f.file),false);
  const lease=control.acquireStorageLease(f.context);
  try{assert.throws(()=>control.beginAttempt(f.context,{request_sha256:H,storage_protocol:control.STORAGE_PROTOCOL}),{code:'verification_startup_nonce_invalid'});
    assert.equal(fs.existsSync(f.file),false);}finally{lease.release();}
});
test('an actual live storage worker blocks direct recovery and mutation while cancellation remains independent', {timeout:20000},async t=>{
  const f=fixture(t),s=actor(f),opened=await init(f,s),id={attempt_id:opened.owner.attempt_id,generation:opened.owner.generation};
  assert.equal(control.readStatus(f.context).attempt.startup_nonce_sha256,hash(N));
  assert.throws(()=>control.recoverAttempt(f.context,id),{code:'verification_storage_lease_required'});
  assert.throws(()=>control.updateAttempt(f.context,opened.owner,{type:'phase',phase:'preparing'}),{code:'verification_storage_lease_required'});
  assert.equal(control.requestCancel(f.context,id).status,'cancel_requested');
  const result=await s.request('finish_failed',{input:{outcome:'failed',cleanup_proof:proof(opened.owner)}});
  assert.equal(result.status,'cancelled');assert.equal(result.ack_released,false);await s.finish();
});
test('terminal ledger state cannot admit a successor until the original storage worker releases its lifetime lease', {timeout:20000},async t=>{
  const f=fixture(t),s=actor(f),opened=await init(f,s);
  await s.request('finish_failed',{input:{outcome:'failed',cleanup_proof:proof(opened.owner)}});
  const contender=actor(f,path.join(__dirname,'helpers/reliability-storage-contender.cjs'));
  await contender.waitFor(()=>contender.messages.some(m=>m.stage==='starting'));
  await delay(200);
  assert.equal(contender.messages.some(m=>m.stage==='result'),false);
  assert.equal(s.child.exitCode,null);assert.equal(control.readStatus(f.context).attempt.generation,opened.owner.generation);
  await s.finish();await contender.closed;
  const result=contender.messages.find(m=>m.stage==='result');assert(result && !result.error,JSON.stringify(result));
  assert.notEqual(result.value.owner.generation,opened.owner.generation);
  assert.equal(control.commitFinish(f.context,result.value.owner,{outcome:'failed',cleanup_proof:proof(result.value.owner)}).ack_released,false);
});
test('lost init ACK plus actual blocking FIFO cannot free storage before exact worker death; nonce recovers afterwards',
  {skip:process.platform==='win32',timeout:20000},async t=>{
  const f=fixture(t),fifo=path.join(f.root,'ack-block.fifo');
  const created=cp.spawnSync('mkfifo',[fifo],{encoding:'utf8',timeout:10000});assert.ifError(created.error);assert.equal(created.status,0,created.stderr);
  const s=actor(f,worker,{faulted:true,fifo});let acknowledged=false;
  const pending=init(f,s).then(()=>{acknowledged=true;},()=>{});
  await s.waitFor(()=>s.stdout.includes('DURABLE_INIT_BEFORE_ACK'));
  const before=fs.readFileSync(f.file),record=control.readStatus(f.context).attempt;
  assert.equal(record.startup_nonce_sha256,hash(N));assert.equal(acknowledged,false);
  assert.throws(()=>recovery.recoverAttempt(f.context,{startup_nonce_sha256:hash('wrong')}),{code:'verification_attempt_mismatch'});
  assert.throws(()=>recovery.recoverAttempt(f.context,{startup_nonce_sha256:hash(N),deadline_ns:String(process.hrtime.bigint()+250000000n)}),
    error=>['lock_timeout','verification_recovery_budget_exceeded'].includes(error.code));
  assert.deepEqual(fs.readFileSync(f.file),before);assert.equal(s.child.exitCode,null);
  const exit=await s.kill();await pending;
  assert.equal(exit.signal,'SIGKILL');assert.equal(exit.ipc_closed,true);
  const recovered=recovery.recoverAttempt(f.context,{startup_nonce_sha256:hash(N)});
  assert.equal(recovered.status,'failed');assert.equal(recovered.ack_released,false);assert.equal(recovered.attempt.claimed,false);
  assert.deepEqual(recovered.attempt.processes,[]);assert.equal(acknowledged,false);
});
test('an older startup nonce cannot recover a successor having the same request bytes', {timeout:20000},async t=>{
  const f=fixture(t),first=actor(f);await init(f,first);await first.finish();
  assert.equal(recovery.recoverAttempt(f.context,{startup_nonce_sha256:hash(N)}).status,'failed');
  const second=actor(f);await init(f,second,'3'.repeat(64));const before=fs.readFileSync(f.file);
  assert.throws(()=>recovery.recoverAttempt(f.context,{startup_nonce_sha256:hash(N)}),{code:'verification_attempt_mismatch'});
  assert.deepEqual(fs.readFileSync(f.file),before);await second.finish();
  assert.equal(recovery.recoverAttempt(f.context,{startup_nonce_sha256:hash('3'.repeat(64))}).status,'failed');
});
test('releasing local storage authority permanently prevents later owner writes through that handle',t=>{
  const f=fixture(t),lease=control.acquireStorageLease(f.context);
  const opened=control.beginAttempt(f.context,{request_sha256:H,storage_protocol:control.STORAGE_PROTOCOL,startup_nonce_sha256:hash(N)});
  lease.release();const before=fs.readFileSync(f.file);
  assert.equal(lease.release(),false);
  assert.throws(()=>control.updateAttempt(f.context,opened.owner,{type:'phase',phase:'preparing'}),{code:'verification_storage_lease_required'});
  assert.deepEqual(fs.readFileSync(f.file),before);
  assert.equal(recovery.recoverAttempt(f.context,{startup_nonce_sha256:hash(N)}).status,'failed');
});
