'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {spawn}=require('node:child_process');
const source=process.env.KNOWLEDGE_LOCK_TEST_SOURCE?path.resolve(process.env.KNOWLEDGE_LOCK_TEST_SOURCE):path.resolve(__dirname,'..');
const manager=require(path.join(source,'tools/lib/contained-lock-manager')), {LOCKS,LOCK_POLICY}=require(path.join(source,'tools/lib/lock-policy'));
const worker=path.join(__dirname,'helpers/reliability-lock-worker.cjs');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function snap(file){const s=fs.lstatSync(file,{bigint:true});return [s.dev,s.ino];}
function fixture(t){
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-lock-lifecycle-'))), children=[];
  t.after(async()=>{for(const item of children){if(item.child.exitCode===null&&item.child.signalCode===null)item.child.kill('SIGKILL');await item.done;}fs.rmSync(root,{recursive:true,force:true});});
  const state=path.join(root,'state'),request={rootKind:'state',rootPath:state,context:{stateRoot:state},lockName:'team-flow',purpose:LOCKS['team-flow'].purpose};
  function launch(mode,token=mode){
    const child=spawn(process.execPath,[...(mode==='gc-held'?['--expose-gc']:[]),worker,source,root,mode,token],{env:{...process.env,NODE_OPTIONS:'',NODE_PATH:''},stdio:['ignore','pipe','pipe']});
    const item={child,stdout:'',stderr:'',token};child.stdout.on('data',x=>item.stdout+=x);child.stderr.on('data',x=>item.stderr+=x);
    item.done=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal,stdout:item.stdout,stderr:item.stderr}));});
    children.push(item);return item;
  }
  async function ready(item){const deadline=Date.now()+15000,file=path.join(root,`ready-${item.token}.json`);while(Date.now()<deadline){if(fs.existsSync(file))return JSON.parse(fs.readFileSync(file,'utf8'));if(item.child.exitCode!==null||item.child.signalCode!==null)throw new Error(`worker exited before boundary: ${item.stderr} ${item.stdout}`);await delay(10);}throw new Error('Owned child did not reach scheduling boundary');}
  return {root,state,request,publicPath:path.join(state,'locks/v1/team-flow.lock'),launch,ready};
}

test('real SIGKILL before owner preparation leaves no public ownerless lock', {timeout:20000}, async t=>{
  const f=fixture(t),child=f.launch('before-owner');await f.ready(child);
  // Same semantic boundary on the legacy and new implementation: directory
  // creation has happened, owner bytes have not. The crash is an OS kill.
  const publicBefore=fs.existsSync(f.publicPath);
  child.child.kill('SIGKILL');const exit=await child.done;assert.ok(exit.signal==='SIGKILL'||exit.code!==0);
  assert.equal(publicBefore,false,'An incomplete owner must never occupy the public admission name.');
  const stages=fs.readdirSync(path.join(f.state,'locks/v1/.release')).filter(name=>name.startsWith('publish-'));
  assert.equal(stages.length,1);const orphan=path.join(f.state,'locks/v1/.release',stages[0]),before=snap(orphan);
  const handle=manager.acquireContainedLock(f.request);handle.release();
  assert.deepEqual(snap(orphan),before,'Unknown private crash debris is retained without blocking a fresh admission.');
  assert.equal(manager.inspectLockSafety(f.request).status,'safe');
});
test('real SIGKILL after publication before acknowledgment recovers without waiting on wall age', {timeout:20000}, async t=>{
  const f=fixture(t),child=f.launch('after-publish');await f.ready(child);
  const owner=fs.readFileSync(path.join(f.publicPath,'owner.json'));const parsed=JSON.parse(owner);
  if(parsed.schema_version==='knowledge-lock-owner.v3')assert.equal(parsed.kernel_lease.method,process.platform==='win32'?'windows-owner-event.v1':'owner-inode-lease.v1');
  else assert.ok(parsed.native_identity,'The legacy physical acceptance requires its qualified native owner provider.');
  assert.equal(LOCK_POLICY.default_stale_ms,120000);assert.equal(LOCK_POLICY.default_timeout_ms,30000);
  child.child.kill('SIGKILL');await child.done;
  const start=process.hrtime.bigint();const h=manager.acquireContainedLock({...f.request,timeoutMs:2000});h.release();
  assert.ok(Number(process.hrtime.bigint()-start)/1e6<2000,'Exact death should recover without the legacy 120-second age gate.');
  const retained=fs.readdirSync(path.join(f.state,'locks/v1/.stale'));
  assert.equal(retained.length,1);assert.deepEqual(fs.readFileSync(path.join(f.state,'locks/v1/.stale',retained[0],'owner.json')),owner);
});
test('a paused prepared publisher cannot replace an intervening live owner', {timeout:20000}, async t=>{
  const f=fixture(t),child=f.launch('before-publish');await f.ready(child);
  const live=manager.acquireContainedLock(f.request);t.after(()=>{try{live.release();}catch{}});
  const before=snap(f.publicPath),owner=fs.readFileSync(path.join(f.publicPath,'owner.json'));
  fs.writeFileSync(path.join(f.root,'gate-before-publish'),'resume');const exit=await child.done;
  assert.equal(exit.code,0,exit.stderr);assert.match(exit.stdout,/"code":"lock_timeout"/);
  assert.deepEqual(snap(f.publicPath),before);assert.deepEqual(fs.readFileSync(path.join(f.publicPath,'owner.json')),owner);
  live.release();
});
test('competing real processes serialize every mutation with the normal production budget', {timeout:45000}, async t=>{
  const f=fixture(t),children=Array.from({length:6},(_,i)=>f.launch('counter',String(i)));
  const exits=await Promise.all(children.map(item=>item.done));for(const exit of exits)assert.equal(exit.code,0,exit.stderr);
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.root,'counter.json'),'utf8')),30);
  const rows=fs.readFileSync(path.join(f.root,'order.ndjson'),'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(rows.length,60);for(let i=0;i<rows.length;i+=2){assert.equal(rows[i].event,'enter');assert.equal(rows[i+1].event,'leave');assert.equal(rows[i].token,rows[i+1].token);assert.equal(rows[i].i,rows[i+1].i);}
});
test('legacy ownerless public state is preserved, including after its diagnostic grace', {timeout:10000}, t=>{
  const f=fixture(t);fs.mkdirSync(f.publicPath,{recursive:true});const old=new Date(Date.now()-86400000);fs.utimesSync(f.publicPath,old,old);const before=snap(f.publicPath);
  assert.throws(()=>manager.acquireContainedLock({...f.request,timeoutMs:200}),e=>e.code==='lock_timeout'&&e.owner_disposition==='owner_initialization_unconfirmed');
  assert.deepEqual(snap(f.publicPath),before);assert.deepEqual(fs.readdirSync(f.publicPath),[]);
  assert.equal(manager.inspectLockSafety(f.request).status,'unsafe');
});
test('slow preparation cannot admit work after the original acquisition deadline', {timeout:10000}, t=>{
  const f=fixture(t),sync=fs.fsyncSync;let delayed=false,handle,error;
  fs.fsyncSync=function(fd){if(!delayed&&fs.fstatSync(fd).isFile()){delayed=true;Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,150);}return sync.apply(this,arguments);};
  try{handle=manager.acquireContainedLock({...f.request,timeoutMs:100});}catch(e){error=e;}finally{fs.fsyncSync=sync;if(handle)handle.release();}
  assert.equal(delayed,true);assert.equal(error?.code,'lock_timeout');assert.equal(fs.existsSync(f.publicPath),false);
});
test('wall-clock jumps do not reset the elapsed contender budget', {timeout:10000}, t=>{
  const f=fixture(t),live=manager.acquireContainedLock(f.request),now=Date.now;let error;
  const start=process.hrtime.bigint();Date.now=()=>now()-86400000;
  try{manager.acquireContainedLock({...f.request,timeoutMs:200});}catch(e){error=e;}finally{Date.now=now;live.release();}
  const elapsed=Number(process.hrtime.bigint()-start)/1e6;assert.equal(error?.code,'lock_timeout');assert.ok(elapsed>=200&&elapsed<4000,`elapsed ${elapsed}`);
});
test('a v3 reclaimer holds the old owner lease while paused before namespace retirement', {timeout:20000}, async t=>{
  const f=fixture(t),departed=f.launch('exit-held');assert.equal((await departed.done).code,0);
  const bytes=fs.readFileSync(path.join(f.publicPath,'owner.json')),before=snap(f.publicPath);
  const reclaimer=f.launch('before-stale-rename');await f.ready(reclaimer);
  assert.throws(()=>manager.acquireContainedLock({...f.request,timeoutMs:250}),error=>error.code==='lock_timeout'&&error.owner_disposition==='kernel_owner_lease_held');
  assert.deepEqual(snap(f.publicPath),before);assert.deepEqual(fs.readFileSync(path.join(f.publicPath,'owner.json')),bytes);
  fs.writeFileSync(path.join(f.root,'gate-before-stale-rename'),'resume');const exit=await reclaimer.done;assert.equal(exit.code,0,exit.stderr);
  const next=manager.acquireContainedLock(f.request);next.release();
});
test('real process exit is recoverable even when the optional procfs identity was unavailable', {timeout:20000}, async t=>{
  const f=fixture(t),child=f.launch('exit-held-no-proc');const exit=await child.done;assert.equal(exit.code,0,exit.stderr);
  const owner=JSON.parse(fs.readFileSync(path.join(f.publicPath,'owner.json')));assert.equal(owner.native_identity,null);assert.equal(owner.kernel_lease.method,process.platform==='win32'?'windows-owner-event.v1':'owner-inode-lease.v1');
  const next=manager.acquireContainedLock(f.request);assert.notEqual(next.lock_id,owner.lock_id);next.release();
});
test('garbage collection of the JS handle cannot release a live native writer lease', {timeout:20000}, async t=>{
  const f=fixture(t),child=f.launch('gc-held'),ready=await f.ready(child);assert.equal(ready.collected,true);
  const before=snap(f.publicPath),owner=fs.readFileSync(path.join(f.publicPath,'owner.json'));
  assert.throws(()=>manager.acquireContainedLock({...f.request,timeoutMs:250}),error=>error.code==='lock_timeout'&&error.owner_disposition==='kernel_owner_lease_held');
  assert.deepEqual(snap(f.publicPath),before);assert.deepEqual(fs.readFileSync(path.join(f.publicPath,'owner.json')),owner);
  child.child.kill('SIGKILL');await child.done;const next=manager.acquireContainedLock(f.request);next.release();
});
test('repeated ordinary owner reads and unsuccessful probes never unlock the holder', {timeout:10000}, t=>{
  const f=fixture(t),held=manager.acquireContainedLock(f.request),native=require(path.join(source,'tools/lib/lock-publication'));
  try{for(let i=0;i<40;i++){const bytes=fs.readFileSync(path.join(f.publicPath,'owner.json'));assert.ok(bytes.length<4096);const probe=native.probeOwnerLease(f.state,'team-flow.lock');assert.equal(probe.status,'busy');}}
  finally{held.release();}
});
