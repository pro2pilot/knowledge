'use strict';
// Fault-injected ownership metadata on disposable real lock directories.
// No live foreign host is claimed; the invariant is that unknown liveness
// cannot become permission to evict merely because an age threshold elapsed.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const {spawnSync}=require('node:child_process');
const SOURCE=path.resolve(__dirname,'..');
const LEGACY_SOURCE=path.join(__dirname,'fixtures','lock-v2-runtime');
const WORK=os.tmpdir();
fs.mkdirSync(WORK,{recursive:true});
const manager=require(path.join(SOURCE,'tools/lib/contained-lock-manager'));
const legacyManager=require(path.join(LEGACY_SOURCE,'tools/lib/contained-lock-manager'));
const {LOCKS}=require(path.join(SOURCE,'tools/lib/lock-policy'));
const {canonicalOwnerText}=require(path.join(SOURCE,'tools/lib/lock-owner-schema'));
function fixture(t){
 const root=fs.mkdtempSync(path.join(WORK,'owner-uncertainty-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const state=path.join(root,'state');
 const request={rootKind:'state',rootPath:state,context:{stateRoot:state},
  lockName:'team-flow',purpose:LOCKS['team-flow'].purpose,timeoutMs:1000,staleMs:1};
 // Keep a real historical v2 writer for PID/remote uncertainty assertions.
 // V3 kernel-lease recovery is exercised independently. A semantic probe
 // has a realistic budget; setup uses the unchanged production budget.
 const first=legacyManager.acquireContainedLock({...request,timeoutMs:30000});
 const ownerPath=path.join(first.path,'owner.json');
 const owner=JSON.parse(fs.readFileSync(ownerPath,'utf8'));
 function age(){const past=new Date(Date.now()-3*24*3600*1000);fs.utimesSync(first.path,past,past);}
 function snapshot(){const s=fs.lstatSync(first.path,{bigint:true});return {dev:String(s.dev),ino:String(s.ino),body:fs.readFileSync(ownerPath,'utf8')};}
 function refuse(){
  const before=snapshot();let acquired=null,error=null;
  try {acquired=manager.acquireContainedLock(request);} catch(e){error=e;}
  if(acquired)acquired.release();
  assert.ok(error,'Contender acquired and replaced a lock whose owner exit was not confirmed');
  assert.equal(error.code,'lock_timeout');assert.deepEqual(snapshot(),before,'Uncertain owner evidence changed');
 }
 return {root,state,request,first,ownerPath,owner,age,refuse};
}
test('remote age expiry alone never grants eviction of a valid owner',t=>{
 const f=fixture(t);f.owner.hostname='unobserved-foreign-host.invalid';
 // Hostnames are diagnostic text in v2. This foreign-owner fixture has no
 // verified native scope; do not transplant the current process's identity.
 if(f.owner.schema_version==='knowledge-lock-owner.v2')f.owner.native_identity=null;
 fs.writeFileSync(f.ownerPath,canonicalOwnerText(f.owner));f.age();
 f.refuse();
 const observed=manager.inspectLockSafety(f.request);
 assert.notEqual(observed.current.status,'stale','24-hour remote age was treated as owner death');
 const policy=manager.__test.requestPolicy(f.request);
 assert.equal(manager.__test.inspectCurrent(policy,manager.lockPaths(policy)).disposition.alive,null);
});
test('an unknown local process-probe error never grants stale recovery',t=>{
 const f=fixture(t);assert.equal(f.owner.hostname.toLowerCase(),os.hostname().toLowerCase());f.age();
 const old=process.kill;
 process.kill=(pid,signal)=>{assert.equal(pid,process.pid);assert.equal(signal,0);throw Object.assign(new Error('injected process probe unavailable'),{code:'EIO'});};
 try {f.refuse();} finally {process.kill=old;}
});
test('an aged live local owner remains exclusive',t=>{
 const f=fixture(t);f.age();f.refuse();assert.equal(f.first.release().status,'released');
});
test('a permission-denied process observation remains exclusive',t=>{
 const f=fixture(t);f.age();const old=process.kill;
 process.kill=()=>{throw Object.assign(new Error('injected no permission'),{code:'EPERM'});};
 try{f.refuse();}finally{process.kill=old;}
 assert.equal(f.first.release().status,'released');
});
test('an observed exited child permits recovery only when native ownership scope is qualified',t=>{
 const f=fixture(t);assert.equal(f.first.release().status,'released');
 const code="const path=require('node:path');const locks=require(path.join(process.argv[1],'tools/lib/contained-lock-manager'));const request=JSON.parse(process.argv[2]);locks.acquireContainedLock(request);process.stdout.write(String(process.pid));";
 const child=spawnSync(process.execPath,['-e',code,LEGACY_SOURCE,JSON.stringify(f.request)],{encoding:'utf8',timeout:30000});
 assert.ifError(child.error);assert.equal(child.status,0,child.stderr);
 const childPid=Number(child.stdout);assert(Number.isSafeInteger(childPid)&&childPid>0);
 assert.throws(()=>process.kill(childPid,0),e=>e.code==='ESRCH','OS must confirm the recorded child has exited');
 f.age();const recorded=JSON.parse(fs.readFileSync(f.ownerPath,'utf8'));
 const observed=manager.inspectLockSafety(f.request);
 if(recorded.schema_version==='knowledge-lock-owner.v2'&&recorded.native_identity===null){
  assert.equal(observed.current.status,'active');f.refuse();return;
 }
 assert.equal(observed.current.status,'stale');
 const policy=manager.__test.requestPolicy(f.request);
 assert.equal(manager.__test.inspectCurrent(policy,manager.lockPaths(policy)).disposition.alive,false);
 const successor=manager.acquireContainedLock(f.request);assert.notEqual(successor.lock_id,f.first.lock_id);
 assert.equal(successor.release().status,'released');
});
test('legacy remote locks also retain unknown ownership beyond the diagnostic age',t=>{
 const f=fixture(t);assert.equal(f.first.release().status,'released');
 const legacy=manager.lockPaths(manager.__test.requestPolicy(f.request)).legacy;
 fs.mkdirSync(legacy);
 const bytes=JSON.stringify({lock_id:'legacy-foreign',pid:process.pid,hostname:'unobserved-foreign-host.invalid',started_at:'2026-01-01T00:00:00.000Z'})+'\n';
 fs.writeFileSync(path.join(legacy,'owner.json'),bytes);
 const old=new Date(Date.now()-3*24*3600*1000);fs.utimesSync(legacy,old,old);
 let successor=null,error=null;try{successor=manager.acquireContainedLock(f.request);}catch(e){error=e;}
 if(successor)successor.release();
 assert.ok(error,'Legacy foreign lock was evicted solely by age');assert.equal(error.code,'lock_timeout');
 assert.equal(fs.readFileSync(path.join(legacy,'owner.json'),'utf8'),bytes);
});
