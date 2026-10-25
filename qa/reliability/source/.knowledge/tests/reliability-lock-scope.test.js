'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const {createCommandSession}=require('../tools/lib/command-runner');
const manager=require('../tools/lib/contained-lock-manager'),{LOCKS}=require('../tools/lib/lock-policy');
const {validateExecutionScope,queryScopeClosure}=require('../tools/lib/command-scope-proof');
const native={skip:process.platform!=='linux',timeout:90000};
function fixture(t){const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-lock-scope-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return{root,request:{context:{stateRoot:root},rootKind:'state',rootPath:root,lockName:'team-flow',purpose:LOCKS['team-flow'].purpose},publicPath:path.join(root,'locks/v1/team-flow.lock')};}
async function session(t,f){const value=await createCommandSession({cwd:f.root});t.after(async()=>{await value.drain();await value.finish();});assert.equal(validateExecutionScope(value.scope),true);return value;}
function snapshot(file){const stat=fs.statSync(file,{bigint:true});return{dev:String(stat.dev),ino:String(stat.ino),owner:fs.readFileSync(path.join(file,'owner.json'),'utf8')};}
test('a requested invalid execution scope never falls back to a process-only owner',t=>{
  const f=fixture(t);assert.throws(()=>manager.acquireContainedLock({...f.request,executionScope:{schema_version:'unknown',backend:'linux_pid_namespace'}}),{code:'lock_execution_scope_invalid'});
  assert.equal(fs.existsSync(f.publicPath),false);
});
test('normal release keeps the native owner lease until its actual child scope has drained',native,async t=>{
  const f=fixture(t),s=await session(t,f),h=manager.acquireContainedLock({...f.request,executionScope:s.scope});
  const before=snapshot(f.publicPath),proof=queryScopeClosure(s.scope,{timeoutMs:5000});assert.equal(proof.status,'active',JSON.stringify(proof));
  assert.throws(()=>h.release(),{code:'lock_execution_scope_active'});assert.deepEqual(snapshot(f.publicPath),before);
  const drained=await s.drain();assert.equal(drained.status,'completed',JSON.stringify(drained));
  assert.equal(queryScopeClosure(s.scope,{timeoutMs:5000}).status,'completed');assert.equal(h.release().status,'released');
});
test('a free owner-inode lease cannot reclaim a still-active immutable execution scope',native,async t=>{
  const f=fixture(t),s=await session(t,f),source=path.resolve(__dirname,'..');
  // Keep a real native scope alive in this controller after the disposable
  // owning process exits. This schedules the AND-gate deterministically;
  // the immutable descriptor and its process identities are never forged.
  const code=String.raw`const path=require('path');const [source,request]=process.argv.slice(1);const manager=require(path.join(source,'tools/lib/contained-lock-manager'));const h=manager.acquireContainedLock(JSON.parse(request));console.log(JSON.stringify({lock_id:h.lock_id}));`;
  const child=spawnSync(process.execPath,['-e',code,source,JSON.stringify({...f.request,executionScope:s.scope})],{env:{...process.env,NODE_OPTIONS:'',NODE_PATH:''},encoding:'utf8',timeout:30000});
  assert.ifError(child.error);assert.equal(child.status,0,child.stderr);const before=snapshot(f.publicPath);
  const observed=manager.inspectLockSafety(f.request);assert.equal(observed.current.reason,'owner_lease_free_execution_scope_active');
  assert.throws(()=>manager.acquireContainedLock({...f.request,timeoutMs:1000}),error=>error.code==='lock_timeout'&&error.owner_disposition==='owner_lease_free_execution_scope_active');
  assert.deepEqual(snapshot(f.publicPath),before);assert.equal(queryScopeClosure(s.scope,{timeoutMs:5000}).status,'active');
  assert.equal((await s.drain()).status,'completed');const successor=manager.acquireContainedLock(f.request);assert.notEqual(successor.lock_id,JSON.parse(child.stdout).lock_id);successor.release();
});
test('changed immutable scope bytes cannot authorize release or recovery',native,async t=>{
  const f=fixture(t),s=await session(t,f),h=manager.acquireContainedLock({...f.request,executionScope:s.scope});
  const file=path.join(f.publicPath,'execution-scope.json'),original=fs.readFileSync(file),before=snapshot(f.publicPath);
  fs.writeFileSync(file,Buffer.from(original.toString('utf8').replace('knowledge-command-scope.v1','knowledge-command-scope.v9')));
  assert.throws(()=>h.release(),{code:'lock_execution_scope_invalid'});assert.deepEqual(snapshot(f.publicPath),before);
  assert.equal((await s.drain()).status,'completed');assert.throws(()=>h.release(),{code:'lock_execution_scope_invalid'});
  fs.writeFileSync(file,original);assert.equal(h.release().status,'released');
});
