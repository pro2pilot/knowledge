'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const source=process.env.KNOWLEDGE_LOCK_TEST_SOURCE?path.resolve(process.env.KNOWLEDGE_LOCK_TEST_SOURCE):path.resolve(__dirname,'..');
const managerPath=path.join(source,'tools/lib/contained-lock-manager'),manager=require(managerPath),{LOCKS}=require(path.join(source,'tools/lib/lock-policy'));
function fixture(t){const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-lock-inode-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return{root,request:{context:{stateRoot:root},rootKind:'state',rootPath:root,lockName:'team-flow',purpose:LOCKS['team-flow'].purpose},publicPath:path.join(root,'locks/v1/team-flow.lock')};}
function identity(file){const stat=fs.lstatSync(file,{bigint:true});return[stat.dev,stat.ino];}
function replaceOwner(file){const bytes=fs.readFileSync(file),replacement=file+'.replacement';fs.writeFileSync(replacement,bytes,{flag:'wx'});fs.renameSync(replacement,file);return bytes;}
test('byte-identical owner replacement cannot turn a live writer lease into recovery authority',t=>{
  const f=fixture(t),holder=manager.acquireContainedLock(f.request),owner=path.join(f.publicPath,'owner.json'),before=identity(owner),bytes=replaceOwner(owner),replacement=identity(owner);
  assert.notDeepEqual(replacement,before);assert.equal(JSON.parse(bytes).pid,process.pid);assert.doesNotThrow(()=>process.kill(process.pid,0));
  let successor,error;try{successor=manager.acquireContainedLock({...f.request,timeoutMs:1000});}catch(e){error=e;}
  if(successor)successor.release();
  assert.equal(successor,undefined,'A second writer was admitted while the first still holds its original native inode lease.');
  assert.equal(error?.code,'lock_owner_identity_mismatch');assert.deepEqual(identity(owner),replacement);assert.deepEqual(fs.readFileSync(owner),bytes);
  assert.throws(()=>holder.release(),{code:'lock_owner_identity_mismatch'});
});
test('a copied directory containing identical owner bytes cannot impersonate the original generation',t=>{
  const f=fixture(t),holder=manager.acquireContainedLock(f.request),original=f.publicPath+'.held-original',bytes=fs.readFileSync(path.join(f.publicPath,'owner.json'));
  fs.renameSync(f.publicPath,original);fs.mkdirSync(f.publicPath);fs.writeFileSync(path.join(f.publicPath,'owner.json'),bytes);
  const oldDirectory=identity(original),copy=identity(f.publicPath);let successor,error;
  try{successor=manager.acquireContainedLock({...f.request,timeoutMs:1000});}catch(e){error=e;}if(successor)successor.release();
  assert.equal(successor,undefined);assert.equal(error?.code,'lock_owner_identity_mismatch');assert.deepEqual(identity(original),oldDirectory);assert.deepEqual(identity(f.publicPath),copy);
  // This tests an already-present copied generation; it makes no claim that
  // arbitrary external removal of a live admission name can be made atomic.
  assert.ok(holder.lock_id);
});
test('owner replacement after native publication cannot receive an acquisition acknowledgment',t=>{
  const f=fixture(t),provider=require(path.join(source,'tools/lib/lock-publication')),native=provider.publishPreparedLock;
  let changed=false,handle,error;
  provider.publishPreparedLock=function(...args){const result=native(...args);if(result.status==='published'&&!changed){changed=true;replaceOwner(path.join(args[0],'locks/v1',args[2],'owner.json'));}return result;};
  delete require.cache[require.resolve(managerPath)];const fresh=require(managerPath);provider.publishPreparedLock=native;
  try{handle=fresh.acquireContainedLock(f.request);}catch(e){error=e;}if(handle)handle.release();
  assert.equal(changed,true);assert.equal(handle,undefined,'An acknowledgment was returned with a lease on an unlinked owner inode.');assert.equal(error?.code,'lock_owner_identity_mismatch');
});
test('an untouched original inode still supports normal acquire and exact release',t=>{
  const f=fixture(t),h=manager.acquireContainedLock(f.request);assert.equal(manager.inspectLockSafety(f.request).current.reason,'kernel_owner_lease_held');assert.equal(h.release().status,'released');
});
