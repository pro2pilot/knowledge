'use strict';
// Real POSIX writes and fsync calls; one modeled EIO tests ordering. These
// cases do not claim physical power-cut or storage-controller durability.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const source=process.env.KNOWLEDGE_CONTROL_DURABILITY_SOURCE||path.resolve(__dirname,'..');
const control=require(path.join(source,'tools/lib/verification-control.js'));
function fixture(t,inject){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-control-parent-fsync-')),context={stateRoot:root};
 const parent=path.join(root,'maintenance'),initial=path.join(parent,'verification-control-initial.json'),active=path.join(parent,'verification-control','active.json');
 const events=[],sync=fs.fsyncSync,unlink=fs.unlinkSync;let injected=false;
 fs.fsyncSync=function(fd){
  const st=fs.fstatSync(fd),p=fs.existsSync(parent)?fs.lstatSync(parent):null;
  if(p&&st.dev===p.dev&&st.ino===p.ino&&fs.existsSync(active)){
   const held=fs.existsSync(initial);events.push({kind:'parent_fsync',journal_present:held});
   if(inject&&held&&!injected){injected=true;throw Object.assign(new Error('Modeled parent fsync EIO before syscall'),{code:'EIO'});}
  }
  return sync.apply(this,arguments);
 };
 fs.unlinkSync=function(file){if(file===initial)events.push({kind:'journal_unlink'});return unlink.apply(this,arguments);};
 const restore=()=>{fs.fsyncSync=sync;fs.unlinkSync=unlink;};
 t.after(()=>{restore();fs.rmSync(root,{recursive:true,force:true});});
 return{root,context,parent,initial,active,events,restore,injected:()=>injected};
}
test('the new control-directory parent entry is synced before its only initial journal is unlinked',
 {skip:process.platform==='win32'},t=>{
  const f=fixture(t,false);const value=control.beginAttempt(f.context,{request_sha256:'a'.repeat(64)});
  assert.equal(value.attempt.claimed,true);assert.equal(fs.existsSync(f.initial),false);
  const removal=f.events.findIndex(e=>e.kind==='journal_unlink'),parent=f.events.findIndex(e=>e.kind==='parent_fsync'&&e.journal_present);
  t.diagnostic(JSON.stringify({events:f.events}));assert(parent>=0&&parent<removal,'The parent fsync must precede journal removal');
 });
test('a failed pre-removal parent fsync preserves the complete journal and matching active claim for recovery',
 {skip:process.platform==='win32'},t=>{
  const f=fixture(t,true);assert.throws(()=>control.beginAttempt(f.context,{request_sha256:'b'.repeat(64)}),{code:'EIO'});
  assert.equal(f.injected(),true);assert.equal(fs.existsSync(f.initial),true);assert.equal(fs.existsSync(f.active),true);
  assert.equal(f.events.some(e=>e.kind==='journal_unlink'),false);f.restore();
  const a=control.readStatus(f.context).attempt;assert.equal(a.claimed,true);
  assert.equal(JSON.parse(fs.readFileSync(f.initial)).generation,a.generation);
  const recovered=control.recoverAttempt(f.context,{attempt_id:a.attempt_id,generation:a.generation});
  assert.equal(recovered.ack_released,false);assert.equal(recovered.attempt.claimed,false);assert.equal(fs.existsSync(f.initial),false);
  t.diagnostic(JSON.stringify({events:f.events,recovery:recovered.status}));
 });
