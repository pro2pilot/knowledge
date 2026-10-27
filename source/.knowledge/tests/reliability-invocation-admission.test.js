'use strict';
// Synthetic Windows descriptors exercise pure admission and real ledger I/O.
// No Windows process existence, Job finality or native death is fabricated.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const source=process.env.KNOWLEDGE_INVOCATION_ADMISSION_SOURCE||path.resolve(__dirname,'..');
const control=require(path.join(source,'tools/lib/verification-control'));
const protocol=require(path.join(source,'tools/lib/command-windows-protocol'));
const invocation=require(path.join(source,'tools/lib/verification-invocation'));
const digest=value=>crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
function model(durable){
 const scopeId=crypto.randomBytes(32).toString('hex'),identity=pid=>({pid,birth_filetime:String(133000000000000000n+BigInt(pid))});
 const primary=protocol.keyPair(),secondary=protocol.keyPair();
 const scope=protocol.commandScope({schema_version:'knowledge-windows-command-job.v2',backend:'windows_job_object',scope_id:scopeId,
  job_name:`Local\\KnowledgeCommand-${scopeId}`,native:{schema_version:'knowledge-command-windows-native.v1',source_sha256:'a'.repeat(64),binary_sha256:'b'.repeat(64),architecture:'x64',assignment:protocol.ASSIGNMENT,watchdog:'native-pipe-process-handles.v1'},
  host:{machine_guid_sha256:'c'.repeat(64),computer_name_sha256:'d'.repeat(64),user_sid_sha256:'e'.repeat(64),session_id:1},
  controller:identity(200),root:identity(201),primary:{identity:identity(202),public_key:primary.publicKey},
  secondary:durable?{identity:identity(203),controller:identity(204),public_key:secondary.publicKey}:null,
  receipt_store:durable?{directory:`C:\\Users\\fixture\\AppData\\Local\\Temp\\knowledge-command-receipt-${scopeId}`,dev:'1',ino:'2',scope_id:scopeId}:null});
 return{schema_version:'knowledge-verification-invocation.v1',nonce_sha256:'f'.repeat(64),scope_sha256:digest(scope),scope};
}
function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-invocation-admission-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return{context:{stateRoot:root},root,active:path.join(root,'maintenance','verification-control','active.json')};}
test('control rejects a transient Windows invocation before publishing any durable claim',t=>{
 const f=fixture(t),value=model(false);assert.equal(protocol.validateScope(value.scope),true);assert.equal(invocation.validInvocation(value),false);
 assert.throws(()=>control.beginAttempt(f.context,{request_sha256:'1'.repeat(64),invocation:value}),{code:'verification_invocation_invalid'});
 assert.deepEqual(fs.readdirSync(f.root),[]);
});
test('control reader rejects a stored invocation downgraded from durable to transient custody',t=>{
 const f=fixture(t),value=model(true);control.beginAttempt(f.context,{request_sha256:'2'.repeat(64),invocation:value});
 const a=JSON.parse(fs.readFileSync(f.active));a.invocation.scope.descriptor.secondary=null;a.invocation.scope.descriptor.receipt_store=null;
 a.invocation.scope_sha256=digest(a.invocation.scope);fs.writeFileSync(f.active,JSON.stringify(a,null,2)+'\n');
 assert.equal(protocol.validateScope(a.invocation.scope),true);assert.equal(invocation.validInvocation(a.invocation),false);
 const bytes=fs.readFileSync(f.active);assert.throws(()=>control.readStatus(f.context),{code:'verification_control_corrupt'});assert.deepEqual(fs.readFileSync(f.active),bytes);
});
test('control and producer admit the same complete immutable Windows invocation shape',t=>{
 const f=fixture(t),value=model(true);assert.equal(invocation.validInvocation(value),true);
 const a=control.beginAttempt(f.context,{request_sha256:'3'.repeat(64),invocation:value}).attempt;
 assert.equal(JSON.stringify(a.invocation),JSON.stringify(value));assert.equal(JSON.stringify(control.readStatus(f.context).attempt.invocation),JSON.stringify(value));
});

function legacyModel(){
 const value=model(true),old=value.scope.descriptor;
 value.scope={schema_version:'knowledge-command-scope.v1',backend:'windows_job_object',descriptor:{
  schema_version:'knowledge-windows-job.v1',backend:'windows_job_object',job_name:'Local\\KnowledgeVerification-'+old.scope_id,
  source_sha256:'a'.repeat(64),host:old.host,identities:{controller:{pid:301,os_creation_time:'2026-01-01T00:00:00.000Z'},keeper:{pid:302,os_creation_time:'2026-01-01T00:00:00.001Z'},worker:{pid:303,os_creation_time:'2026-01-01T00:00:00.002Z'}}}};
 value.scope_sha256=digest(value.scope);return value;
}
test('a historical Windows inner Job format cannot become a new whole invocation claim',t=>{
 const f=fixture(t),value=legacyModel();assert.equal(require(path.join(source,'tools/lib/command-scope-proof')).validateExecutionScope(value.scope),true);
 assert.equal(invocation.validInvocation(value),false);
 assert.throws(()=>control.beginAttempt(f.context,{request_sha256:'4'.repeat(64),invocation:value}),{code:'verification_invocation_invalid'});assert.deepEqual(fs.readdirSync(f.root),[]);
});
test('a historical Windows inner Job format cannot replace the stored whole invocation binding',t=>{
 const f=fixture(t);control.beginAttempt(f.context,{request_sha256:'5'.repeat(64),invocation:model(true)});
 const a=JSON.parse(fs.readFileSync(f.active));a.invocation=legacyModel();fs.writeFileSync(f.active,JSON.stringify(a,null,2)+'\n');
 const bytes=fs.readFileSync(f.active);assert.throws(()=>control.readStatus(f.context),{code:'verification_control_corrupt'});assert.deepEqual(fs.readFileSync(f.active),bytes);
});
