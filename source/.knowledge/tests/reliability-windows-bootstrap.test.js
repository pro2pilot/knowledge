'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('fs'),os=require('os'),path=require('path'),cp=require('child_process'),crypto=require('crypto');
assert.equal(process.platform,'win32','Bootstrap Job admission must run on actual Windows, never a portable SKIP');
const loader=require('../tools/lib/command-windows-native');
const runner=require('../tools/lib/command-runner');
async function until(predicate,budget=60000){const end=performance.now()+budget;while(!predicate()){if(performance.now()>=end)throw new Error('Native bootstrap boundary not observed');await new Promise(r=>setTimeout(r,10));}}
function births(directory){
 const text=fs.readFileSync(path.join(directory,'births.ndjson'),'utf8'),rows=text.split('\n').filter(Boolean).map(JSON.parse),unique=new Map();
 for(const row of rows)for(const identity of row.type==='native_ready'?[row.identity]:[row.holder,row.launcher,row.controller]){
  assert.ok(identity?.pid&&identity.birth_filetime);unique.set(identity.pid+':'+identity.birth_filetime,identity);
 }
 return [...unique.values()];
}
function observe(identity,helper){
 const nonce=crypto.randomBytes(32).toString('hex');
 const answer=cp.spawnSync(process.execPath,[path.join(__dirname,'../tools/lib/command-windows-observe-holder.js')],{
  input:JSON.stringify({nonce,identity,helper,timeoutMs:10000}),encoding:'utf8',timeout:12000,killSignal:'SIGKILL',windowsHide:true,maxBuffer:65536,env:runner.safeEnvironment()});
 assert.equal(answer.error,undefined);assert.equal(answer.signal,null);assert.equal(answer.status,0,answer.stderr);
 const value=JSON.parse(answer.stdout);assert.equal(value.nonce,nonce);assert.deepEqual(value.observation.identity,identity);return value.observation;
}
for(const [phase,role,mode] of [
 ['before_resume','primary','crash'],['preload','primary','crash'],['native_load','primary','crash'],
 ['crypto','primary','crash'],['receipt_store','secondary','crash'],['native_load','primary','cancel']
])test(`Windows bootstrap ${mode} during ${role} ${phase} confirms every recorded native birth exits`,{timeout:150000},async t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'windows-bootstrap-test-'));
 const helper=loader.preparePackagedHelper({verifyLoad:false});let cleanable=false,exited=false;
 const child=cp.spawn(process.execPath,[path.join(__dirname,'helpers/reliability-windows-bootstrap-controller.cjs'),directory,phase,role],{
  env:runner.safeEnvironment(),stdio:['ignore','pipe','pipe','ipc'],windowsHide:true});
 const exit=new Promise(resolve=>child.once('exit',()=>{exited=true;resolve();}));let output='';
 child.stdout.on('data',x=>{if(output.length<65536)output+=x;});child.stderr.on('data',x=>{if(output.length<65536)output+=x;});
 try{
  await until(()=>fs.existsSync(path.join(directory,`${role}.${phase}.json`))&&fs.existsSync(path.join(directory,'births.ndjson')));
  const identities=births(directory);assert.ok(identities.length>=4);
  if(mode==='crash')child.kill('SIGKILL');else child.send({type:'cancel'});
  await until(()=>exited,60000);await exit;
  if(mode==='cancel'){const result=JSON.parse(fs.readFileSync(path.join(directory,'outcome.json'),'utf8'));
   assert.equal(result.code,'command_cancelled',JSON.stringify(result));assert.equal(result.cleanup.status,'completed',JSON.stringify(result));}
  let proofs;await until(()=>{proofs=identities.map(identity=>observe(identity,helper));return proofs.every(row=>row.status==='exited');},40000);
  assert.ok(proofs.every(row=>['handle_signaled','birth_replaced','pid_absent'].includes(row.basis)));
  cleanable=true;t.diagnostic(JSON.stringify({phase,role,mode,native_birth_count:proofs.length,all_exact_births_exited:true,output_bytes:Buffer.byteLength(output),scope:'modeled_JS_stall_actual_JOB_LIST_and_native_death'}));
 }finally{
  if(!exited){child.kill('SIGKILL');await exit;}
  assert.equal(loader.cleanupPreparedHelper(helper).status,'completed');
  if(cleanable)fs.rmSync(directory,{recursive:true,force:true});else t.diagnostic('Fixture retained because complete native cleanup was not confirmed');
 }
});
