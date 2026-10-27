'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const native=require('../tools/lib/verification-linux-namespace');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(predicate){const deadline=performance.now()+15000;while(!predicate()){if(performance.now()>=deadline)throw Error('Actual native exit/control EOF not observed');await delay(10);}}
for(const [code,corrupt,killKeeper] of [[0,false,false],[7,false,false],[0,true,false],[0,false,true]])test(`Linux natural worker exit ${code}${corrupt?' with malformed control':''}${killKeeper?' with keeper SIGKILL':''} keeps work failure separate from native cleanup`,
 {skip:process.platform!=='linux',timeout:30000},async t=>{
  const helper=native.preparePackagedHelper({snapshot:true}),failures=[];
  const pair=native.spawnLinuxContainedWorker(process.execPath,['-e',`setTimeout(()=>process.exit(${code}),100);`],
   {stdio:['ignore','ignore','ignore','ipc']},{preparedHelper:helper,lifetimeMs:20000,onFailure:error=>failures.push(error.code)});
  let descriptor,exited=false,ended=false,controlClosed=false,raw='',physical=false;
  pair.worker.once('exit',()=>{exited=true;});pair.worker.stdio[4].once('end',()=>{ended=true;});pair.worker.stdio[4].once('close',()=>{controlClosed=true;});pair.worker.stdio[4].on('data',bytes=>{raw+=bytes;});
  t.after(async()=>{
   if(!exited)await pair.job.close(10000);
   if(descriptor&&exited&&controlClosed)physical=native.verifyProcessExit({...descriptor,identity:descriptor.init}).status==='exited';
   if(physical)assert.equal(native.cleanupPreparedHelper(helper).status,'completed');
   else t.diagnostic('Private helper retained without exact native finality');
  });
  descriptor=await pair.job.ready;
  pair.job.permit();await pair.job.started;
  // Deliberately receive the actual worker-exit notification before the
  // caller requests cleanup. Worker failure is independent of drain proof.
  await until(()=>failures.includes('verification_worker_exited'));
  if(corrupt)pair.worker.stdio[4].emit('data','{"protocol":"corrupt-model","status":"closed"}\n');
  if(killKeeper)pair.worker.kill('SIGKILL');
  const proof=await pair.job.close(10000);
  await until(()=>exited&&(killKeeper?controlClosed:ended));
  const records=raw.trim().split('\n').map(JSON.parse);
  assert.ok(records.some(row=>row.status==='worker_exit'));
  if(!killKeeper)assert.ok(records.some(row=>row.status==='closed'&&row.active_processes===0&&row.init_reaped===true));
  if(corrupt||killKeeper){assert.equal(proof.status,'unconfirmed');if(corrupt)assert.ok(failures.includes('verification_namespace_protocol_invalid'));}
  else{assert.equal(proof.status,'completed',JSON.stringify({proof,failures,records}));assert.equal(proof.namespace_drained,true);}
  if(killKeeper)assert.equal(pair.worker.signalCode,'SIGKILL');else{assert.equal(pair.worker.exitCode,0);assert.equal(pair.worker.signalCode,null);}
  await until(()=>{physical=native.verifyProcessExit({...descriptor,identity:descriptor.init}).status==='exited';return physical;});
 });
