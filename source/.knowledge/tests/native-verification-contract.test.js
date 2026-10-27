'use strict';
// Audit controller only. Physical mode invokes the actual host native backend.
const fs=require('fs'), path=require('path'), crypto=require('crypto'), assert=require('assert/strict'), net=require('net');
const test=require('node:test'), os=require('os');
const source=path.resolve(process.env.KNOWLEDGE_NATIVE_TEST_SOURCE||path.join(__dirname,'..'));
const {removeTempDirStrict}=require('../tools/lib/strict-temp-cleanup');
const lib=n=>path.join(source,'tools/lib',n+'.js');
const names=['verification-supervisor','verification-watchdog','verification-control','verification-progress','verification-policy','verification-finalization','verification-windows-job','repair-on-touch'];
const pins=()=>Object.fromEntries(names.map(n=>[n,crypto.createHash('sha256').update(fs.readFileSync(lib(n))).digest('hex')]));
const before=pins();
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function protocol(){
 const p=require(lib('verification-progress')), policy=require(lib('verification-policy'));
 const progress=policy.createProgress(policy.resolvePolicy({work_budget_ms:5000,no_progress_ms:1000,cleanup_budget_ms:2000}),0n);
 const events=[], failures=[];
 const server=await p.listen(e=>events.push(e),e=>failures.push(e));
 const socket=net.createConnection(server.descriptor.pipe); await new Promise((r,j)=>{socket.once('connect',r);socket.once('error',j);});
 const frame=e=>JSON.stringify({key:server.descriptor.key,event:e})+'\n';
 const phases=ordinal=>['test_setup','command','finalization','receipt_commit'].map(phase=>({type:'phase',ordinal,phase}));
 const id='KVE-'+ 'a'.repeat(64);
 const valid=[...phases(0),{type:'committed',ordinal:0,execution_id:id},...phases(1)];
 // More than LIMIT cumulatively, each individual frame remains valid.
 const payload=valid.map(e=>frame({...e,padding:'x'.repeat(3000)})).join(''); assert(Buffer.byteLength(payload)>16384);
 socket.write(payload); for(let i=0;i<100 && events.length<valid.length;i++) await delay(10);
 assert.equal(events.length,valid.length); assert.deepEqual(failures,[]);
 events.forEach((e,i)=>assert.equal(progress.advance(e,BigInt(i+1)),true));
 assert.equal(progress.advance({type:'committed',ordinal:1,execution_id:id},100n),false,'Duplicate semantic KVE must not become progress');
 socket.end(); for(let i=0;i<100 && !failures.length;i++) await delay(10);
 assert(failures.includes('verification_progress_transport_closed')); server.close();
 const bad=[]; const s2=await p.listen(()=>assert.fail('Error frame must not be delivered'),e=>bad.push(e));
 const c2=net.createConnection(s2.descriptor.pipe); await new Promise((r,j)=>{c2.once('connect',r);c2.once('error',j);});
 c2.write(JSON.stringify({key:'0'.repeat(64),event:{type:'phase',ordinal:0,phase:'test_setup'}})+'\n');
 for(let i=0;i<100 && !bad.length;i++) await delay(10);
 assert(bad.includes('verification_progress_invalid')); c2.destroy(); s2.close();
 const s3=await p.listen(()=>{},()=>{}), client=await p.connect(s3.descriptor,process.hrtime.bigint()+2000000000n);
 s3.close(); await delay(50); assert.throws(()=>client.send({type:'phase',ordinal:0,phase:'test_setup'}),e=>e.code==='verification_progress_transport_failed'); client.close();
 return {coalesced_frames:valid.length,coalesced_bytes:Buffer.byteLength(payload),duplicate_rejected:true,closed_channel_rejected:true,error_frame_rejected:true};
}
async function physical(root,t){
 assert(['win32','linux'].includes(process.platform),'Physical scenario requires a native backend');
 assert(!root.startsWith(source+path.sep) && root!==source,'Fixture cannot be product');
 const runtime=path.join(root,'runtime'),stateRoot=path.join(root,'.knowledge'),marker=path.join(root,'commit-boundary.json');
 fs.cpSync(source,runtime,{recursive:true,filter:file=>!path.relative(source,file).split(path.sep).some(p=>p==='locks'||p.startsWith('.build-')||p.startsWith('.command-build-'))});
 fs.mkdirSync(stateRoot);fs.writeFileSync(path.join(root,'probe.js'),'process.stdout.write("native-control");');
 const ownedLib=n=>path.join(runtime,'tools/lib',n+'.js');
 // The actual commit now executes inside the owned outer worker. Preserve
 // the same fault before its real CAS, after real inner native cleanup.
 fs.appendFileSync(ownedLib('verification-control'),`\n{const original=module.exports.commitFinish;module.exports.commitFinish=function(context,owner,input){
   require('fs').writeFileSync(${JSON.stringify(marker)},JSON.stringify({reached:1,terminalInput:input,pid:process.pid}));
   Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,2500);
   return original(context,owner,input);};}\n`);
 const control=require(ownedLib('verification-control')),context={stateRoot,projectKnowledgeRoot:stateRoot,targetRoot:root,systemRoot:runtime};
 let result,error;
 try{result=require(ownedLib('repair-on-touch')).runVerificationTests({stateRoot,repoRoot:root,taskId:'parent-cas-stall',sessionId:'parent-cas-stall',checkedBy:'independent-critic-controller',sourceFiles:['probe.js'],tests:[{argv:['node','probe.js'],cwd:'.',timeout_ms:30000}],timeoutMs:30000,verificationPolicy:{work_budget_ms:30000,no_progress_ms:0,cleanup_budget_ms:2000}});}
 catch(e){error={code:e.code,message:e.message,has_acceptance:!!e.verification_acceptances,delivery_teardown:e.delivery_teardown,invocation_recovery:e.invocation_recovery,recovery_teardown:e.recovery_teardown};}
 const reached=fs.existsSync(marker)?JSON.parse(fs.readFileSync(marker)):null;
 let status=control.readStatus(context),proof=null;
 const deadline=process.hrtime.bigint()+15000000000n;
 while(status.attempt?.invocation && process.hrtime.bigint()<deadline){
   proof=require(ownedLib('command-scope-proof')).queryScopeClosure(status.attempt.invocation.scope,{timeoutMs:500});
   if(proof.status==='completed')break;await delay(20);
 }
 assert.equal(proof?.status,'completed','An actual independent whole-scope closure must precede recovery');
 if(status.attempt?.claimed){const a=status.attempt;require(ownedLib('verification-recovery')).recoverAttempt(context,{attempt_id:a.attempt_id,generation:a.generation});status=control.readStatus(context);}
 const observation={reached:reached?.reached||0,terminalInput:reached?.terminalInput,error,returned_acceptances:result?.verification_acceptances,status,native_scope:proof};
 fs.writeFileSync(path.join(root,'observation.json'),JSON.stringify(observation,null,2));
 t.diagnostic(JSON.stringify({reached:observation.reached,cleanup_before_fault:reached?.terminalInput.cleanup_proof.status,error:error?.code,actual_outer:proof.status,terminal:status.attempt?.terminal}));
 assert.equal(observation.reached,1,'Must reach actual owned commitFinish');
 assert.equal(reached.terminalInput.cleanup_proof.status,'completed','Fault must follow real confirmed cleanup');
 assert.equal(result,undefined,'Late commit cannot expose ACK');assert(error,'Late commit must fail');
 assert.equal(status.attempt.terminal.outcome,'failed','Independent failure recovery must persist failure after late final admission');
 assert.equal(status.attempt.terminal.ack_sha256,null);assert.equal(status.attempt.claimed,false);
 return observation;
}
test('private progress frames stay bounded and semantic receipts cannot repeat', {timeout:10000}, async()=>{
 await protocol(); assert.deepEqual(pins(),before);
});
test('a delayed final parent commit cannot release a late ACK', {skip:!['win32','linux'].includes(process.platform),timeout:60000}, async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-cas-deadline-'));
 let completed=false;t.after(()=>{if(completed)removeTempDirStrict(root);else t.diagnostic(JSON.stringify({fixture_retained_unconfirmed:root}));});
 await physical(root,t); assert.deepEqual(pins(),before);completed=true;
});
