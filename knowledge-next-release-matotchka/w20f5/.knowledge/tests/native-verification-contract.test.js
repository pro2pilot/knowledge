'use strict';
// Audit controller only. Physical mode invokes real Windows producer and Jobs.
const fs=require('fs'), path=require('path'), crypto=require('crypto'), assert=require('assert/strict'), net=require('net');
const test=require('node:test'), os=require('os');
const source=path.resolve(__dirname,'..');
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
function physical(root){
 assert.equal(process.platform,'win32','Physical scenario requires Windows');
 assert(!root.startsWith(source+path.sep) && root!==source,'Fixture cannot be product');
 fs.mkdirSync(path.join(root,'.knowledge'));
 fs.writeFileSync(path.join(root,'probe.js'),'process.stdout.write("native-control");');
 const control=require(lib('verification-control')), original=control.commitFinish;
 let reached=0, terminalInput;
 control.commitFinish=function(context,owner,input){
   reached++; terminalInput=input;
   // Trusted controller fault: delay only parent terminal CAS, after real Jobs.
   const until=performance.now()+2500; while(performance.now()<until){}
   return original(context,owner,input);
 };
 let result,error;
 try{ result=require(lib('repair-on-touch')).runVerificationTests({stateRoot:path.join(root,'.knowledge'),repoRoot:root,taskId:'parent-cas-stall',sessionId:'parent-cas-stall',checkedBy:'independent-critic-controller',sourceFiles:['probe.js'],tests:[{argv:['node','probe.js'],cwd:'.',timeout_ms:5000}],timeoutMs:5000,verificationPolicy:{work_budget_ms:5000,no_progress_ms:0,cleanup_budget_ms:2000}}); }
 catch(e){error={code:e.code,message:e.message,has_acceptance:!!e.verification_acceptances};}
 finally{control.commitFinish=original;}
 const status=control.readStatus({stateRoot:path.join(root,'.knowledge'),projectKnowledgeRoot:path.join(root,'.knowledge'),targetRoot:root,systemRoot:source});
 const observation={reached,terminalInput,error,returned_acceptances:result?.verification_acceptances,status};
 fs.writeFileSync(path.join(root,'observation.json'),JSON.stringify(observation,null,2));
 assert.equal(reached,1,'Must reach actual parent commitFinish');
 assert.equal(terminalInput.cleanup_proof.status,'completed','Fault must follow real confirmed cleanup');
 assert.equal(result,undefined,'Late parent commit cannot expose ACK');
 assert(error,'Late parent commit must fail');
 assert.equal(status.attempt.terminal.outcome,'failed','Late final parent admission must persist failed outcome');
 assert.equal(status.attempt.terminal.ack_sha256,null);
 return observation;
}
test('private progress frames stay bounded and semantic receipts cannot repeat', {timeout:10000}, async()=>{
 await protocol(); assert.deepEqual(pins(),before);
});
test('a delayed final parent commit cannot release a late ACK', {skip:process.platform!=='win32',timeout:20000}, t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-cas-deadline-'));
 t.after(()=>removeTempDirStrict(root));
 physical(root); assert.deepEqual(pins(),before);
});
