'use strict';

// Real public verification and native containment. The fault hook adds only
// a synchronous wait at a storage boundary; no OS proof is replaced.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawn,spawnSync}=require('node:child_process');
const source=process.env.KNOWLEDGE_PUBLIC_INVOCATION_SOURCE||path.resolve(__dirname,'..'),q=JSON.stringify,delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const mono=()=>process.hrtime.bigint();
async function until(fn,ms,message){const end=mono()+BigInt(ms)*1000000n;while(!fn()&&mono()<end)await delay(20);assert(fn(),message);}
const supported=['linux','win32'].includes(process.platform);
function birth(pid){try{const stat=fs.readFileSync('/proc/'+pid+'/stat','utf8');return{pid:Number(pid),start_ticks:stat.slice(stat.lastIndexOf(')')+2).split(' ')[19]};}catch(e){if(['ENOENT','ESRCH'].includes(e.code))return null;throw e;}}

async function fixture(t,mode){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-public-invocation-')),runtime=path.join(root,'runtime'),repo=path.join(root,'repo'),stateRoot=path.join(repo,'.knowledge');
  fs.cpSync(source,runtime,{recursive:true,filter:file=>!path.relative(source,file).split(path.sep).some(p=>p==='locks'||p.startsWith('.build-')||p.startsWith('.command-build-'))});
  fs.mkdirSync(repo);fs.mkdirSync(stateRoot);fs.writeFileSync(path.join(repo,'probe.js'),'process.stdout.write("invocation-positive");\n');
  const marker=path.join(root,'boundary.json'),children=[];
  const pause=`const fs=require('fs');const data={mode:${q(mode)},pid:process.pid,at_ns:String(process.hrtime.bigint())};
    if(process.platform==='linux'){const stat=fs.readFileSync('/proc/self/stat','utf8'),ppid=Number(stat.slice(stat.lastIndexOf(')')+2).split(' ')[1]);
      data.init_stat=fs.readFileSync('/proc/'+ppid+'/stat','utf8');data.init_status=fs.readFileSync('/proc/'+ppid+'/status','utf8');
      data.boot_id=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim();}
    fs.writeFileSync(${q(marker)},JSON.stringify(data));Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);`;
  if(mode==='cancel')fs.appendFileSync(path.join(runtime,'tools/lib/verification-control.js'),`\n{const original=module.exports.beginAttempt;
    module.exports.beginAttempt=function(...args){const value=original(...args);if(!require('fs').existsSync(${q(marker)})){${pause}}return value;};}\n`);
  if(mode==='crash')fs.appendFileSync(path.join(runtime,'tools/lib/json-store.js'),`\n{const original=module.exports.writeJsonAtomicContained;
    module.exports.writeJsonAtomicContained=function(file,...rest){if(require('path').basename(file)==='active.json'&&!require('fs').existsSync(file)&&!require('fs').existsSync(${q(marker)})){${pause}}return original(file,...rest);};}\n`);
  const request={stateRoot,repoRoot:repo,taskId:'public-invocation-'+mode,sessionId:'actual-controller',checkedBy:'independent-lock-critic',sourceFiles:['probe.js'],
    tests:[{argv:['node','probe.js'],cwd:'.',timeout_ms:30000}],timeoutMs:30000,verificationPolicy:{work_budget_ms:30000,no_progress_ms:0,cleanup_budget_ms:15000}};
  const caller=path.join(root,'caller.cjs');fs.writeFileSync(caller,`let out;try{const entries=require(${q(path.join(runtime,'tools/lib/repair-on-touch.js'))}).runVerificationTests(${q(request)});
      out={status:'passed',ids:entries.map(e=>e.record.execution_id),acceptances:entries.verification_acceptances,budget:entries.verification_budget};}
    catch(e){out={status:'error',code:e.code,message:e.message,delivery_teardown:e.delivery_teardown,invocation:e.invocation,
      invocation_recovery:e.invocation_recovery,recovery_teardown:e.recovery_teardown,cleanup_deadline_ns:e.cleanup_deadline_ns};}process.stdout.write(JSON.stringify(out));\n`);
  const context={stateRoot,projectKnowledgeRoot:stateRoot,targetRoot:repo,systemRoot:runtime};
  const control=require(path.join(runtime,'tools/lib/verification-control.js'));
  let administrativeClosed=true;
  function administer(moduleName,method,input){
    // These real public mutations load the copied publication addon. On
    // Windows a DLL loaded in this long-lived test process cannot be removed
    // during fixture cleanup, even after every product process has exited.
    // Keep the mutation in an observed, bounded process and retain the fixture
    // if that process does not terminate successfully. No API or proof is mocked.
    administrativeClosed=false;
    const script='const [moduleName,method,context,input]=process.argv.slice(1);const value=require(moduleName)[method](JSON.parse(context),JSON.parse(input));process.stdout.write(JSON.stringify(value),()=>process.exit(0));';
    const result=spawnSync(process.execPath,['-e',script,path.join(runtime,'tools/lib',moduleName),method,JSON.stringify(context),JSON.stringify(input)],
      {encoding:'utf8',timeout:15000,maxBuffer:1024*1024,windowsHide:true,env:{...process.env,NODE_OPTIONS:'',NODE_PATH:''}});
    assert.equal(result.error,undefined,result.error?.message);assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr);
    const value=JSON.parse(result.stdout);administrativeClosed=true;return value;
  }
  function launch(){const child=spawn(process.execPath,[caller],{stdio:['ignore','pipe','pipe'],env:{...process.env,NODE_OPTIONS:'',NODE_PATH:''}});
    const row={child,stdout:'',stderr:'',exited:false,closed:false,result:null};children.push(row);
    child.stdout.on('data',b=>{row.stdout+=b;});child.stderr.on('data',b=>{row.stderr+=b;});child.once('exit',(code,signal)=>{row.exited=true;row.exit={code,signal};});
    child.once('close',()=>{row.closed=true;try{row.result=JSON.parse(row.stdout);}catch{}});return row;}
  let init=null,boot=null,capturedScope=null,scopeClosed=false;
  function captureScope(scope){capturedScope=JSON.parse(JSON.stringify(scope));}
  function observeScopeClosed(){
    if(scopeClosed)return true;if(!capturedScope)return false;
    const proof=require(path.join(runtime,'tools/lib/command-scope-proof.js')).queryScopeClosure(capturedScope,{timeoutMs:500});
    if(proof.status==='completed' && proof.scope_sha256===require('crypto').createHash('sha256').update(JSON.stringify(capturedScope)).digest('hex'))scopeClosed=true;
    return scopeClosed;
  }
  function observeInit(){const value=JSON.parse(fs.readFileSync(marker));boot=value.boot_id;
    init={pid:Number(value.init_stat.slice(0,value.init_stat.indexOf(' '))),start_ticks:value.init_stat.slice(value.init_stat.lastIndexOf(')')+2).split(' ')[19]};
    const chain=/^NSpid:\s+(.+)$/m.exec(value.init_status)?.[1].trim().split(/\s+/).map(Number);assert.equal(chain?.at(-1),1);
    assert.deepEqual(birth(init.pid),init);t.diagnostic(JSON.stringify({actual_init:init,boot_id:boot}));}
  function initGone(){if(!init||fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim()!==boot)return false;const current=birth(init.pid);return!current||current.start_ticks!==init.start_ticks;}
  t.after(async()=>{for(const row of children)if(!row.exited)row.child.kill('SIGKILL');
    const end=mono()+15000000000n;while(mono()<end&&(children.some(r=>!r.closed)||init&&!initGone()))await delay(20);
    const closed=administrativeClosed&&children.every(r=>r.closed&&(r.result?.budget?.delivery_ownership?.cleanup?.status==='completed'||r.result?.delivery_teardown?.status==='completed'||r.exit?.signal==='SIGKILL'&&(process.platform==='linux'?initGone():observeScopeClosed())));
    if(closed&&(!init||initGone())){
      assert.equal(require.cache[path.join(runtime,'tools/lib/native',process.platform+'-'+process.arch,'lock-publication.node')],undefined,
        'Administrative calls must not leave the copied native addon mapped in the fixture owner');
      fs.rmSync(root,{recursive:true,force:true});
    }else t.diagnostic(JSON.stringify({fixture_retained_unconfirmed:root}));});
  return{root,runtime,context,control,marker,launch,observeInit,initGone,captureScope,observeScopeClosed,administer};
}

test('public verification persists the exact whole invocation before its first claim', {skip:!supported,timeout:90000},async t=>{
  const f=await fixture(t,'normal'),run=f.launch();await until(()=>run.closed,55000,'Public verification must return and close');
  assert.equal(run.result?.status,'passed',JSON.stringify({result:run.result,stderr:run.stderr}));assert.equal(run.result.acceptances.length,1);
  const attempt=f.control.readStatus(f.context).attempt;assert(attempt.invocation,'The actual public producer must bind its initial durable claim');
  assert.equal(attempt.claimed,false);assert.equal(attempt.terminal.outcome,'passed');
  assert.equal(JSON.stringify(attempt.invocation),JSON.stringify(run.result.budget.delivery_ownership.invocation));
  const proof=require(path.join(f.runtime,'tools/lib/command-scope-proof.js')).queryScopeClosure(attempt.invocation.scope,{timeoutMs:10000});
  assert.equal(proof.status,'completed',JSON.stringify(proof));assert.equal(proof.scope_sha256,attempt.invocation.scope_sha256);
});
test('cancellation of a blocked first claim performs exact automatic recovery before a new public verification', {skip:!supported,timeout:120000},async t=>{
  const f=await fixture(t,'cancel'),run=f.launch();await until(()=>fs.existsSync(f.marker),20000,'The actual first claim must reach its blocked boundary');
  const before=f.control.readStatus(f.context).attempt;f.administer('verification-control.js','requestCancel',{attempt_id:before.attempt_id,generation:before.generation});
  await until(()=>run.closed,20000,'Cancelled public verification must close within cleanup budget plus transport overhead');
  t.diagnostic(JSON.stringify({code:run.result?.code,recovery:run.result?.invocation_recovery?.status,recovery_teardown:run.result?.recovery_teardown,stderr:run.stderr}));
  assert.equal(run.result?.code,'verification_cancelled');assert.equal(run.result.delivery_teardown?.status,'completed');
  assert.equal(run.result.invocation_recovery?.status,'cancelled');assert.equal(run.result.invocation_recovery.ack_released,false);assert.equal(run.result.recovery_teardown?.status,'completed');
  const ended=f.control.readStatus(f.context).attempt;assert.equal(ended.claimed,false);assert.equal(ended.attempt_id,before.attempt_id);assert.equal(ended.terminal.ack_sha256,null);
  assert(ended.cleanup.invocation_transcript);assert.equal(ended.processes.length,0);
  const next=f.launch();await until(()=>next.closed,55000,'A new actual verification must close');
  assert.equal(next.result?.status,'passed',JSON.stringify({result:next.result,stderr:next.stderr}));assert.equal(next.result.acceptances.length,1);
  assert.notEqual(f.control.readStatus(f.context).attempt.generation,before.generation);
});
test('original caller crash before active publication permits external exact recovery and a new public verification', {skip:!supported,timeout:120000},async t=>{
  const f=await fixture(t,'crash'),run=f.launch();await until(()=>fs.existsSync(f.marker),20000,'Actual first publication boundary must be reached');
  if(process.platform==='linux')f.observeInit();
  assert.equal(fs.existsSync(path.join(f.context.stateRoot,'maintenance','verification-control','active.json')),false);
  const before=f.control.readStatus(f.context).attempt;assert(before?.claimed&&before.invocation);f.captureScope(before.invocation.scope);
  run.child.kill('SIGKILL');await until(()=>run.closed&&(process.platform==='linux'?f.initGone():f.observeScopeClosed()),20000,
    'The exact caller must close and its entire recorded native scope must be confirmed closed');assert.equal(run.exit.signal,'SIGKILL');
  assert(f.observeScopeClosed(),'Fresh exact native closure must precede external recovery');
  const result=f.administer('verification-recovery.js','recoverAttempt',{attempt_id:before.attempt_id,generation:before.generation});
  t.diagnostic(JSON.stringify({status:result.status,ack_released:result.ack_released,invocation_transcript:!!result.attempt?.cleanup.invocation_transcript}));
  // Automatic caller-loss recovery can finish while the external administrator
  // starts. Either API result must identify the same durable failed invocation;
  // idempotence never substitutes for exact closure or permits an acceptance.
  assert(['failed','already_terminal'].includes(result.status),JSON.stringify(result));assert.equal(result.ack_released,false);
  const ended=result.attempt;assert.equal(ended.attempt_id,before.attempt_id);assert.equal(ended.generation,before.generation);
  assert.deepEqual(ended.invocation,before.invocation);assert.equal(ended.phase,'terminal');assert.equal(ended.claimed,false);
  assert.equal(ended.terminal.outcome,'failed');assert.equal(ended.terminal.ack_sha256,null);assert.equal(ended.cleanup.status,'confirmed');
  const transcript=ended.cleanup.invocation_transcript;assert(transcript);
  const hash=value=>require('crypto').createHash('sha256').update(JSON.stringify(value)).digest('hex');
  assert.equal(transcript.attempt_id,before.attempt_id);assert.equal(transcript.generation,before.generation);
  assert.equal(transcript.invocation_sha256,hash(before.invocation));assert.equal(transcript.scope_sha256,before.invocation.scope_sha256);
  assert.equal(transcript.payload_sha256,hash(transcript.payload));
  const proof=transcript.payload.native_return;assert.equal(proof.status,'completed');assert.equal(proof.active_processes,0);
  assert.equal(proof.method,before.invocation.scope.backend);assert.equal(proof.scope_sha256,before.invocation.scope_sha256);
  assert.deepEqual(f.control.readStatus(f.context).attempt,ended,'Returned recovery must match the persisted exact terminal attempt');
  const next=f.launch();await until(()=>next.closed,55000,'A successor must close after exact external recovery');
  assert.equal(next.result?.status,'passed',JSON.stringify({result:next.result,stderr:next.stderr}));assert.equal(next.result.acceptances.length,1);
  assert.notEqual(f.control.readStatus(f.context).attempt.generation,before.generation);
});
