'use strict';
// Exact production JavaScript with modeled native ownership and explicit IPC
// events. These are protocol tests, not native containment qualification.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),Module=require('node:module'),{EventEmitter}=require('node:events');
const source=process.env.KNOWLEDGE_AUDIT_SOURCE||path.resolve(__dirname,'..');
const protocol='knowledge-verification-supervisor.v1';
function load(name,mocks){
  const file=path.join(source,'tools/lib',name+'.js'),m={exports:{}},local=Module.createRequire(file);
  vm.runInThisContext(Module.wrap(fs.readFileSync(file,'utf8')),{filename:file})(m.exports,key=>Object.hasOwn(mocks,key)?mocks[key]:local(key),m,file,path.dirname(file));
  return m.exports;
}
async function scenario(mode,event){
  const worker=new EventEmitter();Object.assign(worker,{pid:42424,connected:true,exitCode:null,signalCode:null,stdin:new EventEmitter(),stdout:new EventEmitter(),send(){},kill(){},disconnect(){this.connected=false;},unref(){}});
  worker.stdin.end=()=>{};
  const owner={attempt_id:'VAT-'+ 'a'.repeat(32),generation:'b'.repeat(32)},start=process.hrtime.bigint();
  let closes=0,beforeFallback=false,driverError=null,spawnId=0;
  const birth='2026-01-01T00:00:00.000Z';
  const job={ready:Promise.resolve(),started:Promise.resolve(),permit(){},keeper_pid:42425,keeper_executable_sha256:'a'.repeat(64),descriptor:{backend:'linux_pid_namespace'},
    identities:{controller:{pid:process.pid,os_creation_time:birth},worker:{pid:worker.pid,os_creation_time:birth},keeper:{pid:42425,os_creation_time:birth}},
    async close(){closes++;return {status:'completed',method:'modeled_container'};}};
  const progress={connect:async()=>({send(){},close(){}}),listen:async()=>({descriptor:{},close(){}})};
  const control={readStatus:()=>({attempt:{...owner,cancel:{requested:false},recovery:null}}),updateAttempt:()=>({spawn_id:++spawnId}),assertResourceAvailable(){}};
  const native={spawnLinuxContainedWorker(){setImmediate(()=>{worker.emit('spawn');setImmediate(()=>{
    try{
      if(event==='disconnect'){worker.connected=false;worker.emit('disconnect');}
      else if(event==='short'){worker.emit('message',{protocol,type:'candidate',status:'failed',bytes:5});worker.stdout.emit('data',Buffer.from('{}'));worker.stdout.emit('end');}
      else if(event==='stdout_error')worker.stdout.emit('error',new Error('synthetic pipe failure'));
      else if(event==='before_metadata'){worker.stdout.emit('data',Buffer.from('{}'));worker.stdout.emit('end');worker.emit('message',{protocol,type:'candidate',status:'failed',bytes:2});}
      else {worker.emit('message',{protocol,type:'candidate',status:'failed',bytes:2});worker.stdout.emit('data',Buffer.from('{}'));worker.stdout.emit('end');}
    }catch(e){driverError=e.message;}
    setImmediate(()=>{beforeFallback=closes>0;if(!beforeFallback)worker.emit('error',Object.assign(new Error('explicit fixture cleanup'),{code:'audit_fallback_cleanup'}));});
  });});return {worker,job};}};
  const mocks={'./verification-linux-namespace':native,'./verification-progress':progress,'./verification-control':control};
  let result;
  if(mode==='supervisor')result=await load('verification-supervisor',mocks).__test.supervise({protocol,started_ns:String(start),deadline_ns:String(start+30000000000n),timeout_ms:30000,request:{tests:[{argv:['node','test.js']}],verificationPolicy:{work_budget_ms:30000,no_progress_ms:0,cleanup_budget_ms:10000}}});
  else {
    mocks['./verification-supervisor']={assertContainmentAvailable(){}};
    result=await load('verification-watchdog',mocks).__test.watch({protocol,started_ns:String(start),deadline_ns:String(start+30000000000n),timeout_ms:30000,policy:{no_progress_ms:0,cleanup_budget_ms:10000},test_count:1,request_sha256:'a'.repeat(64),request_json:'{}',control:{context:{stateRoot:'modeled'},owner,spawn_id:1}});
  }
  await new Promise(resolve=>setImmediate(resolve));
  return {result,beforeFallback,closes,driverError};
}
for(const [mode,event,code] of [
  ['supervisor','disconnect','verification_worker_transport_closed'],
  ['watchdog','disconnect','verification_authority_transport_closed'],
  ['watchdog','short','verification_authority_transport_truncated'],
  ['watchdog','stdout_error','verification_authority_transport_failed']]){
  test(`${mode} ${event} starts cleanup without waiting for work budget`,{skip:process.platform!=='linux'},async()=>{
    const r=await scenario(mode,event);assert.equal(r.beforeFallback,true,'protocol loss ignored until explicit fixture cleanup');assert.equal(r.result.error?.code,code);assert.equal(r.closes,1);
  });
}
for(const event of ['before_metadata','after_metadata'])test(`complete stdout ${event} preserves valid candidate ordering`,{skip:process.platform!=='linux'},async()=>{
  const r=await scenario('watchdog',event);assert.equal(r.driverError,null);assert.equal(r.beforeFallback,true);assert.equal(r.result.authority_status,'failed');assert.equal(r.result.authority_payload,'{}');assert.equal(r.closes,1);
});
