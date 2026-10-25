'use strict';
// Real Linux scope/owner preparation. Only the read-only closure response and
// deterministic latency are injected; they always say active, never dead.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const runner=require('../tools/lib/command-runner'),manager=require('../tools/lib/contained-lock-manager');
const proof=require('../tools/lib/command-scope-proof'),{LOCKS}=require('../tools/lib/lock-policy');
const pause=ms=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,ms);
async function fixture(t){
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-scope-budget-'))),scope=await runner.createCommandSession({cwd:root});
  t.after(async()=>{await scope.drain();await scope.finish();fs.rmSync(root,{recursive:true,force:true});});
  const request={context:{stateRoot:root},rootKind:'state',rootPath:root,lockName:'team-flow',purpose:LOCKS['team-flow'].purpose,executionScope:scope.scope};
  const source=path.resolve(__dirname,'..');
  const code="const path=require('path');require(path.join(process.argv[1],'tools/lib/contained-lock-manager')).acquireContainedLock(JSON.parse(process.argv[2]));";
  const child=cp.spawnSync(process.execPath,['-e',code,source,JSON.stringify(request)],{encoding:'utf8',timeout:30000});
  assert.ifError(child.error);assert.equal(child.status,0,child.stderr);
  return {root,scope,request};
}
for(const slowStage of ['preparation','previous_observation'])test(`scope query receives remaining acquisition time after slow ${slowStage}`,
  {skip:process.platform!=='linux',timeout:30000},async t=>{
  const f=await fixture(t),calls=[];let delayed=false;
  if(slowStage==='preparation'){
    const original=fs.fsyncSync;
    t.mock.method(fs,'fsyncSync',function(fd){
      const file=fs.readlinkSync('/proc/self/fd/'+fd);
      if(!delayed && file.startsWith(f.root) && file.includes('/.release/publish-') && file.endsWith('/owner.json')){delayed=true;pause(650);}
      return original.call(fs,fd);
    });
  }
  const started=process.hrtime.bigint();
  t.mock.method(proof,'queryScopeClosure',(_scope,options)=>{
    calls.push({timeout:options.timeoutMs,elapsed:Number(process.hrtime.bigint()-started)/1e6});
    if(slowStage==='previous_observation' && !delayed){delayed=true;pause(650);}
    return {status:'active',method:'owned-test-readonly-observation'};
  });
  assert.throws(()=>manager.acquireContainedLock({...f.request,timeoutMs:1000}),{code:'lock_timeout'});
  assert.equal(delayed,true);assert(calls.length>=(slowStage==='previous_observation'?2:1));
  for(const call of calls)assert(call.timeout>0 && call.timeout<=1000-call.elapsed+20,
    'A closure query received renewed time: '+JSON.stringify(call));
});
