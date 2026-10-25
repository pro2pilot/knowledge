'use strict';
const fs=require('fs'),path=require('path');
const [source,root,mode,token]=process.argv.slice(2);
const library=path.join(source,'tools/lib'), state=path.join(root,'state');
const publicPath=path.join(state,'locks/v1/team-flow.lock');
let paused=false;
function pause(boundary, extra={}) {
  if(paused)return; paused=true;
  const value={pid:process.pid,boundary,public_exists:fs.existsSync(publicPath),...extra};
  fs.writeFileSync(path.join(root,`ready-${token}.json`),JSON.stringify(value));
  fs.writeSync(1,JSON.stringify(value)+'\n');
  while(!fs.existsSync(path.join(root,`gate-${token}`))) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10);
}
if(mode==='before-stale-rename') {
  const rename=fs.renameSync;
  fs.renameSync=function(from,to,...args){
    if(path.resolve(from)===publicPath&&path.dirname(path.resolve(to))===path.join(state,'locks/v1/.stale'))pause('holding_reclaimer_lease_before_rename');
    return rename.call(this,from,to,...args);
  };
}
if(mode==='exit-held-no-proc')fs.statfsSync=()=>{throw Object.assign(new Error('fixture: proc observer unavailable'),{code:'EACCES'});};
if(mode==='before-owner') {
  const mkdir=fs.mkdirSync;
  fs.mkdirSync=function(file,...args) {
    const result=mkdir.call(this,file,...args);
    if(path.resolve(file)===publicPath || (path.dirname(path.resolve(file))===path.join(state,'locks/v1/.release') && path.basename(file).startsWith('publish-team-flow-')))pause('after_created_directory_before_owner');
    return result;
  };
}
if(mode==='after-publish'||mode==='before-publish') {
  const provider=path.join(library,'lock-publication.js');
  if(fs.existsSync(provider)) {
    const publication=require(provider),call=publication.publishPreparedLock;
    publication.publishPreparedLock=function(...args) {
      if(mode==='before-publish')pause('before_native_publish');
      const result=call(...args);
      if(mode==='after-publish'&&result.status==='published')pause('after_native_publish_before_ack');
      return result;
    };
  } else if(mode==='after-publish') {
    const store=require(path.join(library,'json-store')),write=store.writeFileAtomicContained;
    store.writeFileAtomicContained=function(file,...args){const result=write.call(this,file,...args);if(path.resolve(file)===path.join(publicPath,'owner.json'))pause('after_owner_write_before_ack');return result;};
  }
}
const manager=require(path.join(library,'contained-lock-manager')), {LOCKS}=require(path.join(library,'lock-policy'));
const request={rootKind:'state',rootPath:state,context:{stateRoot:state},lockName:'team-flow',purpose:LOCKS['team-flow'].purpose,
  ...(mode==='before-publish'?{timeoutMs:2000}:{})};
if(mode==='gc-held') {
  (async()=>{
    if(typeof global.gc!=='function')throw new Error('Explicit --expose-gc is required by this fixture');
    let handle=manager.acquireContainedLock(request);const weak=new WeakRef(handle);handle=null;
    for(let i=0;i<8;i++){await new Promise(resolve=>setImmediate(resolve));global.gc();}
    pause('collected_js_handle_native_lease_held',{collected:weak.deref()===undefined});
  })().catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
} else if(mode==='counter') {
  for(let i=0;i<5;i++) manager.withContainedLock(request,()=>{
    const ledger=path.join(root,'counter.json'), log=path.join(root,'order.ndjson');
    const value=fs.existsSync(ledger)?JSON.parse(fs.readFileSync(ledger,'utf8')):0;
    fs.appendFileSync(log,JSON.stringify({event:'enter',token,i})+'\n');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,3+i);
    fs.writeFileSync(ledger,JSON.stringify(value+1));
    fs.appendFileSync(log,JSON.stringify({event:'leave',token,i})+'\n');
  });
  fs.writeSync(1,JSON.stringify({completed:true,token})+'\n');
} else if(mode==='before-publish') {
  try{const h=manager.acquireContainedLock(request);h.release();process.exitCode=2;fs.writeSync(1,JSON.stringify({unexpected_acquisition:true})+'\n');}
  catch(error){fs.writeSync(1,JSON.stringify({code:error.code})+'\n');if(error.code!=='lock_timeout')process.exitCode=3;}
} else {
  const handle=manager.acquireContainedLock(request);
  fs.writeSync(1,JSON.stringify({acquired:true,lock_id:handle.lock_id})+'\n');
  if(!['exit-held','exit-held-no-proc'].includes(mode))handle.release();
}
