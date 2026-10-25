'use strict';
// Parent-only CLI fault injection. --require is not inherited by spawned steps.
// Delegate the final append to the real filesystem after replacing our own
// fixture event file with a directory. No process or lock result is mocked.
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const originalAppend=fs.appendFileSync;
const expectedRoot=path.resolve(process.env.TEAM_DIAGNOSTIC_ROOT);
const marker=process.env.TEAM_DIAGNOSTIC_MARKER;
let injected=false;
fs.appendFileSync=function(file,body,...args) {
  let event=null;try {event=JSON.parse(String(body));}catch{}
  const target=typeof file==='string'?path.resolve(file):'';
  if(!injected && event?.type==='lock_released' && target.startsWith(expectedRoot+path.sep)) {
    injected=true;
    const saved=target+'.preserved-before-release-fault';
    const bytes=fs.readFileSync(target);
    fs.renameSync(target,saved);
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target,'fault-sentinel.txt'),'Physical parent-only release event obstruction.\n');
    fs.writeFileSync(marker,JSON.stringify({type:'physical_event_obstruction_before_actual_append',pid:process.pid,
      target,preserved_file:saved,preserved_sha256:crypto.createHash('sha256').update(bytes).digest('hex'),
      requested_event:event,actual_append_delegated:true},null,2)+'\n');
  }
  return originalAppend.call(this,file,body,...args);
};
