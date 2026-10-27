'use strict';
const fs=require('fs'),path=require('path'),cp=require('child_process');
const [directory,phase,role]=process.argv.slice(2),records=path.join(directory,'births.ndjson');
const spawn=cp.spawn;
cp.spawn=function(exe,args,options){
  const launcher=args.some(value=>String(value).endsWith('command-windows-bootstrap.js'));
  if(launcher){args=['--require',path.join(__dirname,'reliability-windows-bootstrap-inject.cjs'),...args];
    options={...options,env:{...options.env,KNOWLEDGE_QA_HOLDER_STALL:JSON.stringify({phase,roles:[role],marker_directory:directory})}};}
  const child=spawn.call(cp,exe,args,options);
  if(launcher||args.some(value=>String(value).endsWith('command-windows-guard.js')))
    child.on('message',value=>{if(['bootstrap_created','native_ready'].includes(value?.type))fs.appendFileSync(records,JSON.stringify(value)+'\n');});
  return child;
};
const controller=new AbortController();process.on('message',value=>{if(value?.type==='cancel')controller.abort();});
const runner=require('../../tools/lib/command-runner');
runner.createCommandSession({signal:controller.signal,budgets:{setupMs:60000,workMs:120000,cleanupMs:20000,progressMs:0}}).then(async session=>{
 const cleanup=await session.finish();fs.writeFileSync(path.join(directory,'outcome.json'),JSON.stringify({unexpected_ready:true,cleanup}));process.exit(1);
},error=>{
 fs.writeFileSync(path.join(directory,'outcome.json'),JSON.stringify({code:error.code,cleanup:error.cleanup}));
 process.exit(error.cleanup?.status==='completed'?0:1);
});
