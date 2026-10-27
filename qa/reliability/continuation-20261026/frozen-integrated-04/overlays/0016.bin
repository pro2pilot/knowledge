'use strict';
// Exact production JS with modeled kernel ownership. This proves terminal
// ordering, not physical Windows pipe behavior or native containment.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),Module=require('node:module'),{EventEmitter}=require('node:events');
const protocol='knowledge-verification-supervisor.v1';
const root=process.env.KNOWLEDGE_AUDIT_SOURCE||path.resolve(__dirname,'..');
const immediate=()=>new Promise(resolve=>setImmediate(resolve));
async function scenario(mode){
 const file=path.join(root,'tools/lib/verification-watchdog.js'),local=Module.createRequire(file),m={exports:{}};
 const worker=new EventEmitter();Object.assign(worker,{pid:42424,connected:true,exitCode:null,signalCode:null,stdin:new EventEmitter(),stdout:new EventEmitter(),send(){},kill(){},disconnect(){this.connected=false;},unref(){}});worker.stdin.end=()=>{};
 const owner={attempt_id:'VAT-'+'a'.repeat(32),generation:'b'.repeat(32)},start=process.hrtime.bigint(),birth='2026-01-01T00:00:00.000Z';
 const order=[],updates=[];let onEvent,release,finishEntered=false,flushEnd,finishEnd,spawn=0;
 const held=new Promise(resolve=>{release=resolve;});
 const job={ready:Promise.resolve(),started:Promise.resolve(),permit(){},keeper_pid:42425,keeper_executable_sha256:'a'.repeat(64),descriptor:{backend:'linux_pid_namespace'},identities:{controller:{pid:process.pid,os_creation_time:birth},worker:{pid:42424,os_creation_time:birth},keeper:{pid:42425,os_creation_time:birth}},async close(){order.push('native_close');return{status:'completed',method:'modeled_container'};}};
 const reporter={send(){},async flush(event,end){flushEnd=end;order.push('flush');},async finish(end){finishEnd=end;finishEntered=true;order.push('finish_enter');await held;if(mode==='reject')throw Object.assign(new Error('modeled terminal transport loss'),{code:'verification_progress_transport_failed'});order.push('finish_complete');},close(){order.push('unawaited_close');}};
 const mocks={
  fs:{...fs,readFileSync(file,...args){return file===process.execPath?Buffer.from('modeled-node-image'):fs.readFileSync(file,...args);}},
  './verification-supervisor':{assertContainmentAvailable(){}},
  './verification-progress':{connect:async()=>reporter,listen:async callback=>{onEvent=callback;return{descriptor:{},close(){order.push('inner_close');}};}},
  './verification-control':{readStatus:()=>({attempt:{...owner,cancel:{requested:false},recovery:null}}),updateAttempt(_c,_o,event){updates.push(event);return{spawn_id:++spawn};},assertResourceAvailable(){}},
  './verification-policy':{resolvePolicy:()=>({work_budget_ms:30000,cleanup_budget_ms:10000,no_progress_ms:0,control_poll_ms:1000,profile:'modeled'}),createProgress:()=>({advance:()=>true,snapshot:()=>({phase:'running',progress_signal_available:true}),isStalled:()=>false}),timerDelay:n=>n},
  './verification-linux-namespace':{getInvocationHelper:()=>null,spawnLinuxContainedWorker(){setImmediate(()=>{worker.emit('spawn');setImmediate(async()=>{await onEvent({type:'committed',execution_id:'KVE-modeled'});await onEvent({type:'work_completed',at_ns:String(process.hrtime.bigint()),count:1});worker.emit('message',{protocol,type:'candidate',status:'completed',bytes:2});worker.stdout.emit('data',Buffer.from('{}'));worker.stdout.emit('end');});});return{worker,job};}}
 };
 const modeled=Object.create(process);Object.defineProperty(modeled,'platform',{value:'linux'});
 vm.runInThisContext('(function(exports,require,module,__filename,__dirname,process){'+fs.readFileSync(file,'utf8')+'\n})',{filename:file})(m.exports,key=>Object.hasOwn(mocks,key)?mocks[key]:local(key),m,file,path.dirname(file),modeled);
 let resolved=false;const pending=m.exports.__test.watch({protocol,started_ns:String(start),deadline_ns:String(start+30000000000n),timeout_ms:30000,policy:{no_progress_ms:0,cleanup_budget_ms:10000},test_count:1,request_sha256:'a'.repeat(64),request_json:'{}',outer_lifecycle:{},control:{context:{stateRoot:'modeled'},owner,spawn_id:1}}).then(value=>{resolved=true;order.push('resolved');return value;});
 for(let i=0;i<100&&!finishEntered&&!resolved;i++)await immediate();
 const before={resolved,finishEntered};release();const result=await pending;
 return{result,before,order,updates,flushEnd,finishEnd};
}
test('watchdog withholds terminal envelope until outer lifecycle graceful finish completes',{timeout:10000},async()=>{
 const r=await scenario('success');assert.deepEqual(r.before,{resolved:false,finishEntered:true});assert.equal(r.result.authority_status,'completed');assert.equal(r.result.authority_teardown.status,'completed');assert(r.order.indexOf('native_close')<r.order.indexOf('finish_complete'));assert(r.order.indexOf('finish_complete')<r.order.indexOf('resolved'));assert(!r.order.includes('unawaited_close'));
});
test('watchdog refuses candidate on outer lifecycle finish failure while preserving native cleanup proof',{timeout:10000},async()=>{
 const r=await scenario('reject');assert.equal(r.result.error?.code,'verification_progress_transport_failed');assert.equal(r.result.authority_payload,undefined);assert.equal(r.result.authority_teardown.status,'completed');assert.equal(r.result.error.teardown.status,'completed');assert(r.updates.some(row=>row.type==='cleanup_proven'));
});
test('watchdog outer epoch flush and graceful finish use one original cleanup deadline',{timeout:10000},async()=>{
 const r=await scenario('success');assert.equal(typeof r.flushEnd,'bigint');assert.equal(r.finishEnd,r.flushEnd);assert(r.flushEnd>process.hrtime.bigint());
});
