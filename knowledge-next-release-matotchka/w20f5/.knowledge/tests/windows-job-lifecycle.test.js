'use strict';
// Keeper state-machine regressions: real module, inert EventEmitter keeper.
// Never starts PowerShell, a worker, a Job, or any product subprocess.
const fs=require('fs'),path=require('path'),vm=require('vm'),{EventEmitter}=require('events'),assert=require('assert/strict'),crypto=require('crypto');
const source=path.resolve(__dirname,'../tools/lib/verification-windows-job.js');
const bytes=fs.readFileSync(source),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
function fixture({killCloseDelay=10,onEnd}={}){
 const log=[];const keeper=new EventEmitter();keeper.exitCode=null;keeper.signalCode=null;
 keeper.stdout=new EventEmitter();keeper.stdout.setEncoding=()=>{};keeper.stdout.destroy=()=>log.push('stdout-destroy');
 keeper.stdin=new EventEmitter();keeper.stdin.destroy=()=>log.push('stdin-destroy');
 keeper.stdin.end=data=>{log.push('end:'+data.trim());if(onEnd)onEnd(api);};
 keeper.kill=()=>{log.push('kill');setTimeout(()=>close(1),killCloseDelay);return true;};keeper.unref=()=>log.push('unref');
 function close(code){if(keeper.exitCode!==null)return;keeper.exitCode=code;log.push('keeper-close:'+code);keeper.emit('close',code);}
 const exports={};const context={module:{exports},exports,require:name=>name==='child_process'?{spawn:()=>{log.push('spawn');return keeper;}}:require(name),__dirname:path.dirname(source),process:{env:{SystemRoot:path.resolve('inert-audit-systemroot')}},setTimeout,clearTimeout,Buffer};
 vm.runInNewContext(fs.readFileSync(source,'utf8'),context,{filename:source});
 const job=context.module.exports.createWindowsJob({pid:12345,exitCode:null,signalCode:null},()=>log.push('failure-callback'),1000);job.ready.catch(()=>{});
 const api={job,log,keeper,close,frame:x=>keeper.stdout.emit('data',JSON.stringify(x)+'\n')};return api;
}
async function run(){const rows=[];
 {const f=fixture({killCloseDelay:30});let resolved=false;const p=f.job.close(200).then(x=>{resolved=true;f.log.push('resolved');return x;});await delay(5);assert(!resolved);assert(f.log.includes('kill'));const r=await p;assert.equal(r.status,'unconfirmed');assert.equal(r.keeper_exited,true);assert(f.log.indexOf('resolved')>f.log.indexOf('keeper-close:1'));rows.push({case:'close-before-ready waits real close observation',status:'PASS',log:f.log});}
 {const f=fixture({killCloseDelay:10});f.frame({status:'ready'});await f.job.ready;const r=await f.job.close(90);assert.equal(r.status,'unconfirmed');assert.equal(r.code,'job_teardown_timeout');assert.equal(r.keeper_exited,true);assert.equal(f.log.filter(x=>x==='kill').length,1);rows.push({case:'timeout kill still waits keeper close',status:'PASS',log:f.log});}
 {const f=fixture({onEnd:f=>setTimeout(()=>{f.frame({status:'unexpected'});f.frame({status:'closed',active_processes:0});f.close(0);},5)});f.frame({status:'ready'});await f.job.ready;const r=await f.job.close(200);assert.equal(r.status,'unconfirmed');assert.equal(r.keeper_exited,true);assert.equal(f.log.filter(x=>x==='failure-callback').length,0);rows.push({case:'unexpected closing protocol stays failed after valid closed/exit0',status:'PASS',log:f.log});}
 {const f=fixture({onEnd:f=>setTimeout(()=>{f.keeper.stdout.emit('data','{bad-json}\n');f.frame({status:'closed',active_processes:0});f.close(0);},5)});f.frame({status:'ready'});await f.job.ready;const r=await f.job.close(200);assert.equal(r.status,'unconfirmed');rows.push({case:'malformed JSON during close cannot complete',status:'PASS',log:f.log});}
 {const f=fixture({onEnd:f=>setTimeout(()=>{f.frame({status:'closed',active_processes:0});f.close(0);},10)});f.frame({status:'ready'});await f.job.ready;const p1=f.job.close(200),p2=f.job.close(3000);const [a,b]=await Promise.all([p1,p2]);assert.equal(a.status,'completed');assert.strictEqual(a,b);assert.equal(f.log.filter(x=>x==='end:close').length,1);assert.equal(f.log.filter(x=>x==='unref').length,1);const again=await f.job.close(1);assert.strictEqual(a,again);rows.push({case:'repeated close is idempotent including settled replay',status:'PASS',log:f.log});}
 assert.equal(sha(fs.readFileSync(source)),sha(bytes));const result={status:'PASS',cases:rows.length,source,source_sha256:sha(bytes),source_unchanged:true,scope:'VM-loaded actual createWindowsJob with inert EventEmitter spawn; state machine proof only, not Windows Job/exit/runtime deadline proof',product_subprocesses_started:0,results:rows};console.log(JSON.stringify(result,null,2));}
require('node:test')('keeper close waits, rejects protocol faults and is idempotent', run);
