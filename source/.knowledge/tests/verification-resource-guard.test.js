'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path'),os=require('os'),cp=require('child_process'),crypto=require('crypto');
const control=require('../tools/lib/verification-control'),batch=require('../tools/lib/knowledge-currency-batch'),finalization=require('../tools/lib/verification-finalization');
const {fixture:overlay}=require('./helpers/currency-overlay');
const source=path.resolve(__dirname,'..'),modulePath=path.join(source,'tools/lib/verification-control.js'),H=crypto.createHash('sha256').update('resource guard fixture').digest('hex');
function fixture(t){const parent=fs.realpathSync(os.tmpdir()),root=fs.mkdtempSync(path.join(parent,'v-resource-'));t.after(()=>{const resolved=fs.realpathSync(root);assert.equal(path.dirname(resolved),parent);assert(path.basename(resolved).startsWith('v-resource-'));fs.rmSync(resolved,{recursive:true,force:false});});return {root,context:{stateRoot:root}};}
function begin(f){return control.beginAttempt(f.context,{request_sha256:H});}
function terminal(f,s){return control.commitFinish(f.context,s.owner,{outcome:'failed',cleanup_proof:{method:'no_processes_started',attempt_id:s.owner.attempt_id,generation:s.owner.generation}});}
function tree(root){const rows={};function walk(dir){if(!fs.existsSync(dir))return;for(const item of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,item.name),rel=path.relative(root,p).replace(/\\/g,'/');if(rel==='locks'||rel==='maintenance/verification-control')continue;if(item.isDirectory())walk(p);else rows[rel]=crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');}}walk(root);return rows;}
function holdUntil(file,ms=5000){const deadline=Date.now()+ms;while(!fs.existsSync(file)){if(Date.now()>=deadline)throw Error('Actor barrier expired');Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5);}}

test('resource mutation rejects active and cleanup-unconfirmed claims without invoking its callback',t=>{
 for(const unconfirmed of [false,true]){const f=fixture(t),s=begin(f);if(unconfirmed){control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'keeper'});control.updateAttempt(f.context,s.owner,{type:'cleanup_started'});control.updateAttempt(f.context,s.owner,{type:'cleanup_unconfirmed'});}const before=tree(f.root);let calls=0;assert.throws(()=>control.withResourceAvailable(f.context,()=>{calls++;fs.writeFileSync(path.join(f.root,'forbidden'),'bad');}),{code:'verification_recovery_required'});assert.equal(calls,0);assert.deepEqual(tree(f.root),before);assert.equal(control.readStatus(f.context).status,'blocked');}
});

test('resource guard supports only synchronous call-stack reentry, and releases its mutex after thrown actions',t=>{
 const f=fixture(t);assert.equal(control.withResourceAvailable(f.context,()=>control.withResourceAvailable(f.context,()=>42)),42);
 assert.throws(()=>control.withResourceAvailable(f.context,()=>begin(f)),{code:'verification_resource_busy'});
 assert.throws(()=>control.withResourceAvailable(f.context,()=>{throw Object.assign(Error('fixture'),{code:'fixture_throw'});}),{code:'fixture_throw'});
 assert.throws(()=>control.withResourceAvailable(f.context,()=>Promise.resolve()),{code:'verification_resource_async_unsupported'});
 const s=begin(f);terminal(f,s);
});

test('an actual competing process cannot issue a claim until the guarded mutation releases the physical mutex',async t=>{
 const f=fixture(t),ready=path.join(f.root,'actor-ready'),claimed=path.join(f.root,'actor-claimed');let child,out='',err='';
 const script=`const fs=require('fs'),c=require(${JSON.stringify(modulePath)});fs.writeFileSync(process.argv[2],'ready');try{const s=c.beginAttempt({stateRoot:process.argv[1]},{request_sha256:${JSON.stringify(H)}});fs.writeFileSync(process.argv[3],JSON.stringify({attempt_id:s.owner.attempt_id}));process.stdout.write('claimed');}catch(e){process.stderr.write(e.code);process.exitCode=2}`;
 control.withResourceAvailable(f.context,()=>{
  child=cp.spawn(process.execPath,['-e',script,f.root,ready,claimed],{stdio:['ignore','pipe','pipe'],windowsHide:true});child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);
  holdUntil(ready);Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,100);assert.equal(fs.existsSync(claimed),false);assert.equal(control.readStatus(f.context).status,'idle');fs.writeFileSync(path.join(f.root,'mutation'),'committed');
 });
 const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});assert.equal(code,0,err);assert.equal(out,'claimed');assert(fs.existsSync(claimed));assert.equal(control.readStatus(f.context).status,'blocked');
});

test('currency exports and direct recertify mutations reject quarantined roots before any transaction or lifecycle write',t=>{
 const f=overlay(t,'blocked-mutator'),s=control.beginAttempt(f.context,{request_sha256:H});control.updateAttempt(f.context,s.owner,{type:'spawn_intent',role:'keeper'});control.updateAttempt(f.context,s.owner,{type:'cleanup_started'});control.updateAttempt(f.context,s.owner,{type:'cleanup_unconfirmed'});const before=tree(f.state);
 for(const api of ['issueBatch','issueBatchUnlocked'])assert.throws(()=>batch[api](f.context,f.batchPath,[]),{code:'verification_recovery_required'});
 const actor=`process.argv=[process.execPath,'fixture',...JSON.parse(process.env.GUARD_CONTEXT_FLAGS)];const r=require(${JSON.stringify(path.join(source,'tools/recertify.js'))});for(const fn of ['run','applyVerificationReceipt','finalizeTrustElevation']){try{r[fn]({});process.exit(3)}catch(e){if(e.code!=='verification_recovery_required')throw e;}}process.stdout.write('blocked-three-entrypoints');`;
 const flags=['--mode=repo','--state-root='+f.state,'--project-knowledge-root='+f.context.projectKnowledgeRoot,'--target-root='+f.root,'--system-root='+source];
 const child=cp.spawnSync(process.execPath,['-e',actor],{cwd:f.root,encoding:'utf8',timeout:15000,windowsHide:true,env:{...process.env,GUARD_CONTEXT_FLAGS:JSON.stringify(flags),KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1'}});assert.equal(child.status,0,child.stderr);assert.equal(child.stdout,'blocked-three-entrypoints');assert.deepEqual(tree(f.state),before);
});

test('a physically accepted current ACK cannot issue currency while another process leaves a quarantined claim',{skip:!['win32','linux'].includes(process.platform)},t=>{
 const f=overlay(t,'current-ack-lease'),v=f.verify();assert.equal(finalization.requireFinalizedExecutions(f.state,v.execution_ids,v.verification_acceptances).status,'accepted');
 const actor=`const c=require(${JSON.stringify(modulePath)});const s=c.beginAttempt({stateRoot:process.argv[1]},{request_sha256:${JSON.stringify(H)}});c.updateAttempt({stateRoot:process.argv[1]},s.owner,{type:'spawn_intent',role:'keeper'});c.updateAttempt({stateRoot:process.argv[1]},s.owner,{type:'cleanup_started'});c.updateAttempt({stateRoot:process.argv[1]},s.owner,{type:'cleanup_unconfirmed'});process.stdout.write('quarantined');`;
 const claim=cp.spawnSync(process.execPath,['-e',actor,f.state],{encoding:'utf8',timeout:15000,windowsHide:true});assert.equal(claim.status,0,claim.stderr);assert.equal(claim.stdout,'quarantined');const before=tree(f.state);
 const contender=`const b=require(${JSON.stringify(path.join(source,'tools/lib/knowledge-currency-batch.js'))}),i=JSON.parse(require('fs').readFileSync(0,'utf8'));try{b.issueBatch(i.context,i.batchPath,i.v.execution_ids,null,i.v.verification_acceptances);process.exit(3)}catch(e){process.stdout.write(e.code);process.exitCode=e.code==='verification_recovery_required'?0:2}`;
 const rejected=cp.spawnSync(process.execPath,['-e',contender],{input:JSON.stringify({context:f.context,batchPath:f.batchPath,v}),encoding:'utf8',timeout:15000,windowsHide:true});assert.equal(rejected.status,0,rejected.stderr);assert.equal(rejected.stdout,'verification_recovery_required');assert.deepEqual(tree(f.state),before);assert.deepEqual(f.ledgers().map(b=>b.toString()),[fs.readFileSync(path.join(f.state,'maintenance/stale_items.json'),'utf8'),fs.readFileSync(path.join(f.state,'maintenance/repair_queue.json'),'utf8')]);
 if(process.env.KNOWLEDGE_CONTROL_TEST_EVIDENCE){const out=path.join(process.env.KNOWLEDGE_CONTROL_TEST_EVIDENCE,'current-ack-blocked');fs.mkdirSync(out,{recursive:true});for(const store of ['verification_executions','verification_finalizations','verification-control'])fs.cpSync(path.join(f.state,'maintenance',store),path.join(out,store),{recursive:true});fs.writeFileSync(path.join(out,'verification.json'),JSON.stringify(v,null,2)+'\n');fs.writeFileSync(path.join(out,'before-after-tree.json'),JSON.stringify({before,after:tree(f.state),actor_stdout:claim.stdout,contender_stdout:rejected.stdout},null,2)+'\n');}
});

test('successful currency mutation can reenter its guard and preserves native acceptance semantics',{skip:!['win32','linux'].includes(process.platform)},t=>{
 const f=overlay(t,'guard-success'),v=f.verify();const result=control.withResourceAvailable(f.context,()=>f.issue(v));assert.equal(result.status,'committed');assert.equal(f.evaluate().valid,true);assert.equal(control.readStatus(f.context).status,'terminal');
});
