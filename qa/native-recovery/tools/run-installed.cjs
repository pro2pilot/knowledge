'use strict';
const fs=require('fs'),path=require('path'),cp=require('child_process'),crypto=require('crypto'),assert=require('assert/strict');
const out=process.argv[2],summary=[];
const digest=x=>crypto.createHash('sha256').update(JSON.stringify(x)).digest('hex');
function run(root,name,exe,args){const start=Date.now(),r=cp.spawnSync(exe,args,{cwd:root,env:{...process.env,KNOWLEDGE_AGENT_ID:'rc5-linux-installed',KNOWLEDGE_MODE:'repo',KNOWLEDGE_SYSTEM_ROOT:path.join(root,'.knowledge'),KNOWLEDGE_TARGET_ROOT:root,KNOWLEDGE_STATE_ROOT:path.join(root,'.knowledge'),KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT:path.join(root,'.knowledge'),KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH:'1'},encoding:'utf8',windowsHide:true,timeout:150000,maxBuffer:16*1024*1024});fs.writeFileSync(path.join(root,name+'.stdout.log'),r.stdout||'');fs.writeFileSync(path.join(root,name+'.stderr.log'),r.stderr||'');const value={name,argv:[exe,...args],cwd:root,status:r.status,error:r.error&&r.error.message,elapsed_ms:Date.now()-start};summary.push(value);fs.writeFileSync(path.join(root,name+'.command.json'),JSON.stringify(value,null,2));assert.ifError(r.error);assert.equal(r.status,0,(r.stderr||'')+(r.stdout||''));return r;}
const verifyCode=String.raw`
const fs=require('fs'),path=require('path'),cp=require('child_process'),assert=require('assert/strict'),crypto=require('crypto');
const root=process.cwd(),state=path.join(root,'.knowledge'),original=cp.spawnSync;let actualTransport;
cp.spawnSync=(exe,args,options)=>{const r=original(exe,args,options);if(args[0]===path.join(state,'tools/lib/verification-watchdog.js')){actualTransport={status:r.status,signal:r.signal,error:r.error&&r.error.code,stdout:r.stdout,stderr:r.stderr};fs.writeFileSync('actual-watchdog-transport.json',JSON.stringify(actualTransport,null,2));}return r;};
const n=require(path.join(state,'tools/lib/repair-on-touch.js')),f=require(path.join(state,'tools/lib/verification-finalization.js')),c=require(path.join(state,'tools/lib/verification-control.js'));
const value=n.runVerificationTests({stateRoot:state,repoRoot:root,taskId:'installed-audit',sessionId:'installed-audit',checkedBy:'installed-linux-audit',sourceFiles:['src/value.js','tests/value.js'],tests:[{argv:['node','tests/value.js'],cwd:'.',timeout_ms:30000},{argv:['node','tests/value.js'],cwd:'.',timeout_ms:30000}],timeoutMs:120000,verificationPolicy:{work_budget_ms:120000,no_progress_ms:60000,cleanup_budget_ms:30000}});
const ids=value.map(x=>x.record.execution_id),reader=f.requireFinalizedExecutions(state,ids,value.verification_acceptances),attempt=c.readStatus({stateRoot:state}).attempt;
assert.equal(ids.length,2);assert.equal(reader.status,'accepted');assert.equal(reader.execution_records.length,2);assert.equal(attempt.terminal.outcome,'passed');assert.equal(attempt.claimed,false);assert.match(attempt.terminal.ack_sha256,/^[a-f0-9]{64}$/);
const t=attempt.cleanup.native_transcript,actual=JSON.parse(actualTransport.stdout).authority_teardown;
assert.equal(JSON.stringify(t.payload.native_return),JSON.stringify(actual));assert.equal(JSON.stringify(t.payload.bound_proof.native_return),JSON.stringify(actual));assert.equal(JSON.stringify(attempt.containment.cleanup_receipt.native_return),JSON.stringify(actual));
const hash=x=>crypto.createHash('sha256').update(JSON.stringify(x)).digest('hex'),{evidence_sha256,...bound}=t.payload.bound_proof;
assert.equal(hash(bound),evidence_sha256);assert.equal(evidence_sha256,attempt.cleanup.evidence_sha256);assert.equal(hash(t.payload),t.payload_sha256);
const result={status:'pass',platform:process.platform,node:process.version,execPath:process.execPath,node_sha256:crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'),execution_ids:ids,acceptances:value.verification_acceptances,reader:{status:reader.status,records:reader.execution_records.length,bindings:reader.bindings},attempt,verification_budget:value.verification_budget,exact_raw_native_return:true};
fs.writeFileSync('installed-verification.json',JSON.stringify(result,null,2));console.log(JSON.stringify({status:'pass',ids,ack:attempt.terminal.ack_sha256,reader:reader.status}));
`;
try{
for(const name of ['fresh-node','project spaces пример']){
 const root=path.join(out,'fixtures',name);fs.mkdirSync(path.join(root,'src'));fs.mkdirSync(path.join(root,'tests'));
 fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'synthetic-installed-audit',version:'1.0.0',private:true}));fs.writeFileSync(path.join(root,'README.md'),'# Synthetic install fixture\n');fs.writeFileSync(path.join(root,'src/value.js'),'module.exports=7;\n');fs.writeFileSync(path.join(root,'tests/value.js'),"require('assert/strict').equal(require('../src/value'),7);\n");
 run(root,'git-init','git',['init','--quiet']);run(root,'git-add','git',['add','package.json','README.md','src/value.js','tests/value.js']);run(root,'git-commit','git',['-c','user.name=Pro2Pilot','-c','user.email=286498725+pro2pilot@users.noreply.github.com','commit','--quiet','-m','Synthetic fixture']);
 for(const rel of ['package.json','install-manifest.json','tools/install-check.js','tools/flow.js','INSTALL.md','install-policy.json'])assert(fs.existsSync(path.join(root,'.knowledge',rel)));
 assert(!fs.existsSync(path.join(root,'.knowledge','.git')));
 run(root,'install-check',process.execPath,['.knowledge/tools/install-check.js','--json']);
 run(root,'import',process.execPath,['.knowledge/tools/flow.js','import','--json']);
 run(root,'doctor',process.execPath,['.knowledge/tools/doctor.js','--json']);
 fs.writeFileSync(path.join(root,'installed-verify.cjs'),verifyCode);run(root,'native-two-command',process.execPath,['installed-verify.cjs']);
 const cliCode="const c=require('./.knowledge/tools/lib/verification-control');const r=c.beginAttempt({stateRoot:require('path').resolve('.knowledge')},{request_sha256:'a'.repeat(64)});console.log(JSON.stringify({attempt_id:r.owner.attempt_id,generation:r.owner.generation}));";
 const id=JSON.parse(run(root,'control-begin-no-process',process.execPath,['-e',cliCode]).stdout);
 const flags=['--json','--attempt='+id.attempt_id,'--generation='+id.generation];
 run(root,'cli-status',process.execPath,['.knowledge/tools/verification-control.js','status',...flags]);
 run(root,'cli-cancel',process.execPath,['.knowledge/tools/verification-control.js','cancel',...flags]);
 const recovered=JSON.parse(run(root,'cli-recover-no-process',process.execPath,['.knowledge/tools/verification-control.js','recover',...flags]).stdout);
 assert.equal(recovered.status,'cancelled');assert.equal(recovered.ack_released,false);assert.equal(recovered.attempt.terminal.ack_sha256,null);
}
fs.writeFileSync(path.join(out,'INSTALLED_RUN_RESULTS.json'),JSON.stringify({status:'pass',scope:'exact attempt2 audit ZIP Linux fresh+unicode install/native verification; CLI no-process cancel/recover smoke only',commands:summary},null,2));console.log(JSON.stringify({status:'pass',commands:summary.length}));
}catch(error){fs.writeFileSync(path.join(out,'INSTALLED_RUN_RESULTS.json'),JSON.stringify({status:'fail',error:{message:error.message,stack:error.stack},commands:summary},null,2));console.error(error);process.exitCode=1;}


