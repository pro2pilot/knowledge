'use strict';
const assert=require('assert/strict');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const {spawnSync}=require('child_process');
const systemRoot=path.resolve(process.argv[2]);
const root=path.resolve(process.argv[3]);
const preload=path.resolve(process.argv[4]);
fs.mkdirSync(root,{recursive:false});
const checks=[];const commands=[];
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const env={...process.env};
for(const key of Object.keys(env))if(/^(?:KNOWLEDGE_|NODE_|TEAM_DIAGNOSTIC_)/.test(key))delete env[key];
Object.assign(env,{KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1',KNOWLEDGE_FLOW_NO_OPEN:'1',
 KNOWLEDGE_INSPECTOR_NO_OPEN:'1',BROWSER:'none',KNOWLEDGE_LOCK_TIMEOUT_MS:'1000'});
function run(command,cwd,extra={}) {
  const index=commands.length;const started=process.hrtime.bigint();
  const result=spawnSync(process.execPath,command,{cwd,env:{...env,...extra},timeout:120000,
    killSignal:'SIGKILL',maxBuffer:16*1024*1024,windowsHide:true});
  const stdout=result.stdout||Buffer.alloc(0),stderr=result.stderr||Buffer.alloc(0);
  const receipt={index,command:[process.execPath,...command],cwd,status:result.status,signal:result.signal,
    error:result.error?{code:result.error.code,message:result.error.message}:null,
    duration_ms:Number(process.hrtime.bigint()-started)/1e6,
    stdout_path:`command-${index}.stdout.log`,stdout_sha256:sha(stdout),stdout_bytes:stdout.length,
    stderr_path:`command-${index}.stderr.log`,stderr_sha256:sha(stderr),stderr_bytes:stderr.length,
    stdout_text:stdout.toString('utf8'),stderr_text:stderr.toString('utf8')};
  fs.writeFileSync(path.join(root,receipt.stdout_path),stdout);fs.writeFileSync(path.join(root,receipt.stderr_path),stderr);
  commands.push(receipt);return {...receipt,stdout:stdout.toString('utf8'),stderr:stderr.toString('utf8')};
}
function setup(name) {
  const fixture=path.join(root,name);fs.mkdirSync(fixture);
  const project=path.join(fixture,'project');fs.mkdirSync(project);
  const kb=path.join(project,'.knowledge');fs.cpSync(systemRoot,kb,{recursive:true,errorOnExist:true,force:false});
  const file=path.join(kb,'config.yaml');const before=fs.readFileSync(file);
  const after=before.toString('utf8').replace('updates:\n  enabled: true\n','updates:\n  enabled: false\n');
  assert(after.includes('updates:\n  enabled: false\n'), 'Fixture must disable optional update checks');
  fs.writeFileSync(file,after);
  fs.writeFileSync(path.join(fixture,'offline-profile.json'),JSON.stringify({path:file,
    before_sha256:sha(before),after_sha256:sha(Buffer.from(after)),change:after===before.toString('utf8')?'already offline':'updates.enabled true -> false'},null,2)+'\n');
  const teamRoot=path.join(fixture,'team');
  const args=['--mode','team','--system-root',systemRoot,'--target-root',project,'--team-root',teamRoot,
    '--workspace-id','workspace','--agent-id','regression-agent','--json'];
  const result=run([path.join(systemRoot,'tools/workspace-register.js'),...args],project);
  assert.equal(result.status,0,result.stderr);
  const body=JSON.parse(result.stdout);assert.equal(body.context.mode,'team');
  return {fixture,project,teamRoot,args,repoId:body.context.repoId,stateRoot:body.context.stateRoot};
}
function execute(ctx,flow,fault) {
  const marker=path.join(ctx.fixture,'release-fault-marker.json');
  const args=fault?['--require',preload]:[];
  args.push(path.join(systemRoot,'tools/flow.js'),flow,'--exclusive',...ctx.args);
  const result=run(args,ctx.project,fault?{TEAM_DIAGNOSTIC_ROOT:ctx.teamRoot,TEAM_DIAGNOSTIC_MARKER:marker}:{});
  if(fault)assert(fs.existsSync(marker),'controlled fault did not execute');
  else assert(!fs.existsSync(marker));
  // The selected fault happens after handle.release. Only this probe claims absence.
  assert(!fs.existsSync(path.join(ctx.teamRoot,'repos',ctx.repoId,'locks/v1/team-flow.lock')));
  return result;
}
function check(name,fn) {
  try {fn(setup(String(checks.length)));checks.push({name,status:'pass'});}
  catch(error) {checks.push({name,status:'fail',error:error.stack||error.message});}
}
check('successful flow and release produce one unchanged success JSON',ctx=>{
  const result=execute(ctx,'import',false);assert.equal(result.status,0,result.stderr);
  const value=JSON.parse(result.stdout);assert.equal(value.overall_status,'ok');
  assert.equal(value.steps_ok,11);assert.equal(value.steps_total,11);assert.equal(value.error,undefined);
});
check('successful flow then release-event failure produces one failure JSON',ctx=>{
  const result=execute(ctx,'import',true);assert.equal(result.status,2);
  const value=JSON.parse(result.stdout);assert.equal(value.overall_status,'failed');
  assert.deepEqual(value.finalization_error,{stage:'team_flow_release',code:'EISDIR'});
  assert.equal(value.checks_status,'ok');assert.equal(value.steps_ok,11);
  assert.equal(value.flow_log_status,'written');assert.equal(value.onboarding_follow_up,null);
  const bytes=fs.readFileSync(path.isAbsolute(value.flow_log)?value.flow_log:path.resolve(ctx.project,value.flow_log));
  assert.equal(sha(bytes),value.flow_log_sha256);assert.equal(bytes.length,value.flow_log_bytes);
  const marker=JSON.parse(fs.readFileSync(path.join(ctx.fixture,'release-fault-marker.json'),'utf8'));
  const events=fs.readFileSync(marker.preserved_file,'utf8').trim().split('\n').map(JSON.parse);
  assert(events.some(event=>event.type==='flow_end'&&event.overall_status==='ok'&&event.steps_ok===11));
});
check('primary flow exception survives a concurrent release-event exception',ctx=>{
  const result=execute(ctx,'diagnostic-unknown-flow',true);assert.equal(result.status,1);
  const value=JSON.parse(result.stdout);assert.equal(value.overall_status,'failed');
  assert.match(value.error.message,/Unknown flow: diagnostic-unknown-flow/);
  assert.equal(value.error.code,'flow_unexpected_error');assert.equal(value.error.lock_release_error,'EISDIR');
});
check('primary flow exception and successful release preserve existing error shape',ctx=>{
  const result=execute(ctx,'diagnostic-unknown-flow',false);assert.equal(result.status,1);
  const value=JSON.parse(result.stdout);assert.equal(value.overall_status,'failed');
  assert.match(value.error.message,/Unknown flow: diagnostic-unknown-flow/);
  assert.equal(value.error.lock_release_error,undefined);
});
check('returned Doctor failure survives release error with exact original evidence binding',ctx=>{
  const lock=path.join(ctx.stateRoot,'locks/v1/doctor.lock');
  fs.mkdirSync(lock,{recursive:true});const aged=new Date(Date.now()-10000);fs.utimesSync(lock,aged,aged);
  const before=fs.lstatSync(lock,{bigint:true});assert.deepEqual(fs.readdirSync(lock),[]);
  // RC4 import preflight already rejects the unsafe Doctor lock. Use lint to
  // exercise the returned Doctor failure instead of bypassing that preflight.
  const result=execute(ctx,'lint',true);assert.equal(result.status,2);
  const value=JSON.parse(result.stdout);assert.equal(value.overall_status,'failed');assert.equal(value.status,'failed');
  assert.equal(value.checks_status,'failed');assert(Array.isArray(value.steps));
  const doctor=value.steps.find(step=>step.step==='doctor');assert(doctor,'Doctor step disappeared from failure record');
  assert.equal(doctor.success,false);assert.notEqual(doctor.exit,0);
  assert.equal(value.failure_code,null,'original semantic failure code must not be replaced with a release error');
  assert.deepEqual(value.finalization_error,{stage:'team_flow_release',code:'EISDIR'});
  assert.equal(value.flow_log_status,'written');assert(Number.isInteger(value.flow_log_bytes)&&value.flow_log_bytes>0);
  assert.match(value.flow_log_sha256,/^[a-f0-9]{64}$/);
  const file=path.isAbsolute(value.flow_log)?value.flow_log:path.resolve(ctx.project,value.flow_log);
  const bytes=fs.readFileSync(file);assert.equal(bytes.length,value.flow_log_bytes);assert.equal(sha(bytes),value.flow_log_sha256);
  const log=JSON.parse(bytes);const loggedDoctor=log.steps.find(step=>step.step==='doctor');
  assert.equal(loggedDoctor.success,false);assert.notEqual(loggedDoctor.exit,0);
  const after=fs.lstatSync(lock,{bigint:true});
  assert.equal(after.dev,before.dev);assert.equal(after.ino,before.ino);
  assert.equal(after.mtimeNs,before.mtimeNs);assert.equal(after.ctimeNs,before.ctimeNs);
  assert.deepEqual(fs.readdirSync(lock),[],'ownerless Doctor lock must stay unchanged');
});
const failed=checks.filter(c=>c.status==='fail').length;
process.stdout.write(JSON.stringify({schema_version:'knowledge-team-flow-finalization-regression.v2',
 status:failed?'fail':'pass',basis_version:require(path.join(systemRoot,'package.json')).version,
 checks_total:checks.length,passed:checks.length-failed,failed,checks,commands,
 fixture_root:root,offline_profile:true},null,2)+'\n');
if(failed)process.exitCode=1;
