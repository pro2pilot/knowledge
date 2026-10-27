'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const systemRoot = path.resolve(process.argv[2]);
const root = path.resolve(process.argv[3]);
fs.mkdirSync(root, {recursive:false});
const team = require(path.join(systemRoot, 'tools/lib/team-store.js'));
const manager = require(path.join(systemRoot,'tools/lib/contained-lock-manager.js'));
const { LOCKS } = require(path.join(systemRoot,'tools/lib/lock-policy.js'));
const checks=[];
function tree(directory) {
  if (!fs.existsSync(directory)) return null;
  const result=[];
  const walk=(file)=>{
    const st=fs.lstatSync(file,{bigint:true});
    assert(!st.isSymbolicLink());
    const item={path:path.relative(directory,file),dev:String(st.dev),ino:String(st.ino),
      mtime:String(st.mtimeNs),ctime:String(st.ctimeNs),mode:String(st.mode),nlink:String(st.nlink)};
    if(st.isFile()) {item.type='file';item.sha256=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');}
    else {assert(st.isDirectory()); item.type='directory';}
    result.push(item);
    if(st.isDirectory()) for(const name of fs.readdirSync(file).sort()) walk(path.join(file,name));
  };
  walk(directory);return result;
}
function context(name) {
  const fixture=path.join(root,name);fs.mkdirSync(fixture);
  return {mode:'team',systemRoot,projectKnowledgeRoot:systemRoot,targetRoot:fixture,
    teamRoot:path.join(fixture,'team'),repoId:'repo-a',workspaceId:'workspace',agentId:'agent-a',
    git:{},branch:'test',headSha:null,warnings:[]};
}
function lockPath(ctx,name) {
  return path.join(name==='team-registry'?ctx.teamRoot:path.join(ctx.teamRoot,'repos',ctx.repoId),'locks/v1',name+'.lock');
}
function ownerless(ctx,name) {
  const file=lockPath(ctx,name);fs.mkdirSync(file,{recursive:true});const old=new Date(Date.now()-10000);fs.utimesSync(file,old,old);
}
function run(name,fn) {
  try {fn(context(String(checks.length)));checks.push({name,status:'pass'});}
  catch(error) {checks.push({name,status:'fail',error:error.stack||error.message});}
}
function readOnlyStatus(ctx) {
  const before=tree(ctx.teamRoot);const value=team.listTeamStatus(ctx.teamRoot);
  assert.deepEqual(tree(ctx.teamRoot),before,'team status must not create, replace, or rewrite any file/directory');
  return value;
}
run('nonexistent team root is explicitly uninspected and remains nonexistent',ctx=>{
  const value=readOnlyStatus(ctx);assert.equal(value.locks.registry,null);assert.equal(value.workspaces_total,0);
});
run('existing empty root reports missing registry lock as safe without initializing layout',ctx=>{
  fs.mkdirSync(ctx.teamRoot);const value=readOnlyStatus(ctx);assert.equal(value.locks.registry.status,'safe');
  assert.equal(fs.existsSync(path.join(ctx.teamRoot,'locks')),false);
});
run('registered healthy team exposes registry safety and preserves per-repo flow safety',ctx=>{
  team.registerWorkspace(ctx);const value=readOnlyStatus(ctx);assert.equal(value.locks.registry.status,'safe');
  assert.equal(value.repos[0].locks.flow.status,'safe');assert.deepEqual(value.warnings,[]);
});
run('live shared owner is active, not unsafe, and no warning is fabricated',ctx=>{
  team.registerWorkspace(ctx);
  const handle=manager.acquireContainedLock({context:{...ctx,stateRoot:ctx.teamRoot},rootKind:'state',
    rootPath:ctx.teamRoot,lockName:'team-registry',purpose:LOCKS['team-registry'].purpose});
  try {const value=readOnlyStatus(ctx);assert.equal(value.locks.registry.status,'active');
    assert.equal(value.locks.registry.current.owner.pid,process.pid);assert.deepEqual(value.warnings,[]);}
  finally {handle.release();}
});
run('aged ownerless shared lock is visible, unchanged, and still blocks mutation',ctx=>{
  team.registerWorkspace(ctx);ownerless(ctx,'team-registry');const before=tree(ctx.teamRoot);
  const value=readOnlyStatus(ctx);assert.equal(value.locks.registry.status,'unsafe');
  assert(value.locks.registry.findings.some(f=>f.code==='lock_owner_invalid'&&f.reason==='missing'));
  assert(value.warnings.some(w=>w.includes('team-registry')&&w.includes('lock_owner_invalid')));
  // Exercise the real public facade with the existing explicit test timeout.
  // Production default budgets are unchanged; missing metadata never grants a write.
  const previousTimeout=process.env.KNOWLEDGE_LOCK_TIMEOUT_MS;
  process.env.KNOWLEDGE_LOCK_TIMEOUT_MS='1500';
  try {
    assert.throws(()=>team.registerWorkspace({...ctx,branch:'must-not-change'}),e=>e.code==='lock_timeout'&&
      e.owner_disposition==='owner_initialization_unconfirmed'&&e.recovery_required==='owner_metadata_evidence');
  } finally {
    if(previousTimeout===undefined)delete process.env.KNOWLEDGE_LOCK_TIMEOUT_MS;
    else process.env.KNOWLEDGE_LOCK_TIMEOUT_MS=previousTimeout;
  }
  // The contender owns a private prepared generation under .release. Its
  // creation/removal changes only that directory's timestamps; the unknown
  // public owner and all registry/workspace bytes and identities stay exact.
  const stable = rows => rows.map(row => { if (row.path !== 'locks/v1/.release') return row; const {mtime,ctime,...other}=row; return other; });
  assert.deepEqual(stable(tree(ctx.teamRoot)),stable(before));
});
run('shared registry warning preserves stale workspace warning and ownerless flow detail',ctx=>{
  team.registerWorkspace(ctx);
  const file=path.join(ctx.teamRoot,'repos/repo-a/workspaces/workspace/workspace.json');
  const ws=JSON.parse(fs.readFileSync(file,'utf8'));ws.updated_at='2000-01-01T00:00:00.000Z';
  fs.writeFileSync(file,JSON.stringify(ws,null,2)+'\n');
  ownerless(ctx,'team-registry');ownerless(ctx,'team-flow');
  const value=readOnlyStatus(ctx);assert.equal(value.locks.registry.status,'unsafe');
  assert.equal(value.repos[0].locks.flow.status,'unsafe');
  assert(value.warnings.some(w=>w.includes('stale workspace')));
  assert.equal(value.warnings.filter(w=>w.includes('team-registry')).length,1);
});
const failed=checks.filter(x=>x.status==='fail').length;
process.stdout.write(JSON.stringify({schema_version:'knowledge-team-registry-visibility-regression.v1',
 status:failed?'fail':'pass',basis_version:require(path.join(systemRoot,'package.json')).version,
 checks_total:checks.length,passed:checks.length-failed,failed,fixture_root:root,checks},null,2)+'\n');
if(failed)process.exitCode=1;
