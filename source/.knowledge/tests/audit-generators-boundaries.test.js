'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const source = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const { captureTempDirIdentity, removeTempDirStrict } = require(path.join(source, 'tools/lib/strict-temp-cleanup'));

const worker = String.raw`
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const [source, project, state, command, mode, teamArgs]=process.argv.slice(1);
for(const key of Object.keys(process.env))if(key.startsWith('KNOWLEDGE_'))delete process.env[key];
Object.assign(process.env,{KNOWLEDGE_SYSTEM_ROOT:source,KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT:path.join(project,'.knowledge'),KNOWLEDGE_TARGET_ROOT:project,KNOWLEDGE_STATE_ROOT:state,KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1'});
let childCalls=0;
if(command==='evaluation-harness')require(path.join(source,'tools/lib/command-runner')).createCommandSession=async()=>{childCalls++;throw Object.assign(new Error('Repository command admission reached'),{code:'test_repository_admission'});};
const originalLog=console.log;console.log=()=>{};
let result=null,error=null;
(async()=>{try {
 if(command==='team-pr-summary')result=require(path.join(source,'tools',command+'.js'))(JSON.parse(teamArgs));
 else if(command==='build-visual-inspector')result=require(path.join(source,'tools',command+'.js'))({skipLock:true,quiet:true});
 else if(command==='evaluation-harness')result=await require(path.join(source,'tools',command+'.js')).__owned.main();
 else result=require(path.join(source,'tools',command+'.js'))();
}catch(e){error={code:e.code||null,message:e.message};}
console.log=originalLog;process.stdout.write(JSON.stringify({result,error,childCalls})+'\n');})();
`;

function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-generator-audit-'));
  const identity=captureTempDirIdentity(root);
  t.after(()=>removeTempDirStrict(root,{expectedIdentity:identity}));
  const project=path.join(root,'project'), state=path.join(root,'separate-state'), outside=path.join(root,'outside');
  for(const p of [project,path.join(project,'.knowledge'),state,outside])fs.mkdirSync(p,{recursive:true});
  return {root,project,state,outside};
}
function run(f,command,args=[]) {
  const child=spawnSync(process.execPath,['-e',worker,source,f.project,f.state,command,'',JSON.stringify(args)],{
    cwd:f.project,encoding:'utf8',timeout:60000,killSignal:'SIGKILL',windowsHide:true,maxBuffer:8*1024*1024
  });
  assert.equal(child.error,undefined,child.error?.message);
  assert.equal(child.signal,null,'The driver must exit normally; a timeout is not cleanup evidence');
  assert.equal(child.status,0,child.stderr);
  return JSON.parse(child.stdout);
}
function put(file,body) {fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,body);}
function symlink(t,target,link,type) {
  try {fs.symlinkSync(target,link,type);return true;}
  catch(e) {if(process.platform==='win32'&&['EPERM','EACCES','ENOSYS'].includes(e.code)){t.skip('Native symlink privilege unavailable');return false;}throw e;}
}
function refused(result) {assert.ok(result.error,JSON.stringify(result));}

for(const [command,dir] of [['collect-metrics','metrics'],['generate-pr-summary','maintenance'],['evaluation-harness',path.join('evaluation','results')],['build-visual-inspector','inspector']]) {
  test(command+' refuses an output directory symlink without writing elsewhere',t=>{
    const f=fixture(t),link=path.join(f.state,dir);fs.mkdirSync(path.dirname(link),{recursive:true});
    if(!symlink(t,f.outside,link,'junction'))return;
    const result=run(f,command); refused(result);assert.deepEqual(fs.readdirSync(f.outside),[]);
    if(command==='evaluation-harness')assert.equal(result.childCalls,0,'Output preflight must happen before any child operation');
  });
}

for(const [command,dir,first,last] of [['collect-metrics','metrics','baseline.json','README.md'],['build-visual-inspector','inspector','data.json','index.html']]) {
  for(const kind of ['symlink','hardlink','directory'])test(command+' preflights every output before replacing the first ('+kind+')',t=>{
    const f=fixture(t),target=path.join(f.state,dir,last),firstPath=path.join(f.state,dir,first),sentinel=path.join(f.outside,'sentinel');
    put(firstPath,'ORIGINAL FIRST\n');put(sentinel,'OUTSIDE SENTINEL\n');
    if(kind==='symlink'){if(!symlink(t,sentinel,target,'file'))return;}
    else if(kind==='hardlink')fs.linkSync(sentinel,target);else fs.mkdirSync(target);
    const result=run(f,command);refused(result);
    assert.equal(fs.readFileSync(firstPath,'utf8'),'ORIGINAL FIRST\n','A known invalid later output must not leave a partially updated set');
    assert.equal(fs.readFileSync(sentinel,'utf8'),'OUTSIDE SENTINEL\n');
  });
}

test('evaluation refuses a hardlinked report before invoking children',t=>{
  const f=fixture(t),sentinel=path.join(f.outside,'sentinel'),target=path.join(f.state,'evaluation/results/latest.json');
  put(sentinel,'ORIGINAL\n');fs.mkdirSync(path.dirname(target),{recursive:true});fs.linkSync(sentinel,target);
  const result=run(f,'evaluation-harness');refused(result);assert.equal(result.childCalls,0);assert.equal(fs.readFileSync(sentinel,'utf8'),'ORIGINAL\n');
});

test('PR summary in a separate state root reports its actual output',t=>{
  const f=fixture(t),r=run(f,'generate-pr-summary');assert.equal(r.error,null,JSON.stringify(r));
  const actual=path.join(f.state,'maintenance/pr_summary.md');assert.ok(fs.statSync(actual).isFile());
  assert.equal(path.resolve(f.project,r.result.written),actual);
});
test('Inspector in a separate state root reports both actual outputs',t=>{
  const f=fixture(t),r=run(f,'build-visual-inspector');assert.equal(r.error,null,JSON.stringify(r));
  assert.equal(path.resolve(f.project,r.result.output),path.join(f.state,'inspector/index.html'));
  assert.equal(path.resolve(f.project,r.result.data),path.join(f.state,'inspector/data.json'));
  for(const file of ['index.html','data.json','status.json'])assert.ok(fs.statSync(path.join(f.state,'inspector',file)).isFile());
});

function team(f,repo='repo-a',workspace='ws') {
  const root=path.join(f.root,'team'),state=path.join(root,'repos',repo,'workspaces',workspace,'state');
  fs.mkdirSync(state,{recursive:true});
  const record={workspaceId:workspace,repoId:repo,agentId:'test-agent',targetRoot:f.project,projectKnowledgeRoot:path.join(f.project,'.knowledge'),stateRoot:state};
  const file=path.join(path.dirname(state),'workspace.json');put(file,JSON.stringify(record));
  return {root,state,file,record,args:['--team-root',root,'--workspace-id',workspace,'--repo-id',repo]};
}
for(const kind of ['outside','sibling'])test('Team refuses unattested '+kind+' workspace state redirection',t=>{
  const f=fixture(t),a=team(f),other=kind==='outside'?f.outside:team(f,'repo-b','other').state;
  put(a.file,JSON.stringify({...a.record,stateRoot:other}));
  const r=run(f,'team-pr-summary',a.args);refused(r);
  assert.equal(fs.existsSync(path.join(other,'maintenance/team_pr_summary.md')),false);
});
test('Team uses the requested repo when two repositories share a workspace ID',t=>{
  const f=fixture(t),a=team(f),b=team(f,'repo-b');
  const r=run(f,'team-pr-summary',b.args);assert.equal(r.error,null,JSON.stringify(r));
  assert.equal(r.result.workspace.repoId,'repo-b');assert.equal(r.result.pr_summary,path.join(b.state,'maintenance/team_pr_summary.md'));
  assert.equal(fs.existsSync(path.join(a.state,'maintenance/team_pr_summary.md')),false);
});
test('Team refuses a symlink inside its canonical workspace state',t=>{
  const f=fixture(t),a=team(f);if(!symlink(t,f.outside,path.join(a.state,'maintenance'),'junction'))return;
  const r=run(f,'team-pr-summary',a.args);refused(r);assert.deepEqual(fs.readdirSync(f.outside),[]);
});
test('Team accepts a custom state root bound to an actual v2 flow start',t=>{
  const f=fixture(t),a=team(f),selected=path.join(a.root,'run-state','custom');fs.mkdirSync(selected,{recursive:true});
  const store=require(path.join(source,'tools/lib/team-store'));
  const context={mode:'team',teamRoot:a.root,repoId:'repo-a',workspaceId:'ws',agentId:'test-agent',stateRoot:selected,targetRoot:f.project,projectKnowledgeRoot:path.join(f.project,'.knowledge')};
  const start=store.beginTeamFlow(context,'audit-custom-state');assert.match(start.run_id,/^TFR-/);
  const r=run(f,'team-pr-summary',a.args);assert.equal(r.error,null,JSON.stringify(r));
  assert.equal(r.result.pr_summary,path.join(selected,'maintenance/team_pr_summary.md'));
  assert.equal(r.result.workspace.binding_version,'run_bound_v2');
});
