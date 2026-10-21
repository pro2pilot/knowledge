'use strict';
// Independent request-boundary tests. CLI tests execute the real entrypoint,
// replacing only its final native runner with an inert capture sentinel.
// They prove propagation/refusal and hash binding, never native execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const SOURCE = path.resolve(__dirname, '..');
const WORK = require('node:os').tmpdir();
fs.mkdirSync(WORK,{recursive:true});
const root = fs.mkdtempSync(path.join(WORK,'request-boundary-'));
test.after(() => fs.rmSync(root, { recursive: true, force: true }));
const state = path.join(root,'.knowledge');
fs.mkdirSync(state);
fs.mkdirSync(path.join(root,'tests'));
fs.writeFileSync(path.join(root,'tests','unit.js'),'process.exit(0);\n');
const context = {mode:'repo',systemRoot:SOURCE,targetRoot:root,projectKnowledgeRoot:state,stateRoot:state,
 teamRoot:null,repoId:'critic-native-request',workspaceId:null,agentId:'critic',git:{is_git_repo:false},warnings:[]};
const workflow = require(path.join(SOURCE,'tools/lib/agent-task-workflow'));
const config = socket => ({darwin:{enabled:true,mode:'isolated_copy',broker_path:'/usr/local/libexec/knowledge-broker',broker_socket:socket,copy:{}}});
const A=config('/var/run/knowledge-a.sock'),B=config('/var/run/knowledge-b.sock');
const request = extra => ({source_files:['tests/unit.js'],changed_files:['tests/unit.js'],
 tests_to_run:[{argv:['node','tests/unit.js'],cwd:'.',timeout_ms:120000}],...extra});
const normalize=x=>workflow.__test.normalizedFinishRequest(context,x);
const native=x=>x.native_execution??x.nativeExecution;
const preloader=path.join(root,'capture-runner.cjs');
fs.writeFileSync(preloader,`'use strict';\nconst fs=require('node:fs'),path=require('node:path');\nconst p=require(path.join(process.env.CRITIC_PRODUCT_ROOT,'tools/lib/repair-on-touch'));\np.runVerificationTests=options=>{fs.writeFileSync(process.env.CRITIC_CAPTURE,JSON.stringify(options));throw Object.assign(new Error('INERT_CAPTURE_ONLY'),{code:'critic_capture_only'});};\n`);
let id=0;
function cli(extra){
 const n=++id,requestFile=path.join(root,'request-'+n+'.json'),capture=path.join(root,'capture-'+n+'.json');
 fs.writeFileSync(requestFile,JSON.stringify({task_id:'critic-task',session_id:'critic-session',...request(extra)}));
 const env={...process.env,KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1',KNOWLEDGE_SYSTEM_ROOT:SOURCE,
 KNOWLEDGE_TARGET_ROOT:root,KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT:state,KNOWLEDGE_STATE_ROOT:state,
 CRITIC_CAPTURE:capture,CRITIC_PRODUCT_ROOT:SOURCE};
 delete env.NODE_OPTIONS;delete env.NODE_PATH;
 const result=cp.spawnSync(process.execPath,['--require',preloader,path.join(SOURCE,'tools/repair-on-touch.js'),
 'verify','--request',requestFile],{env,cwd:root,encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
 fs.writeFileSync(path.join(root,'cli-'+n+'.json'),JSON.stringify({status:result.status,signal:result.signal,error:result.error?.code??null,stdout:result.stdout,stderr:result.stderr},null,2));
 assert.equal(result.error,undefined);
 assert.notEqual(result.status,0,'capture/refusal must never appear as verification success');
 return {captured:fs.existsSync(capture)?JSON.parse(fs.readFileSync(capture,'utf8')):null,result};
}
test('workflow finish preserves explicit native_execution request',()=>{
 const n=normalize(request({native_execution:A}));
 assert.equal(native(n)?.darwin?.enabled,true,'Darwin opt-in was silently lost');
 assert.equal(native(n).darwin.broker_socket,A.darwin.broker_socket);
});
test('changing requested Darwin boundary changes the persisted finish replay hash',()=>{
 const a=normalize(request({native_execution:A})),b=normalize(request({native_execution:B}));
 assert.notEqual(workflow.__test.digest(a),workflow.__test.digest(b),'changed execution policy must not replay prior native acceptance');
});
test('workflow refuses disagreeing snake/camel native execution policies',()=>{
 assert.throws(()=>normalize(request({native_execution:A,nativeExecution:B})),e=>typeof e.code==='string');
});
test('real CLI verify carries native_execution into the native runner',()=>{
 const {captured}=cli({native_execution:A});assert.ok(captured,'valid explicit configuration should reach request boundary');
 assert.equal(native(captured)?.darwin?.enabled,true,'CLI dropped Darwin request and would fall back to host backend');
 assert.equal(native(captured).darwin.broker_socket,A.darwin.broker_socket);
});
test('real CLI refuses conflicting native execution aliases before runner invocation',()=>{
 const {captured}=cli({native_execution:A,nativeExecution:B});assert.equal(captured,null);
});
test('real CLI refuses malformed requested Darwin policy before runner invocation',()=>{
 const {captured}=cli({native_execution:{darwin:{enabled:true,mode:'inplace'}}});assert.equal(captured,null);
});


test('inert alias normalization preserves legacy absence and refuses accessors/proxies', () => {
  const policy = require(path.join(SOURCE, 'tools/lib/verification-policy'));
  assert.equal(policy.nativeExecutionRequest({}), undefined);
  assert.deepEqual(policy.nativeExecutionRequest({nativeExecution: {}}), {darwin: {enabled: false}});
  assert.deepEqual(policy.nativeExecutionRequest({native_execution: A}), policy.nativeExecutionRequest({nativeExecution: A}));
  let invoked = 0;
  assert.throws(() => policy.nativeExecutionRequest({get native_execution() { invoked++; return A; }}),
    {code: 'verification_darwin_config_invalid'});
  assert.throws(() => policy.nativeExecutionRequest(new Proxy({}, {})), {code: 'verification_darwin_config_invalid'});
  assert.throws(() => policy.nativeExecutionRequest({native_execution: undefined}), {code: 'verification_darwin_config_invalid'});
  assert.throws(() => policy.nativeExecutionRequest({native_execution: A, nativeExecution: A}), {code: 'verification_native_execution_conflict'});
  assert.equal(invoked, 0);
});

test('requested Darwin execution cannot fall back to the host backend or create a claim', () => {
  const repair = require(path.join(SOURCE, 'tools/lib/repair-on-touch'));
  const target = fs.mkdtempSync(path.join(root, 'no-fallback-'));
  const stateRoot = path.join(target, 'state');
  fs.writeFileSync(path.join(target, 'unit.js'), "require('node:fs').writeFileSync('COMMAND_RAN', 'bad');\n");
  const base = {repoRoot: target, stateRoot, taskId: 'native-request', sessionId: 'native-request',
    tests: [{argv: ['node', 'unit.js'], cwd: '.', timeout_ms: 120000}], sourceFiles: ['unit.js']};
  for (const native of [{nativeExecution: A}, {native_execution: A}]) {
    assert.throws(() => repair.runVerificationTests({...base, ...native}), error => {
      assert.equal(error.code, 'verification_containment_unavailable');
      assert.equal(error.containment.backend, 'darwin_private_ruid');
      assert.equal(error.containment.status, 'unavailable');
      assert.equal(error.execution.status, 'not_started');
      return true;
    });
  }
  assert.equal(fs.existsSync(path.join(target, 'COMMAND_RAN')), false);
  assert.equal(fs.existsSync(stateRoot), false);
});

test('disabled native configuration keeps the existing host capability and request shape', () => {
  const boundary = require(path.join(SOURCE, 'tools/lib/verification-supervisor'));
  assert.deepEqual(boundary.containmentCapability({darwin: {enabled: false}}), boundary.containmentCapability());
  const legacy = normalize(request({}));
  assert.equal(Object.hasOwn(legacy, 'native_execution'), false);
  const explicit = normalize(request({nativeExecution: {darwin: {enabled: false}}}));
  assert.deepEqual(explicit.native_execution, {darwin: {enabled: false}});
  assert.equal(Object.hasOwn(explicit, 'nativeExecution'), false);
});

test('copy limits reject prototype names and remain the same in client and planner', () => {
  const client = require(path.join(SOURCE, 'tools/lib/verification-darwin-client'));
  const copy = require(path.join(SOURCE, 'tools/lib/verification-isolated-copy'));
  assert.throws(() => copy.limits({constructor: 1}), {code: 'verification_copy_limits_invalid'});
  assert.deepEqual(client.config(A).darwin.copy, copy.limits());
  assert.throws(() => client.config({darwin: {...A.darwin, copy: {constructor: 1}}}),
    {code: 'verification_darwin_config_invalid'});
});
