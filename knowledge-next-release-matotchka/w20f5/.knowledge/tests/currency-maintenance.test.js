'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {fixture,hash}=require('./helpers/currency-overlay');
const workflow=require('../tools/lib/agent-task-workflow');
const native=require('../tools/lib/repair-on-touch');
const batch=require('../tools/lib/knowledge-currency-batch');
const helper=workflow.__test;
function task(f) { return {route_modules:{direct:[f.first.id],selected:[f.first.id]},route:{scope:{paths:[f.first.source]}}}; }
const request=f=>({changed_files:[f.first.source]});

test('successful primary work does not silently renew facts; RU maintenance notice and explicit deferral preserve risks',t=>{
  const f=fixture(t,'maintenance'); const before=f.ledgers();
  const snapshot=helper.inspectKnowledgeMaintenance(f.context,task(f),request(f));
  assert.equal(snapshot.blocking_issues.length,0,JSON.stringify(snapshot));
  assert.deepEqual(snapshot.deferrable_lifecycle_ids,[f.first.row.lifecycle_id]);
  assert.deepEqual(snapshot.protected_risk_lifecycle_ids,[f.first.risk.lifecycle_id]);
  const report=helper.knowledgeMaintenanceReport(snapshot,snapshot,request(f),{status:'not_requested'},'ru');
  assert.equal(report.status,'action_required'); assert.match(report.chat_notice,/Успешные тесты сами по себе не обновляют/);
  const defer={...request(f),currency_defer:{lifecycle_ids:[f.first.row.lifecycle_id],reason:'Нужен отдельный независимый review утверждения.'}};
  helper.validateCurrencyDeferral(defer,snapshot);
  const deferred=helper.knowledgeMaintenanceReport(snapshot,snapshot,defer,{status:'not_requested'},'ru');
  assert.equal(deferred.status,'deferred'); assert.equal(deferred.deferral_grants_closure,false);
  assert.equal(deferred.deferral_grants_trust,false);
  assert.throws(()=>helper.validateCurrencyDeferral({...request(f),currency_defer:{lifecycle_ids:[f.first.risk.lifecycle_id],reason:'Synthetic'}},snapshot),{code:'agent_task_currency_defer_protected'});
  assert.deepEqual(f.ledgers(),before);
});

test('renewal and stale scope report remain separate from operational readiness and raw lifecycle state',t=>{
  const f=fixture(t,'renewal'), before=f.ledgers();
  const stale=helper.inspectKnowledgeMaintenance(f.context,task(f),request(f));
  const result=f.issue(f.verify());
  const current=helper.inspectKnowledgeMaintenance(f.context,task(f),request(f));
  const report=helper.knowledgeMaintenanceReport(stale,current,request(f),result,'ru');
  assert.equal(report.status,'renewed'); assert.equal(report.maintenance_succeeded,true);
  assert.equal(current.protected_risk_lifecycle_ids.length,1);
  f.write(f.first.source,'module.exports = 8;\n');
  const changed=helper.inspectKnowledgeMaintenance(f.context,task(f),request(f));
  assert.equal(changed.stale_units.length,1); assert.equal(changed.blocking_issues.length,0);
  assert.deepEqual(f.ledgers(),before);
});

test('finish rejects caller accessors, hidden policy and revoked proxy before recording or workflow creation',t=>{
  const f=fixture(t,'finish-admission'); let calls=0;
  const revoked=Proxy.revocable({},{});revoked.revoke();
  const values=[Object.defineProperty({},'language',{enumerable:true,get(){calls++;return 'ru';}}),
    Object.create({currency_updates:'fake.json'}),Object.defineProperty({},'repair_mode',{value:'report_only'}),revoked.proxy];
  for(const value of values)assert.throws(()=>workflow.finish(f.context,'ATW-'+'1'.repeat(64),value),{code:'agent_task_finish_request_invalid'});
  assert.equal(calls,0); assert(!fs.existsSync(path.join(f.state,'sessions/task-workflows')));
});

test('finish binds the first-read acknowledgement and exact batch, physically verifies once, issues overlay and persists maintenance outcome',t=>{
  const f=fixture(t,'workflow');
  const taskHash='a'.repeat(64),snapshotHash='b'.repeat(64),firstRead='Synthetic routing fixture: read the factual source and its claims.\n';
  const route={task_scope_hash:taskHash,snapshot_hash:snapshotHash,routing_snapshot_hash:snapshotHash,
    scope:{task:'Review synthetic facts',modules:[f.first.id],paths:[f.first.source]},
    state:{current_status:'current',bundle:{selected_modules:[f.first.id]},metrics:{}},
    first_read:{path:'synthetic-first-read.md',sha256:hash(firstRead),bytes:Buffer.byteLength(firstRead),content:firstRead}};
  let verificationCalls=0;
  const deps={taskRoute:()=>route,doctor:()=>({quality_score:42,status:'usable_with_warnings'}),
    resolveEffectiveTaskRoutingState:()=>({current_status:'current',snapshot_hash:snapshotHash,metrics:{},effective_claim_eligible:false}),
    runTool:(context,tool,args)=>{
      const command={tool,duration_ms:1,exit_code:0};
      if(tool==='agent-session.js')return {record:command,output:{ok:true,session:{status:'done'}}};
      if(tool==='repair-on-touch.js'&&args[0]==='plan')return {record:command,output:{status:'planned',opportunities:[]}};
      if(tool==='repair-on-touch.js'&&args[0]==='status')return {record:command,output:{status:'ok',opportunities:[],verified_closures:[],task_readiness:{score:86}}};
      if(tool==='repair-on-touch.js'&&args[0]==='verify'){
        verificationCalls++;
        const input=JSON.parse(fs.readFileSync(args[args.indexOf('--request')+1],'utf8'));
        const verification=native.runVerificationTests({stateRoot:f.state,repoRoot:f.root,taskId:input.task_id,sessionId:input.session_id,
          tests:input.tests_to_run,sourceFiles:input.source_files.map(path=>({path})),checkedBy:'currency-workflow-fixture'});
        const executions=verification.map(entry=>entry.record);
        return {record:command,output:{status:executions.every(row=>row.status==='pass')?'pass':'fail',
          verification_acceptances:verification.verification_acceptances,executions}};
      }
      throw Error('Unexpected synthetic tool: '+tool+' '+args[0]);
    }};
  const started=workflow.begin(f.context,{task:'Review synthetic facts',modules:[f.first.id],paths:[f.first.source],language:'ru'},deps);
  f.first.request.task_id=taskHash;f.first.request.session_id=started.workflow_id;
  const prepared=f.prepareBatch();
  f.write('tests/primary.js',"require('assert').strictEqual(require('../"+f.first.source+"'),7);\n");
  const sources=[...new Set([f.batchPath,f.first.requestPath,'tests/primary.js',...prepared.pins.map(pin=>pin.path)])];
  const finishRequest={route_first_read_sha256:started.route.first_read.sha256,source_files:sources,changed_files:[f.first.source],
    tests_to_run:[{argv:['node','tests/primary.js'],cwd:'.',timeout_ms:10000}],run_release_flow:false,currency_updates:f.batchPath};
  const before=f.ledgers();
  const result=workflow.finish(f.context,started.workflow_id,finishRequest,deps);
  assert.equal(result.primary_verification.status,'pass');assert.equal(result.primary_verification.verification_acceptances.length,1);assert.equal(verificationCalls,1);
  assert.equal(result.knowledge_maintenance.status,'renewed');assert.equal(result.repair.kvr_id,null);
  assert.equal(result.repair.eligibility.reason,'factual_currency_only');
  assert.equal(result.route.first_read_acknowledgement.first_read_sha256,started.route.first_read.sha256);
  assert.deepEqual(f.ledgers(),before);assert.equal(f.evaluate().valid,true);
  const repeated=workflow.finish(f.context,started.workflow_id,finishRequest,deps);
  assert.equal(verificationCalls,1);assert.deepEqual(repeated,JSON.parse(JSON.stringify(result)));
  // Route/Doctor are explicit mocks; KVE execution, issuance, ACK and raw-byte checks are physical.
});
