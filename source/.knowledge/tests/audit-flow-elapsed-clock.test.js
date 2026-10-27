'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {test}=require('node:test');
const source=path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE || path.join(__dirname,'..'));
const flow=require(path.join(source,'tools/flow'));
const evaluation=require(path.join(source,'tools/evaluation-harness'));
const {captureTempDirIdentity,removeTempDirStrict}=require(path.join(source,'tools/lib/strict-temp-cleanup'));
const success=()=>({status:0,signal:null,stdout:'{"status":"ok"}',stderr:''});
function context(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-clock-audit-')),identity=captureTempDirIdentity(root);
  t.after(()=>removeTempDirStrict(root,{expectedIdentity:identity}));
  return {mode:'repo',systemRoot:source,targetRoot:root,projectKnowledgeRoot:root,stateRoot:root,warnings:[]};
}
function skew(delta,fn){const original=Date.now;let clock=1700000000000;Date.now=()=>clock;try{return fn(()=>{clock+=delta});}finally{Date.now=original;}}
function measured(value){assert.ok(Number.isFinite(value)&&value>=0,'Wall clock rollback cannot make elapsed time negative');
  assert.ok(value<3600000,'A synthetic one-day wall clock jump cannot become elapsed execution time');}
for(const [name,delta] of [['rollback',-86400000],['forward',86400000]]){
  test('Flow child elapsed time survives a wall clock '+name,t=>{
    const ctx=context(t),r=skew(delta,change=>flow.runOne('doctor.js',ctx,{spawnSync(){change();return success();}}));
    assert.equal(r.success,true);measured(r.duration_ms);t.diagnostic(JSON.stringify({scope:'child dispatch simulated',duration_ms:r.duration_ms,wall_delta_ms:delta}));
  });
  test('Evaluation child elapsed time survives a wall clock '+name,t=>{
    const r=skew(delta,change=>evaluation.runCheck({name:'probe',command:'tools/doctor.js'},{spawnSync(){change();return success();}}));
    assert.equal(r.status,'pass');measured(r.duration_ms);t.diagnostic(JSON.stringify({scope:'child dispatch simulated',duration_ms:r.duration_ms,wall_delta_ms:delta}));
  });
  test('Whole Flow elapsed time survives a wall clock '+name,t=>{
    const ctx=context(t),r=skew(delta,change=>flow.runFlow({name:'scan',context:ctx,quiet:true,json:true,noColor:true},{stepsForFlow:()=>['probe.js'],
      runOne(){change();return {step:'probe',command:'probe.js',exit:0,success:true,status:'pass',json_status:'ok',semantic_errors:[],duration_ms:0,parsed:{status:'ok'}};},
      writeFlowLog:()=>({path:'maintenance/flow-logs/probe.json',bytes:1,sha256:'a'.repeat(64)})}));
    assert.equal(r.overall_status,'ok');measured(r.duration_total_ms);assert.ok(Number.isFinite(Date.parse(r.started_at)));
    t.diagnostic(JSON.stringify({scope:'step and log writer simulated; elapsed computation actual',duration_ms:r.duration_total_ms,wall_delta_ms:delta}));
  });
}
