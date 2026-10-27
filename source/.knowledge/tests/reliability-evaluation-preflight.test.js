'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('fs'),os=require('os'),path=require('path');
const evaluation=require('../tools/evaluation-harness');
const {contextEnv,resolveKnowledgeContext}=require('../tools/lib/path-context');
for(const kind of ['directory_symlink','hardlinked_file'])test(`public evaluation rejects ${kind} before repository commands and confirms outer drain`,{skip:!['linux','win32'].includes(process.platform)},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'evaluation-preflight-')),system=path.join(root,'.knowledge'),state=path.join(root,'state'),outside=path.join(root,'outside'),marker=path.join(root,'repository-command-ran');
 fs.mkdirSync(path.join(system,'tools'),{recursive:true});fs.mkdirSync(state);fs.mkdirSync(outside);
 fs.writeFileSync(path.join(system,'config.yaml'),'updates:\n  enabled: false\n');fs.writeFileSync(path.join(system,'package.json'),'{"version":"3.4.4"}');
 for(const name of ['sync-tracked.js','build-wiki-graph.js','lint-wiki.js','external-memory-status.js','build-routing-bundle.js','build-search-index.js','scan-secrets.js','doctor.js','build-visual-inspector.js','collect-metrics.js','generate-pr-summary.js'])
  fs.writeFileSync(path.join(system,'tools',name),`require('fs').writeFileSync(${JSON.stringify(marker)},'ran');console.log('{"status":"ok"}');`);
 const target=path.join(state,'evaluation/results');fs.mkdirSync(path.dirname(target),{recursive:true});
 const sentinel=path.join(outside,'sentinel');fs.writeFileSync(sentinel,'ORIGINAL');
 if(kind==='directory_symlink')fs.symlinkSync(outside,target,'junction');else{fs.mkdirSync(target);fs.linkSync(sentinel,path.join(target,'latest.json'));}
 const context=resolveKnowledgeContext({__skipCli:true,systemRoot:system,targetRoot:root,projectKnowledgeRoot:system,stateRoot:state});let cleanable=false;
 try{
  await assert.rejects(evaluation.mainAsync({env:contextEnv(context),budgets:{setupMs:20000,workMs:20000,cleanupMs:20000,progressMs:0}}),error=>{
   assert.equal(error.cleanup?.status,'completed',JSON.stringify(error));cleanable=true;return true;
  });
  assert.equal(fs.existsSync(marker),false);assert.equal(fs.readFileSync(sentinel,'utf8'),'ORIGINAL');
 }finally{if(cleanable)fs.rmSync(root,{recursive:true,force:true});else t.diagnostic('Fixture retained without native cleanup proof');}
});
