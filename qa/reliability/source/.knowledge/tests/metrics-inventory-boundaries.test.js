'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const systemRoot=path.resolve(__dirname,'..'),tool=path.join(systemRoot,'tools/collect-metrics.js');
function write(file,body){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,body);}
function runFixture(fn){const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-metrics-inventory-'));const env={...process.env},log=console.log;try{
 for(const key of Object.keys(process.env))if(key.startsWith('KNOWLEDGE_'))delete process.env[key];
 Object.assign(process.env,{KNOWLEDGE_MODE:'repo',KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1',KNOWLEDGE_SYSTEM_ROOT:systemRoot,KNOWLEDGE_TARGET_ROOT:root});console.log=()=>{};
 const collect=(curated,state)=>{Object.assign(process.env,{KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT:curated,KNOWLEDGE_STATE_ROOT:state});delete require.cache[require.resolve(tool)];return require(tool)();};
 return fn({root,collect});
 }finally{console.log=log;for(const key of Object.keys(process.env))if(!(key in env))delete process.env[key];Object.assign(process.env,env);fs.rmSync(root,{recursive:true,force:true});}}
test('metrics count contained regular aliases once and diagnose directory, dangling and outside aliases',()=>runFixture(({root,collect})=>{
 const curated=path.join(root,'.knowledge');write(path.join(curated,'config.yaml'),'version: 3.4.4\n');write(path.join(curated,'project_index.json'),'{}\n');write(path.join(curated,'docs/one.md'),'# Actual document\n');const outside=path.join(root,'private.md');write(outside,'PRIVATE_SENTINEL\n');
 fs.symlinkSync(path.join(curated,'docs/one.md'),path.join(curated,'same-file-alias.md'),'file');fs.symlinkSync(path.join(curated,'docs'),path.join(curated,'directory-alias'),process.platform==='win32'?'junction':'dir');fs.symlinkSync(path.join(curated,'absent.md'),path.join(curated,'missing-alias.md'),'file');fs.symlinkSync(outside,path.join(curated,'outside-alias.md'),'file');
 const report=collect(curated,curated);assert.equal(report.files.curated_total,3);assert.equal(report.files.runtime_total,0);assert.equal(report.files.unique_total,3);assert.equal(report.files.json,1);assert.equal(report.files.markdown,1);assert.equal(report.files.regular_aliases.curated,1);assert.equal(report.files.inventory_complete,false);
 const exclusions=report.files.inventory_exclusions.filter(r=>r.root_role==='curated');assert.equal(exclusions.length,3);for(const reason of ['nonregular_alias_not_counted','entry_unavailable','alias_outside_inventory_root'])assert(exclusions.some(r=>r.reason===reason));assert(!JSON.stringify(report).includes('PRIVATE_SENTINEL'));assert.equal(report.routing.claim_eligible,false);assert.equal(report.routing.estimated_tokens_saved,0);
 const persisted=JSON.parse(fs.readFileSync(path.join(curated,'metrics/baseline.json')));assert.deepEqual(persisted.files,report.files);assert(fs.readFileSync(path.join(curated,'metrics/README.md'),'utf8').includes('Inventory complete: false'));
}));
test('aliases crossing selected role roots are excluded in the referring root while real files remain counted',()=>runFixture(({root,collect})=>{
 const curated=path.join(root,'curated'),state=path.join(root,'state');write(path.join(curated,'config.yaml'),'version: 3.4.4\n');write(path.join(curated,'real.json'),'{}\n');write(path.join(state,'runtime.md'),'# Runtime\n');fs.symlinkSync(path.join(state,'runtime.md'),path.join(curated,'runtime-alias.md'),'file');fs.symlinkSync(path.join(curated,'real.json'),path.join(state,'curated-alias.json'),'file');
 const r=collect(curated,state);assert.equal(r.files.curated_total,2);assert.equal(r.files.runtime_total,1);assert.equal(r.files.unique_total,3);assert.equal(r.files.json,1);assert.equal(r.files.markdown,1);assert.equal(r.files.roots_overlap,false);assert.equal(r.files.regular_aliases.curated,0);assert.equal(r.files.regular_aliases.runtime,0);assert.equal(r.files.inventory_exclusions.filter(x=>x.reason==='alias_outside_inventory_root').length,2);
}));
test('ordinary complete file inventory retains complete diagnostic state and no measured savings claim',()=>runFixture(({root,collect})=>{
 const curated=path.join(root,'curated'),state=path.join(root,'state');write(path.join(curated,'config.yaml'),'version: 3.4.4\n');write(path.join(curated,'real.json'),'{}\n');const r=collect(curated,state);assert.equal(r.files.unique_total,2);assert.equal(r.files.inventory_complete,true);assert.deepEqual(r.files.inventory_exclusions,[]);assert.equal(r.routing.actual_model_usage.available,false);assert.equal(r.routing.claim_eligible,false);
}));
