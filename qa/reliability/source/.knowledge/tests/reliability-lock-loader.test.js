'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {spawnSync}=require('node:child_process');
const source=path.resolve(__dirname,'..');
const nativeDir=`tools/lib/native/${process.platform}-${process.arch}`;
function fixture(t){
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-lock-loader-'))),runtime=path.join(root,'runtime'),state=path.join(root,'state');
  const files=['tools/lib/contained-lock-manager.js','tools/lib/lock-owner-schema.js','tools/lib/lock-policy.js','tools/lib/lock-publication.js','tools/lib/json-store.js','tools/lib/strict-temp-cleanup.js','tools/native/lock-publication.c',`${nativeDir}/lock-publication.node`,`${nativeDir}/lock-publication.manifest.json`];
  for(const relative of files){const dest=path.join(runtime,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(source,relative),dest);}
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  return {root,runtime,state,binary:path.join(runtime,nativeDir,'lock-publication.node'),manifest:path.join(runtime,nativeDir,'lock-publication.manifest.json')};
}
function attempt(f){
  const code=String.raw`const path=require('path'),fs=require('fs');const [runtime,state]=process.argv.slice(1);const m=require(path.join(runtime,'tools/lib/contained-lock-manager')),p=require(path.join(runtime,'tools/lib/lock-policy'));try{const h=m.acquireContainedLock({rootKind:'state',rootPath:state,context:{stateRoot:state},lockName:'team-flow',purpose:p.LOCKS['team-flow'].purpose});h.release();console.log(JSON.stringify({acquired:true}));}catch(e){console.log(JSON.stringify({acquired:false,code:e.code,reason:e.reason,public_exists:fs.existsSync(path.join(state,'locks/v1/team-flow.lock')),layout_exists:fs.existsSync(path.join(state,'locks'))}));}`;
  const child=spawnSync(process.execPath,['-e',code,f.runtime,f.state],{env:{...process.env,PATH:path.join(f.root,'no-executables'),NODE_OPTIONS:'',NODE_PATH:''},encoding:'utf8',timeout:20000});
  assert.ifError(child.error);assert.equal(child.status,0,child.stderr);return JSON.parse(child.stdout);
}
test('a physically copied pinned runtime can acquire and release without a compiler or PATH helper',t=>{
  const f=fixture(t);assert.deepEqual(attempt(f),{acquired:true});
});
for(const mode of ['missing-binary','changed-binary','changed-source','wrong-platform','unknown-manifest-field','hardlinked-binary'])test(`loader rejects ${mode} before any public lock layout`,t=>{
  const f=fixture(t);
  if(mode==='missing-binary')fs.unlinkSync(f.binary);
  else if(mode==='changed-binary')fs.appendFileSync(f.binary,'changed');
  else if(mode==='changed-source')fs.appendFileSync(path.join(f.runtime,'tools/native/lock-publication.c'),'\n/* changed */\n');
  else if(mode==='hardlinked-binary')fs.linkSync(f.binary,path.join(f.root,'alias.node'));
  else{const m=JSON.parse(fs.readFileSync(f.manifest));if(mode==='wrong-platform')m.platform='unsupported';else m.extra='unrecognized';fs.writeFileSync(f.manifest,JSON.stringify(m));}
  const result=attempt(f);assert.equal(result.acquired,false);assert.equal(result.code,'lock_native_publication_unavailable');
  assert.equal(result.public_exists,false);assert.equal(result.layout_exists,false);
});
