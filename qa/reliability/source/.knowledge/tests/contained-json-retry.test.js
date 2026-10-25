'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const store=require('../tools/lib/json-store');
function write(file,body){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,body);}
function busy(){const e=new Error('controlled first rename busy');e.code='EBUSY';return e;}
function fixture(fn){const root=fs.mkdtempSync(path.join(os.tmpdir(),'k-json-retry-'));try{return fn(root);}finally{fs.rmSync(root,{recursive:true,force:true});}}
function invoke(kind,target,root,options){return kind==='JSON'?store.writeJsonAtomicContained(target,{new:true},root,options):store.appendNdjsonContained(target,{event:'new'},root,options);}
for(const kind of ['JSON','NDJSON']){
 test(`${kind}: root dotfiles and literal double-dot child names remain contained`,()=>fixture(root=>{
  const names=['.events.json','..literal.json','..literal-dir/events.json'];
  for(const relative of names){
   const target=path.join(root,relative);write(target,'{"old":true}\n');invoke(kind,target,root,{});
   const body=fs.readFileSync(target,'utf8');
   if(kind==='JSON')assert.deepEqual(JSON.parse(body),{new:true});
   else assert.deepEqual(body.trim().split('\n').map(JSON.parse),[{old:true},{event:'new'}]);
  }
 }));
 test(`${kind}: bounded unchanged-namespace rename retry publishes one complete document`,()=>fixture(root=>{
  const owned=path.join(root,'owned'),target=path.join(owned,'parent/report.json');write(target,'{"old":true}\n');let count=0;
  invoke(kind,target,owned,{hooks:{retryDelaysMs:[0],sleepSync:()=>{},renameSync(from,to){if(++count===1)throw busy();return fs.renameSync(from,to);}}});
  assert.equal(count,2);const body=fs.readFileSync(target,'utf8');if(kind==='JSON')assert.deepEqual(JSON.parse(body),{new:true});else assert.deepEqual(body.trim().split('\n').map(JSON.parse),[{old:true},{event:'new'}]);assert.deepEqual(fs.readdirSync(path.dirname(target)),['report.json']);
 }));
 for(const mutation of ['symlink-parent','successor-parent-with-original-temp','replacement-temp','hardlinked-temp','successor-root']){
  test(`${kind}: ${mutation} during retry preserves successor target and temporary entry`,()=>fixture(root=>{
   const owned=path.join(root,'owned'),parent=path.join(owned,'parent'),target=path.join(parent,'report.json');write(target,'{"old":true}\n');let count=0,observed=[];
   const remember=file=>{observed.push([file,fs.readFileSync(file)]);};
   const hooks={retryDelaysMs:[0],sleepSync:()=>{},renameSync(from,to){
    ++count;assert.equal(count,1,'A replaced namespace/temp must be refused before second OS rename');
    if(mutation==='symlink-parent'){
     const outside=path.join(root,'outside');fs.mkdirSync(outside);fs.renameSync(parent,path.join(owned,'retired'));fs.symlinkSync(outside,parent,process.platform==='win32'?'junction':'dir');write(to,'FOREIGN_TARGET\n');write(from,'FOREIGN_TEMP\n');remember(to);remember(from);
    }else if(mutation==='successor-parent-with-original-temp'){
     const retired=path.join(owned,'retired');fs.renameSync(parent,retired);fs.mkdirSync(parent);fs.renameSync(path.join(retired,path.basename(from)),from);write(to,'FOREIGN_TARGET\n');remember(to);remember(from);
    }else if(mutation==='replacement-temp'){
     fs.renameSync(from,from+'.original');write(from,'FOREIGN_TEMP\n');remember(to);remember(from);
    }else if(mutation==='hardlinked-temp'){
     fs.linkSync(from,from+'.alias');remember(to);remember(from);
    }else{
     const retired=path.join(root,'retired-root');fs.renameSync(owned,retired);fs.mkdirSync(owned);fs.renameSync(path.join(retired,'parent'),parent);remember(to);remember(from);
    }
    throw busy();
   }};
   let error;try{invoke(kind,target,owned,{hooks});}catch(e){error=e;}
   assert.equal(error?.code,'contained_path_unsafe');assert.equal(count,1);assert.equal(error.temp_cleanup_status,'failed');assert.equal(error.temp_cleanup_error_code,'contained_path_unsafe');
   for(const[file,bytes]of observed)assert.deepEqual(fs.readFileSync(file),bytes,`Successor entry changed: ${file}`);
  }));
 }
 test(`${kind}: terminal rename refusal removes only its owned temporary file`,()=>fixture(root=>{
  const owned=path.join(root,'owned'),target=path.join(owned,'report.json');write(target,'{"old":true}\n');const before=fs.readFileSync(target);let error;
  try{invoke(kind,target,owned,{hooks:{renameSync(){const e=new Error('terminal refusal');e.code='EIO';throw e;}}});}catch(e){error=e;}
  assert.equal(error?.code,'EIO');assert.equal(error.temp_cleanup_status,'removed');assert.deepEqual(fs.readFileSync(target),before);assert.deepEqual(fs.readdirSync(owned),['report.json']);
 }));
}
test('text dotfile retry publishes .gitattributes through its actual double-dot temporary name',()=>fixture(root=>{
 const target=path.join(root,'.gitattributes');write(target,'USER RULE\n');let attempts=0;
 store.writeFileAtomicContained(target,'USER RULE\nAGENTS.md text eol=lf\n',root,{hooks:{retryDelaysMs:[0],sleepSync:()=>{},renameSync(from,to){
  assert.equal(path.dirname(from),root);assert(path.basename(from).startsWith('..gitattributes.tmp-'));
  if(++attempts===1)throw busy();return fs.renameSync(from,to);
 }}});
 assert.equal(attempts,2);assert.equal(fs.readFileSync(target,'utf8'),'USER RULE\nAGENTS.md text eol=lf\n');assert.deepEqual(fs.readdirSync(root),['.gitattributes']);
}));
test('true parent and sibling-prefix escapes are refused before temporary creation',()=>fixture(root=>{
 const owned=path.join(root,'owned');fs.mkdirSync(owned);
 const targets=[path.join(root,'parent-sentinel.txt'),path.join(root,'owned-sibling','sentinel.txt'),path.join(owned,'..','other-sibling','sentinel.txt')];
 for(const target of targets){
  write(target,'UNCHANGED\n');assert.throws(()=>store.writeFileAtomicContained(target,'BAD\n',owned),{code:'contained_path_unsafe'});
  assert.equal(fs.readFileSync(target,'utf8'),'UNCHANGED\n');assert.deepEqual(fs.readdirSync(owned),[]);
 }
 assert.throws(()=>store.writeFileAtomicContained(root,'BAD\n',owned),{code:'contained_path_unsafe'});
}));
