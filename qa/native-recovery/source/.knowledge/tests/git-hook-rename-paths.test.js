'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {spawnSync}=require('node:child_process');
const source=path.resolve(__dirname,'..');
function write(file,body){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,body);}
function fixture(fn){const base=fs.mkdtempSync(path.join(os.tmpdir(),'k-hook-renames-'));const root=path.join(base,'project with spaces');fs.mkdirSync(root);const kit=path.join(root,'.knowledge');fs.mkdirSync(path.join(kit,'tools'),{recursive:true});fs.copyFileSync(path.join(source,'tools/run-git-hook-sync.js'),path.join(kit,'tools/run-git-hook-sync.js'));write(path.join(kit,'tools/sync-tracked.js'),'console.log(JSON.stringify({changed:JSON.parse(process.env.KNOWLEDGE_CHANGED_FILES),trigger:process.env.KNOWLEDGE_TRIGGER,cwd:process.cwd()}));\n');
 const env={...process.env,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:path.join(base,'absent-config'),GIT_TERMINAL_PROMPT:'0'};for(const k of Object.keys(env))if(/^GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|CONFIG_COUNT)$/.test(k))delete env[k];
 const run=(cmd,args,cwd=root)=>{const r=spawnSync(cmd,args,{cwd,env,encoding:'utf8',timeout:15000});assert(!r.error,r.error?.message);assert.equal(r.status,0,r.stderr);return r.stdout;};
 const git=(...args)=>run('git',['-c','user.name=Audit fixture','-c','user.email=fixture@example.invalid',...args]).trim();git('init','--quiet');write(path.join(root,'.gitignore'),'.knowledge/\n');git('add','.gitignore');git('commit','--quiet','-m','root');
 try{return fn({root,kit,run,git});}finally{fs.rmSync(base,{recursive:true,force:true});}}
for(const hook of ['post-commit','post-merge','post-checkout'])test(`${hook} forwards both rename paths and a deletion from a nested cwd`,()=>fixture(({root,kit,run,git})=>{
 const suffix=process.platform==='win32'?'space ю.js':'space\tline\nю.js';const old='src/old '+suffix,next='src/new '+suffix,deleted='src/deleted '+suffix;
 write(path.join(root,old),'unchanged body\n'.repeat(30));write(path.join(root,deleted),'deleted body\n');git('add','--',old,deleted);git('commit','--quiet','-m','before');const first=git('rev-parse','HEAD');git('mv','--',old,next);fs.unlinkSync(path.join(root,deleted));git('add','--all','src');git('commit','--quiet','-m','after');const second=git('rev-parse','HEAD');git('update-ref','ORIG_HEAD',first);const sub=path.join(root,'src/nested cwd');fs.mkdirSync(sub);
 const args=hook==='post-checkout'?[hook,first,second,'1']:[hook];const result=JSON.parse(run(process.execPath,[path.join(kit,'tools/run-git-hook-sync.js'),...args],sub));assert.deepEqual(result.changed.sort(),[old,next,deleted].sort());assert.equal(result.cwd,root);assert.equal(result.trigger,`git-${hook}`);
}));
test('root-checkout zero old object ID keeps exact added paths',()=>fixture(({root,kit,run,git})=>{
 const first=git('rev-parse','HEAD');const zero='0'.repeat(first.length);const result=JSON.parse(run(process.execPath,[path.join(kit,'tools/run-git-hook-sync.js'),'post-checkout',zero,first,'1']));assert.deepEqual(result.changed,['.gitignore']);assert.equal(result.cwd,root);
}));
