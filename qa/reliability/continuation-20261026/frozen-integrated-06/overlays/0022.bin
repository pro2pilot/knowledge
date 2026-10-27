'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),vm=require('node:vm'),crypto=require('node:crypto'),Module=require('node:module'),{EventEmitter}=require('node:events');
const file=path.resolve(__dirname,'../tools/lib/verification-windows-job.js'),local=Module.createRequire(file),sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function image(machine=0xaa64){const b=Buffer.alloc(512);b.writeUInt16LE(0x5a4d);b.writeUInt32LE(128,0x3c);b.writeUInt32LE(0x4550,128);b.writeUInt16LE(machine,132);return b;}
function fixture(t,options={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'powershell-selection-')),systemRoot=path.join(root,'Windows'),programFiles=path.join(root,'Program Files'),executable=path.join(programFiles,'PowerShell','7','pwsh.exe');
 fs.mkdirSync(path.dirname(executable),{recursive:true});fs.writeFileSync(executable,options.bytes||image());t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const env={SystemRoot:systemRoot,ProgramFiles:programFiles,...options.env},modeled={arch:options.arch||'arm64',env,pid:process.pid};
 const m={exports:{}},requireFor=name=>name==='child_process'&&options.spawn?{spawn:options.spawn}:name==='./stable-file'&&options.stable?{readStableFile:options.stable}:local(name);
 vm.runInThisContext('(function(exports,require,module,__filename,__dirname,process){'+fs.readFileSync(file,'utf8')+'\n})',{filename:file})(m.exports,requireFor,m,file,path.dirname(file),modeled);
 return{...m.exports,root,executable,env,legacy:path.join(systemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe')};
}
test('Windows ARM selects only the stable native installed PowerShell image and pins its exact bytes',t=>{
 const f=fixture(t),value=f.selectPowerShell();assert.equal(value.executable,f.executable);assert.equal(value.sha256,sha(fs.readFileSync(f.executable)));
});
test('Windows x64 keeps the existing system PowerShell path without probing a replacement',t=>{
 const f=fixture(t,{arch:'x64',stable(){throw new Error('Native replacement must not be probed');}});assert.deepEqual(f.selectPowerShell(),{executable:f.legacy,sha256:null});
});
test('Windows PowerShell selection rejects wrong architecture malformed and truncated PE images',t=>{
 const f=fixture(t),wrongSignature=image(),wrongDos=image(),outside=image(),smallOffset=image();wrongSignature.writeUInt32LE(0,128);wrongDos.writeUInt16LE(0);outside.writeUInt32LE(0xffffffff,0x3c);smallOffset.writeUInt32LE(8,0x3c);
 for(const bytes of [image(0x8664),image(0x14c),wrongSignature,wrongDos,outside,smallOffset,Buffer.alloc(63),image().subarray(0,132)]){
  fs.writeFileSync(f.executable,bytes);assert.deepEqual(f.selectPowerShell(),{executable:f.legacy,sha256:null});
 }
});
test('Windows PowerShell selection refuses relative or redirected Program Files roots and ignores PATH',t=>{
 const f=fixture(t);for(const root of ['relative',path.join(f.root,'foreign')]){f.env.ProgramFiles=root;f.env.PATH=path.dirname(f.executable);assert.deepEqual(f.selectPowerShell(),{executable:f.legacy,sha256:null});}
});
test('Windows PowerShell selection rejects shared or concurrently changed executable bytes',t=>{
 const f=fixture(t),alias=path.join(f.root,'shared.exe');fs.linkSync(f.executable,alias);assert.deepEqual(f.selectPowerShell(),{executable:f.legacy,sha256:null});fs.unlinkSync(alias);
 const read=fs.readSync;let changed=false;fs.readSync=function(fd){const n=read.apply(this,arguments);if(n&&!changed){changed=true;fs.appendFileSync(f.executable,'changed');}return n;};
 try{assert.deepEqual(f.selectPowerShell(),{executable:f.legacy,sha256:null});assert(changed);}finally{fs.readSync=read;}
});
test('Windows native keeper readiness requires the selected executable hash and preserves exact spawn path',async t=>{
 let args,spawned;const keeper=new EventEmitter();keeper.pid=42425;keeper.stdin=new EventEmitter();keeper.stdout=new EventEmitter();keeper.stdout.setEncoding=()=>{};keeper.stdin.destroy=keeper.stdout.destroy=()=>{};keeper.unref=()=>{};
 const f=fixture(t,{spawn(executable,argv){spawned=executable;args=argv;return keeper;}}),job=f.createWindowsJob({pid:42424,exitCode:null,signalCode:null},()=>{},1000);
 assert.equal(spawned,f.executable);assert.equal(args[args.indexOf('-ExecutableSha256')+1],sha(fs.readFileSync(f.executable)));assert.equal(job.keeper_executable_sha256,sha(fs.readFileSync(f.executable)));
 const message={status:'ready',job_name:args[args.indexOf('-JobName')+1],keeper_executable_sha256:'0'.repeat(64),identities:{controller:{pid:process.pid,os_creation_time:'2026-01-01T00:00:00Z'},worker:{pid:42424,os_creation_time:'2026-01-01T00:00:00Z'},keeper:{pid:keeper.pid,os_creation_time:'2026-01-01T00:00:00Z'}},host:{machine_guid_sha256:'a'.repeat(64),computer_name_sha256:'b'.repeat(64),user_sid_sha256:'c'.repeat(64),session_id:1}};
 const rejected=assert.rejects(job.ready,{code:'verification_job_setup_failed'});keeper.stdout.emit('data',JSON.stringify(message)+'\n');await rejected;assert.equal(job.descriptor,undefined);keeper.emit('close',1);assert.equal((await job.close(10)).status,'unconfirmed');
});
