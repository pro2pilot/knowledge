'use strict';
// Physical files; hooks inject a precisely timed filesystem change. No native
// containment claim is made. Each FIFO scenario lives in its own killable child.
const fs = require('node:fs'), path = require('node:path'), cp = require('node:child_process');
const source = process.env.KNOWLEDGE_AUDIT_SOURCE || path.resolve(__dirname, '../..');
const [kind, scenario, root] = process.argv.slice(2);
fs.mkdirSync(root, { recursive: true });
let file, read, original;
if (kind === 'artifact') {
  file = path.join(root, 'data.json'); original = Buffer.from('{"value":"ordinary"}' + ' '.repeat(200));
  fs.writeFileSync(file, original);
  read = () => require(path.join(source,'tools/lib/contained-artifact')).readContainedJsonFromRoot(root, 'data.json', {maxBytes: 1024});
} else if (kind === 'control') {
  const c = require(path.join(source,'tools/lib/verification-control'));
  c.beginAttempt({stateRoot:root}, {request_sha256:'a'.repeat(64), profile:{work_budget_ms:120000,no_progress_ms:60000,cleanup_budget_ms:30000}});
  file = path.join(root,'maintenance/verification-control/active.json');
  original = fs.readFileSync(file); fs.appendFileSync(file, ' '.repeat(200)); original = fs.readFileSync(file);
  read = () => { try { return {value:c.readStatus({stateRoot:root}),error:null}; } catch(e) { return {error:e.code || e.message}; } };
} else {
  file = path.join(root,'maintenance/verification_executions','a'.repeat(64)+'.json');
  fs.mkdirSync(path.dirname(file),{recursive:true}); original=Buffer.from('{"value":"ordinary"}'+' '.repeat(200)); fs.writeFileSync(file,original);
  read = () => { const r=require(path.join(source,'tools/lib/verification-execution')).readNativeRecord(root,'a'.repeat(64),'verification_executions');return {value:r,error:r?null:'record_rejected'}; };
}
if(scenario==='utf8') {
  const b=Buffer.from(original); const at=b.indexOf(kind==='control'?'reserved':'ordinary');
  if(at<0)throw new Error('fixture token absent'); b[at]=0xff;fs.writeFileSync(file,b);
}
const open=fs.openSync, readFile=fs.readFileSync, readSync=fs.readSync;
let targetFd=null, hooked=false, first=true, actualReadBytes=0;
const rawPrefix=()=>Buffer.from(original.toString('utf8').trim());
function mutateAfter() {
  if(scenario!=='same_size' || hooked)return;
  hooked=true;const b=Buffer.from(original);
  if(kind==='control') { const at=b.indexOf('a'.repeat(64));if(at<0)throw new Error('request hash absent');b.fill(98,at,at+64); }
  else b[b.length-1]=b[b.length-1]===32?9:32;
  fs.writeFileSync(file,b);
  const stamp=new Date(Date.now()+10000);fs.utimesSync(file,stamp,stamp);
}
function beforeRead() {
  if(scenario==='growth'&&!hooked){hooked=true;fs.appendFileSync(file,Buffer.alloc(2*1024*1024,32));}
}
fs.openSync=function(p,...args) {
  if(typeof p==='string'&&path.resolve(p)===file) {
    if(scenario==='fifo'&&!hooked){hooked=true;fs.unlinkSync(file);const made=cp.spawnSync('mkfifo',[file],{encoding:'utf8'});if(made.error||made.status!==0)throw new Error('FIFO fixture unavailable: '+made.stderr);fs.writeFileSync(path.join(root,'FIFO_REPLACED'),'yes');}
    const fd=open.call(fs,p,...args);targetFd=fd;return fd;
  }
  return open.call(fs,p,...args);
};
fs.readFileSync=function(p,...args){
  if((typeof p==='string'&&path.resolve(p)===file)||p===targetFd){
    beforeRead();let b=readFile.call(fs,p,...args);actualReadBytes+=Buffer.byteLength(b);
    if(scenario==='early_eof'){hooked=true;b=rawPrefix();}
    mutateAfter();return b;
  }
  return readFile.call(fs,p,...args);
};
fs.readSync=function(fd,buf,offset,length,position){
  if(fd!==targetFd)return readSync.call(fs,fd,buf,offset,length,position);
  beforeRead();
  if(scenario==='early_eof') {hooked=true;if(!first)return 0;first=false;const p=rawPrefix();p.copy(buf,offset,0,Math.min(length,p.length));return Math.min(length,p.length);}
  const n=readSync.call(fs,fd,buf,offset,length,position);actualReadBytes+=n;mutateAfter();return n;
};
let result;
try {result=read();} finally {fs.openSync=open;fs.readFileSync=readFile;fs.readSync=readSync;}
const physicalRequestSha=kind==='control'&&scenario==='same_size'?JSON.parse(fs.readFileSync(file,'utf8')).request_sha256:null;
process.stdout.write(JSON.stringify({result,hooked,actualReadBytes,physicalRequestSha}));
