'use strict';
// The production read algorithm is extracted verbatim. Only Foundation's data
// allocation/type/nil syntax is adapted to a C struct. This is an inert adapter
// check with real Linux target-file I/O, not an Objective-C or Darwin build.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const { test, before, after } = require('node:test');
const sourceRoot = process.env.KNOWLEDGE_AUDIT_SOURCE || path.join(__dirname, '..');
const compiler = process.env.CC || 'cc';
const capture=process.env.KNOWLEDGE_AUDIT_CAPTURE;
function record(reader,name,value) {
  if(!capture)return;const folder=path.join(capture,reader);fs.mkdirSync(folder,{recursive:true});
  fs.writeFileSync(path.join(folder,name),typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');
}
const available = process.platform === 'linux' && cp.spawnSync(compiler, ['--version']).status === 0;
const options = { skip: !available ? 'Linux inert Foundation-allocation adapter requires C compiler; not Darwin qualification' : false };
let directory; const executables = {};
function section(source, start, end) {
  const i=source.indexOf(start),j=source.indexOf(end,i+start.length);
  assert.ok(i>=0&&j>i,`production section ${start}`);return source.slice(i,j);
}
function oneFunction(source, signature) {
  const start=source.indexOf(signature),open=source.indexOf('{',start);
  assert.ok(start>=0&&open>start,`production function ${signature}`);
  let depth=0,quote=null,comment=null,escaped=false;
  for(let i=open;i<source.length;i++) {
    const c=source[i],next=source[i+1];
    if(comment==='line'){if(c==='\n')comment=null;continue;}
    if(comment==='block'){if(c==='*'&&next==='/'){comment=null;i++;}continue;}
    if(quote){if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c===quote)quote=null;continue;}
    if(c==='/'&&next==='/'){comment='line';i++;continue;}
    if(c==='/'&&next==='*'){comment='block';i++;continue;}
    if(c==='"'||c==="'"){quote=c;continue;}
    if(c==='{')depth++;
    if(c==='}'&&--depth===0)return source.slice(start,i+1)+'\n';
  }
  assert.fail(`unclosed production function ${signature}`);
}
function allocationAdapter(body, variable, statVariable) {
  const declaration=`NSMutableData *${variable}=[NSMutableData dataWithLength:(NSUInteger)${statVariable}.st_size]`;
  assert.ok(body.includes(declaration),'recognizable allocation expression');
  const out=body.replace('static NSData *','static TestData ').replace(declaration,`TestData ${variable}=testData((size_t)${statVariable}.st_size)`)
    .replace(/\bNSUInteger\b/g,'size_t').replace(/\bnil\b/g,'invalidData');
  assert.ok(!/NSData|NSMutableData|NSUInteger/.test(out),'no unmodeled Foundation data syntax');return out;
}
before(() => {
  if(!available)return;
  directory=fs.mkdtempSync(path.join(os.tmpdir(),'knowledge-native-data-readers-'));
  const template=fs.readFileSync(path.join(__dirname,'fixtures/audit-native-reader-probe.c'),'utf8');
  const broker=fs.readFileSync(path.join(sourceRoot,'tools/lib/verification-darwin-broker.m'),'utf8');
  const history=fs.readFileSync(path.join(sourceRoot,'tools/lib/verification-darwin-uid-history.m'),'utf8');
  const allocation=`typedef bool BOOL; typedef struct {size_t length;void *mutableBytes;} TestData;
static const TestData invalidData={0,NULL};
static TestData testData(size_t n){return (TestData){n,calloc(n?n:1,1)};}
`;
  const sources={
    broker: section(broker,'static bool exactIO(', 'static NSData *jsonData(')
      +(broker.includes('static bool sameFileSnapshot(')?section(broker,'static bool sameFileSnapshot(', 'static NSData *readFD('):'')
      // QA functions may follow readFD in the actor implementation. Extract
      // exactly this function, never neighboring unmodeled Foundation code.
      +allocationAdapter(oneFunction(broker,'static NSData *readFD('),'d','s'),
    history: (history.includes('static BOOL KVSameSnapshot(')?section(history,'static BOOL KVSameSnapshot(', 'static NSData *KVRead('):'')
      +allocationAdapter(oneFunction(history,'static NSData *KVRead('),'data','st')
  };
  for(const [name,body] of Object.entries(sources)) {
    const read=name==='broker'?'readFD':'KVRead';
    const wrapper=`static bool protected_image(const char *file,char digest[65]) {
(void)digest;int fd=open(file,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return false;
TestData d=${read}(fd,256u*1024u*1024u);bool ok=d.mutableBytes!=NULL;
result_bytes=ok?d.length:0;free(d.mutableBytes);if(close(fd))ok=false;return ok;
}`;
    const combined=template.replace('/* EXTRACTED_PRODUCTION_FUNCTIONS */',allocation+body+wrapper);
    const filename=path.join(directory,`${name}.c`),binary=path.join(directory,name);fs.writeFileSync(filename,combined);
    const compiled=cp.spawnSync(compiler,['-std=c11','-O0','-Wall','-Wextra','-Wno-unused-function',filename,'-o',binary],{encoding:'utf8',timeout:30000});
    record(name,'compiled-producer.c',combined);
    record(name,'compile.stdout',compiled.stdout||'');record(name,'compile.stderr',compiled.stderr||'');
    record(name,'compile.json',{compiler,args:['-std=c11','-O0','-Wall','-Wextra','-Wno-unused-function',filename,'-o',binary],status:compiled.status,signal:compiled.signal,error:compiled.error?.code});
    assert.equal(compiled.status,0,compiled.stderr||String(compiled.error));executables[name]=binary;
  }
});
after(()=>{if(directory)fs.rmSync(directory,{recursive:true,force:true});});
function run(reader,mode) {
  const filename=path.join(directory,`${reader}-${mode}`);fs.writeFileSync(filename,mode==='empty'?'':Buffer.alloc(4096,'a'),{mode:0o600});
  const child=cp.spawnSync(executables[reader],[mode,filename],{encoding:'utf8',timeout:5000,killSignal:'SIGKILL'});
  record(reader,`${mode}.json`,{pid:child.pid,mode,status:child.status,signal:child.signal,error:child.error?.code,stdout:child.stdout,stderr:child.stderr});
  assert.equal(child.error,undefined,child.error?.message);assert.equal(child.status,0,child.stderr);
  const value=JSON.parse(child.stdout);
  if(!['stable','empty'].includes(mode))assert.equal(value.hook_fired,true,'fixture reached intended read boundary');
  return value;
}
for(const reader of ['broker','history']) {
  test(`${reader} data reader accepts stable regular bytes`,options,()=>{const r=run(reader,'stable');assert.equal(r.accepted,true);assert.equal(r.result_bytes,4096);});
  test(`${reader} data reader accepts stable empty bytes`,options,()=>{const r=run(reader,'empty');assert.equal(r.accepted,true);assert.equal(r.result_bytes,0);});
  test(`${reader} data reader rejects growth without reading unbounded suffix`,options,()=>{const r=run(reader,'growth');assert.equal(r.accepted,false);assert.ok(r.read_bytes<=4097,JSON.stringify(r));});
  test(`${reader} data reader rejects same-size rewrite`,options,()=>{assert.equal(run(reader,'same-length').accepted,false);});
  test(`${reader} data reader rejects early EOF`,options,()=>{assert.equal(run(reader,'early-eof').accepted,false);});
  test(`${reader} data reader handles a single interrupted read`,options,()=>{const r=run(reader,'eintr');assert.equal(r.accepted,true);assert.equal(r.result_bytes,4096);});
}
