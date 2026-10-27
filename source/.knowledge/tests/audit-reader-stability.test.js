'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),cp=require('node:child_process');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'audit-readers-'));
test.after(()=>fs.rmSync(root,{recursive:true,force:true}));
const helper=path.join(__dirname,'helpers/audit-reader-worker.cjs');
let sequence=0;
for(const kind of ['artifact','control','record']){
  for(const scenario of ['ordinary','utf8','same_size','early_eof','fifo',...(kind==='artifact'?['growth']:[])]){
    test(`${kind}: ${scenario} keeps the read physically bounded and coherent`,{skip:scenario==='fifo'&&process.platform==='win32'},t=>{
      const where=path.join(root,String(++sequence));
      const child=cp.spawnSync(process.execPath,[helper,kind,scenario,where],{encoding:'utf8',timeout:8000,killSignal:'SIGKILL',maxBuffer:1024*1024});
      t.diagnostic(JSON.stringify({kind,scenario,pid:child.pid,status:child.status,signal:child.signal,error:child.error?.code??null,stdout:child.stdout,stderr:child.stderr,
        cleanup:child.signal==='SIGKILL'?'direct child reaped after SIGKILL; worker creates no descendants except completed FIFO setup':child.status!==null?'direct child exited':'unconfirmed'}));
      assert.equal(child.error,undefined,`${scenario}: ${child.error?.message}; fixture reached=${fs.existsSync(path.join(where,'FIFO_REPLACED'))}`);
      assert.equal(child.status,0,child.stderr);
      const row=JSON.parse(child.stdout);
      if(scenario==='ordinary')assert.equal(row.result.error,null,child.stdout);
      // Control CAS permits a bounded retry after a transient race. It may
      // reject the read or return the new coherent request, never old bytes.
      else if(kind==='control'&&scenario==='same_size') {
        if(!row.result.error)assert.equal(row.result.value.attempt.request_sha256,row.physicalRequestSha,'stale pre-mutation request returned');
      }
      else assert.ok(row.result.error,`unstable or malformed input accepted: ${child.stdout.slice(0,400)}`);
      if(['same_size','early_eof','fifo','growth'].includes(scenario))assert.equal(row.hooked,true,'fault injection not reached');
      if(scenario==='growth')assert.ok(row.actualReadBytes<=1025,`reader consumed ${row.actualReadBytes} bytes for maxBytes=1024`);
    });
  }
}
