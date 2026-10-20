#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const native = require('./lib/repair-on-touch');
const runner = require('./lib/verification-supervisor');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-budget-'));
const checks = [];
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, ms = 7000) {
  const end = performance.now() + ms;
  while (!fn() && performance.now() < end) await sleep(20);
  assert(fn(), 'Expected process/fixture condition was not observed within its bound');
}
function fixture(name) {
  const repo = path.join(root, name); fs.mkdirSync(repo);
  const state = path.join(repo, '.knowledge'); fs.mkdirSync(state);
  const file = (rel, text) => { fs.writeFileSync(path.join(repo, rel), text); return rel; };
  file('source.js', 'module.exports=1;\n');
  return { repo, state, file, request(tests, timeoutMs) {
    return { stateRoot: state, repoRoot: repo, taskId: 'budget-test', sessionId: 'budget-session',
      checkedBy: 'budget-test', sourceFiles: ['source.js', ...tests.map(t=>t.argv[1])], tests,
      ...(timeoutMs === undefined ? {} : { timeoutMs }) };
  }};
}
const command = (file, timeout_ms = 10000) => ({ argv: ['node', file], cwd: '.', timeout_ms });
async function check(name, fn) {
  const f = fixture(String(checks.length)); const start = performance.now();
  try { const evidence = await fn(f); checks.push({ name, status: 'pass', duration_ms: performance.now()-start, evidence }); }
  catch (error) { checks.push({ name, status: 'fail', duration_ms: performance.now()-start, error: error.stack, budget: error.verification_budget, teardown: error.teardown }); }
}
function expectTimeout(fn) {
  let error; try { fn(); } catch(e) { error=e; }
  assert.equal(error?.code, 'verification_timeout'); assert.equal(error.timed_out, true);
  return error;
}
function syntheticPayload(timeout = 3000) {
  const now = process.hrtime.bigint();
  return { protocol: runner.__test.PROTOCOL, started_ns: String(now), deadline_ns: String(now+BigInt(timeout)*1000000n), timeout_ms: timeout, request: {} };
}
async function synthetic(f, body, timeout = 3000) {
  const file = f.file('worker.cjs', `const p='${runner.__test.PROTOCOL}';process.on('message',m=>{${body}});`);
  return runner.__test.supervise(syntheticPayload(timeout), path.join(f.repo, file));
}
(async () => {
  await check('exact timeout values and invalid types', () => {
    for (const n of [1, 17, 300001, 600000]) assert.equal(native.verificationTimeoutMs(n), n);
    for (const n of [null, true, false, {}, '1000', 0, -1, 1.5, NaN, 600001]) assert.throws(()=>native.verificationTimeoutMs(n),e=>e.code==='verification_timeout_invalid');
    assert.equal(native.verificationTimeoutMs(undefined),120000);
  });
  await check('ordinary sequential execution preserves KVE contracts and reports total budget', f => {
    const probe=f.file('probe.js', 'process.stdout.write("ok");');
    const result=native.runVerificationTests(f.request([command(probe), command(probe)],15000));
    assert.equal(result.length,2);
    for(const r of result) { assert.equal(r.record.status,'pass'); assert(native.loadExecutionRecord(f.state,r.record.execution_id)); }
    assert.equal(result.verification_budget.timeout_ms,15000);
    assert.equal(result.verification_budget.teardown.status,'completed');
    assert.equal(result.verification_budget.work_budget_ms,15000);
    assert(result.verification_budget.work_elapsed_ms < 15000);
    assert(result.verification_budget.cleanup_budget_ms > 0);
    assert(result.verification_budget.cleanup_elapsed_ms >= 0 && result.verification_budget.cleanup_elapsed_ms < result.verification_budget.cleanup_budget_ms);
    assert.equal(result.verification_budget.authority_teardown.status,'completed');
    assert.equal(result.verification_budget.authority_teardown.keeper_exited,true);
    return result.verification_budget;
  });
  await check('exhausted setup budget starts no worker command and publishes no KVE', f => {
    const p=f.file('probe.js','require("fs").writeFileSync("ran","unexpected");');
    const e=expectTimeout(()=>native.runVerificationTests(f.request([command(p)],1)));
    assert(['setup', 'watchdog'].includes(e.stage)); assert(!fs.existsSync(path.join(f.repo,'ran')));
    assert(!fs.existsSync(path.join(f.state,'maintenance/verification_executions')));
    assert.deepEqual(e.completed_executions,[]); return e.verification_budget;
  });
  await check('batch deadline stops sequential probes and preserves committed IDs', f => {
    const first=f.file('first.js','setTimeout(()=>process.stdout.write("first"),30);');
    const slow=f.file('slow.js','require("fs").writeFileSync("second-started","yes");setTimeout(()=>{},20000);');
    const last=f.file('last.js','require("fs").writeFileSync("third-ran","unexpected");');
    const e=expectTimeout(()=>native.runVerificationTests(f.request([command(first,600000),command(slow,600000),command(last,600000)],5000)));
    assert(fs.existsSync(path.join(f.repo,'second-started'))); assert(!fs.existsSync(path.join(f.repo,'third-ran')));
    assert.equal(e.completed_executions.length,1); assert(native.loadExecutionRecord(f.state,e.completed_executions[0].execution_id));
    assert.equal(e.teardown.status,'completed');
    assert.equal(e.verification_budget.work_budget_ms,5000);
    assert(e.verification_budget.cleanup_budget_ms > 0);
    assert(e.verification_budget.cleanup_elapsed_ms >= 0 && e.verification_budget.cleanup_elapsed_ms < e.verification_budget.cleanup_budget_ms,
      'cleanup has its own bounded allowance after work stops');
    assert(e.verification_budget.total_elapsed_ms >= e.verification_budget.work_elapsed_ms);
    return { budget:e.verification_budget, committed:e.completed_executions, teardown:e.teardown };
  });
  await check('per-command deadline kills a TERM-ignoring child within the batch deadline', async f => {
    const probe=f.file('ignore.js','require("fs").writeFileSync("pid",String(process.pid));process.on("SIGTERM",()=>{});setInterval(()=>{},1000);');
    const e=expectTimeout(()=>native.runVerificationTests(f.request([command(probe,500)],15000)));
    assert.equal(e.stage,'command');
    assert(e.verification_budget.work_elapsed_ms < e.verification_budget.work_budget_ms,'the shorter command deadline ends work before the batch deadline');
    const pid=Number(fs.readFileSync(path.join(f.repo,'pid'),'utf8')); await until(()=>!alive(pid));
    assert.equal(e.teardown.status,'completed'); return { pid, budget:e.verification_budget, teardown:e.teardown };
  });
  await check('deadline kills owned descendants holding inherited pipes', async f => {
    const child=f.file('child.js','require("fs").writeFileSync("child-ready",String(process.pid));process.on("SIGTERM",()=>{});setInterval(()=>{},1000);');
    const probe=f.file('tree.js',`const c=require('child_process').spawn(process.execPath,[${JSON.stringify(child)}],{stdio:'inherit'});require('fs').writeFileSync('pids',JSON.stringify([process.pid,c.pid]));process.on('SIGTERM',()=>{});setInterval(()=>{},1000);`);
    const e=expectTimeout(()=>native.runVerificationTests(f.request([command(probe,1000)],15000)));
    const pids=JSON.parse(fs.readFileSync(path.join(f.repo,'pids'),'utf8')); assert(fs.existsSync(path.join(f.repo,'child-ready')));
    await until(()=>pids.every(pid=>!alive(pid))); assert.equal(e.teardown.status,'completed'); return {pids,teardown:e.teardown};
  });
  await check('successful command cannot leave an orphan with detached stdio', async f => {
    const child=f.file('orphan.js','require("fs").writeFileSync("orphan-ready",String(process.pid));setInterval(()=>{},1000);');
    const probe=f.file('parent.js',`const fs=require('fs');const c=require('child_process').spawn(process.execPath,[${JSON.stringify(child)}],{stdio:'ignore'});c.unref();const i=setInterval(()=>{if(fs.existsSync('orphan-ready')){clearInterval(i);process.exit(0);}},10);`);
    const r=native.runVerificationTests(f.request([command(probe)],15000));
    const pid=Number(fs.readFileSync(path.join(f.repo,'orphan-ready'),'utf8'));
    await until(()=>!alive(pid)); assert.equal(r[0].record.status,'pass'); assert.equal(r.verification_budget.teardown.status,'completed');
    return { pid,teardown:r.verification_budget.teardown };
  });
  await check('watchdog preempts synchronous setup in a worker', async f => {
    const r=await synthetic(f,"if(m.type==='run'){while(true){}}",3000);
    assert.equal(r.error.code,'verification_timeout'); assert.equal(r.budget.stage,'setup'); assert.equal(r.teardown.status,'completed'); return r;
  });
  await check('watchdog preempts synchronous finalization', async f => {
    const r=await synthetic(f,"if(m.type==='run')process.send({protocol:p,type:'phase',id:1,stage:'finalization',deadline_ns:m.deadline_ns});else if(m.type==='ack'){while(true){}}",3000);
    assert.equal(r.error.code,'verification_timeout'); assert.equal(r.budget.stage,'finalization'); assert.equal(r.teardown.status,'completed'); return r;
  });
  await check('worker crash is a failure, with no fabricated receipt', async f => {
    const r=await synthetic(f,"if(m.type==='run')process.exit(7);",10000);
    assert.equal(r.status,'failed'); assert.equal(r.error.code,'verification_worker_exited'); assert.deepEqual(r.completed_executions,[]); return r;
  });
  await check('invalid control protocol fails closed', async f => {
    const r=await synthetic(f,"if(m.type==='run')process.send({protocol:'bad',type:'result',result:[]});",10000);
    assert.equal(r.error.code,'verification_protocol_invalid'); assert.equal(r.teardown.status,'completed'); return r;
  });
  await check('oversized request refuses before spawn', () => {
    assert.throws(()=>runner.runSupervised({padding:'x'.repeat(33*1024*1024)},10000),e=>e.code==='verification_input_invalid');
  });
  await check('nonzero command cannot publish a successful KVE', f => {
    const probe=f.file('fail.js','process.exit(9);');
    let error; try { native.runVerificationTests(f.request([command(probe)],15000)); } catch(e) { error=e; }
    assert(error); assert.match(error.message,/execution_not_passed/);
    assert.deepEqual(error.completed_executions,[]);
    assert.equal(error.teardown.status,'completed');
    assert(!fs.existsSync(path.join(f.state,'maintenance/verification_executions')));
  });
  if(process.platform==='win32') {
    await check('helper crash closes its kernel job and all descendants', async f => {
      const marker=path.join(f.repo,'owned-pids');
      const child=f.file('child.cjs','setInterval(()=>{},1000);');
      const workerFile=f.file('worker.cjs',`process.on('message',()=>{const c=require('child_process').spawn(process.execPath,[${JSON.stringify(path.join(f.repo,child))}],{stdio:'ignore'});require('fs').writeFileSync(${JSON.stringify(marker)},JSON.stringify([process.pid,c.pid]));});`);
      const worker=spawn(process.execPath,[path.join(f.repo,workerFile)],{stdio:['ignore','ignore','ignore','ipc'],windowsHide:true});
      const helper=spawn(path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),
        ['-NoProfile','-NonInteractive','-File',path.join(__dirname,'lib/verification-windows-job.ps1'),'-WorkerPid',String(worker.pid),'-ControllerPid',String(process.pid),'-LifetimeMs','15000','-JobName','Local\\KnowledgeVerification-'+require('crypto').randomBytes(32).toString('hex')],
        {stdio:['pipe','pipe','ignore'],windowsHide:true});
      let output=''; helper.stdout.on('data',b=>{output+=b;});
      try {
        await until(()=>output.includes('"status":"ready"'));
        worker.send({run:true}); await until(()=>fs.existsSync(marker));
        const pids=JSON.parse(fs.readFileSync(marker,'utf8'));
        helper.kill('SIGKILL'); await until(()=>pids.every(pid=>!alive(pid)));
        return { pids, remaining_processes:0 };
      } finally {
        if(helper.exitCode===null&&helper.signalCode===null)helper.kill('SIGKILL');
        if(worker.exitCode===null&&worker.signalCode===null)worker.kill('SIGKILL');
      }
    });
    await check('unavailable Job Object helper refuses before probes', async f => {
      const original=process.env.SystemRoot;
      process.env.SystemRoot=path.join(f.repo,'absent-windows');
      try {
        const marker=path.join(f.repo,'unexpected-probe');
        const r=await synthetic(f,`if(m.type==='run')require('fs').writeFileSync(${JSON.stringify(marker)},'bad');`,10000);
        assert(!fs.existsSync(marker));
        assert.equal(r.status,'failed'); assert.match(r.error.code,/verification_job/); assert.deepEqual(r.completed_executions,[]); return r;
      } finally { process.env.SystemRoot=original; }
    });
    await check('supervisor crash closes the job through control EOF', async f => {
      const probe=f.file('linger.js','require("fs").writeFileSync("pids",JSON.stringify([process.pid,process.ppid]));setInterval(()=>{},1000);');
      const payload=syntheticPayload(15000); payload.request=f.request([command(probe,15000)],15000);
      const controller=spawn(process.execPath,[path.join(__dirname,'lib/verification-supervisor.js'),'--supervisor'],{stdio:['pipe','ignore','ignore'],windowsHide:true});
      controller.stdin.end(JSON.stringify(payload));
      try {
        await until(()=>fs.existsSync(path.join(f.repo,'pids')),10000);
        const pids=JSON.parse(fs.readFileSync(path.join(f.repo,'pids'),'utf8'));
        controller.kill('SIGKILL'); await until(()=>pids.every(pid=>!alive(pid)),7000);
        return { pids, remaining_processes:0 };
      } finally { if(controller.exitCode===null&&controller.signalCode===null)controller.kill('SIGKILL'); }
    });
  }
  const failed=checks.filter(c=>c.status!=='pass').length;
  console.log(JSON.stringify({status:failed?'fail':'pass',total:checks.length,passed:checks.length-failed,checks},null,2));
  process.exitCode=failed?1:0;
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>{
  const resolved=path.resolve(root);
  if(path.dirname(resolved)!==path.resolve(os.tmpdir())||!path.basename(resolved).startsWith('k-budget-'))throw new Error('Unsafe test root');
  removeTempDirStrict(resolved,{label:'verification budget fixtures'});
});
