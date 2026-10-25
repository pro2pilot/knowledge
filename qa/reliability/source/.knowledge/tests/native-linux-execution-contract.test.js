'use strict';

// Real Linux producer, namespaces and recovery. Fault injection changes only
// trusted controller boundaries; no native proof or successful ACK is mocked.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');
const source = path.resolve(__dirname, '..');
const lib = n => path.join(source, 'tools/lib', n + '.js');
const q = JSON.stringify;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const control = require('../tools/lib/verification-control');
const finalization = require('../tools/lib/verification-finalization');

async function until(predicate, budget = 45000) {
  const deadline = performance.now() + budget;
  while (performance.now() < deadline) {
    const result = predicate();
    if (result) return result;
    await pause(25);
  }
  assert.fail('Owned fixture did not reach its required physical milestone');
}

function setup(t, mode) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-linux-contract-'));
  const state = path.join(root, '.knowledge'); fs.mkdirSync(state);
  const write = (name, content) => { const p = path.join(root, name); fs.writeFileSync(p, content); return p; };
  const context = {stateRoot: state, projectKnowledgeRoot: state, targetRoot: root, systemRoot: source};
  const marker = name => `require('fs').writeFileSync(${q(path.join(root, name + '.json'))},JSON.stringify({phase:${q(name)},pid:process.pid,proc_pid:Number(require('fs').readlinkSync('/proc/self'))}));`;
  let body = marker('command');
  if (['cancel','crash','work-timeout'].includes(mode)) body += 'setInterval(()=>{},1000);';
  else if (mode.startsWith('silent')) body += 'const until=performance.now()+4500;while(performance.now()<until){};';
  else body += 'process.stdout.write("ok");';
  write('probe.js', body);
  let authorityFault = '';
  if (mode === 'preparation') authorityFault = `const crypto=require('crypto'),original=crypto.generateKeyPairSync;crypto.generateKeyPairSync=(...a)=>{${marker(mode)}const until=performance.now()+20000;while(performance.now()<until){};return original(...a);};`;
  if (mode === 'signing') authorityFault = `const crypto=require('crypto'),original=crypto.sign;crypto.sign=(...a)=>{${marker(mode)}const until=performance.now()+8000;while(performance.now()<until){};return original(...a);};`;
  if (mode === 'receipt-io') {
    const supervisor = write('fault-supervisor.cjs', `require(${q(lib('verification-finalization'))}).persistFinalization=()=>{${marker(mode)}setInterval(()=>{},1000);return new Promise(()=>{});};require(${q(lib('verification-supervisor'))}).__test.runStdioSupervisor();`);
    authorityFault = `const cp=require('child_process'),old=cp.spawnSync;cp.spawnSync=(exe,args,opts)=>old(exe,args[0]===${q(lib('verification-supervisor'))}?[${q(supervisor)},...args.slice(1)]:args,opts);`;
  }
  const authority = write('authority.cjs', authorityFault + `require(${q(lib('verification-watchdog'))}).__test.runAuthority();`);
  const watcher = write('watcher.cjs', `const b=require(${q(lib('verification-linux-namespace'))}),old=b.spawnLinuxContainedWorker;b.spawnLinuxContainedWorker=(exe,args,opts,settings)=>old(exe,args[0]===${q(lib('verification-watchdog'))}&&args[1]==='--authority'?[${q(authority)}]:args,opts,settings);require(${q(lib('verification-watchdog'))}).__test.runStdioWatchdog();`);
  const work = ['work-timeout','preparation'].includes(mode) ? 8000 : 45000;
  const cleanup = ['signing','receipt-io'].includes(mode) ? 3000 : 15000;
  const request = {stateRoot:state,repoRoot:root,taskId:'linux-'+mode,sessionId:'linux-contract',checkedBy:'physical-linux-contract',
    sourceFiles:['probe.js'],tests:[{argv:['node','probe.js'],cwd:'.',timeout_ms:work}],timeoutMs:work,
    verificationPolicy:{work_budget_ms:work,no_progress_ms:mode.startsWith('silent')?2500:0,cleanup_budget_ms:cleanup}};
  const caller = write('caller.cjs', `const fs=require('fs'),cp=require('child_process'),old=cp.spawnSync;cp.spawnSync=(exe,args,opts)=>old(exe,args[0]===${q(lib('verification-watchdog'))}?[${q(watcher)}]:args,opts);let value;try{const r=require(${q(lib('repair-on-touch'))}).runVerificationTests(${q(request)});value={status:'pass',budget:r.verification_budget,acceptances:r.verification_acceptances,ids:r.map(x=>x.record.execution_id)};}catch(e){value={status:'error',code:e.code,timed_out:e.timed_out,has_acceptance:!!e.verification_acceptances,budget:e.verification_budget,teardown:e.teardown};}fs.writeFileSync(${q(path.join(root,'result.json'))},JSON.stringify(value,null,2));`);
  const actor = cp.spawn(process.execPath, [caller], {stdio:['ignore','pipe','pipe']});
  let stderr='';actor.stderr.on('data',b=>stderr+=b); actor.stdout.resume();
  t.after(async () => {
    if (actor.exitCode===null && actor.signalCode===null) actor.kill('SIGKILL');
    // Guardian cleanup is distinct from every assertion and never counts as a
    // product recovery PASS. It targets only this fixture's recorded owner.
    try {const a=control.readStatus(context).attempt;if(a?.claimed && a.containment)require('../tools/lib/verification-recovery').recoverAttempt(context,{attempt_id:a.attempt_id,generation:a.generation});} catch {}
    const report={mode,root,stderr,status:control.readStatus(context),result:fs.existsSync(path.join(root,'result.json'))?JSON.parse(fs.readFileSync(path.join(root,'result.json'))):null};
    console.log('PHYSICAL_LINUX_CONTRACT '+JSON.stringify(report));
    if(process.env.KNOWLEDGE_AUDIT_RETAIN_FIXTURES!=='1' && !report.status.attempt?.claimed)require('../tools/lib/strict-temp-cleanup').removeTempDirStrict(root);
  });
  return {root,state,context,actor,work,cleanup,
    marker:name=>fs.existsSync(path.join(root,name+'.json')),
    result:async()=>{await until(()=>actor.exitCode!==null || actor.signalCode!==null,work+cleanup+20000);assert.equal(actor.exitCode,0,stderr);return JSON.parse(fs.readFileSync(path.join(root,'result.json')));}};
}

test('physical Linux work, cancellation and recovery contract', {skip:process.platform!=='linux',timeout:240000}, async t => {
  for(const mode of ['silent','silent-load','cancel','work-timeout','preparation','signing','receipt-io','crash']) {
    await t.test(mode,async t=>{
      const f=setup(t,mode);
      if(mode==='silent-load') {
        await until(()=>f.marker('command'));
        const loads=Array.from({length:2},()=>cp.spawn(process.execPath,['-e','const end=performance.now()+6000;while(performance.now()<end){}'],{stdio:'ignore'}));
        t.after(()=>{for(const child of loads)if(child.exitCode===null && child.signalCode===null)child.kill('SIGKILL');});
        console.log('OWNED_CPU_LOAD '+JSON.stringify(loads.map(child=>child.pid)));
      }
      if(mode==='cancel' || mode==='crash') {
        await until(()=>f.marker('command'));
        const a=control.readStatus(f.context).attempt;
        assert(a.containment?.descriptor_sha256);
        if(mode==='cancel')control.requestCancel(f.context,{attempt_id:a.attempt_id,generation:a.generation});
        else {const watchdog=a.processes.find(p=>p.role==='watchdog');assert(watchdog.pid>1);process.kill(watchdog.pid,'SIGKILL');}
      }
      const observed=await f.result();
      let attempt=control.readStatus(f.context).attempt;
      if(mode.startsWith('silent')) {
        assert.equal(observed.status,'pass',JSON.stringify(observed));assert.equal(observed.acceptances.length,1);
        assert.equal(finalization.requireFinalizedExecutions(f.state,observed.ids,observed.acceptances).status,'accepted');
        assert(observed.budget.work_elapsed_ms>2500,'Silent work outlives no-progress interval');
        assert.equal(attempt.claimed,false);assert.equal(attempt.terminal.outcome,'passed');
      } else {
        assert.equal(observed.status,'error',JSON.stringify(observed));assert.equal(observed.has_acceptance,false);
        assert.equal(f.marker(mode==='preparation'?'preparation':'command'),true,'Fault must reach its intended stage');
        if(mode==='cancel'){assert.equal(observed.code,'verification_cancelled');assert.equal(attempt.terminal.outcome,'cancelled');}
        if(['work-timeout','preparation'].includes(mode)){assert.equal(observed.code,'verification_timeout');assert.equal(attempt.terminal.outcome,'timed_out');}
        if(['signing','receipt-io'].includes(mode))assert(f.marker(mode),'Finalization fault must physically execute');
        if(attempt.claimed) {
          const result=require('../tools/lib/verification-recovery').recoverAttempt(f.context,{attempt_id:attempt.attempt_id,generation:attempt.generation});
          assert.equal(result.ack_released,false,JSON.stringify(result));
          attempt=control.readStatus(f.context).attempt;assert.equal(attempt.claimed,false);
        }
        assert.equal(attempt.terminal.ack_sha256,null);
      }
    });
  }
});
