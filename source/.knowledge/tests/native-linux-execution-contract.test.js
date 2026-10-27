'use strict';

// Real Linux producer, namespaces and recovery. Fault injection changes only
// trusted controller boundaries; no native proof or successful ACK is mocked.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');
const source = path.resolve(process.env.KNOWLEDGE_NATIVE_TEST_SOURCE || path.join(__dirname, '..'));
const lib = n => path.join(source, 'tools/lib', n + '.js');
const q = JSON.stringify;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const control = require(lib('verification-control'));
const finalization = require(lib('verification-finalization'));

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
  const runtime = path.join(root, 'runtime');
  fs.cpSync(source,runtime,{recursive:true,filter:file=>!path.relative(source,file).split(path.sep).some(p=>p==='locks'||p.startsWith('.build-')||p.startsWith('.command-build-'))});
  const lib = n => path.join(runtime, 'tools/lib', n + '.js');
  const write = (name, content) => { const p = path.join(root, name); fs.writeFileSync(p, content); return p; };
  const context = {stateRoot: state, projectKnowledgeRoot: state, targetRoot: root, systemRoot: runtime};
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
  const trigger = path.join(root,'owned-watchdog-crash.trigger');
  const watchdogCrash = mode === 'crash' ? `setInterval(()=>{if(require('fs').existsSync(${q(trigger)})){${marker('watchdog-self-kill')}process.kill(process.pid,'SIGKILL');}},20);` : '';
  const watcher = write('watcher.cjs', `const b=require(${q(lib('verification-linux-namespace'))}),old=b.spawnLinuxContainedWorker;b.spawnLinuxContainedWorker=(exe,args,opts,settings)=>old(exe,args[0]===${q(lib('verification-watchdog'))}&&args[1]==='--authority'?[${q(authority)}]:args,opts,settings);${watchdogCrash}require(${q(lib('verification-watchdog'))}).__test.runStdioWatchdog();`);
  // Trusted fixture hook executes in the actual owned outer worker. Parent
  // monkeypatches no longer cross that boundary. No native return is replaced.
  const supervisorSource=fs.readFileSync(lib('verification-supervisor'),'utf8');
  const injection=`\n// Test-only boundary hook, before the module captures spawnSync.\nconst fixtureSpawnSync=require('child_process').spawnSync;
    require('child_process').spawnSync=(exe,argv,opts)=>fixtureSpawnSync(exe,argv[0]===${q(lib('verification-watchdog'))}?[${q(watcher)},...argv.slice(1)]:argv,opts);\n`;
  assert(supervisorSource.startsWith("'use strict';"));
  fs.writeFileSync(lib('verification-supervisor'),supervisorSource.replace("'use strict';","'use strict';"+injection));
  const work = ['work-timeout','preparation'].includes(mode) ? 8000 : 45000;
  const cleanup = ['signing','receipt-io'].includes(mode) ? 3000 : 15000;
  const request = {stateRoot:state,repoRoot:root,taskId:'linux-'+mode,sessionId:'linux-contract',checkedBy:'physical-linux-contract',
    sourceFiles:['probe.js'],tests:[{argv:['node','probe.js'],cwd:'.',timeout_ms:work}],timeoutMs:work,
    verificationPolicy:{work_budget_ms:work,no_progress_ms:mode.startsWith('silent')?2500:0,cleanup_budget_ms:cleanup}};
  const caller = write('caller.cjs', `const fs=require('fs');let value;try{const r=require(${q(lib('repair-on-touch'))}).runVerificationTests(${q(request)});value={status:'pass',budget:r.verification_budget,acceptances:r.verification_acceptances,ids:r.map(x=>x.record.execution_id)};}catch(e){value={status:'error',code:e.code,timed_out:e.timed_out,has_acceptance:!!e.verification_acceptances,budget:e.verification_budget,teardown:e.teardown,delivery_teardown:e.delivery_teardown,invocation_recovery:e.invocation_recovery,recovery_teardown:e.recovery_teardown};}fs.writeFileSync(${q(path.join(root,'result.json'))},JSON.stringify(value,null,2));`);
  const actor = cp.spawn(process.execPath, [caller], {stdio:['ignore','pipe','pipe']});
  let stderr='',actorClosed=false;actor.stderr.on('data',b=>stderr+=b); actor.stdout.resume();actor.once('close',()=>{actorClosed=true;});
  t.after(async () => {
    if (actor.exitCode===null && actor.signalCode===null) actor.kill('SIGKILL');
    const end=process.hrtime.bigint()+15000000000n;
    while(!actorClosed&&process.hrtime.bigint()<end)await pause(20);
    // Cleanup evidence is independent of assertions. Unknown physical closure
    // retains all fixture state; elapsed time never proves process death.
    let status=null,nativeProof=null,cleanupError=null;
    try {
      status=control.readStatus(context);
      while(status.attempt?.invocation&&process.hrtime.bigint()<end){
        nativeProof=require(lib('command-scope-proof')).queryScopeClosure(status.attempt.invocation.scope,{timeoutMs:500});
        if(nativeProof.status==='completed')break;await pause(20);
      }
      if(actorClosed&&nativeProof?.status==='completed'&&status.attempt?.claimed){const a=status.attempt;
        require(lib('verification-recovery')).recoverAttempt(context,{attempt_id:a.attempt_id,generation:a.generation});status=control.readStatus(context);}
    }catch(e){cleanupError={code:e.code,message:e.message};}
    const report={mode,root,stderr,actor_closed:actorClosed,native_proof:nativeProof,cleanup_error:cleanupError,status,
      result:fs.existsSync(path.join(root,'result.json'))?JSON.parse(fs.readFileSync(path.join(root,'result.json'))):null};
    console.log('PHYSICAL_LINUX_CONTRACT '+JSON.stringify(report));
    if(process.env.KNOWLEDGE_AUDIT_RETAIN_FIXTURES!=='1'&&actorClosed&&nativeProof?.status==='completed'&&status&&!status.attempt?.claimed&&!cleanupError)
      require(lib('strict-temp-cleanup')).removeTempDirStrict(root);
    else t.diagnostic(JSON.stringify({fixture_retained_unconfirmed:root}));
  });
  return {root,state,context,actor,work,cleanup,trigger,
    marker:name=>fs.existsSync(path.join(root,name+'.json')),
    result:async()=>{await until(()=>actorClosed,work+cleanup+20000);assert.equal(actor.exitCode,0,stderr);return JSON.parse(fs.readFileSync(path.join(root,'result.json')));}};
}

test('physical Linux work, cancellation and recovery contract', {skip:process.platform!=='linux',timeout:240000}, async t => {
  for(const mode of ['silent','silent-load','cancel','work-timeout','preparation','signing','receipt-io','crash']) {
    await t.test(mode,async t=>{
      const f=setup(t,mode);
      if(mode==='silent-load') {
        await until(()=>f.marker('command'));
        const loads=Array.from({length:2},()=>cp.spawn(process.execPath,['-e','const end=performance.now()+6000;while(performance.now()<end){}'],{stdio:'ignore'}));
        t.after(async()=>{await Promise.all(loads.map(child=>new Promise(resolve=>{if(child.exitCode!==null||child.signalCode!==null)return resolve();child.once('close',resolve);child.kill('SIGKILL');})));});
        console.log('OWNED_CPU_LOAD '+JSON.stringify(loads.map(child=>child.pid)));
      }
      if(mode==='cancel' || mode==='crash') {
        await until(()=>f.marker('command'));
        const a=control.readStatus(f.context).attempt;
        assert(a.containment?.descriptor_sha256);
        if(mode==='cancel')control.requestCancel(f.context,{attempt_id:a.attempt_id,generation:a.generation});
        else {const watchdog=a.processes.find(p=>p.role==='watchdog');assert(watchdog.pid>1);fs.writeFileSync(f.trigger,'self SIGKILL after real command admission\n');}
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
        if(mode==='crash')assert(f.marker('watchdog-self-kill'),'Living owned watchdog must observe the trigger before self SIGKILL');
        if(attempt.claimed) {
          const result=require(lib('verification-recovery')).recoverAttempt(f.context,{attempt_id:attempt.attempt_id,generation:attempt.generation});
          assert.equal(result.ack_released,false,JSON.stringify(result));
          attempt=control.readStatus(f.context).attempt;assert.equal(attempt.claimed,false);
        }
        assert.equal(attempt.terminal.ack_sha256,null);
      }
    });
  }
});
