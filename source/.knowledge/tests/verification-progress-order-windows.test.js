'use strict';
// Real native verification with one trusted transport timing adapter. The
// adapter delays delivery of observed final frames without changing any byte,
// ordering, Job implementation, native proof, candidate, or acceptance reader.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');
const crypto = require('crypto');
const source = path.resolve(__dirname, '..');
const lib = name => path.join(source, 'tools/lib', name + '.js');
const q = JSON.stringify;
const opts = { skip: process.platform !== 'win32', timeout: 90000 };
function scenario(t, mode) {
  const parent = process.env.KNOWLEDGE_PROGRESS_ORDER_EVIDENCE_ROOT || os.tmpdir();
  fs.mkdirSync(parent, { recursive: true });
  const root = fs.mkdtempSync(path.join(parent, 'windows-progress-order-'));
  fs.mkdirSync(path.join(root, '.knowledge'));
  const file = (name, content) => { const target = path.join(root, name); fs.writeFileSync(target, content); return target; };
  const trace = path.join(root, 'actual-progress.jsonl');
  file('probe.js', mode === 'timeout'
    ? "const fs=require('fs');const target=BigInt(fs.readFileSync('probe-target.txt','utf8'));while(process.hrtime.bigint()<target){};process.stdout.write('ok');"
    : "process.stdout.write('ok');");
  const watchdog = file('watchdog-timing.cjs', `
    const fs=require('fs'),p=require(${q(lib('verification-progress'))}),c=require(${q(lib('verification-control'))});
    const context={stateRoot:${q(path.join(root, '.knowledge'))}},original=p.listen;
    const log=value=>fs.appendFileSync(${q(trace)},JSON.stringify({at_ns:String(process.hrtime.bigint()),...value})+'\\n');
    p.listen=(events,errors)=>{
      let pending=null,queue=[];
      const enqueue=(kind,event)=>{queue.push({kind,event});log({action:'held',kind,event});};
      const flush=()=>{const captured=queue;queue=[];pending=null;for(const item of captured){log({action:'delivered',...item});(item.kind==='event'?events:errors)(item.event);}};
      return original(event=>{
        if(pending){enqueue('event',event);return;}
        if(event.type==='work_completed'){
          enqueue('event',event);pending=setTimeout(flush,400);
          ${mode === 'cancel' ? `setTimeout(()=>{const a=c.readStatus(context).attempt;const result=c.requestCancel(context,{attempt_id:a.attempt_id,generation:a.generation});log({action:'cancel',status:result.status});},100);` : ''}
          return;
        }
        log({action:'delivered',kind:'event',event});return events(event);
      },error=>{if(pending)enqueue('error',error);else{log({action:'delivered',kind:'error',event:error});errors(error);}});
    };
    require(${q(lib('verification-watchdog'))}).__test.runStdioWatchdog();`);
  const caller = file('caller.cjs', `
    const cp=require('child_process'),fs=require('fs'),original=cp.spawnSync;
    cp.spawnSync=(exe,args,options)=>{
      const actual=original(exe,args[0]===${q(lib('verification-watchdog'))}?[${q(watchdog)},...args.slice(1)]:args,options);
      if(args[0]===${q(lib('verification-watchdog'))})fs.writeFileSync(${q(path.join(root, 'actual-watchdog-transport.json'))},JSON.stringify({status:actual.status,signal:actual.signal,error:actual.error&&{code:actual.error.code,message:actual.error.message},stdout:actual.stdout,stderr:actual.stderr},null,2));
      return actual;
    };
    const n=require(${q(lib('repair-on-touch'))}),c=require(${q(lib('verification-control'))});
    const start=process.hrtime.bigint();
    ${mode === 'timeout' ? "fs.writeFileSync('probe-target.txt',String(start+4700000000n));" : ''}
    let result;
    try{const value=n.runVerificationTests({stateRoot:${q(path.join(root, '.knowledge'))},repoRoot:${q(root)},taskId:'progress-order',sessionId:'progress-order',checkedBy:'physical-progress-order',sourceFiles:['probe.js'],tests:[{argv:['node','probe.js'],cwd:'.',timeout_ms:30000}],timeoutMs:${mode === 'timeout' ? 5000 : 120000},verificationPolicy:{work_budget_ms:${mode === 'timeout' ? 5000 : 120000},no_progress_ms:60000,cleanup_budget_ms:30000}});result={status:'pass',ids:value.map(x=>x.record.execution_id),acceptances:value.verification_acceptances,budget:value.verification_budget};}
    catch(error){result={status:'error',code:error.code,message:error.message,timed_out:error.timed_out,budget:error.verification_budget,has_acceptance:!!error.verification_acceptances};}
    result.elapsed_ms=Number(process.hrtime.bigint()-start)/1e6;result.attempt=c.readStatus({stateRoot:${q(path.join(root, '.knowledge'))}}).attempt;
    fs.writeFileSync(${q(path.join(root, 'result.json'))},JSON.stringify(result,null,2));console.log(JSON.stringify(result));`);
  const pins = {};
  for (const name of ['verification-control', 'verification-supervisor', 'verification-watchdog', 'verification-progress', 'verification-windows-job', 'verification-windows-recovery']) {
    const target = lib(name); pins[path.basename(target)] = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  }
  file('source-pins.json', JSON.stringify({ platform: process.platform, node: process.version, execPath: process.execPath,
    node_sha256: crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'), pins, mode, delay_ms: 400 }, null, 2));
  const child = cp.spawnSync(process.execPath, [caller], { encoding: 'utf8', cwd: root, windowsHide: true, timeout: 80000 });
  file('caller.stdout.log', child.stdout || ''); file('caller.stderr.log', child.stderr || '');
  t.after(() => {
    console.log(JSON.stringify({ native_fixture: root, mode }));
    if (!process.env.KNOWLEDGE_PROGRESS_ORDER_EVIDENCE_ROOT) fs.rmSync(root, { recursive: true, force: true });
  });
  assert.ifError(child.error); assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  const events = fs.readFileSync(trace, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
  assert(events.some(x => x.action === 'held' && x.event?.type === 'work_completed'), 'real final progress frame reached the timing boundary');
  return { result, events, root };
}
test('Windows completed candidate waits for legitimately delayed final progress before ACK', opts, t => {
  const { result, events } = scenario(t, 'success');
  assert.equal(result.status, 'pass', result.message); assert.equal(result.acceptances.length, 1);
  assert.equal(result.attempt.terminal.outcome, 'passed'); assert.match(result.attempt.terminal.ack_sha256, /^[a-f0-9]{64}$/);
  assert(events.some(x => x.action === 'delivered' && x.event?.type === 'work_completed'));
});
test('Windows cancellation while completed candidate awaits final progress cannot release ACK', opts, t => {
  const { result, events } = scenario(t, 'cancel');
  assert(events.some(x => x.action === 'cancel' && x.status === 'cancel_requested'));
  assert.equal(result.status, 'error'); assert.equal(result.code, 'verification_cancelled');
  assert.equal(result.has_acceptance, false); assert.equal(result.attempt.terminal.outcome, 'cancelled');
  assert.equal(result.attempt.terminal.ack_sha256, null);
});
test('Windows work deadline while completed candidate awaits final progress cannot release ACK', opts, t => {
  const { result } = scenario(t, 'timeout');
  assert.equal(result.status, 'error'); assert.equal(result.timed_out, true);
  assert.equal(result.has_acceptance, false); assert.equal(result.attempt.terminal.outcome, 'timed_out');
  assert.equal(result.attempt.terminal.ack_sha256, null);
});
