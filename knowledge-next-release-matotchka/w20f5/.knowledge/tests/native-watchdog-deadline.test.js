'use strict';
// Physical Windows execution with narrow fault adapters in trusted controllers.
// No fake backend, platform replacement, receipt fabrication or paid provider.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const { removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');
const source = path.resolve(__dirname, '..');
const lib = name => path.join(source, 'tools/lib', name + '.js');
const q = JSON.stringify;
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
// Historical +100ms return measurements remain in the audit evidence. The
// current contract gives cleanup its own budget, not an exact return deadline.
const CLEANUP_MS = 3000;
const HARNESS_MARGIN_MS = 3000;

function scenario(root, mode, timeoutMs = 5000) {
  fs.mkdirSync(root, { recursive: true });
  fs.mkdirSync(path.join(root, '.knowledge'));
  const write = (name, body) => { const file = path.join(root, name); fs.writeFileSync(file, body); return file; };
  const mark = phase => `require('fs').writeFileSync(${q(path.join(root, phase + '.json'))},JSON.stringify({pid:process.pid,ppid:process.ppid,phase:${q(phase)},at_ns:String(process.hrtime.bigint())}));`;
  write('probe.js', mark('command') + 'process.stdout.write("ok");');
  if (mode === 'watchdog-crash') {
    const descendant = write('descendant.js', mark('descendant') + 'setInterval(()=>{},1000);');
    write('probe.js', mark('command') + `const cp=require('child_process'),fs=require('fs');const c=cp.spawn(process.execPath,[${q(descendant)}],{detached:true,stdio:'ignore'});c.unref();const timer=setInterval(()=>{if(fs.existsSync(${q(path.join(root, 'descendant.json'))})){clearInterval(timer);process.kill(JSON.parse(fs.readFileSync(${q(path.join(root, 'watcher.json'))},'utf8')).pid,'SIGKILL');}},20);setInterval(()=>{},1000);`);
  }
  const stall = phase => mark(phase) + 'const until=performance.now()+8000;while(performance.now()<until){};';
  let authorityFault = '';
  if (mode === 'preparation') authorityFault = `const c=require('crypto'),f=c.generateKeyPairSync;c.generateKeyPairSync=(...a)=>{${stall(mode)}return f(...a);};`;
  if (mode === 'signing') authorityFault = `const c=require('crypto'),f=c.sign;c.sign=(...a)=>{${stall(mode)}return f(...a);};`;
  if (mode === 'readback' || mode === 'receipt-io') {
    const supervisor = write('fault-supervisor.cjs', mark('supervisor') +
      (mode === 'readback'
        ? `const c=require(${q(lib('verification-execution'))}),f=c.readNativeRecord;c.readNativeRecord=(...a)=>{if(a[2]==='verification_finalizations'){${stall(mode)}}return f(...a);};`
        : `require(${q(lib('verification-finalization'))}).persistFinalization=()=>{${mark(mode)}setInterval(()=>{},1000);return new Promise(()=>{});};`) +
      `require(${q(lib('verification-supervisor'))}).__test.runStdioSupervisor();`);
    authorityFault = `const cp=require('child_process'),old=cp.spawnSync;cp.spawnSync=(exe,args,opts)=>old(exe,args[0]===${q(lib('verification-supervisor'))}?[${q(supervisor)},...args.slice(1)]:args,opts);`;
  }
  if (mode === 'authority-crash') authorityFault = `const c=require('crypto');c.generateKeyPairSync=()=>{${mark(mode)}process.exit(7);};`;
  const authority = write('authority.cjs', mark('authority') + authorityFault + `require(${q(lib('verification-watchdog'))}).__test.runAuthority();`);
  const watcher = write('watcher.cjs', mark('watcher') +
    `const cp=require('child_process'),old=cp.spawn;cp.spawn=(exe,args,opts)=>old(exe,args[0]===${q(lib('verification-watchdog'))}&&args[1]==='--authority'?[${q(authority)}]:args,opts);require(${q(lib('verification-watchdog'))}).__test.runStdioWatchdog();`);
  const request = { stateRoot: path.join(root, '.knowledge'), repoRoot: root,
    taskId: 'wall-return', sessionId: 'wall-return', checkedBy: 'physical-deadline-test',
    sourceFiles: ['probe.js'], tests: [{ argv: ['node', 'probe.js'], cwd: '.', timeout_ms: 15000 }], timeoutMs,
    verificationPolicy: { work_budget_ms: timeoutMs, no_progress_ms: 0, cleanup_budget_ms: CLEANUP_MS } };
  const parent = write('caller.cjs', `const cp=require('child_process'),old=cp.spawnSync;cp.spawnSync=(exe,args,opts)=>old(exe,args[0]===${q(lib('verification-watchdog'))}?[${q(watcher)}]:args,opts);const native=require(${q(lib('repair-on-touch'))});const start=performance.now();let value;try{const r=native.runVerificationTests(${q(request)});value={status:'pass',budget:r.verification_budget,acceptances:r.verification_acceptances,ids:r.map(x=>x.record.execution_id)};}catch(e){value={status:'error',code:e.code,stage:e.stage,timed_out:e.timed_out,budget:e.verification_budget,teardown:e.teardown,authority_teardown:e.authority_teardown,has_acceptance:!!e.verification_acceptances};}value.caller_elapsed_ms=performance.now()-start;process.stdout.write(JSON.stringify(value));`);
  const child = spawnSync(process.execPath, [parent], { encoding: 'utf8', windowsHide: true, timeout: timeoutMs + 12000 });
  assert.equal(child.status, 0, child.stderr); assert(!child.error);
  return JSON.parse(child.stdout);
}

test('physical authority watchdog bounds preparation/readback/signing and gates ACK on both Jobs', { skip: process.platform !== 'win32', timeout: 80000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-watchdog-'));
  const observations = [];
  try {
    for (const mode of ['control', 'preparation', 'readback', 'signing', 'receipt-io', 'authority-crash', 'watchdog-crash']) {
      await t.test(mode, async () => {
        const fixture = path.join(root, mode), observed = scenario(fixture, mode);
        const markers = fs.readdirSync(fixture).filter(name => name.endsWith('.json'))
          .map(name => JSON.parse(fs.readFileSync(path.join(fixture, name), 'utf8')));
        const stop = performance.now() + 7000;
        while (markers.some(item => alive(item.pid)) && performance.now() < stop) await delay(20);
        const remaining = markers.filter(item => alive(item.pid));
        const store = name => {
          const directory = path.join(fixture, '.knowledge/maintenance', name);
          return fs.existsSync(directory) ? fs.readdirSync(directory).filter(name => name.endsWith('.json')) : [];
        };
        const kve = store('verification_executions'), kvf = store('verification_finalizations');
        observations.push({ mode, observed, markers, remaining, fixture, kve, kvf,
          work_budget_ms: 5000, cleanup_budget_ms: CLEANUP_MS, harness_margin_ms: HARNESS_MARGIN_MS,
          historical_strict_return_requirement: 'superseded_by_user_20261020' });
        assert.deepEqual(remaining, [], 'Every observed process of this run must exit');
        if (mode === 'control') {
          assert.equal(observed.status, 'pass'); assert.equal(observed.acceptances.length, 1);
          for (const teardown of [observed.budget.teardown, observed.budget.authority_teardown]) {
            assert.equal(teardown.status, 'completed'); assert.equal(teardown.active_processes, 0);
          }
        } else {
          assert.equal(observed.status, 'error'); assert.equal(observed.has_acceptance, false);
          assert(markers.some(item => item.phase === (mode === 'watchdog-crash' ? 'descendant' : mode)), 'Fault must physically reach its intended phase');
          if (mode === 'authority-crash') assert.equal(observed.code, 'verification_authority_exited');
          else if (mode === 'watchdog-crash') {
            assert.equal(observed.code, 'verification_transport_failed');
            assert.equal(observed.teardown.status, 'unconfirmed');
          }
          else {
            if (mode === 'preparation') {
              assert.equal(observed.code, 'verification_timeout'); assert.equal(observed.timed_out, true);
            } else assert.equal(observed.code, 'verification_cleanup_unconfirmed');
            assert(observed.caller_elapsed_ms < 5000 + CLEANUP_MS + HARNESS_MARGIN_MS,
              `Actual API return ${observed.caller_elapsed_ms}ms exceeds the fault harness bound`);
          }
          if (mode === 'preparation') assert(!markers.some(item => item.phase === 'command'));
          else if (mode !== 'authority-crash') assert(markers.some(item => item.phase === 'command'));
          if (['readback', 'signing', 'receipt-io'].includes(mode)) {
            assert.equal(kve.length, 1);
            assert.equal(kvf.length, mode === 'receipt-io' ? 0 : 1);
            assert.throws(() => require('../tools/lib/verification-finalization').requireFinalizedExecutions(
              path.join(fixture, '.knowledge'), ['KVE-' + kve[0].slice(0, -5)], []), error => error.code === 'verification_finalization_required');
          }
        }
      });
    }
  } finally {
    console.log(JSON.stringify({ schema: 'physical-watchdog-deadline-test.v1', observations, fixture_root: root }));
    if (process.env.KNOWLEDGE_AUDIT_RETAIN_FIXTURES !== '1') removeTempDirStrict(root);
  }
});

test('dense inert admission shares the original deadline without child execution', { skip: process.platform !== 'win32' }, () => {
  const native = require('../tools/lib/repair-on-touch');
  const request = { tests: [{ argv: ['node', 'probe.js'], timeout_ms: 1000 }], timeoutMs: 1,
    extra: Array(90000).fill(1), stateRoot: 'not-created', repoRoot: 'not-created' };
  const start = performance.now();
  let error; try { native.runVerificationTests(request); } catch (caught) { error = caught; }
  const elapsed = performance.now() - start;
  assert.equal(error?.code, 'verification_timeout');
  assert.equal(error?.teardown.status, 'not_required');
  assert.equal(error.verification_budget.reason, 'insufficient_execution_budget');
  assert(elapsed < 2000, `Admission unexpectedly blocked for ${elapsed}ms`);
  console.log(JSON.stringify({ admission_elapsed_ms: elapsed, timeout_ms: 1,
    purpose: 'fault_admission_only', strict_millisecond_return: 'superseded' }));
});

module.exports = { scenario };
