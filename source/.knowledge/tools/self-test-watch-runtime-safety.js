#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { systemVersion } = require('./lib/system-version');

const systemRoot = path.resolve(__dirname, '..');
const checks = [];
function check(name, fn) { fn(); checks.push(name); }
function write(file, body) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, body); }
function read(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } }
async function waitFor(predicate, label, timeout = 12000) {
  const deadline = performance.now() + timeout;
  while (performance.now() < deadline) {
    const value = predicate(); if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`Timed out: ${label}`);
}
function envFor(repo, installed, stateRoot, extra = {}) {
  return {
    ...process.env, KNOWLEDGE_SYSTEM_ROOT: installed, KNOWLEDGE_TARGET_ROOT: repo,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(repo, '.knowledge'), KNOWLEDGE_STATE_ROOT: stateRoot,
    KNOWLEDGE_WATCH_DEBOUNCE_MS: '80', KNOWLEDGE_WATCH_HEARTBEAT_MS: '100',
    KNOWLEDGE_WORK_TIMEOUT_MS: '15000', KNOWLEDGE_SETUP_TIMEOUT_MS: '10000', KNOWLEDGE_CLEANUP_TIMEOUT_MS: '5000',
    KNOWLEDGE_SMOKE_WATCH_MS: '15000', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1', KNOWLEDGE_FLOW_NO_OPEN: '1',
    ...extra
  };
}
async function stop(child) {
  if (!child) return;
  if (child.exitCode !== null || child.signalCode !== null) { await child.fixtureClosed;return; }
  if (child.connected) child.send({ type: 'knowledge:watch-stop' }, () => {});
  else child.kill('SIGTERM');
  try { await waitFor(() => child.exitCode !== null || child.signalCode !== null, 'watcher termination', 12000);await child.fixtureClosed; }
  catch (error) { child.kill('SIGKILL'); throw error; }
}
async function ready(child, file, diagnostics) {
  return waitFor(() => {
    if (child.exitCode !== null) throw new Error(`Watcher exited ${child.exitCode}: ${diagnostics()}`);
    const status = read(file);
    return Object.values(status?.active_watchers || {}).some(row => row.pid === child.pid && row.running === true);
  }, 'watcher readiness');
}
function noProbeFiles(repo) { return !fs.readdirSync(repo).some(name => name.startsWith('knowledge-smoke-probe-')); }
function copySystem(destination) {
  fs.cpSync(systemRoot, destination, { recursive: true, filter: file => !['locks', '.runtime'].includes(path.relative(systemRoot, file).split(path.sep)[0]) });
}
function assertNativeStop(receipt) {
  assert(receipt, 'The managed watcher must publish its actual terminal result');
  const value = receipt.value || receipt.error?.watcher, cleanup = receipt.value?.cleanup || receipt.error?.cleanup;
  assert.equal(cleanup?.status, 'completed');assert.equal(cleanup.output_closed, true);assert.equal(cleanup.active_processes, 0);
  assert.equal(value?.ownership?.scope?.schema_version, 'knowledge-command-scope.v1');
  if (process.platform === 'linux') {
    assert.equal(cleanup.method, 'linux_pid_namespace');assert.equal(cleanup.namespace_drained, true);
    assert.equal(cleanup.descriptor_sha256, crypto.createHash('sha256').update(JSON.stringify(value.ownership.scope.descriptor)).digest('hex'));
  } else {
    assert.equal(cleanup.method, 'windows_job_object');assert.equal(cleanup.root_exited, true);assert.equal(cleanup.primary_holder_exited, true);
    assert.equal(value.ownership.scope.backend, 'windows_job_object');
  }
  return value;
}

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-watch-safety-'));
  let child = null;
  try {
    const realRepo = path.join(root, 'real-repo');
    const realSystem = path.join(realRepo, '.knowledge');
    copySystem(realSystem);
    const config = path.join(realSystem, 'config.yaml');
    fs.writeFileSync(config, fs.readFileSync(config, 'utf8').replace(/(updates:\s*\r?\n\s+enabled:)\s*true/, '$1 false').replace(/(auto_check_on_inspector_open:)\s*true/g, '$1 false'));
    write(path.join(realRepo, 'smoke-probe.txt'), 'USER CONTENT MUST SURVIVE\n');
    write(path.join(realRepo, 'src/probe.js'), 'module.exports = true;\n');
    const actualSmoke = spawnSync(process.execPath, [path.join(realSystem, 'tools/watch-smoke.js')], {
      cwd: realRepo, env: envFor(realRepo, realSystem, realSystem), encoding: 'utf8', timeout: 25000
    });
    check('real watcher detects its probe and completes actual sync-tracked command', () => assert.equal(actualSmoke.status, 0, `${actualSmoke.stdout}\n${actualSmoke.stderr}`));
    const smokeReport = JSON.parse(actualSmoke.stdout);
    check('smoke result confirms teardown before PASS', () => { assert(smokeReport.watcher_stopped); assert(smokeReport.probe_removed); assert(smokeReport.probe_observed); });
    check('smoke never overwrites or deletes existing user probe filename', () => assert.equal(fs.readFileSync(path.join(realRepo, 'smoke-probe.txt'), 'utf8'), 'USER CONTENT MUST SURVIVE\n'));
    check('smoke removes only its unique temporary probe', () => assert(noProbeFiles(realRepo)));
    check('smoke shutdown clears live watcher status', () => assert.equal(read(path.join(realSystem, 'maintenance/automation_status.json')).watcher_running, false));

    const installed = path.join(root, 'separate-system');
    copySystem(installed);
    const privateWorker = path.join(installed, 'tools/lib/watch-maintenance-worker.js'), originalWorker = fs.readFileSync(privateWorker, 'utf8');
    const workerAnchor = 'module.exports = async function runWatcher(payload, runtime) {';
    assert.equal(originalWorker.split(workerAnchor).length, 2, 'The private fixture requires the exact storage-worker entry');
    function instrumentPrivateWorker(hook) {
      write(privateWorker, originalWorker.replace(workerAnchor, workerAnchor + '\n(function(){\n' + hook + '\n})();\n'));
    }
    const entry = path.join(root, 'managed-watch-entry.cjs');
    write(entry, `'use strict';const watcher=require(${JSON.stringify(path.join(installed, 'tools/watch-maintenance.js'))});
function done(result){process.exitCode=result.ok?0:1;if(!result.ok){const e=result.error||result.value?.error||{};console.error('Watcher failed ['+(e.code||e.name)+']: '+e.message);}
 const receipt={type:'fixture:watch-terminal',...result};if(process.connected)process.send(receipt,()=>process.disconnect());else console.log(JSON.stringify(receipt));}
watcher.main([]).then(value=>done({ok:value.status!=='failed',value}),error=>done({ok:false,error:{code:error.code,name:error.name,message:error.message,cleanup:error.cleanup,watcher:error.watcher}}));\n`);
    const repo = path.join(root, 'separate-repo');
    const state = path.join(repo, 'custom-runtime');
    write(path.join(repo, '.knowledge/config.yaml'), 'updates:\n  enabled: false\n');
    write(path.join(repo, 'smoke-probe.txt'), 'PRESERVE ON FAILURE\n');
    const sync = path.join(installed, 'tools/sync-tracked.js');
    write(sync, 'process.exit(7);\n');
    const failedSmoke = spawnSync(process.execPath, [path.join(installed, 'tools/watch-smoke.js')], { cwd: repo, env: envFor(repo, installed, state), encoding: 'utf8', timeout: 15000 });
    check('smoke propagates real sync failure instead of reporting PASS', () => { assert.notEqual(failedSmoke.status, 0); assert(failedSmoke.stderr.includes('Watcher sync failed')); assert(!failedSmoke.stdout.includes('"status": "pass"')); });
    check('failed smoke cleans up child and temporary probe', () => { assert(noProbeFiles(repo)); assert.equal(read(path.join(state, 'maintenance/automation_status.json')).watcher_running, false); });
    check('failed smoke preserves unrelated file content', () => assert.equal(fs.readFileSync(path.join(repo, 'smoke-probe.txt'), 'utf8'), 'PRESERVE ON FAILURE\n'));
    check('watcher reports nonzero sync without fabricating successful maintenance time', () => { const s = read(path.join(state, 'maintenance/automation_status.json')); assert.equal(s.last_sync_exit_code, 7); assert.equal(s.automation_health, 'degraded_watcher_sync_error'); assert(!s.last_auto_maintenance_at); });

    const childPid = path.join(state, 'active-sync-pid.json');
    const childExit = path.join(state, 'active-sync-exited.json');
    const childTrace = path.join(state, 'active-sync-progress.ndjson');
    write(sync, `const fs=require('fs');fs.writeFileSync(${JSON.stringify(childPid)},JSON.stringify({pid:process.pid}));process.on('SIGTERM',()=>{fs.writeFileSync(${JSON.stringify(childExit)},JSON.stringify({terminated:true}));process.exit(0)});let sequence=0;setInterval(()=>fs.appendFileSync(${JSON.stringify(childTrace)},JSON.stringify({sequence:++sequence})+'\\n'),30);\n`);
    const subscriptionTrace = path.join(state, 'watch-subscriptions.jsonl');
    instrumentPrivateWorker(`const fs=require('fs');const original=fs.watch;fs.watch=function(file,options,...rest){fs.appendFileSync(${JSON.stringify(subscriptionTrace)},JSON.stringify({file:String(file),recursive:options?.recursive===true})+'\\n');return original.call(this,file,options,...rest)};`);
    let diagnostics = '';
    child = spawn(process.execPath, [entry], { cwd: repo, env: envFor(repo, installed, state), stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    const activeWatcher = child;activeWatcher.fixtureTerminal = null;
    activeWatcher.on('message', message => { if (message?.type === 'fixture:watch-terminal') { assert.equal(activeWatcher.fixtureTerminal, null);activeWatcher.fixtureTerminal = message; } });
    activeWatcher.fixtureClosed = new Promise(resolve => activeWatcher.once('close', resolve));
    child.stderr.on('data', chunk => { diagnostics += chunk; });
    const statusPath = path.join(state, 'maintenance/automation_status.json');
    await ready(child, statusPath, () => diagnostics);
    for (let index = 0; index < 20; index += 1) {
      const transient = path.join(state, 'locks/v1/.release', `synthetic-release-${index}.lock`);
      fs.mkdirSync(transient, { recursive: true });
      fs.writeFileSync(path.join(transient, 'owner.json'), '{}');
      fs.rmSync(transient, { recursive: true });
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    check('watch subscriptions exclude transient runtime trees before native traversal', () => {
      const subscriptions = fs.readFileSync(subscriptionTrace, 'utf8').trim().split('\n').map(line => JSON.parse(line));
      assert(subscriptions.length > 0);
      assert(subscriptions.every(row => !row.recursive));
      assert(subscriptions.every(row => !path.resolve(row.file).startsWith(path.resolve(state) + path.sep)));
      assert.equal(child.exitCode, null, diagnostics);
    });
    // The runtime directory sits inside the target. Its own heartbeat writes
    // must not recursively become source changes.
    await new Promise(resolve => setTimeout(resolve, 350));
    check('custom stateRoot heartbeat does not trigger a sync feedback loop', () => assert(!fs.existsSync(childPid)));
    write(path.join(repo, 'source-change.txt'), 'trigger owned sync\n');
    await waitFor(() => read(childPid), 'sync child launch');
    await waitFor(() => fs.existsSync(childTrace), 'actual admitted sync progress');
    await stop(child);
    check('graceful watcher stop waits for owned active sync child to terminate', () => {
      assert.equal(child.exitCode, 0);
      const terminal = assertNativeStop(child.fixtureTerminal);
      assert.equal(terminal.durable_stop_confirmed, true);assert.equal(terminal.sync_interrupted, true);
      assert.equal(read(statusPath)?.automation_health, 'degraded_watcher_sync_interrupted');
      assert.equal(read(statusPath).watcher_running, false);
    });
    const stoppedTrace = fs.readFileSync(childTrace);await new Promise(resolve => setTimeout(resolve, 150));
    check('confirmed native drain prevents late sync writes without interpreting namespace-local PID numbers', () => assert.deepEqual(fs.readFileSync(childTrace), stoppedTrace));
    child = null;
    check('terminated watcher leaves no runtime watcher record', () => assert.equal(fs.readdirSync(path.join(state, '.runtime/watchers')).length, 0));

    const faultState = path.join(repo, 'watch-fault-state');
    instrumentPrivateWorker("require('fs').watch=()=>{const e=new Error('fixture watch denied');e.code='EACCES';throw e;};");
    const denied = spawnSync(process.execPath, [entry], { cwd: repo, env: envFor(repo, installed, faultState), encoding: 'utf8', timeout: 12000 });
    check('unavailable native and fallback watchers fail closed', () => { assert.equal(denied.status, 1); assert(denied.stderr.includes('fixture watch denied')); });
    check('watch-start failure confirms native drain and preserves its primary refusal', () => { const receipt=JSON.parse(denied.stdout);assert.equal(receipt.ok,false);const value=assertNativeStop(receipt);assert.equal(value.error.code,'EACCES'); });
    check('watch-start failure does not leave false healthy running state', () => { const s=read(path.join(faultState,'maintenance/automation_status.json'));assert.equal(s.watcher_running,false);assert.equal(s.automation_health,'degraded_watcher_error'); });
    write(privateWorker, originalWorker);

    for (const script of ['watch-maintenance.js', 'watch-smoke.js']) {
      const before = fs.existsSync(path.join(root, 'help-state'));
      const result = spawnSync(process.execPath, [path.join(installed, 'tools', script), '--help'], { cwd: repo, env: envFor(repo, installed, path.join(root,'help-state')), encoding: 'utf8', timeout: 3000 });
      check(`${script} help exits without starting or writing a watcher`, () => { assert.equal(result.status,0);assert(result.stdout.includes('Usage:'));assert.equal(fs.existsSync(path.join(root,'help-state')),before); });
    }
    const invalid = spawnSync(process.execPath,[path.join(installed,'tools/watch-maintenance.js')],{cwd:repo,env:envFor(repo,installed,path.join(root,'invalid-state'),{KNOWLEDGE_WATCH_DEBOUNCE_MS:'NaN'}),encoding:'utf8',timeout:3000});
    check('invalid watch timing is rejected before state writes',()=>{assert.notEqual(invalid.status,0);assert(!fs.existsSync(path.join(root,'invalid-state')));});
    console.log(JSON.stringify({schema_version:systemVersion(),status:'pass',checks_total:checks.length,checks},null,2));
  } finally { await stop(child); fs.rmSync(root,{recursive:true,force:true}); }
}
main().catch(error=>{console.error(JSON.stringify({status:'failed',checks_total:checks.length,checks,error:error.stack||error.message},null,2));process.exitCode=1;});
