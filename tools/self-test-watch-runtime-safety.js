#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { systemVersion } = require('./lib/system-version');

const systemRoot = path.resolve(__dirname, '..');
const checks = [];
function check(name, fn) { fn(); checks.push(name); }
function write(file, body) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, body); }
function read(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } }
async function waitFor(predicate, label, timeout = 5000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
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
    KNOWLEDGE_SMOKE_WATCH_MS: '15000', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1', KNOWLEDGE_FLOW_NO_OPEN: '1',
    ...extra
  };
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  if (child.connected) child.send({ type: 'knowledge:watch-stop' });
  else child.kill('SIGTERM');
  try { await waitFor(() => child.exitCode !== null || child.signalCode !== null, 'watcher termination', 5000); }
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

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-watch-safety-'));
  let child = null;
  try {
    const realRepo = path.join(root, 'real-repo');
    const realSystem = path.join(realRepo, '.knowledge');
    fs.cpSync(systemRoot, realSystem, { recursive: true });
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
    fs.cpSync(systemRoot, installed, { recursive: true });
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
    write(sync, `const fs=require('fs');fs.writeFileSync(${JSON.stringify(childPid)},JSON.stringify({pid:process.pid}));process.on('SIGTERM',()=>{fs.writeFileSync(${JSON.stringify(childExit)},JSON.stringify({terminated:true}));process.exit(0)});setInterval(()=>{},1000);\n`);
    const subscriptionTrace = path.join(state, 'watch-subscriptions.jsonl');
    const watchProbe = path.join(root, 'watch-subscriptions-preload.js');
    write(watchProbe, `const fs=require('fs');const original=fs.watch;fs.watch=function(file,options,...rest){fs.appendFileSync(${JSON.stringify(subscriptionTrace)},JSON.stringify({file:String(file),recursive:options?.recursive===true})+'\\n');return original.call(this,file,options,...rest)};\n`);
    let diagnostics = '';
    child = spawn(process.execPath, ['--require', watchProbe, path.join(installed, 'tools/watch-maintenance.js')], { cwd: repo, env: envFor(repo, installed, state), stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
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
    const active = await waitFor(() => read(childPid), 'sync child launch');
    await stop(child);
    check('graceful watcher stop waits for owned active sync child to terminate', () => {
      assert.equal(child.exitCode, 0);
      if (process.platform !== 'win32') assert.equal(read(childExit)?.terminated, true);
      else assert.equal(read(statusPath)?.automation_health, 'degraded_watcher_sync_interrupted');
      assert.throws(() => process.kill(active.pid, 0), error => error.code === 'ESRCH');
    });
    child = null;
    check('terminated watcher leaves no runtime watcher record', () => assert.equal(fs.readdirSync(path.join(state, '.runtime/watchers')).length, 0));

    const faultState = path.join(repo, 'watch-fault-state');
    const hook = path.join(root, 'watch-denied-preload.js');
    write(hook, "require('fs').watch=()=>{const e=new Error('fixture watch denied');e.code='EACCES';throw e;};\n");
    const denied = spawnSync(process.execPath, ['--require', hook, path.join(installed, 'tools/watch-maintenance.js')], { cwd: repo, env: envFor(repo, installed, faultState), encoding: 'utf8', timeout: 6000 });
    check('unavailable native and fallback watchers fail closed', () => { assert.equal(denied.status, 1); assert(denied.stderr.includes('fixture watch denied')); });
    check('watch-start failure does not leave false healthy running state', () => { const s=read(path.join(faultState,'maintenance/automation_status.json'));assert.equal(s.watcher_running,false);assert.equal(s.automation_health,'degraded_watcher_error'); });

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
