'use strict';

// Actual public controller, actual fs.watch and native whole-tree custody.
// The fsync case injects a bounded synchronous stall into a PRIVATE copy of
// the state worker; it never substitutes a signal/PID heuristic for closure.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const cp = require('node:child_process');
const proof = require('../tools/lib/command-scope-proof');
const { captureTempDirIdentity, removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');
const systemRoot = path.resolve(__dirname, '..');
const supported = ['linux', 'win32'].includes(process.platform);
const policy = { workMs: 10000, setupMs: 30000, cleanupMs: 10000, progressMs: 0 };
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function read(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT' || error instanceof SyntaxError) return null;throw error; } }
async function until(predicate, label, timeout = 45000) {
  const deadline = performance.now() + timeout;
  while (performance.now() < deadline) { const result = predicate();if (result) return result;await pause(20); }
  throw new Error('Timed out: ' + label);
}
function assertNativeClosed(value) {
  assert.equal(value?.status, 'completed', JSON.stringify(value));
  assert.equal(value.active_processes, 0, JSON.stringify(value));
}
async function observeClosed(scope) {
  assert.equal(proof.validateExecutionScope(scope), true, 'Fresh observer receives a valid birth-bound complete scope');
  return until(() => {
    const result = proof.queryScopeClosure(scope, { timeoutMs: 2000 });
    return result.status === 'completed' && result.active_processes === 0 ? result : false;
  }, 'fresh native whole-tree closure', policy.cleanupMs + 3000);
}
async function fixture(t, { blockedState = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owned-watch-native-'));
  const identity = captureTempDirIdentity(root);
  const repo = path.join(root, 'repo'), state = path.join(root, 'state'), synthetic = path.join(root, 'synthetic-system');
  for (const directory of [path.join(repo, '.knowledge'), state, path.join(synthetic, 'tools')]) fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(repo, '.knowledge', 'config.yaml'), 'updates:\n  enabled: false\n');
  fs.writeFileSync(path.join(repo, 'source.js'), 'fixture initial\n');
  const admitted = path.join(state, 'sync-admitted.json'), descendant = path.join(state, 'descendant-admitted.json');
  const late = path.join(state, 'forbidden-late-write'), blocked = path.join(state, 'fsync-blocked.json'), arm = path.join(state, 'arm-fsync-stall');
  const lateGate = path.join(state, 'release-late-write');
  const detached = "const fs=require('fs');fs.writeFileSync(" + JSON.stringify(descendant) +
    ",JSON.stringify({pid:process.pid}));setInterval(()=>{if(fs.existsSync(" + JSON.stringify(lateGate) +
    "))fs.writeFileSync(" + JSON.stringify(late) + ",'descendant survived');},20);setTimeout(()=>process.exit(0),20000);";
  fs.writeFileSync(path.join(synthetic, 'tools/sync-tracked.js'),
    "const fs=require('fs'),cp=require('child_process');const child=cp.spawn(process.execPath,['-e'," +
    JSON.stringify(detached) + "],{detached:true,stdio:'ignore'});child.unref();fs.writeFileSync(" +
    JSON.stringify(admitted) + ",JSON.stringify({pid:process.pid}));setTimeout(()=>process.exit(0),20000);\n");
  let runtime = systemRoot, instrumentedHash = null;
  const originalHash = hash(path.join(systemRoot, 'tools/lib/watch-maintenance-worker.js'));
  if (blockedState) {
    runtime = path.join(root, 'private-runtime');fs.cpSync(systemRoot, runtime, { recursive: true });
    const file = path.join(runtime, 'tools/lib/watch-maintenance-worker.js'), source = fs.readFileSync(file, 'utf8');
    const anchor = 'module.exports = async function runWatcher(payload, runtime) {';
    assert.equal(source.split(anchor).length, 2, 'Fixture insertion must bind the exact owned-worker entry');
    const hook = "\n  (()=>{const realFsync=fs.fsyncSync;let once=false;fs.fsyncSync=function(fd){" +
      "if(!once&&fs.existsSync(" + JSON.stringify(arm) + ")){once=true;fs.writeFileSync(" + JSON.stringify(blocked) +
      ",JSON.stringify({pid:process.pid,boundary:'worker_fsync'}));Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,60000);}" +
      "return realFsync.apply(this,arguments);};})();\n";
    fs.writeFileSync(file, source.replace(anchor, anchor + hook));instrumentedHash = hash(file);
    assert.notEqual(instrumentedHash, originalHash);
  }
  const wrapper = path.join(root, 'watch-controller.cjs');
  fs.writeFileSync(wrapper, "'use strict';const send=value=>{if(process.connected)process.send(value,()=>{});};" +
    "require(" + JSON.stringify(path.join(runtime, 'tools/watch-maintenance.js')) + ").main([],{" +
    "budgets:" + JSON.stringify(policy) + ",onNativeReady(descriptor){const scope={schema_version:'knowledge-command-scope.v1'," +
    "backend:descriptor.backend,descriptor,...(descriptor.backend==='linux_pid_namespace'?{observer_lineage:[{namespace:descriptor.observer_pid_namespace,depth:descriptor.controller.proc_pid_chain.length}]}:{})};" +
    "send({type:'scope',scope});},onReady(value){send({type:'ready',value});}}).then(" +
    "value=>{send({type:'terminal',ok:true,value});if(process.connected)process.disconnect();}," +
    "error=>{send({type:'terminal',ok:false,error:{code:error.code,message:error.message,cleanup:error.cleanup,watcher:error.watcher,durable_stop_confirmed:false}});" +
    "process.exitCode=1;if(process.connected)process.disconnect();});\n");
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(KNOWLEDGE_|NODE_|GIT_|MEM0_|PINECONE_)/.test(key)));
  Object.assign(env, { KNOWLEDGE_MODE: 'repo', KNOWLEDGE_SYSTEM_ROOT: synthetic, KNOWLEDGE_TARGET_ROOT: repo,
    KNOWLEDGE_STATE_ROOT: state, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(repo, '.knowledge'), KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1',
    KNOWLEDGE_AGENT_ID: 'owned-watch-native', KNOWLEDGE_WATCH_DEBOUNCE_MS: '40', KNOWLEDGE_WATCH_HEARTBEAT_MS: '100',
    KNOWLEDGE_WATCHER_STALE_MS: '120000', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' });
  const child = cp.spawn(process.execPath, [wrapper], { env, cwd: repo, stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true });
  const f = { root, repo, state, admitted, descendant, late, lateGate, blocked, arm, child, scopes: [], ready: false, terminal: null, closed: false,
    exit: null, output: '', stderr: '', observed: null, blockedState, originalHash, instrumentedHash,
    async stop() {
      if (f.closed) return;
      if (child.connected) child.send({ type: 'knowledge:watch-stop' }, () => {});else child.kill('SIGTERM');
      await until(() => f.closed, 'watcher controller graceful terminal', policy.cleanupMs + 4000);
    } };
  child.stdout.on('data', part => { if (f.output.length < 65536) f.output += part; });
  child.stderr.on('data', part => { if (f.stderr.length < 65536) f.stderr += part; });
  child.on('message', message => {
    if (message?.type === 'scope') f.scopes.push(message.scope);
    if (message?.type === 'ready') { f.ready = true;f.watcherId = message.value.watcher_id; }
    if (message?.type === 'terminal') f.terminal = message;
  });
  child.once('error', error => { f.spawnError = error; });
  const closed = new Promise(resolve => child.once('close', (code, signal) => { f.closed = true;f.exit = { code, signal };resolve(); }));
  t.after(async () => {
    try {
      if (!f.closed) { child.kill('SIGKILL');await closed; }
      if (f.scopes.length && !f.observed) f.observed = await observeClosed(f.scopes.at(-1));
      assert.equal(hash(path.join(systemRoot, 'tools/lib/watch-maintenance-worker.js')), originalHash, 'Real product source must remain untouched');
      t.diagnostic(JSON.stringify({ evidence_kind: blockedState ? 'actual native ownership; modeled bounded fsync stall in private worker copy' :
        'actual public watcher and native whole-tree drain; bounded synthetic sync descendants',
        exit: f.exit, terminal: f.terminal, native_closure: f.observed, original_worker_sha256: originalHash,
        instrumented_worker_sha256: instrumentedHash, late_write: fs.existsSync(late), stderr: f.stderr }));
      if (!f.scopes.length || f.observed?.status === 'completed') removeTempDirStrict(root, { expectedIdentity: identity });
      else t.diagnostic('Unconfirmed owned scope: preserved fixture ' + root);
    } catch (error) { t.diagnostic('Cleanup evidence unconfirmed; preserved fixture ' + root);throw error; }
  });
  await until(() => {
    if (f.closed || f.spawnError) throw new Error('Watcher failed before ready: ' + JSON.stringify(f.terminal || f.exit || f.spawnError) + f.stderr);
    return f.ready && f.scopes.length;
  }, 'native-owned watcher readiness');
  return f;
}
async function trigger(f) {
  fs.appendFileSync(path.join(f.repo, 'source.js'), 'owned event\n');
  await until(() => read(f.admitted) && read(f.descendant), 'actual sync and detached descendant admission');
}

test('watcher controller SIGKILL drains an admitted detached producer before its delayed write', { skip: !supported, timeout: 120000 }, async t => {
  const f = await fixture(t);await trigger(f);
  assert.equal(f.child.kill('SIGKILL'), true, 'Termination is requested through the retained creator-owned ChildProcess');
  await until(() => f.closed, 'actual watcher crash exit', 5000);
  if (process.platform === 'win32') {
    // Windows TerminateProcess can be surfaced as a nonzero exit code rather
    // than a POSIX signal. Neither shape is used as descendant-closure proof.
    assert(f.exit.signal === 'SIGKILL' || Number.isInteger(f.exit.code) && f.exit.code !== 0);
  } else assert.equal(f.exit.signal, 'SIGKILL');
  assert.equal(f.terminal, null, 'The abrupt crash must not be a graceful worker completion');
  f.observed = await observeClosed(f.scopes.at(-1));assertNativeClosed(f.observed);
  fs.writeFileSync(f.lateGate, 'probe only after exact native closure');await pause(250);
  assert.equal(fs.existsSync(f.late), false, 'No descendant may write after fresh native closure');
});

test('graceful watcher stop publishes interruption only after managed sync tree drain', { skip: !supported, timeout: 120000 }, async t => {
  const f = await fixture(t);await trigger(f);await f.stop();
  assert.deepEqual(f.exit, { code: 0, signal: null });assert.equal(f.terminal?.ok, true);
  assert.equal(f.terminal.value.durable_stop_confirmed, true);assert.equal(f.terminal.value.sync_interrupted, true);
  assertNativeClosed(f.terminal.value.cleanup);assertNativeClosed(f.terminal.value.sync_cleanup);
  const status = read(path.join(f.state, 'maintenance/automation_status.json'));
  assert.equal(status.active_watchers[f.watcherId].running, false);
  assert.equal(status.automation_health, 'degraded_watcher_sync_interrupted');
  assertNativeClosed(status.last_sync_cleanup);
  assert.equal(fs.existsSync(path.join(f.state, '.runtime/watchers', f.watcherId + '.json')), false);
  f.observed = await observeClosed(f.scopes.at(-1));fs.writeFileSync(f.lateGate, 'probe only after exact native closure');
  await pause(250);assert.equal(fs.existsSync(f.late), false);
});

test('synchronous watcher-state fsync stall cannot block stop admission or outer native tree drain', { skip: !supported, timeout: 120000 }, async t => {
  const f = await fixture(t, { blockedState: true });await trigger(f);
  fs.writeFileSync(f.arm, 'arm exactly this private worker');
  await until(() => read(f.blocked), 'controlled synchronous fsync obstruction', 5000);
  const started = performance.now();await f.stop();const elapsed = performance.now() - started;
  assert.equal(f.exit.code, 1);assert.equal(f.terminal?.ok, false);
  assert.equal(f.terminal.error.durable_stop_confirmed, false);
  assertNativeClosed(f.terminal.error.cleanup);
  assert(elapsed < policy.cleanupMs + 2000, 'One original cleanup allowance plus observer scheduling tolerance');
  f.observed = await observeClosed(f.scopes.at(-1));assertNativeClosed(f.observed);
  fs.writeFileSync(f.lateGate, 'probe only after exact native closure');await pause(250);
  assert.equal(fs.existsSync(f.late), false);
  // A frozen storage worker cannot truthfully publish a durable stopped row.
  // The external terminal explicitly says false instead of inventing a write.
  const status = read(path.join(f.state, 'maintenance/automation_status.json'));
  assert.notEqual(status.last_trigger_source, 'watcher_stop');
});
