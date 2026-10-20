'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { createWatcherStateStore, MAX_STATE_BYTES } = require('../tools/lib/watcher-state-store');
const { captureTempDirIdentity, removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');

const systemRoot = path.resolve(__dirname, '..');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const read = file => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT' || error instanceof SyntaxError) return null; throw error; } };
const snapshot = file => { const stat = fs.lstatSync(file, { bigint: true }), bytes = fs.readFileSync(file); return { dev: String(stat.dev), ino: String(stat.ino), sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length }; };
async function waitFor(predicate, label, timeout = 7000) {
  const start = performance.now();
  while (performance.now() - start < timeout) { const value = predicate(); if (value) return value; await sleep(10); }
  throw new Error('Timed out: ' + label);
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'watch-attempt-')), identity = captureTempDirIdentity(root), daemons = [];
  t.after(async () => {
    try {
      for (const daemon of daemons) await daemon.stop();
      if (daemons.length) t.diagnostic(JSON.stringify({ evidence_kind: 'real watcher/fs.watch; explicitly synthetic bounded sync children',
        watchers: daemons.map(d => ({ pid: d.child.pid, exit: d.exit, stderr: d.stderr, synthetic_sync_events: d.events(), aggregate_publication_events: d.aggregateEvents() })) }));
    } finally { removeTempDirStrict(root, { expectedIdentity: identity }); }
  });
  return { root, daemons };
}
function storeFixture(t) {
  const f = fixture(t), store = createWatcherStateStore({ stateRoot: f.root, watcherId: 'owned-watcher' });
  return { ...f, store };
}
function replaceFile(file, value = { attempt_id: 'explicit-successor', sentinel: true }) {
  fs.renameSync(file, file + '.retired'); fs.writeFileSync(file, JSON.stringify(value) + '\n'); return snapshot(file);
}

test('watcher state initializes exclusively and follows its own atomic replacement inode', t => {
  const { store, root } = storeFixture(t);
  store.initialize({ running: true, counter: 0 }); const before = snapshot(store.filePath), first = read(store.filePath);
  fs.writeFileSync(path.join(root, 'unrelated.txt'), 'normal parent contents may change');
  store.write({ running: true, counter: 1 }); const after = snapshot(store.filePath);
  assert.notEqual(before.ino, after.ino); assert.equal(read(store.filePath).attempt_id, first.attempt_id);
  store.write({ running: true, counter: 2 }); assert.equal(read(store.filePath).counter, 2); assert.equal(store.assertOwned(), true);
  store.remove(); assert.equal(fs.existsSync(store.filePath), false);
});

test('an existing legacy or foreign watcher record is never adopted on initialization', t => {
  const { store } = storeFixture(t); fs.mkdirSync(path.dirname(store.filePath), { recursive: true });
  fs.writeFileSync(store.filePath, '{"pid":123,"running":true}\n'); const before = snapshot(store.filePath);
  assert.throws(() => store.initialize({ running: true }), error => error.code === 'watcher_state_ownership_lost' && error.reason === 'initial_state_conflict');
  store.remove(); assert.deepEqual(snapshot(store.filePath), before);
});

test('state pathname replacement refuses writes and removal without changing successor bytes', t => {
  const { store } = storeFixture(t); store.initialize({ running: true }); const successor = replaceFile(store.filePath);
  assert.throws(() => store.write({ running: false }), { code: 'watcher_state_ownership_lost' });
  assert.throws(() => store.remove(), { code: 'watcher_state_ownership_lost' }); assert.deepEqual(snapshot(store.filePath), successor);
});

test('same-inode byte changes revoke state ownership without deleting the changed record', t => {
  const { store } = storeFixture(t); store.initialize({ running: true }); const original = snapshot(store.filePath);
  fs.writeFileSync(store.filePath, '{"attempt_id":"changed-in-place"}\n'); const changed = snapshot(store.filePath); assert.equal(changed.ino, original.ino);
  assert.throws(() => store.write({ running: false }), error => error.code === 'watcher_state_ownership_lost' && error.reason === 'state_bytes_changed');
  assert.throws(() => store.remove(), { code: 'watcher_state_ownership_lost' }); assert.deepEqual(snapshot(store.filePath), changed);
});

test('replacement of a captured watchers directory preserves the successor subtree', t => {
  const { store } = storeFixture(t); store.initialize({ running: true }); const directory = path.dirname(store.filePath);
  fs.renameSync(directory, directory + '-retired'); fs.mkdirSync(directory); fs.writeFileSync(store.filePath, 'successor tree\n'); const successor = snapshot(store.filePath);
  assert.throws(() => store.write({ running: false }), error => error.code === 'watcher_state_ownership_lost' && error.reason === 'physical_parent_replaced');
  assert.throws(() => store.remove(), { code: 'watcher_state_ownership_lost' }); assert.deepEqual(snapshot(store.filePath), successor);
});

test('symbolic-link replacement of state is refused and its target remains untouched', t => {
  const { store, root } = storeFixture(t); store.initialize({ running: true }); fs.renameSync(store.filePath, store.filePath + '.retired');
  const target = path.join(root, 'successor.json'); fs.writeFileSync(target, '{"sentinel":true}\n');
  try { fs.symlinkSync(target, store.filePath, 'file'); }
  catch (error) { if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error.code)) { t.skip('Creating a Windows file symlink requires host privileges'); return; } throw error; }
  const successor = snapshot(target);
  assert.throws(() => store.write({ running: false }), { code: 'watcher_state_ownership_lost' }); assert.throws(() => store.remove(), { code: 'watcher_state_ownership_lost' });
  assert(fs.lstatSync(store.filePath).isSymbolicLink()); assert.deepEqual(snapshot(target), successor);
});

test('an atomic write retry rechecks ownership and preserves a successor introduced after the first obstruction', t => {
  const { store } = storeFixture(t); store.initialize({ running: true }); const rename = fs.renameSync; let calls = 0, successor;
  fs.renameSync = function(source, destination) {
    if (destination === store.filePath) {
      calls++; rename(store.filePath, store.filePath + '.retired'); fs.writeFileSync(store.filePath, '{"attempt_id":"retry-successor"}\n'); successor = snapshot(store.filePath);
      throw Object.assign(new Error('Scoped publication obstruction'), { code: 'EBUSY' });
    }
    return rename.apply(this, arguments);
  };
  try { assert.throws(() => store.write({ running: true, counter: 1 }), { code: 'watcher_state_ownership_lost' }); }
  finally { fs.renameSync = rename; }
  assert.equal(calls, 1); assert.deepEqual(snapshot(store.filePath), successor);
});

test('oversized state payload is rejected before initial directories or existing bytes are changed', t => {
  const { store, root } = storeFixture(t), oversized = { changed: 'я'.repeat(MAX_STATE_BYTES) };
  assert.throws(() => store.initialize(oversized), { code: 'watcher_state_payload_too_large' }); assert.equal(fs.existsSync(path.join(root, '.runtime')), false);
  store.initialize({ running: true }); const before = snapshot(store.filePath);
  assert.throws(() => store.write(oversized), { code: 'watcher_state_payload_too_large' }); assert.deepEqual(snapshot(store.filePath), before);
  store.write({ running: true, recovered: true }); assert.equal(read(store.filePath).recovered, true);
});

test('a state file growing after fstat is read through a bounded descriptor buffer', t => {
  const { store } = storeFixture(t); store.initialize({ running: true }); const before = snapshot(store.filePath);
  const fstat = fs.fstatSync, readSync = fs.readSync; let injected = false, maximumRead = 0;
  fs.fstatSync = function(descriptor, options) {
    const stat = fstat.apply(this, arguments);
    if (!injected) { injected = true; fs.appendFileSync(store.filePath, 'x'.repeat(MAX_STATE_BYTES * 2)); }
    return stat;
  };
  fs.readSync = function(descriptor, buffer, offset, length, position) { maximumRead = Math.max(maximumRead, length); return readSync.apply(this, arguments); };
  try { assert.throws(() => store.assertOwned(), { code: 'watcher_state_ownership_lost' }); }
  finally { fs.fstatSync = fstat; fs.readSync = readSync; }
  assert(injected); assert(maximumRead > 0 && maximumRead <= before.bytes + 1);
  assert.equal(fs.statSync(store.filePath).size, before.bytes + MAX_STATE_BYTES * 2);
});

test('repeat removal never deletes a new record created after the own record was removed', t => {
  const { store } = storeFixture(t); store.initialize({ running: true }); store.remove();
  fs.writeFileSync(store.filePath, '{"attempt_id":"later-successor"}\n'); const successor = snapshot(store.filePath);
  store.remove(); assert.deepEqual(snapshot(store.filePath), successor);
});

const syntheticSync = `'use strict';
const fs=require('node:fs'),path=require('node:path');
const root=process.env.KNOWLEDGE_STATE_ROOT, trace=path.join(root,'synthetic-sync.ndjson');
const changed=JSON.parse(process.env.KNOWLEDGE_CHANGED_FILES||'[]');
function event(phase){fs.appendFileSync(trace,JSON.stringify({phase,pid:process.pid,ppid:process.ppid,changed,at:new Date().toISOString()})+'\\n');}
event('start'); const deadline=setTimeout(()=>{event('bounded_timeout');process.exit(91)},5000);
const poll=setInterval(()=>{if(fs.existsSync(path.join(root,'release-'+process.pid))){clearInterval(poll);clearTimeout(deadline);event('finish');process.exit(0)}},10);
process.on('SIGTERM',()=>{event('owned_shutdown');process.exit(0)});
`;

async function daemonFixture(t, options = {}) {
  const f = fixture(t), repo = path.join(f.root, 'repo'), state = path.join(f.root, 'state'), synthetic = path.join(f.root, 'synthetic-system');
  fs.mkdirSync(path.join(repo, '.knowledge'), { recursive: true }); fs.mkdirSync(state); fs.mkdirSync(path.join(synthetic, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(repo, '.knowledge/config.yaml'), 'updates:\n  enabled: false\n'); fs.writeFileSync(path.join(repo, 'source.js'), 'before watcher\n');
  fs.writeFileSync(path.join(synthetic, 'tools/sync-tracked.js'), syntheticSync);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(KNOWLEDGE_|NODE_|GIT_|MEM0_|PINECONE_)/.test(key)));
  Object.assign(env, { KNOWLEDGE_SYSTEM_ROOT: synthetic, KNOWLEDGE_TARGET_ROOT: repo, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(repo, '.knowledge'),
    KNOWLEDGE_STATE_ROOT: state, KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_AGENT_ID: 'attempt-test', KNOWLEDGE_MODE: 'repo',
    KNOWLEDGE_WATCH_DEBOUNCE_MS: String(options.debounce ?? 50), KNOWLEDGE_WATCH_HEARTBEAT_MS: String(options.heartbeat ?? 60000), KNOWLEDGE_WATCHER_STALE_MS: '120000', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' });
  const args = [];
  if (options.preload) { const hook = path.join(f.root, 'own-preload.cjs'); fs.writeFileSync(hook, options.preload({ state })); args.push('--require', hook); }
  args.push(path.join(systemRoot, 'tools/watch-maintenance.js'));
  const child = spawn(process.execPath, args, { cwd: repo, env, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const d = { ...f, repo, state, child, stderr: '', exit: { closed: false, error: null, code: null, signal: null, forced: false }, statusFile: path.join(state, 'maintenance/automation_status.json'),
    events() { const file = path.join(state, 'synthetic-sync.ndjson'); if (!fs.existsSync(file)) return []; return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)); },
    aggregateEvents() { const file = path.join(state, 'aggregate-publications.ndjson'); if (!fs.existsSync(file)) return []; return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)); },
    async stop() {
      if (!d.exit.closed) {
        if (child.connected) child.send({ type: 'knowledge:watch-stop' }, () => {}); else child.kill('SIGTERM');
        try { await waitFor(() => d.exit.closed, 'owned watcher stop', 6000); }
        catch (error) { d.exit.forced = true; child.kill('SIGKILL'); await d.closed; throw error; }
      }
      await d.closed;
    }
  };
  f.daemons.push(d); child.stderr.on('data', chunk => { if (d.stderr.length < 65536) d.stderr += chunk; });
  child.on('error', error => { d.exit.error = { code: error.code, message: error.message }; });
  d.closed = new Promise(resolve => child.once('close', (code, signal) => { Object.assign(d.exit, { closed: true, code, signal }); resolve(); }));
  await waitFor(() => {
    if (d.exit.error || d.exit.closed) throw new Error('Watcher exited before readiness: ' + JSON.stringify(d.exit) + d.stderr);
    const status = read(d.statusFile), row = Object.entries(status?.active_watchers || {}).find(([, value]) => value.pid === child.pid && value.running);
    if (!row) return false;
    d.id = row[0]; d.stateFile = path.join(state, '.runtime/watchers', d.id + '.json'); return Boolean(read(d.stateFile));
  }, 'watcher readiness');
  return d;
}
async function startSync(d) {
  fs.appendFileSync(path.join(d.repo, 'source.js'), 'owned source event\n');
  return waitFor(() => d.events().find(event => event.phase === 'start'), 'owned synthetic sync start');
}
function release(d, event) { fs.writeFileSync(path.join(d.state, 'release-' + event.pid), 'release own child'); }
function assertStopped(d, code) { assert.equal(d.exit.error, null); assert.equal(d.exit.code, code, d.stderr); assert.equal(d.exit.signal, null); assert.equal(d.exit.forced, false); }

test('real daemon preserves attempt identity through heartbeat, source event, sync finish and normal stop', async t => {
  const d = await daemonFixture(t, { heartbeat: 60 }), initial = read(d.stateFile);
  await waitFor(() => read(d.stateFile)?.heartbeat_at, 'real heartbeat');
  const sync = await startSync(d); release(d, sync);
  await waitFor(() => read(d.statusFile)?.last_sync_exit_code === 0, 'real callback after synthetic sync finish');
  const current = read(d.stateFile); assert.equal(current.attempt_id, initial.attempt_id); assert.equal(current.started_at, initial.started_at);
  assert.equal(sync.ppid, d.child.pid); await d.stop(); assertStopped(d, 0);
  assert.equal(fs.existsSync(d.stateFile), false); assert.equal(read(d.statusFile).active_watchers[d.id].running, false);
});

for (const boundary of ['heartbeat', 'event', 'trigger', 'finish', 'shutdown']) {
  test('real daemon refuses successor state at the ' + boundary + ' writer boundary', async t => {
    const d = await daemonFixture(t, { heartbeat: boundary === 'heartbeat' ? 80 : 60000, debounce: boundary === 'trigger' ? 250 : 50 });
    let sync;
    if (boundary === 'finish' || boundary === 'shutdown') sync = await startSync(d);
    if (boundary === 'trigger') {
      fs.appendFileSync(path.join(d.repo, 'source.js'), 'queued before replacement\n');
      await waitFor(() => read(d.stateFile)?.touched_pending > 0, 'event recorded before pending trigger');
    }
    const successor = replaceFile(d.stateFile);
    if (boundary === 'event') fs.appendFileSync(path.join(d.repo, 'source.js'), 'event after replacement\n');
    if (boundary === 'finish') release(d, sync);
    if (boundary === 'shutdown') await d.stop(); else await waitFor(() => d.exit.closed, 'ownership refusal at ' + boundary);
    assertStopped(d, 1); assert.match(d.stderr, /watcher_state_ownership_lost/); assert.deepEqual(snapshot(d.stateFile), successor);
    const status = read(d.statusFile); assert.equal(status.active_watchers[d.id].running, false); assert.equal(status.automation_health, 'degraded_watcher_error');
    if (boundary === 'trigger' || boundary === 'event' || boundary === 'heartbeat') assert.equal(d.events().filter(event => event.phase === 'start').length, 0);
    if (sync) assert.throws(() => process.kill(sync.pid, 0), error => error.code === 'ESRCH');
  });
}

test('a foreign aggregate slot is preserved even while the local watcher state remains its own', async t => {
  const d = await daemonFixture(t, { heartbeat: 80 }), status = read(d.statusFile);
  const successor = { ...status.active_watchers[d.id], attempt_id: 'explicit-foreign-attempt', sentinel: true };
  const unrelated = { pid: process.pid, running: true, last_seen_at: new Date().toISOString(), sentinel: 'unrelated' };
  status.active_watchers[d.id] = successor; status.active_watchers.unrelated = unrelated; fs.writeFileSync(d.statusFile, JSON.stringify(status) + '\n'); const before = snapshot(d.statusFile);
  await waitFor(() => d.exit.closed, 'foreign aggregate ownership refusal'); assertStopped(d, 1);
  assert.match(d.stderr, /watcher_status_ownership_lost/); assert.deepEqual(snapshot(d.statusFile), before);
  assert.deepEqual(read(d.statusFile).active_watchers[d.id], successor); assert.deepEqual(read(d.statusFile).active_watchers.unrelated, unrelated);
  assert.equal(fs.existsSync(d.stateFile), false);
});

test('malformed aggregate data remains intact and its primary callback error survives shutdown', async t => {
  const d = await daemonFixture(t, { heartbeat: 80 }); fs.writeFileSync(d.statusFile, '{invalid aggregate\n'); const before = snapshot(d.statusFile);
  await waitFor(() => d.exit.closed, 'malformed aggregate refusal'); assertStopped(d, 1); assert.deepEqual(snapshot(d.statusFile), before);
  assert.match(d.stderr, /Watcher failed \[SyntaxError\]/); assert.match(d.stderr, /Watcher shutdown failed \[SyntaxError\]/);
  assert.equal(fs.existsSync(d.stateFile), false);
});

test('aggregate publication retry refuses a newly foreign slot before overwriting it', async t => {
  const d = await daemonFixture(t, { preload: ({ state }) => `
const fs=require('node:fs'),path=require('node:path'); const rename=fs.renameSync;
const state=${JSON.stringify(state)}, marker=path.join(state,'inject-aggregate-retry'), target=path.join(state,'maintenance/automation_status.json');
let injected=false;
fs.renameSync=function(from,to){
  if(to===target&&!injected&&fs.existsSync(marker)){
    injected=true;const data=JSON.parse(fs.readFileSync(target,'utf8')),id=Object.keys(data.active_watchers)[0];
    data.active_watchers[id].attempt_id='injected-foreign-retry';data.sentinel='preserve aggregate replacement';
    fs.writeFileSync(target,JSON.stringify(data)+'\\n');fs.writeFileSync(path.join(state,'injected-snapshot.json'),fs.readFileSync(target));
    throw Object.assign(new Error('Explicit own aggregate retry obstruction'),{code:'EBUSY'});
  }
  return rename.apply(this,arguments);
};` });
  fs.writeFileSync(path.join(d.state, 'inject-aggregate-retry'), 'enable explicit own fault'); fs.appendFileSync(path.join(d.repo, 'source.js'), 'source event\n');
  await waitFor(() => d.exit.closed, 'aggregate retry refusal'); assertStopped(d, 1); assert.match(d.stderr, /watcher_status_ownership_lost/);
  assert.equal(fs.readFileSync(d.statusFile, 'utf8'), fs.readFileSync(path.join(d.state, 'injected-snapshot.json'), 'utf8'));
  assert.equal(fs.existsSync(d.stateFile), false); assert.equal(d.events().length, 0);
});

// A controlled, explicitly synthetic competing publisher uses the same actual
// contained JSON writer as sync. It runs between the watcher's read and publish
// and preserves the own nonce/owner unless the selected case replaces that row.
function aggregateChangePreload({ state }, { phase = 'fsync', continuous = false, replaceOnSecond = false } = {}) {
  return `
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {writeJsonAtomicContained}=require(${JSON.stringify(path.join(systemRoot, 'tools/lib/json-store.js'))});
const state=${JSON.stringify(state)},target=path.join(state,'maintenance/automation_status.json'),marker=path.join(state,'inject-aggregate-change');
const trace=path.join(state,'aggregate-publications.ndjson'),open=fs.openSync,close=fs.closeSync,fsync=fs.fsyncSync,rename=fs.renameSync;
const descriptors=new Map();let injecting=false,count=0;
fs.openSync=function(file,...args){const fd=open.call(this,file,...args);if(typeof file==='string')descriptors.set(fd,path.resolve(file));return fd;};
fs.closeSync=function(fd){try{return close.apply(this,arguments);}finally{descriptors.delete(fd);}};
function inject(temporary){
  if(injecting||!fs.existsSync(marker)||(!${continuous}&&count>=${replaceOnSecond ? 2 : 1}))return false;
  if(path.dirname(temporary)!==path.dirname(target)||!path.basename(temporary).startsWith('.automation_status.json.tmp-'))return false;
  injecting=true;
  try{
    const data=JSON.parse(fs.readFileSync(target,'utf8')),entry=Object.entries(data.active_watchers).find(([,row])=>row.pid===process.pid);
    if(!entry)throw new Error('Controlled publication requires the existing own slot');
    const ownBefore=JSON.stringify(entry[1]);count++;
    data.concurrent_revision=count;data.routing_bundle_status='controlled-latest-routing';
    data.active_watchers.concurrent_fixture={attempt_id:'independent-attempt',agent_id:'independent-fixture',pid:process.ppid,hostname:require('node:os').hostname(),running:true,last_seen_at:new Date().toISOString(),sentinel:count};
    if(${replaceOnSecond}&&count===2)entry[1].attempt_id='foreign-after-legitimate-rebase';
    writeJsonAtomicContained(target,data,state);
    const bytes=fs.readFileSync(target);fs.writeFileSync(path.join(state,'latest-competing-publication.json'),bytes);
    fs.appendFileSync(trace,JSON.stringify({phase:${JSON.stringify(phase)},count,own_identity_preserved:JSON.stringify(entry[1])===ownBefore,sha256:crypto.createHash('sha256').update(bytes).digest('hex')})+'\\n');
    return true;
  }finally{injecting=false;}
}
fs.fsyncSync=function(fd){const result=fsync.apply(this,arguments);if(${JSON.stringify(phase)}==='fsync'&&descriptors.has(fd))inject(descriptors.get(fd));return result;};
fs.renameSync=function(from,to){if(${JSON.stringify(phase)}==='retry'&&to===target&&inject(from))throw Object.assign(new Error('Controlled aggregate rename obstruction'),{code:'EBUSY'});return rename.apply(this,arguments);};
`;
}

function armAggregateChange(d) {
  fs.writeFileSync(path.join(d.state, 'inject-aggregate-change'), 'controlled competing publisher');
}
function assertLatestOtherFields(d, revision = 1) {
  const current = read(d.statusFile), latest = read(path.join(d.state, 'latest-competing-publication.json'));
  assert.equal(current.concurrent_revision, revision);
  assert.equal(current.routing_bundle_status, 'controlled-latest-routing');
  assert.deepEqual(current.active_watchers.concurrent_fixture, latest.active_watchers.concurrent_fixture);
}

for (const phase of ['fsync', 'retry']) {
  test(`legitimate aggregate changes at ${phase} are rebased while preserving latest fields and other rows`, async t => {
    const d = await daemonFixture(t, { debounce: 2000, preload: options => aggregateChangePreload(options, { phase }) });
    const own = read(d.stateFile).attempt_id;
    armAggregateChange(d);fs.appendFileSync(path.join(d.repo, 'source.js'), 'controlled concurrent aggregate publication\n');
    await waitFor(() => d.exit.closed || read(d.stateFile)?.last_event_path === 'source.js', 'event after aggregate drift');
    assert.equal(d.exit.closed, false, d.stderr);
    assert.equal(read(d.stateFile).attempt_id, own);assertLatestOtherFields(d);
    assert.equal(d.aggregateEvents().length, 1);assert.equal(d.aggregateEvents()[0].own_identity_preserved, true);
    await d.stop();assertStopped(d, 0);assertLatestOtherFields(d);assert.equal(d.events().length, 0);
  });
}

test('a legitimate aggregate change during shutdown is rebased before stopping the own row', async t => {
  const d = await daemonFixture(t, { preload: options => aggregateChangePreload(options) });
  armAggregateChange(d);await d.stop();assertStopped(d, 0);assertLatestOtherFields(d);
  assert.equal(read(d.statusFile).active_watchers[d.id].running, false);
  assert.equal(d.aggregateEvents().length, 1);assert.equal(fs.existsSync(d.stateFile), false);
});

test('an own-slot replacement after one legitimate rebase is refused without overwriting its bytes', async t => {
  const d = await daemonFixture(t, { debounce: 2000, preload: options => aggregateChangePreload(options, { replaceOnSecond: true }) });
  armAggregateChange(d);fs.appendFileSync(path.join(d.repo, 'source.js'), 'two controlled aggregate publications\n');
  await waitFor(() => d.exit.closed, 'ownership refusal after legitimate rebase');assertStopped(d, 1);
  assert.match(d.stderr, /Watcher failed \[watcher_status_ownership_lost\]/);
  assert.doesNotMatch(d.stderr, /watcher_status_changed/);
  assert.equal(d.aggregateEvents().length, 2);assert.equal(d.aggregateEvents()[0].own_identity_preserved, true);assert.equal(d.aggregateEvents()[1].own_identity_preserved, false);
  assert.equal(fs.readFileSync(d.statusFile, 'utf8'), fs.readFileSync(path.join(d.state, 'latest-competing-publication.json'), 'utf8'));
  assert.equal(fs.existsSync(d.stateFile), false);assert.equal(d.events().length, 0);
});

test('continuous aggregate contention has a bounded retry budget and preserves the last competing publication', async t => {
  const d = await daemonFixture(t, { debounce: 2000, preload: options => aggregateChangePreload(options, { continuous: true }) });
  armAggregateChange(d);fs.appendFileSync(path.join(d.repo, 'source.js'), 'continuous controlled contention\n');
  await waitFor(() => d.exit.closed, 'bounded aggregate contention refusal');assertStopped(d, 1);
  assert.match(d.stderr, /watcher_status_changed/);assert.match(d.stderr, /after 3 attempts/);
  const events = d.aggregateEvents();assert(events.length >= 3 && events.length <= 9, 'At most three attempts each for event, diagnostic and shutdown publication');
  assert(events.every(event => event.own_identity_preserved));
  assert.equal(fs.readFileSync(d.statusFile, 'utf8'), fs.readFileSync(path.join(d.state, 'latest-competing-publication.json'), 'utf8'));
  assert.equal(fs.existsSync(d.stateFile), false);assert.equal(d.events().length, 0);
});

function actualWriterFixture(t) {
  const f = fixture(t), repo = path.join(f.root, 'actual-repo'), state = path.join(repo, '.knowledge');
  fs.cpSync(systemRoot, state, { recursive: true });
  const put = (name, value) => {
    const file = path.join(state, name);fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n');
  };
  fs.writeFileSync(path.join(repo, 'README.md'), '# Owned aggregate writer fixture\n');
  put('config.yaml', 'updates:\n  enabled: false\nexternal_memory:\n  enabled: false\n');
  put('modules/module_registry.json', { modules: [] });
  put('project_index.json', { project_name: 'aggregate fixture', status: 'stub', primary_source_of_truth: 'code', modules: [], task_routing: [] });
  put('freshness.json', { tracked_files: [], artifact_dependencies: {}, artifact_statuses: {} });
  put('maps/file_criticality.json', { files: [], coverage_by_module: {} });
  put('maps/critical_paths.json', { paths: [] });
  put('maps/wiki_graph.json', { structural_status: 'healthy', broken_edge_count: 0 });
  put('evidence/file_facts.json', { facts: [] });put('contradictions.json', { items: [] });
  put('maintenance/repair_queue.json', { queue: [] });put('maintenance/stale_items.json', { items: [] });
  put('maintenance/quality_report.json', { quality_score: 100, issues: [] });
  put('maintenance/trust_report.json', { status: 'healthy', modules: { trusted: [], near_trusted: [], routing_trusted: [], advisory_only: [], suspect: [], low_confidence: [] }, module_statuses: [] });
  put('maintenance/wiki_lint_report.json', { structural_status: 'healthy' });put('maintenance/sync_log.json', { entries: [] });
  put('maintenance/concurrency_policy.json', { mode: 'locked_atomic_writes' });put('wiki/index.md', '# Owned fixture wiki\n');
  const existing = { attempt_id: 'existing-controlled-attempt', agent_id: 'existing-actor', pid: process.pid,
    hostname: os.hostname(), running: true, last_seen_at: '2026-10-19T10:00:00.000Z', event_count: 1 };
  put('maintenance/automation_status.json', { mode: 'event-driven', active_watchers: { existing }, trigger_history: [{ trigger: 'existing-event' }] });
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(KNOWLEDGE_|NODE_|GIT_|MEM0_|PINECONE_)/.test(key)));
  Object.assign(env, { KNOWLEDGE_MODE: 'repo', KNOWLEDGE_SYSTEM_ROOT: state, KNOWLEDGE_TARGET_ROOT: repo, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: state,
    KNOWLEDGE_STATE_ROOT: state, KNOWLEDGE_AGENT_ID: 'actual-writer-test', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1', KNOWLEDGE_DISCOVER_NEW: '0',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null', GIT_TERMINAL_PROMPT: '0' });
  return { ...f, repo, state, put, env, statusFile: path.join(state, 'maintenance/automation_status.json') };
}

function writerInterleaving(f, phase) {
  const hook = path.join(f.root, 'writer-interleaving.cjs');
  fs.writeFileSync(hook, `
'use strict';
const fs=require('node:fs'),path=require('node:path');
const state=${JSON.stringify(f.state)},target=${JSON.stringify(f.statusFile)},phase=${JSON.stringify(phase)};
const {writeJsonAtomicContained}=require(path.join(state,'tools/lib/json-store.js'));
const read=fs.readFileSync,open=fs.openSync,close=fs.closeSync,fsync=fs.fsyncSync;const descriptors=new Map();let injected=false;
function publish(before){
  if(injected)return;injected=true;
  const newer={...before,actor_extra:{sentinel:'latest independent fields'},hooks_installed:true,
    watcher_last_seen_at:'2026-10-19T10:00:02.000Z',trigger_history:[...(before.trigger_history||[]),{trigger:'concurrent-event'}],
    active_watchers:{...before.active_watchers,existing:{...before.active_watchers.existing,last_seen_at:'2026-10-19T10:00:02.000Z',event_count:9},
      added:{attempt_id:'new-controlled-attempt',agent_id:'new-actor',pid:process.ppid,hostname:require('node:os').hostname(),running:true,last_seen_at:'2026-10-19T10:00:02.000Z'}}};
  writeJsonAtomicContained(target,newer,state);fs.writeFileSync(path.join(state,'competing-writer-publication.json'),read(target));
}
fs.readFileSync=function(file,...args){const bytes=read.call(this,file,...args);if(phase==='initial-read'&&!injected&&typeof file==='string'&&path.resolve(file)===target)publish(JSON.parse(Buffer.isBuffer(bytes)?bytes.toString('utf8'):bytes));return bytes;};
fs.openSync=function(file,...args){const fd=open.call(this,file,...args);if(typeof file==='string')descriptors.set(fd,path.resolve(file));return fd;};
fs.closeSync=function(fd){try{return close.apply(this,arguments);}finally{descriptors.delete(fd);}};
fs.fsyncSync=function(fd){const result=fsync.apply(this,arguments),temporary=descriptors.get(fd);
  if(phase==='routing-publication'&&!injected&&temporary&&path.dirname(temporary)===path.dirname(target)&&path.basename(temporary).startsWith('.automation_status.json.tmp-')){
    const candidate=JSON.parse(read(temporary,'utf8'));if(Object.hasOwn(candidate,'routing_bundle_status'))publish(JSON.parse(read(target,'utf8')));
  }return result;
};
`);
  return hook;
}

function runActualWriter(t, f, tool, phase, expectedExit) {
  const hook = writerInterleaving(f, phase), script = path.join(f.state, 'tools', tool + '.js'), before = snapshot(script);
  const args = ['--require', hook, script, ...(tool === 'sync-tracked' ? ['--scan'] : [])];
  const result = spawnSync(process.execPath, args, { cwd: f.repo, env: f.env, encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
  t.diagnostic(JSON.stringify({ evidence_kind: 'actual local writer CLI; controlled competing record uses actual contained JSON writer', tool, phase,
    args, status: result.status, signal: result.signal, error: result.error?.message || null, stdout: result.stdout, stderr: result.stderr,
    controlled_publication: read(path.join(f.state, 'competing-writer-publication.json')) }));
  assert.equal(result.error, undefined);assert.equal(result.signal, null);assert.equal(result.status, expectedExit, result.stderr);
  assert.deepEqual(snapshot(script), before);return result;
}

function assertLatestWriterFields(f) {
  const latest = read(path.join(f.state, 'competing-writer-publication.json')), result = read(f.statusFile);
  assert(latest, 'The specified controlled interleaving must actually occur');
  assert.deepEqual(result.active_watchers, latest.active_watchers);
  assert.deepEqual(result.actor_extra, latest.actor_extra);
  assert.equal(result.hooks_installed, true);assert.equal(result.watcher_last_seen_at, latest.watcher_last_seen_at);
  assert.equal(result.trigger_history.filter(row => row.trigger === 'concurrent-event').length, 1);
}

test('actual sync preserves newer watcher rows and history published after its initial read', t => {
  const f = actualWriterFixture(t), result = runActualWriter(t, f, 'sync-tracked', 'initial-read', 0);
  assert.equal(JSON.parse(result.stdout).status, 'ok');assertLatestWriterFields(f);
  assert.equal(read(f.statusFile).trigger_history.filter(row => row.trigger === 'manual-scan').length, 1);
});

for (const failingRouting of [false, true]) {
  test(`actual sync routing ${failingRouting ? 'failure' : 'success'} patch preserves a later competing publication`, t => {
    const f = actualWriterFixture(t);
    if (failingRouting) f.put('tools/build-routing-bundle.js', "module.exports=()=>{throw new Error('Explicit bounded routing fixture failure');};\n");
    const result = runActualWriter(t, f, 'sync-tracked', 'routing-publication', failingRouting ? 2 : 0);
    assert.equal(JSON.parse(result.stdout).status, failingRouting ? 'failed' : 'ok');assertLatestWriterFields(f);
    assert.equal(read(f.statusFile).routing_bundle_status, failingRouting ? 'failed' : 'healthy');
    if (failingRouting) assert.match(read(f.statusFile).routing_bundle_error, /Explicit bounded routing fixture failure/);
  });
}

test('actual hook installation preserves watcher rows published after its first aggregate read', t => {
  const f = actualWriterFixture(t), initialized = spawnSync('git', ['init', '--quiet'], { cwd: f.repo, env: f.env, encoding: 'utf8', timeout: 5000 });
  assert.equal(initialized.error, undefined);assert.equal(initialized.status, 0, initialized.stderr);
  const result = runActualWriter(t, f, 'install-git-hooks', 'initial-read', 0);assertLatestWriterFields(f);
  assert.equal(JSON.parse(result.stdout).installed_hooks.length, 3);
  assert.equal(read(f.statusFile).hook_mode, 'managed_block');
});

test('actual hook installation refuses malformed aggregate before changing managed hooks', t => {
  for (const value of ['null\n', '{malformed aggregate\n']) {
    const f = actualWriterFixture(t), initialized = spawnSync('git', ['init', '--quiet'], { cwd: f.repo, env: f.env, encoding: 'utf8', timeout: 5000 });
    assert.equal(initialized.error, undefined);assert.equal(initialized.status, 0, initialized.stderr);
    f.put('maintenance/automation_status.json', value);const before = snapshot(f.statusFile);
    const result = runActualWriter(t, f, 'install-git-hooks', 'none', 1);
    assert.match(result.stderr, /aggregate|JSON/);assert.deepEqual(snapshot(f.statusFile), before);
    for (const name of ['post-commit', 'post-merge', 'post-checkout']) assert.equal(fs.existsSync(path.join(f.repo, '.git/hooks', name)), false);
  }
});

function persistedFiles(root) {
  const result = {};
  function walk(directory) {
    for (const name of fs.readdirSync(directory).sort()) {
      const file = path.join(directory, name), stat = fs.lstatSync(file);
      if (stat.isDirectory()) walk(file);
      else if (stat.isFile()) result[path.relative(root, file)] = snapshot(file);
      else throw new Error('Unexpected physical fixture entry: ' + file);
    }
  }
  walk(root);return result;
}

test('actual sync refuses malformed watcher collection before queue or report writes', t => {
  for (const active_watchers of [null, []]) {
    const f = actualWriterFixture(t);f.put('maintenance/automation_status.json', { mode: 'event-driven', active_watchers });
    const before = persistedFiles(f.state), result = runActualWriter(t, f, 'sync-tracked', 'none', 1);
    assert.match(result.stderr, /Watcher aggregate has an invalid shape/);
    assert.deepEqual(persistedFiles(f.state), before, 'A newly strict input refusal must precede other persisted sync writes');
  }
});
