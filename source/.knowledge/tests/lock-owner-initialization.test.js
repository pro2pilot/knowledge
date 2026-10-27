'use strict';

// Actual owned child processes and physical directories. The only injection is
// a deliberate delay after the real publisher's mkdir, before its real owner
// publication. These fixture budgets do not change production lock policies.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const SOURCE = process.env.KNOWLEDGE_TEST_LOCK_SOURCE
  ? path.resolve(process.env.KNOWLEDGE_TEST_LOCK_SOURCE) : path.resolve(__dirname, '..');
const LEGACY_SOURCE = path.join(__dirname, 'fixtures', 'lock-v2-runtime');
const manager = require(path.join(SOURCE, 'tools/lib/contained-lock-manager'));
const { LOCKS } = require(path.join(SOURCE, 'tools/lib/lock-policy'));

function fixture(t, timeoutMs) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-owner-publication-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const state = path.join(root, 'state');
  const request = { rootKind: 'state', rootPath: state, context: { stateRoot: state },
    lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose, timeoutMs };
  const warm = manager.acquireContainedLock(request), directory = warm.path;
  assert.equal(warm.release().status, 'released');
  return { root, request, directory, events: path.join(root, 'child-events.ndjson'),
    ownerFile: path.join(directory, 'owner.json') };
}

function identity(file) {
  const s = fs.lstatSync(file, { bigint: true });
  return { dev: String(s.dev), ino: String(s.ino), mtime: String(s.mtimeNs),
    ctime: String(s.ctimeNs), names: fs.readdirSync(file).sort() };
}
function events(file) {
  try { return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(row => JSON.parse(row)); }
  catch (error) { if (error.code === 'ENOENT' || error instanceof SyntaxError) return []; throw error; }
}

const CHILD = String.raw`
const fs = require('node:fs'), path = require('node:path');
const [source, raw, file, mode, directory] = process.argv.slice(1);
const request = JSON.parse(raw), pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const record = event => fs.appendFileSync(file, JSON.stringify({event, at:Date.now()})+'\n');
const manager = require(path.join(source,'tools/lib/contained-lock-manager'));
if (mode === 'publisher') {
  const nativeMkdir = fs.mkdirSync; let delayed = false;
  fs.mkdirSync = function(target,...args) {
    const result = nativeMkdir.call(fs,target,...args);
    if (!delayed && path.resolve(String(target)) === directory) {
      delayed = true; record('directory_visible'); pause(3500); record('publication_resumed');
    }
    return result;
  };
  const handle = manager.acquireContainedLock(request); record('owner_published');
  pause(350); const result = handle.release();
  if (result.status !== 'released') throw new Error('real publisher release failed');
  record('owner_released');
} else {
  record('mutation_ready');
  if (mode === 'malformed') {
    pause(600); fs.writeFileSync(path.join(directory,'owner.json'),'{broken',{flag:'wx'}); record('malformed_published');
  } else if (mode === 'symlink') {
    pause(600); fs.renameSync(directory,directory+'.retired');
    fs.symlinkSync(path.join(path.dirname(file),'owned-target'),directory,process.platform==='win32'?'junction':'dir');
    record('symlink_published');
  } else if (mode === 'churn') {
    for (let i=0;i<18;i++) {
      pause(150);
      const replacement=directory+'.replacement-'+i;
      fs.mkdirSync(replacement); const old=new Date('2000-01-01T00:00:00.000Z');
      fs.utimesSync(replacement,old,old);
      // POSIX rename atomically replaces this fixture's empty directory.
      fs.renameSync(replacement,directory); record('directory_replaced');
    }
    record('churn_finished');
  } else throw new Error('unknown fixture mode');
}
`;

async function startChild(t, f, mode) {
  const child = spawn(process.execPath, ['-e', CHILD, mode === 'publisher' ? LEGACY_SOURCE : SOURCE, JSON.stringify(f.request),
    f.events, mode, f.directory], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let stderr = '', stdout = '';
  child.stderr.on('data', value => { stderr += value; });
  child.stdout.on('data', value => { stdout += value; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal, stderr, stdout }));
  });
  const guard = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }, 20000);
  t.after(async () => { clearTimeout(guard); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done.catch(() => {}); });
  const limit = performance.now() + 10000;
  while (!events(f.events).length) {
    if (child.exitCode !== null || child.signalCode !== null) assert.fail(JSON.stringify(await done));
    if (performance.now() >= limit) assert.fail('Owned child did not enter its fixture before the harness deadline');
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  return { done, child };
}
function attempt(request) {
  const start = performance.now(), at = Date.now();
  let handle = null, failure = null;
  try { handle = manager.acquireContainedLock(request); }
  catch (error) { failure = error; }
  return { handle, failure, elapsed: performance.now() - start, at, finishedAt: Date.now() };
}
function assertMissingTimeout(error) {
  assert.ok(error, 'Unknown ownership must not be acquired or removed');
  assert.equal(error.code, 'lock_timeout');
  assert.equal(error.owner_disposition, 'owner_initialization_unconfirmed');
  assert.equal(error.recovery_required, 'owner_metadata_evidence');
}

test('a real healthy legacy v2 publisher delayed beyond two seconds may publish and release within the new contender budget', { timeout: 25000 }, async t => {
  const f = fixture(t, 12000), child = await startChild(t, f, 'publisher');
  const observed = attempt(f.request);
  if (observed.handle) assert.equal(observed.handle.release().status, 'released');
  assert.deepEqual(await child.done, { code: 0, signal: null, stderr: '', stdout: '' });
  const rows = events(f.events), visible = rows.find(x => x.event === 'directory_visible'),
    published = rows.find(x => x.event === 'owner_published');
  assert.ok(published.at - visible.at >= 3000, 'Fixture must physically delay owner publication beyond the former grace');
  assert.ok(observed.at < published.at, 'Contender must begin before valid owner publication');
  assert.equal(observed.failure, null, observed.failure?.stack);
  assert.ok(observed.handle, 'A healthy released owner should allow acquisition within the original budget');
  assert.ok(rows.some(x => x.event === 'owner_released'));
  t.diagnostic(JSON.stringify({ actual_child: true, publication_delay_ms: published.at - visible.at,
    contender_elapsed_ms: observed.elapsed, request_budget_ms: f.request.timeoutMs }));
});

test('aged ownerless storage waits only its original budget, stays physically unchanged, and remains a read-only finding', { timeout: 10000 }, t => {
  const f = fixture(t, 800); fs.mkdirSync(f.directory);
  const old = new Date('2000-01-01T00:00:00.000Z'); fs.utimesSync(f.directory, old, old);
  const before = identity(f.directory), diagnostic = manager.inspectLockSafety(f.request);
  assert.equal(diagnostic.status, 'unsafe');
  assert.ok(diagnostic.findings.some(x => x.code === 'lock_owner_invalid' && x.reason === 'missing'));
  assert.deepEqual(identity(f.directory), before, 'Read-only diagnostics must not repair ownership');
  const observed = attempt(f.request);
  if (observed.handle) observed.handle.release();
  assertMissingTimeout(observed.failure);
  assert.ok(observed.elapsed >= f.request.timeoutMs - 5, 'Aged mtime must not preempt the original request budget');
  assert.deepEqual(identity(f.directory), before, 'Timeout must not remove, rewrite or replace unknown ownership');
});

test('malformed owner published during an initialization wait remains an immediate strict refusal', { timeout: 15000 }, async t => {
  const f = fixture(t, 8000); fs.mkdirSync(f.directory); const before = identity(f.directory);
  const child = await startChild(t, f, 'malformed'), observed = attempt(f.request);
  if (observed.handle) observed.handle.release();
  assert.deepEqual(await child.done, { code: 0, signal: null, stderr: '', stdout: '' });
  assert.equal(observed.failure?.code, 'lock_owner_invalid');
  assert.equal(observed.failure?.reason, 'malformed_json');
  assert.equal(fs.readFileSync(f.ownerFile, 'utf8'), '{broken');
  assert.equal(identity(f.directory).ino, before.ino);
  assert.ok(observed.elapsed < f.request.timeoutMs, 'Invalid published owner must not consume the full acquisition budget');
});

test('a symlink replacing an initializing directory is refused and its owned target remains unchanged', { timeout: 15000 }, async t => {
  const f = fixture(t, 8000); fs.mkdirSync(f.directory);
  const target = path.join(f.root, 'owned-target'); fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'sentinel'), 'unchanged-target');
  const before = identity(target), child = await startChild(t, f, 'symlink'), observed = attempt(f.request);
  if (observed.handle) observed.handle.release();
  assert.deepEqual(await child.done, { code: 0, signal: null, stderr: '', stdout: '' });
  assert.ok(['unsafe_lock_path', 'unsafe_lock_owner'].includes(observed.failure?.code), observed.failure?.stack);
  assert.deepEqual(identity(target), before);
  assert.equal(fs.readFileSync(path.join(target, 'sentinel'), 'utf8'), 'unchanged-target');
});

test('replacement of empty initializing directories cannot restart the acquisition budget', { timeout: 15000 }, async t => {
  if (process.platform === 'win32') return t.skip('Fixture uses POSIX atomic replacement of an empty directory');
  const f = fixture(t, 900); fs.mkdirSync(f.directory);
  const child = await startChild(t, f, 'churn'), observed = attempt(f.request);
  if (observed.handle) observed.handle.release();
  assert.deepEqual(await child.done, { code: 0, signal: null, stderr: '', stdout: '' });
  assertMissingTimeout(observed.failure);
  const rows = events(f.events), finished = rows.find(x => x.event === 'churn_finished');
  assert.ok(rows.filter(x => x.event === 'directory_replaced' && x.at <= observed.finishedAt).length >= 2);
  assert.ok(observed.finishedAt < finished.at, 'Original budget must expire while replacement churn still continues');
  assert.deepEqual(fs.readdirSync(f.directory), []);
  assert.deepEqual(fs.readdirSync(path.join(path.dirname(f.directory), '.stale')), []);
  assert.deepEqual(fs.readdirSync(path.join(path.dirname(f.directory), '.release')), []);
});
