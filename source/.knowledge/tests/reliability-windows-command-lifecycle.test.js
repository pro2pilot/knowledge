'use strict';
// This suite is a physical Windows gate, intentionally not a portable model.
// Its test-only preload stalls JavaScript; all process handles, assignment,
// Job limits, native watchdogs, signatures and receipt I/O remain real.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
assert.equal(process.platform, 'win32', 'Run this gate on an actual Windows host; it must not become a Linux SKIP/PASS');
const captured = [], realSpawn = cp.spawn;
let injection;
cp.spawn = function(command, args, options) {
  const file = args?.find(value => typeof value === 'string' && /command-windows-(?:bootstrap|guard)\.js$/.test(value));
  if (file && path.basename(file) === 'command-windows-bootstrap.js' && injection) {
    args = ['--require', path.join(__dirname, 'helpers/reliability-windows-bootstrap-inject.cjs'), ...args];
    options = { ...options, env: { ...options.env, KNOWLEDGE_QA_HOLDER_STALL: JSON.stringify(injection) } };
  }
  const child = realSpawn.call(cp, command, args, options);
  if (file) {
    const row = { child, file, initialization: null, ready: null, terminal: null, exit_observed: false, native_exit_observed: false, birth_binding: null };
    captured.push(row);
    child.once('exit', () => { row.exit_observed = true; });
    child.on('message', message => {
      if (message?.type === 'bootstrap_created') row.birth_binding = message;
      if (message?.type === 'bootstrap_exited') row.native_exit_observed = message.observation?.holder_exited === true && message.observation?.watcher_exited === true && message.observation?.active_processes === 0;
      if (message?.type === 'holder_ready') row.ready = message;
      if (message?.type === 'terminal') row.terminal = message;
    });
    const send = child.send.bind(child);
    child.send = function(message, ...rest) {
      if (message?.type === 'init') row.initialization = message;
      return send(message, ...rest);
    };
  }
  return child;
};
const runner = require('../tools/lib/command-runner');
const proof = require('../tools/lib/command-scope-proof');
const protocol = require('../tools/lib/command-windows-protocol');
const receiptIO = require('../tools/lib/command-windows-receipts');
const policy = { workMs: 60000, setupMs: 60000, cleanupMs: 60000, progressMs: 0 };
const options = { timeout: 180000 };
function command(code) { return { executable: process.execPath, args: ['-e', code], cwd: process.cwd(), env: process.env }; }
async function until(predicate, allowance = 60000) {
  const start = runner.mono();
  while (!predicate()) {
    if (runner.mono() - start >= allowance) throw new Error('Expected physical boundary was not observed');
    await runner.delay(10);
  }
}
function holders(scope) {
  const rows = captured.filter(row => row.initialization?.scope_id === scope.descriptor.scope_id);
  assert.equal(rows.length, 2, 'Exactly two separately owned holder processes are required');
  return Object.fromEntries(rows.map(row => [row.initialization.role, row]));
}
async function killOwned(row) {
  assert.ok(row.child.pid && !row.exit_observed, 'Test must kill a still-owned live child, never reopen a numeric PID');
  assert.ok(row.birth_binding && row.child.connected, 'The launcher must retain the exact native holder handle');
  row.child.send({type:'kill'});
  await until(() => row.exit_observed && row.native_exit_observed);
}
function assertClosed(value) {
  assert.equal(value.status, 'completed', JSON.stringify(value));
  assert.equal(value.active_processes, 0, JSON.stringify(value));
  assert.equal(value.root_exited, true, JSON.stringify(value));
}
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'windows-command-lifecycle-'));
  return { root, remove() { fs.rmSync(root, { recursive: true, force: true }); } };
}
function diagnostic(t, session, extra = {}) {
  t.diagnostic(JSON.stringify({ native: session.scope.descriptor.native,
    holder_count: 2, real_platform: process.platform, architecture: process.arch, ...extra }));
}

test('Windows Job has a live exact root and signed finality after both holders close', options, async t => {
  const session = await runner.createCommandSession({ budgets: policy });
  try {
    assert.equal(proof.validateExecutionScope(session.scope), true);
    const active = proof.queryScopeClosure(session.scope, { timeoutMs: 20000 });
    assert.equal(active.status, 'active', JSON.stringify(active));
    const value = await session.run(command('console.log("native-windows-job")'));
    assert.equal(value.error, null, JSON.stringify(value)); assert.equal(value.status, 0); assert.equal(value.stdout, 'native-windows-job\n');
    assertClosed(await session.drain()); assertClosed(await session.finish());
    const ended = holders(session.scope);
    assert.ok(ended.primary.exit_observed && ended.primary.native_exit_observed && ended.secondary.exit_observed && ended.secondary.native_exit_observed);
    const receipt = receiptIO.readTerminal(session.scope); assertClosed(receipt);
    const fresh = proof.queryScopeClosure(session.scope, { timeoutMs: 20000 }); assertClosed(fresh);
    assert.equal(fresh.basis, 'signed_terminal_receipt');
    diagnostic(t, session, { closure_basis: fresh.basis });
  } finally { await session.drain(); await session.finish(); }
});

for (const role of ['primary', 'secondary']) test(`Windows ${role} holder crash drains admitted descendants and leaves survivor proof`, options, async t => {
  const f = fixture(), marker = path.join(f.root, 'payload-admitted');
  const session = await runner.createCommandSession({ budgets: policy }); let pending;
  try {
    pending = session.run(command(`require('fs').writeFileSync(${JSON.stringify(marker)},'started');setInterval(()=>{},1000)`));
    pending.catch(() => {});
    await until(() => fs.existsSync(marker));
    const owned = holders(session.scope); await killOwned(owned[role]);
    const result = await Promise.allSettled([pending]);
    assert.ok(result[0].status === 'rejected' || result[0].value.error, 'A killed owner must not return a successful command');
    assertClosed(await session.drain()); assertClosed(await session.finish());
    const survivor = role === 'primary' ? 'secondary' : 'primary';
    const receipt = receiptIO.readRole(session.scope, survivor);
    assert.equal(protocol.validateTerminal(receipt, session.scope), true);
    assert.equal(owned[survivor].exit_observed, true); assert.equal(owned[survivor].native_exit_observed, true);
    const fresh = proof.queryScopeClosure(session.scope, { timeoutMs: 20000 }); assertClosed(fresh);
    diagnostic(t, session, { killed_holder: role, surviving_receipt: survivor, closure_basis: fresh.basis });
  } finally {
    await session.drain(); await session.finish(); await Promise.allSettled(pending ? [pending] : []); f.remove();
  }
});

for (const role of ['primary', 'secondary']) test(`Windows ${role} receipt fsync stall and crash does not stop the other native holder`, options, async t => {
  const f = fixture(); injection = { phase: 'receipt_fsync', roles: [role], marker_directory: f.root };
  let session;
  try {
    session = await runner.createCommandSession({ budgets: policy }); injection = undefined;
    const owned = holders(session.scope), closing = session.drain();
    await until(() => fs.existsSync(path.join(f.root, `${role}.receipt_fsync.json`)));
    await killOwned(owned[role]);
    assertClosed(await closing); assertClosed(await session.finish());
    const survivor = role === 'primary' ? 'secondary' : 'primary';
    assert.equal(protocol.validateTerminal(receiptIO.readRole(session.scope, survivor), session.scope), true);
    assertClosed(proof.queryScopeClosure(session.scope, { timeoutMs: 20000 }));
    diagnostic(t, session, { injected_boundary: 'modeled_js_fsync_stall', killed_holder: role,
      actual_kernel_watchdogs: true, incomplete_store_preserved: true });
  } finally { injection = undefined; if (session) { await session.drain(); await session.finish(); } f.remove(); }
});

test('Windows both holders crash before receipt keeps missing Job closure unconfirmed', options, async t => {
  const f = fixture(); injection = { phase: 'bound', roles: ['primary', 'secondary'], marker_directory: f.root };
  let session;
  try {
    session = await runner.createCommandSession({ budgets: policy }); injection = undefined;
    await until(() => ['primary', 'secondary'].every(role => fs.existsSync(path.join(f.root, `${role}.bound.json`))));
    const owned = holders(session.scope);
    // Both JS loops are blocked, so neither can manufacture a terminal file
    // between these creator-owned kills. Native Job teardown is still real.
    const a = killOwned(owned.primary), b = killOwned(owned.secondary); await Promise.all([a, b]);
    const cleanup = await session.drain(); assert.equal(cleanup.status, 'unconfirmed', JSON.stringify(cleanup));
    const finished = await session.finish(); assert.equal(finished.status, 'unconfirmed', JSON.stringify(finished));
    const observed = proof.queryScopeClosure(session.scope, { timeoutMs: 20000 });
    assert.equal(observed.status, 'unconfirmed', JSON.stringify(observed));
    assert.equal(receiptIO.readTerminal(session.scope).status, 'unconfirmed');
    for (const role of ['primary', 'secondary']) assert.equal(fs.existsSync(path.join(session.scope.descriptor.receipt_store.directory, `${role}.closed.json`)), false);
    diagnostic(t, session, { injected_boundary: 'modeled_js_after_bind_stall', actual_holder_crashes: 2,
      missing_receipt_is_not_closure: true, cleanup_status: cleanup.status, preserved_private_artifacts: true });
  } finally { injection = undefined; if (session) { await session.drain(); await session.finish(); } f.remove(); }
});

test('Windows native watchdogs cancel active work while both holder JavaScript loops are blocked', options, async t => {
  const f = fixture(), controller = new AbortController(), marker = path.join(f.root, 'payload-admitted');
  const release = path.join(f.root, 'resume-holder-javascript');
  injection = { phase: 'bound', roles: ['primary', 'secondary'], marker_directory: f.root, release_file: release };
  let session, pending;
  try {
    session = await runner.createCommandSession({ budgets: policy, signal: controller.signal }); injection = undefined;
    await until(() => ['primary', 'secondary'].every(role => fs.existsSync(path.join(f.root, `${role}.bound.json`))));
    pending = session.run(command(`require('fs').writeFileSync(${JSON.stringify(marker)},'started');for(;;){}`)); pending.catch(() => {});
    await until(() => fs.existsSync(marker)); controller.abort();
    await assert.rejects(pending, { code: 'command_cancelled' });
    let native;
    await until(() => {
      native = proof.queryScopeClosure(session.scope, { timeoutMs: 20000 });
      return native.status === 'completed';
    }, 45000);
    assertClosed(native); assert.equal(native.basis, 'current_kernel_job_zero');
    assert.equal(receiptIO.readTerminal(session.scope).status, 'unconfirmed', 'No holder JS has yet been resumed to publish a receipt');
    for (const row of Object.values(holders(session.scope))) assert.equal(row.exit_observed, false);
    fs.writeFileSync(release, 'resume');
    assertClosed(await session.drain()); assertClosed(await session.finish());
    assertClosed(receiptIO.readTerminal(session.scope));
    diagnostic(t, session, { injected_boundary: 'both_holder_js_loops_blocked_during_active_command',
      kernel_zero_before_js_resumption: true, native_watchdog_cancel: true });
  } finally {
    injection = undefined; controller.abort();
    if (!fs.existsSync(release)) fs.writeFileSync(release, 'resume');
    if (session) { await session.drain(); await session.finish(); }
    await Promise.allSettled(pending ? [pending] : []); f.remove();
  }
});

test('Windows fresh observer rejects forged terminal files, wrong root birth and cross-scope replay', options, async t => {
  const a = await runner.createCommandSession({ budgets: policy }), b = await runner.createCommandSession({ budgets: policy });
  try {
    assertClosed(await a.drain()); assertClosed(await b.drain()); assertClosed(await a.finish()); assertClosed(await b.finish());
    const store = a.scope.descriptor.receipt_store.directory;
    const originals = Object.fromEntries(['primary', 'secondary'].map(role => [role, fs.readFileSync(path.join(store, `${role}.closed.json`))]));
    try {
      for (const role of ['primary', 'secondary']) {
        const value = JSON.parse(originals[role]); value.signature = Buffer.alloc(64, 1).toString('base64');
        fs.writeFileSync(path.join(store, `${role}.closed.json`), JSON.stringify(value));
      }
      assert.equal(proof.queryScopeClosure(a.scope, { timeoutMs: 20000 }).status, 'unconfirmed');
      for (const role of ['primary', 'secondary']) fs.writeFileSync(path.join(store, `${role}.closed.json`), JSON.stringify(receiptIO.readRole(b.scope, role)));
      assert.equal(proof.queryScopeClosure(a.scope, { timeoutMs: 20000 }).status, 'unconfirmed');
    } finally { for (const role of ['primary', 'secondary']) fs.writeFileSync(path.join(store, `${role}.closed.json`), originals[role]); }
    const wrong = JSON.parse(JSON.stringify(a.scope)); wrong.descriptor.root.birth_filetime = String(BigInt(wrong.descriptor.root.birth_filetime) + 1n);
    assert.equal(protocol.validateScope(wrong), true);
    assert.equal(proof.queryScopeClosure(wrong, { timeoutMs: 20000 }).status, 'unconfirmed');
    assertClosed(proof.queryScopeClosure(a.scope, { timeoutMs: 20000 }));
    diagnostic(t, a, { forged_file_rejected: true, wrong_root_rejected: true, replay_rejected: true });
  } finally { await a.drain(); await b.drain(); await a.finish(); await b.finish(); }
});

for (const role of ['primary', 'secondary']) test(`Windows ${role} launcher crash preserves native holder drain and survivor receipt`, options, async t => {
  const f = fixture(), marker = path.join(f.root, 'payload-admitted');
  const session = await runner.createCommandSession({ budgets: policy }); let pending, cleanable = false;
  try {
    pending = session.run(command(`require('fs').writeFileSync(${JSON.stringify(marker)},'started');setInterval(()=>{},1000)`));
    pending.catch(() => {}); await until(() => fs.existsSync(marker));
    const owned = holders(session.scope), row = owned[role];
    assert.ok(row.birth_binding && !row.exit_observed);
    row.child.kill('SIGKILL'); await until(() => row.exit_observed);
    await Promise.allSettled([pending]);
    assertClosed(await session.drain()); assertClosed(await session.finish());
    assertClosed(proof.queryScopeClosure(session.scope, { timeoutMs: 20000 }));
    assertClosed(receiptIO.readTerminal(session.scope));cleanable = true;
    diagnostic(t, session, { killed_launcher: role, holder_death_separately_queried: true, cancellation_pipe_eof: true });
  } finally {
    await session.drain(); await session.finish(); await Promise.allSettled(pending ? [pending] : []);
    if (cleanable) f.remove(); else t.diagnostic('Fixture retained: launcher exit alone is not holder finality');
  }
});
