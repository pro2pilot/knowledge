'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const runner = require('../tools/lib/command-runner');
const supported = ['linux', 'win32'].includes(process.platform);
const policy = { workMs: 6000, progressMs: 0, setupMs: 10000, cleanupMs: 10000 };
function command(code) { return { executable: process.execPath, args: ['-e', code], cwd: process.cwd(), env: process.env }; }
function assertDrained(result) { assert.equal(result.cleanup?.status, 'completed', JSON.stringify(result)); assert.equal(result.cleanup.active_processes, 0); assert.equal(result.cleanup.output_closed, true); }

test('budgets preserve long work, default no-progress disabled, invalid values rejected', () => {
  assert.deepEqual(runner.budgets(), { workMs: 3600000, progressMs: 0, cleanupMs: 60000, setupMs: 60000 });
  for (const value of [{ workMs: 0 }, { cleanupMs: -1 }, { workMs: Infinity }, { setupMs: 2.5 }, { progressMs: -1 }]) assert.throws(() => runner.budgets(value), { code: 'command_budget_invalid' });
});
test('real native command and trailing pipe bytes complete only after drain', { skip: !supported }, async () => {
  const output = 'x'.repeat(100000);
  // Generate the same bytes inside the child. Windows bounds a command line;
  // the assertion is about pipe completion, not oversized argv transport.
  const result = await runner.runOwnedCommand(command('process.stdout.write("x".repeat(100000));'), { budgets: policy });
  assert.equal(result.error, null, JSON.stringify(result)); assert.equal(result.status, 0); assert.equal(result.stdout, output); assertDrained(result);
});
test('silent long work is allowed without a configured progress deadline', { skip: !supported }, async () => {
  const start = runner.mono();
  const result = await runner.runOwnedCommand(command('setTimeout(()=>console.log(JSON.stringify({status:"ok"})),400)'), { budgets: policy });
  assert.equal(result.status, 0, JSON.stringify(result)); assert.ok(runner.mono() - start >= 400); assertDrained(result);
});
test('native guard reports the real nonzero exit without fabricating success', { skip: !supported }, async () => {
  const result = await runner.runOwnedCommand(command('process.exit(7)'), { budgets: policy });
  assert.equal(result.status, 7, JSON.stringify(result)); assert.equal(result.error, null); assertDrained(result);
});
test('output noise cannot extend the absolute work deadline', { skip: !supported }, async () => {
  const result = await runner.runOwnedCommand(command('setInterval(()=>process.stdout.write("noise\\n"),2)'), { budgets: { ...policy, workMs: 180 } });
  assert.equal(result.error?.code, 'command_work_timeout', JSON.stringify(result)); assertDrained(result);
});
test('output noise is not meaningful progress', { skip: !supported }, async () => {
  const result = await runner.runOwnedCommand(command('setInterval(()=>process.stderr.write("noise\\n"),2)'), { budgets: { ...policy, progressMs: 180 } });
  assert.equal(result.error?.code, 'command_progress_timeout', JSON.stringify(result)); assertDrained(result);
});
test('wall-clock rollback does not shorten or invert the monotonic duration', { skip: !supported }, async () => {
  const prior = Date.now; Date.now = () => -3600000;
  try {
    const start = runner.mono();
    const result = await runner.runOwnedCommand(command('setTimeout(()=>console.log("ok"),250)'), { budgets: policy });
    assert.equal(result.status, 0, JSON.stringify(result)); assert.ok(runner.mono() - start >= 250); assertDrained(result);
  } finally { Date.now = prior; }
});
test('detached descendants that close both output pipes are drained before acceptance', { skip: !supported }, async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owned-descendant-')), marker = path.join(root, 'late-write');
  try {
    const descendant = `setTimeout(()=>require('fs').writeFileSync(${JSON.stringify(marker)},'leaked'),1200);setInterval(()=>{},1000)`;
    const code = `const p=require('child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{detached:true,stdio:'ignore'});p.unref();console.log(JSON.stringify({status:'ok'}));`;
    const result = await runner.runOwnedCommand(command(code), { budgets: policy });
    assert.equal(result.status, 0, JSON.stringify(result)); assertDrained(result);
    await runner.delay(1400); assert.equal(fs.existsSync(marker), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('AbortSignal stops an admitted command independently of its I/O', { skip: !supported }, async () => {
  const controller = new AbortController(); let timer;
  const result = await runner.runOwnedCommand(command('console.log("admitted");for(;;){}'), {
    budgets: policy, signal: controller.signal,
    onOutput(name, bytes) { if (bytes.includes('admitted')) timer = setTimeout(() => controller.abort(), 30); }
  });
  clearTimeout(timer); assert.equal(result.error?.code, 'command_cancelled', JSON.stringify(result)); assertDrained(result);
});
test('bounded output overflow drains the scope and cannot return a successful candidate', { skip: !supported }, async () => {
  const result = await runner.runOwnedCommand(command('setInterval(()=>process.stdout.write("x".repeat(10000)),1)'), { budgets: policy, maxOutputBytes: 20000 });
  assert.equal(result.error?.code, 'command_output_limit', JSON.stringify(result)); assertDrained(result); assert.ok(Buffer.byteLength(result.stdout) <= 20000);
});
test('persistent command session supports nested native scopes and drains between commands', { skip: !supported }, async () => {
  const session = await runner.createCommandSession({ budgets: policy });
  try {
    const first = await session.run(command('console.log("first")'));
    const second = await session.run(command('console.log("second")'));
    assert.equal(first.status, 0, JSON.stringify(first)); assert.equal(second.status, 0, JSON.stringify(second));
    assertDrained(first); assertDrained(second);
  } finally { assert.equal((await session.drain()).status, 'completed'); assert.equal((await session.finish()).status, 'completed'); }
});
test('scope proof distinguishes a live session from its immutable native finality', { skip: process.platform !== 'linux' }, async () => {
  const proof = require('../tools/lib/command-scope-proof');
  const session = await runner.createCommandSession({ budgets: policy });
  assert.equal(proof.validateExecutionScope(session.scope), true);
  try { assert.equal(proof.queryScopeClosure(session.scope, { timeoutMs: 4999.5 }).status, 'active'); }
  finally { assert.equal((await session.drain()).status, 'completed'); await session.finish(); }
  const closed = proof.queryScopeClosure(session.scope);
  assert.equal(closed.status, 'completed', JSON.stringify(closed)); assert.equal(closed.namespace_drained, true);
  const wrong = JSON.parse(JSON.stringify(session.scope)); wrong.observer_lineage[0].depth++;
  assert.equal(proof.validateExecutionScope(wrong), false); assert.equal(proof.queryScopeClosure(wrong).status, 'unconfirmed');
});
test('invalid UTF-8 stdout cannot become a successful semantic candidate', { skip: !supported }, async () => {
  const result = await runner.runOwnedCommand(command('process.stdout.write(Buffer.from([0x7b,0x22,0xc3,0x22,0x7d]))'), { budgets: policy });
  assert.equal(result.error?.code, 'command_output_encoding', JSON.stringify(result));
  assertDrained(result);
});
test('concurrent session request is refused without disturbing the first admitted command', { skip: !supported }, async () => {
  const session = await runner.createCommandSession({ budgets: policy });
  let first;
  try {
    first = session.run(command('setTimeout(()=>console.log("first-completed"),200)'));
    await assert.rejects(session.run(command('console.log("forbidden-concurrent")')), { code: 'command_concurrent_request' });
    const completed = await first;
    assert.equal(completed.status, 0, JSON.stringify(completed)); assert.equal(completed.stdout, 'first-completed\n'); assertDrained(completed);
    const next = await session.run(command('console.log("next-completed")'));
    assert.equal(next.status, 0, JSON.stringify(next)); assert.equal(next.stdout, 'next-completed\n'); assertDrained(next);
  } finally {
    assert.equal((await session.drain()).status, 'completed');
    await Promise.allSettled(first ? [first] : []);
    assert.equal((await session.finish()).status, 'completed');
  }
});
test('a session budget closes native admission even if its caller never requests drain', { skip: process.platform !== 'linux' }, async () => {
  const proof = require('../tools/lib/command-scope-proof');
  const session = await runner.createCommandSession({ budgets: { ...policy, workMs: 200 } });
  try {
    const deadline = runner.mono() + policy.cleanupMs;
    let observed;
    do {
      await runner.delay(30); observed = proof.queryScopeClosure(session.scope);
    } while (observed.status !== 'completed' && runner.mono() < deadline);
    assert.equal(observed.status, 'completed', JSON.stringify(observed));
    assert.equal(observed.namespace_drained, true);
    await assert.rejects(session.run(command('console.log("forbidden-late")')), { code: 'command_work_timeout' });
  } finally { assert.equal((await session.drain()).status, 'completed'); assert.equal((await session.finish()).status, 'completed'); }
});
test('a throwing output consumer causes native drain and preserves its error category', { skip: !supported }, async () => {
  const result = await runner.runOwnedCommand(command('console.log("first");setInterval(()=>{},1000)'), {
    budgets: policy, onOutput() { throw new Error('consumer broke'); }
  });
  assert.equal(result.error?.code, 'command_output_callback_failed', JSON.stringify(result)); assertDrained(result);
});
