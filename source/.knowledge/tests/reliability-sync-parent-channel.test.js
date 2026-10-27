'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), cp = require('node:child_process');
const source = path.resolve(__dirname, '..'), driver = path.join(source, 'tools/lib/command-sync-driver.js');
const preload = path.join(__dirname, 'helpers/reliability-sync-operation.cjs');
const supported = ['linux', 'win32'].includes(process.platform), wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const budgets = { workMs: 30000, setupMs: 10000, cleanupMs: 5000, progressMs: 0 };
const env = { ...process.env, NODE_OPTIONS: '', NODE_PATH: '', KNOWLEDGE_SYNC_TEST_SOURCE: source };
for (const operation of ['positive', 'expected-failure']) test(`sync parent channel preserves ${operation} result`, { skip: !supported, timeout: 20000 }, () => {
  const child = cp.spawnSync(process.execPath, ['--require', preload, driver], {
    input: JSON.stringify({ operation, payload: {}, budgets }), env, stdio: ['pipe', 'pipe', 'pipe', 'pipe'], encoding: 'utf8', timeout: 15000
  });
  assert.equal(child.error, undefined); assert.equal(child.signal, null);
  assert.equal(child.status, operation === 'positive' ? 0 : 1, child.stderr + child.stdout);
  const result = JSON.parse(child.stdout);
  if (operation === 'positive') { assert.equal(result.value.status, 'passed'); assert(result.value.setupMs > 0 && result.value.setupMs <= budgets.setupMs); }
  else assert.equal(result.error.code, 'fixture_expected_failure');
  assert(/^[\x00]+$/.test(child.output[3]), 'The declared child-writable pipe must carry its initial liveness byte');
});
for (const mode of ['reader-close', 'parent-crash']) test(`sync parent channel confirms driver exit after ${mode}`, { skip: !supported, timeout: 40000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-sync-parent-')), marker = path.join(root, 'driver.json'), abort = path.join(root, 'abort');
  let helper, child, closed = false, exactExit = false, stream = '', diagnostic = '';
  if (process.platform === 'win32') { helper = require(path.join(source, 'tools/lib/command-windows-native')).preparePackagedHelper({ verifyLoad: false }); fs.writeFileSync(path.join(root, 'helper.json'), JSON.stringify(helper)); }
  const request = JSON.stringify({ operation: 'wait', payload: { marker, abort, helper: path.join(root, 'helper.json') }, budgets });
  function nativeExit(identity) {
    if (process.platform === 'linux') return require(path.join(source, 'tools/lib/verification-linux-namespace')).verifyProcessExit(identity).status === 'exited';
    const p = cp.spawnSync(process.execPath, [path.join(source, 'tools/lib/command-windows-observe-holder.js')], {
      input: JSON.stringify({ helper, identity, nonce: 'a'.repeat(64), timeoutMs: 3000 }), env, encoding: 'utf8', timeout: 5000
    });
    if (p.status !== 0 || p.error || p.signal) return false;
    try { return JSON.parse(p.stdout).observation.status === 'exited'; } catch { return false; }
  }
  t.after(async () => {
    if (child && !closed) child.kill('SIGKILL');
    const end = process.hrtime.bigint() + 10000000000n;
    while (!closed && process.hrtime.bigint() < end) await wait(20);
    if (!exactExit && fs.existsSync(marker)) exactExit = nativeExit(JSON.parse(fs.readFileSync(marker)).identity);
    const artifact = helper && exactExit ? require(path.join(source, 'tools/lib/command-windows-native')).cleanupPreparedHelper(helper) : null;
    if (closed && exactExit && (!helper || artifact?.status === 'completed')) fs.rmSync(root, { recursive: true, force: true });
    else t.diagnostic(JSON.stringify({ fixture_retained: root, closed, exactExit, artifact }));
  });
  if (mode === 'reader-close') {
    child = cp.spawn(process.execPath, ['--require', preload, driver], { env, stdio: ['pipe', 'pipe', 'pipe', 'pipe'] });
    child.stdin.end(request); child.stdout.on('data', b => { stream += b; }); child.stderr.on('data', b => { diagnostic += b; }); child.stdio[3].resume();
  } else {
    const controller = path.join(root, 'parent.cjs');
    fs.writeFileSync(controller, `const cp=require('node:child_process');const r=cp.spawnSync(process.execPath,${JSON.stringify(['--require', preload, driver])},{env:process.env,input:${JSON.stringify(request)},encoding:'utf8',stdio:['pipe','pipe','pipe','pipe'],timeout:35000});process.stdout.write(JSON.stringify({status:r.status,stdout:r.stdout,stderr:r.stderr}));`);
    child = cp.spawn(process.execPath, [controller], { env, stdio: ['ignore', 'pipe', 'pipe'] }); child.stdout.on('data', b => { stream += b; }); child.stderr.on('data', b => { diagnostic += b; });
  }
  child.once('close', () => { closed = true; });
  const readyEnd = process.hrtime.bigint() + 10000000000n;
  while (!fs.existsSync(marker) && !closed && process.hrtime.bigint() < readyEnd) await wait(20);
  assert(fs.existsSync(marker), JSON.stringify({ stream, diagnostic, closed }));
  const identity = JSON.parse(fs.readFileSync(marker)).identity;
  assert.equal(nativeExit(identity), false, 'The exact driver birth must be active before the fault');
  if (mode === 'reader-close') child.stdio[3].destroy(); else child.kill('SIGKILL');
  const end = process.hrtime.bigint() + 10000000000n;
  while (process.hrtime.bigint() < end) { if (closed && nativeExit(identity)) { exactExit = true; break; } await wait(50); }
  assert(closed); assert(exactExit, JSON.stringify({ stream, diagnostic }));
  if (mode === 'reader-close') { assert.equal(child.exitCode, 1); assert.equal(JSON.parse(stream).error.code, 'command_cancelled'); assert(fs.existsSync(abort)); }
  else assert.equal(child.signalCode, 'SIGKILL');
});
