'use strict';
// Physical gaps exposed by the formerly unowned aggregate QA timeout.
// These use the shipped Job owner unchanged; no mocked process/Job result.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path'), net = require('net'), crypto = require('crypto'), cp = require('child_process');
assert.equal(process.platform, 'win32', 'This gate requires physical Windows Job Objects');
const runner = require('../tools/lib/command-runner');
const protocol = require('../tools/lib/command-windows-protocol');
const policy = { workMs: 30000, setupMs: 30000, cleanupMs: 30000, progressMs: 0 };
const options = { timeout: 120000 };
function command(code) { return { executable: process.execPath, args: ['-e', code], cwd: process.cwd(), env: process.env }; }
function drained(t, result, scope, detail = {}) {
  assert.equal(protocol.validateScope(scope), true, 'Native scope must retain exact process births and source binding');
  assert.equal(result.cleanup?.status, 'completed', JSON.stringify(result));
  for (const key of ['root_exited', 'output_closed', 'primary_holder_exited', 'secondary_holder_exited']) assert.equal(result.cleanup[key], true, key);
  assert.equal(result.cleanup.active_processes, 0);
  assert.equal(result.cleanup.artifact_cleanup?.status, 'completed');
  assert.ok(result.cleanup.cleanup_duration_ms >= 0 && result.cleanup.cleanup_duration_ms <= policy.cleanupMs);
  t.diagnostic(JSON.stringify({ native_scope: scope, cleanup: result.cleanup, ...detail }));
}

test('Windows direct child exit with inherited output pipes drains the live pipe holder', options, async t => {
  let scope;
  const leaf = 'process.send({ready:true});setInterval(()=>{},1000);';
  const code = `const p=require('child_process').spawn(process.execPath,['-e',${JSON.stringify(leaf)}],{stdio:['ignore',1,2,'ipc']});p.once('message',()=>{p.disconnect();console.log('direct-exit-with-live-pipe-holder');process.exit(0);});`;
  const result = await runner.runOwnedCommand(command(code), { budgets: policy,
    onNativeReady(d) { scope = protocol.commandScope(d); } });
  assert.equal(result.status, 0, JSON.stringify(result)); assert.equal(result.error, null);
  assert.equal(result.stdout.trim(), 'direct-exit-with-live-pipe-holder');
  drained(t, result, scope, { direct_exit_before_pipe_holder_exit: true });
});

for (const direction of ['read', 'write']) test(`Windows cancellation drains an actual pending named-pipe ${direction}`, options, async t => {
  const pipe = '\\\\.\\pipe\\knowledge-audit8-' + crypto.randomBytes(16).toString('hex');
  const sockets = new Set(); let connected = 0, scope, timer, attempted = false, observedOutput = '';
  const server = net.createServer(socket => {
    connected++; sockets.add(socket); socket.pause();
    socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(pipe, resolve); });
  const controller = new AbortController();
  const operation = direction === 'read'
    ? 'fs.readSync(fd,Buffer.alloc(1),0,1,null);'
    : 'const bytes=Buffer.alloc(65536);for(let i=0;i<4096;i++)fs.writeSync(fd,bytes,0,bytes.length);';
  const code = `const fs=require('fs');const fd=fs.openSync(${JSON.stringify(pipe)},${JSON.stringify(direction === 'read' ? 'r' : 'w')});fs.writeSync(1,Buffer.from('io-connected\\n'));${operation}fs.writeSync(1,Buffer.from('io-returned\\n'));setInterval(()=>{},1000);`;
  try {
    const result = await runner.runOwnedCommand(command(code), { budgets: policy, signal: controller.signal,
      onNativeReady(d) { scope = protocol.commandScope(d); },
      onOutput(name, bytes) {
        if (name === 'stdout') observedOutput = (observedOutput + bytes.toString('utf8')).slice(-4096);
        if (name === 'stdout' && observedOutput.includes('io-connected') && !attempted) {
          attempted = true; timer = setTimeout(() => controller.abort(), 250);
        }
      }
    });
    clearTimeout(timer);
    assert.equal(connected, 1, 'The real Windows named-pipe connection must be observed');
    assert.equal(attempted, true); assert.equal(result.stdout.includes('io-returned'), false,
      'An I/O operation that already returned is not the intended pending-I/O case');
    assert.equal(result.error?.code, 'command_cancelled', JSON.stringify(result));
    drained(t, result, scope, { physical_io: 'windows_named_pipe', direction, provider_sent_bytes: 0,
      provider_reads_paused: true, connected, pending_operation_completed_normally: false });
  } finally {
    clearTimeout(timer); controller.abort(); for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  }
});

test('Windows cancellation seals late descendant births without a numerical PID sweep', options, async t => {
  let scope, ready = false, observedOutput = ''; const controller = new AbortController();
  const child = 'setInterval(()=>{},1000);';
  const code = `const cp=require('child_process');let n=0;const timer=setInterval(()=>{const p=cp.spawn(process.execPath,['-e',${JSON.stringify(child)}],{detached:true,stdio:['ignore',1,2]});p.unref();console.log('birth-'+(++n));if(n===8)clearInterval(timer);},25);setInterval(()=>{},1000);`;
  const result = await runner.runOwnedCommand(command(code), { budgets: policy, signal: controller.signal,
    onNativeReady(d) { scope = protocol.commandScope(d); },
    onOutput(name, bytes) {
      if (name === 'stdout') observedOutput = (observedOutput + bytes.toString('utf8')).slice(-4096);
      if (name === 'stdout' && observedOutput.includes('birth-2')) { ready = true; controller.abort(); }
    }
  });
  assert.equal(ready, true); assert.equal(result.error?.code, 'command_cancelled', JSON.stringify(result));
  drained(t, result, scope, { racing_births: true, numerical_pid_cleanup_used: false });
});

test('Windows cancellation at native readiness admits no project command and confirms drain', options, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'windows-admission-cancel-'));
  const marker = path.join(root, 'forbidden-project-work'); let scope, cleanable = false;
  const controller = new AbortController();
  try {
    const result = await runner.runOwnedCommand(command(`require('fs').writeFileSync(${JSON.stringify(marker)},'forbidden');`), {
      budgets: policy, signal: controller.signal,
      onNativeReady(d) { scope = protocol.commandScope(d); controller.abort(); }
    });
    assert.equal(result.error?.code, 'command_cancelled', JSON.stringify(result));
    assert.equal(fs.existsSync(marker), false);
    drained(t, result, scope, { synchronous_cancel_at_native_readiness: true, project_work_admitted: false });
    cleanable = true;
  } finally { if (cleanable) fs.rmSync(root, { recursive: true, force: true }); }
});


test('Windows case-insensitive Node preload variables cannot execute before native admission', options, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'windows-env-case-'));
  const marker = path.join(root, 'unexpected-preload'), preload = path.join(root, 'preload.cjs');
  fs.writeFileSync(preload, `require('fs').writeFileSync(${JSON.stringify(marker)},'preload-ran');`);
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toUpperCase() === 'NODE_OPTIONS') delete env[key];
  env.node_options = '--require=' + JSON.stringify(preload.replace(/\\/g, '/'));
  let scope, cleanable = false;
  try {
    // Real positive control on this Windows/Node pair, already enclosed by
    // the outer QA Job: the case variant must actually activate the preload.
    const baseline = cp.spawnSync(process.execPath, ['-e', 'console.log("baseline");'],
      { env, encoding: 'utf8', timeout: 10000, windowsHide: true });
    assert.equal(baseline.status, 0, baseline.stderr || JSON.stringify(baseline.error));
    assert.equal(fs.readFileSync(marker, 'utf8'), 'preload-ran'); fs.unlinkSync(marker);
    const filtered = runner.safeEnvironment({ ...env, nOdE_pAtH: root, node_channel_fd: '3', Node_Channel_Serialization_Mode: 'advanced' });
    assert.equal(Object.keys(filtered).some(key => ['NODE_OPTIONS','NODE_PATH','NODE_CHANNEL_FD','NODE_CHANNEL_SERIALIZATION_MODE'].includes(key.toUpperCase())), false);
    const result = await runner.runOwnedCommand({ ...command('console.log("owned-normal");'), env }, {
      budgets: policy, onNativeReady(d) { scope = protocol.commandScope(d); }
    });
    assert.equal(result.status, 0, JSON.stringify(result)); assert.equal(result.error, null);
    assert.equal(result.stdout.trim(), 'owned-normal');
    assert.equal(fs.existsSync(marker), false, 'A case-variant preload executed before or inside the owned command');
    drained(t, result, scope, { real_case_insensitive_preload_positive_control: true, owned_command_preload_executed: false });
    cleanable = true;
  } finally { if (cleanable) fs.rmSync(root, { recursive: true, force: true }); }
});
