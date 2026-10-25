'use strict';
// Real local child/IPC lifecycle; hashing/ACL observation is deliberately
// modeled. This helper is never imported by runtime code.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const cp = require('node:child_process');
const { once } = require('node:events');
const assert = require('node:assert/strict');
async function withFixture(t, mode, action, { suppressKill = false, onMessage, trace } = {}) {
  const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-preparer-fixture-'));
  const file = path.join(root, 'fixture.js'), originalFork = cp.fork, children = [];
  let reached;const ready = new Promise(resolve => { reached = resolve; });
  fs.writeFileSync(file, `'use strict';
const mode=process.argv[2];process.on('disconnect',()=>process.exit(1));
process.once('message',q=>{
 const hex='a'.repeat(64),pins=Object.fromEntries(['source_sha256','stub_source_sha256','transport_header_sha256','uid_history_header_sha256','uid_history_source_sha256'].map(k=>[k,hex]));
 const executable={schema:'knowledge-darwin-protected-executable.v1',status:'verified',sha256:hex,device:'1',inode:'2',bytes:'3',ctime_sec:'1',ctime_nsec:'0',mtime_sec:'1',mtime_nsec:'0'};
 const value={type:'prepared_readonly',nonce:q.nonce,pins,binarySHA:hex,runtimeSHA:hex,executable};
 if(mode==='late-success')process.on('SIGTERM',()=>{});
 process.stderr.write('READY\\n',()=>{
  if(mode==='hold'){Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,30000);return;}
  if(mode==='late-success'){setTimeout(()=>process.send(value,()=>process.exit(0)),150);return;}
  if(mode==='wrong-nonce')value.nonce='b'.repeat(64);
  if(mode==='oversized')value.extra='x'.repeat(20000);
  process.send(value,()=>{
   if(mode==='result-without-exit'){setInterval(()=>{},1000);return;}
   if(mode==='duplicate'){process.send(value,()=>setInterval(()=>{},1000));return;}
   process.exit(0);
  });
 });
});
`);
  t.mock.method(cp, 'fork', (module, args, options) => {
    assert.equal(path.basename(module), 'verification-darwin-preparer.js');assert.deepEqual(args, []);
    assert.deepEqual(options.execArgv, []);assert.equal(options.execPath, process.execPath);
    const child = originalFork(file, [mode], options), originalKill = child.kill;
    const exited = once(child, 'exit');children.push({ child, originalKill, exited });
    if (trace) { child.on('exit', (code, signal) => trace({ event: 'fixture_exit', pid: child.pid, code, signal }));
      child.on('close', (code, signal) => trace({ event: 'fixture_close', pid: child.pid, code, signal })); }
    child.stderr.on('data', bytes => { if (bytes.toString().includes('READY')) reached(child); });
    if (onMessage) child.on('message', onMessage);
    if (suppressKill) child.kill = () => false;
    return child;
  });
  try { return await action({ ready, children }); }
  finally {
    t.mock.restoreAll();
    for (const { child, originalKill, exited } of children) {
      // The production unconfirmed path intentionally unrefs its surviving
      // read-only child. The test controller must re-own the event-loop handle
      // before its independent forced cleanup and physical close observation.
      child.ref();
      trace?.({ event: 'cleanup_begin', pid: child.pid, exitCode: child.exitCode, signalCode: child.signalCode });
      if (child.exitCode === null && child.signalCode === null) {
        const signaled = originalKill.call(child, 'SIGKILL');trace?.({ event: 'cleanup_signal', pid: child.pid, signaled });
      }
      // The deliberately forced-disconnect negative path has destroyed its
      // pipes; Node can omit ChildProcess 'close' in that state. Test cleanup
      // observes actual waitpid-backed 'exit', then closes only its own handles.
      await exited;child.stderr?.destroy();if (child.connected) child.disconnect();child.unref();
      trace?.({ event: 'cleanup_exit_confirmed', pid: child.pid });
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
}
module.exports = { withFixture };
