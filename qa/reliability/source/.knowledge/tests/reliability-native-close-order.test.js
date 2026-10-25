'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const native = require('../tools/lib/verification-linux-namespace');
test('native close waits for its actual control EOF when keeper exit is delivered first', { skip: process.platform !== 'linux' }, async () => {
  const helper = native.preparePackagedHelper();
  const { worker, job } = native.spawnLinuxContainedWorker(process.execPath, ['-e', 'setInterval(()=>{},1000)'],
    { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }, { preparedHelper: helper, lifetimeMs: 20000 });
  const control = worker.stdio[4], resume = control.resume; let pending, receipt, settled = false, raw = '';
  control.on('data', chunk => { raw += chunk; });
  try {
    await job.ready; job.permit(); await job.started;
    // This is real kernel exit and real final bytes. Only their delivery order
    // to JavaScript is held, matching a loaded/backpressured event loop.
    control.pause();
    // ChildProcess normally resumes unread streams after exit. Hold that
    // automatic delivery too, then restore the original stream method.
    control.resume = function () { return this; };
    const exit = new Promise(resolve => worker.once('exit', resolve));
    pending = job.close(10000); pending.then(value => { receipt = value; settled = true; });
    await exit;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(settled, false, JSON.stringify({ receipt, raw, keeper_exit_code: worker.exitCode }));
    control.resume = resume; control.resume();
    receipt = await pending;
    assert.equal(receipt.status, 'completed', JSON.stringify({ receipt, raw }));
    assert.equal(receipt.active_processes, 0); assert.equal(receipt.init_reaped, true);
  } finally {
    control.resume = resume; control.resume(); receipt = await (pending || job.close(10000));
    console.log(JSON.stringify({ scenario: 'real_native_exit_before_control_EOF', keeper_exit_code: worker.exitCode,
      keeper_signal: worker.signalCode, receipt, raw_control: raw }));
    if (worker.connected) worker.disconnect();
  }
});
for (const corruption of ['partial_line', 'duplicate_closed', 'unknown_after_closed']) {
  test(`native close rejects ${corruption} despite a real successful keeper exit`, { skip: process.platform !== 'linux' }, async () => {
    const helper = native.preparePackagedHelper();
    const { worker, job } = native.spawnLinuxContainedWorker(process.execPath, ['-e', 'setInterval(()=>{},1000)'],
      { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }, { preparedHelper: helper, lifetimeMs: 20000 });
    const control = worker.stdio[4], emit = control.emit;
    let pending, nativeBytes = '', injectedBytes;
    try {
      await job.ready; job.permit(); await job.started;
      // Explicit transport-fault model after real native admission. The
      // keeper still performs its real kill/reap; only terminal wire delivery
      // is altered before the JavaScript consumer sees it.
      control.emit = function (event, ...args) {
        if (event === 'data') { nativeBytes += String(args[0]); return true; }
        if (event === 'end') {
          const terminal = nativeBytes.trimEnd().split('\n').find(line => JSON.parse(line).status === 'closed');
          injectedBytes = corruption === 'partial_line' ? nativeBytes.trimEnd()
            : corruption === 'duplicate_closed' ? nativeBytes + terminal + '\n'
            : nativeBytes + '{"protocol":"knowledge-linux-namespace-helper.v1","status":"unexpected"}\n';
          emit.call(this, 'data', injectedBytes);
        }
        return emit.call(this, event, ...args);
      };
      pending = job.close(10000); const receipt = await pending;
      assert.equal(worker.exitCode, 0); assert.equal(worker.signalCode, null);
      assert.equal(receipt.status, 'unconfirmed', JSON.stringify(receipt));
      console.log(JSON.stringify({ scenario: 'terminal_control_fault', scope: 'real native drain plus modeled transport corruption',
        corruption, native_control: nativeBytes, injected_control: injectedBytes, receipt }));
    } finally {
      await (pending || job.close(10000)); control.emit = emit;
      if (worker.connected) worker.disconnect();
    }
  });
}
