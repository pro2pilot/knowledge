'use strict';
const fs = require('fs'), path = require('path');
const [source, fixture, kind] = process.argv.slice(2);
const context = JSON.parse(fs.readFileSync(path.join(fixture, 'context.json')));
const controller = new AbortController();
process.on('SIGTERM', () => controller.abort());
process.on('SIGINT', () => controller.abort());
fs.writeFileSync(path.join(fixture, 'caller.json'), JSON.stringify({ pid: process.pid, proc_pid: Number(fs.readlinkSync('/proc/self')) }));
const options = { signal: controller.signal, budgets: { workMs: 20000, cleanupMs: 5000, setupMs: 10000 } };
(async () => {
  if (kind === 'flow-write') {
    const flow = require(path.join(source, 'tools/flow.js'));
    const request = { name: 'doctor', context, json: true, quiet: true };
    // The same external API intent is exercised on the recorded synchronous
    // predecessor and on the new explicit asynchronous API. No product hook
    // fakes command execution, native cleanup or the cancellation result.
    if (typeof flow.runFlowAsync === 'function') await flow.runFlowAsync(request, options);
    else flow.runFlow(request, options);
  } else {
    const evaluation = require(path.join(source, 'tools/evaluation-harness.js'));
    if (typeof evaluation.mainAsync === 'function') await evaluation.mainAsync(options);
    else evaluation();
  }
  console.log(JSON.stringify({ status: 'unexpected_success' }));
})().catch(error => {
  console.log(JSON.stringify({ status: 'failed', code: error.code || null, cleanup: error.cleanup || null }));
  process.exitCode = 1;
});
