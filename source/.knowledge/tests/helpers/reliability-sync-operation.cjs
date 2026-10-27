'use strict';
// Test-only operation adapter: the production driver, pipe and process exits
// remain real. No project command or product containment proof is modeled.
const Module = require('node:module'), fs = require('node:fs'), path = require('node:path');
const source = process.env.KNOWLEDGE_SYNC_TEST_SOURCE;
const original = Module._load;
const runner = original(path.join(source, 'tools/lib/command-runner.js'), module, false);
Module._load = function (request, parent, isMain) {
  if (request === './command-runner' && parent?.filename === path.join(source, 'tools/lib/command-sync-driver.js')) {
    return { ...runner, async runOwnedOperation(operation, payload, options) {
      if (operation === 'wait') {
        let identity;
        if (process.platform === 'linux') identity = require(path.join(source, 'tools/lib/verification-linux-namespace')).currentProcessIdentity();
        else {
          const record = JSON.parse(fs.readFileSync(payload.helper));
          identity = require(path.join(source, 'tools/lib/command-windows-native')).loadPreparedHelper(record).native.currentIdentity();
        }
        fs.writeFileSync(payload.marker, JSON.stringify({ identity, pid: process.pid }));
        return new Promise((resolve, reject) => {
          const stop = () => { fs.writeFileSync(payload.abort, 'observed'); reject(Object.assign(new Error('cancelled'), { code: 'command_cancelled' })); };
          if (options.signal.aborted) stop(); else options.signal.addEventListener('abort', stop, { once: true });
        });
      }
      await new Promise(resolve => setTimeout(resolve, 100));
      if (options.signal.aborted) throw Object.assign(new Error('Parent unexpectedly closed'), { code: 'command_cancelled' });
      if (operation === 'expected-failure') throw Object.assign(new Error('Expected failure'), { code: 'fixture_expected_failure' });
      return { value: { status: 'passed', setupMs: options.budgets.setupMs } };
    } };
  }
  return original(request, parent, isMain);
};
