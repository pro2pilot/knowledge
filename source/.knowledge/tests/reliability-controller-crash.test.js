'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const runner = require('../tools/lib/command-runner');
const source = path.resolve(process.env.KNOWLEDGE_TEST_TARGET_SOURCE || path.join(__dirname, '..'));
for (const signal of ['SIGKILL', 'SIGTERM']) test(`synchronous caller ${signal} closes the independent driver and every observed namespace init`, { skip: process.platform !== 'linux' }, async () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'owned-crash-'));
  const system = path.join(fixture, '.knowledge'); fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
  const beat = path.join(fixture, 'heartbeat.json');
  fs.writeFileSync(path.join(system, 'tools/busy.js'), `const fs=require('fs');let n=0;setInterval(()=>fs.writeFileSync(${JSON.stringify(beat)},JSON.stringify({n:++n,proc_pid:Number(fs.readlinkSync('/proc/self'))})),10);`);
  try {
    const helper = require('../tools/lib/verification-linux-namespace').preparePackagedHelper();
    const result = await runner.runOwnedCommand({ executable: process.execPath, args: [path.join(__dirname, 'helpers/reliability-crash-observer.cjs'), source, fixture, helper.executable, signal],
      cwd: fixture, env: process.env, nestedAuthority: true }, { budgets: { workMs: 20000, setupMs: 10000, cleanupMs: 10000 } });
    assert.equal(result.cleanup.status, 'completed', JSON.stringify(result));
    assert.equal(result.status, 0, JSON.stringify(result));
    const observation = JSON.parse(result.stdout); console.log(JSON.stringify(observation));
    assert.equal(observation.status, 'pass');
    assert.ok(observation.namespace_init_count >= 2, 'The real isolated sync driver and command scopes must both have native init finality');
  } finally { fs.rmSync(fixture, { recursive: true, force: true }); }
});
