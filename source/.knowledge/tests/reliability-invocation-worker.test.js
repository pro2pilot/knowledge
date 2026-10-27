'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const crypto = require('crypto');
const supported = ['linux', 'win32'].includes(process.platform);
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function run(mutate) {
  const linux = process.platform === 'linux';
  const loader = require(linux ? '../tools/lib/verification-linux-namespace' : '../tools/lib/command-windows-native');
  const helper = loader.preparePackagedHelper({ snapshot: true, verifyLoad: false });
  const options = { env: require('../tools/lib/command-runner').safeEnvironment(), stdio: ['ignore', 'pipe', 'pipe', 'ipc'], windowsHide: true };
  const { worker, job } = linux ? loader.spawnLinuxContainedWorker(process.execPath, [path.join(__dirname, '../tools/lib/command-worker.js')], options,
    { preparedHelper: helper, lifetimeMs: 20000, trustedAuthority: true }) :
    require('../tools/lib/command-windows-scope').spawnWindowsContainedWorker(options,
      { preparedHelper: helper, lifetimeMs: 10000, setupMs: 10000, cleanupMs: 10000, durable: true });
  const ready = new Promise(resolve => worker.on('message', row => { if (row?.type === 'host_ready') resolve(); }));
  const result = new Promise((resolve, reject) => {
    worker.on('message', row => { if (row?.type === 'result') resolve(row); });
    worker.once('error', reject); worker.once('exit', () => reject(new Error('Worker exited before its result')));
  });
  result.catch(() => {});
  worker.stdout.resume(); worker.stderr.resume();
  let cleanup;
  try {
    await job.ready;
    const d = job.descriptor;
    const scope = { schema_version: 'knowledge-command-scope.v1', backend: d.backend, descriptor: d,
      ...(linux ? { observer_lineage: [{ namespace: d.observer_pid_namespace, depth: d.controller.proc_pid_chain.length }] } : {}) };
    const invocation = { schema_version: 'knowledge-verification-invocation.v1', nonce_sha256: 'a'.repeat(64), scope_sha256: digest(scope), scope };
    const altered = mutate(invocation);
    job.permit(); await ready;
    // An intentionally null request cannot name a project or perform storage.
    // The positive control must pass native self-birth admission and reach
    // that later request boundary; all negatives must stop before it.
    worker.send({ type: 'start', kind: 'operation', payload: { operation: 'verification-run', payload: {
      request: null, timeout_ms: 10000, started_ns: String(process.hrtime.bigint()) } },
      budgets: { workMs: 10000, setupMs: 10000, cleanupMs: 10000, progressMs: 0 }, helper, invocation: altered });
    return await result;
  } finally {
    cleanup = await job.close(10000);
    assert.equal(cleanup.status, 'completed', JSON.stringify(cleanup));
    if (!linux) assert.equal((await job.retireProof(10000)).status, 'completed');
    assert.equal(loader.cleanupPreparedHelper(helper).status, 'completed');
    if (worker.connected) worker.disconnect();
  }
}
test('actual invocation worker accepts its exact native birth before validating the project request', { skip: !supported }, async () => {
  const value = await run(value => value);
  assert.equal(value.error.code, 'command_worker_error', JSON.stringify(value));
  assert.match(value.error.message, /stateRoot/);
});
for (const [name, mutate] of [
  ['missing immutable binding', () => undefined],
  ['different scope digest', value => ({ ...value, scope_sha256: '0'.repeat(64) })],
  ['recomputed digest for another native birth', value => {
    const target = process.platform === 'linux' ? value.scope.descriptor.worker : value.scope.descriptor.root;
    const key = process.platform === 'linux' ? 'start_ticks' : 'birth_filetime'; target[key] = String(BigInt(target[key]) + 1n);
    value.scope_sha256 = digest(value.scope); return value;
  }],
  ['noncanonical invocation nonce', value => ({ ...value, nonce_sha256: 'invalid' })]
]) test(`actual invocation worker rejects ${name} before project admission`, { skip: !supported }, async () => {
  const value = await run(mutate);
  assert.equal(value.error.code, 'verification_invocation_invalid', JSON.stringify(value));
});
