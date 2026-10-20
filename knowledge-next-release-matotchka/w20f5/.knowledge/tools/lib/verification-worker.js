'use strict';
// Only the supervisor connects this IPC worker. Never pass child stdout to IPC.
const PROTOCOL = 'knowledge-verification-supervisor.v1';
let used = false, sequence = 0;
const acknowledgements = new Map();
function send(message) {
  return new Promise((resolve, reject) => process.send({ protocol: PROTOCOL, ...message }, error => error ? reject(error) : resolve()));
}
async function phase(stage, deadline) {
  const id = ++sequence;
  const ack = new Promise(resolve => acknowledgements.set(id, resolve));
  await send({ type: 'phase', id, stage, deadline_ns: String(deadline) });
  await ack;
}
process.on('message', async message => {
  if (message?.protocol !== PROTOCOL) return;
  if (message.type === 'ack') { const resolve = acknowledgements.get(message.id); acknowledgements.delete(message.id); if (resolve) resolve(); return; }
  if (used || message.type !== 'run' || !/^\d+$/.test(message.deadline_ns || '')) return;
  used = true;
  try {
    const core = require('./repair-on-touch').__runVerificationTestsCore;
    const result = await core(message.request, { deadline: BigInt(message.deadline_ns), batchId: message.batch_id, publicKey: message.public_key, requestSha256: message.request_sha256, phase,
      committed: item => send({ type: 'committed', value: { execution_id: item.record.execution_id, execution_sha256: item.record.content_sha256, execution_path: item.relative_path, status: item.record.status } }) });
    await send({ type: 'result', result });
  } catch (error) {
    const serialized = { code: error.code || 'verification_worker_failed', message: error.message };
    for (const key of ['validation', 'lock_release_error', 'lock_cleanup_error', 'containment', 'execution', 'teardown']) if (error[key] !== undefined) serialized[key] = error[key];
    await send({ type: 'error', error: serialized });
  }
  // Stay alive for the supervisor's owned-tree sweep, including on success.
});
