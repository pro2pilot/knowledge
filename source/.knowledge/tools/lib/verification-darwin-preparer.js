'use strict';

// Fixed read-only setup child. It cannot reserve an allocation, register an
// authority, launch project code, write project state, or issue a broker RPC.
// The inherited IPC channel binds the creating monitor; a delayed syscall may
// finish after cancellation, but this process has no path to admit user work.
const { copyInertData } = require('./inert-data');
const { verifyProtectedExecutable } = require('./lock-publication');
const { sourcePins, stableHash } = require('./verification-darwin-session');
let used = false;
process.on('disconnect', () => process.exit(1));
process.once('message', async raw => {
  let query;
  try {
    query = copyInertData(raw, null, 16384);
    if (used || !query || query.type !== 'prepare_readonly' ||
        Object.keys(query).sort().join(',') !== 'broker_path,deadline_ns,nonce,parent_pid,runtime_path,type' ||
        !/^[a-f0-9]{64}$/.test(query.nonce) || !/^[1-9][0-9]{0,23}$/.test(query.deadline_ns) ||
        !Number.isSafeInteger(query.parent_pid) || query.parent_pid < 1 || query.parent_pid !== process.ppid ||
        query.runtime_path !== process.execPath || typeof query.broker_path !== 'string' ||
        !query.broker_path.startsWith('/') || query.broker_path.length > 4096) throw new Error('invalid');
    used = true;
    const deadline = BigInt(query.deadline_ns);
    const remaining = () => Number((deadline - process.hrtime.bigint()) / 1000000n);
    function checkpoint() {
      if (!process.connected || process.ppid !== query.parent_pid) {
        throw Object.assign(new Error('parent_gone'), { code: 'verification_darwin_preparer_parent_gone' });
      }
      if (remaining() < 1) throw Object.assign(new Error('expired'), { code: 'verification_darwin_setup_budget_exceeded' });
    }
    checkpoint();const pins = await sourcePins({ checkpoint });checkpoint();
    const runtimeSHA = await stableHash(process.execPath, 268435456, false, { checkpoint });checkpoint();
    const executable = verifyProtectedExecutable(query.broker_path,
      { maxBytes: 268435456, remainingMs: Math.min(600000, remaining()) });checkpoint();
    process.send({ type: 'prepared_readonly', nonce: query.nonce, pins, runtimeSHA,
      binarySHA: executable.sha256, executable }, error => process.exit(error ? 1 : 0));
  } catch (error) {
    const code = /^[a-z0-9_]{1,96}$/.test(error?.code || '') ? error.code : 'verification_darwin_preparer_rejected';
    if (process.connected) process.send({ type: 'prepare_failed', nonce: query?.nonce || null, code }, () => process.exit(1));
    else process.exit(1);
  }
});
