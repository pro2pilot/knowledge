'use strict';
// No project imports, subprocesses or storage until native Job assignment.
// Self-reported birth travels only on the creator's private Node IPC channel;
// a numeric PID captured after process exit must never gain assign authority.
let prepared = false, permitted = false;
process.on('disconnect', () => process.exit(1));
process.stdout.on('error', () => process.exit(1));
process.stderr.on('error', () => process.exit(1));
function receive(message) {
  try {
    if (!prepared && message?.type === 'native_prepare') {
      const { native, binding } = require('./command-windows-native').loadPreparedHelper(message.helper);
      const identity = native.currentIdentity(); prepared = true;
      process.send({ type: 'native_ready', identity, binding }, error => { if (error) process.exit(1); });
    } else if (prepared && !permitted && message?.type === 'native_permit') {
      permitted = true; process.removeListener('message', receive); require('./command-worker');
    } else process.exit(1);
  } catch (error) {
    process.send({ type: 'native_failed', code: error.code || 'command_windows_guard_unconfirmed' }, () => process.exit(1));
  }
}
process.on('message', receive);
