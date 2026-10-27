'use strict';
// Fixed preparer/retirer. It never dispatches project code, creates a project
// lock, or invokes a compiler. Its only writes are its private native snapshot.
process.on('disconnect', () => process.exit(1));
const backend = process.platform === 'win32' ? './command-windows-native' : './verification-linux-namespace';
function failed(error) {
  process.send({ type: 'prepare_failed', code: error.code || 'command_setup_failed', message: error.message,
    artifact_cleanup: error.artifact_cleanup }, () => process.exit(1));
}
if (process.argv[2] === '--cleanup') {
  process.once('message', message => {
    try {
      if (message?.type !== 'cleanup' || Buffer.byteLength(JSON.stringify(message)) > 16384) throw new Error('Invalid cleanup request');
      const receipt = require(backend).cleanupPreparedHelper(message.helper, { allowIncomplete: message.allowIncomplete === true });
      process.send({ type: 'cleaned', receipt }, error => process.exit(error ? 1 : 0));
    } catch (error) { failed(error); }
  });
} else {
  try {
    const helper = require(backend).preparePackagedHelper({ snapshot: true,
      onSnapshot: value => process.send({ type: 'snapshot_created', helper: value }) });
    process.send({ type: 'prepared', helper }, error => process.exit(error ? 1 : 0));
  } catch (error) { failed(error); }
}
