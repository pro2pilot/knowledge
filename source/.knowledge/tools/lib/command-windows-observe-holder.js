'use strict';
// Readonly exact-birth observation after a launcher crash. No PID signaling.
const protocol = require('./command-windows-protocol');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; if (Buffer.byteLength(input) > 65536) process.exit(1); });
process.stdin.on('end', () => {
  try {
    const request = JSON.parse(input);
    if (!protocol.HEX.test(request.nonce || '') || !protocol.validIdentity(request.identity) ||
        !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > 600000) throw new Error('invalid observation');
    const { native } = require('./command-windows-native').loadPreparedHelper(request.helper);
    const parent = native.processIdentity(process.ppid);
    if (parent.exited) throw new Error('parent exited');
    native.armReadonlyGuard({ pid: parent.pid, birth_filetime: parent.birth_filetime }, request.timeoutMs);
    const observation = native.observeIdentity(request.identity);
    process.stdout.write(JSON.stringify({ nonce: request.nonce, observation }));
  } catch { process.exitCode = 1; }
});
