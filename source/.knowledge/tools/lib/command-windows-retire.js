'use strict';
// Fixed isolated retirement worker. The controller has already observed
// native closure and both holders' exits; the caller confirmed lock release.
// Filesystem work here cannot stall the responsive controller's event loop.
const protocol = require('./command-windows-protocol');
let body = '', invalid = false;
process.stdin.setEncoding('utf8');
process.stdin.on('data', part => {
  body += part;
  if (Buffer.byteLength(body) > 65536) { invalid = true; process.stdin.destroy(); process.exitCode = 1; }
});
process.stdin.on('end', () => {
  let request;
  try {
    if (invalid) throw new Error('oversized'); request = JSON.parse(body);
    if (!protocol.validateScope(request.scope) || !request.scope.descriptor.secondary || !protocol.HEX.test(request.nonce || '') ||
        !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > 600000) throw new Error('invalid');
    const loaded = require('./command-windows-native').loadPreparedHelper(request.helper), native = loaded.native;
    const parent = native.processIdentity(process.ppid);
    if (parent.exited) throw new Error('parent exited');
    native.armReadonlyGuard({ pid: parent.pid, birth_filetime: parent.birth_filetime }, request.timeoutMs);
    const receipt = require('./command-windows-receipts').cleanupTerminalStore(request.scope);
    process.stdout.write(JSON.stringify({ nonce: request.nonce, scope_sha256: protocol.digest(request.scope), receipt }));
  } catch (error) {
    process.stdout.write(JSON.stringify({ nonce: request?.nonce || null,
      scope_sha256: request?.scope ? protocol.digest(request.scope) : null,
      receipt: { status: 'unconfirmed', method: 'windows_terminal_receipt_store',
        code: /^[a-zA-Z0-9_]{1,96}$/.test(error.code || '') ? error.code : 'command_windows_retirement_failed' } }));
    process.exitCode = 1;
  }
});
