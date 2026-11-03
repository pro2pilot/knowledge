'use strict';
// Public stdout is exclusively the bounded ciphertext envelope. No path,
// exception stack, raw child output, environment, or plaintext fallback.
const path = require('node:path');
const T = require('./evidence-transport.cjs');
function argumentsExact(argv) {
  if (argv.length !== 4 || argv[0] !== '--request' || argv[2] !== '--public-key' ||
      !path.isAbsolute(argv[1]) || !path.isAbsolute(argv[3])) throw new Error('INVALID_ARGUMENTS');
  return { request: argv[1], publicKey: argv[3] };
}
try {
  const args = argumentsExact(process.argv.slice(2));
  const request = T.parseStrictJSON(T.readBoundedFile(args.request, T.LIMITS.request), T.LIMITS.request);
  const publicPem = T.readBoundedFile(args.publicKey, T.LIMITS.key);
  // Production CLI always uses the TASK-pinned key/input. Only module-level
  // tests can pass an ephemeral expected key. There is no CLI bypass flag.
  const { log } = T.encryptRequest(request, publicPem);
  process.stdout.on('error', () => { process.exitCode = 74; });
  process.stdout.write(log, error => { if (error) process.exitCode = 74; });
} catch {
  process.stderr.write('D5_ENCRYPT_EXPORT_FAILED\n');
  process.exitCode = 74;
}
