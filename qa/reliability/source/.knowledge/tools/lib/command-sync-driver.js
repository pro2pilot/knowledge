'use strict';
const net = require('net');
const controller = new AbortController();
// spawnSync supplies a separate liveness pipe. Unlike stdin it remains open
// after the request has been read. Parent death closes it independently of
// the caller's blocked JS event loop.
// Use libuv's nonblocking pipe watcher. A fs.ReadStream would occupy a worker
// thread in a blocking read and can prevent process shutdown while the parent
// intentionally keeps this socket open.
const parent = new net.Socket({ fd: 3, readable: true, writable: false });
parent.on('end', () => controller.abort());
parent.on('error', () => controller.abort());
parent.resume();
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => controller.abort());
const chunks = []; let bytes = 0;
process.stdin.on('data', chunk => { bytes += chunk.length; if (bytes > 64 * 1024 * 1024) process.exit(1); chunks.push(chunk); });
process.stdin.on('end', async () => {
  try {
    const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const answer = await require('./command-runner').runOwnedOperation(request.operation, request.payload, { budgets: request.budgets, signal: controller.signal });
    process.stdout.write(JSON.stringify({ value: answer.value }), () => { parent.destroy(); process.exit(0); });
  } catch (error) {
    process.stdout.write(JSON.stringify({ error: { code: error.code || 'command_failed', message: error.message, cleanup: error.cleanup } }), () => { parent.destroy(); process.exit(1); });
  }
});
