'use strict';
// This synchronous manager's transport child performs only a read-only query
// through its already established control parent. No endpoint is persisted.
const net = require('net');
let request = '', invalid = false;
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { request += chunk; if (Buffer.byteLength(request) > 65536) { invalid = true; process.exit(1); } });
process.stdin.on('end', () => {
  try {
    if (invalid) throw new Error('oversized');
    const value = JSON.parse(request);
    if (!Number.isSafeInteger(value.timeoutMs) || value.timeoutMs < 1 || value.timeoutMs > 600000 || !/^[a-f0-9]{64}$/.test(value.relay?.token || '') ||
        value.relay.address?.host !== '127.0.0.1' || !Number.isInteger(value.relay.address.port) || value.relay.address.port < 1 || value.relay.address.port > 65535) throw new Error('invalid');
    const socket = net.createConnection(value.relay.address); let response = '', ended = false;
    const timer = setTimeout(() => { socket.destroy(); process.exit(1); }, value.timeoutMs + 1000);
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.end(JSON.stringify({ token: value.relay.token, scope: value.scope, timeoutMs: value.timeoutMs })));
    socket.on('data', chunk => { response += chunk; if (Buffer.byteLength(response) > 65536) { socket.destroy(); process.exit(1); } });
    socket.on('error', () => process.exit(1));
    socket.on('end', () => { ended = true; clearTimeout(timer); process.stdout.write(response); });
    socket.on('close', () => { if (!ended) process.exitCode = 1; });
  } catch { process.exitCode = 1; }
});
