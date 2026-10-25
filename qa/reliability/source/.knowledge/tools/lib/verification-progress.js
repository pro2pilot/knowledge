'use strict';

// Private controller channel. Command stdout/stderr never enters this pipe.
const net = require('net');
const crypto = require('crypto');
const { timerDelay } = require('./verification-policy');
const LIMIT = 16384;

async function listen(onEvent, onFailure) {
  const key = crypto.randomBytes(32).toString('hex');
  const pipe = '\\\\.\\pipe\\knowledge-verification-' + crypto.randomBytes(16).toString('hex');
  let connection = null, ended = false;
  const server = net.createServer(socket => {
    if (connection || ended) { socket.destroy(); onFailure('verification_progress_connection_invalid'); return; }
    connection = socket;
    let text = '';
    socket.setEncoding('utf8');
    socket.on('error', () => { if (!ended) onFailure('verification_progress_transport_failed'); });
    socket.on('end', () => { if (!ended) onFailure('verification_progress_transport_closed'); });
    socket.on('data', chunk => {
      text += chunk;
      let at;
      while ((at = text.indexOf('\n')) >= 0) {
        if (Buffer.byteLength(text.slice(0, at)) > LIMIT) { onFailure('verification_progress_oversized'); socket.destroy(); return; }
        let message;
        try { message = JSON.parse(text.slice(0, at)); } catch { onFailure('verification_progress_invalid'); socket.destroy(); return; }
        text = text.slice(at + 1);
        if (message.key !== key || !message.event || typeof message.event !== 'object') {
          onFailure('verification_progress_invalid'); socket.destroy(); return;
        }
        onEvent(message.event);
      }
      if (Buffer.byteLength(text) > LIMIT) { onFailure('verification_progress_oversized'); socket.destroy(); }
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(pipe, resolve);
  });
  return { descriptor: { pipe, key }, close() { ended = true; connection?.destroy(); server.close(); } };
}

async function connect(descriptor, deadline, required = true) {
  if (!descriptor && !required) return { send() {}, close() {} };
  if (!descriptor) throw new Error('Verification progress channel required');
  if (typeof descriptor.pipe !== 'string' || !/^\\\\\.\\pipe\\knowledge-verification-[a-f0-9]{32}$/.test(descriptor.pipe) ||
      !/^[a-f0-9]{64}$/.test(descriptor.key || '')) throw new Error('Invalid verification progress channel');
  const socket = net.createConnection(descriptor.pipe);
  let failed = false;
  socket.on('error', () => { failed = true; });
  socket.on('close', () => { failed = true; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Verification progress connection expired')); },
      timerDelay(Number(deadline - process.hrtime.bigint()) / 1e6));
    socket.once('connect', () => { clearTimeout(timer); resolve(); });
    socket.once('error', error => { clearTimeout(timer); reject(error); });
  });
  return {
    send(event) {
      if (failed || socket.destroyed) throw Object.assign(new Error('Verification progress channel closed'), { code: 'verification_progress_transport_failed' });
      const frame = JSON.stringify({ key: descriptor.key, event }) + '\n';
      if (Buffer.byteLength(frame) > LIMIT) throw new Error('Oversized verification progress frame');
      socket.write(frame);
    },
    close() { socket.end(); }
  };
}
module.exports = { listen, connect };
