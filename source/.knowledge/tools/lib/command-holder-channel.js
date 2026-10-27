'use strict';
const net = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const MAX = 65536;
function channel() {
  const out = new EventEmitter();
  Object.assign(out, { connected: false, everConnected: false, disconnected: false, complete: false });
  out.send = (value, callback = () => {}) => {
    try {
      const bytes = Buffer.from(JSON.stringify(value) + '\n');
      if (!out.connected || bytes.length > MAX) throw new Error('holder_channel_unavailable');
      out.socket.write(bytes, callback);
    } catch (error) { callback(error); }
  };
  out.close = () => { out.socket?.destroy(); out.server?.close(); };
  return out;
}
function attach(out, socket, authenticate) {
  let pending = Buffer.alloc(0), admitted = !authenticate, finished = false;
  const end = reason => {
    if (finished) return; finished = true;
    if (admitted) { out.connected = false; out.disconnected = true; out.complete = reason === 'eof'; out.emit('disconnect', reason); }
    socket.destroy();
  };
  const admit = () => { out.socket = socket; out.connected = out.everConnected = true; out.emit('connected'); };
  if (admitted) socket.once('connect', admit);
  socket.on('data', part => {
    pending = Buffer.concat([pending, part]);
    if (pending.length > MAX * 2) { end('oversized'); return; }
    let newline;
    while (!finished && (newline = pending.indexOf(10)) !== -1) {
      if (newline >= MAX) { end('oversized'); return; }
      const line = pending.subarray(0, newline); pending = pending.subarray(newline + 1);
      let value;
      try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line));
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('object required');
      } catch { end('malformed'); return; }
      if (!admitted) {
        if (!authenticate(value) || out.everConnected) { end('authentication_failed'); return; }
        admitted = true; admit();
      } else out.emit('message', value);
    }
    if (pending.length >= MAX) end('oversized');
  });
  socket.once('end', () => end(pending.length ? 'truncated' : 'eof'));
  socket.once('error', () => end('read_error'));
  socket.once('close', () => end('closed'));
}
async function createServer(options = {}) {
  const out = channel(), token = crypto.randomBytes(32).toString('hex');
  const sockets = new Set();
  out.server = net.createServer(socket => {
    if (sockets.size >= 4) { socket.destroy(); return; }
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    attach(out, socket, value => Object.keys(value).sort().join(',') === 'token,type' && value.type === 'hello' && value.token === token);
  });
  const close = out.close; out.close = () => { for (const socket of sockets) socket.destroy(); close(); };
  // Keep an error consumer after cancellation as a late OS callback can arrive
  // after the bounded setup promise rejected. Pending peers also close here.
  out.server.on('error', () => out.emit('disconnect', 'server_error'));
  await new Promise((resolve, reject) => {
    let settled = false, timer;
    const finish = error => {
      if (settled) return; settled = true; clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
      out.server.removeListener('error', failed);
      if (error) { out.close();reject(error); } else resolve();
    };
    const failed = error => finish(error);
    const abort = () => finish(Object.assign(new Error('holder_channel_setup_cancelled'), { code: 'holder_channel_setup_cancelled' }));
    out.server.once('error', failed);
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) { abort();return; }
    if (options.timeoutMs !== undefined) {
      if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 2147483647) {
        finish(Object.assign(new Error('holder_channel_setup_budget_invalid'), { code: 'holder_channel_setup_budget_invalid' }));return;
      }
      timer = setTimeout(() => finish(Object.assign(new Error('holder_channel_setup_timeout'), { code: 'holder_channel_setup_timeout' })), options.timeoutMs);
    }
    out.server.listen(0, '127.0.0.1', () => {
      // A late listen callback must not resurrect a cancelled private endpoint.
      if (settled) { out.close();return; }
      finish();
    });
  });
  out.arguments = ['--holder-channel', String(out.server.address().port), token];
  return out;
}
function createClient(argv) {
  if (!Array.isArray(argv) || argv.length !== 3 || argv[0] !== '--holder-channel' ||
      !/^[1-9]\d{0,4}$/.test(argv[1]) || Number(argv[1]) > 65535 || !/^[a-f0-9]{64}$/.test(argv[2])) throw new Error('holder_channel_invalid');
  const out = channel(), socket = net.createConnection({ host: '127.0.0.1', port: Number(argv[1]) });
  attach(out, socket);
  socket.once('connect', () => out.send({ type: 'hello', token: argv[2] }, error => { if (error) socket.destroy(); }));
  return out;
}
module.exports = { createServer, createClient };
