'use strict';

// Private controller channel. Command stdout/stderr never enters this pipe.
const net = require('net');
const crypto = require('crypto');
const { timerDelay } = require('./verification-policy');
const LIMIT = 16384;

async function listen(onEvent, onFailure, options = {}) {
  const key = crypto.randomBytes(32).toString('hex');
  const pipe = '\\\\.\\pipe\\knowledge-verification-' + crypto.randomBytes(16).toString('hex');
  let connection = null, ended = false;
  const server = net.createServer(socket => {
    if (connection || ended) { socket.destroy(); onFailure('verification_progress_connection_invalid'); return; }
    connection = socket;
    let text = '';
    socket.setEncoding('utf8');
    socket.on('error', () => { if (!ended) onFailure('verification_progress_transport_failed'); });
    socket.on('end', () => { if (!ended) onFailure(text.length ? 'verification_progress_truncated' : 'verification_progress_transport_closed'); });
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
    if (options.loopback) server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, resolve);
    else server.listen(pipe, resolve);
  });
  const descriptor = options.loopback ? { transport: 'loopback.v1', port: server.address().port, key } : { pipe, key };
  return { descriptor, close() { ended = true; connection?.destroy(); server.close(); } };
}

async function connect(descriptor, deadline, required = true) {
  if (!descriptor && !required) return { send() {}, async flush() {}, async finish() {}, close() {} };
  if (!descriptor) throw new Error('Verification progress channel required');
  const loopback = descriptor.transport === 'loopback.v1' && Number.isSafeInteger(descriptor.port) && descriptor.port > 0 && descriptor.port <= 65535;
  if ((!loopback && (typeof descriptor.pipe !== 'string' || !/^\\\\\.\\pipe\\knowledge-verification-[a-f0-9]{32}$/.test(descriptor.pipe))) ||
      !/^[a-f0-9]{64}$/.test(descriptor.key || '')) throw new Error('Invalid verification progress channel');
  const socket = loopback ? net.createConnection({ host: '127.0.0.1', port: descriptor.port }) : net.createConnection(descriptor.pipe);
  let failed = false, closing = false, closed = false, readableEnded = false, writableFinished = false, finishing;
  const observers = new Set();
  const notify = () => { for (const observer of [...observers]) observer(); };
  socket.on('error', () => { failed = true; notify(); });
  // A peer EOF observed before the producer requests its own finish is a
  // transport failure. The close callback may arrive later; allowing finish
  // in that interval would turn a peer-initiated loss into a graceful result.
  socket.on('end', () => { readableEnded = true; if (!closing) failed = true; notify(); });
  socket.on('finish', () => { writableFinished = true; notify(); });
  socket.on('close', hadError => { closed = true; if (hadError || !closing) failed = true; notify(); });
  const problem = () => Object.assign(new Error('Verification progress channel did not close completely'), { code: 'verification_progress_transport_failed' });
  const positiveDeadline = end => {
    if (typeof end !== 'bigint' || end <= process.hrtime.bigint()) throw problem();
    return timerDelay(Number(end - process.hrtime.bigint()) / 1e6);
  };
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Verification progress connection expired')); },
      timerDelay(Number(deadline - process.hrtime.bigint()) / 1e6));
    socket.once('connect', () => { clearTimeout(timer); resolve(); });
    socket.once('error', error => { clearTimeout(timer); reject(error); });
  });
  const frame = event => {
      if (failed || closing || socket.destroyed) throw Object.assign(new Error('Verification progress channel closed'), { code: 'verification_progress_transport_failed' });
      const frame = JSON.stringify({ key: descriptor.key, event }) + '\n';
      if (Buffer.byteLength(frame) > LIMIT) throw new Error('Oversized verification progress frame');
      return frame;
  };
  return {
    send(event) { socket.write(frame(event)); },
    flush(event, end) {
      return new Promise((resolve, reject) => {
        let done = false, timer;
        const finish = error => { if (done) return; done = true; clearTimeout(timer); observers.delete(observe); error ? reject(error) : resolve(); };
        const observe = () => { if (failed || closed) finish(problem()); };
        try {
          if (end !== undefined) timer = setTimeout(() => { finish(problem()); socket.destroy(); }, positiveDeadline(end));
          observers.add(observe);
          socket.write(frame(event), error => {
            if (error || failed || end !== undefined && process.hrtime.bigint() >= end) finish(problem());
            else finish();
          });
          observe();
        } catch (error) { finish(error); }
      });
    },
    finish(end) {
      if (finishing) return finishing;
      finishing = new Promise((resolve, reject) => {
        let done = false, timer;
        const finish = error => { if (done) return; done = true; clearTimeout(timer); observers.delete(observe); error ? reject(error) : resolve(); };
        const observe = () => {
          if (failed || process.hrtime.bigint() >= end) { finish(problem()); return; }
          if (closed) finish(readableEnded && writableFinished ? undefined : problem());
        };
        try {
          timer = setTimeout(() => { finish(problem()); socket.destroy(); }, positiveDeadline(end));
          if (failed || closed || closing) { finish(problem()); return; }
          observers.add(observe); closing = true; socket.end(); observe();
        } catch (error) { finish(error); socket.destroy(); }
      });
      return finishing;
    },
    close() { socket.end(); }
  };
}
module.exports = { listen, connect };
