'use strict';

// The fixed root-owned binary authenticates its root peer, seals the input,
// and retains native cancellation custody. This JS side only frames bounded
// data and observes exact helper exit; it never asserts closure from a timer.
const { spawn } = require('node:child_process');
const { copyInertData } = require('./inert-data');
const { safeEnvironment } = require('./command-runner');
const { timerDelay } = require('./verification-policy');
const BROKER_PATH = '/var/lib/knowledge-linux-native-v1/broker';
const EVENT_SCHEMA = 'knowledge-linux-native-service.v1';
const MAX_FRAME = 128 * 1024;
const clock = () => process.hrtime.bigint();
const fail = code => Object.assign(new Error(code), { code });
function frame(op, ordinal, nonce, workDeadline, cleanupMs, payloadBytes = 0, pid = 0) {
  if (!/^[a-f0-9]{64}$/.test(nonce) || typeof workDeadline !== 'bigint' || workDeadline < 1n ||
      !Number.isSafeInteger(cleanupMs) || cleanupMs < 1 || cleanupMs > 3600000 ||
      !Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > 0xffffffff ||
      !Number.isSafeInteger(payloadBytes) || payloadBytes < 0 || payloadBytes > 64 * 1024 * 1024) throw fail('verification_linux_protocol_invalid');
  const bytes = Buffer.alloc(80);
  [0x4b4c5331, 1, op, ordinal, payloadBytes, pid].forEach((value, i) => bytes.writeUInt32LE(value, i * 4));
  bytes.writeBigUInt64LE(workDeadline, 24);bytes.writeBigUInt64LE(BigInt(cleanupMs), 32);
  Buffer.from(nonce, 'hex').copy(bytes, 40);return bytes;
}
function createClient({ config, nonce, workDeadline, cleanupMs, onEvent, onFailure }) {
  if (process.platform !== 'linux' || config?.broker_path !== BROKER_PATH) throw fail('verification_linux_service_config_invalid');
  const child = spawn(BROKER_PATH, ['--client'], { env: safeEnvironment(process.env), stdio: ['pipe', 'pipe', 'pipe'] });
  let input = Buffer.alloc(0), ordinal = 0, ended = false, exited = false, closed = false, stderrEof = false,
    stdoutEof = false, exitCode = null, exitSignal = null, allowedExit = false, lastError = null, stderrBytes = 0;
  const events = [], waiters = new Set();
  const snapshot = () => ({ pid: child.pid || null, exit_observed: exited, stdout_eof: stdoutEof,
    stderr_eof: stderrEof, close_observed: closed, exit_code: exitCode, signal: exitSignal });
  function reject(error) {
    if (!lastError) { lastError = error;onFailure?.(error); }
    for (const waiter of [...waiters]) waiter.check();
  }
  function publish(kind, raw, value) {
    const event = { kind, raw, value };events.push(event);
    if (events.length > 256) { reject(fail('verification_linux_protocol_limit'));return; }
    try { onEvent?.(event); } catch (error) { reject(error); }
    for (const waiter of [...waiters]) waiter.check();
  }
  child.stdout.on('data', chunk => {
    if (lastError) return;
    input = Buffer.concat([input, chunk]);
    try {
      while (input.length >= 16) {
        const size = input.readUInt32LE(12), type = input.readUInt32LE(8);
        if (input.readUInt32LE(0) !== 0x4b4c4f31 || input.readUInt32LE(4) !== 1 ||
            ![1, 2].includes(type) || type === 1 && size < 1 || size > MAX_FRAME) throw fail('verification_linux_protocol_invalid');
        if (input.length < 16 + size) break;
        const bytes = input.subarray(16, 16 + size), raw = bytes.toString('utf8');input = input.subarray(16 + size);
        if (!Buffer.from(raw).equals(bytes)) throw fail('verification_linux_protocol_invalid');
        const value = size === 0 && type === 2 ? null : copyInertData(JSON.parse(raw), null, 2 * 1024 * 1024);
        if (type === 1 && value?.schema_version !== EVENT_SCHEMA) throw fail('verification_linux_protocol_invalid');
        if (type === 1 && value.event === 'denied') throw fail('verification_linux_native_' +
          (/^[a-z_]{1,80}$/.test(value.reason || '') ? value.reason : 'denied'));
        publish(type === 1 ? value.event : 'authority_result', raw, value);
      }
      if (input.length > MAX_FRAME + 16) throw fail('verification_linux_protocol_limit');
    } catch (error) { reject(error.code ? error : fail('verification_linux_protocol_invalid')); }
  });
  child.stdout.on('end', () => { stdoutEof = true;if (input.length) reject(fail('verification_linux_protocol_truncated')); });
  child.stderr.on('data', chunk => { stderrBytes += chunk.length;if (stderrBytes > 65536) reject(fail('verification_linux_stderr_limit')); });
  child.stderr.on('end', () => { stderrEof = true; });
  child.stdin.on('error', error => { if (!ended) reject(fail('verification_linux_transport_write_failed')); });
  child.on('error', () => reject(fail('verification_linux_service_unavailable')));
  child.on('exit', (code, signal) => {
    exited = true;exitCode = code;exitSignal = signal;
    if (!allowedExit) reject(fail('verification_linux_client_exited'));
    for (const waiter of [...waiters]) waiter.check();
  });
  child.on('close', () => { closed = true;for (const waiter of [...waiters]) waiter.check(); });
  function waitFor(predicate, deadline, ignoreError = false) {
    return new Promise((resolve, rejectPromise) => {
      let timer;
      const waiter = { check() {
        const answer = predicate();
        if (answer) { cleanup();resolve(answer); }
        else if (!ignoreError && lastError) { cleanup();rejectPromise(lastError); }
      } };
      const cleanup = () => { clearTimeout(timer);waiters.delete(waiter); };
      waiters.add(waiter);
      const remaining = Number(deadline - clock()) / 1e6;
      if (remaining <= 0) { cleanup();rejectPromise(fail('verification_linux_deadline'));return; }
      timer = setTimeout(() => { cleanup();rejectPromise(fail('verification_linux_deadline')); }, timerDelay(remaining));
      waiter.check();
    });
  }
  function send(op, body = null, pid = 0, onFramed = null) {
    if (ended || exited || (lastError && op !== 4)) return Promise.reject(lastError || fail('verification_linux_client_exited'));
    const data = body === null ? Buffer.alloc(0) : Buffer.from(body);
    const requestOrdinal = ++ordinal;
    onFramed?.(requestOrdinal);
    const bytes = Buffer.concat([frame(op, requestOrdinal, nonce, workDeadline, cleanupMs, data.length, pid), data]);
    return new Promise((resolve, rejectPromise) => child.stdin.write(bytes, error => error ? rejectPromise(error) : resolve(requestOrdinal)));
  }
  return {
    child, events, snapshot, send, waitFor,
    event(kind, deadline, predicate = () => true) {
      return waitFor(() => events.find(event => event.kind === kind && predicate(event.value)), deadline);
    },
    async hello() { await send(1);return this.event('capability', workDeadline); },
    async registerWriter(pid, deadline, onFramed = null) {
      const requestOrdinal = await send(2, null, pid, onFramed);
      return this.event('writer_registered', deadline, value => value.pid === pid && value.ordinal === requestOrdinal);
    },
    async writerClosed(pid, deadline, registration) {
      return this.event('writer_closed', deadline, value => value.pid === pid && (!registration ||
        value.birth_ticks === registration.value.birth_ticks && value.registration_ordinal === registration.value.ordinal));
    },
    stop() { return send(4).catch(() => {}); },
    async finish(deadline) {
      allowedExit = true;ended = true;child.stdin.end();
      await waitFor(() => exited && closed && stdoutEof && stderrEof && snapshot(), deadline, true);
      if (exitCode !== 0 || exitSignal !== null || input.length) throw fail('verification_linux_client_cleanup_unconfirmed');
      return snapshot();
    },
    async terminate(deadline) {
      allowedExit = true;this.stop();ended = true;child.stdin.end();
      try { return await waitFor(() => exited && closed && snapshot(), deadline, true); }
      catch {
        // Closing a transport never proves native or storage closure. Native
        // parent/client pidfds and the write-only cancel pipe remain authoritative.
        child.kill('SIGKILL');child.unref();for (const stream of child.stdio) stream?.destroy?.();return snapshot();
      }
    }
  };
}
module.exports = { BROKER_PATH, EVENT_SCHEMA, frame, createClient };
