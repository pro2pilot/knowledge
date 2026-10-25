'use strict';

// Responsive monitor-side lifecycle for the fixed read-only setup process.
// Success requires its result AND physical child/stream closure within the
// original setup budget. A timeout never supplies an exit observation.
const childProcess = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');
const { copyInertData } = require('./inert-data');
const native = require('./verification-darwin-client');
const { timerDelay, MAX_WORK_MS } = require('./verification-policy');
const fail = code => Object.assign(new Error(code), { code });
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const now = () => process.hrtime.bigint();
const PIN_NAMES = ['source_sha256', 'stub_source_sha256', 'transport_header_sha256',
  'uid_history_header_sha256', 'uid_history_source_sha256'];
function prepareInputs(config, { signal, limitMs } = {}) {
  if (!Number.isSafeInteger(limitMs) || limitMs < 1 || limitMs > MAX_WORK_MS) {
    return Promise.reject(fail('verification_darwin_setup_budget_invalid'));
  }
  if (signal?.aborted) return Promise.reject(fail('verification_darwin_cancelled'));
  return new Promise((resolve, reject) => {
    const started = now(), deadline = started + BigInt(limitMs) * 1000000n, nonce = crypto.randomBytes(32).toString('hex');
    const stderrHash = crypto.createHash('sha256');let stderrBytes = 0, response = null, bad = null;
    let done = false, exited = false, timer, killTimer, cleanupTimer;
    const child = childProcess.fork(path.join(__dirname, 'verification-darwin-preparer.js'), [], {
      execPath: process.execPath, execArgv: [], env: native.nativeEnv(), windowsHide: true,
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'], serialization: 'json'
    });
    const remaining = () => Math.max(0, Number((deadline - now()) / 1000000n));
    function clear() { clearTimeout(timer);clearTimeout(killTimer);clearTimeout(cleanupTimer);signal?.removeEventListener('abort', abort); }
    function receipt() { return { pid: child.pid ?? null, exit_observed: exited,
      exit_code: child.exitCode, signal: child.signalCode, stderr_bytes: stderrBytes,
      elapsed_ms: Number(now() - started) / 1e6, readonly: true, admission_possible: false }; }
    function stop(code) {
      bad ||= fail(code);if (done) return;
      if (!exited) child.kill('SIGTERM');
      killTimer ||= setTimeout(() => { if (!done && !exited) child.kill('SIGKILL'); }, 500);
      cleanupTimer ||= setTimeout(() => {
        if (done) return;done = true;clear();
        child.stderr?.destroy();if (child.connected) child.disconnect();child.unref();
        reject(Object.assign(fail('verification_darwin_preparer_cleanup_unconfirmed'),
          { cause_code: bad.code, helper: receipt() }));
      }, 5000);
    }
    function abort() { stop('verification_darwin_cancelled'); }
    function tick() { if (done) return;if (remaining() < 1) stop('verification_darwin_setup_budget_exceeded');
      else timer = setTimeout(tick, timerDelay(remaining())); }
    child.on('error', () => stop('verification_darwin_preparer_spawn_failed'));
    child.stderr.on('error', () => stop('verification_darwin_preparer_stream_failed'));
    child.stderr.on('data', bytes => { stderrBytes += bytes.length;stderrHash.update(bytes);
      if (stderrBytes > 262144) stop('verification_darwin_preparer_output_oversized'); });
    child.on('message', raw => {
      if (done) return;
      try {
        const value = copyInertData(raw, null, 16384);
        if (response || value?.nonce !== nonce || !['prepared_readonly', 'prepare_failed'].includes(value?.type)) {
          throw fail('verification_darwin_preparer_protocol_invalid');
        }
        response = value;
        if (value.type === 'prepare_failed') stop(/^[a-z0-9_]{1,96}$/.test(value.code || '')
          ? value.code : 'verification_darwin_preparer_rejected');
        else if (Object.keys(value).sort().join(',') !== 'binarySHA,executable,nonce,pins,runtimeSHA,type' ||
            !value.pins || Object.keys(value.pins).sort().join(',') !== PIN_NAMES.slice().sort().join(',') ||
            !PIN_NAMES.every(key => hex(value.pins[key])) || !hex(value.binarySHA) || !hex(value.runtimeSHA) ||
            value.executable?.schema !== 'knowledge-darwin-protected-executable.v1' ||
            value.executable.status !== 'verified' || value.executable.sha256 !== value.binarySHA) {
          throw fail('verification_darwin_preparer_protocol_invalid');
        }
      } catch { stop('verification_darwin_preparer_protocol_invalid'); }
    });
    child.once('exit', () => { exited = true; });
    child.once('close', () => {
      if (done) return;
      if (signal?.aborted) bad ||= fail('verification_darwin_cancelled');
      if (remaining() < 1) bad ||= fail('verification_darwin_setup_budget_exceeded');
      done = true;clear();const helper = { ...receipt(), streams_closed: true, stderr_sha256: stderrHash.digest('hex') };
      if (bad) return reject(Object.assign(bad, { helper }));
      if (!exited || child.exitCode !== 0 || child.signalCode !== null || !response || response.type !== 'prepared_readonly') {
        return reject(Object.assign(fail('verification_darwin_preparer_exit_unconfirmed'), { helper }));
      }
      resolve(Object.freeze({ pins: Object.freeze(response.pins), binarySHA: response.binarySHA,
        runtimeSHA: response.runtimeSHA, executable: Object.freeze(response.executable), helper }));
    });
    signal?.addEventListener('abort', abort, { once: true });tick();
    if (!bad) {
      try { child.send({ type: 'prepare_readonly', broker_path: config.broker_path, runtime_path: process.execPath,
        nonce, parent_pid: process.pid, deadline_ns: deadline.toString() }, error => {
          if (error) stop('verification_darwin_preparer_ipc_failed');
        }); }
      catch { stop('verification_darwin_preparer_ipc_failed'); }
    }
    if (signal?.aborted) abort();
  });
}
module.exports = { prepareInputs };
