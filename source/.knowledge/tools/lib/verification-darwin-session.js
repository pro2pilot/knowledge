'use strict';

// Ordinary-UID async production session. No privileged JavaScript, signing key
// or authoritative-project writes enter the private command UID boundary.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { copyInertData } = require('./inert-data');
const native = require('./verification-darwin-client');
const isolated = require('./verification-isolated-copy');
const wire = require('./verification-darwin-session-protocol');
const { timerDelay, MAX_WORK_MS, MAX_CLEANUP_MS } = require('./verification-policy');
const failure = code => Object.assign(new Error(code), { code });
const now = () => process.hrtime.bigint();
const elapsed = start => Number(now() - start) / 1e6;
const SOURCE_NAMES = Object.freeze({ source_sha256: 'verification-darwin-broker.m',
  stub_source_sha256: 'verification-darwin-stub.c', transport_header_sha256: 'verification-darwin-transport.h',
  uid_history_header_sha256: 'verification-darwin-uid-history.h', uid_history_source_sha256: 'verification-darwin-uid-history.m' });
function normalized(value) { return native.config({ darwin: value }).darwin; }
function checkDuration(value, max, code) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw failure(code);
  return value;
}
function same(a, b) {
  return ['dev', 'ino', 'size', 'nlink', 'mode', 'uid', 'gid', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);
}
async function stableHash(file, maximum, protectedRoot = false, { checkpoint = () => {} } = {}) {
  checkpoint();
  const absolute = path.resolve(file), ancestors = [];
  let parent = path.parse(absolute).root;
  for (const part of ['', ...path.relative(parent, path.dirname(absolute)).split(path.sep).filter(Boolean)]) {
    checkpoint();
    if (part) parent = path.join(parent, part);
    const st = await fs.promises.lstat(parent, { bigint: true });
    const sticky = parent === '/private/tmp' && (st.mode & 0o1000n) !== 0n;
    if (!st.isDirectory() || st.isSymbolicLink() || protectedRoot &&
        (st.uid !== 0n || (st.mode & 0o22n) !== 0n && !sticky)) throw failure('verification_darwin_path_unsafe');
    ancestors.push({ path: parent, dev: st.dev, ino: st.ino, mode: st.mode, uid: st.uid });
  }
  checkpoint();
  const before = await fs.promises.lstat(absolute, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size < 0n || before.size > BigInt(maximum) ||
      protectedRoot && (before.uid !== 0n || (before.mode & 0o6022n) !== 0n)) throw failure('verification_darwin_file_unsafe');
  const handle = await fs.promises.open(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) |
    (fs.constants.O_NONBLOCK || 0));
  let digest;
  try {
    // Enter the finally-owned descriptor scope before checking cancellation.
    // A late open completion must never lose its handle when it is rejected.
    checkpoint();
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !same(before, opened)) throw failure('verification_darwin_file_changed');
    const hash = crypto.createHash('sha256'), block = Buffer.alloc(65536);let offset = 0;
    while (offset < Number(opened.size)) {
      checkpoint();
      const wanted = Math.min(block.length, Number(opened.size) - offset);
      const { bytesRead } = await handle.read(block, 0, wanted, offset);
      if (!bytesRead) throw failure('verification_darwin_file_changed');
      hash.update(block.subarray(0, bytesRead));offset += bytesRead;
    }
    checkpoint();
    const extra = await handle.read(block, 0, 1, offset);
    const after = await handle.stat({ bigint: true }), named = await fs.promises.lstat(absolute, { bigint: true });
    if (extra.bytesRead !== 0 || !same(opened, after) || !same(after, named) || named.isSymbolicLink()) {
      throw failure('verification_darwin_file_changed');
    }
    digest = hash.digest('hex');
  } finally { await handle.close(); }
  for (const expected of ancestors) {
    checkpoint();
    const current = await fs.promises.lstat(expected.path, { bigint: true });
    if (!current.isDirectory() || current.isSymbolicLink() ||
        !['dev', 'ino', 'mode', 'uid'].every(key => current[key] === expected[key])) throw failure('verification_darwin_parent_changed');
  }
  checkpoint();
  return digest;
}
async function sourcePins(options = {}) {
  const rows = await Promise.all(Object.entries(SOURCE_NAMES).map(async ([key, name]) =>
    [key, await stableHash(path.join(__dirname, name), 2 * 1024 * 1024, false, options)]));
  return Object.fromEntries(rows);
}

function parse(bytes) {
  if (bytes.length > native.MAX_REPLY_BYTES) throw failure('verification_darwin_reply_oversized');
  try { return copyInertData(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)), null, native.MAX_REPLY_BYTES); }
  catch { throw failure('verification_darwin_reply_invalid'); }
}

// Low-level transport is also used by explicit diagnostic controllers. It does
// not grant production acceptance: open/attach and wire predicates do that.
function rpc(configValue, input, options = {}) {
  const config = normalized(configValue), run = options.run === true;
  const limitMs = checkDuration(Math.ceil(options.limitMs ?? 120000), MAX_WORK_MS + 2 * MAX_CLEANUP_MS,
    'verification_darwin_rpc_budget_invalid');
  let request;
  try { request = copyInertData(input, null, 1024 * 1024); }
  catch { return Promise.reject(failure('verification_darwin_request_invalid')); }
  if (!config.enabled) return Promise.reject(failure('verification_darwin_opt_in_required'));
  if (options.signal?.aborted) return Promise.reject(failure('verification_darwin_cancelled'));
  return new Promise((resolve, reject) => {
    const started = now(), chunks = [], hashes = [crypto.createHash('sha256'), crypto.createHash('sha256')];
    const counts = [0, 0];let size = 0, done = false, bad = null, exited = false, timer, killTimer, emergency;
    const child = spawn(config.broker_path, [run ? '--run' : '--request', `--socket=${config.broker_socket}`,
      `--lifecycle-timeout-ms=${limitMs}`, '--transport-timeout-ms=30000'], {
      shell: false, windowsHide: true, env: native.nativeEnv(), stdio: ['pipe', 'pipe', 'pipe', 'pipe']
    });
    const finishTimers = () => { clearTimeout(timer);clearTimeout(killTimer);clearTimeout(emergency);
      options.signal?.removeEventListener('abort', abort); };
    const helper = () => ({ pid: child.pid ?? null, exit_observed: exited, exit_code: child.exitCode,
      signal: child.signalCode, elapsed_ms: elapsed(started), stdout_bytes: counts[0], stderr_bytes: counts[1] });
    function stop(reason) {
      bad ||= failure(reason);
      if (done) return;
      if (!exited) child.kill('SIGTERM');
      killTimer ||= setTimeout(() => { if (!done && !exited) child.kill('SIGKILL'); }, 500);
      emergency ||= setTimeout(() => {
        if (done) return;
        done = true;finishTimers();
        for (const stream of [child.stdin, child.stdout, child.stderr, child.stdio[3]]) stream?.destroy();
        child.unref();reject(Object.assign(failure('verification_darwin_helper_cleanup_unconfirmed'), { helper: helper() }));
      }, 5000);
    }
    function abort() { stop('verification_darwin_cancelled'); }
    function tick() {
      if (elapsed(started) >= limitMs) stop('verification_darwin_helper_budget_exceeded');
      else timer = setTimeout(tick, timerDelay(limitMs - elapsed(started)));
    }
    const output = (index, callback) => chunk => {
      if (done) return;counts[index] += chunk.length;hashes[index].update(chunk);
      if (!Number.isSafeInteger(counts[index])) { stop('verification_darwin_output_size_invalid');return; }
      try { callback?.(chunk); } catch { stop('verification_darwin_output_consumer_failed'); }
    };
    const control = run ? child.stdio[3] : child.stdout;
    control.on('data', chunk => {
      if (done) return;size += chunk.length;
      if (size > native.MAX_REPLY_BYTES) stop('verification_darwin_reply_oversized');else chunks.push(chunk);
    });
    if (run) child.stdout.on('data', output(0, options.onStdout));
    child.stderr.on('data', output(1, options.onStderr));
    if (!run) child.stdio[3].resume();
    child.once('exit', () => { exited = true; });
    child.once('error', () => { bad ||= failure('verification_darwin_helper_spawn_failed'); });
    child.stdin.on('error', () => { bad ||= failure('verification_darwin_helper_input_failed'); });
    child.once('close', (status, signal) => {
      if (done) return;done = true;finishTimers();
      // A suspended event loop may dispatch stream/close callbacks before its
      // expired timer. The monotonic budget is checked at the acceptance edge.
      if (elapsed(started) >= limitMs) bad ||= failure('verification_darwin_helper_budget_exceeded');
      const receipt = { ...helper(), stdout_sha256: hashes[0].digest('hex'), stderr_sha256: hashes[1].digest('hex') };
      if (bad) return reject(Object.assign(bad, { helper: receipt }));
      let reply;try { reply = parse(Buffer.concat(chunks)); } catch (error) { return reject(Object.assign(error, { helper: receipt })); }
      if (!exited || status !== 0 || signal !== null || reply.ok !== true) {
        return reject(Object.assign(failure(typeof reply.error === 'string' && /^[A-Z0-9_]{1,128}$/.test(reply.error)
          ? reply.error : 'verification_darwin_rpc_rejected'), { helper: receipt, reply }));
      }
      resolve({ reply, helper: receipt });
    });
    options.signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(tick, timerDelay(limitMs));
    child.stdin.end(JSON.stringify(request));
    if (options.signal?.aborted) abort();
  });
}

async function probeSession(configValue, { signal, setupBudgetMs = 120000 } = {}) {
  if (process.platform !== 'darwin') throw failure('verification_darwin_required');
  const config = normalized(configValue);
  if (!config.enabled) throw failure('verification_darwin_opt_in_required');
  checkDuration(setupBudgetMs, MAX_WORK_MS, 'verification_darwin_setup_budget_invalid');
  const started = now();
  const remaining = () => Math.max(0, Math.floor(setupBudgetMs - elapsed(started)));
  function checkpoint() {
    if (signal?.aborted) throw failure('verification_darwin_cancelled');
    if (!remaining()) throw failure('verification_darwin_setup_budget_exceeded');
  }
  checkpoint();
  const { pins, binarySHA, runtimeSHA } = await require('./verification-darwin-preparation')
    .prepareInputs(config, { signal, limitMs: remaining() });
  checkpoint();
  const response = await rpc(config, { op: 'probe' }, { signal, limitMs: remaining() });
  checkpoint();
  const value = native.decodeReply(Buffer.from(JSON.stringify(response.reply)), pins);
  if (value.capability_qualified !== true || value.qualification_mode !== false || value.qa_persistence_gate !== false) {
    throw failure('verification_darwin_backend_unqualified');
  }
  if (value.registry_healthy !== true || value.entry_store_loaded !== true || value.uid_history.healthy_cached !== true ||
      value.uid_history.health_source !== 'disk_refresh_attempt' || value.account_policy.healthy !== true ||
      value.binary_sha256 !== binarySHA) throw failure('verification_darwin_current_registry_unconfirmed');
  const runtime = Object.keys(value.allowed_runtimes).sort().find(name =>
    path.posix.isAbsolute(name) && value.allowed_runtimes[name] === runtimeSHA);
  if (!runtime) throw failure('verification_darwin_runtime_pin_mismatch');
  return Object.freeze({ ...pins, binary_sha256: binarySHA, stub_binary_sha256: value.stub_binary_sha256,
    stub_wire_version: value.stub_wire_version, guardian_protocol: value.guardian_protocol,
    daemon_epoch: value.daemon_epoch, host_id: value.host_id, boot_id: value.boot_id,
    installation_id: value.uid_history.installation_id_cached, account_policy_id: value.account_policy.id,
    account_policy_sha256: value.account_policy.sha256, runtime_path: runtime, runtime_sha256: runtimeSHA,
    capability_qualified: true, qualification_mode: false });
}

function makeSession({ config, binding, token, capability, cleanupBudgetMs, signal, started, budgetMs }) {
  let stopped = false, closing = false, stopPromise = null, ordinal = 0;
  const workAbort = new AbortController(), workSignal = workAbort.signal;
  const remaining = () => Math.max(0, Math.floor(budgetMs - elapsed(started)));
  const auth = { attempt_id: binding.attempt_id, token };
  function stop(reason = 'cancelled') {
    stopped = true;
    // Revoke existing work transports before attempting the separate native
    // stop RPC. That RPC may be unavailable when its transport is saturated;
    // closing a run transport still reaches the broker's independent latch.
    // The stop RPC deliberately does not inherit this aborted work signal.
    workAbort.abort();
    stopPromise ||= rpc(config, { op: 'stop', ...auth, descriptor_sha256: binding.descriptor_sha256,
      cleanup_budget_ms: cleanupBudgetMs }, { limitMs: cleanupBudgetMs + 30000 })
      .then(value => ({ ...value, reason }), error => { throw Object.assign(error, { binding, stopped: true }); });
    // An event-listener initiated stop may have no direct caller to await it.
    stopPromise.catch(() => {});return stopPromise;
  }
  function guard() {
    if (stopped || signal?.aborted || !remaining()) {
      stop(signal?.aborted ? 'cancelled' : 'work_budget_exceeded');throw failure('verification_darwin_admission_closed');
    }
  }
  function cancellationGuard() {
    if (stopped || signal?.aborted) { stop('cancelled');throw failure('verification_darwin_admission_closed'); }
  }
  const onAbort = () => { stop('cancelled'); };
  signal?.addEventListener('abort', onAbort, { once: true });
  async function request(input, options = {}) {
    guard();if (closing) throw failure('verification_darwin_admission_closed');
    const response = await rpc(config, { ...input, ...auth }, { ...options, signal: workSignal,
      limitMs: options.limitMs ?? Math.min(120000, remaining() + cleanupBudgetMs + 30000) });
    guard();return response.reply;
  }
  const session = {
    binding, capability, workspace_path: binding.descriptor.workspace_path, scratch_path: binding.descriptor.scratch_path,
    privateBinding() { return { config, binding, token, capability, cleanupBudgetMs, workBudgetMs: remaining() }; },
    commandScope() { return require('./verification-darwin-scope').commandScope({ config, binding }); },
    async copyPlan(plan, options = {}) {
      guard();const copied = await isolated.transferProject(plan, input => request(input), {
        checkpoint: guard, progress: options.progress });guard();
      return { ...copied, workspace_path: binding.descriptor.workspace_path,
        source_files: plan.files.map(({ path: name, sha256 }) => ({ path: name, sha256 })) };
    },
    async expectAuthority() { return request({ op: 'expect_authority' }); },
    async registerAuthority() { return request({ op: 'register_authority' }); },
    async permit() { return request({ op: 'permit' }); },
    async run(commandValue, options = {}) {
      guard();if (closing) throw failure('verification_darwin_admission_closed');
      const command = copyInertData(commandValue, null, 1024 * 1024);
      if (!Array.isArray(command.argv) || command.argv[0] !== capability.runtime_path ||
          Object.keys(command).sort().join(',') !== 'argv,cwd,env,timeout_ms') throw failure('verification_darwin_command_unsupported');
      checkDuration(command.timeout_ms, MAX_WORK_MS, 'verification_darwin_command_budget_invalid');
      command.cwd = isolated.relativeName(command.cwd, true);
      command.timeout_ms = Math.min(command.timeout_ms, remaining());
      const expectedOrdinal = ++ordinal;
      try {
        const response = await rpc(config, { op: 'run', ...auth, ...command }, { run: true, signal: workSignal,
          limitMs: command.timeout_ms + cleanupBudgetMs + 30000, onStdout: options.onStdout, onStderr: options.onStderr });
        guard();const result = wire.validateCommand(response.reply, binding, capability, command, expectedOrdinal);
        return { result, command: Object.freeze({ ...command, argv: Object.freeze([...command.argv]), env: Object.freeze({ ...command.env }) }),
          helper: response.helper, status: result.exit_code, exit_code: result.exit_code, signal: result.signal,
          stdout_bytes: response.helper.stdout_bytes, stderr_bytes: response.helper.stderr_bytes,
          stdout_sha256: response.helper.stdout_sha256, stderr_sha256: response.helper.stderr_sha256 };
      } catch (error) { stop('command_failed_or_unconfirmed');throw Object.assign(error, { binding }); }
    },
    async sourceSnapshot(paths) { guard();const values = await isolated.snapshotCopy(binding.descriptor.workspace_path, paths, { checkpoint: guard });guard();return values; },
    async readback(plan, phase) {
      let value;
      if (phase === 'commands_drained' || phase === 'closed') {
        cancellationGuard();value = (await rpc(config, { op: 'readback_copy', ...auth },
          { signal: workSignal, limitMs: cleanupBudgetMs + 30000 })).reply;cancellationGuard();
      } else value = await request({ op: 'readback_copy' });
      return wire.validateReadback(value, binding, plan, phase);
    },
    async drain() {
      guard();
      const value = (await rpc(config, { op: 'drain_commands', ...auth, cleanup_budget_ms: cleanupBudgetMs },
        { signal: workSignal, limitMs: cleanupBudgetMs + 30000 })).reply;
      cancellationGuard();
      return { reply: value, proof: wire.validateProof(value, binding, capability, false) };
    },
    async close() {
      cancellationGuard();closing = true;
      const response = await rpc(config, { op: 'close', attempt_id: binding.attempt_id,
        descriptor_sha256: binding.descriptor_sha256, cleanup_budget_ms: cleanupBudgetMs },
      { signal: workSignal, limitMs: cleanupBudgetMs + 30000 });
      cancellationGuard();const proof = wire.validateProof(response.reply, binding, capability, true);
      signal?.removeEventListener('abort', onAbort);return { ...response, proof };
    },
    stop,
    get stopped() { return stopped; },
  };
  if (signal?.aborted) onAbort();return Object.freeze(session);
}

async function openSession({ config: input, nonce, workBudgetMs, cleanupBudgetMs, signal, expectedCapability }) {
  const started = now(), config = normalized(input);
  checkDuration(workBudgetMs, MAX_WORK_MS, 'verification_darwin_work_budget_invalid');
  checkDuration(cleanupBudgetMs, MAX_CLEANUP_MS, 'verification_darwin_cleanup_budget_invalid');
  if (!wire.hex(nonce)) throw failure('verification_darwin_nonce_invalid');
  const capability = await probeSession(config, { signal, setupBudgetMs: workBudgetMs });
  if (expectedCapability && wire.digest(capability) !== wire.digest(expectedCapability)) throw failure('verification_darwin_capability_changed');
  const remaining = Math.floor(workBudgetMs - elapsed(started));
  if (remaining < 1 || signal?.aborted) throw failure('verification_darwin_work_budget_exceeded');
  let prepared;
  try {
    prepared = (await rpc(config, { op: 'prepare', mode: 'isolated_copy', attempt_nonce: nonce,
      work_budget_ms: remaining, cleanup_budget_ms: cleanupBudgetMs }, { signal, limitMs: remaining + cleanupBudgetMs + 30000 })).reply;
    const binding = wire.validateDescriptor(prepared, capability, nonce);
    return makeSession({ config, binding, token: prepared.token, capability, cleanupBudgetMs, signal, started, budgetMs: workBudgetMs });
  } catch (error) {
    // A lost prepare reply is ambiguous. Resolve the SAME nonce; never prepare
    // a second allocation or interpret a timeout as no native reservation.
    let binding = prepared;
    if (!binding) {
      try { binding = (await rpc(config, { op: 'lookup', attempt_nonce: nonce }, { limitMs: cleanupBudgetMs + 30000 })).reply; } catch {}
    }
    if (wire.hex(binding?.attempt_id) && wire.hex(binding?.descriptor_sha256)) {
      try { await rpc(config, { op: 'stop', attempt_id: binding.attempt_id, descriptor_sha256: binding.descriptor_sha256,
        cleanup_budget_ms: cleanupBudgetMs }, { limitMs: cleanupBudgetMs + 30000 }); } catch {}
    }
    throw Object.assign(error, { binding: binding || null, attempt_nonce: nonce, recovery_required: true });
  }
}
async function attachSession({ config: input, binding, token, cleanupBudgetMs, workBudgetMs, signal }) {
  const started = now(), config = normalized(input);
  checkDuration(cleanupBudgetMs, MAX_CLEANUP_MS, 'verification_darwin_cleanup_budget_invalid');
  checkDuration(workBudgetMs, MAX_WORK_MS, 'verification_darwin_work_budget_invalid');
  const capability = await probeSession(config, { signal, setupBudgetMs: workBudgetMs });
  const validated = wire.validateDescriptor({ ok: true, ...binding, token, workspace_path: binding?.descriptor?.workspace_path },
    capability, binding?.descriptor?.attempt_nonce);
  return makeSession({ config, binding: validated, token, capability, cleanupBudgetMs, workBudgetMs, signal, started, budgetMs: workBudgetMs });
}
async function recoverSession({ config, binding, cleanupBudgetMs }) {
  checkDuration(cleanupBudgetMs, MAX_CLEANUP_MS, 'verification_darwin_cleanup_budget_invalid');
  if (!wire.hex(binding?.attempt_id) || !wire.hex(binding?.descriptor_sha256)) throw failure('verification_darwin_recovery_binding_invalid');
  const response = await rpc(config, { op: 'recover', attempt_id: binding.attempt_id,
    descriptor_sha256: binding.descriptor_sha256, cleanup_budget_ms: cleanupBudgetMs }, { limitMs: cleanupBudgetMs + 30000 });
  // Deliberately no successful-execution assertion: old epochs/sources are
  // cleanup-only and the common control owner must validate recovery evidence.
  return { ...response, cleanup_only: true, production_execution_accepted: false };
}
module.exports = { openSession, attachSession, probeSession, recoverSession, rpc, sourcePins, stableHash };
