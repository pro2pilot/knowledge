'use strict';

// An explicitly diagnostic lifecycle runner. Disjoint store/schema; no KVE,
// KVF, signature, repair, currency, resource release or production acceptance.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, fork } = require('node:child_process');
const { copyInertData } = require('./inert-data');
const native = require('./verification-darwin-client');
const isolated = require('./verification-isolated-copy');
const wire = require('./verification-darwin-diagnostic-protocol');
const { timerDelay } = require('./verification-policy');
const SCHEMA = 'knowledge-darwin-diagnostic-lifecycle.v1';
const now = () => process.hrtime.bigint();
const elapsed = start => Number(now() - start) / 1e6;
const failure = code => Object.assign(new Error(code), { code });
const code = error => /^[a-zA-Z0-9_]{1,128}$/.test(error?.code || '') ? error.code : 'darwin_diagnostic_failed';
const delay = ms => new Promise(resolve => setTimeout(resolve, timerDelay(ms)));
const helperHandles = new Set();
let helpersStarted = 0, helpersClosed = 0;
const helperSummary = () => ({ started: helpersStarted, exit_observed: helpersClosed,
  unconfirmed: [...helperHandles].map(child => ({ pid: child.pid ?? null, exit_observed: false })) });

function parse(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > native.MAX_REPLY_BYTES) throw failure('darwin_diagnostic_reply_oversized');
  try { return copyInertData(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)), null, native.MAX_REPLY_BYTES); }
  catch { throw failure('darwin_diagnostic_reply_invalid'); }
}
// Every helper is a direct child of the role calling this function. --run's
// fd3 is the typed terminal result; stdout/stderr are hashed, never parsed.
function rpc(config, input, { run = false, limitMs = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const begin = now(), chunks = [], hashes = [crypto.createHash('sha256'), crypto.createHash('sha256')];
    const counts = [0, 0]; let size = 0, bad = null, done = false;
    const args = [run ? '--run' : '--request', `--socket=${config.broker_socket}`,
      `--lifecycle-timeout-ms=${Math.ceil(limitMs)}`, '--transport-timeout-ms=30000'];
    const child = spawn(config.broker_path, args, { stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
      env: native.nativeEnv(), shell: false, windowsHide: true });
    helpersStarted++; helperHandles.add(child);
    let timer, killTimer, emergencyTimer;
    function stop(reason) {
      bad ||= failure(reason);
      if (!done) {
        child.kill('SIGTERM');
        killTimer ||= setTimeout(() => { if (!done) child.kill('SIGKILL'); }, 500);
        emergencyTimer ||= setTimeout(() => {
          if (done) return;
          done = true; clearTimeout(timer); clearTimeout(killTimer);
          // Finite emergency result. This is NOT an exit observation. Parent
          // death/stop still fences the native session; retain unconfirmed.
          for (const stream of [child.stdin, child.stdout, child.stderr, child.stdio[3]]) stream.destroy();
          child.unref();
          reject(Object.assign(failure('darwin_diagnostic_helper_cleanup_unconfirmed'), {
            helper: { pid: child.pid ?? null, exit_observed: false }
          }));
        }, 5000);
      }
    }
    function tick() {
      if (elapsed(begin) >= limitMs) stop('darwin_diagnostic_helper_budget_exceeded');
      else timer = setTimeout(tick, timerDelay(limitMs - elapsed(begin)));
    }
    timer = setTimeout(tick, timerDelay(limitMs));
    const control = run ? child.stdio[3] : child.stdout;
    control.on('data', chunk => {
      size += chunk.length;
      if (size > native.MAX_REPLY_BYTES) stop('darwin_diagnostic_reply_oversized');
      else chunks.push(chunk);
    });
    if (run) child.stdout.on('data', chunk => { counts[0] += chunk.length; hashes[0].update(chunk); });
    child.stderr.on('data', chunk => { counts[1] += chunk.length; hashes[1].update(chunk); });
    // Always consume unused fd3 as well; an unexpected stream cannot fill a
    // pipe and deadlock an otherwise bounded request.
    if (!run) child.stdio[3].resume();
    child.on('error', () => { bad ||= failure('darwin_diagnostic_helper_spawn_failed'); });
    child.stdin.on('error', () => { bad ||= failure('darwin_diagnostic_helper_input_failed'); });
    child.on('close', (status, signal) => {
      helperHandles.delete(child); helpersClosed++;
      if (done) return;
      done = true; clearTimeout(timer); clearTimeout(killTimer); clearTimeout(emergencyTimer);
      if (bad) return reject(bad);
      let reply; try { reply = parse(Buffer.concat(chunks)); } catch (error) { return reject(error); }
      if (status !== 0 || signal !== null || reply.ok !== true) return reject(failure(
        typeof reply.error === 'string' && /^[A-Z0-9_]{1,128}$/.test(reply.error) ? reply.error : 'darwin_diagnostic_rpc_rejected'));
      resolve({ reply, helper: { pid: child.pid, exit_observed: true, exit_code: status, signal,
        elapsed_ms: elapsed(begin), stdout_bytes: counts[0], stderr_bytes: counts[1],
        stdout_sha256: hashes[0].digest('hex'), stderr_sha256: hashes[1].digest('hex') } });
    });
    child.stdin.end(JSON.stringify(input));
  });
}

async function directory(root) {
  const absolute = path.resolve(root), parts = absolute.split(path.sep), base = path.parse(absolute).root;
  let current = base;
  for (const part of parts.filter(Boolean)) {
    if (part === base || `${part}${path.sep}` === base) continue;
    current = path.join(current, part);
    const s = await fs.promises.lstat(current);
    if (!s.isDirectory() || s.isSymbolicLink()) throw failure('darwin_diagnostic_state_unsafe');
  }
  return fs.promises.realpath(absolute);
}
async function durableFile(root, name, value) {
  if (!/^[a-z][a-z0-9-]*\.json$/.test(name)) throw failure('darwin_diagnostic_state_unsafe');
  const physical = await directory(root), before = await fs.promises.lstat(physical);
  const bytes = Buffer.from(JSON.stringify(value) + '\n');
  if (bytes.length > 1024 * 1024) throw failure('darwin_diagnostic_state_oversized');
  const file = path.join(physical, name);
  const handle = await fs.promises.open(file, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL |
    (fs.constants.O_NOFOLLOW || 0), 0o600);
  try {
    await handle.writeFile(bytes); await handle.sync();
    const st = await handle.stat(), live = await fs.promises.lstat(file), parent = await fs.promises.lstat(physical);
    if (!st.isFile() || st.nlink !== 1 || st.dev !== live.dev || st.ino !== live.ino ||
        parent.dev !== before.dev || parent.ino !== before.ino || parent.isSymbolicLink()) throw failure('darwin_diagnostic_state_changed');
    const dir = await fs.promises.open(physical, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try { await dir.sync(); } finally { await dir.close(); }
    // Read the SAME open ordinary inode, never reopen a path that may now be a
    // symlink/FIFO. Explicit positions do not reuse writeFile's EOF offset.
    const buffer = Buffer.alloc(bytes.length + 1); let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!bytesRead) break; offset += bytesRead;
    }
    const after = await handle.stat(), named = await fs.promises.lstat(file), currentParent = await fs.promises.lstat(physical);
    if (!buffer.subarray(0, offset).equals(bytes) || !after.isFile() || after.nlink !== 1 || after.size !== bytes.length ||
        named.isSymbolicLink() || named.dev !== st.dev || named.ino !== st.ino || named.size !== bytes.length ||
        currentParent.isSymbolicLink() || currentParent.dev !== before.dev || currentParent.ino !== before.ino ||
        await directory(root) !== physical) throw failure('darwin_diagnostic_state_changed');
  } finally { await handle.close(); }
  return { name, sha256: wire.sha(bytes) };
}
async function readIntent(root, expectedRequest) {
  const physical = await directory(root), parent = await fs.promises.lstat(physical);
  const file = path.join(physical, 'intent.json');
  const handle = await fs.promises.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) |
    (fs.constants.O_NONBLOCK || 0));
  try {
    const st = await handle.stat();
    if (!st.isFile() || st.nlink !== 1 || st.size > 65536 || (st.mode & 0o077)) throw failure('darwin_diagnostic_intent_unsafe');
    const bytes = await handle.readFile(), live = await fs.promises.lstat(file), after = await fs.promises.lstat(physical);
    if (bytes.length !== st.size || live.dev !== st.dev || live.ino !== st.ino || live.isSymbolicLink() ||
        parent.dev !== after.dev || parent.ino !== after.ino || await directory(root) !== physical) {
      throw failure('darwin_diagnostic_intent_changed');
    }
    const value = parse(bytes);
    if (value.schema_version !== 'knowledge-darwin-diagnostic-intent.v1' ||
        value.request_sha256 !== wire.digest(expectedRequest) || !wire.hex(value.attempt_nonce) ||
        value.report_only !== true || value.production_acceptance !== false) throw failure('darwin_diagnostic_intent_invalid');
    return value;
  } finally { await handle.close(); }
}
async function sessionDirectory(stateRoot, id) {
  await directory(stateRoot);
  let parent = stateRoot;
  for (const leaf of ['maintenance', 'darwin-diagnostics']) {
    parent = path.join(parent, leaf);
    try { await fs.promises.mkdir(parent, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    await directory(parent);
  }
  const root = path.join(parent, id);
  await fs.promises.mkdir(root, { mode: 0o700 });
  await directory(root);
  return root;
}
function channel(child) {
  const queue = [], waiters = []; let closed = false;
  child.on('message', value => {
    let item; try { item = copyInertData(value, null, 1024 * 1024); } catch { item = { type: 'invalid' }; }
    if (waiters.length) waiters.shift()(item); else if (queue.length < 8) queue.push(item);
  });
  const exited = new Promise(resolve => child.once('exit', (status, signal) => {
    closed = true; while (waiters.length) waiters.shift()({ type: 'exit' });
    resolve({ pid: child.pid ?? null, exit_observed: true, exit_code: status, signal });
  }));
  child.on('error', () => { closed = true; while (waiters.length) waiters.shift()({ type: 'exit' }); });
  return { exited, next: () => queue.length ? Promise.resolve(queue.shift()) : closed
    ? Promise.resolve({ type: 'exit' }) : new Promise(resolve => waiters.push(resolve)) };
}
function send(child, value) {
  return new Promise(resolve => {
    if (!child.connected) return resolve(false);
    try { child.send(value, error => resolve(!error)); } catch { resolve(false); }
  });
}
async function bounded(promise, limitMs, reason) {
  const start = now(); let timer;
  const expired = new Promise((_, reject) => {
    function check() {
      const left = limitMs - elapsed(start);
      if (left <= 0) reject(failure(reason)); else timer = setTimeout(check, timerDelay(left));
    }
    check();
  });
  try { return await Promise.race([promise, expired]); } finally { clearTimeout(timer); }
}
const childOptions = () => ({ env: native.nativeEnv(), stdio: ['ignore', 'ignore', 'ignore', 'ipc'], execArgv: [] });

async function authority(input) {
  const { config, binding, command, cleanupMs } = input;
  const auth = { attempt_id: binding.attempt_id, token: input.token };
  const inbox = channel(process);
  const registered = await rpc(config, { op: 'register_authority', ...auth });
  await send(process, { type: 'registered', identity: registered.reply.authority });
  const permit = await inbox.next();
  if (permit.type !== 'permit') throw failure('darwin_diagnostic_no_permit');
  const result = await rpc(config, { op: 'run', ...auth, ...command }, { run: true,
    limitMs: command.timeout_ms + cleanupMs + 30000 });
  const typed = wire.commandResult(result.reply, binding, command);
  await send(process, { type: 'command_completed', command: typed, helper: result.helper });
  // A failed command also drains, so its result never omits owned descendants.
  const drain = await rpc(config, { op: 'drain_commands', ...auth, cleanup_budget_ms: cleanupMs },
    { limitMs: cleanupMs + 30000 });
  wire.facts(drain.reply, binding, false);
  await send(process, { type: 'drained', command: typed, helper: result.helper, drain: drain.reply,
    helpers: helperSummary() });
  const finish = await inbox.next();
  if (finish.type !== 'exit') throw failure('darwin_diagnostic_authority_exit_invalid');
  return 0;
}

async function controller(input) {
  const request = wire.request(input.request), config = request.nativeExecution.darwin;
  const start = now(), deadline = start + BigInt(request.verificationPolicy.work_budget_ms) * 1000000n;
  const cleanupMs = request.verificationPolicy.cleanup_budget_ms;
  let workCompleted = null, cleanupDeadline = null;
  let stopped = false, finished = false, reason = null, prepared = null, auth = null, child = null, role = null, terminal = null;
  let stopPromise = null;
  let command = null, drain = null, run = null, authorityExit = null, registry = null;
  const guard = () => {
    if (stopped) throw failure(reason || 'darwin_diagnostic_stopped');
    if (now() >= (cleanupDeadline ?? deadline)) throw failure(cleanupDeadline
      ? 'darwin_diagnostic_cleanup_budget_exceeded' : 'darwin_diagnostic_work_budget_exceeded');
  };
  const stop = why => {
    stopped = true; reason ||= why;
    if (prepared && !stopPromise) stopPromise = rpc(config, { op: 'stop', attempt_id: prepared.attempt_id,
      descriptor_sha256: prepared.descriptor_sha256, cleanup_budget_ms: cleanupMs }, { limitMs: cleanupMs + 30000 }).catch(() => {});
  };
  process.on('message', msg => { if (msg?.type === 'cancel') stop('darwin_diagnostic_cancelled'); });
  process.on('disconnect', () => { if (!finished) stop('darwin_diagnostic_monitor_lost'); });
  const probe = native.diagnosticProbe(request.nativeExecution); guard();
  const plan = await isolated.planProject(request.repoRoot, { limits: config.copy,
    required: request.sourceFiles, cwd: request.test.cwd, checkpoint: guard }); guard();
  const nativeNonce = crypto.randomBytes(32).toString('hex');
  const root = await sessionDirectory(request.stateRoot, input.id);
  registry = root;
  await durableFile(root, 'intent.json', { schema_version: 'knowledge-darwin-diagnostic-intent.v1',
    attempt_nonce: nativeNonce, request_sha256: wire.digest(request), plan_sha256: wire.digest(plan),
    controller_pid: process.pid, report_only: true, production_acceptance: false }); guard();
  await send(process, { type: 'intent', id: input.id, request_sha256: wire.digest(request) });
  try {
    guard();
    const response = await rpc(config, { op: 'prepare', mode: 'isolated_copy', attempt_nonce: nativeNonce,
      work_budget_ms: Math.max(1, Math.floor(Number(deadline - now()) / 1e6)), cleanup_budget_ms: cleanupMs });
    wire.descriptor(response.reply, probe, nativeNonce);
    prepared = response.reply; guard();
    auth = { attempt_id: prepared.attempt_id, token: prepared.token };
    const binding = { attempt_id: prepared.attempt_id, descriptor_sha256: prepared.descriptor_sha256,
      descriptor: prepared.descriptor };
    await durableFile(root, 'reservation.json', { ...binding, production_acceptance: false }); guard();
    await send(process, { type: 'reservation', binding });
    const call = async q => { guard(); const result = await rpc(config, { ...q, ...auth }); guard(); return result.reply; };
    await isolated.transferProject(plan, call, { checkpoint: guard }); guard();
    const readbacks = [];
    const readback = async phase => {
      const observed = await rpc(config, { op: 'readback_copy', ...auth }); guard();
      readbacks.push(wire.readback(observed.reply, binding, plan, phase));
      await isolated.verifyProjectPlan(plan, { checkpoint: guard }); guard();
    };
    await readback('sealed');
    await call({ op: 'expect_authority' });
    child = fork(__filename, ['--authority'], childOptions()); role = channel(child);
    command = { argv: [probe.runtime_path, ...request.test.argv.slice(1)], env: {},
      cwd: request.test.cwd, timeout_ms: Math.min(request.test.timeout_ms, Math.max(1, Math.floor(Number(deadline - now()) / 1e6))) };
    send(child, { type: 'start', config, binding, token: prepared.token, command, cleanupMs });
    const registered = await bounded(role.next(), Math.max(1, Number(deadline - now()) / 1e6), 'darwin_diagnostic_authority_registration_timeout');
    if (registered.type !== 'registered' || registered.identity?.pid !== child.pid) throw failure('darwin_diagnostic_authority_registration_invalid');
    await readback('sealed'); await call({ op: 'permit' }); guard(); send(child, { type: 'permit' });
    const commandMessage = await bounded(role.next(), Math.max(1, Number(deadline - now()) / 1e6), 'darwin_diagnostic_work_budget_exceeded');
    if (commandMessage.type !== 'command_completed') throw failure('darwin_diagnostic_authority_failed');
    run = wire.commandResult(commandMessage.command, binding, command); guard();
    workCompleted = now(); cleanupDeadline = workCompleted + BigInt(cleanupMs) * 1000000n;
    const completed = await bounded(role.next(), Math.max(1, Number(cleanupDeadline - now()) / 1e6), 'darwin_diagnostic_cleanup_budget_exceeded');
    if (completed.type !== 'drained') throw failure('darwin_diagnostic_authority_failed');
    run = wire.commandResult(completed.command, binding, command);
    if (!completed.helpers || completed.helpers.started !== completed.helpers.exit_observed ||
        completed.helpers.unconfirmed?.length !== 0) throw failure('darwin_diagnostic_authority_helpers_unconfirmed');
    drain = wire.facts(completed.drain, binding, false); guard();
    await readback('commands_drained'); guard();
    // Terminal close intentionally stops the registered authority. Keep it
    // alive until that request so ordinary expected teardown is not mistaken
    // for an unexpected owner disappearance before terminal intent exists.
    terminal = (await rpc(config, { op: 'close', attempt_id: prepared.attempt_id,
      descriptor_sha256: prepared.descriptor_sha256, cleanup_budget_ms: cleanupMs }, { limitMs: cleanupMs + 30000 })).reply;
    const proof = wire.facts(terminal, binding, true);
    authorityExit = await bounded(role.exited, Math.max(1, Number(cleanupDeadline - now()) / 1e6), 'darwin_diagnostic_authority_exit_unconfirmed');
    if (authorityExit.exit_code !== null || authorityExit.signal !== 'SIGKILL') throw failure('darwin_diagnostic_authority_exit_failed');
    if (proof.authority_identity?.pid !== child.pid || proof.controller_identity?.pid !== process.pid ||
        proof.command_drain_sha256 !== wire.digest(drain)) throw failure('darwin_diagnostic_role_binding_invalid');
    // Terminal close consumes cleanup time. A new positive work result is not
    // admitted after cancellation/deadline, even when cleanup facts are valid.
    guard(); await readback('closed'); guard();
    const report = { schema_version: SCHEMA, status: wire.commandPassed(run) ? 'diagnostic_completed' : 'command_failed',
      production_acceptance: false, capability_qualified: false, report_only: true,
      request_sha256: wire.digest(request), reservation: binding, command: run,
      original_manifest_sha256: plan.manifest_sha256, original_physical_binding_sha256: plan.physical_binding_sha256,
      readbacks, command_drain_proof: drain, native_terminal_proof: proof,
      authority_exit: authorityExit, authority_exit_method: 'native_exact_terminal_stop_then_child_handle_exit',
      authority_helpers: completed.helpers, controller_helpers: helperSummary(),
      probe_helper: probe.probe_helper, controller_pid: process.pid, elapsed_ms: elapsed(start),
      work_elapsed_ms: Number(workCompleted - start) / 1e6,
      cleanup_elapsed_ms: Number(now() - workCompleted) / 1e6,
      cleanup_deadline_monotonic_ns: cleanupDeadline.toString(),
      progress_signal_available: false, no_progress_limit_applied: false,
      qa_persistence_gate: probe.reply.qa_persistence_gate ?? false, qa_build_id: probe.reply.qa_build_id ?? null,
      work_budget_ms: request.verificationPolicy.work_budget_ms, cleanup_budget_ms: cleanupMs,
      kve_created: false, kvf_created: false, ack_created: false };
    if (helperHandles.size) throw failure('darwin_diagnostic_controller_helpers_unconfirmed');
    await durableFile(root, 'controller-result.json', report); guard();
    finished = true; return report;
  } catch (error) {
    stop(code(error));
    // A lost prepare reply never allocates again. Only lookup/stop/close with
    // the durable original nonce are allowed; there is no command replay.
    if (!prepared) {
      try {
        const found = (await rpc(config, { op: 'lookup', attempt_nonce: nativeNonce })).reply;
        if (wire.hex(found.attempt_id) && wire.hex(found.descriptor_sha256)) prepared = found;
      } catch {}
    }
    if (prepared) {
      try { terminal = (await rpc(config, { op: 'close', attempt_id: prepared.attempt_id,
        descriptor_sha256: prepared.descriptor_sha256, cleanup_budget_ms: cleanupMs }, { limitMs: cleanupMs + 30000 })).reply; } catch {}
    }
    if (child) {
      send(child, { type: 'exit' });
      try { authorityExit = await bounded(role.exited, cleanupMs, 'darwin_diagnostic_authority_exit_unconfirmed'); } catch {}
    }
    const report = { schema_version: SCHEMA, status: 'failed', reason: code(error), production_acceptance: false,
      capability_qualified: false, request_sha256: wire.digest(request),
      native_terminal_observation: terminal, authority_exit: authorityExit,
      controller_helpers: helperSummary(),
      cleanup_status: terminal?.proof?.native_cleanup_facts_confirmed === true ? 'diagnostic_native_facts_only' : 'cleanup_unconfirmed',
      resource_release_authorized: false, elapsed_ms: elapsed(start), kve_created: false, kvf_created: false, ack_created: false };
    try { if (registry) await durableFile(registry, 'controller-failure.json', report); } catch {}
    finished = true; return report;
  }
}

async function runDiagnostic(value) {
  const request = wire.request(value);
  if (process.platform !== 'darwin') throw failure('darwin_diagnostic_requires_macos');
  const id = `DGD-${crypto.randomBytes(16).toString('hex')}`, start = now();
  const child = fork(__filename, ['--controller'], childOptions()), role = channel(child);
  const budget = request.verificationPolicy.work_budget_ms + request.verificationPolicy.cleanup_budget_ms + 30000;
  let observation = null, binding = null, intent = false, cancelled = false;
  const cancel = () => { if (!cancelled) { cancelled = true; send(child, { type: 'cancel' }); } };
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  send(child, { type: 'start', id, request });
  try {
    await bounded((async () => {
      for (;;) {
        const message = await role.next();
        if (message.type === 'intent') intent = true;
        else if (message.type === 'reservation') binding = message.binding;
        else if (message.type === 'result') { observation = message.result; break; }
        else if (message.type === 'exit') break;
      }
    })(), budget, 'darwin_diagnostic_controller_budget_exceeded');
    const exit = await bounded(role.exited, Math.max(1, budget - elapsed(start)), 'darwin_diagnostic_controller_exit_unconfirmed');
    if (!observation || exit.exit_code !== 0 || exit.signal !== null) throw failure('darwin_diagnostic_controller_failed');
    if (cancelled || elapsed(start) >= budget) observation = { ...observation, status: 'failed', reason: cancelled
      ? 'darwin_diagnostic_cancelled' : 'darwin_diagnostic_total_budget_exceeded' };
    // Repeat actual original readback after the observed controller exit. This
    // does not claim a global atomic snapshot or any future immutability.
    if (observation.status === 'diagnostic_completed') {
      if (!/^[0-9]{1,24}$/.test(observation.cleanup_deadline_monotonic_ns || '') ||
          now() >= BigInt(observation.cleanup_deadline_monotonic_ns)) throw failure('darwin_diagnostic_cleanup_budget_exceeded');
      const current = await bounded(isolated.planProject(request.repoRoot, { limits: request.nativeExecution.darwin.copy,
        required: request.sourceFiles, cwd: request.test.cwd }),
      Math.max(1, Number(BigInt(observation.cleanup_deadline_monotonic_ns) - now()) / 1e6), 'darwin_diagnostic_final_readback_budget_exceeded');
      if (current.manifest_sha256 !== observation.original_manifest_sha256 ||
          current.physical_binding_sha256 !== observation.original_physical_binding_sha256 || cancelled ||
          now() >= BigInt(observation.cleanup_deadline_monotonic_ns) || elapsed(start) >= budget) {
        throw failure('darwin_diagnostic_final_original_readback_failed');
      }
    }
    const report = { ...observation, diagnostic_id: id, controller_exit: exit, monitor_pid: process.pid,
      monitor_excluded_from_boundary: true, monitor_elapsed_ms: elapsed(start), production_acceptance: false };
    const reportLeft = observation.status === 'diagnostic_completed'
      ? Number(BigInt(observation.cleanup_deadline_monotonic_ns) - now()) / 1e6 : budget - elapsed(start);
    await bounded(durableFile(path.join(request.stateRoot, 'maintenance', 'darwin-diagnostics', id), 'monitor-result.json', report),
      Math.max(1, reportLeft), 'darwin_diagnostic_report_io_unconfirmed');
    // Diagnostic completion is not a mutable acceptance decision: return any
    // cancellation observed during the durable report write as a failure.
    if (cancelled || elapsed(start) >= budget || observation.status === 'diagnostic_completed' &&
        now() >= BigInt(observation.cleanup_deadline_monotonic_ns)) return { ...report, status: 'failed', reason: cancelled
      ? 'darwin_diagnostic_cancelled' : 'darwin_diagnostic_total_budget_exceeded' };
    return report;
  } catch (error) {
    cancel();
    // Only our direct ChildProcess handle is stopped here. The native observer
    // reacts independently to the controller birth disappearing. Unknown
    // descendants are never killed by a cached UID/PID from this process.
    child.kill('SIGTERM'); await delay(250); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    let exit = null; try { exit = await bounded(role.exited, request.verificationPolicy.cleanup_budget_ms, 'darwin_diagnostic_controller_exit_unconfirmed'); } catch {}
    let terminal = null;
    try { await bounded((async () => {
      if (!binding) {
        const saved = await readIntent(path.join(request.stateRoot, 'maintenance', 'darwin-diagnostics', id), request);
        const found = (await rpc(request.nativeExecution.darwin, { op: 'lookup', attempt_nonce: saved.attempt_nonce })).reply;
        if (wire.hex(found.attempt_id) && wire.hex(found.descriptor_sha256) &&
            found.descriptor?.attempt_nonce === saved.attempt_nonce &&
            wire.digest(found.descriptor) === found.descriptor_sha256) binding = found;
      }
      if (binding) terminal = (await rpc(request.nativeExecution.darwin, { op: 'recover',
        attempt_id: binding.attempt_id, descriptor_sha256: binding.descriptor_sha256,
        cleanup_budget_ms: request.verificationPolicy.cleanup_budget_ms },
      { limitMs: request.verificationPolicy.cleanup_budget_ms + 30000 })).reply;
    })(), request.verificationPolicy.cleanup_budget_ms, 'darwin_diagnostic_monitor_recovery_unconfirmed'); } catch {}
    return { schema_version: SCHEMA, diagnostic_id: id, status: 'failed', reason: code(error),
      intent_observed: intent, production_acceptance: false, capability_qualified: false,
      controller_exit: exit, native_terminal_observation: terminal, cleanup_status: 'cleanup_unconfirmed',
      resource_release_authorized: false, kve_created: false, kvf_created: false, ack_created: false };
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}

if (require.main === module) {
  const inbox = channel(process);
  let childFinished = false;
  process.on('disconnect', () => { if (!childFinished && process.argv[2] === '--authority') process.exit(2); });
  (async () => {
    const message = await inbox.next();
    if (message.type !== 'start') throw failure('darwin_diagnostic_child_input_invalid');
    if (process.argv[2] === '--controller') {
      const result = await controller(message); await send(process, { type: 'result', result });
    } else if (process.argv[2] === '--authority') await authority(message);
    else throw failure('darwin_diagnostic_role_invalid');
    childFinished = true; if (process.connected) process.disconnect();
  })().then(() => process.exit(0), async error => {
    await send(process, { type: 'failed', reason: code(error) });
    if (process.connected) process.disconnect(); process.exit(2);
  });
}
module.exports = { SCHEMA, runDiagnostic };
