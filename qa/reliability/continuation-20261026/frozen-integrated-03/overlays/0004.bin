'use strict';

// These are exact JavaScript-controller tests with modeled native processes,
// RPCs and kernel observations. They are not physical macOS qualification.
// The real module is evaluated unchanged in the current realm; only its
// process/platform and explicit native-boundary imports are substituted.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const { EventEmitter } = require('node:events');
const PROTOCOL = 'knowledge-macos-command-worker.v1';
const nativeProcess = { platform: 'darwin', execPath: '/protected/node',
  getuid: () => 501, hrtime: process.hrtime, env: {} };
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const emptyHash = sha(Buffer.alloc(0));
const forever = () => new Promise(() => {});

function load(name, imports, processModel = nativeProcess) {
  const filename = path.join(__dirname, '../tools/lib/', name + '.js');
  const realRequire = createRequire(filename), module = { exports: {} };
  const requireModeled = id => Object.hasOwn(imports, id) ? imports[id] : realRequire(id);
  const evaluate = vm.runInThisContext('(function(require,module,exports,__filename,__dirname,process){\n' +
    fs.readFileSync(filename, 'utf8') + '\n})', { filename });
  evaluate(requireModeled, module, module.exports, filename, path.dirname(filename), processModel);
  return module.exports;
}

function modeled(options = {}) {
  const children = [], calls = [], output = Buffer.from('{"modeled":true}');
  const controller = new AbortController();
  const scope = { schema: 'modeled-native-scope' };
  const binding = { attempt_id: 'a'.repeat(64), descriptor_sha256: 'b'.repeat(64),
    descriptor: { protected_worker_root: '/protected/runtime', writable_root: '/workspace/project' } };
  const capability = { source_sha256: 'c'.repeat(64) };
  let sessionSignal;
  function sendMessage(child, value) { queueMicrotask(() => child.emit('message', { protocol: PROTOCOL, ...value })); }
  function exit(child, code, signal, proof = true) {
    if (child.exited) return;
    child.exited = true;child.writerProof = proof;
    child.emit('exit', code, signal);
  }
  const session = { binding, capability, scope,
    authorityInput: () => ({ modeled: true }),
    async expectAuthority() { calls.push('expect_authority'); },
    async registerAuthorityCustody(births) {
      calls.push('register_authority_custody');
      assert.equal(births.writer.pid, 9100);assert.equal(births.guardian.pid, 9200);
    },
    async registerStateWriter(births) {
      calls.push('register_state_writer');
      assert.equal(births.writer.pid, 9101);assert.equal(births.guardian.pid, 9201);
      if (options.custodyStalls) return forever();
      if (options.custodyError) throw Object.assign(new Error('modeled custody failure'),
        { code: 'verification_darwin_storage_guardian_permit' });
    },
    async permit() { calls.push('permit');if (options.permitStalls) return forever(); },
    async run(command, handlers) {
      calls.push('run');
      if (options.cancelDuringRun) controller.abort();
      if (options.runStalls) return forever();
      handlers.onStdout(output);
      return { status: 0, signal: null, helper: { stdout_bytes: output.length, stderr_bytes: 0,
        stdout_sha256: options.badOutputHash ? emptyHash : sha(output), stderr_sha256: emptyHash } };
    },
    async drain() { calls.push('drain');return { status: 'completed' }; },
    async close() {
      calls.push('close');
      if (!options.authorityExitMissing) queueMicrotask(() => exit(children[0], null, 'SIGKILL', true));
      return { status: 'completed' };
    },
    async stop() { calls.push('stop');if (options.stopStalls) return forever(); },
    async recover() { calls.push('recover');if (options.recoverStalls) return forever();return { ok: true }; }
  };
  function createStorageChild(input) {
    const child = new EventEmitter();child.pid = 9100 + children.length;child.writerProof = false;child.stdio = [];
    child.role = input.macosWritableRoot !== undefined ? 'operation' : 'authority';
    child.nativeReady = Promise.resolve().then(() => input.beforeMacOSPermit?.({
      writer: { pid: child.pid, ruid: 501 }, guardian: { pid: child.pid + 100, ruid: 501 }
    })).then(() => { if (input.beforeMacOSPermit) calls.push('native_permit_' + child.role); });
    child.nativeReady.catch(() => {});
    child.storageSnapshot = () => ({ writer_exit_observed: child.writerProof,
      guardian_exit_observed: child.exited === true, writer_birth_bound: true });
    child.stopWithin = () => {
      calls.push('stop_' + child.role);
      if (!(options.noCleanupExits || options.authorityExitMissing && child.role === 'authority')) {
        queueMicrotask(() => exit(child, null, 'SIGKILL', true));
      }
    };
    child.disconnect = () => { calls.push('disconnect_' + child.role); };
    child.unref = () => { calls.push('unref_' + child.role); };
    child.send = (message, callback) => {
      if (message.type === 'start') {
        child.role = message.role;
        if (options.callbackNever === child.role) {
          if (options.cancelAtSend) queueMicrotask(() => controller.abort());
          return true;
        }
        if (options.callbackError === child.role) {
          queueMicrotask(() => callback(new Error('modeled send failure')));return true;
        }
        queueMicrotask(() => callback(null));
        if (child.role === 'authority') sendMessage(child, { type: 'registered', registration: {
          ok: true, authority: { pid: child.pid, ruid: options.badAuthorityIdentity ? 502 : 501 } } });
        else if (options.resultBeforeDrain) sendMessage(child, { type: 'result', value: { accepted: true } });
        else sendMessage(child, { type: 'request', id: 1, op: 'execute', command: { modeled: true } });
      } else if (message.type === 'reply') {
        queueMicrotask(() => callback(null));
        if (message.id === 1) sendMessage(child, { type: 'request', id: 2, op: 'drain' });
        else if (message.id === 2) {
          sendMessage(child, { type: 'result', value: { accepted: true } });
          setImmediate(() => exit(child, options.workerExitCode ?? 0, null, !options.workerProofMissing));
        }
      }
      return true;
    };
    children.push(child);return child;
  }
  const runner = load('macos-command-runner', {
    './macos-workspace-session': { configuration: () => ({ config: {}, workspace_id: 'd'.repeat(64) }),
      async openSession(input) { sessionSignal = input.signal;calls.push('open');return session; } },
    './verification-darwin-session': { async rpc(config, request) {
      calls.push(request.op);if (options.observationStalls) return forever();return { reply: { modeled: true } };
    } },
    './verification-darwin-storage-guardian': { createStorageChild },
    './macos-command-scope': { validateObservation() { return { status: options.closureUnconfirmed ? 'unconfirmed' : 'completed' }; } },
    './command-runner': { budgets: value => ({ setupMs: 80, workMs: 160, cleanupMs: 80, progressMs: 0, ...value }),
      safeEnvironment: value => value }
  });
  return { children, calls, controller, runner, scope,
    get sessionSignal() { return sessionSignal; },
    run: value => runner.runOwnedOperation('flow-main', { argv: [] }, { signal: controller.signal, ...value }) };
}

async function bounded(promise, limitMs = 1100) {
  let timeout;
  try { return await Promise.race([promise, new Promise((resolve, reject) => {
    timeout = setTimeout(() => reject(Object.assign(new Error('modeled controller failed finite-return bound'),
      { code: 'test_controller_return_bound' })), limitMs);
  })]); } finally { clearTimeout(timeout); }
}

test('modeled Mac controller accepts only terminal native closure and both exact writer exits', async () => {
  const f = modeled(), result = await bounded(f.run());
  assert.equal(result.value.accepted, true);assert.equal(result.cleanup.status, 'completed');
  assert.equal(result.value.ownership.status, 'completed');assert.equal(result.scope, f.scope);
  assert.equal(result.cleanup.authority_exit.writer_exit_observed, true);
  assert.equal(result.cleanup.state_worker_exit.writer_exit_observed, true);
  assert.deepEqual(f.calls, ['open', 'expect_authority', 'register_authority_custody', 'native_permit_authority',
    'register_state_writer', 'native_permit_operation',
    'permit', 'run', 'drain', 'close', 'observe_scope']);
});

test('modeled Mac controller rejects a result before native terminal closure', async () => {
  const f = modeled({ resultBeforeDrain: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_macos_terminal_missing');
  assert(f.calls.includes('stop'));assert(f.calls.includes('recover'));
});

test('modeled Mac controller never accepts exit notification without the writer exit proof', async () => {
  const f = modeled({ workerProofMissing: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_macos_state_worker_exit_unconfirmed' &&
    error.cleanup.status === 'unconfirmed' && error.recovery_required === true);
});

test('modeled Mac controller binds output bytes to the independently received helper digest', async () => {
  const f = modeled({ badOutputHash: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_output_unconfirmed');
  assert(!f.calls.includes('drain'));assert(f.calls.includes('stop'));
});

test('modeled Mac controller refuses a different authority UID before any leaf execution', async () => {
  const f = modeled({ badAuthorityIdentity: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_macos_authority_identity_invalid');
  assert(!f.calls.includes('run'));assert(!f.calls.includes('permit'));
});

test('modeled Mac controller rejects send callback errors and still requests scope cleanup', async () => {
  for (const options of [{ callbackError: 'operation' }, { custodyError: true }]) {
    const f = modeled(options);
    await assert.rejects(bounded(f.run()), error => error.code === (options.custodyError ?
      'verification_darwin_storage_guardian_permit' : 'command_macos_transport_failed'));
    assert(f.calls.includes('stop'));assert(f.calls.includes('recover'));
    if (options.custodyError) {
      assert(!f.calls.includes('native_permit_operation'));assert(!f.calls.includes('permit'));assert(!f.calls.includes('run'));
    }
  }
});

test('modeled Mac setup callback loss cannot outlive its setup plus cleanup deadlines', async () => {
  for (const options of [{ callbackNever: 'authority' }, { custodyStalls: true }]) {
    const f = modeled({ ...options, noCleanupExits: true });
    await assert.rejects(bounded(f.run()), error => error.code === 'command_setup_timeout' &&
      error.cleanup.status === 'unconfirmed' && error.recovery_required === true);
    assert(f.sessionSignal.aborted);assert(f.calls.includes('unref_authority'));
    assert(!f.calls.includes('permit'));assert(!f.calls.includes('run'));
    if (options.custodyStalls) assert(f.calls.includes('register_state_writer'));
  }
});

test('modeled Mac cancellation interrupts a never-returning start callback', async () => {
  const f = modeled({ callbackNever: 'authority', cancelAtSend: true, noCleanupExits: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_cancelled' &&
    error.cleanup.status === 'unconfirmed');
});

test('modeled Mac authority-exit notification loss stays finite and cannot imply closure', async () => {
  const f = modeled({ authorityExitMissing: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_work_timeout' &&
    error.cleanup.status === 'unconfirmed' && error.recovery_required === true);
});

test('modeled Mac abort cannot wait forever on a failed native stop RPC', async () => {
  const f = modeled({ cancelDuringRun: true, runStalls: true, stopStalls: true, noCleanupExits: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_cancelled' &&
    error.cleanup.status === 'unconfirmed');
});

test('modeled Mac recovery success without a typed native closure remains unconfirmed', async () => {
  const f = modeled({ badOutputHash: true, closureUnconfirmed: true });
  await assert.rejects(bounded(f.run()), error => error.code === 'command_output_unconfirmed' &&
    error.cleanup.status === 'unconfirmed' && error.recovery_required === true);
});

function modeledWorker(options = {}) {
  const messages = [], flowCalls = [], evaluationCalls = [], exits = [], chdirCalls = [];
  const p = Object.assign(new EventEmitter(), nativeProcess, { env: {}, connected: true,
    argv: [], chdir: name => chdirCalls.push(name), exit: code => exits.push(code) });
  const descriptor = { writable_root: '/project', protected_worker_root: path.resolve(__dirname, '..') };
  const scope = { binding: { descriptor } };
  const terminal = { status: 'completed', closure: { observation: { modeled: true } }, capability: {}, observation_nonce: 'e'.repeat(64) };
  p.send = (message, callback) => {
    messages.push(message);queueMicrotask(() => callback(null));
    if (message.type === 'request') queueMicrotask(() => p.emit('message', { protocol: PROTOCOL, type: 'reply', id: message.id,
      value: message.op === 'drain' ? { status: 'completed', terminal } : message.op === 'finish' ? terminal :
        { status: 0, cleanup: { status: 'completed' }, stdout: '', stderr: '' } }));
  };
  load('macos-command-worker', {
    'node:net': { Socket: class extends EventEmitter { resume() {} } },
    './macos-worker-envelope': { install() {} },
    './macos-command-scope': { validateCommandScope: () => true },
    './command-scope-proof': { setMacOSTerminalObservation() {} },
    './path-context': load('path-context', { './git-context': { detectGitContext: () => ({ warnings: [] }) } }, p),
    '../evaluation-harness': { __owned: { async main(runtime) {
      evaluationCalls.push(runtime.context);return { status: 'release_candidate' };
    } } },
    '../flow': { __owned: { async main(argv, runtime) {
      flowCalls.push(argv);return options.flow ? options.flow(runtime) : { accepted: true };
    }, async runFlow(input) { flowCalls.push(input);return { accepted: true }; } } }
  }, p);
  return { messages, flowCalls, evaluationCalls, exits, chdirCalls,
    async run(argv = [], patches = {}) {
      const message = { protocol: PROTOCOL, type: 'start', role: 'operation', operation: 'flow-main', payload: { argv },
        descriptor, scope, environment: {}, budgets: {}, deadline_ns: String(process.hrtime.bigint() + 2000000000n), ...patches };
      await bounded(p.listeners('message')[0](message));
      return messages.find(value => value.type === 'error')?.error;
    } };
}

test('modeled fixed Mac worker binds native scope and protected package before running trusted Flow', async () => {
  const f = modeledWorker();assert.equal(await f.run(['status']), undefined);
  assert.equal(f.flowCalls.length, 1);assert.equal(f.flowCalls[0].at(-2), '--system-root');
  assert.equal(f.flowCalls[0].at(-1), path.resolve(__dirname, '..'));
  assert.deepEqual(f.exits, [0]);assert.deepEqual(f.chdirCalls, ['/project']);
  assert.equal(f.messages.at(-1).type, 'result');
});

test('modeled fixed Mac worker refuses every root flag alias outside the registered workspace', async () => {
  for (const name of ['target-root', 'targetRoot', 'project-knowledge-root', 'projectKnowledgeRoot',
    'state-root', 'stateRoot', 'team-root', 'teamRoot']) {
    for (const argv of [[`--${name}`, '/foreign'], [`--${name}=/foreign`]]) {
      const f = modeledWorker(), error = await f.run(argv);
      assert.equal(error?.code, 'command_macos_context_outside_workspace', JSON.stringify(argv));
      assert.equal(f.flowCalls.length, 0);assert.deepEqual(f.exits, [1]);
      assert.equal(f.messages.some(value => value.type === 'request' || value.type === 'result'), false);
    }
  }
});

test('modeled fixed Mac worker refuses a caller-supplied untrusted package root alias', async () => {
  for (const argv of [['--system-root', '/project/runtime'], ['--systemRoot=/project/runtime']]) {
    const f = modeledWorker(), error = await f.run(argv);
    assert.equal(error?.code, 'command_macos_untrusted_system_root');assert.equal(f.flowCalls.length, 0);
  }
});

test('modeled fixed Mac worker refuses descriptor substitution before project chdir', async () => {
  const f = modeledWorker(), error = await f.run([], { descriptor: { writable_root: '/foreign',
    protected_worker_root: path.resolve(__dirname, '..') } });
  assert.equal(error?.code, 'command_macos_worker_binding_invalid');assert.equal(f.flowCalls.length, 0);
  assert.equal(f.chdirCalls.length, 0);
});

test('modeled fixed Mac worker closes leaf admission after terminal drain', async () => {
  const f = modeledWorker({ async flow(runtime) {
    const lease = await runtime.macosRemote.createSession();await lease.drain();
    await assert.rejects(lease.run({ executable: process.execPath, args: [], cwd: '/project' }),
      error => error.code === 'command_macos_admission_closed');
    await lease.finish();return { accepted: true };
  } });
  assert.equal(await f.run(), undefined);assert.deepEqual(f.exits, [0]);
  assert.deepEqual(f.messages.filter(value => value.type === 'request').map(value => value.op), ['drain', 'finish']);
});

test('modeled fixed Mac worker cannot evaluate a caller-selected nested authority module', async () => {
  const f = modeledWorker({ flow: runtime => runtime.macosRemote.run({ nestedAuthority: true,
    args: ['/project/untrusted.cjs'], cwd: '/project',
    env: { KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: '/project/.knowledge', KNOWLEDGE_STATE_ROOT: '/project/.knowledge' } }) });
  assert.equal((await f.run())?.code, 'command_macos_nested_authority_invalid');
  assert.equal(f.messages.some(value => value.type === 'request' || value.type === 'result'), false);
  assert.deepEqual(f.exits, [1]);
});

test('modeled fixed Mac worker preserves the explicit nested evaluation project and state roots', async () => {
  const f = modeledWorker({ async flow(runtime) {
    const result = await runtime.macosRemote.run({ nestedAuthority: true,
      args: [path.resolve(__dirname, '../tools/evaluation-harness.js')], cwd: '/project/subproject',
      env: { KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: '/project/subproject/.knowledge',
        KNOWLEDGE_STATE_ROOT: '/project/subproject/custom-state' } });
    assert.equal(result.status, 0);return { accepted: true };
  } });
  assert.equal(await f.run(), undefined);assert.equal(f.evaluationCalls.length, 1);
  assert.equal(f.evaluationCalls[0].targetRoot, '/project/subproject');
  assert.equal(f.evaluationCalls[0].projectKnowledgeRoot, '/project/subproject/.knowledge');
  assert.equal(f.evaluationCalls[0].stateRoot, '/project/subproject/custom-state');
  assert.equal(f.evaluationCalls[0].systemRoot, path.resolve(__dirname, '..'));
});

test('modeled fixed Mac worker rejects an already-cancelled leaf before native admission', async () => {
  const f = modeledWorker({ flow(runtime) {
    const abort = new AbortController();abort.abort();
    return runtime.macosRemote.run({ executable: nativeProcess.execPath, args: [], cwd: '/project' }, { signal: abort.signal });
  } });
  assert.equal((await f.run())?.code, 'command_cancelled');
  assert.equal(f.messages.some(value => value.type === 'request' || value.type === 'result'), false);
  assert.deepEqual(f.exits, [1]);
});

function modeledSession(options = {}) {
  const wire = require('../tools/lib/verification-darwin-session-protocol');
  const protocol = require('../tools/lib/macos-workspace-protocol');
  const calls = [], abort = new AbortController(), workspaceId = 'f'.repeat(64), token = 'e'.repeat(64);
  const capability = { binary_sha256: '2'.repeat(64), daemon_epoch: '8'.repeat(64), installation_id: '9'.repeat(64),
    host_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', boot_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    account_policy_id: 'admin_reserved_interval_no_runtime_nss.v1', account_policy_sha256: 'c'.repeat(64),
    runtime_path: options.wrongRuntime ? '/foreign/node' : nativeProcess.execPath, runtime_sha256: 'd'.repeat(64) };
  for (const key of protocol.SOURCE_KEYS) capability[key] = '1'.repeat(64);
  const config = { broker_path: '/protected/broker', broker_socket: '/protected/socket' };
  let prepared, ordinal = 0, releaseRun;
  const api = load('macos-workspace-session', { './verification-darwin-session': {
    async probeSession() { return capability; },
    async rpc(c, request) {
      calls.push(request);
      if (request.op === 'prepare') {
        const d = { ...capability, schema: protocol.SCHEMA, backend: 'darwin_private_ruid', mode: protocol.MODE,
          stub_wire_version: 'KVS3', guardian_protocol: 'KVR2', capability_qualified: true, qualification_mode: false,
          attempt_id: 'a'.repeat(64), boundary_id: 'a'.repeat(64), attempt_nonce: request.attempt_nonce,
          broker_binary_sha256: capability.binary_sha256, allocation_seq: '1', allocation_sha256: 'b'.repeat(64),
          owner_uid: 501, task_ruid: 1000000000, task_gid: 2000000000,
          workspace_path: '/protected/attempt', scratch_path: '/protected/attempt.scratch',
          scratch_policy: 'admin_workspace_acl_sibling.v1',
          allowed_runtimes: { [capability.runtime_path]: capability.runtime_sha256 },
          work_started_monotonic_ms: 1000, work_budget_ms: request.work_budget_ms,
          work_deadline_ms: 1000 + request.work_budget_ms, cleanup_budget_ms: request.cleanup_budget_ms,
          workspace_id: options.wrongWorkspace ? '0'.repeat(64) : workspaceId, workspace_capability_sha256: '3'.repeat(64),
          writable_root: '/project', protected_worker_root: path.resolve(__dirname, '..'),
          writable_identity: { device: '1', inode: '2', owner_uid: 501, group_gid: 2000000000, mode: 0o770 } };
        prepared = { ok: true, attempt_id: d.attempt_id, descriptor_sha256: wire.digest(d), descriptor: d,
          workspace_path: d.workspace_path, token };
        assert.equal(protocol.validDescriptorFields(d), true, 'modeled descriptor fixture must pass structural validation');
        return { reply: prepared };
      }
      if (request.op === 'run') {
        const d = prepared.descriptor;
        const command = Object.fromEntries(['argv', 'cwd', 'env', 'timeout_ms'].map(key => [key, request[key]]));
        const response = { ...capability, ...d, ok: true, schema: 'knowledge-darwin-command-result.v1',
          descriptor_sha256: prepared.descriptor_sha256, proof_current: true, writer_generation: 1,
          command_ordinal: ++ordinal, command_sha256: wire.digest(command), guardian_reaped: true,
          permit_observed: true, timed_out: false, stop_latched: false, admission_closed: false,
          exit_code: 0, signal: null, command_cleanup_confirmed: true, kernel_membership_zero: true,
          cleanup_command_ordinal: ordinal, ...options.runPatch };
        if (options.stallRun) return new Promise(resolve => { releaseRun = () => resolve({ reply: response, helper: {} }); });
        return { reply: response, helper: {} };
      }
      return { reply: { ok: true } };
    }
  } });
  const command = { executable: nativeProcess.execPath, args: ['-e', '0'], cwd: '/project/subdir', env: {} };
  return { calls, abort, token, command, api, release: () => releaseRun(),
    open: () => api.openSession({ config, workspace_id: workspaceId,
      deadlineNs: process.hrtime.bigint() + 1000000000n, cleanupMs: 100, signal: abort.signal }) };
}

test('modeled Mac session rejects a non-pinned runtime before preparing any native scope', async () => {
  const f = modeledSession({ wrongRuntime: true });
  await assert.rejects(f.open(), error => error.code === 'command_macos_protected_runtime_required');
  assert.equal(f.calls.length, 0);
});

test('modeled Mac session stops a mismatched registered workspace and never exposes its bearer token', async () => {
  const f = modeledSession({ wrongWorkspace: true });
  await assert.rejects(f.open(), error => {
    assert.equal(error.code, 'command_macos_workspace_binding_invalid');assert.equal(error.recovery_required, true);
    assert(!JSON.stringify(error).includes(f.token));
    assert.deepEqual(Object.keys(error.binding).sort(), ['attempt_id', 'descriptor_sha256']);return true;
  });
  assert.deepEqual(f.calls.map(value => value.op), ['prepare', 'stop']);
});

test('modeled Mac session requires strict per-command UID sweep facts before any second command', async () => {
  for (const runPatch of [{ command_cleanup_confirmed: false }, { command_cleanup_confirmed: 1 },
    { kernel_membership_zero: false }, { kernel_membership_zero: 1 }, { cleanup_command_ordinal: 2 }]) {
    const f = modeledSession({ runPatch }), session = await f.open();
    await assert.rejects(session.run(f.command), error => error.code === 'command_macos_command_cleanup_unconfirmed');
    await assert.rejects(session.run(f.command));
    assert.deepEqual(f.calls.map(value => value.op), ['prepare', 'run', 'stop']);
  }
});

test('modeled Mac session binds ordinary command proof digest independently from writable cleanup facts', async () => {
  const f = modeledSession({ runPatch: { command_sha256: '0'.repeat(64) } }), session = await f.open();
  await assert.rejects(session.run(f.command), error => error.code === 'verification_darwin_command_receipt_invalid');
  assert.deepEqual(f.calls.map(value => value.op), ['prepare', 'run', 'stop']);
});

test('modeled Mac session removes controller capabilities and puts leaf temp paths in registered scratch', async () => {
  const f = modeledSession(), session = await f.open();
  const value = await session.run({ ...f.command, env: { KNOWLEDGE_MACOS_WORKSPACE_ID: 'secret',
    KNOWLEDGE_MACOS_BROKER_PATH: '/protected/broker', NODE_CHANNEL_FD: '4', NODE_OPTIONS: '--require=evil',
    DYLD_INSERT_LIBRARIES: '/evil', HOME: '/home/private', KEEP_ME: 'ordinary' } });
  assert.equal(value.cleanup.status, 'completed');
  const request = f.calls.find(row => row.op === 'run');assert.equal(request.cwd, 'subdir');
  assert.equal(request.env.KEEP_ME, 'ordinary');assert.equal(request.env.HOME, '/protected/attempt.scratch');
  assert.equal(request.env.TMPDIR, '/protected/attempt.scratch');
  assert(!Object.keys(request.env).some(key => /^(?:KNOWLEDGE_MACOS_|NODE_CHANNEL_|NODE_OPTIONS|DYLD_)/.test(key)));
});

test('modeled Mac session cancellation closes admission even if an in-flight native command later replies successfully', async () => {
  const f = modeledSession({ stallRun: true }), session = await f.open();
  const first = session.run(f.command);f.abort.abort();f.release();
  await assert.rejects(first, error => error.code === 'command_cancelled');
  await assert.rejects(session.run(f.command), error => error.code === 'command_cancelled');
  assert.deepEqual(f.calls.map(value => value.op), ['prepare', 'run', 'stop']);
});

test('modeled Mac session rejects concurrent commands before a second native admission', async () => {
  const f = modeledSession({ stallRun: true }), session = await f.open();
  const first = session.run(f.command);
  await assert.rejects(session.run(f.command), error => error.code === 'command_macos_admission_closed');
  f.release();assert.equal((await first).cleanup.status, 'completed');
  assert.deepEqual(f.calls.map(value => value.op), ['prepare', 'run']);
});
