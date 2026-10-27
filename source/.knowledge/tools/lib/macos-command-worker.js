'use strict';

// Fixed immutable entrypoint, never a repository-provided module. Native
// guardian owns this original-UID writer even while synchronous I/O is stuck.
const net = require('node:net');
const path = require('node:path');
let copyInertData;
const PROTOCOL = 'knowledge-macos-command-worker.v1';
const MAX_MESSAGE = 65 * 1024 * 1024;
const fail = code => Object.assign(new Error(code), { code });
const now = () => process.hrtime.bigint();
const pending = new Map();
let used = false, sequence = 0, ordinal = 0, scope, deadline, nativeDrained = null, active = 0;
const leases = new Set();
const parent = new net.Socket({ fd: 3, readable: true, writable: false });
parent.on('end', () => process.exit(1));parent.on('error', () => process.exit(1));parent.resume();
process.on('disconnect', () => process.exit(1));
function send(value) {
  const message = { protocol: PROTOCOL, ...value };
  if (Buffer.byteLength(JSON.stringify(message)) > MAX_MESSAGE) return Promise.reject(fail('command_output_limit'));
  return new Promise((resolve, reject) => process.send(message, error => error ? reject(error) : resolve()));
}
function guard() {
  if (!process.connected || !deadline || now() >= deadline) throw fail('command_work_timeout');
}
function request(op, extra = {}) {
  guard();if (pending.size) return Promise.reject(fail('command_concurrent_request'));
  const id = ++ordinal;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    send({ type: 'request', id, op, ...extra }).catch(error => { pending.delete(id);reject(error); });
  });
}
function progress(phase, detail) { guard();send({ type: 'progress', sequence: ++sequence, phase, detail }).catch(() => process.exit(1)); }
function inside(root, value) {
  const relative = path.relative(root, path.resolve(value));
  return relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
}
function contextSafe(context, descriptor) {
  if (!context || typeof context !== 'object') throw fail('command_macos_context_invalid');
  const result = { ...context, systemRoot: descriptor.protected_worker_root };
  for (const key of ['targetRoot', 'projectKnowledgeRoot', 'stateRoot', 'teamRoot']) {
    if (result[key] !== undefined && result[key] !== null && (typeof result[key] !== 'string' || !inside(descriptor.writable_root, result[key]))) {
      throw fail('command_macos_context_outside_workspace');
    }
  }
  return result;
}
function configuredEnvironment(raw, descriptor) {
  const result = copyInertData(raw, null, 1024 * 1024);
  for (const key of Object.keys(result)) {
    if (typeof result[key] !== 'string' || /^(?:NODE_|DYLD_|LD_|KNOWLEDGE_MACOS_)/.test(key)) delete result[key];
  }
  Object.assign(result, { KNOWLEDGE_SYSTEM_ROOT: descriptor.protected_worker_root,
    KNOWLEDGE_TARGET_ROOT: result.KNOWLEDGE_TARGET_ROOT || descriptor.writable_root,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: result.KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT || path.join(descriptor.writable_root, '.knowledge'),
    KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1' });
  for (const key of ['KNOWLEDGE_TARGET_ROOT', 'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT', 'KNOWLEDGE_STATE_ROOT', 'KNOWLEDGE_TEAM_ROOT']) {
    if (result[key] && !inside(descriptor.writable_root, result[key])) throw fail('command_macos_context_outside_workspace');
  }
  return result;
}
function argvSafe(argv, descriptor) {
  if (!Array.isArray(argv) || argv.some(arg => typeof arg !== 'string' || arg.includes('\0'))) throw fail('command_invalid');
  // Context flag aliases are parsed by the same trusted parser as Flow.
  const flags = require('./path-context').parseCliArgs(argv).flags;
  for (const key of ['targetRoot', 'projectKnowledgeRoot', 'stateRoot', 'teamRoot']) {
    if (flags[key] !== undefined && (typeof flags[key] !== 'string' || !inside(descriptor.writable_root, flags[key]))) {
      throw fail('command_macos_context_outside_workspace');
    }
  }
  if (flags.systemRoot !== undefined && (typeof flags.systemRoot !== 'string' || path.resolve(flags.systemRoot) !== descriptor.protected_worker_root)) {
    throw fail('command_macos_untrusted_system_root');
  }
  return [...argv, '--system-root', descriptor.protected_worker_root];
}
async function terminalDrain() {
  guard();if (nativeDrained) return nativeDrained;
  const result = await request('drain');guard();
  if (result.status !== 'completed' || result.terminal?.status !== 'completed') throw fail('command_cleanup_unconfirmed');
  const terminal = result.terminal;
  require('./command-scope-proof').setMacOSTerminalObservation(scope, terminal.closure?.observation,
    terminal.capability, terminal.observation_nonce);
  nativeDrained = result;return result;
}
async function execute(command, runtime, options = {}) {
  guard();if (nativeDrained) throw fail('command_macos_admission_closed');
  if (options.signal?.aborted) throw fail('command_cancelled');
  // Nested trusted Flow/evaluation orchestration stays in this fixed writer;
  // every leaf command still crosses the same private-UID boundary.
  if (command.nestedAuthority === true) {
    if (active || !command.args?.length) throw fail('command_concurrent_request');
    const file = path.resolve(command.args[0]);
    const root = path.resolve(__dirname, '../..');
    const contextAPI = require('./path-context'), env = command.env || {};
    const nestedFlags = file === path.join(root, 'tools/flow.js') ? contextAPI.parseCliArgs(command.args.slice(1)).flags : {};
    const nestedContext = contextSafe(contextAPI.resolveKnowledgeContext({ __skipCli: true,
      systemRoot: root, targetRoot: command.cwd, projectKnowledgeRoot: env.KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT,
      stateRoot: env.KNOWLEDGE_STATE_ROOT, teamRoot: env.KNOWLEDGE_TEAM_ROOT, mode: env.KNOWLEDGE_MODE,
      workspaceId: env.KNOWLEDGE_WORKSPACE_ID, agentId: env.KNOWLEDGE_AGENT_ID, ...nestedFlags }), scope.binding.descriptor);
    const nestedRuntime = { ...runtime, context: nestedContext };
    let value;
    if (file === path.join(root, 'tools/evaluation-harness.js')) value = await require('../evaluation-harness').__owned.main(nestedRuntime);
    else if (file === path.join(root, 'tools/flow.js')) {
      const flow = require('../flow');
      // The shared UID generation has no nested irreversible terminal yet.
      // Never release an inner exclusive lock using leaf-only quiescence.
      if (flow.parseArgs(command.args.slice(1)).exclusive) throw fail('command_macos_nested_exclusive_flow_unsupported');
      value = await flow.__owned.main(argvSafe(command.args.slice(1), scope.binding.descriptor), nestedRuntime);
    }
    else throw fail('command_macos_nested_authority_invalid');
    return { status: value.status === 'release_candidate' || value.overall_status === 'ok' ? 0 : 2,
      signal: null, error: null, stdout: JSON.stringify(value), stderr: '',
      cleanup: { status: 'completed', method: 'macos_nested_leaf_commands_quiesced' }, scope };
  }
  active++;
  const cancel = () => { send({ type: 'cancel_active', id: ordinal }).catch(() => process.exit(1)); };
  try {
    const response = request('execute', { command });
    options.signal?.addEventListener('abort', cancel, { once: true });
    if (options.signal?.aborted) cancel();
    const value = await response;guard();return value;
  } finally { options.signal?.removeEventListener('abort', cancel);active--; }
}
function createSession(runtime) {
  guard();if (nativeDrained) throw fail('command_macos_admission_closed');
  const lease = { drained: false, finished: false };leases.add(lease);
  return Promise.resolve({ scope,
    run: command => execute(command, runtime),
    remaining: () => Math.max(0, Math.floor(Number(deadline - now()) / 1e6)),
    async drain() {
      guard();if (active) throw fail('command_concurrent_request');lease.drained = true;
      const other = [...leases].some(row => row !== lease && !row.finished);
      return other ? { status: 'completed', method: 'macos_nested_leaf_commands_quiesced', terminal: false } : terminalDrain();
    },
    async finish() {
      guard();if (!lease.drained) throw fail('command_macos_terminal_order_invalid');
      lease.finished = true;
      if ([...leases].some(row => !row.finished)) return { status: 'completed', method: 'macos_nested_session_returned', terminal: false };
      await terminalDrain();return request('finish');
    }
  });
}
async function operation(message) {
  const descriptor = message.descriptor;
  scope = message.scope;deadline = BigInt(message.deadline_ns);guard();
  if (!require('./macos-command-scope').validateCommandScope(scope) ||
      JSON.stringify(scope.binding.descriptor) !== JSON.stringify(descriptor) ||
      descriptor.protected_worker_root !== path.resolve(__dirname, '../..')) throw fail('command_macos_worker_binding_invalid');
  const env = configuredEnvironment(message.environment, descriptor);
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, env);process.chdir(descriptor.writable_root);
  const runtime = { budgets: message.budgets, onProgress: progress,
    workDeadline: Number(deadline) / 1e6 };
  runtime.macosRemote = Object.freeze({ createSession: () => createSession(runtime), run: (command, options) => execute(command, runtime, options),
    async preflightTeamLock(context) {
      const old = require('./macos-lock-preflight').readTeamFlowScope(contextSafe(context, descriptor));
      if (!old) return;
      const answer = await request('observe_scope', { scope: old });guard();
      if (answer.status !== 'completed') throw fail(answer.status === 'active' ? 'lock_execution_scope_active' : 'lock_execution_scope_unconfirmed');
      require('./command-scope-proof').setMacOSTerminalObservation(old, answer.closure?.observation,
        answer.capability, answer.observation_nonce);
    }
  });
  const payload = message.payload;
  let value;
  if (message.operation === 'flow-main') value = await require('../flow').__owned.main(argvSafe(payload.argv, descriptor), runtime);
  else if (message.operation === 'flow-run') value = await require('../flow').__owned.runFlow({ ...payload.options,
    context: contextSafe(payload.options.context, descriptor) }, runtime);
  else if (message.operation === 'flow-step') value = await require('../flow').__owned.runOne(payload.command, contextSafe(payload.context, descriptor), runtime);
  else if (message.operation === 'evaluation-main') value = await require('../evaluation-harness').__owned.main(runtime);
  else if (message.operation === 'evaluation-check') value = await require('../evaluation-harness').__owned.runCheck(payload.spec, runtime);
  else if (message.operation === 'watch-main') value = await require('./watch-maintenance-worker')({ ...payload, argv: argvSafe(payload.argv, descriptor) }, runtime);
  else if (message.operation === 'macos-command') value = await execute(payload.command, runtime);
  else throw fail('command_macos_operation_unsupported');
  if (active) throw fail('command_concurrent_request');
  await terminalDrain();guard();
  await send({ type: 'result', value });process.exit(0);
}
process.on('message', async raw => {
  try {
    if (!used && raw?.type === 'start' && raw?.role === 'operation' && raw?.protocol === PROTOCOL) {
      // Before the first non-envelope package dependency. The native guardian
      // has already established this exact immutable package root.
      require('./macos-worker-envelope').install({ protectedRoot: path.resolve(__dirname, '../..') });
    }
    copyInertData ||= require('./inert-data').copyInertData;
    const message = copyInertData(raw, null, MAX_MESSAGE);
    if (message?.protocol !== PROTOCOL) throw fail('command_macos_worker_protocol');
    if (message.type === 'cleanup_epoch') {
      if (!used || message.op !== 'cleanup_epoch' || typeof message.deadline_ns !== 'string' || !/^[1-9]\d{0,31}$/.test(message.deadline_ns)) {
        throw fail('command_lifecycle_invalid');
      }
      const end = BigInt(message.deadline_ns);
      if (end <= now() || end - now() > 3600000n * 1000000n) throw fail('command_lifecycle_invalid');
      deadline = end;return;
    }
    if (message.type === 'reply') {
      const target = pending.get(message.id);
      if (!target) throw fail('command_macos_reply_invalid');pending.delete(message.id);target.resolve(message.value);return;
    }
    if (used || message.type !== 'start') throw fail('command_macos_worker_protocol');used = true;
    if (message.role === 'authority') {
      const { config, auth, deadline_ns } = message.input;deadline = BigInt(deadline_ns);guard();
      const registration = (await require('./verification-darwin-session').rpc(config,
        { op: 'register_authority', ...auth }, { limitMs: Math.max(1, Math.floor(Number(deadline - now()) / 1e6)) })).reply;
      guard();await send({ type: 'registered', registration });
      // Remain present until the native terminal sweep kills this exact birth.
      return;
    }
    if (message.role !== 'operation') throw fail('command_macos_worker_protocol');
    await operation(message);
  } catch (error) {
    const detail = { code: /^[A-Za-z0-9_-]{1,100}$/.test(error.code || '') ? error.code : 'command_macos_worker_failed' };
    for (const key of ['run_id', 'retry_of', 'team_release', 'lock_release_error', 'lock_event_error', 'finalization_error', 'record_write_status', 'record_kind']) {
      if (error[key] !== undefined) detail[key] = error[key];
    }
    await send({ type: 'error', error: detail }).catch(() => {});process.exit(1);
  }
});
