'use strict';

// Deterministic controller contract tests. Native ownership is deliberately
// modeled here; reliability-watcher-native.test.js is the physical OS gate.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const { EventEmitter } = require('node:events');
const actualRunner = require('../tools/lib/command-runner');
const parseCliArgs = require('../tools/lib/path-context').parseCliArgs;
const sourceFile = path.resolve(__dirname, '../tools/watch-maintenance.js');
const small = { setupMs: 20, workMs: 20, cleanupMs: 90, progressMs: 0 };
const good = status => ({ value: { status, durable_stop_confirmed: true }, cleanup: { status: 'completed', active_processes: 0, output_closed: true } });
function controller(run) {
  const trace = [], servers = [], proc = new EventEmitter();
  Object.assign(proc, { pid: process.pid, env: {}, hrtime: process.hrtime, argv: [] });
  const runner = { budgets: actualRunner.budgets, cliBudgets: () => actualRunner.budgets(), async runOwnedOperation(name, payload, options) {
    const channel = servers.at(-1), index = trace.filter(row => row.type === 'run').length;
    trace.push({ type: 'run', name, payload, options, index });
    return run({ channel, index, trace, payload, options, ready() {
      channel.connected = true;channel.emit('connected');
      channel.emit('message', { type: 'ready', controller_pid: process.pid, watcher_id: 'model-' + index });
    } });
  } };
  const channels = { async createServer() {
    const channel = new EventEmitter();channel.arguments = ['--holder-channel', '12345', 'a'.repeat(64)];
    channel.send = (value, callback) => { trace.push({ type: 'send', value });channel.onSend?.(value);callback?.(); };
    channel.close = () => { channel.connected = false;trace.push({ type: 'closed' }); };
    servers.push(channel);return channel;
  } };
  const module = { exports: {} };
  const load = name => name === './lib/command-runner' ? runner : name === './lib/command-holder-channel' ? channels :
    name === './lib/path-context' ? { parseCliArgs } : require(name);
  vm.runInNewContext(fs.readFileSync(sourceFile, 'utf8'), {
    require: load, module, exports: module.exports, process: proc, console, Buffer, AbortController,
    setTimeout, clearTimeout
  }, { filename: sourceFile });
  return { ...module.exports, trace, servers, proc };
}

test('watch policy retains original per-sync budgets and gives pre-start publication its own bounded allowance', () => {
  const c = controller(() => { throw new Error('not called'); }), value = c.watchPolicy({});
  assert.equal(JSON.stringify(value.command), JSON.stringify(actualRunner.budgets()));
  assert.equal(value.epochMs, 86400000);
  assert.equal(value.commandAllowance, value.command.setupMs * 2 + value.command.workMs + value.command.cleanupMs);
  for (const epochMs of [1, NaN, Infinity, 0, '1.5', 2147483647]) {
    assert.throws(() => c.watchPolicy({}, { epochMs }), error => error.code === 'watcher_epoch_budget_invalid');
  }
});

test('help and already-cancelled invocation create no native scope or control listener', async () => {
  const c = controller(() => { throw new Error('unrequested admission'); });
  assert.equal((await c.main(['--help'])).status, 'help');
  const signal = new AbortController();signal.abort();
  const value = await c.main([], { signal: signal.signal });
  assert.equal(value.cleanup.method, 'no_scope_admitted');assert.equal(c.servers.length, 0);
  assert.equal(c.proc.eventNames().length, 0);
});

test('stop closes admission and begins the same cleanup epoch before asking the worker to write stopped state', async () => {
  const abort = new AbortController();let payload;
  const c = controller(({ channel, ready, options, payload: request, trace }) => new Promise(resolve => {
    payload = request;
    options.subscribeLifecycle(event => trace.push({ type: 'cleanup_epoch', event }));
    channel.onSend = message => {
      if (message.type === 'stop') {
        channel.emit('message', { type: 'sync_request', id: 1 });
        queueMicrotask(() => resolve(good('stopped')));
      }
    };
    ready();
  }));
  const result = await c.main([], { budgets: small, signal: abort.signal, onReady() { abort.abort(); } });
  assert.equal(result.status, 'stopped');
  assert.equal(c.trace.filter(row => row.type === 'cleanup_epoch').length, 1);
  assert(c.trace.findIndex(row => row.type === 'cleanup_epoch') < c.trace.findIndex(row => row.type === 'send' && row.value.type === 'stop'));
  assert(!c.trace.some(row => row.type === 'send' && row.value.type === 'permit'));
  assert(c.trace.some(row => row.type === 'send' && row.value.type === 'denied'));
  assert.equal(JSON.stringify(payload.command_budgets), JSON.stringify(actualRunner.budgets(small)));
  assert.equal(c.proc.eventNames().length, 0);
});

test('a stalled worker cannot postpone independent native cancellation beyond the one cleanup allowance', async () => {
  const abort = new AbortController();let stoppedAt;
  const c = controller(({ ready, options, trace }) => new Promise((resolve, reject) => {
    options.subscribeLifecycle(event => { stoppedAt = performance.now();trace.push({ type: 'cleanup_epoch', event }); });
    options.signal.addEventListener('abort', () => reject(Object.assign(new Error('modeled native drain after independent stop'), {
      code: 'command_cancelled', cleanup: good('stopped').cleanup
    })), { once: true });
    ready();
  }));
  await assert.rejects(c.main([], { budgets: small, signal: abort.signal, onReady() { abort.abort(); } }),
    error => error.code === 'command_cancelled' && error.cleanup.status === 'completed');
  const elapsed = performance.now() - stoppedAt;
  assert(elapsed >= small.cleanupMs - Math.floor(small.cleanupMs / 3) - 10);
  assert(elapsed < small.cleanupMs + 250, 'The deadline is never reset by an unresponsive worker');
  assert.equal(c.trace.filter(row => row.type === 'cleanup_epoch').length, 1);
});

for (const invalid of [
  { label: 'durable state stop', result: { ...good('stopped'), value: { status: 'stopped', durable_stop_confirmed: false } } },
  { label: 'native descendant drain', result: { ...good('stopped'), cleanup: { status: 'unconfirmed' } } }
]) test('successful daemon exit requires independently confirmed ' + invalid.label, async () => {
  const c = controller(() => invalid.result);
  await assert.rejects(c.main([], { budgets: small }), error => error.code === 'watcher_stop_unconfirmed');
  assert.equal(c.trace.filter(row => row.type === 'run').length, 1);
});

test('epoch renewal waits for complete old scope and requests a full rescan for the subscription gap', async () => {
  const abort = new AbortController();let previousCompleted = false;
  const c = controller(({ channel, ready, index, options }) => new Promise(resolve => {
    if (index) assert.equal(previousCompleted, true);
    options.subscribeLifecycle(() => {});
    channel.onSend = message => {
      if (message.type !== 'stop') return;
      if (!index) {
        assert.equal(message.mode, 'rollover');
        setTimeout(() => { previousCompleted = true;resolve(good('rolled_over')); }, 5);
      } else resolve(good('stopped'));
    };
    ready();
  }));
  const epochMs = small.setupMs * 2 + small.workMs + small.cleanupMs + 1001;
  const result = await c.main([], { budgets: small, epochMs, signal: abort.signal, onReady() {
    if (c.trace.filter(row => row.type === 'run').length === 2) abort.abort();
  } });
  assert.equal(result.completed_epochs, 2);
  assert.equal(c.trace.filter(row => row.type === 'run').map(row => row.payload.resume_scan).join(','), 'false,true');
});

test('observer callback failure drains native owner instead of escaping the event handler', async () => {
  const c = controller(({ ready, options }) => new Promise((resolve, reject) => {
    options.subscribeLifecycle(() => {});
    options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {
      code: 'command_cancelled', cleanup: good('stopped').cleanup
    })), { once: true });
    ready();
  }));
  await assert.rejects(c.main([], { budgets: small, onReady() { throw new Error('fixture observer'); } }),
    error => error.code === 'watcher_ready_callback_failed' && error.cleanup.status === 'completed');
});

test('unexplained control-channel loss aborts the native owner and cannot renew', async () => {
  const c = controller(({ channel, ready, options }) => new Promise((resolve, reject) => {
    options.subscribeLifecycle(() => {});
    options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {
      code: 'command_cancelled', cleanup: good('stopped').cleanup
    })), { once: true });
    ready();channel.emit('disconnect');
  }));
  await assert.rejects(c.main([], { budgets: small }), error => error.code === 'watcher_control_closed' && error.cleanup.status === 'completed');
  assert.equal(c.trace.filter(row => row.type === 'run').length, 1);
});

function modeledWorker(runCommand, options = {}) {
  const trace = [], watchHandles = [], calls = [], control = new EventEmitter();
  let now = 1000000000000n, aggregate = {}, initialized = false, removed = false, readyResolve;
  const ready = new Promise(resolve => { readyResolve = resolve; });
  const roots = { targetRoot: path.resolve('/model-repo'), stateRoot: path.resolve('/model-state'),
    systemRoot: path.resolve('/model-runtime'), projectKnowledgeRoot: path.resolve('/model-repo/.knowledge') };
  const store = { attemptId: 'a'.repeat(32),
    initialize() { initialized = true;trace.push('initialize'); },
    assertOwned() { if (!initialized || removed) throw new Error('model ownership lost'); },
    assertScope() { if (!initialized) throw new Error('model scope absent'); },
    write() { trace.push('state_write'); },
    remove() { removed = true;trace.push('state_remove'); } };
  const modelFs = {
    existsSync() { return true; }, readdirSync() { return []; },
    lstatSync() { return { isDirectory: () => false }; },
    watch() {
      if (options.watchFailure) throw Object.assign(new Error('modeled watch denied'), { code: 'EACCES' });
      const handle = new EventEmitter();handle.close = () => { handle.emit('close');trace.push('watch_close'); };
      watchHandles.push(handle);return handle;
    }
  };
  // fs.watch supplies the callback, not an EventEmitter 'change' listener.
  const watch = modelFs.watch;
  modelFs.watch = function(directory, callback) { const handle = watch(directory);handle.sourceEvent = callback;return handle; };
  const stateModule = { createWatcherStateStore: () => store, updateAutomationStatus(context, update, guards) {
    guards.assertAuthority();guards.validate(aggregate);
    const next = update(aggregate);
    trace.push(next.last_trigger_source);
    if (options.expireDuringStart && next.last_trigger_source === 'watcher') now += 1000000000n;
    aggregate = next;return next;
  } };
  const modelRunner = { budgets: actualRunner.budgets, async runOwnedCommand(command, settings) {
    calls.push({ command, settings });trace.push('native_admitted');return runCommand(command, settings, trace);
  } };
  control.connected = true;
  control.send = (message, callback) => {
    trace.push(message.type);
    if (message.type === 'ready') readyResolve(message);
    if (message.type === 'sync_request' && !options.holdPermit) queueMicrotask(() =>
      control.emit('message', { type: 'permit', id: message.id, deadline_ns: String(now + 200000000n) }));
    callback?.();
  };
  control.close = () => { control.connected = false;control.emit('disconnect'); };
  const proc = { pid: process.pid + 1, execPath: process.execPath, hrtime: { bigint: () => now },
    env: { KNOWLEDGE_WATCH_DEBOUNCE_MS: '1', KNOWLEDGE_WATCH_HEARTBEAT_MS: '60000' } };
  const module = { exports: {} };
  const load = name => name === 'fs' ? modelFs : name === './command-runner' ? modelRunner :
    name === './command-holder-channel' ? { createClient: () => control } :
    name === './json-store' ? { getAgentId: () => 'model-agent', ensurePhysicalRoot() {}, ensureContainedDir() {} } :
    name === './path-context' ? { parseCliArgs, resolveKnowledgeContext: () => roots, contextEnv: () => ({}) } :
    name === './watcher-state-store' ? stateModule : require(name);
  const file = path.resolve(__dirname, '../tools/lib/watch-maintenance-worker.js');
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), { require: load, module, exports: module.exports,
    process: proc, console, AbortController, setTimeout, clearTimeout, setInterval, clearInterval }, { filename: file });
  const completed = module.exports({ argv: [], controller_pid: process.pid, epoch_id: 'a'.repeat(16),
    command_budgets: { workMs: 1000, setupMs: 200, cleanupMs: 200 }, control: [], resume_scan: !!options.resumeScan }, {});
  return { trace, calls, ready, completed, state: () => aggregate, removed: () => removed,
    event() { watchHandles[0].sourceEvent('change', 'source.js'); },
    stop(mode = 'cancelled') { control.emit('message', { type: 'stop', mode }); } };
}
async function modelUntil(predicate) {
  for (let index = 0; index < 100; index++) { if (predicate()) return;await new Promise(resolve => setTimeout(resolve, 2)); }
  throw new Error('Modeled worker boundary was not reached');
}
const commandDone = () => ({ status: 0, signal: null, error: null,
  cleanup: { status: 'completed', active_processes: 0, output_closed: true } });

test('owned worker waits for command drain before publishing healthy sync completion', async () => {
  let finish;
  const f = modeledWorker(() => new Promise(resolve => { finish = resolve; }));
  await f.ready;f.event();await modelUntil(() => f.calls.length === 1);
  assert.equal(f.state().last_sync_finished_at, undefined);
  finish(commandDone());await modelUntil(() => !!f.state().last_sync_finished_at);
  assert.equal(f.state().last_sync_cleanup.status, 'completed');
  f.stop();const result = await f.completed;
  assert.equal(result.status, 'stopped');assert.equal(result.durable_stop_confirmed, true);assert.equal(f.removed(), true);
});

test('owned worker cancels active sync before any durable stopped publication and waits for actual command result', async () => {
  let finish, cancelled = false;
  const f = modeledWorker((command, settings, trace) => new Promise(resolve => {
    finish = resolve;settings.signal.addEventListener('abort', () => { cancelled = true;trace.push('native_cancel'); });
  }));
  await f.ready;f.event();await modelUntil(() => f.calls.length === 1);f.stop();
  assert.equal(cancelled, true);assert.equal(f.trace.includes('watcher_stop'), false);
  finish({ ...commandDone(), status: null, error: { code: 'command_cancelled' } });
  const result = await f.completed;
  assert.equal(result.sync_interrupted, true);assert.equal(result.sync_cleanup.status, 'completed');
  assert(f.trace.indexOf('native_cancel') < f.trace.indexOf('watcher_stop'));
});

test('explicit cancellation supersedes graceful epoch rollover while a sync is running', async () => {
  let finish, cancelled = false;
  const f = modeledWorker((command, settings) => new Promise(resolve => {
    finish = resolve;settings.signal.addEventListener('abort', () => { cancelled = true; });
  }));
  await f.ready;f.event();await modelUntil(() => f.calls.length === 1);
  f.stop('rollover');assert.equal(cancelled, false);f.stop('cancelled');assert.equal(cancelled, true);
  finish({ ...commandDone(), status: null, error: { code: 'command_cancelled' } });
  const result = await f.completed;assert.equal(result.status, 'stopped');assert.equal(result.sync_interrupted, true);
});

test('renewed worker requests a full scan without waiting for a new source event', async () => {
  const f = modeledWorker(() => commandDone(), { resumeScan: true });
  await f.ready;await modelUntil(() => f.calls.length === 1 && !!f.state().last_sync_finished_at);
  assert.equal(f.calls[0].command.args.at(-1), '--scan');f.stop();
  assert.equal((await f.completed).status, 'stopped');
});

test('watch startup failure may publish its first stopped row but never claims healthy or running', async () => {
  const f = modeledWorker(() => { throw new Error('forbidden admission'); }, { watchFailure: true });
  const result = await f.completed;
  assert.equal(result.status, 'failed');assert.equal(result.error.code, 'EACCES');
  assert.equal(f.state().watcher_running, false);assert.equal(f.state().automation_health, 'degraded_watcher_error');
  assert.equal(f.calls.length, 0);assert.equal(f.removed(), true);
});

test('a pre-start state write that consumes the permit budget cannot admit a late native command', async () => {
  const f = modeledWorker(() => { throw new Error('late admission'); }, { expireDuringStart: true });
  await f.ready;f.event();const result = await f.completed;
  assert.equal(f.calls.length, 0);assert.equal(result.status, 'failed');
  assert.equal(result.error.code, 'watcher_admission_timeout');assert.equal(f.state().watcher_running, false);
});

test('stop revokes an outstanding permission request before native command admission', async () => {
  const f = modeledWorker(() => { throw new Error('forbidden admission'); }, { holdPermit: true });
  await f.ready;f.event();await modelUntil(() => f.trace.includes('sync_request'));f.stop();
  const result = await f.completed;assert.equal(result.status, 'stopped');assert.equal(f.calls.length, 0);
});

test('unconfirmed inner sync cleanup cannot publish a healthy completion or durable-success terminal', async () => {
  const f = modeledWorker(() => ({ ...commandDone(), cleanup: { status: 'unconfirmed' } }));
  await f.ready;f.event();const result = await f.completed;
  assert.equal(result.status, 'failed');assert.equal(result.error.code, 'watcher_sync_cleanup_unconfirmed');
  assert.equal(result.durable_stop_confirmed, false);assert.equal(f.state().last_sync_finished_at, undefined);
  assert.equal(f.state().automation_health, 'degraded_watcher_error');
});
