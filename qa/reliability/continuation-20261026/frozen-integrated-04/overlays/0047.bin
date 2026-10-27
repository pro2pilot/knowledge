'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const runner = require('./command-runner');
const channelAPI = require('./command-holder-channel');
const { getAgentId, ensurePhysicalRoot, ensureContainedDir } = require('./json-store');
const { parseCliArgs, resolveKnowledgeContext, contextEnv } = require('./path-context');
const { createWatcherStateStore, updateAutomationStatus: updateSharedAutomationStatus } = require('./watcher-state-store');

module.exports = async function runWatcher(payload, runtime) {
  if (!payload || !Array.isArray(payload.argv) || payload.argv.some(value => typeof value !== 'string' || value.includes('\0')) ||
      !Number.isSafeInteger(payload.controller_pid) || payload.controller_pid < 1 || !/^[a-f0-9]{16}$/.test(payload.epoch_id || '')) {
    throw Object.assign(new Error('Invalid owned watcher request'), { code: 'watcher_request_invalid' });
  }
  const policy = runner.budgets(payload.command_budgets);
  const control = channelAPI.createClient(payload.control);
  let complete, completed = false, stopMode = null, permit = null, permitSequence = 0;
  const completion = new Promise(resolve => { complete = resolve; });
  const errorRecord = (error, fallback = 'watcher_failed') => ({
    code: error.code || fallback, name: error.name || 'Error', message: error.message
  });
  const send = value => new Promise((resolve, reject) => control.send(value, error => error ? reject(error) : resolve()));
  let closePromise;
  const parsed = parseCliArgs(payload.argv);
const context = resolveKnowledgeContext(parsed.flags);
const repoRoot = context.targetRoot;
const knowledgeRoot = context.stateRoot;
const agentId = getAgentId();
const watcherId = `${agentId}-${payload.controller_pid}-${payload.epoch_id}`.replace(/[^a-zA-Z0-9_.-]/g, '_');
const watcherState = createWatcherStateStore({ stateRoot: knowledgeRoot, watcherId });
const startedAt = nowIso();
const watchedRoots = ['.'];
const debounceMs = Number(process.env.KNOWLEDGE_WATCH_DEBOUNCE_MS || 1500);
const watcherStaleMs = Number(process.env.KNOWLEDGE_WATCHER_STALE_MS || 120000);
const heartbeatMs = Number(process.env.KNOWLEDGE_WATCH_HEARTBEAT_MS || 30000);
for (const [name, value] of Object.entries({ debounceMs, watcherStaleMs, heartbeatMs })) {
  if (!Number.isInteger(value) || value <= 0 || value > 2147483647) throw new Error(`${name} must be a positive timer interval`);
}
const ignoredSegments = ['.git', 'node_modules', '.claude', '.agents', '.opencode', '.vercel', '.knowledge', '.knowledge', '.next', '.turbo', '.cache', '.pytest_cache', '.mypy_cache', '.venv', 'venv', 'dist', 'build', 'coverage', 'target', 'bin', 'obj', 'dist-release', 'dist-installer', 'dist-release-fresh', 'runtime-seed', 'comfy_models', 'comfy_input', 'comfy_output', 'comfy_custom_nodes'];

const touched = new Set();
const watchers = [];
const watchedDirectories = new Set();
let timer = null;
let heartbeat = null;
let running = false;
let shuttingDown = false;
let activeSync = null, activeAbort = null;
let shutdownFailure = null, syncInterrupted = false;
let watcherFailure = null;
let aggregatePublished = false;

function nowIso() { return new Date().toISOString(); }
function normalizeRel(value) { return String(value || '').replace(/\\/g, '/').replace(/^\.\//, ''); }
function shouldIgnore(relative) {
  const normalized = normalizeRel(relative);
  if (normalized.split('/').some((part) => part.startsWith('.tmp-'))) return true;
  const absolute = path.resolve(repoRoot, normalized);
  if ([context.stateRoot, context.projectKnowledgeRoot, context.systemRoot].some((root) => {
    if (!root || path.resolve(root) === repoRoot) return false;
    const rel = path.relative(path.resolve(root), absolute);
    return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel));
  })) return true;
  return ignoredSegments.some((seg) => normalized.split('/').includes(seg));
}
function limitArray(items, max) { return items.length > max ? items.slice(items.length - max) : items; }
function isWatcherStale(watcher) {
  if (!watcher || !watcher.last_seen_at) return false;
  const ts = Date.parse(watcher.last_seen_at);
  return Number.isFinite(ts) && Date.now() - ts > watcherStaleMs;
}

function assertWatcherSlot(current, stopping) {
  const slots = current.active_watchers || {};
  if (stopping && aggregatePublished && !Object.hasOwn(slots, watcherId)) {
    throw Object.assign(new Error('Watcher aggregate slot is missing during shutdown'), { code: 'watcher_status_ownership_lost', watcher_id: watcherId, attempt_id: watcherState.attemptId });
  }
  if (Object.hasOwn(slots, watcherId)) {
    const own = slots[watcherId];
    if (!own || own.attempt_id !== watcherState.attemptId || own.pid !== payload.controller_pid || own.agent_id !== agentId || own.hostname !== os.hostname()) {
      throw Object.assign(new Error('Watcher aggregate slot belongs to another attempt'), { code: 'watcher_status_ownership_lost', watcher_id: watcherId, attempt_id: watcherState.attemptId });
    }
  }
}

function updateAutomationStatus(extra = {}, stopping = false) {
  const assertAuthority = stopping && shuttingDown ? watcherState.assertScope : watcherState.assertOwned;
  const published = updateSharedAutomationStatus(context, current => {
    const activeWatchers = { ...(current.active_watchers || {}) };
    for (const [id, watcher] of Object.entries(activeWatchers)) {
      if (id !== watcherId && (watcher.running === false || isWatcherStale(watcher))) delete activeWatchers[id];
    }
    activeWatchers[watcherId] = {
      attempt_id: watcherState.attemptId,
      agent_id: agentId,
      pid: payload.controller_pid,
      worker_pid: process.pid,
      hostname: os.hostname(),
      running: !shuttingDown,
      started_at: startedAt,
      last_seen_at: nowIso(),
      watched_roots: watchedRoots
    };
    return {
      ...current,
      mode: 'event-driven',
      concurrent_safe: true,
      hooks_installed: current.hooks_installed ?? false,
      watcher_supported: true,
      watcher_running: Object.values(activeWatchers).some((watcher) => watcher.running && !isWatcherStale(watcher)),
      watcher_last_seen_at: nowIso(),
      last_trigger_source: current.last_trigger_source || 'watcher',
      automation_health: current.automation_health || 'healthy',
      watched_roots: watchedRoots,
      ignored_segments: ignoredSegments,
      active_watchers: activeWatchers,
      watcher_stale_ms: watcherStaleMs,
      ...extra
    };
  }, { assertAuthority, validate: current => assertWatcherSlot(current, stopping) });
  aggregatePublished = true;
  return published;
}

function writeWatcherState(extra = {}) {
  return watcherState.write(watcherPayload(extra));
}

function watcherPayload(extra = {}) {
  return {
    agent_id: agentId,
    pid: payload.controller_pid,
    worker_pid: process.pid,
    hostname: os.hostname(),
    started_at: startedAt,
    last_seen_at: nowIso(),
    running: !shuttingDown,
    touched_pending: touched.size,
    ...extra
  };
}

async function requestPermit() {
  if (shuttingDown || permit) throw Object.assign(new Error('Watcher admission is closed'), { code: 'watcher_admission_closed' });
  const id = ++permitSequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (permit?.id !== id) return;
      permit = null;
      reject(Object.assign(new Error('Watcher command admission expired'), { code: 'watcher_admission_timeout' }));
    }, policy.setupMs);
    permit = { id, timer, resolve, reject };
    control.send({ type: 'sync_request', id }, error => {
      if (error && permit?.id === id) { clearTimeout(timer);permit = null;reject(error); }
    });
  });
}
function triggerSync(fullScan = false) {
  if (running || shuttingDown) return;
  running = true;
  const changed = Array.from(touched);
  touched.clear();
  activeAbort = new AbortController();
  activeSync = (async () => {
    const admittedUntil = await requestPermit();
    if (shuttingDown || activeAbort.signal.aborted || process.hrtime.bigint() >= admittedUntil) {
      throw Object.assign(new Error('Watcher command admission closed'), { code: 'watcher_admission_closed' });
    }
    updateAutomationStatus({ last_trigger_source: 'watcher', last_changed_files: changed, last_sync_started_at: nowIso(), last_agent_id: agentId });
    writeWatcherState({ last_sync_started_at: nowIso(), last_changed_files: changed });
    if (shuttingDown || activeAbort.signal.aborted || process.hrtime.bigint() >= admittedUntil) {
      throw Object.assign(new Error('Watcher command admission expired before execution'), { code: 'watcher_admission_timeout' });
    }
    const result = await runner.runOwnedCommand({
      executable: process.execPath, args: [path.join(context.systemRoot, 'tools', 'sync-tracked.js'), ...(fullScan ? ['--scan'] : [])], cwd: repoRoot,
      env: { ...contextEnv(context), KNOWLEDGE_AGENT_ID: agentId, KNOWLEDGE_TRIGGER: 'watcher', KNOWLEDGE_CHANGED_FILES: JSON.stringify(changed) }
    }, { ...runtime, signal: activeAbort.signal, budgets: policy });
    if (result.cleanup?.status !== 'completed') {
      throw Object.assign(new Error('Watcher sync descendants were not confirmed stopped'), { code: 'watcher_sync_cleanup_unconfirmed', cleanup: result.cleanup });
    }
    if (shuttingDown) return result;
    const success = result.status === 0 && !result.signal && !result.error;
    updateAutomationStatus({
      last_trigger_source: 'watcher', last_watch_changed_files: changed, last_watch_sync_watcher_id: watcherId,
      ...(success ? { last_auto_maintenance_at: nowIso() } : {}),
      last_sync_finished_at: nowIso(), last_sync_exit_code: result.status,
      last_sync_signal: result.signal || null,
      last_sync_error: result.error?.message || (result.signal ? 'sync terminated by ' + result.signal : result.status !== 0 ? 'sync exited ' + result.status : null),
      automation_health: success ? 'healthy' : 'degraded_watcher_sync_error', last_agent_id: agentId,
      last_sync_cleanup: result.cleanup
    });
    writeWatcherState({ last_sync_finished_at: nowIso(), last_sync_exit_code: result.status, last_sync_signal: result.signal || null,
      last_sync_error: result.error?.message || null, last_sync_cleanup: result.cleanup });
    return result;
  })();
  activeSync.then(() => {
    running = false;
    if (!shuttingDown) { activeSync = null;activeAbort = null;if (touched.size > 0) schedule(); }
  }, error => {
    running = false;
    if (!shuttingDown) { activeSync = null;activeAbort = null;failWatcher(error); }
  });
}

function schedule() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => { try { triggerSync(); } catch (error) { failWatcher(error); } }, debounceMs);
}

function recordEvent(absPath) {
  const relative = normalizeRel(path.relative(repoRoot, absPath));
  if (!relative || relative.startsWith('..') || shouldIgnore(relative)) return;
  touched.add(relative);
  updateAutomationStatus({ last_event_path: relative, last_trigger_source: 'watcher_event', last_agent_id: agentId, last_event_at: nowIso() });
  writeWatcherState({ last_event_path: relative });
  schedule();
}

function watchDirectoryRecursiveFallback(root) {
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    if (watchedDirectories.has(current)) continue;
    let entries = [];
    try { entries = fs.readdirSync(current, { withFileTypes: true }); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    try {
      const watcher = fs.watch(current, (_eventType, filename) => {
        if (!filename) return;
        const abs = path.join(current, filename.toString());
        try {
          recordEvent(abs);
          if (fs.existsSync(abs) && fs.lstatSync(abs).isDirectory() && !shouldIgnore(path.relative(repoRoot, abs))) watchDirectoryRecursiveFallback(abs);
        } catch (error) { if (error.code !== 'ENOENT') failWatcher(error); }
      });
      watchers.push(watcher);
      watchedDirectories.add(current);
      watcher.on('error', failWatcher);
      watcher.on('close', () => watchedDirectories.delete(current));
    } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const abs = path.join(current, entry.name);
      const relative = normalizeRel(path.relative(repoRoot, abs));
      if (!shouldIgnore(relative)) stack.push(abs);
    }
  }
}

function watchRoot(root) {
  const abs = path.join(repoRoot, root);
  if (!fs.existsSync(abs)) return;
  // Native recursive watchers traverse excluded runtime trees before our
  // event filter runs. Transient lock releases can make that traversal fail.
  // Subscribe only to selected source directories on every platform.
  watchDirectoryRecursiveFallback(abs);
}

async function shutdown(mode, failure) {
  if (closePromise) {
    // Cancellation may supersede a planned rollover while its already-admitted
    // sync is still running. Do not wait for the original work deadline.
    if (mode !== 'rollover' && stopMode === 'rollover') {
      stopMode = mode;syncInterrupted ||= running;activeAbort?.abort();
    }
    return closePromise;
  }
  shuttingDown = true;stopMode = mode;
  if (timer) clearTimeout(timer);
  if (heartbeat) clearInterval(heartbeat);
  for (const watcher of watchers) { try { watcher.close(); } catch {} }
  if (permit) { clearTimeout(permit.timer);permit.reject(Object.assign(new Error('Watcher admission closed'), { code: 'watcher_admission_closed' }));permit = null; }
  syncInterrupted = running && mode !== 'rollover';
  if (mode !== 'rollover') activeAbort?.abort();
  closePromise = (async () => {
    let code = failure ? 1 : 0;
    let syncResult;
    if (activeSync) {
      try { syncResult = await activeSync; }
      catch (error) { if (!['watcher_admission_closed', 'command_cancelled'].includes(error.code)) { failure ||= error;code = 1; } }
    }
    // Native command drain precedes all durable stop writes. This process may
    // block on storage, but its disk-free owner can stop the entire native
    // tree within the original cleanup allowance.
    let stateFailure = null;
    try { watcherState.assertOwned(); }
    catch (error) { stateFailure = error;shutdownFailure ||= error;code = 1; }
    try {
      updateAutomationStatus({
        last_trigger_source: 'watcher_stop', last_agent_id: agentId, watcher_last_seen_at: nowIso(),
        ...(syncResult?.cleanup ? { last_sync_cleanup: syncResult.cleanup } : {}),
        ...(failure || stateFailure ? { automation_health: 'degraded_watcher_error', last_watcher_error: (failure || stateFailure).message } : {}),
        ...(syncInterrupted ? { ...(!failure && !stateFailure ? { automation_health: 'degraded_watcher_sync_interrupted' } : {}),
          last_sync_error: 'Owned sync interrupted during watcher shutdown' } : {})
      }, true);
    } catch (error) { shutdownFailure ||= error;code = 1; }
    try { watcherState.remove(); } catch (error) { shutdownFailure ||= error;code = 1; }
    const error = failure || shutdownFailure;
    const value = { status: code ? 'failed' : stopMode === 'rollover' ? 'rolled_over' : 'stopped',
      watcher_id: watcherId, controller_pid: payload.controller_pid, epoch_id: payload.epoch_id,
      durable_stop_confirmed: code === 0, sync_interrupted: syncInterrupted,
      ...(syncResult?.cleanup ? { sync_cleanup: syncResult.cleanup } : {}),
      ...(error ? { error: errorRecord(error) } : {}),
      ...(shutdownFailure ? { shutdown_error: errorRecord(shutdownFailure, 'watcher_shutdown_failed') } : {}) };
    try { await send({ type: 'finished', status: value.status }); }
    catch (error) { value.status = 'failed';value.durable_stop_confirmed = false;value.error ||= errorRecord(error, 'watcher_control_closed'); }
    if (!completed) { completed = true;complete(value); }
    control.close();
    return value;
  })();
  return closePromise;
}
function failWatcher(error) {
  if (shuttingDown) return;
  watcherFailure ||= error;
  // Do not write project state before issuing native cancellation.
  shutdown('failure', error).catch(cause => { if (!completed) { completed = true;complete({ status: 'failed', durable_stop_confirmed: false,
    error: errorRecord(cause, 'watcher_shutdown_failed') }); } });
}
control.on('message', message => {
  if (message?.type === 'stop' && ['cancelled', 'rollover'].includes(message.mode)) {
    shutdown(message.mode).catch(failWatcher);return;
  }
  if (message?.type === 'permit' && permit?.id === message.id && typeof message.deadline_ns === 'string' && /^[1-9]\d{0,31}$/.test(message.deadline_ns)) {
    const pending = permit;permit = null;clearTimeout(pending.timer);
    const deadline = BigInt(message.deadline_ns);
    if (shuttingDown || deadline <= process.hrtime.bigint()) pending.reject(Object.assign(new Error('Watcher admission expired'), { code: 'watcher_admission_closed' }));
    else pending.resolve(deadline);
    return;
  }
  if (message?.type === 'denied' && permit?.id === message.id) {
    const pending = permit;permit = null;clearTimeout(pending.timer);
    pending.reject(Object.assign(new Error('Watcher admission closed'), { code: 'watcher_admission_closed' }));return;
  }
  failWatcher(Object.assign(new Error('Invalid watcher control message'), { code: 'watcher_control_invalid' }));
});
control.on('disconnect', () => { if (!completed) failWatcher(Object.assign(new Error('Watcher controller disconnected'), { code: 'watcher_control_closed' })); });
try {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Object.assign(new Error('Watcher control setup expired'), { code: 'watcher_control_timeout' })), policy.setupMs);
    const connected = () => { clearTimeout(timer);resolve(); };
    control.once('connected', connected);
    control.once('disconnect', () => { clearTimeout(timer);reject(Object.assign(new Error('Watcher control setup closed'), { code: 'watcher_control_closed' })); });
    if (control.connected) connected();
  });
  if (shuttingDown) return completion;
  ensurePhysicalRoot(knowledgeRoot);
  ensureContainedDir(knowledgeRoot, path.join(knowledgeRoot, 'maintenance'));
  watcherState.initialize(watcherPayload());
  for (const root of watchedRoots) watchRoot(root);
  if (watchers.length === 0) throw new Error('No source directories could be watched.');
  updateAutomationStatus({ started_at: startedAt, last_trigger_source: 'watcher_start' });
  await send({ type: 'ready', watcher_id: watcherId, controller_pid: payload.controller_pid });
  if (payload.resume_scan === true && !shuttingDown) triggerSync(true);
  heartbeat = setInterval(() => {
    if (!shuttingDown) {
      try { updateAutomationStatus({ last_trigger_source: 'watcher_heartbeat', last_agent_id: agentId });writeWatcherState({ heartbeat_at: nowIso(), touched_pending: touched.size }); }
      catch (error) { failWatcher(error); }
    }
  }, heartbeatMs);
} catch (error) { failWatcher(error); }
return completion;
};

