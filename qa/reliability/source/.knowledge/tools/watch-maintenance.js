#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const { getAgentId, ensurePhysicalRoot, ensureContainedDir } = require('./lib/json-store');
const { parseCliArgs, resolveKnowledgeContext, contextEnv } = require('./lib/path-context');
const { createWatcherStateStore, updateAutomationStatus: updateSharedAutomationStatus } = require('./lib/watcher-state-store');

const parsed = parseCliArgs(process.argv.slice(2));
if (parsed.flags.help) {
  console.log('Usage: node .knowledge/tools/watch-maintenance.js [--target-root PATH] [--state-root PATH] [--system-root PATH] [--project-knowledge-root PATH]');
  process.exit(0);
}
const context = resolveKnowledgeContext(parsed.flags);
const repoRoot = context.targetRoot;
const knowledgeRoot = context.stateRoot;
const agentId = getAgentId();
const watcherId = `${agentId}-${process.pid}`.replace(/[^a-zA-Z0-9_.-]/g, '_');
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
let activeChild = null;
let shutdownFailure = null;
let watcherFailure = null;

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
  if (stopping && !Object.hasOwn(slots, watcherId)) {
    throw Object.assign(new Error('Watcher aggregate slot is missing during shutdown'), { code: 'watcher_status_ownership_lost', watcher_id: watcherId, attempt_id: watcherState.attemptId });
  }
  if (Object.hasOwn(slots, watcherId)) {
    const own = slots[watcherId];
    if (!own || own.attempt_id !== watcherState.attemptId || own.pid !== process.pid || own.agent_id !== agentId || own.hostname !== os.hostname()) {
      throw Object.assign(new Error('Watcher aggregate slot belongs to another attempt'), { code: 'watcher_status_ownership_lost', watcher_id: watcherId, attempt_id: watcherState.attemptId });
    }
  }
}

function updateAutomationStatus(extra = {}, stopping = false) {
  const assertAuthority = stopping && shuttingDown ? watcherState.assertScope : watcherState.assertOwned;
  return updateSharedAutomationStatus(context, current => {
    const activeWatchers = { ...(current.active_watchers || {}) };
    for (const [id, watcher] of Object.entries(activeWatchers)) {
      if (id !== watcherId && (watcher.running === false || isWatcherStale(watcher))) delete activeWatchers[id];
    }
    activeWatchers[watcherId] = {
      attempt_id: watcherState.attemptId,
      agent_id: agentId,
      pid: process.pid,
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
}

function writeWatcherState(extra = {}) {
  return watcherState.write(watcherPayload(extra));
}

function watcherPayload(extra = {}) {
  return {
    agent_id: agentId,
    pid: process.pid,
    hostname: os.hostname(),
    started_at: startedAt,
    last_seen_at: nowIso(),
    running: !shuttingDown,
    touched_pending: touched.size,
    ...extra
  };
}

function triggerSync() {
  if (running || shuttingDown) return;
  running = true;
  const changed = Array.from(touched);
  touched.clear();
  updateAutomationStatus({ last_trigger_source: 'watcher', last_changed_files: changed, last_sync_started_at: nowIso(), last_agent_id: agentId });
  writeWatcherState({ last_sync_started_at: nowIso(), last_changed_files: changed });

  const child = spawn(process.execPath, [path.join(context.systemRoot, 'tools', 'sync-tracked.js')], {
    cwd: repoRoot,
    env: { ...contextEnv(context), KNOWLEDGE_AGENT_ID: agentId, KNOWLEDGE_TRIGGER: 'watcher', KNOWLEDGE_CHANGED_FILES: JSON.stringify(changed) },
    stdio: 'ignore',
    windowsHide: true
  });
  activeChild = child;
  let settled = false;
  function finishSync(code, signal, error) {
    if (settled) return;
    settled = true;
    if (activeChild === child) activeChild = null;
    running = false;
    if (shuttingDown) return;
    const success = code === 0 && !signal && !error;
    try {
      updateAutomationStatus({
        last_trigger_source: 'watcher',
        last_watch_changed_files: changed,
        last_watch_sync_watcher_id: watcherId,
        ...(success ? { last_auto_maintenance_at: nowIso() } : {}),
        last_sync_finished_at: nowIso(),
        last_sync_exit_code: code,
        last_sync_signal: signal || null,
        last_sync_error: error?.message || (signal ? `sync terminated by ${signal}` : code !== 0 ? `sync exited ${code}` : null),
        automation_health: success ? 'healthy' : 'degraded_watcher_sync_error',
        last_agent_id: agentId
      });
      writeWatcherState({ last_sync_finished_at: nowIso(), last_sync_exit_code: code, last_sync_signal: signal || null, last_sync_error: error?.message || null });
      if (touched.size > 0) schedule();
    } catch (failure) { failWatcher(failure); }
  }
  child.on('error', (error) => finishSync(null, null, error));
  child.on('close', (code, signal) => finishSync(code, signal, null));
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

function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  if (timer) clearTimeout(timer);
  if (heartbeat) clearInterval(heartbeat);
  for (const watcher of watchers) {
    try { watcher.close(); } catch {}
  }
  let stateFailure = null;
  try { watcherState.assertOwned(); }
  catch (error) { stateFailure = error; reportShutdownFailure(error); }
  try {
    updateAutomationStatus({
      last_trigger_source: 'watcher_stop',
      last_agent_id: agentId,
      watcher_last_seen_at: nowIso(),
      ...(watcherFailure || stateFailure ? {
        automation_health: 'degraded_watcher_error',
        last_watcher_error: (watcherFailure || stateFailure).message
      } : {}),
      ...(activeChild && activeChild.exitCode === null && activeChild.signalCode === null ? {
        ...(!watcherFailure && !stateFailure ? { automation_health: 'degraded_watcher_sync_interrupted' } : {}),
        last_sync_error: 'Owned sync interrupted during watcher shutdown'
      } : {})
    }, true);
  } catch (error) { reportShutdownFailure(error); }
  // The aggregate holds the durable stop record. An immediately deleted
  // stopped-state rewrite adds no evidence and could overwrite a successor.
  try { watcherState.remove(); } catch (error) { reportShutdownFailure(error); }
  if (activeChild && activeChild.exitCode === null && activeChild.signalCode === null) {
    try { activeChild.kill('SIGTERM'); } catch {}
  }
}

function reportShutdownFailure(error) {
  shutdownFailure ||= error;
  process.exitCode = 1;
  console.error(`Watcher shutdown failed [${error.code || error.name}]: ${error.message}`);
}

function stopAndExit(code) {
  if (shuttingDown) return;
  const child = activeChild;
  shutdown();
  if (shutdownFailure) code = 1;
  if (!child || child.exitCode !== null || child.signalCode !== null) { process.exit(code); return; }
  // Windows termination is immediate, so record an interrupted owned sync
  // honestly instead of claiming that its SIGTERM handler ran.
  const force = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 2000);
  const deadline = setTimeout(() => process.exit(1), 4000);
  child.once('close', () => { clearTimeout(force); clearTimeout(deadline); process.exit(code); });
}

function failWatcher(error) {
  if (shuttingDown) return;
  watcherFailure ||= error;
  try { updateAutomationStatus({ automation_health: 'degraded_watcher_error', last_watcher_error: error.message }); } catch {}
  console.error(`Watcher failed [${error.code || error.name}]: ${error.message}`);
  stopAndExit(1);
}

process.on('SIGINT', () => stopAndExit(0));
process.on('SIGTERM', () => stopAndExit(0));
// Only a spawning parent with an IPC channel can request this graceful stop.
// Unlike child.kill('SIGTERM'), IPC executes shutdown handlers on Windows.
process.on('message', message => { if (message?.type === 'knowledge:watch-stop') stopAndExit(0); });
process.on('disconnect', () => stopAndExit(1));
process.on('exit', shutdown);

try {
  ensurePhysicalRoot(knowledgeRoot);
  ensureContainedDir(knowledgeRoot, path.join(knowledgeRoot, 'maintenance'));
  watcherState.initialize(watcherPayload());
  for (const root of watchedRoots) watchRoot(root);
  if (watchers.length === 0) throw new Error('No source directories could be watched.');
  updateAutomationStatus({ started_at: startedAt, last_trigger_source: 'watcher_start', last_agent_id: agentId });
  heartbeat = setInterval(() => {
    if (!shuttingDown) {
      try {
        updateAutomationStatus({ last_trigger_source: 'watcher_heartbeat', last_agent_id: agentId });
        writeWatcherState({ heartbeat_at: nowIso(), touched_pending: touched.size });
      } catch (error) { failWatcher(error); }
    }
  }, heartbeatMs);
} catch (error) { failWatcher(error); }
