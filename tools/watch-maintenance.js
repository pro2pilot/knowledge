#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');

const repoRoot = path.resolve(__dirname, '..', '..');
const knowledgeRoot = path.resolve(__dirname, '..');
const lockDir = path.join(knowledgeRoot, '.lock');
const automationStatusPath = path.join(knowledgeRoot, 'maintenance', 'automation_status.json');
const runtimeRoot = path.join(knowledgeRoot, '.runtime');
const watchersDir = path.join(runtimeRoot, 'watchers');
const agentId = getAgentId();
const watcherId = `${agentId}-${process.pid}`.replace(/[^a-zA-Z0-9_.-]/g, '_');
const watcherStatePath = path.join(watchersDir, `${watcherId}.json`);
const watchedRoots = ['.'];
const debounceMs = Number(process.env.KNOWLEDGE_WATCH_DEBOUNCE_MS || 1500);
const watcherStaleMs = Number(process.env.KNOWLEDGE_WATCHER_STALE_MS || 120000);
const ignoredSegments = ['.git', 'node_modules', '.claude', '.agents', '.opencode', '.vercel', '.knowledge', '.knowledge', '.next', '.turbo', '.cache', '.pytest_cache', '.mypy_cache', '.venv', 'venv', 'dist', 'build', 'coverage', 'target', 'bin', 'obj', 'dist-release', 'dist-installer', 'dist-release-fresh', 'runtime-seed', 'comfy_models', 'comfy_input', 'comfy_output', 'comfy_custom_nodes'];

const touched = new Set();
const watchers = [];
let timer = null;
let running = false;
let shuttingDown = false;

function nowIso() { return new Date().toISOString(); }
function normalizeRel(value) { return String(value || '').replace(/\\/g, '/').replace(/^\.\//, ''); }
function shouldIgnore(relative) {
  const normalized = normalizeRel(relative);
  if (normalized.split('/').some((part) => part.startsWith('.tmp-'))) return true;
  return ignoredSegments.some((seg) => normalized.split('/').includes(seg));
}
function limitArray(items, max) { return items.length > max ? items.slice(items.length - max) : items; }
function isWatcherStale(watcher) {
  if (!watcher || !watcher.last_seen_at) return false;
  const ts = Date.parse(watcher.last_seen_at);
  return Number.isFinite(ts) && Date.now() - ts > watcherStaleMs;
}

function updateAutomationStatus(extra = {}) {
  return withLock(lockDir, () => {
    const current = readJson(automationStatusPath, { mode: 'event-driven' });
    const activeWatchers = current.active_watchers || {};
    for (const [id, watcher] of Object.entries(activeWatchers)) {
      if (id !== watcherId && (watcher.running === false || isWatcherStale(watcher))) delete activeWatchers[id];
    }
    activeWatchers[watcherId] = {
      agent_id: agentId,
      pid: process.pid,
      hostname: os.hostname(),
      running: !shuttingDown,
      started_at: activeWatchers[watcherId]?.started_at || nowIso(),
      last_seen_at: nowIso(),
      watched_roots: watchedRoots
    };
    const payload = {
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
    writeJsonAtomic(automationStatusPath, payload);
    return payload;
  }, { timeoutMs: 10000 });
}

function writeWatcherState(extra = {}) {
  ensureDir(watchersDir);
  writeJsonAtomic(watcherStatePath, {
    watcher_id: watcherId,
    agent_id: agentId,
    pid: process.pid,
    hostname: os.hostname(),
    started_at: extra.started_at || undefined,
    last_seen_at: nowIso(),
    running: !shuttingDown,
    touched_pending: touched.size,
    ...extra
  });
}

function triggerSync() {
  if (running || shuttingDown) return;
  running = true;
  const changed = Array.from(touched);
  touched.clear();
  updateAutomationStatus({ last_trigger_source: 'watcher', last_changed_files: changed, last_sync_started_at: nowIso(), last_agent_id: agentId });
  writeWatcherState({ last_sync_started_at: nowIso(), last_changed_files: changed });

  const child = spawn(process.execPath, [path.join(knowledgeRoot, 'tools', 'sync-tracked.js')], {
    cwd: repoRoot,
    env: { ...process.env, KNOWLEDGE_AGENT_ID: agentId, KNOWLEDGE_TRIGGER: 'watcher', KNOWLEDGE_CHANGED_FILES: JSON.stringify(changed) },
    stdio: 'ignore',
    windowsHide: true
  });

  child.on('error', (error) => {
    running = false;
    updateAutomationStatus({
      last_trigger_source: 'watcher',
      last_sync_finished_at: nowIso(),
      last_sync_error: error.message,
      automation_health: 'degraded_watcher_sync_error',
      last_agent_id: agentId
    });
    writeWatcherState({ last_sync_finished_at: nowIso(), last_sync_error: error.message });
    if (touched.size > 0) schedule();
  });

  child.on('exit', (code) => {
    running = false;
    updateAutomationStatus({
      last_trigger_source: 'watcher',
      last_auto_maintenance_at: nowIso(),
      last_sync_finished_at: nowIso(),
      last_sync_exit_code: code,
      automation_health: code === 0 ? 'healthy' : 'degraded_watcher_sync_error',
      last_agent_id: agentId
    });
    writeWatcherState({ last_sync_finished_at: nowIso(), last_sync_exit_code: code });
    if (touched.size > 0) schedule();
  });
}

function schedule() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(triggerSync, debounceMs);
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
    let entries = [];
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { continue; }
    try {
      const watcher = fs.watch(current, (_eventType, filename) => {
        if (!filename) return;
        const abs = path.join(current, filename.toString());
        recordEvent(abs);
        try {
          if (fs.existsSync(abs) && fs.statSync(abs).isDirectory() && !shouldIgnore(path.relative(repoRoot, abs))) watchDirectoryRecursiveFallback(abs);
        } catch {}
      });
      watchers.push(watcher);
    } catch {}
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
  try {
    const watcher = fs.watch(abs, { recursive: true }, (_eventType, filename) => {
      if (!filename) return;
      recordEvent(path.join(abs, filename.toString()));
    });
    watchers.push(watcher);
  } catch {
    watchDirectoryRecursiveFallback(abs);
  }
}

function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  if (timer) clearTimeout(timer);
  for (const watcher of watchers) {
    try { watcher.close(); } catch {}
  }
  try {
    updateAutomationStatus({
      last_trigger_source: 'watcher_stop',
      last_agent_id: agentId,
      watcher_last_seen_at: nowIso()
    });
  } catch {}
  try { writeWatcherState({ stopped_at: nowIso(), running: false }); } catch {}
  try { fs.unlinkSync(watcherStatePath); } catch {}
}

process.on('SIGINT', () => { shutdown(); process.exit(0); });
process.on('SIGTERM', () => { shutdown(); process.exit(0); });
process.on('exit', shutdown);

ensureDir(path.join(knowledgeRoot, 'maintenance'));
ensureDir(watchersDir);
writeWatcherState({ started_at: nowIso() });
for (const root of watchedRoots) watchRoot(root);
updateAutomationStatus({ started_at: nowIso(), last_trigger_source: 'watcher_start', last_agent_id: agentId });
setInterval(() => {
  if (!shuttingDown) {
    updateAutomationStatus({ last_trigger_source: 'watcher_heartbeat', last_agent_id: agentId });
    writeWatcherState({ heartbeat_at: nowIso(), touched_pending: touched.size });
  }
}, Number(process.env.KNOWLEDGE_WATCH_HEARTBEAT_MS || 30000));
