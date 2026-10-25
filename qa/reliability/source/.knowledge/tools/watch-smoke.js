#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext, contextEnv } = require('./lib/path-context');

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve, reject) => {
    let forced = false;
    const force = setTimeout(() => {
      forced = true;
      // Kill only the tree spawned by this smoke; a busy watcher may have an
      // owned sync child. Never report forced cleanup as a graceful PASS.
      if (process.platform === 'win32') spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: 1500, stdio: 'ignore' });
      else child.kill('SIGKILL');
    }, 4500);
    const deadline = setTimeout(() => { clearTimeout(force); reject(new Error('Watcher did not stop after smoke test.')); }, 6500);
    child.once('close', () => { clearTimeout(force); clearTimeout(deadline); if (forced) reject(new Error('Watcher required forced termination; teardown was not graceful.')); else resolve(); });
    if (child.connected) child.send({ type: 'knowledge:watch-stop' }, error => { if (error) child.kill('SIGTERM'); });
    else child.kill('SIGTERM');
  });
}

async function main() {
  const parsed = parseCliArgs(process.argv.slice(2));
  if (parsed.flags.help) {
    console.log('Usage: node .knowledge/tools/watch-smoke.js [--target-root PATH] [--state-root PATH] [--system-root PATH]');
    return;
  }
  const context = resolveKnowledgeContext({ targetRoot: process.env.KNOWLEDGE_TARGET_ROOT || process.cwd(), ...parsed.flags });
  const repoRoot = context.targetRoot;
  const watchDurationMs = Number(process.env.KNOWLEDGE_SMOKE_WATCH_MS || 4000);
  if (!Number.isInteger(watchDurationMs) || watchDurationMs <= 0 || watchDurationMs > 2147483647) {
    throw new Error('KNOWLEDGE_SMOKE_WATCH_MS must be a positive timer interval.');
  }
  const automationStatusPath = path.join(context.stateRoot, 'maintenance', 'automation_status.json');
  const probeName = `knowledge-smoke-probe-${process.pid}-${crypto.randomBytes(8).toString('hex')}.txt`;
  const probeFile = path.join(repoRoot, probeName);
  let probeCreated = false;
  let childError = null;
  let stderr = '';
  let result = null;
  const child = spawn(process.execPath, [path.join(context.systemRoot, 'tools', 'watch-maintenance.js')], {
    cwd: repoRoot,
    env: contextEnv(context),
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    windowsHide: true
  });
  child.on('error', (error) => { childError = error; });
  child.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-2000); });
  function readStatus() {
    if (childError) throw childError;
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Watcher exited before smoke completion: ${child.exitCode ?? child.signalCode}. ${stderr}`);
    try { return JSON.parse(fs.readFileSync(automationStatusPath, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return {}; throw error; }
  }
  try {
    const startupDeadline = Date.now() + 5000;
    let ready = false;
    while (Date.now() < startupDeadline) {
      const state = readStatus();
      ready = Object.values(state.active_watchers || {}).some((watcher) => watcher.pid === child.pid && watcher.running === true);
      if (ready) break;
      await sleep(50);
    }
    if (!ready) throw new Error(`Watcher did not become ready. ${stderr}`);
    const probeStartedAt = Date.now();
    fs.writeFileSync(probeFile, `probe ${new Date(probeStartedAt).toISOString()}\n`, { encoding: 'utf8', flag: 'wx' });
    probeCreated = true;
    const deadline = Date.now() + watchDurationMs;
    let status = {};
    let completed = false;
    while (Date.now() < deadline) {
      status = readStatus();
      // sync-tracked's last_changed_files contains changed tracked sources;
      // a fresh smoke probe is intentionally new, so bind to watcher inputs.
      const observed = (status.last_watch_changed_files || []).includes(probeName);
      const finished = Date.parse(status.last_sync_finished_at || '') >= probeStartedAt;
      if (observed && finished) {
        if (status.last_sync_exit_code !== 0 || status.last_sync_signal || status.last_sync_error) {
          throw new Error(`Watcher sync failed: ${status.last_sync_error || status.last_sync_signal || status.last_sync_exit_code}`);
        }
        completed = true;
        break;
      }
      await sleep(50);
    }
    if (!completed) throw new Error('Watcher did not complete maintenance for this smoke probe before the deadline.');
    result = { status: 'pass', watcher_running: status.watcher_running, probe_observed: true, last_sync_exit_code: status.last_sync_exit_code, last_auto_maintenance_at: status.last_auto_maintenance_at, last_event_path: status.last_event_path || null };
  } finally {
    try { await stopChild(child); }
    finally { if (probeCreated) fs.unlinkSync(probeFile); }
  }
  const finalStatus = JSON.parse(fs.readFileSync(automationStatusPath, 'utf8'));
  if (Object.values(finalStatus.active_watchers || {}).some(watcher => watcher.pid === child.pid && watcher.running === true)) {
    throw new Error('Watcher exited without clearing its running status.');
  }
  console.log(JSON.stringify({ ...result, watcher_stopped: true, probe_removed: true }, null, 2));
}

main().catch((error) => { console.error(error.stack || error.message); process.exitCode = 1; });
