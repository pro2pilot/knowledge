#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext, contextEnv } = require('./lib/path-context');
const { watchPolicy, readyIdentity } = require('./watch-maintenance');
const mono = () => performance.now();
const MAX_TIMER = 2147483647;

function smokeLimits(flags = {}, options = {}) {
  // A short diagnostic has its own conservative profile; daemon defaults allow
  // hour-long work. Explicit CLI/environment budgets still take precedence.
  const policy = watchPolicy({ ...flags,
    setupTimeoutMs: flags.setupTimeoutMs ?? (process.env.KNOWLEDGE_SETUP_TIMEOUT_MS || 30000),
    workTimeoutMs: flags.workTimeoutMs ?? (process.env.KNOWLEDGE_WORK_TIMEOUT_MS || 60000),
    cleanupTimeoutMs: flags.cleanupTimeoutMs ?? (process.env.KNOWLEDGE_CLEANUP_TIMEOUT_MS || 15000)
  }, options);
  // This is an observation budget, not a proof of an I/O latency maximum.
  // Include permit wait, pre-start publication, native setup/work/drain,
  // event/result publication reserves and debounce/polling. Exhaustion stops
  // this smoke attempt and waits for independent native cleanup.
  const debounceMs = Number(options.debounceMs ?? process.env.KNOWLEDGE_WATCH_DEBOUNCE_MS ?? 1500);
  if (!Number.isSafeInteger(debounceMs) || debounceMs < 1 || debounceMs > MAX_TIMER) throw new Error('Invalid smoke debounce interval.');
  const observationMs = policy.commandAllowance + policy.command.setupMs * 3 + debounceMs + 1000;
  const watchMs = Number(options.watchMs ?? process.env.KNOWLEDGE_SMOKE_WATCH_MS ?? observationMs);
  // Caller launch, controller startup, useful work and cleanup are separate.
  const readyMs = policy.command.setupMs + policy.startupMs;
  const cleanupMs = policy.command.cleanupMs;
  const outerMs = readyMs + watchMs + cleanupMs + 4000;
  if (!Number.isSafeInteger(watchMs) || watchMs <= 0 || !Number.isSafeInteger(outerMs) || outerMs > MAX_TIMER) {
    throw new Error('Watcher smoke phase budgets exceed the supported timer range.');
  }
  return { readyMs, watchMs, cleanupMs, outerMs, command: policy.command };
}
function matchesReadyObservation(status, identity) {
  if (!identity) return false;
  const row = status?.active_watchers?.[identity.watcher_id];
  return row?.running === true && row.pid === identity.controller_pid && row.worker_pid === identity.worker_pid &&
    row.attempt_id === identity.attempt_id && row.epoch_id === identity.epoch_id;
}
function probeResult(status, identity, probe) {
  const row = status?.last_watch_sync_result;
  return row?.schema_version === 'knowledge-watch-sync.v1' && identity &&
    row.watcher_id === identity.watcher_id && row.attempt_id === identity.attempt_id && row.epoch_id === identity.epoch_id &&
    Array.isArray(row.changed_files) && row.changed_files.includes(probe) && Number.isFinite(Date.parse(row.finished_at)) ? row : null;
}

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function stopChild(child, cleanupMs) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve, reject) => {
    let forced = false;
    const force = setTimeout(() => {
      forced = true;
      // Kill only the tree spawned by this smoke; a busy watcher may have an
      // owned sync child. Never report forced cleanup as a graceful PASS.
      if (process.platform === 'win32') spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: 1500, stdio: 'ignore' });
      else child.kill('SIGKILL');
    }, cleanupMs + 1000);
    const deadline = setTimeout(() => { clearTimeout(force); reject(new Error('Watcher did not stop after smoke test.')); }, cleanupMs + 3000);
    child.once('close', () => { clearTimeout(force); clearTimeout(deadline); if (forced) reject(new Error('Watcher required forced termination; teardown was not graceful.')); else resolve(); });
    if (child.connected) child.send({ type: 'knowledge:watch-stop' }, error => { if (error) child.kill('SIGTERM'); });
    else child.kill('SIGTERM');
  });
}

async function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  if (parsed.flags.help) {
    console.log('Usage: node .knowledge/tools/watch-smoke.js [--target-root PATH] [--state-root PATH] [--system-root PATH]');
    return;
  }
  const context = resolveKnowledgeContext({ targetRoot: process.env.KNOWLEDGE_TARGET_ROOT || process.cwd(), ...parsed.flags });
  const repoRoot = context.targetRoot;
  const limits = smokeLimits(parsed.flags);
  const automationStatusPath = path.join(context.stateRoot, 'maintenance', 'automation_status.json');
  const probeName = `knowledge-smoke-probe-${process.pid}-${crypto.randomBytes(8).toString('hex')}.txt`;
  const probeFile = path.join(repoRoot, probeName);
  let probeCreated = false;
  let childError = null;
  let stderr = '';
  let result = null;
  let identity = null, terminal = null;
  const startupDeadline = mono() + limits.readyMs;
  const budgetArgs = [`--setup-timeout-ms=${limits.command.setupMs}`, `--work-timeout-ms=${limits.command.workMs}`,
    `--cleanup-timeout-ms=${limits.command.cleanupMs}`, `--progress-timeout-ms=${limits.command.progressMs}`];
  const child = spawn(process.execPath, [path.join(context.systemRoot, 'tools', 'watch-maintenance.js'), ...argv, ...budgetArgs], {
    cwd: repoRoot,
    env: contextEnv(context),
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    windowsHide: true
  });
  child.on('error', (error) => { childError = error; });
  child.on('message', message => {
    if (message?.type === 'knowledge:watch-ready') {
      const candidate = readyIdentity({ ...message, type: 'ready' }, child.pid, message.epoch_id);
      if (!candidate) childError = new Error('Watcher returned an invalid readiness identity.');
      else identity = candidate;
    } else if (message?.type === 'knowledge:watch-terminal') terminal = message;
  });
  child.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-2000); });
  function readStatus() {
    if (childError) throw childError;
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Watcher exited before smoke completion: ${child.exitCode ?? child.signalCode}. ${stderr}`);
    try { return JSON.parse(fs.readFileSync(automationStatusPath, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return {}; throw error; }
  }
  try {
    let ready = false;
    while (mono() < startupDeadline) {
      const state = readStatus();
      if (mono() >= startupDeadline) break;
      ready = matchesReadyObservation(state, identity);
      if (ready) break;
      await sleep(50);
    }
    if (!ready) throw new Error(`Watcher startup budget exceeded before matching readiness was observed. ${stderr}`);
    const probeStartedAt = Date.now();
    fs.writeFileSync(probeFile, `probe ${new Date(probeStartedAt).toISOString()}\n`, { encoding: 'utf8', flag: 'wx' });
    probeCreated = true;
    const deadline = mono() + limits.watchMs;
    let status = {};
    let completed = false;
    while (mono() < deadline) {
      status = readStatus();
      if (mono() >= deadline) break;
      // sync-tracked's last_changed_files contains changed tracked sources;
      // a fresh smoke probe is intentionally new, so bind to watcher inputs.
      const observed = probeResult(status, identity, probeName);
      if (observed) {
        if (observed.ok !== true || observed.exit_code !== 0 || observed.signal || observed.error_code || observed.cleanup?.status !== 'completed') {
          throw new Error(`Watcher sync failed: ${observed.error_code || observed.signal || observed.exit_code}`);
        }
        result = { status: 'pass', probe_observed: true, last_sync_exit_code: observed.exit_code,
          last_auto_maintenance_at: observed.finished_at, last_event_path: probeName };
        completed = true;
        break;
      }
      await sleep(50);
    }
    if (!completed) throw new Error('Watcher did not complete maintenance for this smoke probe before the deadline.');
  } finally {
    try { await stopChild(child, limits.cleanupMs); }
    finally { if (probeCreated) fs.unlinkSync(probeFile); }
  }
  if (terminal?.status !== 'stopped' || terminal.durable_stop_confirmed !== true ||
      terminal.cleanup?.status !== 'completed' || terminal.cleanup.output_closed !== true || terminal.cleanup.active_processes !== 0 ||
      !identity || terminal.readiness?.attempt_id !== identity.attempt_id || terminal.readiness?.epoch_id !== identity.epoch_id ||
      terminal.readiness?.watcher_id !== identity.watcher_id) {
    throw new Error('Watcher native cleanup and exact-attempt durable stop were not confirmed.');
  }
  const finalStatus = JSON.parse(fs.readFileSync(automationStatusPath, 'utf8'));
  if (Object.values(finalStatus.active_watchers || {}).some(watcher => watcher.pid === child.pid && watcher.running === true)) {
    throw new Error('Watcher exited without clearing its running status.');
  }
  const value = { ...result, watcher_stopped: true, probe_removed: true, readiness: identity,
    native_cleanup_confirmed: true, phase_budgets_ms: limits };
  console.log(JSON.stringify(value, null, 2));
  return value;
}

if (require.main === module) main().catch((error) => { console.error(error.stack || error.message); process.exitCode = 1; });
module.exports = { main, smokeLimits, matchesReadyObservation, probeResult };
