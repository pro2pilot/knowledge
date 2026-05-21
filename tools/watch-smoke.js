#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const repoRoot = process.cwd();
const watchDurationMs = Number(process.env.KNOWLEDGE_SMOKE_WATCH_MS || 4000);
const knowledgeRoot = path.join(repoRoot, '.knowledge');
const automationStatusPath = path.join(knowledgeRoot, 'maintenance', 'automation_status.json');
const probeFile = path.join(repoRoot, 'smoke-probe.txt');

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function main() {
  const child = spawn(process.execPath, [path.join(repoRoot, '.knowledge', 'tools', 'watch-maintenance.js')], {
    cwd: repoRoot,
    stdio: 'ignore',
    windowsHide: true
  });
  await sleep(1000);
  fs.writeFileSync(probeFile, `probe ${new Date().toISOString()}\n`, 'utf8');
  await sleep(watchDurationMs);
  const status = JSON.parse(fs.readFileSync(automationStatusPath, 'utf8'));
  child.kill();
  try { fs.unlinkSync(probeFile); } catch {}
  console.log(JSON.stringify({ watcher_running: status.watcher_running, last_trigger_source: status.last_trigger_source, last_auto_maintenance_at: status.last_auto_maintenance_at, last_event_path: status.last_event_path || null }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
