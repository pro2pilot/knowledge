#!/usr/bin/env node
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');
const outputArg = process.argv.find((arg) => arg.startsWith('--output='));
const outputPath = outputArg ? path.resolve(outputArg.slice('--output='.length)) : null;
function emit(report) {
  if (outputPath) { fs.mkdirSync(path.dirname(outputPath), { recursive: true }); fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8'); }
  console.log(JSON.stringify(report, null, 2));
}
function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function lockedFixture(holdMs) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-wiki-structure-lock-'));
  fs.writeFileSync(path.join(dir, 'locked-canary.txt'), 'must remain visible in persistent-lock diagnostics', 'utf8');
  const ready = path.join(os.tmpdir(), `cleanup-ready-${process.pid}-${Date.now()}`);
  const code = `const fs=require('fs');process.chdir(${JSON.stringify(dir)});fs.writeFileSync(${JSON.stringify(ready)},'LOCK_READY');setTimeout(()=>process.exit(0),${holdMs});`;
  const child = spawn(process.execPath, ['-e', code], { windowsHide: true, stdio: 'ignore' });
  const deadline = Date.now() + 5000;
  while (!fs.existsSync(ready) && Date.now() < deadline) sleep(10);
  if (!fs.existsSync(ready)) throw new Error('child did not signal LOCK_READY');
  fs.rmSync(ready, { force: true });
  return { dir, child };
}
const results = [];
if (process.platform !== 'win32') {
  emit({ status: 'skipped', reason: 'windows_only', results });
  process.exit(0);
}
{
  const { dir, child } = lockedFixture(850);
  const report = removeTempDirStrict(dir, { attempts: 12, initialDelayMs: 50, maxElapsedMs: 4000 });
  let childAlive = true; try { process.kill(child.pid, 0); } catch { childAlive = false; }
  if (report.attempts <= 1 || report.diagnostics.length < 1 || fs.existsSync(dir) || childAlive) throw new Error('transient physical lock was not retried, removed, and released');
  results.push({ id: 'physical-transient-lock', status: 'pass', report, child_pid: child.pid, child_exited: !childAlive });
}
{
  const { dir, child } = lockedFixture(4000);
  let observed;
  try { removeTempDirStrict(dir, { attempts: 5, initialDelayMs: 50, maxElapsedMs: 500 }); } catch (error) { observed = error; }
  if (!observed || observed.code !== 'TEMP_FIXTURE_CLEANUP_FAILED' || observed.reason !== 'persistent_resource_lock' || !fs.existsSync(dir) || !observed.remaining_entries.includes('locked-canary.txt')) throw new Error('persistent physical lock did not fail closed with remaining-entry diagnostics');
  child.kill();
  const deadline = Date.now() + 3000; let childAlive = true; while ((fs.existsSync(dir) || childAlive) && Date.now() < deadline) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} try { process.kill(child.pid, 0); } catch { childAlive = false; } sleep(25); }
  if (fs.existsSync(dir) || childAlive) throw new Error('persistent fixture or child remained after child termination');
  results.push({ id: 'physical-persistent-lock', status: 'pass', error: { code: observed.code, reason: observed.reason, attempts: observed.attempts, elapsed_ms: observed.elapsed_ms, remaining_entries: observed.remaining_entries }, child_pid: child.pid, child_exited: !childAlive });
}
const leftovers = fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith('knowledge-wiki-structure-lock-'));
if (leftovers.length) throw new Error(`leftovers: ${leftovers.join(', ')}`);
emit({ status: 'pass', results, leftovers });
