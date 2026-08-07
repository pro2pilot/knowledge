#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const test = path.join(__dirname, 'self-test-wiki-structural-status.js');

function numberArg(name, fallback) {
  const raw = process.argv.find((arg) => arg.startsWith(`--${name}=`))?.split('=')[1];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < 1) throw new TypeError(`${name} must be an integer >= 1`);
  return value;
}

const sequentialRuns = numberArg('runs', 100);
const parallelRounds = numberArg('parallel-rounds', 10);
const parallelWidth = numberArg('parallel-width', 4);
const ciRuns = numberArg('ci-runs', 10);
const loadRuns = numberArg('load-runs', 10);
const outputArg = process.argv.find((arg) => arg.startsWith('--output='));
const outputPath = outputArg ? path.resolve(outputArg.slice('--output='.length)) : null;
const evidenceRoot = outputPath ? path.dirname(outputPath) : null;
const failureRoot = evidenceRoot ? path.join(evidenceRoot, 'wiki-failure-fixtures') : null;
const rawLogRoot = evidenceRoot ? path.join(evidenceRoot, 'wiki-stress-raw-logs') : null;
const results = [];
const activeChildren = new Set();
const leftoverScans = [];

function fixtureNames() {
  return fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith('knowledge-wiki-structure-')).sort();
}

function preserveLeftovers(block, names) {
  if (!failureRoot || names.length === 0) return;
  const destination = path.join(failureRoot, 'leftovers', block);
  fs.mkdirSync(destination, { recursive: true });
  for (const name of names) {
    const source = path.join(os.tmpdir(), name);
    if (fs.existsSync(source)) fs.cpSync(source, path.join(destination, name), { recursive: true });
  }
  fs.writeFileSync(path.join(destination, 'inventory.json'), `${JSON.stringify({
    block,
    names,
    active_child_pids: Array.from(activeChildren),
    process: { pid: process.pid, platform: process.platform, arch: process.arch, node_version: process.version }
  }, null, 2)}\n`, 'utf8');
}

function scanLeftovers(block) {
  const names = fixtureNames();
  preserveLeftovers(block, names);
  leftoverScans.push({ block, count: names.length, names });
  return names;
}

function childEnv(extra = {}) {
  return {
    ...process.env,
    ...extra,
    KNOWLEDGE_STATE_ROOT: '',
    KNOWLEDGE_WIKI_FAILURE_DIR: failureRoot || ''
  };
}

function record(block, index, round, status, exitCode, signal, stdout, stderr, durationMs, pid = null) {
  const item = {
    block,
    index,
    round,
    status,
    exit_code: exitCode,
    signal: signal || null,
    pid,
    duration_ms: durationMs,
    stdout_bytes: Buffer.byteLength(String(stdout || '')),
    stderr_bytes: Buffer.byteLength(String(stderr || '')),
    stdout_tail: String(stdout || '').slice(-500),
    stderr_tail: String(stderr || '').slice(-1000)
  };
  results.push(item);
  if (status !== 'pass' && rawLogRoot) {
    fs.mkdirSync(rawLogRoot, { recursive: true });
    const label = `${block}-r${round || 0}-i${index}`;
    fs.writeFileSync(path.join(rawLogRoot, `${label}.stdout.txt`), String(stdout || ''), 'utf8');
    fs.writeFileSync(path.join(rawLogRoot, `${label}.stderr.txt`), String(stderr || ''), 'utf8');
  }
}

function runSync(block, index, extraEnv = {}) {
  const started = process.hrtime.bigint();
  const result = spawnSync(process.execPath, [test], {
    encoding: 'utf8',
    windowsHide: true,
    env: childEnv(extraEnv),
    maxBuffer: 32 * 1024 * 1024
  });
  const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
  const passed = result.status === 0 && !result.error;
  record(block, index, null, passed ? 'pass' : 'fail', result.status, result.signal, result.stdout, result.stderr || result.error?.stack, Number(durationMs.toFixed(3)));
  return passed;
}

function runParallel(round, index) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const child = spawn(process.execPath, [test], {
      windowsHide: true,
      env: childEnv(),
      stdio: ['ignore', 'pipe', 'pipe']
    });
    activeChildren.add(child.pid);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => { stderr += `${error.stack || error.message}\n`; });
    child.on('close', (code, signal) => {
      activeChildren.delete(child.pid);
      const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
      record('parallel', index, round, code === 0 ? 'pass' : 'fail', code, signal, stdout, stderr, Number(durationMs.toFixed(3)), child.pid);
      resolve(code === 0);
    });
  });
}

async function main() {
  const preexisting = fixtureNames();
  const preexistingCleanup = [];
  for (const name of preexisting) {
    const source = path.join(os.tmpdir(), name);
    if (failureRoot && fs.existsSync(source)) {
      const destination = path.join(failureRoot, 'preexisting-leftovers', name);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.cpSync(source, destination, { recursive: true });
    }
    preexistingCleanup.push({ name, ...removeTempDirStrict(source) });
  }

  for (let index = 1; index <= sequentialRuns; index += 1) {
    if (!runSync('sequential', index)) break;
  }
  scanLeftovers('after-sequential');

  for (let round = 1; round <= parallelRounds; round += 1) {
    await Promise.all(Array.from({ length: parallelWidth }, (_, offset) => runParallel(round, ((round - 1) * parallelWidth) + offset + 1)));
    if (results.some((item) => item.block === 'parallel' && item.round === round && item.status !== 'pass')) break;
  }
  scanLeftovers('after-parallel');

  for (let index = 1; index <= ciRuns; index += 1) {
    if (!runSync('ci', index, { CI: 'true' })) break;
  }
  scanLeftovers('after-ci');

  const load = spawn(process.execPath, ['-e', 'const end=Date.now()+60000;while(Date.now()<end){Math.sqrt(Math.random())}'], {
    windowsHide: true,
    stdio: 'ignore'
  });
  activeChildren.add(load.pid);
  load.on('close', () => activeChildren.delete(load.pid));
  for (let index = 1; index <= loadRuns; index += 1) {
    if (!runSync('load', index)) break;
  }
  if (activeChildren.has(load.pid)) {
    load.kill();
    await new Promise((resolve) => load.once('close', resolve));
  }
  scanLeftovers('after-load');

  const failed = results.filter((item) => item.status !== 'pass');
  const leftovers = Array.from(new Set(leftoverScans.flatMap((scan) => scan.names))).sort();
  const expected = {
    sequential: sequentialRuns,
    parallel_rounds: parallelRounds,
    parallel_width: parallelWidth,
    parallel_total: parallelRounds * parallelWidth,
    ci: ciRuns,
    load: loadRuns
  };
  const executed = {
    sequential: results.filter((item) => item.block === 'sequential').length,
    parallel_rounds: new Set(results.filter((item) => item.block === 'parallel').map((item) => item.round)).size,
    parallel_total: results.filter((item) => item.block === 'parallel').length,
    ci: results.filter((item) => item.block === 'ci').length,
    load: results.filter((item) => item.block === 'load').length
  };
  const countsComplete = executed.sequential === expected.sequential &&
    executed.parallel_rounds === expected.parallel_rounds &&
    executed.parallel_total === expected.parallel_total &&
    executed.ci === expected.ci && executed.load === expected.load;
  const report = {
    schema_version: 'wiki-structural-stress.v2',
    generated_at: new Date().toISOString(),
    status: failed.length === 0 && leftovers.length === 0 && activeChildren.size === 0 && countsComplete ? 'pass' : 'fail',
    expected,
    executed,
    counts_complete: countsComplete,
    preexisting_leftovers: preexisting,
    preexisting_cleanup: preexistingCleanup,
    failed,
    leftover_scans: leftoverScans,
    leftovers,
    leaked_child_processes: Array.from(activeChildren),
    failure_fixture_root: failureRoot,
    raw_log_root: rawLogRoot,
    results
  };
  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  }
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'pass') process.exitCode = 1;
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
