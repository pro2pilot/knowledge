#!/usr/bin/env node
'use strict';

// Evidence-only RC42 driver.  It is deliberately under tools/internal so it
// cannot enter a public candidate archive or change runtime behaviour.
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const RC42 = 'knowledge-v3.3.0-step1-rc4-r42.zip';
const SHA = 'ebdeebd5b67ca3ec4f61779e28fd3018e5eee697b00d1705d194b733b41259f0';

function value(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] || null : null;
}
function sha(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function json(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}
function run(command, args, cwd, timeout = 900000) {
  const started_at = new Date().toISOString();
  const child = childProcess.spawnSync(command, args, {
    cwd, encoding: 'utf8', windowsHide: true, timeout,
    env: { ...process.env, NODE_PATH: '', KNOWLEDGE_FLOW_NO_OPEN: '1' }
  });
  let parsed = null;
  try { parsed = JSON.parse((child.stdout || '').trim()); } catch {}
  return {
    command: [command, ...args].join(' '), started_at,
    finished_at: new Date().toISOString(), exit_code: child.status,
    status: child.status === 0 && !child.error ? 'pass' : 'fail',
    stdout: child.stdout || '', stderr: child.stderr || '',
    error: child.error ? child.error.message : null, parsed
  };
}
function requirePass(result, id) {
  if (result.status !== 'pass') throw new Error(`${id} failed: ${result.stderr || result.error || 'nonzero exit'}`);
}
function candidate(file) {
  const actual = sha(file);
  if (path.basename(file) !== RC42 || actual !== SHA) throw new Error('exact RC42 candidate is required');
  return { candidate_name: RC42, candidate_sha256: actual, candidate_size_bytes: fs.statSync(file).size };
}

function main() {
  const action = value('--action');
  const artifact = path.resolve(value('--artifact') || '');
  const out = path.resolve(value('--out') || '');
  const source = path.resolve(value('--source') || path.resolve(__dirname, '..', '..'));
  if (!action || !artifact || !out) throw new Error('Usage: rc42-evidence-rebind.js --action <artifact|replay|blackbox|integrations|physical|physical-all-integrations|upgrade> --artifact <RC42.zip> --out <report.json> [--baseline <3.2.11.zip>]');
  const bound = candidate(artifact);
  let result;
  if (action === 'artifact') {
    result = run(process.execPath, [path.join(source, 'tools', 'validate-release-artifact.js'), artifact, '--profile', 'public_runtime', '--json'], source);
  } else if (action === 'replay') {
    result = run(process.execPath, [path.join(source, 'tools', 'self-test-audit-replay-bundle.js'), '--zip', artifact], source);
  } else if (action === 'blackbox') {
    result = run(process.execPath, [path.join(source, 'tools', 'verify-contained-lock-rc39.js'), '--zip', artifact], source);
  } else if (action === 'integrations') {
    result = run(process.execPath, [path.join(source, 'tools', 'conformance-install-smoke.js'), artifact, '--json'], source);
  } else if (action === 'physical') {
    const raw = `${out}.raw.json`;
    result = run(process.execPath, [value('--physical-script') || '', '--artifact', artifact, '--out', raw], source, 1200000);
    if (fs.existsSync(raw)) result.physical_report = JSON.parse(fs.readFileSync(raw, 'utf8'));
  } else if (action === 'physical-all-integrations') {
    const physical = path.resolve(value('--physical-report') || '');
    if (!physical || !fs.existsSync(physical)) throw new Error('--physical-report is required');
    const sourceReport = JSON.parse(fs.readFileSync(physical, 'utf8'));
    const steps = sourceReport.execution?.physical_report?.results || [];
    const all = steps.find((step) => step.id === 'install-all-12-integrations');
    if (!all || all.status !== 'pass') throw new Error('physical workflow does not prove all 12 integrations');
    result = { status: 'pass', derived_from: path.basename(physical), all_integrations_step: all, workflow_status: sourceReport.status };
  } else if (action === 'upgrade') {
    const baseline = path.resolve(value('--baseline') || '');
    if (!baseline || !fs.existsSync(baseline)) throw new Error('--baseline <3.2.11.zip> is required for upgrade');
    const captureRoot = `${out}.capture`;
    result = run(process.execPath, [path.join(source, 'docs', 'release', '3.3.0', 'test-evidence', 'release-gates', 'capture-exact-upgrade.js'), '--baseline', baseline, '--candidate', artifact, '--output', captureRoot], source, 1200000);
    if (fs.existsSync(path.join(captureRoot, 'report.json'))) result.capture_report = JSON.parse(fs.readFileSync(path.join(captureRoot, 'report.json'), 'utf8'));
  } else throw new Error(`unknown action: ${action}`);
  requirePass(result, action);
  const report = {
    schema_version: 'knowledge-rc42-exact-evidence.v1', action, status: 'pass',
    generated_at: new Date().toISOString(), ...bound,
    runtime: { platform: process.platform, arch: process.arch, node: process.version },
    execution: result
  };
  json(out, report);
  process.stdout.write(`${JSON.stringify({ status: report.status, action, report: out, candidate_sha256: bound.candidate_sha256 }, null, 2)}\n`);
}
if (require.main === module) main();
