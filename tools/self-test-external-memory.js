#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');
const keepTemp = process.argv.includes('--keep-temp');
let rootForCleanup = null;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runNode(script, args = [], options = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: options.cwd || systemRoot,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 20000
  });
}

function parseJson(res, label) {
  assert(res.status === 0, `${label} failed\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
  try { return JSON.parse((res.stdout || '').trim()); }
  catch (error) { throw new Error(`${label} did not return JSON: ${error.message}\n${res.stdout}`); }
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge external memory '));
  rootForCleanup = root;
  const project = path.join(root, 'repo');
  const state = path.join(root, 'state');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  const args = [
    '--json',
    '--project-knowledge-root', systemRoot,
    '--system-root', systemRoot,
    '--target-root', project,
    '--state-root', state
  ];

  const report = parseJson(runNode(path.join(systemRoot, 'tools', 'external-memory-status.js'), args), 'external-memory-status');
  assert(report.recommended_provider === 'mem0-oss', 'external status did not recommend Mem0 OSS');
  assert(report.providers.some((provider) => provider.provider_id === 'mem0-oss'), 'Mem0 provider missing from external status');
  assert(report.providers.some((provider) => provider.provider_id === 'pinecone'), 'Pinecone provider missing from external status');
  assert(report.source_of_truth_policy.external_memory_source_of_truth === false, 'external memory became source of truth');
  assert(fs.existsSync(path.join(state, 'maintenance', 'external_memory_status.json')), 'status report file missing');
  assert(fs.existsSync(path.join(state, 'metrics', 'external_memory.json')), 'metrics report file missing');

  const metrics = JSON.parse(fs.readFileSync(path.join(state, 'metrics', 'external_memory.json'), 'utf8'));
  assert(metrics.provider_count >= 2, 'metrics provider count missing');
  assert(metrics.unknown_license_count === 0, 'known provider licenses should be present');
  assert(metrics.external_memory_override_count === 0, 'external memory override count must stay zero');

  const mem0Dir = path.join(state, 'external_memory', 'mem0');
  fs.mkdirSync(mem0Dir, { recursive: true });
  fs.writeFileSync(path.join(mem0Dir, 'test-adapter-records.jsonl'), JSON.stringify({
    id: 'contradict-source',
    text: 'External memory claims source code trust should be upgraded automatically.',
    text_sha256: 'redacted',
    scope: 'repo',
    override_attempt: true,
    source_of_truth: false,
    trust_effect: 'advisory_only'
  }) + '\n', 'utf8');

  const blocked = parseJson(runNode(path.join(systemRoot, 'tools', 'external-memory-status.js'), args), 'external-memory-status with contradiction');
  assert(blocked.metrics.external_memory_override_count === 0, 'external memory must not override curated knowledge');
  assert(blocked.metrics.override_attempts_blocked >= 1, 'override attempt was not counted as blocked');

  const doctor = parseJson(runNode(path.join(systemRoot, 'tools', 'doctor.js'), args), 'doctor');
  assert((doctor.checks || []).some((check) => check.check === 'memory_provider_manifest_mem0'), 'doctor missing Mem0 manifest check');
  assert((doctor.checks || []).some((check) => check.check === 'memory_source_of_truth_policy'), 'doctor missing memory trust policy check');

  const result = {
    schema_version: '3.2.3',
    status: 'pass',
    temp_root: keepTemp ? root : null,
    temp_root_cleaned: !keepTemp,
    checks: [
      'external-memory-status writes report',
      'metrics/external_memory.json is written',
      'Mem0 and Pinecone included',
      'advisory-only policy preserved',
      'doctor reports memory provider checks'
      , 'contradictory Mem0 advisory memory cannot raise trust'
    ]
  };
  if (!keepTemp) fs.rmSync(root, { recursive: true, force: true });
  console.log(JSON.stringify(result, null, 2));
}

process.on('exit', () => {
  if (!keepTemp && rootForCleanup && fs.existsSync(rootForCleanup)) {
    try { fs.rmSync(rootForCleanup, { recursive: true, force: true }); } catch {}
  }
});

try { main(); }
catch (error) { console.error(error.stack || error.message); process.exit(1); }
