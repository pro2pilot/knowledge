#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { loadReleaseContract } = require('./lib/release-contract');
const { readZipEntries } = require('./validate-release-artifact');

const root = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const args = { artifact: null, out: null, keepFixtures: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--artifact') args.artifact = argv[++index] || null;
    else if (value.startsWith('--artifact=')) args.artifact = value.slice('--artifact='.length);
    else if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice('--out='.length);
    else if (value === '--keep-fixtures') args.keepFixtures = true;
  }
  return args;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function extract(entries, destination) {
  for (const entry of entries) {
    if (!entry.name.startsWith('.knowledge/')) continue;
    const target = path.join(destination, entry.name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.body);
  }
}

function cleanTestEnvironment() {
  const environment = { ...process.env, NODE_PATH: '', CI: 'true', KNOWLEDGE_INSPECTOR_NO_OPEN: '1', KNOWLEDGE_FLOW_NO_OPEN: '1' };
  for (const key of Object.keys(environment)) {
    if (/^KNOWLEDGE_(?:MODE|SYSTEM_ROOT|TARGET_ROOT|PROJECT_KNOWLEDGE_ROOT|STATE_ROOT|TEAM_ROOT|WORKSPACE_ID|REPO_ID)$/i.test(key)) delete environment[key];
  }
  return environment;
}

function run(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args.artifact) throw new Error('Usage: node tools/run-shipped-self-tests.js --artifact <candidate.zip> [--out report.json]');
  const artifact = path.resolve(args.artifact);
  const contract = loadReleaseContract(root);
  const expected = contract.public_self_test_paths.slice().sort();
  const entries = readZipEntries(artifact).entries;
  const stateRoot = path.join(root, '.self-test-tmp');
  fs.mkdirSync(stateRoot, { recursive: true });
  const runRoot = fs.mkdtempSync(path.join(stateRoot, 'shipped-self-tests-'));
  const results = [];
  for (const test of expected) {
    const fixture = path.join(runRoot, test.replace(/[^a-z0-9]+/gi, '-'));
    const started = process.hrtime.bigint();
    extract(entries, fixture);
    const script = path.join(fixture, '.knowledge', ...test.split('/'));
    const processResult = spawnSync(process.execPath, [script], {
      cwd: path.join(fixture, '.knowledge'),
      encoding: 'utf8',
      env: cleanTestEnvironment(),
      maxBuffer: 32 * 1024 * 1024
    });
    const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
    results.push({
      test,
      exit_code: processResult.status,
      signal: processResult.signal || null,
      duration_ms: Number(durationMs.toFixed(3)),
      stdout: processResult.stdout || '',
      stderr: processResult.stderr || '',
      passed: processResult.status === 0 && !processResult.error
    });
    if (!args.keepFixtures) fs.rmSync(fixture, { recursive: true, force: true });
  }
  const report = {
    schema_version: 'shipped-self-tests.v1',
    generated_at: new Date().toISOString(),
    candidate: artifact,
    candidate_sha256: sha256(artifact),
    expected_tests: expected,
    executed_tests: results.map((item) => item.test),
    passed: results.filter((item) => item.passed).length,
    failed: results.filter((item) => !item.passed).length,
    results,
    status: results.every((item) => item.passed) ? 'pass' : 'fail'
  };
  const out = path.resolve(args.out || path.join(runRoot, 'all-shipped-self-tests.json'));
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'pass') process.exitCode = 2;
  return report;
}

if (require.main === module) {
  try { run(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 2; }
}

module.exports = { run };
