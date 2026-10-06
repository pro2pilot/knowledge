#!/usr/bin/env node
'use strict';

// Native Doctor -> repair CLI -> sync -> Doctor closure regression.
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const systemRoot = path.resolve(__dirname, '..');
const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-doctor-repair-'));
const knowledge = path.join(repo, '.knowledge');
const checks = [];
const outcomes = {};
const sha = (body) => crypto.createHash('sha256').update(body).digest('hex');
const read = (relative) => JSON.parse(fs.readFileSync(path.join(knowledge, relative), 'utf8'));
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
const document = (relative, value) => write(path.join(knowledge, relative), value);
function run(tool, args = [], allowNonzero = false) {
  const result = spawnSync(process.execPath, [path.join(systemRoot, 'tools', tool), ...args], {
    cwd: repo, encoding: 'utf8', timeout: 30000, maxBuffer: 12 * 1024 * 1024,
    env: { ...process.env, KNOWLEDGE_MODE: 'repo', KNOWLEDGE_TEAM_ROOT: '', KNOWLEDGE_WORKSPACE_ID: '',
      KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_SYSTEM_ROOT: systemRoot,
      KNOWLEDGE_TARGET_ROOT: repo, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: knowledge,
      KNOWLEDGE_STATE_ROOT: knowledge, KNOWLEDGE_AGENT_ID: 'doctor-repair-audit',
      KNOWLEDGE_CHANGED_FILES: '[]', KNOWLEDGE_FULL_SCAN: '0', KNOWLEDGE_DISCOVER_NEW: '0' }
  });
  if (!allowNonzero) assert.equal(result.status, 0, result.stderr || result.stdout);
  assert(result.stdout, result.stderr || `${tool} returned no JSON`);
  return { exit_code: result.status, ...JSON.parse(result.stdout) };
}
function request(name, body) {
  const file = path.join(repo, `${name}.json`);
  write(file, body);
  return file;
}
function check(name, callback) {
  callback();
  checks.push(name);
}

let failure = null;
try {
  fs.cpSync(systemRoot, knowledge, { recursive: true });
  document('config.yaml', 'updates:\n  enabled: false\n');
  write(path.join(repo, 'src/probe.js'), 'module.exports = { ok: true };\n');
  write(path.join(repo, 'tests/probe.js'), 'if (!require("../src/probe").ok) process.exit(1);\n');
  const hash = sha(fs.readFileSync(path.join(repo, 'src/probe.js')));
  const now = new Date().toISOString();
  const card = { module_id: 'root', path: '.', card: '.knowledge/modules/root.json',
    key_files: ['src/probe.js'], evidence_files: [], confidence: 'high',
    verification_status: 'verified_from_code', current_trust_level: 'suspect', target_trust_level: 'near_trusted' };
  const documents = {
    'project_index.json': { generated_at: now, modules: ['root'] },
    'modules/module_registry.json': { modules: [card] }, 'modules/root.json': card,
    'freshness.json': { generated_at: now, tracked_files: [{ path: 'src/probe.js', sha256: hash, status: 'needs_recheck' }],
      artifact_dependencies: {}, artifact_statuses: {} },
    'maintenance/concurrency_policy.json': {}, 'maps/critical_paths.json': { paths: [] },
    'evidence/file_facts.json': { facts: [{ file: 'src/probe.js', evidence: { source_sha256: hash } }] },
    'maintenance/trust_report.json': { generated_at: now, modules: { trusted: ['root'], suspect: [], low_confidence: [] } },
    'maintenance/handoff_summary.json': { generated_at: now },
    'maintenance/routing_bundle.json': { generated_at: now, modules: [] },
    'maps/file_criticality.json': { files: [{ path: 'src/probe.js', classification: 'important' }], coverage_by_module: {} },
    'maps/wiki_graph.json': { generated_at: now, status: 'healthy', structural_status: 'healthy', broken_edge_count: 0 },
    'maintenance/wiki_lint_report.json': { generated_at: now, status: 'healthy', structural_status: 'healthy' },
    'maintenance/secret_scan_report.json': { generated_at: now, status: 'clean', findings_total: 0, by_severity: {} },
    'maintenance/external_memory_status.json': { generated_at: now, providers: [],
      source_of_truth_policy: { external_memory_source_of_truth: false, external_memory_can_raise_trust: false, external_memory_can_overwrite_curated_knowledge: false } },
    'search/index.json': { generated_at: now },
    'maintenance/stale_items.json': { items: [] }, 'maintenance/repair_queue.json': { queue: [] },
    'wiki/index.md': '# Index\n'
  };
  for (const [relative, value] of Object.entries(documents)) document(relative, value);
  fs.mkdirSync(path.join(knowledge, 'maintenance/events'), { recursive: true });
  const doctorBefore = run('doctor.js', ['--json']);
  const finding = doctorBefore.issues.find((item) => item.code === 'tracked_file_needs_recheck' && item.artifact === 'src/probe.js');
  assert(finding, 'Doctor did not emit the tracked-source finding');
  outcomes.doctor_finding = { lifecycle_id: finding.lifecycle_id, artifact: finding.artifact, affected_artifacts: finding.affected_artifacts };
  const identity = { task_id: 'TASK-doctor-native', session_id: 'SESSION-doctor-native' };
  run('repair-on-touch.js', ['plan', '--request', request('plan', { ...identity,
    user_task: 'Verify the tracked probe source', selected_modules: ['root'], changed_files: ['src/probe.js'],
    routing: {}, pr_impact: {}, critical_path_map: {}, scope_source: 'explicit' })]);
  const sources = [...new Set([...finding.affected_artifacts, '.knowledge/modules/root.json', '.knowledge/evidence/file_facts.json'])];
  const verified = run('repair-on-touch.js', ['verify', '--request', request('verify', { ...identity,
    source_files: sources, tests_to_run: [{ argv: ['node', 'tests/probe.js'], timeout_ms: 10000 }] })]);
  const created = run('repair-on-touch.js', ['receipt', '--request', request('receipt', { ...identity,
    finding_id: finding.lifecycle_id, source_files: sources,
    test_execution_ids: verified.executions.map((item) => item.execution_id),
    claims_checked: [{ claim_id: 'probe-current-behavior', claim: 'The source returns ok true.', result: 'confirmed', evidence: ['src/probe.js', 'tests/probe.js'] }],
    required_checks_completed: finding.required_checks,
    resolution_predicate: finding.resolution_predicate, predicate_result: 'pass',
    additional_work: { wall_time_ms: Math.max(1, verified.executions.reduce((total, item) => total + item.duration_ms, 0)),
      context_tokens: 0, context_percent: 0, input_tokens: null, output_tokens: null } })]);
  outcomes.receipt_id = created.receipt.receipt_id;
  outcomes.apply = run('repair-on-touch.js', ['apply', '--receipt', created.receipt.receipt_id], true);
  outcomes.sync_status = run('sync-tracked.js', ['--json']).status;
  const doctorAfter = run('doctor.js', ['--json']);
  outcomes.doctor_after = { status: doctorAfter.status, issues: doctorAfter.issues.map((item) => ({ code: item.code, artifact: item.artifact })) };
  const statusArgs = ['status', '--task-id', identity.task_id, '--session-id', identity.session_id];
  outcomes.status_after = run('repair-on-touch.js', statusArgs);
  check('Doctor primary repair remains closed with valid evidence after apply, sync and Doctor', () => {
    assert.equal(outcomes.apply.exit_code, 0, JSON.stringify(outcomes.apply));
    assert(outcomes.status_after.verified_closures.includes(finding.lifecycle_id), JSON.stringify(outcomes.status_after.closure_provenance));
    assert(!doctorAfter.issues.some((item) => item.code === 'tracked_file_needs_recheck' && item.artifact === 'src/probe.js'));
  });
  check('Current source remains required by the accepted KVR', () => {
    assert(created.receipt.source_files_checked.some((item) => item.path === 'src/probe.js' && item.sha256 === hash));
    assert(created.receipt.source_files_checked.some((item) => item.path === 'tests/probe.js'));
  });
  check('Tampering both primary closure projections is rejected', () => {
    const originals = new Map();
    for (const [relative, field] of [['maintenance/stale_items.json', 'items'], ['maintenance/repair_queue.json', 'queue']]) {
      originals.set(relative, read(relative));
      const edited = read(relative);
      edited[field].find((item) => item.lifecycle_id === finding.lifecycle_id).resolution_evidence.verified_by = 'uncommitted-verifier';
      document(relative, edited);
    }
    const rejected = run('repair-on-touch.js', statusArgs);
    assert(!rejected.verified_closures.includes(finding.lifecycle_id));
    assert(rejected.closure_provenance.invalid.some((item) => item.lifecycle_id === finding.lifecycle_id));
    for (const [relative, value] of originals) document(relative, value);
  });
  check('A forged clean freshness hash cannot authorize changed source under the old KVR', () => {
    write(path.join(repo, 'src/probe.js'), 'module.exports = { ok: false };\n');
    const freshness = read('freshness.json');
    const tracked = freshness.tracked_files.find((item) => item.path === 'src/probe.js');
    tracked.status = 'clean';
    tracked.sha256 = sha(fs.readFileSync(path.join(repo, 'src/probe.js')));
    document('freshness.json', freshness);
    const rejected = run('repair-on-touch.js', ['apply', '--receipt', created.receipt.receipt_id], true);
    assert.equal(rejected.status, 'rejected', JSON.stringify(rejected));
    assert(rejected.errors?.some((item) => item.startsWith('source_hash_current_mismatch:src/probe.js')),
      JSON.stringify(rejected));
    assert(!run('repair-on-touch.js', statusArgs).verified_closures.includes(finding.lifecycle_id));
  });
} catch (error) {
  failure = error.message;
} finally {
  try { removeTempDirStrict(repo); }
  catch (error) { failure = `${failure || ''}\n${error.message}`; }
}
console.log(JSON.stringify({ schema_version: 'knowledge-doctor-repair-lifecycle-self-test.v1',
  status: failure ? 'fail' : 'pass', checks, failure, outcomes }, null, 2));
if (failure) process.exitCode = 1;
