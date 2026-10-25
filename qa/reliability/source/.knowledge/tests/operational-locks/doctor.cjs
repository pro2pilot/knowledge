#!/usr/bin/env node
'use strict';

// Physical, offline Doctor regressions. All locks belong to disposable fixtures;
// no owner replacement, timestamp rewriting, recovery, or recursive lock cleanup.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert/strict');
const { spawnSync } = require('child_process');

const flags = Object.fromEntries(process.argv.slice(2).reduce((out, value, index, argv) => {
  if (index % 2 === 0) out.push([value.replace(/^--/, ''), argv[index + 1]]);
  return out;
}, []));
for (const name of ['system-root', 'output', 'work']) assert(flags[name], `Missing --${name}`);
const systemRoot = path.resolve(flags['system-root']);
const output = path.resolve(flags.output);
const work = path.resolve(flags.work);
fs.mkdirSync(output, { recursive: false });
fs.mkdirSync(work, { recursive: false });
const manager = require(path.join(systemRoot, 'tools/lib/contained-lock-manager'));
const { LOCKS } = require(path.join(systemRoot, 'tools/lib/lock-policy'));
const repair = require(path.join(systemRoot, 'tools/lib/repair-on-touch'));
const sha = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const identity = (file) => { const b = fs.readFileSync(file); return { bytes: b.length, sha256: sha(b) }; };
const write = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
};
const tree = (root) => {
  const result = {};
  function visit(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = path.join(dir, entry.name);
      assert(!entry.isSymbolicLink(), `Unexpected source symlink: ${abs}`);
      if (entry.isDirectory()) visit(abs);
      else if (entry.isFile()) result[path.relative(root, abs).replace(/\\/g, '/')] = identity(abs);
    }
  }
  visit(root);
  return result;
};
const before = tree(systemRoot);
const nodeBefore = identity(process.execPath);
const commands = [];
const cases = [];
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function seed(name, { splitState = false } = {}) {
  const repo = path.join(work, name);
  const knowledge = path.join(repo, '.knowledge');
  const state = splitState ? path.join(repo, 'isolated-state') : knowledge;
  fs.mkdirSync(repo);
  fs.cpSync(systemRoot, knowledge, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  // The production default enables update checks. This explicit fixture-only
  // configuration is captured in every command receipt and never edits source.
  write(path.join(knowledge, 'config.yaml'), 'updates:\n  enabled: false\n');
  write(path.join(repo, 'src/main.js'), 'module.exports = 1;\n');
  const now = new Date().toISOString();
  const card = { module_id: 'root', path: '.', card: '.knowledge/modules/root.json', key_files: ['src/main.js'], evidence_files: [], confidence: 'high', verification_status: 'verified_from_code' };
  const curated = {
    'project_index.json': { generated_at: now, modules: ['root'] },
    'modules/module_registry.json': { modules: [card] },
    'modules/root.json': card,
    'maintenance/concurrency_policy.json': {},
    'maps/critical_paths.json': { paths: [] },
    'evidence/file_facts.json': { facts: [{ file: 'src/main.js', evidence: { source_sha256: identity(path.join(repo, 'src/main.js')).sha256 } }] },
    'wiki/index.md': '# Index\n'
  };
  const runtime = {
    'freshness.json': { generated_at: now, tracked_files: [{ path: 'src/main.js', sha256: identity(path.join(repo, 'src/main.js')).sha256, status: 'clean' }], artifact_dependencies: {}, artifact_statuses: {} },
    'maintenance/trust_report.json': { generated_at: now, modules: { trusted: ['root'], suspect: [], low_confidence: [] } },
    'maintenance/handoff_summary.json': { generated_at: now },
    'maintenance/routing_bundle.json': { generated_at: now, modules: [] },
    'maps/file_criticality.json': { files: [], coverage_by_module: {} },
    'maps/wiki_graph.json': { generated_at: now, status: 'healthy', structural_status: 'healthy', broken_edge_count: 0 },
    'maintenance/wiki_lint_report.json': { generated_at: now, status: 'healthy', structural_status: 'healthy' },
    'maintenance/secret_scan_report.json': { generated_at: now, status: 'clean', findings_total: 0, by_severity: {} },
    'search/index.json': { generated_at: now },
    'maintenance/external_memory_status.json': { generated_at: now, providers: [], source_of_truth_policy: { external_memory_source_of_truth: false, external_memory_can_raise_trust: false, external_memory_can_overwrite_curated_knowledge: false } },
    'maintenance/stale_items.json': { items: [] },
    'maintenance/repair_queue.json': { queue: [] }
  };
  for (const [rel, value] of Object.entries(curated)) write(path.join(knowledge, rel), value);
  for (const [rel, value] of Object.entries(runtime)) write(path.join(state, rel), value);
  fs.mkdirSync(path.join(state, 'maintenance/events'), { recursive: true });
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(KNOWLEDGE_|NODE_|GIT_|MEM0_|PINECONE_)/.test(key)));
  Object.assign(env, {
    KNOWLEDGE_MODE: 'repo', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1',
    KNOWLEDGE_SYSTEM_ROOT: systemRoot, KNOWLEDGE_TARGET_ROOT: repo,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: knowledge, KNOWLEDGE_STATE_ROOT: state,
    KNOWLEDGE_AGENT_ID: 'doctor-lock-safety-regression', KNOWLEDGE_LOCK_TIMEOUT_MS: '150',
    KNOWLEDGE_NO_OPEN: '1', CI: '1'
  });
  const log = path.join(output, name);
  fs.mkdirSync(log);
  write(path.join(log, 'fixture-source-before.json'), tree(knowledge));
  write(path.join(log, 'environment-overrides.json'), Object.fromEntries(Object.entries(env).filter(([key]) => key.startsWith('KNOWLEDGE_'))));
  write(path.join(log, 'offline-config.yaml'), fs.readFileSync(path.join(knowledge, 'config.yaml'), 'utf8'));
  return { name, repo, knowledge, state, env, log, commandNumber: 0, locks: [] };
}

function run(fixture, { taskScope = null } = {}) {
  const argv = taskScope
    ? ['-e', 'const doctor = require(process.argv[1]); const report = doctor({quiet: true, taskScope: JSON.parse(process.argv[2])}); process.stdout.write(JSON.stringify(report));', path.join(systemRoot, 'tools/doctor.js'), JSON.stringify(taskScope)]
    : [path.join(systemRoot, 'tools/doctor.js'), '--json'];
  const started = performance.now();
  const result = spawnSync(process.execPath, argv, { cwd: fixture.repo, env: fixture.env, encoding: 'utf8', timeout: 30000, windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
  const number = String(++fixture.commandNumber).padStart(2, '0');
  const receipt = { argv: [process.execPath, ...argv], cwd: fixture.repo, exit_code: result.status, signal: result.signal,
    spawn_error: result.error ? { code: result.error.code, message: result.error.message } : null,
    duration_ms: performance.now() - started, offline_config: identity(path.join(fixture.knowledge, 'config.yaml')),
    environment_overrides: Object.fromEntries(Object.entries(fixture.env).filter(([key]) => key.startsWith('KNOWLEDGE_'))) };
  for (const [stream, value] of [['stdout', result.stdout || ''], ['stderr', result.stderr || '']]) {
    const file = path.join(fixture.log, `${number}-doctor.${stream}.log`);
    write(file, value);
    receipt[stream] = { path: path.relative(output, file), ...identity(file), text: value };
  }
  commands.push({ case: fixture.name, ...receipt });
  let report = null;
  try { report = JSON.parse(result.stdout); } catch { /* Abort paths return stderr. */ }
  if (report) assert(!report.checks?.some((item) => item.check === 'update_check'), 'Offline fixture invoked automatic update checks');
  return { ...receipt, report, stderr_text: result.stderr || '' };
}

function lockPath(fixture, lockName, root = fixture.state) {
  return path.join(root, 'locks/v1', `${lockName}.lock`);
}
function lockSnapshot(directory) {
  if (!fs.existsSync(directory)) return { exists: false };
  const st = fs.lstatSync(directory, { bigint: true });
  const files = {};
  for (const entry of fs.readdirSync(directory).sort()) {
    const file = path.join(directory, entry);
    const fst = fs.lstatSync(file, { bigint: true });
    files[entry] = { dev: String(fst.dev), ino: String(fst.ino), mode: String(fst.mode), size: String(fst.size), mtime_ns: String(fst.mtimeNs), ctime_ns: String(fst.ctimeNs),
      ...(fst.isFile() ? { ...identity(file), bytes_base64: fs.readFileSync(file).toString('base64') } : {}) };
  }
  return { exists: true, dev: String(st.dev), ino: String(st.ino), mode: String(st.mode), mtime_ns: String(st.mtimeNs), ctime_ns: String(st.ctimeNs), files };
}
function emptyLock(fixture, lockName, root = fixture.state, malformed = false) {
  const directory = lockPath(fixture, lockName, root);
  fs.mkdirSync(directory, { recursive: true });
  if (malformed) write(path.join(directory, 'owner.json'), '{"fixture_invalid_owner":true}\n');
  else sleep(2200); // Policy grace elapses naturally; never forge timestamps.
  return directory;
}
function scopedTask() {
  return repair.buildTaskScope({ task_id: 'lock-audit-task', session_id: 'lock-audit-session', selected_modules: ['unrelated'], changed_files: ['unrelated/readme.md'] });
}
function assertUnsafe(report, lockName, expectedRootKinds = null) {
  assert(report, 'Doctor did not emit JSON');
  assert.equal(report.lock_safety?.status, 'unsafe', 'Unsafe lock was missing from the Doctor snapshot');
  assert.equal(report.operational_readiness?.status, 'blocked', 'Unsafe lock did not block operational readiness');
  assert.equal(report.operational_readiness?.snapshot_only, true);
  assert.notEqual(report.status, 'healthy', 'Doctor advertised healthy with an unsafe lock');
  assert.equal(report.structural_status, 'healthy', 'A lock problem was misclassified as broken wiki structure');
  const finding = report.lock_safety.findings.find((item) => item.lock_name === lockName);
  assert(finding, 'Missing detailed lock evidence');
  if (expectedRootKinds) assert.deepEqual(finding.root_kinds, expectedRootKinds);
  const debt = report.issues.find((item) => item.code === 'doctor_lock_unsafe');
  assert(debt && debt.severity === 'critical' && debt.repair_class === 'manual_review' && debt.safe_during_current_task === false, 'Unsafe lock was not protected manual debt');
  assert.equal(report.checks.find((item) => item.check === 'lock_safety')?.status, 'fail');
}
function check(name, callback, options = {}) {
  const f = seed(name, options);
  const record = { name, status: 'running', observations: {} };
  try { callback(f, record.observations); record.status = 'pass'; }
  catch (error) { record.status = 'fail'; record.error = { name: error.name, message: error.message, stack: error.stack }; }
  finally {
    for (const handle of f.locks) handle.release();
    write(path.join(f.log, 'fixture-source-after.json'), tree(f.knowledge));
    write(path.join(f.log, 'case.json'), record);
    cases.push(record);
  }
}

check('healthy_self_lock_is_not_debt_and_root_is_deduplicated', (f, observed) => {
  const result = run(f); observed.report = result.report;
  assert.equal(result.exit_code, 0);
  assert.equal(result.report.quality_score, 100);
  assert.equal(result.report.status, 'healthy');
  assert.equal(result.report.lock_safety?.status, 'active');
  assert.equal(result.report.lock_safety?.roots.length, 1);
  assert.equal(result.report.lock_safety?.summary.duplicates_avoided, 1);
  assert.equal(result.report.operational_readiness?.status, 'not_blocked');
  assert.equal(result.report.issues.length, 0);
  assert(!result.report.checks.some((item) => item.check === 'update_check'), 'Fixture invoked update checks');
});
check('live_sync_owner_is_preserved_without_debt', (f, observed) => {
  const handle = manager.acquireContainedLock({ context: { stateRoot: f.state }, rootKind: 'state', rootPath: f.state, lockName: 'sync', purpose: LOCKS.sync.purpose });
  f.locks.push(handle);
  const directory = lockPath(f, 'sync');
  observed.before = lockSnapshot(directory);
  const result = run(f); observed.report = result.report;
  observed.after = lockSnapshot(directory);
  assert.deepEqual(observed.after, observed.before, 'Doctor altered a live lock');
  assert.equal(result.exit_code, 0);
  assert.equal(result.report.quality_score, 100);
  assert.equal(result.report.lock_safety?.status, 'active');
  assert.equal(result.report.operational_readiness?.status, 'not_blocked');
  assert(!result.report.issues.some((item) => item.code === 'doctor_lock_unsafe'));
});
for (const lockName of ['sync', 'agent-task']) check(`ownerless_${lockName}_blocks_readiness_and_preserves_directory`, (f, observed) => {
  const directory = emptyLock(f, lockName);
  observed.before = lockSnapshot(directory);
  const result = run(f); observed.report = result.report;
  observed.after = lockSnapshot(directory);
  assert.deepEqual(observed.after, observed.before, 'Doctor changed unknown-owner lock evidence');
  assert.equal(result.exit_code, 0);
  assertUnsafe(result.report, lockName, ['state', 'project']);
  assert.equal(result.report.lock_safety.findings[0].reason, 'missing');
});
check('malformed_owner_bytes_and_inode_are_retained', (f, observed) => {
  const directory = emptyLock(f, 'sync', f.state, true);
  observed.before = lockSnapshot(directory);
  const result = run(f); observed.report = result.report;
  observed.after = lockSnapshot(directory);
  assert.deepEqual(observed.after, observed.before, 'Doctor rewrote invalid owner evidence');
  assert.equal(result.exit_code, 0);
  assertUnsafe(result.report, 'sync');
});
check('unrelated_content_score_does_not_override_operational_block', (f, observed) => {
  const directory = emptyLock(f, 'agent-task');
  observed.before = lockSnapshot(directory);
  const taskScope = scopedTask();
  const result = run(f, { taskScope }); observed.report = result.report;
  observed.after = lockSnapshot(directory);
  assert.deepEqual(observed.after, observed.before);
  assert.equal(result.exit_code, 0);
  assertUnsafe(result.report, 'agent-task');
  assert.equal(result.report.task_readiness.score, 100, 'Unrelated content score was fabricated');
  assert.equal(result.report.task_readiness.relevant_findings_open, 0);
  assert.equal(result.report.task_readiness.content_status, 'ready');
  assert.equal(result.report.task_readiness.status, 'needs_verification');
  assert.deepEqual(result.report.task_readiness.operational_blockers, ['unsafe_lock_state']);
  const artifact = repair.buildOpportunitiesArtifact({ findings: result.report.findings, scope: taskScope,
    policyResolution: { effective: { ...repair.DEFAULT_REPAIR_POLICY, mode: 'safe-only' } } });
  observed.opportunities = artifact;
  assert(!artifact.opportunities.some((item) => item.code === 'doctor_lock_unsafe' && ['selected', 'repaired'].includes(item.status)), 'Unknown-owner lock was selected for automatic repair');
});
check('doctor_own_ownerless_lock_aborts_and_preserves_report', (f, observed) => {
  assert.equal(run(f).exit_code, 0);
  const quality = path.join(f.state, 'maintenance/quality_report.json');
  observed.quality_before = identity(quality);
  const directory = emptyLock(f, 'doctor');
  observed.before = lockSnapshot(directory);
  const result = run(f); observed.failure = { exit_code: result.exit_code, stderr: result.stderr_text };
  observed.after = lockSnapshot(directory);
  observed.quality_after = identity(quality);
  assert.deepEqual(observed.after, observed.before);
  assert.deepEqual(observed.quality_after, observed.quality_before);
  assert.equal(result.exit_code, 1);
  assert.equal(result.signal, null, 'Unknown ownership must produce an intentional refusal, not a killed Doctor');
  assert.equal(result.spawn_error, null);
  assert.equal(result.report, null, 'A failed acquisition must not publish a fresh Doctor report');
  assert.match(result.stderr_text, /^Error: Lock "doctor" owner metadata is missing; acquisition budget expired with ownership unconfirmed\./);
});
check('split_state_root_detects_sync_without_duplicate_project_finding', (f, observed) => {
  const directory = emptyLock(f, 'sync');
  observed.before = lockSnapshot(directory);
  const result = run(f); observed.report = result.report;
  observed.after = lockSnapshot(directory);
  assert.deepEqual(observed.after, observed.before);
  assert.equal(result.exit_code, 0);
  assertUnsafe(result.report, 'sync', ['state']);
  assert.equal(result.report.lock_safety.roots.length, 2);
  assert.equal(result.report.lock_safety.summary.duplicates_avoided, 0);
}, { splitState: true });
check('project_lock_is_detected_with_separate_state_root', (f, observed) => {
  const directory = emptyLock(f, 'apply-template', f.knowledge, true);
  observed.before = lockSnapshot(directory);
  const result = run(f); observed.report = result.report;
  observed.after = lockSnapshot(directory);
  assert.deepEqual(observed.after, observed.before);
  assert.equal(result.exit_code, 0);
  assertUnsafe(result.report, 'apply-template', ['project']);
}, { splitState: true });
check('missing_project_root_is_unsafe_and_is_not_created', (f, observed) => {
  const missing = path.join(f.repo, 'missing-project', '.knowledge');
  f.env.KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT = missing;
  observed.missing_root = missing;
  assert.equal(fs.existsSync(missing), false);
  const result = run(f); observed.report = result.report;
  observed.missing_root_created = fs.existsSync(missing);
  assert.equal(observed.missing_root_created, false, 'Lock inspection created the missing project root');
  assert.equal(result.exit_code, 0);
  assert.equal(result.report.lock_safety?.status, 'unsafe');
  assert.equal(result.report.operational_readiness?.status, 'blocked');
  assert(result.report.lock_safety.findings.some((item) => item.code === 'unsafe_lock_root' && item.root_kinds.includes('project')));
}, { splitState: true });
check('team_report_names_uninspected_shared_registry_and_flow_roots', (f, observed) => {
  f.env.KNOWLEDGE_MODE = 'team';
  f.env.KNOWLEDGE_TEAM_ROOT = path.join(f.repo, 'shared-team');
  f.env.KNOWLEDGE_WORKSPACE_ID = 'doctor-visibility';
  fs.mkdirSync(f.env.KNOWLEDGE_TEAM_ROOT);
  const result = run(f); observed.report = result.report;
  assert.equal(result.exit_code, 0);
  assert.equal(result.report.mode, 'team');
  assert.equal(result.report.structural_status, 'healthy');
  assert(!result.report.issues.some((item) => item.code === 'doctor_lock_unsafe'));
  assert.equal(result.report.operational_readiness?.status, 'not_blocked');
  assert.deepEqual(result.report.operational_readiness?.root_kinds, ['state', 'project']);
  assert.deepEqual(result.report.operational_readiness?.not_inspected, ['shared_team_registry_root', 'repository_team_flow_root', 'maintainer_system_root']);
}, { splitState: true });
check('unrelated_task_without_operational_block_remains_ready', (f, observed) => {
  const result = run(f, { taskScope: scopedTask() }); observed.report = result.report;
  assert.equal(result.exit_code, 0);
  assert.equal(result.report.task_readiness.score, 100);
  assert.equal(result.report.task_readiness.status, 'ready');
  assert(!result.report.task_readiness.operational_blockers?.length);
});

const after = tree(systemRoot);
write(path.join(output, 'source-before.json'), before);
write(path.join(output, 'source-after.json'), after);
const summary = { schema_version: 'knowledge-doctor-lock-safety-regression.v1', actual_source: systemRoot,
  source_package: JSON.parse(fs.readFileSync(path.join(systemRoot, 'package.json'), 'utf8')),
  test: identity(__filename), node: { executable: process.execPath, ...nodeBefore },
  source_unchanged: JSON.stringify(before) === JSON.stringify(after), node_unchanged: JSON.stringify(nodeBefore) === JSON.stringify(identity(process.execPath)),
  passed: cases.filter((item) => item.status === 'pass').length, total: cases.length, cases, commands,
  limits: ['RC4 integration regression; no missing RC5 or historical Linux execution claim', 'Every fixture explicitly disables update checks', 'Operational lock snapshot covers state/project roots, not shared team registry/repo flow roots', 'No unknown-owner cleanup or identity replacement', 'Generic downstream taskReadiness recomputation is unchanged'] };
summary.status = summary.passed === summary.total && summary.source_unchanged && summary.node_unchanged ? 'pass' : 'fail';
write(path.join(output, 'summary.json'), summary);
console.log(JSON.stringify({ status: summary.status, passed: summary.passed, total: summary.total, source_unchanged: summary.source_unchanged, node_unchanged: summary.node_unchanged }));
process.exitCode = summary.status === 'pass' ? 0 : 1;
