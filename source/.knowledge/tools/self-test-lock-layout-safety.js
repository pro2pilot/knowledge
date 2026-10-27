#!/usr/bin/env node
'use strict';

// Offline regressions for read-only lock layout diagnostics. The fixture root
// is retained for evidence; no unknown lock, obstruction, link, or fixture is
// removed. The positive control releases only the lock it actually acquired.
// --source allows the same assertions to demonstrate the defect on a baseline.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const option = name => process.argv.slice(2).find(value => value.startsWith(`--${name}=`))?.slice(name.length + 3);
const source = fs.realpathSync(path.resolve(option('source') || path.join(__dirname, '..')));
const parent = fs.realpathSync(path.resolve(option('fixture-parent') || os.tmpdir()));
assert(fs.lstatSync(parent).isDirectory(), 'Fixture parent must be a physical directory');
const root = fs.mkdtempSync(path.join(parent, 'knowledge-lock-layout-'));
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const pinPaths = ['package.json', 'tools/lib/contained-lock-manager.js', 'tools/lib/lock-policy.js',
  'tools/lib/json-store.js', 'tools/lib/team-store.js', 'tools/lib/semantic-json.js', 'tools/doctor.js'];
const sourcePins = () => Object.fromEntries(pinPaths.map(file => [file, digest(fs.readFileSync(path.join(source, file)))]));
const beforeSource = sourcePins();
const beforeNode = digest(fs.readFileSync(process.execPath));
const manager = require(path.join(source, 'tools/lib/contained-lock-manager'));
const { LOCKS } = require(path.join(source, 'tools/lib/lock-policy'));
const team = require(path.join(source, 'tools/lib/team-store'));
const semantic = require(path.join(source, 'tools/lib/semantic-json'));
const checks = [];
let sequence = 0;

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function snapshot(file) {
  let stat;
  try { stat = fs.lstatSync(file, { bigint: true }); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  const value = { dev: String(stat.dev), ino: String(stat.ino), mode: String(stat.mode),
    nlink: String(stat.nlink), size: String(stat.size), mtime_ns: String(stat.mtimeNs), ctime_ns: String(stat.ctimeNs) };
  if (stat.isSymbolicLink()) return { ...value, type: 'symlink', target: fs.readlinkSync(file) };
  if (stat.isFile()) return { ...value, type: 'file', sha256: digest(fs.readFileSync(file)) };
  assert(stat.isDirectory(), `Unexpected special fixture object: ${file}`);
  return { ...value, type: 'directory', children: Object.fromEntries(fs.readdirSync(file).sort()
    .map(name => [name, snapshot(path.join(file, name))])) };
}
function fixture(name) {
  const directory = path.join(root, `${String(++sequence).padStart(2, '0')}-${name}`);
  const stateRoot = path.join(directory, 'state');
  const projectKnowledgeRoot = path.join(directory, 'project');
  fs.mkdirSync(stateRoot, { recursive: true });
  fs.mkdirSync(projectKnowledgeRoot);
  return { directory, stateRoot, projectKnowledgeRoot };
}
function request(context) {
  return { context, rootKind: 'project', rootPath: context.projectKnowledgeRoot,
    lockName: 'apply-template', purpose: LOCKS['apply-template'].purpose, timeoutMs: 100 };
}
function inspectReadOnly(context) {
  const before = snapshot(context.directory);
  const results = {
    context: manager.inspectContextLockSafety(context),
    named: manager.inspectLockSafety(request(context)),
    all: manager.inspectAllLockSafety({ rootPath: context.projectKnowledgeRoot, rootKind: 'project' }),
  };
  assert.deepEqual(snapshot(context.directory), before, 'Lock inspection mutated its fixture');
  return results;
}
function summarize(results) {
  return Object.fromEntries(Object.entries(results).map(([name, value]) => [name,
    { status: value.status, findings: value.findings }]));
}
function check(name, fn) {
  const observations = {};
  try { fn(observations); checks.push({ name, status: 'pass', observations }); }
  catch (error) { checks.push({ name, status: 'fail', observations,
    error: { code: error.code || null, message: error.message, stack: error.stack } }); }
}

check('missing layout is safe and is not initialized by inspection', observations => {
  const context = fixture('missing-layout');
  const results = inspectReadOnly(context);
  observations.inspections = summarize(results);
  for (const value of Object.values(results)) assert.equal(value.status, 'safe');
  assert.equal(fs.existsSync(path.join(context.stateRoot, 'locks')), false);
  assert.equal(fs.existsSync(path.join(context.projectKnowledgeRoot, 'locks')), false);
});

check('missing context and team roots remain absent', observations => {
  const context = fixture('missing-roots');
  const missingState = path.join(context.directory, 'absent-state');
  const missingTeam = path.join(context.directory, 'absent-team');
  const before = snapshot(context.directory);
  const contextResult = manager.inspectContextLockSafety({ ...context, stateRoot: missingState });
  const teamResult = team.listTeamStatus(missingTeam);
  observations.context_status = contextResult.status;
  observations.team_registry_lock = teamResult.locks.registry;
  assert.equal(contextResult.status, 'unsafe');
  assert(contextResult.findings.some(finding => finding.code === 'unsafe_lock_root'));
  assert.equal(teamResult.locks.registry, null);
  assert.deepEqual(snapshot(context.directory), before);
  assert.equal(fs.existsSync(missingState), false);
  assert.equal(fs.existsSync(missingTeam), false);
});

check('physical reserved directories and retained evidence are safe', observations => {
  const context = fixture('valid-reserved');
  const version = path.join(context.projectKnowledgeRoot, 'locks/v1');
  for (const name of ['.stale', '.release']) write(path.join(version, name, 'retained.txt'), 'retained fixture evidence\n');
  const results = inspectReadOnly(context);
  observations.inspections = summarize(results);
  for (const value of Object.values(results)) assert.equal(value.status, 'safe');
  const beforeStale = snapshot(path.join(version, '.stale/retained.txt'));
  const beforeRelease = snapshot(path.join(version, '.release/retained.txt'));
  const handle = manager.acquireContainedLock(request(context));
  observations.release = handle.release();
  assert.equal(observations.release.status, 'released');
  assert.deepEqual(snapshot(path.join(version, '.stale/retained.txt')), beforeStale);
  assert.deepEqual(snapshot(path.join(version, '.release/retained.txt')), beforeRelease);
});

const parents = [
  ['locks', 'locks_parent_unsafe'],
  ['locks/v1', 'version_parent_unsafe'],
  ['locks/v1/.stale', 'stale_parent_unsafe'],
  ['locks/v1/.release', 'release_parent_unsafe'],
];
for (const [relative, reason] of parents) {
  for (const kind of ['file', 'symlink', 'dangling-symlink']) {
    check(`${relative} as ${kind} is unsafe and acquisition remains denied`, observations => {
      const context = fixture(`${relative.replaceAll('/', '-')}-${kind}`);
      const obstruction = path.join(context.projectKnowledgeRoot, relative);
      fs.mkdirSync(path.dirname(obstruction), { recursive: true });
      const target = path.join(context.directory, 'link-target');
      if (kind === 'file') write(obstruction, 'reserved lock path is a regular file\n');
      else {
        if (kind === 'symlink') write(path.join(target, 'sentinel.txt'), 'link target must be preserved\n');
        // Junctions provide the corresponding Windows directory-reparse case.
        fs.symlinkSync(target, obstruction, process.platform === 'win32' ? 'junction' : 'dir');
      }
      const beforeObstruction = snapshot(obstruction);
      const beforeTarget = snapshot(target);
      const results = inspectReadOnly(context);
      observations.inspections = summarize(results);
      let handle = null;
      let denied = null;
      try { handle = manager.acquireContainedLock(request(context)); }
      catch (error) { denied = { code: error.code, os_code: error.os_code || null }; }
      observations.acquisition_error = denied;
      assert.equal(handle, null, 'An unsafe layout unexpectedly acquired a lock');
      assert.equal(denied?.code, 'unsafe_lock_parent');
      assert.deepEqual(snapshot(obstruction), beforeObstruction, 'Acquisition altered the obstruction');
      assert.deepEqual(snapshot(target), beforeTarget, 'Acquisition altered or created the link target');
      observations.obstruction_and_target_unchanged = true;
      for (const value of Object.values(results)) {
        assert.equal(value.status, 'unsafe');
        assert(value.findings.some(finding => finding.code === 'unsafe_lock_parent' && finding.reason === reason));
      }
    });
  }
}

check('shared state/project root is deduplicated and unsafe', observations => {
  const context = fixture('shared-root');
  context.stateRoot = context.projectKnowledgeRoot;
  write(path.join(context.projectKnowledgeRoot, 'locks/v1/.release'), 'shared root obstruction\n');
  const before = snapshot(context.directory);
  const result = manager.inspectContextLockSafety(context);
  observations.status = result.status;
  observations.summary = result.summary;
  assert.deepEqual(snapshot(context.directory), before);
  assert.equal(result.status, 'unsafe');
  assert.equal(result.roots.length, 1);
  assert.equal(result.summary.duplicates_avoided, 1);
  assert.deepEqual(result.findings[0].root_kinds, ['state', 'project']);
});

check('young ownerless lock retains publication grace without mutation', observations => {
  const context = fixture('publication-grace');
  const lock = path.join(context.projectKnowledgeRoot, 'locks/v1/apply-template.lock');
  fs.mkdirSync(lock, { recursive: true });
  const results = inspectReadOnly(context);
  observations.inspections = summarize(results);
  for (const value of Object.values(results)) assert.equal(value.status, 'active');
  assert.equal(results.named.current.owner, null);
  assert.deepEqual(fs.readdirSync(lock), []);
});

check('existing shared registry layout error is visible without status writes', observations => {
  const context = fixture('team-registry');
  const teamRoot = path.join(context.directory, 'team');
  write(path.join(teamRoot, 'locks/v1/.stale'), 'registry layout obstruction\n');
  const before = snapshot(context.directory);
  const result = team.listTeamStatus(teamRoot);
  observations.registry = result.locks.registry;
  observations.warnings = result.warnings;
  assert.deepEqual(snapshot(context.directory), before);
  assert.equal(result.locks.registry.status, 'unsafe');
  assert(result.locks.registry.findings.some(finding => finding.reason === 'stale_parent_unsafe'));
  assert(result.warnings.some(warning => warning.includes('team-registry') && warning.includes('unsafe_lock_parent')));
});

check('Doctor blocks unsafe project layout with separate state and preserves task content score', observations => {
  const context = fixture('doctor');
  const target = path.join(context.directory, 'app');
  const knowledge = path.join(target, '.knowledge');
  fs.mkdirSync(target);
  // A used source/install can retain reserved lock directories after release.
  // Runtime locks are not fixture input; leave them untouched in their source.
  fs.cpSync(source, knowledge, { recursive: true, errorOnExist: true, force: false,
    filter: file => path.relative(source, file).split(path.sep)[0] !== 'locks' });
  const now = new Date().toISOString();
  const src = 'module.exports = 1;\n';
  write(path.join(target, 'src/main.js'), src);
  write(path.join(knowledge, 'config.yaml'), 'updates:\n  enabled: false\n');
  const card = { module_id: 'root', path: '.', card: '.knowledge/modules/root.json', key_files: ['src/main.js'], evidence_files: [], confidence: 'high', verification_status: 'verified_from_code' };
  for (const [relative, value] of Object.entries({
    'project_index.json': { generated_at: now, modules: ['root'] },
    'modules/module_registry.json': { modules: [card] }, 'modules/root.json': card,
    'maintenance/concurrency_policy.json': {}, 'maps/critical_paths.json': { paths: [] },
    'evidence/file_facts.json': { facts: [{ file: 'src/main.js', evidence: { source_sha256: digest(src) } }] },
    'wiki/index.md': '# Index\n',
  })) write(path.join(knowledge, relative), value);
  for (const [relative, value] of Object.entries({
    'freshness.json': { generated_at: now, tracked_files: [{ path: 'src/main.js', sha256: digest(src), status: 'clean' }], artifact_dependencies: {}, artifact_statuses: {} },
    'maintenance/trust_report.json': { generated_at: now, modules: { trusted: ['root'], suspect: [], low_confidence: [] } },
    'maintenance/handoff_summary.json': { generated_at: now }, 'maintenance/routing_bundle.json': { generated_at: now, modules: [] },
    'maps/file_criticality.json': { files: [], coverage_by_module: {} },
    'maps/wiki_graph.json': { generated_at: now, status: 'healthy', structural_status: 'healthy', broken_edge_count: 0 },
    'maintenance/wiki_lint_report.json': { generated_at: now, status: 'healthy', structural_status: 'healthy' },
    'maintenance/secret_scan_report.json': { generated_at: now, status: 'clean', findings_total: 0, by_severity: {} },
    'search/index.json': { generated_at: now },
    'maintenance/external_memory_status.json': { generated_at: now, providers: [], source_of_truth_policy: { external_memory_source_of_truth: false, external_memory_can_raise_trust: false, external_memory_can_overwrite_curated_knowledge: false } },
    'maintenance/stale_items.json': { items: [] }, 'maintenance/repair_queue.json': { queue: [] },
  })) write(path.join(context.stateRoot, relative), value);
  fs.mkdirSync(path.join(context.stateRoot, 'maintenance/events'), { recursive: true });
  const obstruction = path.join(knowledge, 'locks/v1/.release');
  write(obstruction, 'Doctor must report this project layout obstruction\n');
  const before = snapshot(obstruction);
  const overrides = { KNOWLEDGE_MODE: 'repo', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_SYSTEM_ROOT: source,
    KNOWLEDGE_TARGET_ROOT: target, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: knowledge, KNOWLEDGE_STATE_ROOT: context.stateRoot,
    KNOWLEDGE_AGENT_ID: 'lock-layout-regression', KNOWLEDGE_LOCK_TIMEOUT_MS: '100', KNOWLEDGE_NO_OPEN: '1', CI: 'true' };
  const saved = Object.fromEntries(Object.keys(overrides).map(key => [key, process.env[key]]));
  let report;
  try {
    Object.assign(process.env, overrides);
    const repair = require(path.join(source, 'tools/lib/repair-on-touch'));
    const taskScope = repair.buildTaskScope({ task_id: 'layout-task', session_id: 'layout-session',
      selected_modules: ['unrelated'], changed_files: ['unrelated/readme.md'] });
    report = require(path.join(source, 'tools/doctor.js'))({ quiet: true, taskScope });
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
  write(path.join(context.directory, 'doctor-report.json'), report);
  observations.report_path = path.join(context.directory, 'doctor-report.json');
  observations.status = report.status;
  observations.quality_score = report.quality_score;
  observations.operational_readiness = report.operational_readiness;
  observations.lock_check = report.checks.find(item => item.check === 'lock_safety');
  observations.task_readiness = report.task_readiness;
  assert.deepEqual(snapshot(obstruction), before);
  assert.equal(report.lock_safety.status, 'unsafe');
  assert.equal(report.operational_readiness.status, 'blocked');
  assert.equal(report.operational_readiness.snapshot_only, true);
  assert.notEqual(report.status, 'healthy');
  assert.equal(report.structural_status, 'healthy');
  assert.equal(observations.lock_check.status, 'fail');
  const finding = report.findings.find(item => item.code === 'doctor_lock_unsafe');
  assert.equal(finding?.repair_class, 'manual_review');
  assert.equal(finding?.safe_during_current_task, false);
  assert.equal(report.task_readiness.score, 100);
  assert.equal(report.task_readiness.content_status, 'ready');
  assert.equal(report.task_readiness.status, 'needs_verification');
  assert.deepEqual(report.task_readiness.operational_blockers, ['unsafe_lock_state']);
  assert.equal(semantic.inspectSemanticJson(report).ok, false);
  assert.equal(report.checks.some(item => item.check === 'update_check'), false);
});

check('audited source and original Node bytes remain unchanged', observations => {
  observations.source_pins = sourcePins();
  assert.deepEqual(observations.source_pins, beforeSource);
  assert.equal(digest(fs.readFileSync(process.execPath)), beforeNode);
});

const failed = checks.filter(item => item.status === 'fail').length;
console.log(JSON.stringify({ schema_version: 'knowledge-lock-layout-regressions.v1',
  status: failed ? 'fail' : 'pass', total: checks.length, passed: checks.length - failed, failed,
  source, node: { executable: process.execPath, version: process.version, platform: process.platform, sha256: beforeNode },
  source_pins: beforeSource, retained_fixture_root: root, fixture_cleanup: 'not_attempted', checks }, null, 2));
process.exitCode = failed ? 1 : 0;
