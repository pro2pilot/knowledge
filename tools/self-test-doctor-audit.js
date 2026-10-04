#!/usr/bin/env node
'use strict';

// Offline integration regressions for Doctor, tracked-source freshness and
// guarded maintenance. Every command targets a disposable repository.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { withTempFixture } = require('./lib/strict-temp-cleanup');
const { canonicalWikiStatus } = require('./lib/wiki-status');
const { buildTaskScope, taskReadiness } = require('./lib/repair-on-touch');
const systemRoot = path.resolve(__dirname, '..');
const checks = [];
const skipped = [];
let commands = 0;

function assert(value, message) { if (!value) throw new Error(message); }
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function hash(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function seed(outer, options = {}) {
  const root = path.join(outer, 'repository');
  const knowledge = path.join(root, '.knowledge');
  fs.mkdirSync(root, { recursive: true });
  fs.cpSync(systemRoot, knowledge, { recursive: true });
  // Doctor's normal update policy may perform a network check. Fixtures
  // explicitly exercise only its documented offline configuration.
  write(path.join(knowledge, 'config.yaml'), 'updates:\n  enabled: false\n');
  const fixture = {
    outer, root, knowledge, state: knowledge,
    write: (relative, value) => write(path.join(knowledge, relative), value),
    read: (relative) => JSON.parse(fs.readFileSync(path.join(knowledge, relative), 'utf8')),
    source: (relative, value) => write(path.join(root, relative), value)
  };
  if (options.empty) return fixture;
  const now = new Date().toISOString();
  fixture.source('src/main.js', 'module.exports = 1;\n');
  const card = { module_id: 'root', path: '.', card: '.knowledge/modules/root.json', key_files: ['src/main.js'], evidence_files: [], confidence: 'high', verification_status: 'verified_from_code' };
  const documents = {
    'project_index.json': { generated_at: now, modules: ['root'] },
    'modules/module_registry.json': { modules: [card] },
    'modules/root.json': card,
    'freshness.json': { generated_at: now, hash_algorithm: 'sha256', tracked_files: [{ path: 'src/main.js', sha256: hash(path.join(root, 'src/main.js')), status: 'clean' }], artifact_dependencies: {}, artifact_statuses: {} },
    'maintenance/concurrency_policy.json': {},
    'maps/critical_paths.json': { paths: [] },
    'evidence/file_facts.json': { facts: [{ file: 'src/main.js', evidence: { source_sha256: hash(path.join(root, 'src/main.js')) } }] },
    'maintenance/trust_report.json': { generated_at: now, modules: { trusted: ['root'], suspect: [], low_confidence: [] } },
    'maintenance/handoff_summary.json': { generated_at: now },
    'maintenance/routing_bundle.json': { generated_at: now, modules: [] },
    'maps/file_criticality.json': { files: [{ path: 'src/main.js', classification: 'important' }], coverage_by_module: {} },
    'maps/wiki_graph.json': { generated_at: now, status: 'healthy', structural_status: 'healthy', broken_edge_count: 0 },
    'maintenance/wiki_lint_report.json': { generated_at: now, status: 'healthy', structural_status: 'healthy' },
    'maintenance/secret_scan_report.json': { generated_at: now, status: 'clean', findings_total: 0, by_severity: {} },
    'search/index.json': { generated_at: now },
    'maintenance/external_memory_status.json': { generated_at: now, providers: [], source_of_truth_policy: { external_memory_source_of_truth: false, external_memory_can_raise_trust: false, external_memory_can_overwrite_curated_knowledge: false } },
    'maintenance/stale_items.json': { items: [] },
    'maintenance/repair_queue.json': { queue: [] },
    'wiki/index.md': '# Index\n'
  };
  for (const [file, value] of Object.entries(documents)) fixture.write(file, value);
  fs.mkdirSync(path.join(knowledge, 'maintenance/events'), { recursive: true });
  return fixture;
}
function run(fixture, tool, args = [], env = {}) {
  commands += 1;
  const result = spawnSync(process.execPath, [path.join(systemRoot, 'tools', tool), ...args], {
    cwd: fixture.root, encoding: 'utf8', timeout: 30000, maxBuffer: 8 * 1024 * 1024,
    env: {
      ...process.env,
      KNOWLEDGE_MODE: 'repo', KNOWLEDGE_TEAM_ROOT: '', KNOWLEDGE_WORKSPACE_ID: '',
      KNOWLEDGE_SYSTEM_ROOT: systemRoot,
      KNOWLEDGE_TARGET_ROOT: fixture.root,
      KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: fixture.knowledge,
      KNOWLEDGE_STATE_ROOT: fixture.state,
      KNOWLEDGE_AGENT_ID: 'doctor-audit-self-test',
      KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1',
      KNOWLEDGE_CHANGED_FILES: '[]', KNOWLEDGE_FULL_SCAN: '0', KNOWLEDGE_DISCOVER_NEW: '0',
      ...env
    }
  });
  let json = null;
  try { json = JSON.parse(result.stdout); } catch { /* The failure path may have stderr only. */ }
  return { ...result, json };
}
function successful(fixture, tool, args = [], env = {}) {
  const result = run(fixture, tool, args, env);
  assert(result.status === 0, `${tool} exited ${result.status}: ${result.stderr || result.stdout}`);
  assert(result.json && typeof result.json === 'object', `${tool} did not return a JSON report`);
  return result.json;
}
function finding(report, code) { return (report.issues || []).find((item) => item.code === code); }
function check(name, callback, options = {}) {
  withTempFixture({
    baseDir: process.env.KNOWLEDGE_DOCTOR_AUDIT_TMPDIR || os.tmpdir(),
    prefix: 'knowledge-doctor-audit-',
    evidenceDir: process.env.KNOWLEDGE_DOCTOR_AUDIT_FAILURE_DIR || null,
    evidenceLabel: name
  }, (outer) => callback(seed(outer, options)));
  checks.push(name);
}

function main() {
  check('healthy_fixture_is_100_and_healthy', (f) => {
    const report = successful(f, 'doctor.js');
    assert(report.quality_score === 100 && report.status === 'healthy' && !report.issues.length, 'healthy fixture unexpectedly has debt');
  });
  check('empty_install_reports_missing_state_without_crash', (f) => {
    const report = successful(f, 'doctor.js');
    assert(finding(report, 'missing_required_file') && report.status !== 'healthy', 'empty project was accepted as healthy');
  }, { empty: true });
  check('doctor_detects_unsynced_source_and_preserves_scan_baseline', (f) => {
    const before = hash(path.join(f.knowledge, 'freshness.json'));
    f.source('src/main.js', 'module.exports = 2;\n');
    const report = successful(f, 'doctor.js');
    assert(finding(report, 'tracked_file_needs_recheck') && report.status === 'usable_with_warnings', 'Doctor missed physical source drift');
    assert(finding(report, 'tracked_file_needs_recheck').affected_artifacts.every((artifact) => artifact === 'src/main.js'), 'source finding required mutable detector state as immutable verification evidence');
    assert(hash(path.join(f.knowledge, 'freshness.json')) === before, 'Doctor rewrote its freshness baseline');
    const scope = buildTaskScope({ task_id: 'audit', session_id: 'audit', selected_modules: ['root'], changed_files: ['src/main.js'] });
    const readiness = taskReadiness(report.issues, scope);
    assert(readiness.score < 100, 'task readiness ignored its changed source');
  });
  check('repeated_sync_preserves_unverified_change_and_lifecycle', (f) => {
    assert(successful(f, 'sync-tracked.js').trusted_modules.includes('root'), 'valid current evidence did not establish the positive baseline');
    f.source('src/main.js', 'module.exports = 2;\n');
    successful(f, 'sync-tracked.js');
    const firstQueue = f.read('maintenance/stale_items.json').items.filter((item) => item.code === 'tracked_file_changed');
    const result = successful(f, 'sync-tracked.js');
    const secondQueue = f.read('maintenance/stale_items.json').items.filter((item) => item.code === 'tracked_file_changed');
    assert(f.read('freshness.json').tracked_files[0].status === 'changed', 'second scan cleared unverified source');
    assert(!result.trusted_modules.includes('root') && result.suspect_modules.includes('root'), 'second scan promoted stale facts to trusted');
    assert(firstQueue.length === 1 && secondQueue.length === 1 && firstQueue[0].lifecycle_id === secondQueue[0].lifecycle_id && firstQueue[0].occurrence === secondQueue[0].occurrence, 'repeated scan duplicated or replaced the active lifecycle');
  });
  check('unknown_freshness_state_is_not_promoted_to_clean', (f) => {
    const freshness = f.read('freshness.json');
    freshness.tracked_files[0].status = 'unknown_future_status';
    f.write('freshness.json', freshness);
    assert(finding(successful(f, 'doctor.js'), 'tracked_file_needs_recheck'), 'Doctor accepted unknown source status');
    const result = successful(f, 'sync-tracked.js');
    assert(f.read('freshness.json').tracked_files[0].status === 'needs_recheck' && !result.trusted_modules.includes('root'), 'sync promoted unknown source status');
  });
  for (const [name, evidence] of [['hashless', {}], ['stale_hash', { source_sha256: '0'.repeat(64) }]]) {
    check(`${name}_facts_do_not_cover_source`, (f) => {
      f.write('evidence/file_facts.json', { facts: [{ file: 'src/main.js', evidence }] });
      const result = successful(f, 'sync-tracked.js');
      assert(!result.trusted_modules.includes('root'), 'unbound file fact granted trust');
      assert(f.read('maintenance/trust_report.json').uncovered_important_files.some((item) => item.file === 'src/main.js'), 'unbound file fact counted as coverage');
    });
  }
  check('deleted_then_restored_source_requires_reverification', (f) => {
    const source = path.join(f.root, 'src/main.js');
    const original = fs.readFileSync(source);
    fs.rmSync(source);
    assert(successful(f, 'sync-tracked.js').missing_files.includes('src/main.js'), 'deleted tracked file was missed');
    assert(finding(successful(f, 'doctor.js'), 'tracked_file_missing'), 'Doctor did not report missing source');
    fs.writeFileSync(source, original);
    const result = successful(f, 'sync-tracked.js');
    assert(f.read('freshness.json').tracked_files[0].status === 'needs_recheck' && !result.trusted_modules.includes('root'), 'restoration silently recertified source');
  });
  check('rename_tracks_new_path_and_keeps_old_missing', (f) => {
    fs.renameSync(path.join(f.root, 'src/main.js'), path.join(f.root, 'src/renamed.js'));
    const result = successful(f, 'sync-tracked.js', ['--scan', '--discover']);
    assert(result.missing_files.includes('src/main.js') && result.new_files.some((item) => item.path === 'src/renamed.js'), 'rename did not preserve both sides of the change');
    assert(f.read('freshness.json').tracked_files.find((item) => item.path === 'src/renamed.js').status === 'needs_recheck', 'renamed source was trusted automatically');
  });
  check('generated_backup_and_dependency_paths_are_excluded', (f) => {
    const ignored = ['dist/generated.js', 'build/generated.js', 'node_modules/pkg/index.js', '.knowledge_backup_old/src/app.js', 'qa-runs/result.js', '.tmp-copy/index.js'];
    for (const file of ignored) f.source(file, 'module.exports = 7;\n');
    const freshness = f.read('freshness.json');
    freshness.tracked_files.push(...ignored.map((file) => ({ path: file, sha256: hash(path.join(f.root, file)), status: 'changed' })));
    f.write('freshness.json', freshness);
    const result = successful(f, 'sync-tracked.js', ['--scan', '--discover'], { KNOWLEDGE_CHANGED_FILES: JSON.stringify(ignored) });
    assert(ignored.every((file) => result.ignored_tracked_paths_removed.includes(file)), 'old generated tracking was retained');
    assert(!result.new_files.some((item) => ignored.includes(item.path)) && f.read('freshness.json').tracked_files.length === 1, 'generated paths were rediscovered');
  });
  check('critical_classification_protects_doctor_and_sync_findings', (f) => {
    f.write('maps/file_criticality.json', { files: [{ path: 'src/main.js', classification: 'critical' }], coverage_by_module: {} });
    f.source('src/main.js', 'module.exports = 2;\n');
    successful(f, 'sync-tracked.js');
    const syncFinding = f.read('maintenance/stale_items.json').items.find((item) => item.code === 'tracked_file_changed');
    assert(syncFinding.critical_path === true, 'sync did not preserve critical classification');
    const report = successful(f, 'doctor.js');
    assert(finding(report, 'suspect_module').critical_path && finding(report, 'tracked_file_needs_recheck').critical_path, 'Doctor lost critical-path protection');
  });
  check('security_paths_protect_doctor_and_sync_findings', (f) => {
    f.source('src/auth.js', 'module.exports = false;\n');
    const freshness = f.read('freshness.json');
    freshness.tracked_files.push({ path: 'src/auth.js', sha256: hash(path.join(f.root, 'src/auth.js')), status: 'needs_recheck' });
    f.write('freshness.json', freshness);
    successful(f, 'sync-tracked.js');
    assert(f.read('maintenance/stale_items.json').items.find((item) => item.code === 'tracked_file_needs_recheck' && item.affected_artifacts.includes('src/auth.js')).security_sensitive, 'sync lost auth-file protection');
    assert(successful(f, 'doctor.js').issues.find((item) => item.code === 'tracked_file_needs_recheck' && item.artifact === 'src/auth.js').security_sensitive, 'Doctor lost auth-file protection');
  });
  const malformed = [
    ['registry_object', 'modules/module_registry.json', { modules: {} }],
    ['registry_null_entry', 'modules/module_registry.json', { modules: [null] }],
    ['module_card_null', 'modules/root.json', null],
    ['freshness_null_entry', 'freshness.json', { tracked_files: [null] }],
    ['freshness_escaping_path', 'freshness.json', { tracked_files: [{ path: '../outside.js', status: 'clean' }] }],
    ['trust_suspect_string', 'maintenance/trust_report.json', { modules: { suspect: 'root' } }],
    ['external_null', 'maintenance/external_memory_status.json', null],
    ['external_providers_object', 'maintenance/external_memory_status.json', { providers: {} }],
    ['secret_null', 'maintenance/secret_scan_report.json', null],
    ['criticality_files_object', 'maps/file_criticality.json', { files: {} }],
    ['wiki_graph_null', 'maps/wiki_graph.json', null],
    ['wiki_lint_null', 'maintenance/wiki_lint_report.json', null],
    ['queue_null', 'maintenance/stale_items.json', null]
  ];
  for (const [name, relative, value] of malformed) {
    check(`doctor_reports_${name}_without_rewriting_input`, (f) => {
      f.write(relative, value);
      const before = hash(path.join(f.knowledge, relative));
      const report = successful(f, 'doctor.js');
      assert(finding(report, 'invalid_artifact_shape') && report.status !== 'healthy', 'invalid shape did not produce a usable diagnostic');
      assert(hash(path.join(f.knowledge, relative)) === before, 'Doctor rewrote malformed input');
    });
  }
  for (const relative of ['maintenance/stale_items.json', 'maintenance/repair_queue.json', 'freshness.json']) {
    check(`invalid_json_preserved_${relative.replace(/[/.]/g, '_')}`, (f) => {
      f.write(relative, '{broken');
      const before = hash(path.join(f.knowledge, relative));
      const otherQueue = relative === 'maintenance/stale_items.json' ? 'maintenance/repair_queue.json' : 'maintenance/stale_items.json';
      const pairedBefore = hash(path.join(f.knowledge, otherQueue));
      const report = successful(f, 'doctor.js');
      assert(finding(report, 'invalid_json') && hash(path.join(f.knowledge, relative)) === before, 'Doctor erased invalid JSON');
      if (relative !== 'freshness.json') {
        assert(report.queue_reconciliation_status === 'skipped_invalid_input' && hash(path.join(f.knowledge, otherQueue)) === pairedBefore, 'Doctor mutated half of an invalid queue pair');
      }
      const sync = run(f, 'sync-tracked.js');
      assert(sync.status !== 0 && hash(path.join(f.knowledge, relative)) === before, 'sync overwrote corrupt persisted state');
    });
  }
  check('missing_source_not_satisfied_by_knowledge_copy', (f) => {
    fs.rmSync(path.join(f.root, 'src/main.js'));
    f.write('src/main.js', 'module.exports = 1;\n');
    assert(finding(successful(f, 'doctor.js'), 'tracked_file_missing'), 'knowledge-local copy masked missing repository source');
  });
  check('directory_cannot_replace_a_tracked_file', (f) => {
    fs.rmSync(path.join(f.root, 'src/main.js'));
    fs.mkdirSync(path.join(f.root, 'src/main.js'));
    assert(finding(successful(f, 'doctor.js'), 'tracked_file_missing'), 'Doctor treated a directory as a source file');
    assert(successful(f, 'sync-tracked.js').missing_files.includes('src/main.js'), 'sync crashed or accepted directory source');
  });
  check('directory_touch_hint_is_not_hashed', (f) => {
    fs.mkdirSync(path.join(f.root, 'other.js'));
    const report = successful(f, 'sync-tracked.js', [], { KNOWLEDGE_CHANGED_FILES: JSON.stringify(['other.js', '../outside.js']) });
    assert(!report.new_files.length, 'unsafe or directory touch hint was tracked');
  });
  check('separate_state_root_does_not_shadow_project_registry', (f) => {
    f.state = path.join(f.outer, 'state');
    fs.mkdirSync(f.state, { recursive: true });
    for (const relative of ['freshness.json', 'maintenance', 'maps/file_criticality.json', 'maps/wiki_graph.json', 'search']) {
      const source = path.join(f.knowledge, relative), target = path.join(f.state, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.cpSync(source, target, { recursive: true });
    }
    write(path.join(f.state, 'modules/module_registry.json'), { modules: [] });
    const report = successful(f, 'doctor.js');
    assert(report.checks.find((item) => item.check === 'module_registry_non_empty').modules === 1, 'state copy shadowed authoritative project registry');
    assert(report.checks.find((item) => item.check === 'tracked_files_exist').tracked_files === 1, 'Doctor lost the separate freshness state');
  });
  check('missing_wiki_half_cannot_report_healthy', (f) => {
    fs.rmSync(path.join(f.knowledge, 'maps/wiki_graph.json'));
    const report = successful(f, 'doctor.js');
    assert(report.structural_status === 'usable_with_warnings' && report.status === 'usable_with_warnings', 'healthy lint hid an absent graph');
    assert(canonicalWikiStatus(null, null) === 'usable_with_warnings', 'null wiki input should not throw');
    assert(canonicalWikiStatus({}, { status: 'healthy' }) === 'usable_with_warnings', 'healthy graph hid absent lint');
    assert(canonicalWikiStatus({ status: 'healthy' }, { broken_edges: [{}] }) === 'structurally_broken', 'partial input downgraded observed broken edges');
  });
  check('structural_failure_overrides_both_status_views', (f) => {
    f.write('maps/wiki_graph.json', { generated_at: new Date().toISOString(), structural_status: 'structurally_broken', broken_edge_count: 1 });
    const report = successful(f, 'doctor.js');
    assert(report.status === 'structurally_broken' && report.global.status === 'structurally_broken', 'global summary contradicted structural failure');
  });
  check('routing_refresh_error_is_persisted', (f) => {
    const emptySystem = path.join(f.outer, 'system-without-tools');
    fs.mkdirSync(emptySystem);
    const report = successful(f, 'doctor.js', [], { KNOWLEDGE_SYSTEM_ROOT: emptySystem });
    assert(report.routing_bundle_refresh_error && f.read('maintenance/quality_report.json').routing_bundle_refresh_error === report.routing_bundle_refresh_error, 'routing refresh failure disappeared from the stored report');
  });
  check('symlink_source_and_maintenance_are_not_followed', (f) => {
    const outside = path.join(f.outer, 'outside');
    fs.mkdirSync(outside);
    const sentinel = path.join(outside, 'sentinel.js');
    write(sentinel, 'sensitive fixture sentinel\n');
    const before = hash(sentinel);
    fs.rmSync(path.join(f.root, 'src/main.js'));
    try { fs.symlinkSync(sentinel, path.join(f.root, 'src/main.js')); }
    catch (error) {
      if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { skipped.push({ name: 'symlink_source_and_maintenance_are_not_followed', reason: error.code }); return; }
      throw error;
    }
    assert(finding(successful(f, 'doctor.js'), 'tracked_file_missing'), 'Doctor followed source symlink');
    assert(successful(f, 'sync-tracked.js').missing_files.includes('src/main.js'), 'sync followed source symlink');
    fs.rmSync(path.join(f.knowledge, 'maintenance'), { recursive: true });
    fs.symlinkSync(outside, path.join(f.knowledge, 'maintenance'), process.platform === 'win32' ? 'junction' : 'dir');
    assert(run(f, 'doctor.js').status !== 0 && run(f, 'sync-tracked.js').status !== 0, 'maintenance writes followed linked parent');
    assert(hash(sentinel) === before && fs.readdirSync(outside).length === 1, 'maintenance changed outside sentinel directory');
  });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks, commands_executed: commands, skipped, network: 'disabled_in_all_fixtures' }, null, 2));
}

try { main(); }
catch (error) { console.error(error.stack || error.message); process.exitCode = 1; }
