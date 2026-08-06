#!/usr/bin/env node
'use strict';

// This is deliberately a real 72-assertion contract suite.  The reported
// count is derived from executed checks, not from a declaration.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const routing = require('./lib/task-routing');
const { formatTaskRoutingEstimate } = require('./lib/routing-estimate-formatter');

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2));
}
function fixture(options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-task-routing-v2-'));
  const knowledge = path.join(root, '.knowledge');
  const modules = [
    { module_id: 'cgilighthouse', path: 'cgilighthouse/', card: '.knowledge/modules/cgilighthouse.json', purpose: 'website rendering', key_files: ['cgilighthouse/critical.js'] },
    { module_id: 'root', path: 'root/', card: '.knowledge/modules/root.json', purpose: 'root level runtime', key_files: ['root/index.js'] },
    { module_id: 'tools', path: 'tools/', card: '.knowledge/modules/tools.json', purpose: 'shared tooling', key_files: ['tools/index.js'] },
    { module_id: 'pro2pilot', path: 'pro2pilot/', card: '.knowledge/modules/pro2pilot.json', purpose: 'Pro2Pilot customer integration', keywords: ['pro2pilot'], dependencies: ['tools'], key_files: ['pro2pilot/knowledge.html', 'pro2pilot/inspector.html'] },
    { module_id: 'pro2pilot2', path: 'pro2pilot2/', card: '.knowledge/modules/pro2pilot2.json', purpose: 'separate fixture trap', key_files: ['pro2pilot2/should-not-match.html'] },
    { module_id: 'auth', path: 'auth/', card: '.knowledge/modules/auth.json', purpose: 'authentication credentials', security_sensitive: true, key_files: ['auth/login.js'] }
  ];
  write(path.join(knowledge, 'modules', 'module_registry.json'), { modules });
  write(path.join(knowledge, 'project_index.json'), {
    project_name: 'routing-fixture', repo_root: '.', primary_source_of_truth: 'code',
    modules: modules.map((item) => ({ module_id: item.module_id, card: item.card, confidence: 'high' })),
    task_routing: [{ route_id: 'pro2pilot', keywords: ['pro2pilot'], target_modules: ['pro2pilot'] }]
  });
  write(path.join(knowledge, 'maintenance', 'concurrency_policy.json'), { mode: 'locked_atomic_writes' });
  write(path.join(knowledge, 'maintenance', 'routing_bundle.json'), {
    schema_version: 'knowledge-routing-bootstrap.v1', workspace: { id: 'fixture' },
    global_health: { status: 'healthy' }, task_routing: { command: 'task-routing' },
    pointers: {}, first_read_strategy: { read_first: '.knowledge/maintenance/routing_bundle.json' }
  });
  write(path.join(knowledge, 'maintenance', 'wiki_lint_report.json'), { structural_status: options.broken ? 'structurally_broken' : 'healthy' });
  write(path.join(knowledge, 'maps', 'wiki_graph.json'), { structural_status: options.broken ? 'structurally_broken' : 'healthy', broken_edge_count: options.broken ? 1 : 0 });
  write(path.join(knowledge, 'maps', 'critical_paths.json'), { paths: [{ id: 'authn', path: 'auth/login.js', modules: ['auth'], severity: 'high' }] });
  write(path.join(knowledge, 'maintenance', 'quality_report.json'), { contradictions: options.contradiction ? [{ id: 'c1', module_id: 'auth', status: 'open' }] : [] });
  write(path.join(knowledge, 'maintenance', 'repair_queue.json'), { queue: [{ id: 'r1', module_id: 'pro2pilot', status: 'open' }, { id: 'r2', module_id: 'auth', status: 'open' }] });
  write(path.join(knowledge, 'maintenance', 'trust_report.json'), {
    modules_total: modules.length,
    modules_low_confidence: 0,
    stale_artifacts_total: 0,
    open_contradictions_total: options.contradiction ? 1 : 0,
    high_severity_contradictions_total: 0,
    modules: {
      trusted: modules.filter((item) => item.module_id !== 'auth' || !options.authSuspect).map((item) => item.module_id),
      near_trusted: [], routing_trusted: [], advisory_only: [],
      suspect: options.authSuspect ? ['auth'] : [], low_confidence: []
    },
    module_statuses: modules.map((item) => ({ module_id: item.module_id, trust_status: item.module_id === 'auth' && options.authSuspect ? 'suspect' : 'trusted', freshness_status: 'fresh', confidence: 'high', reasons: { open_contradictions: item.module_id === 'auth' && options.contradiction ? ['c1'] : [] } }))
  });
  const stale = Array.from({ length: options.overflow || 0 }, (_, index) => ({ path: `pro2pilot/stale-${String(index).padStart(3, '0')}.html`, status: options.highRisk && index > 0 ? 'missing' : 'stale' }));
  write(path.join(knowledge, 'freshness.json'), { tracked_files: stale });
  for (const moduleInfo of modules) {
    write(path.join(root, moduleInfo.card), { module_id: moduleInfo.module_id, key_files: moduleInfo.key_files });
    for (const file of moduleInfo.key_files) write(path.join(root, file), options.large && file === 'pro2pilot/knowledge.html' ? 'x'.repeat(options.large) : `// ${file}\n`);
  }
  const context = { targetRoot: root, projectKnowledgeRoot: knowledge, stateRoot: knowledge, repoId: 'fixture-workspace', workspaceId: 'fixture', headSha: options.head || null, agentId: 'self-test', git: { changed_files: [] } };
  const initialScope = routing.canonicalScope({ task: 'Audit and update only the Pro2Pilot knowledge website', taskClass: 'content_consistency_audit', modules: ['pro2pilot'], paths: ['pro2pilot/'], scopeSource: 'explicit' }, context);
  const baselineFile = path.join(root, 'pro2pilot', 'knowledge.html');
  const baselineBody = fs.readFileSync(baselineFile);
  write(path.join(knowledge, 'maintenance', 'routing_bundle.json'), { schema_version: 'knowledge-routing-baseline.v2', workspace_id: 'fixture', repository_id: context.repoId, task_scope_hash: initialScope.task_scope_hash, snapshot_marker: 'fixture', method: 'task_first_read_baseline.v2', measurement_payload: { files: [{ path: 'pro2pilot/knowledge.html', sha256: require('crypto').createHash('sha256').update(baselineBody).digest('hex') }], policy_inputs: [] }, provenance: { generated_at: 'fixed', generated_by: 'self-test' } });
  return { root, knowledge, context };
}
function scope(context, overrides = {}) {
  return routing.canonicalScope({
    task: 'Audit and update only the Pro2Pilot knowledge website',
    taskClass: 'content_consistency_audit', modules: ['pro2pilot'], paths: ['pro2pilot/'],
    excludeModules: [], excludePaths: [], scopeSource: 'explicit', ...overrides
  }, context);
}
function main() {
  const checks = [];
  const check = (name, fn) => { fn(); checks.push(name); };
  const base = fixture();
  try {
    const a = scope(base.context);
    const b = scope(base.context, { modules: ['pro2pilot'], paths: ['pro2pilot/'] });
    check('01_scope_hash_stable', () => assert.equal(a.task_scope_hash, b.task_scope_hash));
    check('02_scope_schema_v2', () => assert.equal(a.schema_version, routing.SCOPE_SCHEMA));
    check('03_scope_task_preserved', () => assert.equal(a.task, 'Audit and update only the Pro2Pilot knowledge website'));
    check('04_scope_task_class_preserved', () => assert.equal(a.task_class, 'content_consistency_audit'));
    check('05_scope_source_preserved', () => assert.equal(a.scope_source, 'explicit'));
    check('06_scope_path_canonical', () => assert.deepEqual(a.paths, ['pro2pilot']));
    check('07_scope_module_canonical', () => assert.deepEqual(a.modules, ['pro2pilot']));
    check('08_stop_word_and_ignored', () => assert(!routing.__test.tokens(a.task).includes('and')));
    check('09_generic_website_ignored', () => assert(!routing.__test.tokens(a.task).includes('website')));
    check('10_task_token_pro2pilot_kept', () => assert(routing.__test.tokens(a.task).includes('pro2pilot')));
    check('11_unsafe_path_rejected', () => assert.throws(() => scope(base.context, { paths: ['../maintenance'] }), /safe relative/));
    check('12_path_boundary_accepts_child', () => assert(routing.__test.pathWithin('pro2pilot/a.html', 'pro2pilot')));
    check('13_path_boundary_rejects_prefix_trap', () => assert(!routing.__test.pathWithin('pro2pilot2/a.html', 'pro2pilot')));
    const selected = routing.__test.moduleSelection(JSON.parse(fs.readFileSync(path.join(base.knowledge, 'modules', 'module_registry.json'))).modules, a);
    check('14_explicit_module_selected', () => assert(selected.find((item) => item.module_id === 'pro2pilot').relevant));
    check('15_direct_dependency_selected', () => assert(selected.find((item) => item.module_id === 'tools').relevant));
    check('16_stopword_root_not_selected', () => assert(!selected.find((item) => item.module_id === 'root').relevant));
    check('17_generic_site_not_selected', () => assert(!selected.find((item) => item.module_id === 'cgilighthouse').relevant));
    check('18_prefix_trap_not_selected', () => assert(!selected.find((item) => item.module_id === 'pro2pilot2').relevant));
    check('19_explicit_scope_has_hard_boundary', () => assert(selected.filter((item) => item.relevant).every((item) => ['pro2pilot', 'tools'].includes(item.module_id))));
    const genericScope = routing.canonicalScope({ task: 'update website', scopeSource: 'inferred' }, base.context);
    const genericSelected = routing.__test.moduleSelection(JSON.parse(fs.readFileSync(path.join(base.knowledge, 'modules', 'module_registry.json'))).modules, genericScope);
    check('20_generic_inferred_does_not_select_cgi', () => assert(!genericSelected.find((item) => item.module_id === 'cgilighthouse').relevant));
    check('21_generic_inferred_does_not_select_root', () => assert(!genericSelected.find((item) => item.module_id === 'root').relevant));
    const first = routing.buildSnapshot(base.context, a);
    const differentHead = routing.buildSnapshot({ ...base.context, headSha: 'f'.repeat(40) }, a);
    check('22_snapshot_ignores_head_sha', () => assert.equal(first.snapshot_hash, differentHead.snapshot_hash));
    check('23_snapshot_provenance_declares_no_head', () => assert(first.decision.provenance.snapshot_identity_excludes.includes('git_head_sha')));
    check('24_snapshot_has_trust_input', () => assert(first.decision.provenance.read_set.some((item) => item.path === 'inputs/trust_report[selected]')));
    check('25_snapshot_has_critical_input', () => assert(first.decision.provenance.read_set.some((item) => item.path === 'inputs/critical_paths[selected]')));
    check('26_snapshot_has_repair_input', () => assert(first.decision.provenance.read_set.some((item) => item.path === 'inputs/repair_queue[selected]')));
    check('27_snapshot_has_wiki_input', () => assert(first.decision.provenance.read_set.some((item) => item.path === 'inputs/wiki_structural_status')));
    check('28_snapshot_has_adaptive_input', () => assert(first.decision.provenance.read_set.some((item) => item.path === 'inputs/adaptive_safety')));
    fs.appendFileSync(path.join(base.root, 'pro2pilot', 'knowledge.html'), 'changed');
    const sourceChanged = routing.buildSnapshot(base.context, a);
    check('29_relevant_source_changes_snapshot', () => assert.notEqual(first.snapshot_hash, sourceChanged.snapshot_hash));
    fs.writeFileSync(path.join(base.root, 'cgilighthouse', 'critical.js'), 'unrelated changed');
    const unrelatedChanged = routing.buildSnapshot(base.context, a);
    check('30_unrelated_source_does_not_change_snapshot', () => assert.equal(sourceChanged.snapshot_hash, unrelatedChanged.snapshot_hash));
    const trust = JSON.parse(fs.readFileSync(path.join(base.knowledge, 'maintenance', 'trust_report.json'))); trust.module_statuses.find((item) => item.module_id === 'pro2pilot').trust_status = 'suspect'; write(path.join(base.knowledge, 'maintenance', 'trust_report.json'), trust);
    const refreshedBaseline = JSON.parse(fs.readFileSync(path.join(base.knowledge, 'maintenance', 'routing_bundle.json')));
    refreshedBaseline.measurement_payload.files[0].sha256 = require('crypto').createHash('sha256').update(fs.readFileSync(path.join(base.root, 'pro2pilot', 'knowledge.html'))).digest('hex');
    write(path.join(base.knowledge, 'maintenance', 'routing_bundle.json'), refreshedBaseline);
    const trustChanged = routing.buildSnapshot(base.context, a);
    check('31_relevant_trust_changes_snapshot', () => assert.notEqual(unrelatedChanged.snapshot_hash, trustChanged.snapshot_hash));
    check('32_metrics_content_method', () => assert.equal(trustChanged.metrics.estimator_method, 'workspace_to_task_first_read_bytes_divided_by_four'));
    check('33_metrics_workspace_narrowing_contract', () => assert.equal(trustChanged.metrics.comparison_kind, 'workspace_to_task_first_read_narrowing'));
    check('34_metrics_claim_receipt', () => assert.equal(trustChanged.metrics.comparison_receipt.task_scope_hash, a.task_scope_hash));
    check('35_metrics_has_actual_usage_disclaimer', () => assert.equal(trustChanged.metrics.actual_model_usage.available, false));
    check('36_metrics_baseline_has_content_inputs', () => assert(trustChanged.metrics.comparison_receipt.baseline_inputs.length > 1));
    const tiny = fixture({ large: 1 }); const giant = fixture({ large: 1000000 });
    try {
      const tinyMetrics = routing.buildSnapshot(tiny.context, scope(tiny.context)).metrics;
      const giantMetrics = routing.buildSnapshot(giant.context, scope(giant.context)).metrics;
      check('37_workspace_baseline_independent_of_task_source_size', () => assert.equal(tinyMetrics.baseline.estimated_tokens, giantMetrics.baseline.estimated_tokens));
      check('38_workspace_baseline_identity_independent_of_task_source_size', () => assert.equal(tinyMetrics.baseline.baseline_hash, giantMetrics.baseline.baseline_hash));
      check('39_estimator_small_routing', () => assert(tinyMetrics.routing.estimated_tokens < giantMetrics.routing.estimated_tokens));
      check('40_estimator_no_fixed_percent', () => assert.notEqual(tinyMetrics.signed_delta_percent, giantMetrics.signed_delta_percent));
    } finally { fs.rmSync(tiny.root, { recursive: true, force: true }); fs.rmSync(giant.root, { recursive: true, force: true }); }
    const overflow = fixture({ overflow: 100, highRisk: true });
    try {
      const overflowBuild = routing.buildSnapshot(overflow.context, scope(overflow.context));
      check('41_path_payload_is_bounded', () => assert(overflowBuild.bundle.relevant_changed_or_stale_paths.length < 100));
      check('42_path_payload_honors_mode_cap', () => assert(overflowBuild.bundle.relevant_changed_or_stale_paths.length <= routing.PATH_BUDGETS.minimal));
      check('43_noncritical_path_omissions_recorded', () => assert.equal(overflowBuild.decision.truncation.omitted_relevant_paths.length, 1));
      check('44_high_risk_paths_continue_without_omission', () => assert.equal(overflowBuild.decision.truncation.high_risk_continuation.paths_total, 90));
      check('45_high_risk_continuation_blocks_readiness', () => assert.equal(overflowBuild.bundle.task_readiness, 'requires_high_risk_continuation'));
      check('46_path_budget_reason_recorded', () => assert.equal(overflowBuild.decision.truncation.reason, 'task_path_budget_exhausted'));
    } finally { fs.rmSync(overflow.root, { recursive: true, force: true }); }
    const broken = fixture({ broken: true, authSuspect: true, contradiction: true });
    try {
      const brokenBuild = routing.buildSnapshot(broken.context, scope(broken.context));
      check('47_structural_state_consumed', () => assert.equal(brokenBuild.decision.wiki_status, 'structurally_broken'));
      check('48_structural_safety_mode_consumed', () => assert.equal(brokenBuild.decision.routing_mode, 'full'));
      check('49_structural_safety_override_recorded', () => assert(brokenBuild.decision.safety_overrides.includes('structurally_broken_graph')));
      check('50_structural_readiness_blocked', () => assert.equal(brokenBuild.bundle.task_readiness, 'needs_structural_repair'));
      check('51_outside_scope_risk_deferred_to_workspace_debt', () => { assert.deepEqual(brokenBuild.decision.safety_findings_outside_scope, []); assert.equal(brokenBuild.decision.workspace_safety_notice.details, 'maintenance/maintenance_debt.json'); });
      check('52_explicit_scope_still_excludes_auth', () => assert(!brokenBuild.bundle.selected_modules.includes('auth')));
    } finally { fs.rmSync(broken.root, { recursive: true, force: true }); }
    const created = routing.create(base.context, { task: a.task, taskClass: a.task_class, modules: a.modules, paths: a.paths, scopeSource: a.scope_source });
    const snap = routing.snapshotRoot(base.context, created.task_scope_hash, created.snapshot_hash);
    check('53_create_returns_ok', () => assert.equal(created.status, 'ok'));
    check('54_snapshot_complete_marker_written', () => assert(fs.existsSync(path.join(snap, 'complete.json'))));
    check('55_snapshot_complete_verifies', () => assert(routing.snapshotComplete(base.context, snap)));
    check('56_all_required_snapshot_files_written', () => assert(routing.REQUIRED_SNAPSHOT_FILES.every((name) => fs.existsSync(path.join(snap, name)))));
    check('57_manifest_current_written_after_completion', () => assert.equal(JSON.parse(fs.readFileSync(path.join(base.knowledge, 'routing', 'tasks', created.task_scope_hash, 'manifest.json'))).current_snapshot_hash, created.snapshot_hash));
    check('58_current_pointer_marks_complete', () => assert.equal(JSON.parse(fs.readFileSync(path.join(base.knowledge, 'routing', 'tasks', created.task_scope_hash, 'current.json'))).complete, true));
    const again = routing.create(base.context, { task: a.task, taskClass: a.task_class, modules: a.modules, paths: a.paths, scopeSource: a.scope_source });
    check('59_idempotent_snapshot_hash', () => assert.equal(created.snapshot_hash, again.snapshot_hash));
    check('60_idempotent_manifest_one_snapshot', () => assert.equal(routing.listTasks(base.context)[0].snapshots.length, 1));
    routing.invalidate(base.context, created.task_scope_hash, 'test');
    check('61_invalidate_marks_stale', () => assert.equal(routing.listTasks(base.context)[0].stale.status, 'stale'));
    const refreshed = routing.refreshTask(base.context, created.task_scope_hash);
    check('62_refresh_reuses_task_id', () => assert.equal(refreshed.task_scope_hash, created.task_scope_hash));
    check('63_refresh_clears_stale', () => assert(!routing.listTasks(base.context)[0].stale));
    check('64_refresh_preserves_task_contract', () => assert.equal(routing.listTasks(base.context)[0].scope.task_class, 'content_consistency_audit'));
    check('65_invalidate_rejects_traversal', () => assert.throws(() => routing.invalidate(base.context, '../../maintenance', 'bad'), /canonical SHA-256/));
    check('66_refresh_rejects_traversal', () => assert.throws(() => routing.refreshTask(base.context, '../../maintenance'), /canonical SHA-256/));
    const partial = fixture();
    try {
      const partialScope = scope(partial.context); const partialBuild = routing.buildSnapshot(partial.context, partialScope);
      const partialRoot = routing.snapshotRoot(partial.context, partialScope.task_scope_hash, partialBuild.snapshot_hash); write(path.join(partialRoot, 'bundle.json'), '{}');
      check('67_partial_snapshot_is_not_complete', () => assert(!routing.snapshotComplete(partial.context, partialRoot)));
      check('68_partial_snapshot_cannot_be_promoted', () => assert.throws(() => routing.create(partial.context, { task: partialScope.task, taskClass: partialScope.task_class, modules: partialScope.modules, paths: partialScope.paths, scopeSource: partialScope.scope_source }), /incomplete task snapshot/));
      check('69_partial_snapshot_has_no_current', () => assert(!fs.existsSync(path.join(partial.knowledge, 'routing', 'tasks', partialScope.task_scope_hash, 'current.json'))));
    } finally { fs.rmSync(partial.root, { recursive: true, force: true }); }
    const second = routing.create(base.context, { task: 'Audit tools only', taskClass: 'maintenance', modules: ['tools'], paths: ['tools/'], scopeSource: 'explicit' });
    check('70_separate_scope_has_separate_task_id', () => assert.notEqual(second.task_scope_hash, created.task_scope_hash));
    check('71_index_contains_both_tasks', () => assert.equal(routing.writeIndex(base.context).tasks.length, 2));
    check('72_workspace_debt_counts_findings_not_paths', () => assert.equal(JSON.parse(fs.readFileSync(path.join(snap, 'bundle.json'))).workspace_debt.relevant_to_current_task, 1));
    const rc4 = fixture({ authSuspect: true });
    try {
      const rc4Scope = scope(rc4.context);
      const initial = routing.create(rc4.context, { task: rc4Scope.task, taskClass: rc4Scope.task_class, modules: rc4Scope.modules, paths: rc4Scope.paths, scopeSource: rc4Scope.scope_source });
      const initialCurrent = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'current.json')));
      const initialBundle = routing.buildSnapshot(rc4.context, rc4Scope).bundle;
      check('73_outside_scope_auth_is_workspace_notice_not_blocker', () => assert.equal(initialBundle.task_readiness, 'ready'));
      check('74_ready_scoped_route_is_claim_eligible', () => assert.equal(initial.metrics.claim_eligible, true));
      check('75_current_pointer_is_canonical_v4', () => assert.equal(initialCurrent.schema_version, 'knowledge-task-routing-current.v4'));
      check('76_current_pointer_has_metrics_comparison_hash', () => assert.match(initialCurrent.metrics_comparison_hash, /^[a-f0-9]{64}$/));
      check('77_create_updates_index_projection', () => assert.equal(JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'index.json'))).tasks[0].current_snapshot_hash, initial.snapshot_hash));
      const trustRc4 = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'maintenance', 'trust_report.json')));
      trustRc4.module_statuses.find((item) => item.module_id === 'pro2pilot').trust_status = 'suspect';
      write(path.join(rc4.knowledge, 'maintenance', 'trust_report.json'), trustRc4);
      const changedRefresh = routing.refreshTask(rc4.context, initial.task_scope_hash);
      const refreshedHash = changedRefresh.current_snapshot_hash;
      check('78_refresh_returns_previous_and_current_snapshot', () => assert.equal(changedRefresh.previous_snapshot_hash, initial.snapshot_hash));
      check('79_refresh_updates_index_projection', () => assert.equal(JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'index.json'))).tasks[0].current_snapshot_hash, refreshedHash));
      write(path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'current.json'), initialCurrent);
      const repairedRefresh = routing.refreshTask(rc4.context, initial.task_scope_hash);
      const repairedCurrent = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'current.json')));
      check('80_refresh_repairs_rewound_current_pointer', () => assert.equal(repairedCurrent.snapshot_hash, refreshedHash));
      check('81_refresh_repairs_manifest_projection', () => assert.equal(JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'manifest.json'))).current_snapshot_hash, refreshedHash));
      check('82_refresh_repairs_index_projection', () => assert.equal(JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'index.json'))).tasks[0].current_snapshot_hash, refreshedHash));
      fs.unlinkSync(path.join(rc4.knowledge, 'routing', 'index.json'));
      routing.listTasks(rc4.context);
      check('83_list_rebuilds_missing_index', () => assert(fs.existsSync(path.join(rc4.knowledge, 'routing', 'index.json'))));
      fs.writeFileSync(path.join(rc4.knowledge, 'routing', 'index.json'), '{ corrupt');
      routing.inspectTask(rc4.context, initial.task_scope_hash);
      check('84_status_rebuilds_corrupt_index', () => assert.doesNotThrow(() => JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'index.json'), 'utf8'))));
      const baselinePath = path.join(rc4.knowledge, 'maintenance', 'trust_report.json');
      const baselineBackup = `${baselinePath}.backup`;
      fs.renameSync(baselinePath, baselineBackup);
      const noBaseline = routing.buildSnapshot(rc4.context, rc4Scope).metrics;
      fs.renameSync(baselineBackup, baselinePath);
      check('85_missing_baseline_is_not_comparable', () => assert.equal(noBaseline.comparison_contract_valid, false));
      check('86_missing_baseline_is_not_claim_eligible', () => assert.equal(noBaseline.claim_eligible, false));
      const beforeBaseline = routing.buildSnapshot(rc4.context, rc4Scope);
      const bootstrap = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'maintenance', 'routing_bundle.json'), 'utf8')); bootstrap.rc4_nonce = 'x'.repeat(2048); write(path.join(rc4.knowledge, 'maintenance', 'routing_bundle.json'), bootstrap);
      const afterBaseline = routing.buildSnapshot(rc4.context, rc4Scope);
      check('87_baseline_metadata_padding_does_not_change_snapshot_identity', () => assert.equal(beforeBaseline.snapshot_hash, afterBaseline.snapshot_hash));
      check('88_baseline_metadata_padding_does_not_change_comparison_identity', () => assert.equal(beforeBaseline.metrics.metrics_comparison_hash, afterBaseline.metrics.metrics_comparison_hash));
      write(path.join(rc4.root, 'pro2pilot', 'new-page.html'), 'untracked\n');
      rc4.context.git = { changed_files: ['pro2pilot/new-page.html'], changed_file_details: [{ path: 'pro2pilot/new-page.html', status: 'untracked' }] };
      const diffBuild = routing.buildSnapshot(rc4.context, rc4Scope);
      check('89_relevant_untracked_git_diff_is_included_with_provenance', () => assert(diffBuild.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'pro2pilot/new-page.html' && item.status === 'untracked' && item.provenance.includes('git_untracked') && item.git_status === 'untracked')));
      const overflowRc4 = fixture({ overflow: 100, highRisk: true });
      try {
        const overflowMetrics = routing.buildSnapshot(overflowRc4.context, scope(overflowRc4.context)).metrics;
        check('90_high_risk_continuation_disables_claim', () => assert.equal(overflowMetrics.claim_eligible, false));
      check('91_high_risk_continuation_reports_zero_silent_omissions', () => assert.equal(overflowMetrics.workspace_narrowing.relevant_high_risk_paths_omitted, 0));
      } finally { fs.rmSync(overflowRc4.root, { recursive: true, force: true }); }
      const canonicalBaselinePath = path.join(rc4.knowledge, 'routing', 'workspace-baselines', repairedCurrent.baseline_hash, 'baseline.json');
      const comparisonPath = path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'comparisons', repairedCurrent.metrics_comparison_hash, 'metrics.json');
      const canonicalBaseline = JSON.parse(fs.readFileSync(canonicalBaselinePath, 'utf8'));
      check('92_current_pointer_has_routing_snapshot_hash', () => assert.equal(repairedCurrent.routing_snapshot_hash, repairedCurrent.snapshot_hash));
      check('93_current_pointer_has_baseline_hash', () => assert.match(repairedCurrent.baseline_hash, /^[a-f0-9]{64}$/));
      check('94_production_baseline_is_physical', () => assert(fs.existsSync(canonicalBaselinePath)));
      check('95_production_baseline_generator_allowlisted', () => assert.equal(canonicalBaseline.generator, 'pro2pilot.workspace-baseline.canonical-generator'));
      check('96_production_baseline_recipe_versioned', () => assert.deepEqual([canonicalBaseline.recipe_id, canonicalBaseline.recipe_version], ['knowledge-workspace-first-read-recipe', 'v1']));
      check('97_production_baseline_roles_are_canonical', () => assert.deepEqual(canonicalBaseline.roles.map((item) => item.role), ['workspace_project_index', 'workspace_module_registry', 'workspace_trust_summary', 'workspace_repair_summary', 'workspace_handoff_summary', 'workspace_critical_paths_summary', 'source_of_truth_policy_summary', 'concurrency_policy_summary']));
      check('98_comparison_is_physical', () => assert(fs.existsSync(comparisonPath)));
      check('99_snapshot_has_no_mutable_metrics', () => assert(!fs.existsSync(path.join(routing.snapshotRoot(rc4.context, initial.task_scope_hash, repairedCurrent.snapshot_hash), 'metrics.json'))));
      check('100_custom_baseline_diagnostic_is_ineligible', () => assert.deepEqual(
        routing.__test.diagnoseCustomBaseline(path.join(rc4.knowledge, 'maintenance', 'routing_bundle.json')).claim_ineligible_reason,
        'custom_baseline_not_claim_eligible'
      ));
      check('101_formatter_savings_golden', () => assert.equal(
        formatTaskRoutingEstimate({ assessment: 'estimated_narrowing', signed_delta_percent: 5, workspace_baseline: { estimated_tokens: 500 }, task_context: { estimated_tokens: 475 }, workspace_narrowing: { modules_total: 5, modules_selected: 1, unrelated_paths_excluded: 4 } }, { effective_claim_eligible: true }),
        'Estimated workspace-to-task first-read narrowing: 500 estimated tokens in the canonical workspace-wide first-read projection versus 475 in the task-scoped first-read, a 5% reduction. The task route selected 1 of 5 workspace modules and excluded 4 unrelated workspace paths from the first-read artifact. This is a deterministic local context estimate, not actual provider-reported model-token usage.'
      ));
      check('102_formatter_overhead_golden', () => assert.equal(
        formatTaskRoutingEstimate({ assessment: 'estimated_overhead', signed_delta_percent: -4, workspace_baseline: { estimated_tokens: 300 }, task_context: { estimated_tokens: 312 } }, { effective_claim_eligible: true }),
        'Estimated workspace-to-task first-read overhead: 312 estimated tokens in the task-scoped first-read versus 300 in the canonical workspace-wide projection, a 4% overhead. This is a deterministic local context estimate, not actual provider-reported model-token usage.'
      ));
      check('103_formatter_neutral_golden', () => assert.equal(
        formatTaskRoutingEstimate({ assessment: 'neutral' }, { effective_claim_eligible: true }),
        'No material estimated workspace-to-task first-read difference. This is a deterministic local context estimate, not actual provider-reported model-token usage.'
      ));
      check('104_formatter_ineligible_golden', () => assert.equal(
        formatTaskRoutingEstimate({}, { effective_claim_eligible: false, claim_ineligible_reasons: ['requires_explicit_frozen_scope'] }),
        'No public workspace-narrowing estimate is available for this report: requires_explicit_frozen_scope.'
      ));
      routing.refreshTask(rc4.context, initial.task_scope_hash);
      const comparisonOnlyBefore = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'current.json')));
      const growthRegistry = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'modules', 'module_registry.json')));
      growthRegistry.modules.push({ module_id: 'design_artifacts', name: 'Design artifacts', path: 'design_artifacts/', card: '.knowledge/modules/design_artifacts.json', purpose: 'Bounded design artifacts', key_files: [] });
      write(path.join(rc4.knowledge, 'modules', 'module_registry.json'), growthRegistry);
      write(path.join(rc4.knowledge, 'modules', 'design_artifacts.json'), { module_id: 'design_artifacts', key_files: [] });
      const growthProject = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'project_index.json')));
      growthProject.modules.push({ module_id: 'design_artifacts', card: '.knowledge/modules/design_artifacts.json', confidence: 'high' });
      write(path.join(rc4.knowledge, 'project_index.json'), growthProject);
      const growthTrust = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'maintenance', 'trust_report.json')));
      growthTrust.modules_total += 1;
      growthTrust.modules.trusted.push('design_artifacts');
      growthTrust.module_statuses.push({ module_id: 'design_artifacts', trust_status: 'trusted', freshness_status: 'fresh', confidence: 'high' });
      write(path.join(rc4.knowledge, 'maintenance', 'trust_report.json'), growthTrust);
      const comparisonOnlyRefresh = routing.refreshTask(rc4.context, initial.task_scope_hash);
      const comparisonOnlyAfter = JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'current.json')));
      check('105_baseline_only_change_keeps_route_hash', () => assert.equal(comparisonOnlyAfter.routing_snapshot_hash, comparisonOnlyBefore.routing_snapshot_hash));
      check('106_baseline_only_change_updates_baseline_hash', () => assert.notEqual(comparisonOnlyAfter.baseline_hash, comparisonOnlyBefore.baseline_hash));
      check('107_baseline_only_change_updates_comparison_hash', () => assert.notEqual(comparisonOnlyAfter.metrics_comparison_hash, comparisonOnlyBefore.metrics_comparison_hash));
      routing.inspectTask(rc4.context, initial.task_scope_hash);
      check('108_reconcile_preserves_new_comparison_hash', () => assert.equal(
        JSON.parse(fs.readFileSync(path.join(rc4.knowledge, 'routing', 'tasks', initial.task_scope_hash, 'current.json'))).metrics_comparison_hash,
        comparisonOnlyRefresh.current_metrics_comparison_hash
      ));
    } finally { fs.rmSync(rc4.root, { recursive: true, force: true }); }
    assert.equal(checks.length, 108, `Expected 108 executed checks, got ${checks.length}`);
    console.log(JSON.stringify({ schema_version: 'knowledge-task-routing-self-test.v3', status: 'pass', checks_total: checks.length, checks }, null, 2));
  } finally { fs.rmSync(base.root, { recursive: true, force: true }); }
}
try { main(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 1; }
