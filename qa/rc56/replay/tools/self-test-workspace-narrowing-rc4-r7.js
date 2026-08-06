#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const routing = require('./lib/task-routing');
const { __test: gitTest } = require('./lib/git-context');
const { formatTaskRoutingEstimate } = require('./lib/routing-estimate-formatter');
const { resolveTaskRoutingContext } = require('./lib/task-routing-state');

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}

function read(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-workspace-narrowing-r7-'));
  const knowledge = path.join(root, '.knowledge');
  const modules = [
    { module_id: 'pro2pilot', name: 'Pro2Pilot', path: 'pro2pilot/', card: '.knowledge/modules/pro2pilot.json', purpose: 'Pro2Pilot knowledge website', key_files: ['pro2pilot/app.js'], evidence_files: [{ path: 'pro2pilot/optional.md', required: false }] },
    { module_id: 'tools', name: 'Tools', path: 'tools/', card: '.knowledge/modules/tools.json', purpose: 'Shared workspace tools', key_files: ['tools/index.js'] },
    { module_id: 'cgilighthouse', name: 'CGI Lighthouse', path: 'cgilighthouse/', card: '.knowledge/modules/cgilighthouse.json', purpose: 'CGI Lighthouse project', key_files: ['cgilighthouse/index.js'] },
    { module_id: 'design_artifacts', name: 'Design artifacts', path: 'design_artifacts/', card: '.knowledge/modules/design_artifacts.json', purpose: 'Design artifacts', key_files: [] },
    { module_id: 'root', name: 'Root', path: 'root/', card: '.knowledge/modules/root.json', purpose: 'Workspace root', key_files: ['root/index.js'] }
  ];
  for (const moduleInfo of modules) {
    write(path.join(root, moduleInfo.card), { module_id: moduleInfo.module_id, key_files: moduleInfo.key_files });
    for (const file of moduleInfo.key_files) write(path.join(root, file), `// ${file}\n`);
  }
  write(path.join(knowledge, 'modules', 'module_registry.json'), { modules });
  write(path.join(knowledge, 'project_index.json'), {
    project_name: 'multi-project-fixture', repo_root: '.', primary_source_of_truth: 'code',
    modules: modules.map((item) => ({ module_id: item.module_id, card: item.card, confidence: 'high' })), task_routing: []
  });
  write(path.join(knowledge, 'maintenance', 'trust_report.json'), {
    modules_total: modules.length, modules_low_confidence: 0, stale_artifacts_total: 0,
    open_contradictions_total: 0, high_severity_contradictions_total: 0,
    modules: { trusted: modules.map((item) => item.module_id), near_trusted: [], routing_trusted: [], advisory_only: [], suspect: [], low_confidence: [] },
    module_statuses: modules.map((item) => ({ module_id: item.module_id, confidence: 'high', freshness_status: 'fresh', trust_status: 'trusted' }))
  });
  write(path.join(knowledge, 'maintenance', 'repair_queue.json'), { queue: [] });
  write(path.join(knowledge, 'maintenance', 'handoff_summary.json'), { schema_version: '3.3.0', project_operational_summary: 'Workspace routing fixture.', trusted_modules: modules.map((item) => item.module_id), next_agent_first_reads: ['.knowledge/maintenance/routing_bundle.json'] });
  write(path.join(knowledge, 'maintenance', 'concurrency_policy.json'), { mode: 'concurrent_safe', write_policy: { atomic_writes: true, lock_path: '.knowledge/.lock' }, merge_policy: { code_is_source_of_truth: true, tests_beat_prose: true, suspect_or_low_confidence_requires_code_recheck: true } });
  write(path.join(knowledge, 'maintenance', 'wiki_lint_report.json'), { structural_status: 'healthy' });
  write(path.join(knowledge, 'maintenance', 'quality_report.json'), { contradictions: [], issues: [] });
  write(path.join(knowledge, 'maps', 'wiki_graph.json'), { structural_status: 'healthy' });
  write(path.join(knowledge, 'maps', 'critical_paths.json'), { paths: [] });
  write(path.join(knowledge, 'freshness.json'), { tracked_files: [] });
  const context = {
    targetRoot: root, projectKnowledgeRoot: knowledge, stateRoot: knowledge,
    repoId: 'r7-repo', workspaceId: 'r7-workspace', agentId: 'r7-test',
    git: { changed_files: [], changed_file_details: [] }
  };
  const input = { task: 'Audit and update only the Pro2Pilot knowledge website', modules: ['pro2pilot'], paths: ['pro2pilot/'], scopeSource: 'explicit' };
  return { root, knowledge, context, input, scope: routing.canonicalScope(input, context) };
}

function main() {
  const x = fixture();
  const results = [];
  const check = (id, fn) => {
    try { fn(); results.push({ id, status: 'pass' }); }
    catch (error) { results.push({ id, status: 'fail', actual: error.message }); }
  };
  try {
    const valid = routing.buildSnapshot(x.context, x.scope);
    check('methodology_comparison_kind', () => assert.equal(valid.metrics.comparison_kind, 'workspace_to_task_first_read_narrowing'));
    check('methodology_schema_version', () => assert.equal(valid.metrics.schema_version, 'knowledge-workspace-narrowing-comparison.v1'));
    check('methodology_measurement_kind', () => assert.equal(valid.metrics.measurement_kind, 'estimated_local_first_read_context'));
    check('methodology_actual_usage_unavailable', () => assert.equal(valid.metrics.actual_model_usage.available, false));
    check('methodology_no_same_scope_text', () => assert(!/same.?scope|same frozen task scope/i.test(valid.metrics.estimator_interpretation)));
    check('methodology_no_version_comparison_text', () => assert(!/3\.2\.11|version comparison/i.test(formatTaskRoutingEstimate(valid.metrics, { effective_claim_eligible: true }))));

    check('baseline_complete', () => assert.equal(valid.metrics.workspace_baseline_complete, true));
    check('baseline_contract_valid', () => assert.equal(valid.metrics.comparison_contract_valid, true));
    check('baseline_recipe_id', () => assert.equal(valid.metrics.workspace_baseline.recipe_id, 'knowledge-workspace-first-read-recipe'));
    check('baseline_recipe_version', () => assert.equal(valid.metrics.workspace_baseline.recipe_version, 'v1'));
    check('baseline_roles_total', () => assert.equal(valid.baseline.parsed.roles.length, 8));
    check('baseline_role_projectors_versioned', () => assert(valid.baseline.parsed.roles.every((item) => /\.v2$/.test(item.projector_version))));
    check('baseline_role_projections_hashed', () => assert(valid.baseline.parsed.roles.filter((item) => item.valid).every((item) => /^[a-f0-9]{64}$/.test(item.projection_hash))));
    check('baseline_independent_of_task', () => assert.equal(valid.baseline.parsed.task_scope_hash, undefined));
    check('baseline_modules_total_five', () => assert.equal(valid.metrics.workspace_narrowing.modules_total, 5));
    check('baseline_selected_one', () => assert.equal(valid.metrics.workspace_narrowing.modules_selected, 1));

    const projectFile = path.join(x.knowledge, 'project_index.json');
    const projectBackup = fs.readFileSync(projectFile);
    write(projectFile, { foo: 'bar' });
    const invalidProject = routing.buildSnapshot(x.context, x.scope);
    check('invalid_project_blocks_complete', () => assert.equal(invalidProject.metrics.workspace_baseline_complete, false));
    check('invalid_project_blocks_claim', () => assert.equal(invalidProject.metrics.claim_eligible, false));
    check('invalid_project_not_comparable', () => assert.equal(invalidProject.metrics.assessment, 'not_comparable'));
    fs.writeFileSync(projectFile, projectBackup);

    const registryFile = path.join(x.knowledge, 'modules', 'module_registry.json');
    const registryBackup = fs.readFileSync(registryFile);
    write(registryFile, { modules: [{ module_id: 'broken' }] });
    const invalidRegistry = routing.buildSnapshot(x.context, x.scope);
    check('invalid_registry_blocks_claim', () => assert.equal(invalidRegistry.metrics.claim_eligible, false));
    check('invalid_registry_contract_invalid', () => assert.equal(invalidRegistry.metrics.comparison_contract_valid, false));
    fs.writeFileSync(registryFile, registryBackup);

    const trustFile = path.join(x.knowledge, 'maintenance', 'trust_report.json');
    const trustBackup = fs.readFileSync(trustFile);
    write(trustFile, { foo: 'bar' });
    check('invalid_trust_blocks_claim', () => assert.equal(routing.buildSnapshot(x.context, x.scope).metrics.claim_eligible, false));
    fs.writeFileSync(trustFile, trustBackup);

    const projectUnknown = read(projectFile);
    projectUnknown.unknown_padding = 'x'.repeat(1024 * 1024);
    write(projectFile, projectUnknown);
    const unknownPadding = routing.buildSnapshot(x.context, x.scope);
    check('unknown_field_does_not_change_baseline', () => assert.equal(unknownPadding.baseline.baseline_hash, valid.baseline.baseline_hash));
    write(path.join(x.root, 'arbitrary-unrelated.bin'), 'x'.repeat(1024 * 1024));
    check('arbitrary_file_does_not_change_baseline', () => assert.equal(routing.buildSnapshot(x.context, x.scope).baseline.baseline_hash, valid.baseline.baseline_hash));
    fs.writeFileSync(projectFile, projectBackup);

    const oversizedRegistry = read(registryFile);
    oversizedRegistry.modules[0].purpose = 'x'.repeat(1024 * 1024);
    write(registryFile, oversizedRegistry);
    const oversized = routing.buildSnapshot(x.context, x.scope);
    check('oversized_field_blocks_claim', () => assert.equal(oversized.metrics.claim_eligible, false));
    check('oversized_field_reason', () => assert(oversized.metrics.claim_ineligible_reasons.includes('workspace_baseline_role_size_anomaly')));
    fs.writeFileSync(registryFile, registryBackup);

    const beforeGrowth = routing.buildSnapshot(x.context, x.scope);
    const growthRegistry = read(registryFile);
    growthRegistry.modules.push({ module_id: 'sixth', name: 'Sixth', path: 'sixth/', card: '.knowledge/modules/sixth.json', purpose: 'Legitimate sixth project', key_files: [] });
    write(registryFile, growthRegistry);
    write(path.join(x.knowledge, 'modules', 'sixth.json'), { module_id: 'sixth', key_files: [] });
    const growthProject = read(projectFile);
    growthProject.modules.push({ module_id: 'sixth', card: '.knowledge/modules/sixth.json', confidence: 'high' });
    write(projectFile, growthProject);
    const growthTrust = read(trustFile);
    growthTrust.modules_total = 6;
    growthTrust.modules.trusted.push('sixth');
    growthTrust.module_statuses.push({ module_id: 'sixth', confidence: 'high', freshness_status: 'fresh', trust_status: 'trusted' });
    write(trustFile, growthTrust);
    const afterGrowth = routing.buildSnapshot(x.context, x.scope);
    check('growth_changes_baseline_hash', () => assert.notEqual(afterGrowth.baseline.baseline_hash, beforeGrowth.baseline.baseline_hash));
    check('growth_keeps_route_hash', () => assert.equal(afterGrowth.snapshot_hash, beforeGrowth.snapshot_hash));
    check('growth_increments_modules_total', () => assert.equal(afterGrowth.metrics.workspace_narrowing.modules_total, 6));
    check('growth_keeps_selected_modules', () => assert.equal(afterGrowth.metrics.workspace_narrowing.modules_selected, 1));
    check('growth_changes_comparison_hash', () => assert.notEqual(afterGrowth.metrics.metrics_comparison_hash, beforeGrowth.metrics.metrics_comparison_hash));
    fs.writeFileSync(registryFile, registryBackup);
    fs.writeFileSync(projectFile, projectBackup);
    fs.writeFileSync(trustFile, trustBackup);

    const existingSources = routing.buildSnapshot(x.context, x.scope);
    check('existing_required_source_complete', () => assert.equal(existingSources.metrics.required_sources_complete, true));
    check('optional_missing_source_non_blocking', () => assert.equal(existingSources.bundle.task_readiness, 'ready'));
    fs.unlinkSync(path.join(x.root, 'pro2pilot', 'app.js'));
    const missingSource = routing.buildSnapshot(x.context, x.scope);
    check('missing_required_source_blocks_readiness', () => assert.equal(missingSource.bundle.task_readiness, 'needs_required_sources'));
    check('missing_required_source_blocks_claim', () => assert.equal(missingSource.metrics.claim_eligible, false));
    check('missing_required_source_receipt', () => assert(missingSource.decision.provenance.read_set.some((item) => item.path === 'pro2pilot/app.js' && item.required && item.path_state === 'missing')));
    write(path.join(x.root, 'pro2pilot', 'app.js'), '// restored\n');
    check('required_source_reappears_after_refresh', () => assert.equal(routing.buildSnapshot(x.context, x.scope).bundle.task_readiness, 'ready'));
    x.context.git = { changed_files: ['pro2pilot/app.js'], changed_file_details: [{ path: 'pro2pilot/app.js', status: 'deleted', index_status: ' ', worktree_status: 'D' }] };
    const deletedSource = routing.buildSnapshot(x.context, x.scope);
    check('deleted_required_source_status_preserved', () => assert(deletedSource.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'pro2pilot/app.js' && item.status === 'deleted')));
    check('deleted_required_source_blocks_readiness', () => assert.equal(deletedSource.bundle.task_readiness, 'needs_required_sources'));
    check('deleted_required_source_blocks_claim', () => assert.equal(deletedSource.metrics.claim_eligible, false));
    x.context.git = { changed_files: [], changed_file_details: [] };

    const gitCases = [
      ['modified', ' M src/app.js\0', 'src/app.js', 'modified'],
      ['deleted', ' D src/app.js\0', 'src/app.js', 'deleted'],
      ['staged_modified', 'M  src/app.js\0', 'src/app.js', 'modified'],
      ['staged_deleted', 'D  src/app.js\0', 'src/app.js', 'deleted'],
      ['added', 'A  src/new.js\0', 'src/new.js', 'added'],
      ['untracked', '?? src/new.js\0', 'src/new.js', 'untracked'],
      ['spaces', ' M src/file with spaces.js\0', 'src/file with spaces.js', 'modified'],
      ['unicode', ' M src/файл.js\0', 'src/файл.js', 'modified'],
      ['leading_space', ' M  leading.js\0', ' leading.js', 'modified'],
      ['trailing_space', ' M trailing.js \0', 'trailing.js ', 'modified']
    ];
    for (const [id, input, expectedPath, expectedStatus] of gitCases) {
      check(`git_${id}`, () => {
        const parsed = gitTest.parsePorcelain(input).changed[0];
        assert.equal(parsed.path, expectedPath);
        assert.equal(parsed.status, expectedStatus);
      });
    }
    check('git_rename_pair', () => assert.deepEqual(
      gitTest.parsePorcelain('R  src/new.js\0src/old.js\0').changed[0],
      { path: 'src/new.js', status: 'renamed', index_status: 'R', worktree_status: ' ', index: 'R', worktree: ' ', source: 'git_porcelain', original_path: 'src/old.js', raw: 'R  src/new.js' }
    ));
    check('git_multiple_records', () => assert.equal(gitTest.parsePorcelain(' M a.js\0?? b.js\0 D c.js\0').changed.length, 3));

    const eligibleState = { effective_claim_eligible: true };
    const narrowing = formatTaskRoutingEstimate({ assessment: 'estimated_narrowing', signed_delta_percent: 25, workspace_baseline: { estimated_tokens: 400 }, task_context: { estimated_tokens: 300 } }, eligibleState);
    check('formatter_narrowing_wording', () => assert(/workspace-to-task first-read narrowing/i.test(narrowing)));
    check('formatter_disclaimer', () => assert(/not actual provider-reported model-token usage/i.test(narrowing)));
    const overhead = formatTaskRoutingEstimate({ assessment: 'estimated_overhead', signed_delta_percent: -5, workspace_baseline: { estimated_tokens: 400 }, task_context: { estimated_tokens: 420 } }, eligibleState);
    check('formatter_overhead_only', () => assert(/overhead/.test(overhead) && !/saving=0|reduction/.test(overhead)));
    check('formatter_neutral', () => assert(/No material/.test(formatTaskRoutingEstimate({ assessment: 'neutral' }, eligibleState))));
    const stale = formatTaskRoutingEstimate({ assessment: 'estimated_narrowing', signed_delta_percent: 99 }, { effective_claim_eligible: false, claim_ineligible_reasons: ['task_routing_snapshot_stale'] });
    check('formatter_stale_exclusive', () => assert(/^No public workspace-narrowing estimate/.test(stale)));
    check('formatter_stale_no_raw_assessment', () => assert(!/estimated_narrowing|99%/.test(stale)));

    const createdOne = routing.create(x.context, x.input);
    const createdTwo = routing.create(x.context, { task: 'Tools task', modules: ['tools'], paths: ['tools/'], scopeSource: 'explicit' });
    const manifests = routing.listTasks(x.context);
    check('multi_task_explicit', () => assert.equal(resolveTaskRoutingContext({ context: x.context, manifests, explicitTaskId: createdOne.task_scope_hash }).source, 'explicit_task_id'));
    write(path.join(x.knowledge, 'sessions', 'agent-registry.json'), { sessions: [{ session_id: 's1', task_id: createdTwo.task_scope_hash, status: 'running' }] });
    check('multi_task_agent_session', () => assert.equal(resolveTaskRoutingContext({ context: x.context, manifests, sessionId: 's1' }).task_scope_hash, createdTwo.task_scope_hash));
    write(path.join(x.knowledge, 'routing', 'pr-task-map.json'), { mappings: [{ pr_number: 77, task_scope_hash: createdOne.task_scope_hash }] });
    write(path.join(x.knowledge, 'sessions', 'agent-registry.json'), { sessions: [] });
    check('multi_task_pr_mapping', () => assert.equal(resolveTaskRoutingContext({ context: x.context, manifests, prNumber: 77 }).source, 'pr_mapping'));
    const ambiguous = resolveTaskRoutingContext({ context: x.context, manifests });
    check('multi_task_ambiguous', () => assert.equal(ambiguous.reason, 'task_routing_context_ambiguous'));
    check('multi_task_ambiguous_public_no_percentage', () => assert(!/%/.test(formatTaskRoutingEstimate({}, { effective_claim_eligible: false, claim_ineligible_reasons: [ambiguous.reason] }))));
  } finally {
    fs.rmSync(x.root, { recursive: true, force: true });
  }

  const failed = results.filter((item) => item.status !== 'pass');
  process.stdout.write(`${JSON.stringify({
    schema_version: 'knowledge-workspace-narrowing-rc4-r7-self-test.v1',
    status: failed.length ? 'fail' : 'pass',
    checks_total: results.length,
    passed: results.length - failed.length,
    failed: failed.length,
    results
  }, null, 2)}\n`);
  if (failed.length) process.exitCode = 1;
}

main();
