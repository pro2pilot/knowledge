#!/usr/bin/env node
'use strict';

// Historical RC4-R5 regression filename, updated for the RC4-R6 canonical
// baseline/storage contract. Every check uses physical files and artifacts.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const routing = require('./lib/task-routing');

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-r6-regression-'));
  const knowledge = path.join(root, '.knowledge');
  write(path.join(root, 'app', 'a.js'), 'module.exports = 1;\n');
  write(path.join(root, 'app', 'b.js'), 'module.exports = 2;\n');
  write(path.join(knowledge, 'modules', 'app.json'), { module_id: 'app', key_files: ['app/a.js'] });
  write(path.join(knowledge, 'modules', 'module_registry.json'), {
    modules: [{ module_id: 'app', name: 'App', path: 'app/', card: '.knowledge/modules/app.json', purpose: 'Application fixture', key_files: ['app/a.js'] }]
  });
  write(path.join(knowledge, 'project_index.json'), {
    project_name: 'r6-regression', repo_root: '.', primary_source_of_truth: 'code',
    modules: [{ module_id: 'app', card: '.knowledge/modules/app.json', confidence: 'high' }], task_routing: []
  });
  write(path.join(knowledge, 'wiki', 'index.md'), '# Wiki\n');
  write(path.join(knowledge, 'maintenance', 'routing_bundle.json'), {
    schema_version: 'knowledge-routing-bootstrap.v1',
    workspace: { id: 'r6' },
    task_routing: {}
  });
  for (const [name, value] of [
    ['concurrency_policy.json', {}],
    ['trust_report.json', {
      modules_total: 1, modules_low_confidence: 0, stale_artifacts_total: 0,
      modules: { trusted: ['app'], near_trusted: [], routing_trusted: [], advisory_only: [], suspect: [], low_confidence: [] },
      module_statuses: [{ module_id: 'app', trust_status: 'trusted', freshness_status: 'fresh', confidence: 'high' }]
    }],
    ['wiki_lint_report.json', { structural_status: 'healthy' }],
    ['quality_report.json', {}],
    ['repair_queue.json', { queue: [] }]
  ]) write(path.join(knowledge, 'maintenance', name), value);
  write(path.join(knowledge, 'maps', 'wiki_graph.json'), { structural_status: 'healthy' });
  write(path.join(knowledge, 'maps', 'critical_paths.json'), { paths: [] });
  write(path.join(knowledge, 'freshness.json'), { tracked_files: [] });
  const context = {
    targetRoot: root,
    projectKnowledgeRoot: knowledge,
    stateRoot: knowledge,
    repoId: 'r6-repo',
    workspaceId: 'r6',
    git: { changed_files: [] }
  };
  const input = { task: 'app task', modules: ['app'], paths: ['app/'], scopeSource: 'explicit' };
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
    const before = routing.buildSnapshot(x.context, x.scope);
    check('R5-01-production-canonical-baseline-is-claim-eligible', () => {
      assert.equal(before.metrics.claim_eligible, true);
      assert.equal(before.metrics.baseline.schema_version, 'knowledge-workspace-first-read-baseline.v1');
    });

    const custom = path.join(x.root, 'custom-baseline.json');
    write(custom, { schema_version: 'knowledge-routing-baseline.v2', measurement_payload: { files: ['app/b.js'] } });
    check('R5-02-custom-baseline-is-diagnostic-only', () => {
      const diagnostic = routing.__test.diagnoseCustomBaseline(custom);
      assert.equal(diagnostic.claim_eligible, false);
      assert.equal(diagnostic.claim_ineligible_reason, 'custom_baseline_not_claim_eligible');
    });

    write(path.join(x.knowledge, 'maintenance', 'routing_bundle.json'), { foo: 'arbitrary-file-list', files: ['app/b.js'] });
    const afterInjection = routing.buildSnapshot(x.context, x.scope);
    check('R5-03-arbitrary-maintenance-file-list-does-not-change-route', () => assert.equal(afterInjection.snapshot_hash, before.snapshot_hash));
    check('R5-04-arbitrary-maintenance-file-list-does-not-change-baseline', () => assert.equal(afterInjection.metrics.baseline_hash, before.metrics.baseline_hash));
    check('R5-05-arbitrary-maintenance-file-list-does-not-change-comparison', () => assert.equal(afterInjection.metrics.metrics_comparison_hash, before.metrics.metrics_comparison_hash));

    const created = routing.create(x.context, x.input);
    const currentPath = path.join(x.knowledge, 'routing', 'tasks', created.task_scope_hash, 'current.json');
    const current = JSON.parse(fs.readFileSync(currentPath, 'utf8'));
    check('R5-06-current-pointer-names-three-independent-identities', () => {
      assert.equal(current.routing_snapshot_hash, created.snapshot_hash);
      assert.match(current.baseline_hash, /^[a-f0-9]{64}$/);
      assert.match(current.metrics_comparison_hash, /^[a-f0-9]{64}$/);
    });
    check('R5-07-snapshot-does-not-contain-comparison-metrics', () => {
      assert.equal(fs.existsSync(path.join(x.knowledge, 'routing', 'tasks', created.task_scope_hash, 'snapshots', created.snapshot_hash, 'metrics.json')), false);
    });
    check('R5-08-baseline-and-comparison-are-physical-independent-artifacts', () => {
      assert(fs.existsSync(path.join(x.knowledge, 'routing', 'workspace-baselines', current.baseline_hash, 'baseline.json')));
      assert(fs.existsSync(path.join(x.knowledge, 'routing', 'tasks', created.task_scope_hash, 'comparisons', current.metrics_comparison_hash, 'metrics.json')));
    });

    const registry = JSON.parse(fs.readFileSync(path.join(x.knowledge, 'modules', 'module_registry.json')));
    registry.modules.push({ module_id: 'other', name: 'Other', path: 'other/', card: '.knowledge/modules/other.json', purpose: 'Unrelated workspace project', key_files: [] });
    write(path.join(x.knowledge, 'modules', 'module_registry.json'), registry);
    write(path.join(x.knowledge, 'modules', 'other.json'), { module_id: 'other', key_files: [] });
    const project = JSON.parse(fs.readFileSync(path.join(x.knowledge, 'project_index.json')));
    project.modules.push({ module_id: 'other', card: '.knowledge/modules/other.json', confidence: 'high' });
    write(path.join(x.knowledge, 'project_index.json'), project);
    const trust = JSON.parse(fs.readFileSync(path.join(x.knowledge, 'maintenance', 'trust_report.json')));
    trust.modules_total = 2;
    trust.modules.trusted.push('other');
    trust.module_statuses.push({ module_id: 'other', trust_status: 'trusted', freshness_status: 'fresh', confidence: 'high' });
    write(path.join(x.knowledge, 'maintenance', 'trust_report.json'), trust);
    const refreshed = routing.refreshTask(x.context, created.task_scope_hash);
    check('R5-09-baseline-only-change-keeps-routing-snapshot', () => assert.equal(refreshed.current_snapshot_hash, created.snapshot_hash));
    check('R5-10-baseline-only-change-persists-new-comparison', () => {
      assert.notEqual(refreshed.current_baseline_hash, current.baseline_hash);
      assert.notEqual(refreshed.current_metrics_comparison_hash, current.metrics_comparison_hash);
      const reconciled = routing.reconcileTask(x.context, created.task_scope_hash);
      assert.equal(reconciled.current.metrics_comparison_hash, refreshed.current_metrics_comparison_hash);
    });
  } finally {
    fs.rmSync(x.root, { recursive: true, force: true });
  }
  const failed = results.filter((item) => item.status !== 'pass');
  process.stdout.write(`${JSON.stringify({
    schema_version: 'knowledge-routing-rc4-r6-regression-self-test.v1',
    status: failed.length ? 'fail' : 'pass',
    checks_total: results.length,
    results
  }, null, 2)}\n`);
  if (failed.length) process.exitCode = 1;
}

main();
