#!/usr/bin/env node
'use strict';
// Focused RC4-R4 contract checks. Each assertion builds a physical temp
// workspace; no mocked routing state is used.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const routing = require('./lib/task-routing');
const state = require('./lib/task-routing-state');
function write(file, value) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`); }
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-rc4-r4-')); const k = path.join(root, '.knowledge');
  write(path.join(root, 'app', 'a.js'), 'module.exports = 1;\n'); write(path.join(root, 'other.js'), 'x\n');
  write(path.join(k, 'modules', 'app.json'), { module_id: 'app', key_files: ['app/a.js'] });
  write(path.join(k, 'modules', 'module_registry.json'), { modules: [{ module_id: 'app', name: 'App', path: 'app/', card: '.knowledge/modules/app.json', purpose: 'Application fixture', key_files: ['app/a.js'] }] });
  write(path.join(k, 'project_index.json'), { project_name: 'r4-fixture', repo_root: '.', primary_source_of_truth: 'code', modules: [{ module_id: 'app', card: '.knowledge/modules/app.json', confidence: 'high' }], task_routing: [] });
  write(path.join(k, 'maintenance', 'routing_bundle.json'), { schema_version: 'knowledge-routing-bootstrap.v1', workspace: { id: 'r4' }, global_health: { status: 'healthy' }, task_routing: { command: 'task-routing' }, pointers: {}, first_read_strategy: { read_first: '.knowledge/maintenance/routing_bundle.json' } });
  for (const [file, value] of [['concurrency_policy.json', {}], ['trust_report.json', { modules_total: 1, modules_low_confidence: 0, modules: { trusted: ['app'], near_trusted: [], routing_trusted: [], advisory_only: [], suspect: [], low_confidence: [] }, module_statuses: [{ module_id: 'app', trust_status: 'trusted', freshness_status: 'fresh', confidence: 'high' }] }], ['wiki_lint_report.json', { structural_status: 'healthy' }], ['quality_report.json', {}], ['repair_queue.json', { queue: [] }]]) write(path.join(k, 'maintenance', file), value);
  write(path.join(k, 'maps', 'wiki_graph.json'), { structural_status: 'healthy' }); write(path.join(k, 'maps', 'critical_paths.json'), { paths: [] }); write(path.join(k, 'freshness.json'), { tracked_files: [] });
  return { root, k, context: { targetRoot: root, projectKnowledgeRoot: k, stateRoot: k, repoId: 'r4-fixture', workspaceId: 'r4', agentId: 'r4', git: { changed_files: [] } } };
}
function main() {
  const x = fixture(); const checks = []; const check = (id, fn) => { fn(); checks.push(id); };
  try {
    const input = { task: 'app change', modules: ['app'], paths: ['app/'], scopeSource: 'explicit' };
    const initialScope = routing.canonicalScope(input, x.context);
    const initialBody = fs.readFileSync(path.join(x.root, 'app', 'a.js'));
    write(path.join(x.k, 'maintenance', 'routing_bundle.json'), { schema_version: 'knowledge-routing-baseline.v2', workspace_id: 'r4', repository_id: x.context.repoId, task_scope_hash: initialScope.task_scope_hash, snapshot_marker: 'fixture', method: 'task_first_read_baseline.v2', measurement_payload: { files: [{ path: 'app/a.js', sha256: require('crypto').createHash('sha256').update(initialBody).digest('hex') }], policy_inputs: [] }, provenance: { generated_at: 'fixed', generated_by: 'test' } });
    const created = routing.create(x.context, input);
    check('R4-01-current-route-is-effectively-eligible', () => { const resolved = state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }); assert.equal(resolved.effective_claim_eligible, true, JSON.stringify({ effective: resolved.claim_ineligible_reasons, immutable: resolved.metrics.claim_ineligible_reasons, read: resolved.metrics.claim_eligible, created: created.metrics.claim_eligible })); });
    routing.invalidate(x.context, created.task_scope_hash, 'test');
    check('R4-02-invalidated-route-is-not-effectively-eligible', () => assert.equal(state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }).effective_claim_eligible, false));
    check('R4-03-invalidated-route-names-stale-reason', () => assert(state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }).claim_ineligible_reasons.includes('task_routing_snapshot_stale')));
    routing.refreshTask(x.context, created.task_scope_hash); fs.appendFileSync(path.join(x.root, 'app', 'a.js'), '// drift\n');
    check('R4-04-live-relevant-drift-is-not-eligible', () => assert.equal(state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }).effective_claim_eligible, false));
    check('R4-05-live-relevant-drift-names-reason', () => assert(state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }).claim_ineligible_reasons.includes('live_relevant_input_drift')));
    const invalid = path.join(x.k, 'maintenance', 'routing_bundle.json'); write(invalid, { foo: 'bar' });
    check('R4-06-arbitrary-bootstrap-cannot-replace-canonical-baseline', () => assert.equal(routing.buildSnapshot(x.context, routing.canonicalScope(input, x.context)).metrics.comparison_contract_valid, true));
    const scoped = routing.canonicalScope(input, x.context); const appBody = fs.readFileSync(path.join(x.root, 'app', 'a.js'));
    const baselineV2 = { schema_version: 'knowledge-routing-baseline.v2', workspace_id: 'r4', repository_id: 'wrong-repository', task_scope_hash: scoped.task_scope_hash, snapshot_marker: 'fixture', method: 'task_first_read_baseline.v2', measurement_payload: { files: [{ path: 'app/a.js', sha256: require('crypto').createHash('sha256').update(appBody).digest('hex') }], policy_inputs: [] }, provenance: { generated_at: 'fixed', generated_by: 'test' } };
    write(invalid, baselineV2);
    check('R4-07-custom-baseline-is-diagnostic-only', () => {
      const diagnostic = routing.__test.diagnoseCustomBaseline(invalid);
      assert.equal(diagnostic.claim_eligible, false);
      assert.equal(diagnostic.claim_ineligible_reason, 'custom_baseline_not_claim_eligible');
      assert.equal(routing.buildSnapshot(x.context, scoped).metrics.baseline_complete, true);
    });
    baselineV2.repository_id = x.context.repoId; write(invalid, baselineV2);
    check('R4-08-valid-custom-baseline-still-cannot-authorize-a-claim', () => {
      const diagnostic = routing.__test.diagnoseCustomBaseline(invalid);
      assert.equal(diagnostic.claim_eligible, false);
      assert.equal(routing.buildSnapshot(x.context, scoped).metrics.baseline_complete, true);
    });
    const over = state.formatTaskRoutingEstimate({ assessment: 'estimated_overhead', signed_delta_percent: -4, workspace_baseline: { estimated_tokens: 100 }, task_context: { estimated_tokens: 104 } }, { effective_claim_eligible: true });
    check('R4-09-overhead-is-never-rendered-as-saved', () => assert(/overhead/.test(over) && !/saved|reduction/.test(over)));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-rc4-r4-outside-')); write(path.join(outside, 'secret.txt'), 'must not be read');
    try { fs.symlinkSync(outside, path.join(x.root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir'); check('R4-10-parent-symlink-or-junction-is-never-read', () => assert.equal(routing.__test.fileData(x.root, 'escape/secret.txt'), null)); }
    finally { fs.rmSync(outside, { recursive: true, force: true }); }
    const noOp = fixture();
    try {
      const noOpScope = routing.canonicalScope(input, noOp.context);
      const noOpBody = fs.readFileSync(path.join(noOp.root, 'app', 'a.js'));
      write(path.join(noOp.k, 'maintenance', 'routing_bundle.json'), { schema_version: 'knowledge-routing-baseline.v2', workspace_id: 'r4', repository_id: noOp.context.repoId, task_scope_hash: noOpScope.task_scope_hash, snapshot_marker: 'fixture', method: 'task_first_read_baseline.v2', measurement_payload: { files: [{ path: 'app/a.js', sha256: require('crypto').createHash('sha256').update(noOpBody).digest('hex') }], policy_inputs: [] }, provenance: { generated_at: 'fixed', generated_by: 'test' } });
      const first = routing.create(noOp.context, input); const refresh = routing.refreshTask(noOp.context, first.task_scope_hash);
      check('R4-11-no-op-refresh-keeps-snapshot-identity', () => assert.equal(refresh.status, 'current') && assert.equal(refresh.current_snapshot_hash, first.snapshot_hash));
      fs.appendFileSync(path.join(noOp.root, 'other.js'), '// unrelated\n');
      check('R4-12-unrelated-drift-keeps-route-current', () => assert.equal(state.resolveEffectiveTaskRoutingState({ context: noOp.context, taskScopeHash: first.task_scope_hash }).effective_claim_eligible, true));
    } finally { fs.rmSync(noOp.root, { recursive: true, force: true }); }
    const multi = fixture();
    try {
      const first = routing.create(multi.context, input);
      routing.create(multi.context, { task: 'other app change', modules: ['app'], paths: ['other.js'], scopeSource: 'explicit' });
      const common = ['--target-root', multi.root, '--system-root', x.k, '--project-knowledge-root', multi.k, '--state-root', multi.k];
      childProcess.execFileSync(process.execPath, [path.join(__dirname, 'generate-pr-summary.js'), ...common], { encoding: 'utf8' });
      const ambiguous = fs.readFileSync(path.join(multi.k, 'maintenance', 'pr_summary.md'), 'utf8');
      check('R4-15-multi-task-pr-summary-is-ambiguous-without-explicit-id', () => assert(ambiguous.includes('task_routing_context_ambiguous') && !/estimated token reduction/i.test(ambiguous)));
      childProcess.execFileSync(process.execPath, [path.join(__dirname, 'generate-pr-summary.js'), ...common, '--task-id', first.task_scope_hash], { encoding: 'utf8' });
      const selected = fs.readFileSync(path.join(multi.k, 'maintenance', 'pr_summary.md'), 'utf8');
      check('R4-16-multi-task-pr-summary-uses-explicit-task-id', () => assert(!selected.includes('task_routing_context_ambiguous')));
    } finally { fs.rmSync(multi.root, { recursive: true, force: true }); }
    const continuation = fixture();
    try {
      const stale = [];
      for (let i = 0; i < 40; i += 1) { const relative = `app/high-risk-${i}.js`; write(path.join(continuation.root, relative), `// ${i}\n`); stale.push({ path: relative, status: 'missing' }); }
      write(path.join(continuation.k, 'freshness.json'), { tracked_files: stale });
      const metrics = routing.buildSnapshot(continuation.context, routing.canonicalScope(input, continuation.context)).metrics;
      check('R4-13-mandatory-continuations-are-explicitly-accounted', () => assert(metrics.mandatory_continuation_estimated_tokens > 0 && metrics.routing_total_estimated_tokens === metrics.inline_estimated_tokens + metrics.mandatory_continuation_estimated_tokens));
      check('R4-14-incomplete-mandatory-continuation-blocks-claim', () => assert.equal(metrics.claim_eligible, false));
    } finally { fs.rmSync(continuation.root, { recursive: true, force: true }); }
    assert.equal(checks.length, 16); console.log(JSON.stringify({ schema_version: 'knowledge-routing-rc4-r4-self-test.v1', status: 'pass', checks_total: checks.length, results: checks.map((id) => ({ id, status: 'pass' })) }, null, 2));
  } finally { fs.rmSync(x.root, { recursive: true, force: true }); }
}
try { main(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 1; }
