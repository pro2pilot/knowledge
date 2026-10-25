'use strict';
// Data fixture adapted from self-test-task-routing.js; assertions below exercise
// real persisted routing and live-source transitions through the footer API.
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { test } = require('node:test');
const routing = require('../tools/lib/task-routing');
const footer = require('../tools/agent-footer');
const { removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');
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

function currentFixture(run, scopeSource = 'explicit') {
  const f = fixture();
  try {
    f.context.systemRoot = path.resolve(__dirname, '..');
    f.context.mode = 'repo';
    const file = path.join(f.knowledge, 'maintenance/trust_report.json');
    const trust = JSON.parse(fs.readFileSync(file));
    trust.status = 'healthy'; write(file, trust);
    f.created = routing.create(f.context, {task: 'Audit and update only the Pro2Pilot knowledge website',
      taskClass: 'content_consistency_audit', modules: ['pro2pilot'], paths: ['pro2pilot/'], scopeSource});
    f.settings = {task_id: f.created.task_scope_hash, mode: 'compact', only_when_trust_incomplete: true};
    return run(f);
  } finally { removeTempDirStrict(f.root); }
}

test('healthy cached report cannot hide a footer after actual bound source drift', () => currentFixture(f => {
  const prior = footer.estimateContext(f.context, f.settings);
  assert.equal(prior.status, 'available'); assert.equal(prior.state.live_inputs_match, true);
  assert.equal(footer.renderFooter(f.context, f.settings), '');
  fs.appendFileSync(path.join(f.root, 'pro2pilot/knowledge.html'), '\nchanged live source\n');
  const changed = footer.estimateContext(f.context, f.settings);
  assert.equal(changed.state.live_inputs_match, false); assert.equal(changed.status, 'unavailable');
  const rendered = footer.renderFooter(f.context, f.settings);
  assert.match(rendered, /^\.knowledge: Trust Needs recheck/);
  assert.match(rendered, /live_relevant_input_drift/);
  assert.doesNotMatch(rendered, /[0-9]% reduction/);
  const full = footer.renderFooter(f.context, {...f.settings, mode: 'full'});
  assert.match(full, /Knowledge trust: Needs recheck/);
  assert.match(full, /Saved global report: healthy/);
}));

test('missing bound completion evidence remains visible with incomplete-only settings', () => currentFixture(f => {
  const root = routing.snapshotRoot(f.context, f.created.task_scope_hash, f.created.snapshot_hash);
  fs.unlinkSync(path.join(root, 'complete.json'));
  const rendered = footer.renderFooter(f.context, f.settings);
  assert(rendered.length > 0); assert.match(rendered, /Trust (Unknown|Unavailable)/);
  assert.doesNotMatch(rendered, /Trust healthy/);
}));

test('estimator scope limitation alone does not invent a stale-source warning', () => currentFixture(f => {
  const state = footer.estimateContext(f.context, f.settings);
  assert.equal(state.status, 'unavailable'); assert.equal(state.state.live_inputs_match, true);
  assert.equal(state.state.current_status, 'current'); assert.equal(state.state.task_readiness, 'ready');
  assert(state.state.claim_ineligible_reasons.includes('requires_explicit_frozen_scope'));
  assert.equal(footer.renderFooter(f.context, f.settings), '');
  assert.match(footer.renderFooter(f.context, {...f.settings, only_when_trust_incomplete: false}), /Trust healthy/);
}, 'inferred'));

test('unbound healthy global report is not a current task claim; explicit off still suppresses output', () => {
  const f = fixture();
  try {
    const file = path.join(f.knowledge, 'maintenance/trust_report.json');
    const trust = JSON.parse(fs.readFileSync(file)); trust.status = 'healthy'; write(file, trust);
    const settings = {mode: 'compact', only_when_trust_incomplete: true};
    assert.match(footer.renderFooter(f.context, settings), /Trust Unknown/);
    assert.equal(footer.renderFooter(f.context, {...settings, mode: 'off'}), '');
  } finally { removeTempDirStrict(f.root); }
});
