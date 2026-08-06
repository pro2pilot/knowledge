#!/usr/bin/env node
'use strict';
// Maintainer-only verifier. It never reads bundled self-test result counters:
// every assertion below creates and mutates a fresh physical candidate fixture.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function sha(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function write(file, value) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`); }
function flags(argv) { return Object.fromEntries(argv.filter((item) => item.startsWith('--')).map((item) => { const [key, value = ''] = item.slice(2).split(/=(.*)/s); return [key, value]; })); }
function fixture(candidate) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-r4-contract-'));
  const k = path.join(root, '.knowledge');
  write(path.join(root, 'app', 'a.js'), 'module.exports = 1;\n'); write(path.join(root, 'other.js'), 'module.exports = 2;\n');
  write(path.join(k, 'modules', 'module_registry.json'), { modules: [{ module_id: 'app', path: 'app/', key_files: ['app/a.js'] }] });
  write(path.join(k, 'project_index.json'), { task_routing: [] });
  write(path.join(k, 'maintenance', 'routing_bundle.json'), { schema_version: 'knowledge-routing-bootstrap.v1', workspace: { id: 'r4-contract' }, global_health: { status: 'healthy' }, task_routing: { command: 'task-routing' }, pointers: {}, first_read_strategy: { read_first: '.knowledge/maintenance/routing_bundle.json' } });
  for (const [name, value] of [['concurrency_policy.json', {}], ['trust_report.json', { module_statuses: [{ module_id: 'app', trust_status: 'trusted' }] }], ['wiki_lint_report.json', { structural_status: 'healthy' }], ['quality_report.json', {}], ['repair_queue.json', { queue: [] }]]) write(path.join(k, 'maintenance', name), value);
  write(path.join(k, 'maps', 'wiki_graph.json'), { structural_status: 'healthy' }); write(path.join(k, 'maps', 'critical_paths.json'), { paths: [] }); write(path.join(k, 'freshness.json'), { tracked_files: [] });
  return { root, k, context: { mode: 'repo', systemRoot: candidate, targetRoot: root, projectKnowledgeRoot: k, stateRoot: k, repoId: 'r4-contract-fixture', agentId: 'r4-contract', git: { changed_files: [] } }, candidate };
}
function runProcess(command, args, options) { return spawnSync(command, args, { encoding: 'utf8', windowsHide: true, ...options }); }
function verify(zip, out) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-r4-candidate-'));
  const results = []; const evidence = [];
  const check = (id, setup, command, expected, fn) => {
    try { const actual = fn(); results.push({ id, setup, command, expected, actual: actual ?? 'observed', status: 'pass' }); }
    catch (error) { results.push({ id, setup, command, expected, actual: error.message, status: 'fail' }); }
  };
  try {
    const extracted = path.join(sandbox, 'candidate');
    const expand = runProcess('powershell.exe', ['-NoProfile', '-Command', `Expand-Archive -LiteralPath '${zip.replace(/'/g, "''")}' -DestinationPath '${extracted.replace(/'/g, "''")}' -Force`]);
    if (expand.status !== 0) throw new Error(`candidate extraction failed: ${expand.stderr || expand.stdout}`);
    const candidate = path.join(extracted, '.knowledge');
    for (const relative of ['tools/lib/task-routing.js', 'tools/lib/task-routing-state.js', 'tools/lib/field-report/collector.js', 'tools/generate-pr-summary.js', 'tools/build-visual-inspector.js']) assert(fs.existsSync(path.join(candidate, relative)), `candidate missing ${relative}`);
    const routing = require(path.join(candidate, 'tools', 'lib', 'task-routing'));
    const state = require(path.join(candidate, 'tools', 'lib', 'task-routing-state'));
    const collector = require(path.join(candidate, 'tools', 'lib', 'field-report', 'collector'));
    const input = { task: 'app change', modules: ['app'], paths: ['app/'], scopeSource: 'explicit' };
    const x = fixture(candidate);
    try {
      const created = routing.create(x.context, input);
      check('R4-01-current-route-eligible', 'fresh route', 'resolveEffectiveTaskRoutingState', 'effective eligible', () => { assert.equal(state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }).effective_claim_eligible, true); return 'eligible'; });
      routing.invalidate(x.context, created.task_scope_hash, 'contract');
      check('R4-02-invalidate-blocks-state', 'invalidate fresh route', 'state resolver', 'ineligible with stale reason', () => { const v = state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }); assert.equal(v.effective_claim_eligible, false); assert(v.claim_ineligible_reasons.includes('task_routing_snapshot_stale')); return v.claim_ineligible_reasons; });
      check('R4-03-field-report-uses-live-state', 'invalidated route', 'Field Report collector', 'routing claim false', () => { const facts = collector.collect(x.context, { routingTaskId: created.task_scope_hash }); assert.equal(facts.values.routing_claim_eligible.value, false); return facts.values.routing_claim_ineligible_reason.value; });
      routing.refreshTask(x.context, created.task_scope_hash); fs.appendFileSync(path.join(x.root, 'app', 'a.js'), '// relevant drift\n');
      check('R4-04-relevant-drift-blocks-state', 'mutated relevant source without refresh', 'state resolver', 'ineligible live drift', () => { const v = state.resolveEffectiveTaskRoutingState({ context: x.context, taskScopeHash: created.task_scope_hash }); assert.equal(v.effective_claim_eligible, false); assert(v.claim_ineligible_reasons.includes('live_relevant_input_drift')); return v.claim_ineligible_reasons; });
      check('R4-05-inspector-uses-live-state', 'relevant drift fixture', 'build-visual-inspector', 'claim_eligible false', () => { const r = runProcess(process.execPath, [path.join(candidate, 'tools', 'build-visual-inspector.js'), '--target-root', x.root, '--system-root', candidate, '--project-knowledge-root', x.k, '--state-root', x.k], { cwd: extracted }); assert.equal(r.status, 0, r.stderr || r.stdout); const data = JSON.parse(fs.readFileSync(path.join(x.k, 'inspector', 'data.json'), 'utf8')); const route = (data.taskRouting?.tasks || []).find((item) => item.task_scope_hash === created.task_scope_hash); assert(route); assert.equal(route.claim_eligible, false); return route.claim_ineligible_reasons; });
    } finally { fs.rmSync(x.root, { recursive: true, force: true }); }
    const unrelated = fixture(candidate);
    try { const c = routing.create(unrelated.context, input); fs.appendFileSync(path.join(unrelated.root, 'other.js'), '// unrelated\n'); check('R4-06-unrelated-drift-stays-current', 'mutated unrelated source', 'state resolver', 'effective eligible', () => { assert.equal(state.resolveEffectiveTaskRoutingState({ context: unrelated.context, taskScopeHash: c.task_scope_hash }).effective_claim_eligible, true); return 'eligible'; }); } finally { fs.rmSync(unrelated.root, { recursive: true, force: true }); }
    const baseline = fixture(candidate);
    try { const scope = routing.canonicalScope(input, baseline.context); write(path.join(baseline.k, 'maintenance', 'routing_bundle.json'), { foo: 'bar' }); check('R4-07-arbitrary-baseline-rejected', 'arbitrary baseline JSON', 'buildSnapshot', 'not comparable', () => { assert.equal(routing.buildSnapshot(baseline.context, scope).metrics.scope_comparable, false); return 'not comparable'; }); } finally { fs.rmSync(baseline.root, { recursive: true, force: true }); }
    const padding = fixture(candidate);
    try { const scope = routing.canonicalScope(input, padding.context); const before = routing.buildSnapshot(padding.context, scope); const bundle = JSON.parse(fs.readFileSync(path.join(padding.k, 'maintenance', 'routing_bundle.json'), 'utf8')); bundle.untrusted_padding = 'x'.repeat(100000); write(path.join(padding.k, 'maintenance', 'routing_bundle.json'), bundle); check('R4-08-padding-does-not-change-identity', 'v1 baseline with metadata padding', 'buildSnapshot twice', 'same snapshot/comparison identity', () => { const after = routing.buildSnapshot(padding.context, scope); assert.equal(after.snapshot_hash, before.snapshot_hash); assert.equal(after.metrics.metrics_comparison_hash, before.metrics.metrics_comparison_hash); return after.snapshot_hash; }); } finally { fs.rmSync(padding.root, { recursive: true, force: true }); }
    const repeat = fixture(candidate);
    try { const c = routing.create(repeat.context, input); check('R4-09-no-op-refresh-stable', 'unchanged route', 'refreshTask', 'same snapshot and comparison hashes', () => { const r = routing.refreshTask(repeat.context, c.task_scope_hash); assert.equal(r.status, 'current'); assert.equal(r.current_snapshot_hash, c.snapshot_hash); assert.equal(r.current_metrics_comparison_hash, c.metrics.metrics_comparison_hash); return r.current_snapshot_hash; }); } finally { fs.rmSync(repeat.root, { recursive: true, force: true }); }
    check('R4-10-overhead-is-not-savings', 'overhead metrics', 'shared formatter', 'explicit overhead and no saved/reduction', () => { const text = state.formatTaskRoutingEstimate({ assessment: 'estimated_overhead', estimated_tokens_overhead: 27, estimated_percent_overhead: 4 }, { effective_claim_eligible: true }); assert(/overhead/.test(text) && !/saved|reduction/i.test(text)); return text; });
    const containment = fixture(candidate); const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-r4-outside-'));
    try { write(path.join(outside, 'secret.txt'), 'outside'); fs.symlinkSync(outside, path.join(containment.root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir'); check('R4-11-parent-link-cannot-be-read', 'external parent symlink/junction', 'candidate fileData', 'null', () => { assert.equal(routing.__test.fileData(containment.root, 'escape/secret.txt'), null); return 'not read'; }); } finally { fs.rmSync(containment.root, { recursive: true, force: true }); fs.rmSync(outside, { recursive: true, force: true }); }
    const continuation = fixture(candidate);
    try { const tracked = []; for (let i = 0; i < 40; i += 1) { const p = `app/high-${i}.js`; write(path.join(continuation.root, p), `// ${i}\n`); tracked.push({ path: p, status: 'missing' }); } write(path.join(continuation.k, 'freshness.json'), { tracked_files: tracked }); check('R4-12-continuations-are-accounted-and-block-incomplete', 'high-risk stale paths', 'buildSnapshot', 'explicit totals and ineligible', () => { const m = routing.buildSnapshot(continuation.context, routing.canonicalScope(input, continuation.context)).metrics; assert(m.mandatory_continuation_estimated_tokens > 0); assert.equal(m.routing_total_estimated_tokens, m.inline_estimated_tokens + m.mandatory_continuation_estimated_tokens); assert.equal(m.claim_eligible, false); return { inline: m.inline_estimated_tokens, mandatory: m.mandatory_continuation_estimated_tokens }; }); } finally { fs.rmSync(continuation.root, { recursive: true, force: true }); }
    const multi = fixture(candidate);
    try { const first = routing.create(multi.context, input); routing.create(multi.context, { task: 'other app change', modules: ['app'], paths: ['other.js'], scopeSource: 'explicit' }); const args = [path.join(candidate, 'tools', 'generate-pr-summary.js'), '--target-root', multi.root, '--system-root', candidate, '--project-knowledge-root', multi.k, '--state-root', multi.k]; check('R4-13-multi-task-requires-explicit-id', 'two current routes', 'generate-pr-summary', 'ambiguous without ID, resolved with ID', () => { let r = runProcess(process.execPath, args, { cwd: extracted }); assert.equal(r.status, 0, r.stderr); const a = fs.readFileSync(path.join(multi.k, 'maintenance', 'pr_summary.md'), 'utf8'); assert(a.includes('task_routing_context_ambiguous')); r = runProcess(process.execPath, [...args, '--task-id', first.task_scope_hash], { cwd: extracted }); assert.equal(r.status, 0, r.stderr); const b = fs.readFileSync(path.join(multi.k, 'maintenance', 'pr_summary.md'), 'utf8'); assert(!b.includes('task_routing_context_ambiguous')); return 'ambiguous then explicit'; }); } finally { fs.rmSync(multi.root, { recursive: true, force: true }); }
    evidence.push({ candidate_extracted: true, verifier: 'independent physical fixtures', internal_test_counters_used: false });
  } finally { fs.rmSync(sandbox, { recursive: true, force: true }); }
  const report = { schema_version: 'knowledge-routing-contract-verification.v3', candidate_sha256: sha(zip), checks_total: results.length, results, evidence, status: results.length && results.every((row) => row.status === 'pass') ? 'pass' : 'fail' };
  fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`); fs.writeFileSync(out.replace(/\.json$/i, '.md'), `# Routing RC4-R4 contract verification\n\nCandidate SHA-256: \`${report.candidate_sha256}\`\n\nStatus: **${report.status}**\n\n${results.map((row) => `- ${row.id}: ${row.status}`).join('\n')}\n`);
  process.stdout.write(`${JSON.stringify({ status: report.status, output: out, checks_total: report.checks_total }, null, 2)}\n`); if (report.status !== 'pass') process.exitCode = 1;
}
try { const f = flags(process.argv.slice(2)); if (!f.zip || !fs.existsSync(path.resolve(f.zip))) throw new Error('--zip=<physical candidate ZIP> is required'); verify(path.resolve(f.zip), f.out ? path.resolve(f.out) : path.join(process.cwd(), 'routing-contract-verification.json')); } catch (error) { console.error(error.stack || error.message); process.exitCode = 1; }
