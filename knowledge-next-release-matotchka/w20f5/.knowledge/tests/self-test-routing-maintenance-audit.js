#!/usr/bin/env node
'use strict';

// Offline regressions for typed scopes, maintenance readers, and queue/score
// boundaries. A runtime override permits exact before/after audit replay.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const systemRoot = path.resolve(process.env.KNOWLEDGE_ROUTING_AUDIT_RUNTIME || path.join(__dirname, '..'));
const parent = path.resolve(process.env.KNOWLEDGE_ROUTING_AUDIT_TMP || os.tmpdir());
const evidenceRoot = process.env.KNOWLEDGE_ROUTING_AUDIT_EVIDENCE ? path.resolve(process.env.KNOWLEDGE_ROUTING_AUDIT_EVIDENCE) : null;
fs.mkdirSync(parent, { recursive: true });
if (evidenceRoot) fs.mkdirSync(evidenceRoot, { recursive: true });
const routing = require(path.join(systemRoot, 'tools/lib/task-routing'));
const repair = require(path.join(systemRoot, 'tools/lib/repair-on-touch'));
const { reconcile } = require(path.join(systemRoot, 'tools/lib/queue-lifecycle'));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const checks = [], commands = [], overrides = [], roots = [];
const started = process.hrtime.bigint();
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function check(name, action) {
  const start = process.hrtime.bigint();
  try { const observation = action(); checks.push({ name, status: 'pass', observation, duration_ms: Number(process.hrtime.bigint() - start) / 1e6 }); }
  catch (error) { checks.push({ name, status: 'fail', error: error.message, stack: error.stack, duration_ms: Number(process.hrtime.bigint() - start) / 1e6 }); }
}
function fixture() {
  const root = fs.mkdtempSync(path.join(parent, 'routing-maintenance-'));
  roots.push(root);
  const knowledge = path.join(root, '.knowledge');
  fs.cpSync(systemRoot, knowledge, { recursive: true });
  const config = path.join(knowledge, 'config.yaml');
  const before = fs.existsSync(config) ? sha(fs.readFileSync(config)) : null;
  write(config, 'updates:\n  enabled: false\n');
  overrides.push({ fixture: root, file: '.knowledge/config.yaml', reason: 'offline fixture only', before_sha256: before, after_sha256: sha(fs.readFileSync(config)), updates_enabled: false });
  const f = { root, knowledge, file: relative => path.join(root, relative), read: relative => JSON.parse(fs.readFileSync(path.join(root, relative), 'utf8')), write: (relative, value) => write(path.join(root, relative), value) };
  const stamp = '2026-10-17T00:00:00.000Z';
  f.write('feature/current.js', 'module.exports = 1;\n');
  f.write('src/registry-only.js', 'module.exports = 2;\n');
  const modules = [
    { module_id: 'root', path: '.', card: '.knowledge/modules/root.json', key_files: [], evidence_files: [] },
    { module_id: 'feature', path: 'feature/', card: '.knowledge/modules/feature.json', key_files: ['feature/current.js'], evidence_files: [] }
  ];
  const docs = {
    'modules/module_registry.json': { modules },
    'project_index.json': { generated_at: stamp, modules: ['root', 'feature'], task_routing: [] },
    'freshness.json': { generated_at: stamp, tracked_files: [{ path: 'feature/current.js', sha256: sha(fs.readFileSync(f.file('feature/current.js'))), status: 'clean' }], artifact_dependencies: {}, artifact_statuses: {} },
    'maintenance/trust_report.json': { generated_at: stamp, modules: { trusted: ['feature'], routing_trusted: ['root'], suspect: [], low_confidence: [] }, module_statuses: [{ module_id: 'feature', trust_status: 'trusted' }, { module_id: 'root', trust_status: 'routing_trusted' }] },
    'maintenance/concurrency_policy.json': {},
    'maintenance/handoff_summary.json': { generated_at: stamp },
    'maintenance/routing_bundle.json': { generated_at: stamp, modules: [] },
    'maintenance/wiki_lint_report.json': { generated_at: stamp, status: 'healthy', structural_status: 'healthy' },
    'maintenance/secret_scan_report.json': { generated_at: stamp, status: 'clean', findings_total: 0, by_severity: {} },
    'maintenance/external_memory_status.json': { generated_at: stamp, providers: [], source_of_truth_policy: { external_memory_source_of_truth: false, external_memory_can_raise_trust: false, external_memory_can_overwrite_curated_knowledge: false } },
    'maintenance/stale_items.json': { items: [] },
    'maintenance/repair_queue.json': { queue: [] },
    'maintenance/sync_log.json': { entries: [] },
    'maintenance/automation_status.json': {},
    'contradictions.json': { items: [] },
    'maps/file_criticality.json': { files: [{ path: 'feature/current.js', classification: 'important' }], coverage_by_module: {} },
    'maps/critical_paths.json': { paths: [] },
    'maps/wiki_graph.json': { generated_at: stamp, status: 'healthy', structural_status: 'healthy', broken_edge_count: 0 },
    'evidence/file_facts.json': { facts: [{ file: 'feature/current.js', evidence: { source_sha256: sha(fs.readFileSync(f.file('feature/current.js'))) } }] },
    'search/index.json': { generated_at: stamp },
    'wiki/index.md': '# Offline fixture\n'
  };
  for (const module of modules) f.write(module.card, { ...module, confidence: 'high', verification_status: 'verified_from_code' });
  for (const [relative, value] of Object.entries(docs)) f.write(`.knowledge/${relative}`, value);
  fs.mkdirSync(f.file('.knowledge/maintenance/events'), { recursive: true });
  return f;
}
function run(f, args) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (/^KNOWLEDGE_/i.test(name) || name === 'NODE_OPTIONS') delete env[name];
  Object.assign(env, { KNOWLEDGE_MODE: 'repo', KNOWLEDGE_SYSTEM_ROOT: f.knowledge, KNOWLEDGE_TARGET_ROOT: f.root, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: f.knowledge, KNOWLEDGE_STATE_ROOT: f.knowledge, KNOWLEDGE_AGENT_ID: 'routing-maintenance-audit', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_DISCOVER_NEW: '0', KNOWLEDGE_FULL_SCAN: '0', GIT_CEILING_DIRECTORIES: f.root, TMPDIR: parent, TEMP: parent, TMP: parent });
  const begin = process.hrtime.bigint();
  const child = spawnSync(process.execPath, args, { cwd: f.root, env, encoding: 'utf8', timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
  const index = String(commands.length + 1).padStart(3, '0');
  const row = { argv: [process.execPath, ...args], cwd: f.root, status: child.status, signal: child.signal, error: child.error?.message || null, duration_ms: Number(process.hrtime.bigint() - begin) / 1e6, stdout_sha256: sha(child.stdout || ''), stderr_sha256: sha(child.stderr || '') };
  if (evidenceRoot) {
    row.stdout_file = `${index}.stdout.log`; row.stderr_file = `${index}.stderr.log`;
    fs.writeFileSync(path.join(evidenceRoot, row.stdout_file), child.stdout || '');
    fs.writeFileSync(path.join(evidenceRoot, row.stderr_file), child.stderr || '');
  }
  commands.push(row);
  let json = null;
  try { json = JSON.parse(child.stdout); } catch { /* Negative CLI cases may return only stderr. */ }
  return { ...child, json };
}
function cli(f, tool, args = []) { return run(f, [f.file(`.knowledge/tools/${tool}`), ...args]); }
function success(result) { assert.equal(result.status, 0, result.stderr || result.stdout); assert(result.json); return result.json; }
const scope = { direct_modules: ['feature'], direct_artifacts: [], dependency_modules: [], dependency_artifacts: [], essential_dependency_modules: [] };
function oneFinding() {
  const stale = { items: [] }, queue = { queue: [] };
  reconcile({ staleItems: stale, repairQueue: queue, source: 'sync', agentId: 'fixture', timestamp: '2026-10-17T00:00:00.000Z', findings: [{ module_id: 'feature', code: 'tracked_file_changed', artifact: 'feature/current.js', severity: 'medium' }] });
  return stale.items[0];
}

check('null lifecycle score cost preserves the severity cost of open debt', () => {
  const row = oneFinding(); assert.equal(row.score_cost, null);
  const result = repair.taskReadiness([row], scope);
  assert.equal(result.score, 93); assert.equal(result.relevant_findings_open, 1); return result;
});
check('negative score cost cannot increase readiness above 100', () => {
  const result = repair.taskReadiness([{ ...oneFinding(), score_cost: -7 }], scope);
  assert.equal(result.score, 93); return result;
});
check('malformed plain readiness scope is unavailable without throwing', () => {
  const result = repair.taskReadiness([oneFinding()], { ...scope, direct_modules: [], direct_artifacts: null });
  assert.equal(result.score, null); assert.equal(result.reason, 'readiness_input_invalid'); return result;
});
check('malformed current cohort row is unavailable without throwing', () => {
  const row = { ...oneFinding(), score_cost: 7 };
  const result = repair.compareTaskReadiness([row], [row, null], scope);
  assert.equal(result.status, 'unavailable'); assert.equal(result.after.score, null); return result;
});
check('invalid readiness scope cannot produce a comparable cohort status', () => {
  const row = { ...oneFinding(), score_cost: 7 };
  const result = repair.compareTaskReadiness([row], [row], []);
  assert.equal(result.status, 'unavailable'); assert.equal(result.after.score, null); return result;
});
check('typed file scope does not widen to descendant module boundaries', () => {
  const context = { targetRoot: parent, repoId: 'scope-fixture', agentId: 'fixture' };
  const canonical = routing.canonicalScope({ task: 'review', paths: ['absent-file'], path_boundaries: [{ path: 'absent-file', directory: false }] }, context);
  const registry = [{ module_id: 'root', path: '.', key_files: [] }, { module_id: 'nested', path: 'absent-file/nested/', key_files: [] }];
  const selected = routing.__test.moduleSelection(registry, canonical).filter(row => row.relevant).map(row => row.module_id);
  assert.deepEqual(selected, ['root']); return { canonical, selected };
});
check('curated and repository directory scopes retain distinct path identities', () => {
  const context = { targetRoot: parent, repoId: 'scope-fixture', agentId: 'fixture' };
  const canonical = routing.canonicalScope({ task: 'review', paths: ['.knowledge/docs/'] }, context);
  const registry = [{ module_id: 'root', path: '.', key_files: [] }, { module_id: 'docs', path: 'docs/', key_files: ['docs/guide.md'] }];
  const selected = routing.__test.moduleSelection(registry, canonical).filter(row => row.relevant).map(row => row.module_id);
  assert.deepEqual(selected, []); return { canonical, selected };
});
check('ordinary dependency targets cannot disappear from an explicit route', () => {
  const context = { targetRoot: parent, repoId: 'scope-fixture', agentId: 'fixture' };
  const canonical = routing.canonicalScope({ task: 'review', modules: ['feature'] }, context);
  for (const declaration of [{ dependencies: ['missing-module'] }, { depends_on: [{}] }]) {
    const registry = [{ module_id: 'root', path: '.' }, { module_id: 'feature', path: 'feature/', ...declaration }];
    assert.throws(() => routing.__test.moduleSelection(registry, canonical), error => error.code === 'module_ownership_invalid');
  }
});
check('Doctor reports a missing card-only source in its declaring module', () => {
  const f = fixture(), card = f.read('.knowledge/modules/feature.json');
  card.key_files.push('feature/card-only-missing.js'); f.write('.knowledge/modules/feature.json', card);
  const result = success(cli(f, 'doctor.js'));
  const row = result.issues.find(item => item.code === 'missing_module_referenced_file' && item.message.includes('feature/card-only-missing.js'));
  assert(row, 'Doctor omitted a card-only missing source'); assert.equal(row.module_id, 'feature'); assert(result.quality_score < 100); return row;
});
check('Doctor source ownership follows declarations instead of a stale freshness label', () => {
  const f = fixture(), freshness = f.read('.knowledge/freshness.json');
  freshness.tracked_files[0].module_id = 'root';
  freshness.tracked_files[0].status = 'needs_recheck';
  f.write('.knowledge/freshness.json', freshness);
  const changed = success(cli(f, 'doctor.js'));
  const changedRow = changed.issues.find(item => item.code === 'tracked_file_needs_recheck' && item.artifact === 'feature/current.js');
  assert(changedRow); assert.equal(changedRow.module_id, 'feature', 'stale freshness module label displaced declared source ownership');
  fs.unlinkSync(f.file('feature/current.js'));
  const missing = success(cli(f, 'doctor.js'));
  const missingRow = missing.issues.find(item => item.code === 'tracked_file_missing' && item.artifact === 'feature/current.js');
  assert(missingRow); assert.equal(missingRow.module_id, 'feature');
  return { changed: changedRow, missing: missingRow };
});
check('sync trust assessment includes registry-only source evidence gaps', () => {
  const f = fixture(), registry = f.read('.knowledge/modules/module_registry.json');
  registry.modules[1].key_files.push('src/registry-only.js'); f.write('.knowledge/modules/module_registry.json', registry);
  const result = success(cli(f, 'sync-tracked.js', ['--scan']));
  assert(result.suspect_modules.includes('feature'), 'registry-only source without evidence was omitted from trust');
  assert(!result.trusted_modules.includes('feature')); return result;
});
check('sync lifecycle ownership includes card-only exact references', () => {
  const f = fixture(), card = f.read('.knowledge/modules/feature.json'), freshness = f.read('.knowledge/freshness.json');
  f.write('shared/card-owned.js', 'module.exports = 3;\n');
  card.key_files.push('shared/card-owned.js'); f.write('.knowledge/modules/feature.json', card);
  freshness.tracked_files.push({ path: 'shared/card-owned.js', sha256: '0'.repeat(64), status: 'changed' }); f.write('.knowledge/freshness.json', freshness);
  success(cli(f, 'sync-tracked.js', ['--scan']));
  const row = f.read('.knowledge/maintenance/stale_items.json').items.find(item => item.affected_artifacts?.includes('shared/card-owned.js'));
  assert(row); assert.equal(row.module_id, 'feature'); return row;
});
check('sync rejects conflicting card/registry primary paths before publishing queues', () => {
  const f = fixture(), card = f.read('.knowledge/modules/feature.json');
  card.path = 'conflicting/'; f.write('.knowledge/modules/feature.json', card);
  const before = ['stale_items.json', 'repair_queue.json'].map(file => sha(fs.readFileSync(f.file(`.knowledge/maintenance/${file}`))));
  const result = cli(f, 'sync-tracked.js', ['--scan']);
  assert.notEqual(result.status, 0, 'sync accepted conflicting ownership declarations');
  const after = ['stale_items.json', 'repair_queue.json'].map(file => sha(fs.readFileSync(f.file(`.knowledge/maintenance/${file}`))));
  assert.deepEqual(after, before); return { status: result.status, before, after };
});
check('Doctor surfaces conflicting primary ownership as a diagnostic blocker', () => {
  const f = fixture(), card = f.read('.knowledge/modules/feature.json');
  card.path = 'conflicting/'; f.write('.knowledge/modules/feature.json', card);
  const result = success(cli(f, 'doctor.js'));
  const row = result.issues.find(item => item.code === 'invalid_module_ownership');
  assert(row, 'Doctor accepted conflicting primary ownership as healthy'); assert.equal(row.safe_during_current_task, false); assert.notEqual(result.status, 'healthy'); return row;
});
check('sync reads the configured curated card instead of a repository shadow', () => {
  const f = fixture(), card = f.read('.knowledge/modules/feature.json');
  card.key_files.push('src/registry-only.js'); f.write('.knowledge/modules/feature.json', card);
  const curated = path.join(f.root, 'curated-knowledge'); fs.renameSync(f.knowledge, curated); f.knowledge = curated;
  f.write('.knowledge/modules/feature.json', { module_id: 'feature', path: 'feature/', key_files: [], evidence_files: [], confidence: 'high', verification_status: 'verified_from_code' });
  const realCard = path.join(curated, 'modules/feature.json'), shadowCard = f.file('.knowledge/modules/feature.json');
  const before = [realCard, shadowCard].map(file => sha(fs.readFileSync(file)));
  const result = success(run(f, [path.join(curated, 'tools/sync-tracked.js'), '--scan']));
  assert(result.suspect_modules.includes('feature'), 'repository shadow suppressed configured curated evidence gaps');
  assert.deepEqual([realCard, shadowCard].map(file => sha(fs.readFileSync(file))), before); return { result, card_sha256: before };
});
check('Doctor does not replace a concurrent writer queue-pair update', () => {
  const f = fixture();
  const hook = path.join(f.root, 'doctor-concurrent-writer.cjs');
  write(hook, `const fs = require('node:fs');\nconst currency = require(${JSON.stringify(f.file('.knowledge/tools/lib/knowledge-currency.js'))});\nconst evaluate = currency.evaluateCurrency;\ncurrency.evaluateCurrency = function(...args) { const result = evaluate(...args); fs.writeFileSync(${JSON.stringify(f.file('.knowledge/maintenance/stale_items.json'))}, JSON.stringify({items:[{id:'concurrent-stale',status:'open',reason:'External observer evidence'}]})); fs.writeFileSync(${JSON.stringify(f.file('.knowledge/maintenance/repair_queue.json'))}, JSON.stringify({queue:[{id:'concurrent-repair',status:'open',subject:'External observer evidence'}]})); return result; };\n`);
  const result = run(f, ['--require', hook, f.file('.knowledge/tools/doctor.js')]);
  const stale = f.read('.knowledge/maintenance/stale_items.json'), queue = f.read('.knowledge/maintenance/repair_queue.json');
  assert(stale.items.some(item => item.id === 'concurrent-stale'), 'Doctor overwrote concurrent stale evidence');
  assert(queue.queue.some(item => item.id === 'concurrent-repair'), 'Doctor overwrote concurrent repair evidence');
  assert.notEqual(result.status, 0, 'stale queue snapshot must fail the guarded publication'); return { status: result.status, stale, queue };
});
check('retained ignored-card cleanup debt remains visible on a second sync', () => {
  const f = fixture(), registry = f.read('.knowledge/modules/module_registry.json');
  const ignored = { module_id: 'retired', path: 'qa-runs/old/', card: '.knowledge/modules/retired.json', key_files: ['qa-runs/old/file.js'] };
  registry.modules.push(ignored); f.write('.knowledge/modules/module_registry.json', registry); f.write(ignored.card, ignored); f.write('qa-runs/old/file.js', 'old\n');
  f.write('.knowledge/maintenance/stale_items.json', { items: [{ id: 'legacy-retired', artifact: ignored.card, status: 'needs_recheck', reason: 'Retained historical card' }] });
  f.write('.knowledge/maintenance/repair_queue.json', { queue: [{ id: 'legacy-retired-repair', affected_artifacts: [ignored.card], status: 'open', subject: 'Retained historical card' }] });
  const before = sha(fs.readFileSync(f.file(ignored.card)));
  const first = success(cli(f, 'sync-tracked.js', ['--scan'])), second = success(cli(f, 'sync-tracked.js', ['--scan']));
  assert(first.preserved_cleanup_debt.ignored_module_cards.includes(ignored.card));
  assert(second.preserved_cleanup_debt.ignored_module_cards.includes(ignored.card), 'second sync hid retained ignored-card debt');
  assert(second.preserved_cleanup_debt.legacy_stale_items.some(item => item.id === 'legacy-retired'));
  assert.equal(sha(fs.readFileSync(f.file(ignored.card))), before); return { first: first.preserved_cleanup_debt, second: second.preserved_cleanup_debt, card_sha256: before };
});
check('raw repaired status never improves the native cohort without closure provenance', () => {
  const f = fixture(), row = { ...oneFinding(), score_cost: 7 }, artifact = { task_scope: scope, opportunities: [{ ...row, status: 'selected' }] };
  f.write('.knowledge/maintenance/stale_items.json', { items: [{ ...row, status: 'repaired' }] });
  f.write('.knowledge/maintenance/repair_queue.json', { queue: [{ ...row, status: 'repaired' }] });
  const snippet = `const assert = require('node:assert/strict'); const { sanitizedOpportunityProjection } = require(${JSON.stringify(f.file('.knowledge/tools/repair-on-touch.js'))}); const result = sanitizedOpportunityProjection(${JSON.stringify(artifact)}, {lifecycle_ids:[],receipts:[],dedicated_receipts:[],invalid:[],status:'verified'}); console.log(JSON.stringify(result)); assert.equal(result.task_readiness_before.score,93); assert.equal(result.task_readiness_after.score,93); assert.equal(result.current_findings[0].status,'open');`;
  return success(run(f, ['--eval', snippet]));
});

for (const mode of ['error_with_zero_exit', 'signal_with_zero_exit', 'physical_success']) {
  check(`native verification transport: ${mode}`, () => {
    const f = fixture();
    f.write('tests/verify-current.js', "require('node:assert/strict').equal(require('../feature/current.js'), 1); console.log('physical verification child passed');\n");
    const simulated = mode === 'physical_success' ? '' : `require('node:child_process').spawnSync = () => { transportCalls += 1; return { status: 0, signal: ${mode === 'signal_with_zero_exit' ? "'SIGTERM'" : 'null'}, error: ${mode === 'error_with_zero_exit' ? "Object.assign(new Error('synthetic transport failure'), {code:'EPERM'})" : 'undefined'}, stdout: Buffer.from(''), stderr: Buffer.from('') }; };`;
    // An unrelated capability refusal must not count as exercising transport.
    const assertions = mode === 'physical_success'
      ? "assert.equal(error,null);assert.equal(result[0].record.status,'pass');assert(result[0].record.stdout_bytes>0);"
      : "assert.equal(transportCalls,1,'transport stub must be exercised exactly once: '+JSON.stringify({transport_stub_calls:transportCalls,error}));assert.equal(error?.code,'verification_transport_failed','transport error or signal must fail with its specific code');assert.equal(files.length,0,'transport failure published verification authority');";
    const snippet = `const assert=require('node:assert/strict');const fs=require('node:fs');let transportCalls=0;${simulated}const native=require(${JSON.stringify(f.file('.knowledge/tools/lib/repair-on-touch.js'))});let result=null,error=null;try{result=native.runVerificationTests({stateRoot:${JSON.stringify(f.knowledge)},repoRoot:${JSON.stringify(f.root)},taskId:'transport-fixture',sessionId:'transport-session',tests:[{argv:['node','tests/verify-current.js'],cwd:'.',timeout_ms:10000}],sourceFiles:[{path:'feature/current.js'}],checkedBy:'transport-fixture'});}catch(caught){error={code:caught.code,message:caught.message,validation:caught.validation};}const directory=${JSON.stringify(f.file('.knowledge/maintenance/verification_executions'))};const files=fs.existsSync(directory)?fs.readdirSync(directory):[];console.log(JSON.stringify({result,error,files,transport_stub_calls:transportCalls}));${assertions}`;
    return success(run(f, ['--eval', snippet]));
  });
}

const cleanup = [];
for (const root of roots) {
  const realParent = fs.realpathSync.native(parent), realRoot = fs.realpathSync.native(root), relative = path.relative(realParent, realRoot);
  assert(relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative), 'fixture cleanup escaped its owned parent');
  fs.rmSync(realRoot, { recursive: true, force: false }); cleanup.push({ root, removed: !fs.existsSync(root) });
}
const result = { status: checks.every(row => row.status === 'pass') ? 'pass' : 'fail', checks_total: checks.length, checks_passed: checks.filter(row => row.status === 'pass').length, runtime_root: systemRoot, node: process.execPath, node_version: process.version, duration_ms: Number(process.hrtime.bigint() - started) / 1e6, checks, commands, fixture_overrides: overrides, cleanup, evidence_kind: 'isolated regression; synthetic state is not native verification authority' };
if (evidenceRoot) write(path.join(evidenceRoot, 'result.json'), result);
console.log(JSON.stringify(result, null, 2));
if (result.status !== 'pass') process.exitCode = 1;
