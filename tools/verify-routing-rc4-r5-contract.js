#!/usr/bin/env node
'use strict';

// Maintainer-only R5 verifier.  It extracts the supplied candidate and uses
// fresh physical workspaces; it never consumes candidate self-test counters.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function sha(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function zipSha(file) { return sha(fs.readFileSync(file)); }
function flag(argv, name) {
  const entry = argv.find((item) => item.startsWith(`--${name}=`));
  return entry ? entry.slice(name.length + 3) : null;
}
function fixture(candidate) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-r5-contract-'));
  const knowledge = path.join(root, '.knowledge');
  write(path.join(root, 'app', 'a.js'), 'module.exports = 1;\n');
  write(path.join(root, 'app', 'b.js'), 'module.exports = 2;\n');
  write(path.join(knowledge, 'modules', 'module_registry.json'), {
    modules: [{ module_id: 'app', path: 'app/', key_files: ['app/a.js'] }]
  });
  write(path.join(knowledge, 'project_index.json'), { task_routing: [] });
  for (const [name, value] of [
    ['concurrency_policy.json', {}],
    ['trust_report.json', { module_statuses: [{ module_id: 'app', trust_status: 'trusted' }] }],
    ['wiki_lint_report.json', { structural_status: 'healthy' }],
    ['quality_report.json', {}],
    ['repair_queue.json', { generated_at: 'first', queue: [{ module_id: 'app', status: 'open', updated_at: 'first' }] }]
  ]) write(path.join(knowledge, 'maintenance', name), value);
  write(path.join(knowledge, 'maps', 'wiki_graph.json'), { structural_status: 'healthy' });
  write(path.join(knowledge, 'maps', 'critical_paths.json'), { paths: [] });
  write(path.join(knowledge, 'freshness.json'), { tracked_files: [] });
  return {
    root,
    knowledge,
    context: {
      mode: 'repo', systemRoot: candidate, targetRoot: root,
      projectKnowledgeRoot: knowledge, stateRoot: knowledge,
      repoId: 'r5-contract', workspaceId: 'r5-contract',
      agentId: 'r5-contract', git: { changed_files: [] }
    }
  };
}
function baseline(x, routing, changes = {}) {
  const scope = routing.canonicalScope({
    task: 'app change', modules: ['app'], paths: ['app/'], scopeSource: 'explicit'
  }, x.context);
  const body = fs.readFileSync(path.join(x.root, 'app', 'a.js'));
  return {
    scope,
    value: {
      schema_version: 'knowledge-routing-baseline.v2',
      workspace_id: x.context.workspaceId,
      repository_id: x.context.repoId,
      task_scope_hash: scope.task_scope_hash,
      method: 'task_first_read_baseline.v2',
      measurement_payload: { files: [{ path: 'app/a.js', sha256: sha(body) }], policy_inputs: [] },
      provenance: { generated_by: 'independent-r5-verifier' },
      ...changes
    }
  };
}
function install(x, value) { write(path.join(x.knowledge, 'maintenance', 'routing_bundle.json'), value); }
function main() {
  const zip = flag(process.argv.slice(2), 'zip');
  const out = flag(process.argv.slice(2), 'out') || path.join(process.cwd(), 'verify-routing-rc4-r5-contract.json');
  if (!zip || !fs.existsSync(path.resolve(zip))) throw new Error('--zip=<physical candidate ZIP> is required');
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-r5-candidate-'));
  const results = [];
  const check = (id, setup, command, expected, fn) => {
    try { results.push({ id, setup, command, expected, actual: fn() ?? 'observed', status: 'pass' }); }
    catch (error) { results.push({ id, setup, command, expected, actual: error.message, status: 'fail' }); }
  };
  try {
    const extracted = path.join(sandbox, 'candidate');
    const command = `Expand-Archive -LiteralPath '${path.resolve(zip).replace(/'/g, "''")}' -DestinationPath '${extracted.replace(/'/g, "''")}' -Force`;
    const expanded = spawnSync('powershell.exe', ['-NoProfile', '-Command', command], { encoding: 'utf8', windowsHide: true });
    if (expanded.status !== 0) throw new Error(`candidate extraction failed: ${expanded.stderr || expanded.stdout}`);
    const candidate = path.join(extracted, '.knowledge');
    for (const relative of ['tools/lib/task-routing.js', 'tools/field-report.js', 'tools/lib/field-report/renderer.js']) {
      assert(fs.existsSync(path.join(candidate, relative)), `candidate missing ${relative}`);
    }
    const routing = require(path.join(candidate, 'tools', 'lib', 'task-routing.js'));
    const readCandidate = (relative) => fs.readFileSync(path.join(candidate, relative), 'utf8');
    check('R5-01-v1-diagnostic-only', 'v1 bootstrap', 'buildSnapshot', 'not comparable and named legacy reason', () => {
      const x = fixture(candidate); try {
        install(x, { schema_version: 'knowledge-routing-bootstrap.v1', workspace: {}, global_health: {}, task_routing: {}, first_read_strategy: {} });
        const m = routing.buildSnapshot(x.context, baseline(x, routing).scope).metrics;
        assert.equal(m.scope_comparable, false); assert(m.claim_ineligible_reasons.includes('legacy_baseline_v1_not_claim_eligible'));
        return m.claim_ineligible_reasons;
      } finally { fs.rmSync(x.root, { recursive: true, force: true }); }
    });
    check('R5-02-v2-identity-and-method-enforced', 'foreign workspace/repository and arbitrary method', 'buildSnapshot', 'all rejected', () => {
      const x = fixture(candidate); try {
        for (const changes of [{ workspace_id: 'foreign' }, { repository_id: 'foreign' }, { method: 'arbitrary.v9' }]) {
          const b = baseline(x, routing, changes); install(x, b.value);
          assert.equal(routing.buildSnapshot(x.context, b.scope).metrics.baseline_complete, false);
        }
        return 'three identity/method mutations rejected';
      } finally { fs.rmSync(x.root, { recursive: true, force: true }); }
    });
    check('R5-03-v2-payload-is-canonical-and-recounted', 'declared token, item padding, duplicate path', 'buildSnapshot', 'all rejected', () => {
      const x = fixture(candidate); try {
        const mutations = [
          (b) => { b.measurement_payload.files[0].estimated_tokens = 1000000; },
          (b) => { b.measurement_payload.files[0].padding = 'x'; },
          (b) => { b.measurement_payload.files.push({ ...b.measurement_payload.files[0] }); }
        ];
        for (const mutate of mutations) { const b = baseline(x, routing); mutate(b.value); install(x, b.value); assert.equal(routing.buildSnapshot(x.context, b.scope).metrics.baseline_complete, false); }
        return 'three non-canonical payloads rejected';
      } finally { fs.rmSync(x.root, { recursive: true, force: true }); }
    });
    check('R5-04-baseline-affects-only-comparison-identity', 'valid v2 baseline changes', 'buildSnapshot twice', 'snapshot stable, comparison changes', () => {
      const x = fixture(candidate); try {
        const first = baseline(x, routing); install(x, first.value); const before = routing.buildSnapshot(x.context, first.scope);
        const second = baseline(x, routing); const b = fs.readFileSync(path.join(x.root, 'app', 'b.js')); second.value.measurement_payload.files.push({ path: 'app/b.js', sha256: sha(b) }); install(x, second.value);
        const after = routing.buildSnapshot(x.context, second.scope);
        assert.equal(before.snapshot_hash, after.snapshot_hash); assert.notEqual(before.metrics.metrics_comparison_hash, after.metrics.metrics_comparison_hash);
        return { snapshot: after.snapshot_hash, comparison: after.metrics.metrics_comparison_hash };
      } finally { fs.rmSync(x.root, { recursive: true, force: true }); }
    });
    check('R5-05-operational-repair-and-policy-metadata-does-not-churn-routing', 'timestamp-only repair and policy changes', 'buildSnapshot twice', 'same snapshot identity', () => {
      const x = fixture(candidate); try {
        const b = baseline(x, routing); install(x, b.value); const before = routing.buildSnapshot(x.context, b.scope);
        write(path.join(x.knowledge, 'maintenance', 'repair_queue.json'), { generated_at: 'second', queue: [{ module_id: 'app', status: 'open', updated_at: 'second' }] });
        write(path.join(x.knowledge, 'project_index.json'), { task_routing: [], generated_at: 'second' });
        const after = routing.buildSnapshot(x.context, b.scope);
        assert.equal(before.snapshot_hash, after.snapshot_hash); return after.snapshot_hash;
      } finally { fs.rmSync(x.root, { recursive: true, force: true }); }
    });
    check('R5-06-field-report-live-attestation-is-in-source-and-hashed', 'candidate Field Report implementation', 'source contract inspection', 'refresh at all public stages and approval payload binding', () => {
      const source = readCandidate('tools/field-report.js');
      for (const token of ['refreshLiveRouting(context, manifest, reportPaths, \'render\')', 'refreshLiveRouting(context, manifest, reportPaths, \'approval\')', 'refreshLiveRouting(context, manifest, reportPaths, \'preview\')', 'refreshLiveRouting(context, manifest, reportPaths, \'final publication\')', 'routing_attestation']) assert(source.includes(token), token);
      return 'render/approve/preview/publish and payload bind live routing';
    });
    check('R5-07-overhead-rendering-is-branch-aware', 'candidate renderer', 'source contract inspection', 'positive only saving/overhead rows', () => {
      const source = readCandidate('tools/lib/field-report/renderer.js'); assert(source.includes('Number(item.value) <= 0')); return 'zero-valued branch omitted';
    });
    const names = spawnSync('powershell.exe', ['-NoProfile', '-Command', `Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::OpenRead('${path.resolve(zip).replace(/'/g, "''")}').Entries | ForEach-Object FullName`], { encoding: 'utf8', windowsHide: true });
    check('R5-08-zip-entry-portability', 'candidate ZIP central directory', 'ZipFile entry list', 'forward slash names only', () => { assert.equal(names.status, 0, names.stderr); assert(!names.stdout.includes('\\')); return 'forward slashes only'; });
  } finally { fs.rmSync(sandbox, { recursive: true, force: true }); }
  const report = { schema_version: 'knowledge-routing-rc4-r5-contract.v1', candidate_sha256: zipSha(path.resolve(zip)), checks_total: results.length, results, status: results.every((row) => row.status === 'pass') ? 'pass' : 'fail' };
  write(path.resolve(out), report);
  process.stdout.write(`${JSON.stringify({ status: report.status, checks_total: report.checks_total, output: path.resolve(out) })}\n`);
  if (report.status !== 'pass') process.exitCode = 1;
}
try { main(); } catch (error) { process.stderr.write(`${error.stack || error.message}\n`); process.exitCode = 1; }
