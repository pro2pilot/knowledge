#!/usr/bin/env node
'use strict';

// Deterministic fixture coverage for STF-004.  The fixture is deliberately
// external to this checkout so it exercises the public --target-root path.
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const doctorStatus = require('./doctor').__test;
const { canonicalWikiStatus } = require('./lib/wiki-status');
const { collect: collectFieldReportFacts } = require('./lib/field-report/collector');
const { withTempFixture } = require('./lib/strict-temp-cleanup');

const systemRoot = path.resolve(__dirname, '..');

function assert(condition, message) { if (!condition) throw new Error(message); }
function write(filePath, value) { fs.mkdirSync(path.dirname(filePath), { recursive: true }); fs.writeFileSync(filePath, value, 'utf8'); }
function writeJson(filePath, value) { write(filePath, `${JSON.stringify(value, null, 2)}\n`); }
function sha256(filePath) { return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex'); }
function artifactState(root, relativePath) {
  const filePath = path.join(root, ...relativePath.split('/'));
  if (!fs.existsSync(filePath)) return { path: relativePath, exists: false };
  const stat = fs.statSync(filePath);
  let parsed = null;
  if (relativePath.endsWith('.json')) {
    try { parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (_) { /* hash is still authoritative */ }
  }
  return {
    path: relativePath,
    exists: true,
    size: stat.size,
    sha256: sha256(filePath),
    mtime_ms: stat.mtimeMs,
    generated_at: parsed?.generated_at ?? null,
    producer: parsed?.generated_by ?? parsed?.producer ?? null,
    transaction_id: parsed?.transaction_id ?? parsed?.generation_id ?? null
  };
}
function page(title, links = '') { return `---\ntrust: advisory_only\nlinks:${links ? `\n  related: ${links}` : ''}\n---\n# ${title}\n`; }
function withWikiFixture(label, pages, callback) {
  return withTempFixture({
    prefix: 'knowledge-wiki-structure-',
    evidenceDir: process.env.KNOWLEDGE_WIKI_FAILURE_DIR || null,
    evidenceLabel: label,
    keepOnFailure: false
  }, (repo) => {
    for (const [file, body] of Object.entries(pages)) write(path.join(repo, '.knowledge', 'wiki', file), body);
    return callback(repo);
  });
}
function lint(repo) {
  const fixtureKnowledgeRoot = path.join(repo, '.knowledge');
  const result = spawnSync(process.execPath, [path.join(systemRoot, 'tools', 'lint-wiki.js'), '--system-root', fixtureKnowledgeRoot, '--target-root', repo, '--quiet'], { encoding: 'utf8', windowsHide: true, env: { ...process.env, KNOWLEDGE_SYSTEM_ROOT: fixtureKnowledgeRoot, KNOWLEDGE_TARGET_ROOT: repo } });
  assert(result.status === 0, `lint failed: ${result.stderr || result.stdout}`);
  return JSON.parse(fs.readFileSync(path.join(repo, '.knowledge', 'maintenance', 'wiki_lint_report.json'), 'utf8'));
}
function lintStrictExit(repo) {
  const fixtureKnowledgeRoot = path.join(repo, '.knowledge');
  return spawnSync(process.execPath, [path.join(systemRoot, 'tools', 'lint-wiki.js'), '--system-root', fixtureKnowledgeRoot, '--target-root', repo, '--strict', '--quiet'], {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, KNOWLEDGE_SYSTEM_ROOT: fixtureKnowledgeRoot, KNOWLEDGE_TARGET_ROOT: repo }
  }).status;
}
function runTool(repo, tool, args = []) {
  const fixtureKnowledgeRoot = path.join(repo, '.knowledge');
  const result = spawnSync(process.execPath, [
    path.join(systemRoot, 'tools', tool),
    '--system-root', fixtureKnowledgeRoot,
    '--target-root', repo,
    '--project-knowledge-root', fixtureKnowledgeRoot,
    '--state-root', fixtureKnowledgeRoot,
    ...args
  ], {
    encoding: 'utf8',
    windowsHide: true,
    env: {
      ...process.env,
      KNOWLEDGE_AGENT_ID: 'wiki-status-self-test',
      KNOWLEDGE_SYSTEM_ROOT: fixtureKnowledgeRoot,
      KNOWLEDGE_TARGET_ROOT: repo,
      KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: fixtureKnowledgeRoot,
      KNOWLEDGE_STATE_ROOT: fixtureKnowledgeRoot
    }
  });
  const commandRoot = path.join(fixtureKnowledgeRoot, 'maintenance', 'wiki-self-test-commands');
  fs.mkdirSync(commandRoot, { recursive: true });
  const commandId = `${String(fs.readdirSync(commandRoot).filter((name) => name.endsWith('.json')).length + 1).padStart(2, '0')}-${tool.replace(/[^a-z0-9]+/gi, '-')}`;
  write(path.join(commandRoot, `${commandId}.stdout.txt`), result.stdout || '');
  write(path.join(commandRoot, `${commandId}.stderr.txt`), result.stderr || '');
  writeJson(path.join(commandRoot, `${commandId}.json`), {
    command_id: commandId,
    tool,
    args,
    exit_code: result.status,
    signal: result.signal || null,
    state_root: fixtureKnowledgeRoot,
    system_root: fixtureKnowledgeRoot,
    target_root: repo
  });
  assert(result.status === 0, `${tool} failed: ${result.stderr || result.stdout}`);
  return result;
}
function statusOf(name, pages, expected) {
  return withWikiFixture(name, pages, (repo) => {
    const report = lint(repo);
    assert(report.structural_status === expected, `${name}: expected ${expected}, got ${report.structural_status}`);
    assert(report.status === expected, `${name}: aggregate status ${report.status} must equal structural status ${expected}`);
    return { name, structural_status: report.structural_status, status: report.status };
  });
}

function main() {
  assert(
    doctorStatus.statusWithStructure(93, 0, 'structurally_broken') === 'structurally_broken',
    'doctor aggregate must preserve structurally_broken'
  );
  assert(doctorStatus.statusWithStructure(40, 2, 'healthy') === 'usable_with_warnings', 'doctor low score must use the exact warning enum');
  assert(doctorStatus.statusWithStructure(100, 0, 'usable_with_warnings') === 'usable_with_warnings', 'doctor must preserve structural warnings');
  const correct = { 'index.md': '# Index\n[good](good.md)\n', 'good.md': page('Good') };
  const checks = [
    { name: 'doctor_aggregate_override', structural_status: 'structurally_broken', status: 'structurally_broken' },
    statusOf('correct', correct, 'healthy'),
    statusOf('broken', { 'index.md': '# Index\n[bad](bad.md)\n', 'bad.md': page('Bad', 'missing.md') }, 'structurally_broken'),
    statusOf('duplicate', { 'index.md': '# Index\n[one](one.md)\n[two](two.md)\n', 'one.md': page('Same'), 'two.md': page('Same') }, 'usable_with_warnings'),
    statusOf('orphan', { 'index.md': '# Index\n', 'alone.md': page('Alone') }, 'usable_with_warnings'),
    statusOf('multiple', { 'index.md': '# Index\n[first](first.md)\n[second](second.md)\n', 'first.md': page('Same', 'missing.md'), 'second.md': page('Same'), 'orphan.md': page('Orphan') }, 'structurally_broken')
  ];
  const divergentMatrix = [
    {
      name: 'lint_healthy_graph_broken',
      lint: { status: 'healthy', structural_status: 'healthy' },
      graph: { structural_status: 'structurally_broken', broken_edge_count: 1 },
      expected: 'structurally_broken'
    },
    {
      name: 'lint_warning_graph_healthy',
      lint: { status: 'usable_with_warnings', structural_status: 'usable_with_warnings' },
      graph: { structural_status: 'healthy', broken_edge_count: 0 },
      expected: 'usable_with_warnings'
    },
    {
      name: 'lint_broken_graph_healthy',
      lint: { status: 'structurally_broken', structural_status: 'structurally_broken' },
      graph: { structural_status: 'healthy', broken_edge_count: 0 },
      expected: 'structurally_broken'
    },
    {
      name: 'graph_broken_edges_array_without_summary',
      lint: { status: 'healthy', structural_status: 'healthy' },
      graph: { broken_edges: [{ from: 'index.md', to: 'missing.md' }] },
      expected: 'structurally_broken'
    },
    {
      name: 'same_generated_at_broken_graph_wins',
      lint: { generated_at: '2026-08-01T00:00:00.000Z', status: 'healthy', structural_status: 'healthy' },
      graph: { generated_at: '2026-08-01T00:00:00.000Z', structural_status: 'structurally_broken', broken_edge_count: 1 },
      expected: 'structurally_broken'
    },
    {
      name: 'backwards_timestamp_broken_graph_wins',
      lint: { generated_at: '2026-08-02T00:00:00.000Z', status: 'healthy', structural_status: 'healthy' },
      graph: { generated_at: '2026-07-31T00:00:00.000Z', structural_status: 'structurally_broken', broken_edge_count: 1 },
      expected: 'structurally_broken'
    },
    {
      name: 'older_lint_broken_status_wins',
      lint: { generated_at: '2026-07-31T00:00:00.000Z', status: 'structurally_broken', structural_status: 'structurally_broken' },
      graph: { generated_at: '2026-08-02T00:00:00.000Z', structural_status: 'healthy', broken_edge_count: 0 },
      expected: 'structurally_broken'
    }
  ];
  for (const item of divergentMatrix) {
    const observed = canonicalWikiStatus(item.lint, item.graph);
    assert(observed === item.expected, `${item.name}: expected ${item.expected}, got ${observed}`);
    checks.push({ name: item.name, structural_status: observed, status: observed });
  }

  withWikiFixture('strict-healthy', correct, (strictHealthy) => {
    assert(lintStrictExit(strictHealthy) === 0, 'strict CI gate must pass a healthy graph');
    checks.push({ name: 'strict_healthy_exit', observed_process_exit: 0 });
  });

  withWikiFixture('strict-broken', { 'index.md': '# Index\n[bad](bad.md)\n', 'bad.md': page('Bad', 'missing.md') }, (strictBroken) => {
    assert(lintStrictExit(strictBroken) === 2, 'strict CI gate must block a structurally broken graph');
    checks.push({ name: 'strict_broken_exit', observed_process_exit: 2 });
  });

  withWikiFixture('repaired', { 'index.md': '# Index\n[repair](repair.md)\n', 'repair.md': page('Repair', 'missing.md') }, (repairedRepo) => {
    assert(lint(repairedRepo).structural_status === 'structurally_broken', 'repaired precondition must be broken');
    write(path.join(repairedRepo, '.knowledge', 'wiki', 'target.md'), page('Target'));
    write(path.join(repairedRepo, '.knowledge', 'wiki', 'index.md'), '# Index\n[repair](repair.md)\n[target](target.md)\n');
    write(path.join(repairedRepo, '.knowledge', 'wiki', 'repair.md'), page('Repair', 'target.md'));
    const repaired = lint(repairedRepo);
    assert(repaired.structural_status === 'healthy', `repaired: expected healthy, got ${repaired.structural_status}`);
    checks.push({ name: 'repaired', structural_status: repaired.structural_status, status: repaired.status });
  });

  withWikiFixture('cross-consumer-divergence', correct, (divergentRepo) => {
    const checkpoints = [];
    const fixtureKnowledgeRoot = path.join(divergentRepo, '.knowledge');
    const checkpoint = (id, expected, actual, artifactPaths) => {
      const record = {
        checkpoint: id,
        expected,
        actual,
        pass: expected === actual,
        state_root: fixtureKnowledgeRoot,
        system_root: fixtureKnowledgeRoot,
        target_root: divergentRepo,
        artifacts: artifactPaths.map((item) => artifactState(divergentRepo, item))
      };
      checkpoints.push(record);
      writeJson(path.join(fixtureKnowledgeRoot, 'maintenance', 'wiki-self-test-checkpoints.json'), { checkpoints });
      assert(record.pass, `${id}: expected ${expected}, got ${actual}`);
      return record;
    };
    writeJson(path.join(fixtureKnowledgeRoot, 'maintenance', 'wiki-self-test-environment.json'), {
      platform: process.platform,
      arch: process.arch,
      node_version: process.version,
      os_release: os.release(),
      temp_path: os.tmpdir(),
      state_root: fixtureKnowledgeRoot,
      system_root: fixtureKnowledgeRoot,
      target_root: divergentRepo
    });
    const healthyLint = lint(divergentRepo);
    assert(healthyLint.status === 'healthy', 'divergent fixture must start healthy');
    const graphPath = path.join(fixtureKnowledgeRoot, 'maps', 'wiki_graph.json');
    const brokenGraph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
    brokenGraph.generated_at = healthyLint.generated_at;
    brokenGraph.structural_status = 'structurally_broken';
    brokenGraph.broken_edge_count = 1;
    brokenGraph.summary = { ...(brokenGraph.summary || {}), structural_status: 'structurally_broken' };
    writeJson(graphPath, brokenGraph);
    const manualGraphHash = sha256(graphPath);
    checkpoint('A-manual-broken-graph', 'structurally_broken', canonicalWikiStatus(healthyLint, brokenGraph), [
      '.knowledge/maintenance/wiki_lint_report.json',
      '.knowledge/maps/wiki_graph.json'
    ]);

    runTool(divergentRepo, 'build-routing-bundle.js', ['--task', 'edit docs', '--quiet']);
    const routing = JSON.parse(fs.readFileSync(path.join(fixtureKnowledgeRoot, 'maintenance', 'routing_bundle.json'), 'utf8'));
    assert(routing.schema_version === 'knowledge-routing-bootstrap.v1' &&
      routing.pointers.maintenance_debt === 'maintenance/maintenance_debt.json',
    'routing bootstrap did not preserve the task/global separation contract');
    assert(sha256(graphPath) === manualGraphHash, 'routing unexpectedly rewrote the manual broken graph');
    checkpoint('B-after-routing', 'structurally_broken', canonicalWikiStatus(healthyLint, JSON.parse(fs.readFileSync(graphPath, 'utf8'))), [
      '.knowledge/maintenance/wiki_lint_report.json',
      '.knowledge/maps/wiki_graph.json',
      '.knowledge/maintenance/routing_bundle.json',
      '.knowledge/maintenance/maintenance_debt.json'
    ]);

    runTool(divergentRepo, 'doctor.js', ['--quiet']);
    const quality = JSON.parse(fs.readFileSync(path.join(fixtureKnowledgeRoot, 'maintenance', 'quality_report.json'), 'utf8'));
    assert(quality.structural_status === 'structurally_broken' &&
      quality.status === 'structurally_broken', 'Doctor downgraded divergent broken graph');
    checkpoint('C-after-doctor', 'structurally_broken', quality.structural_status, [
      '.knowledge/maintenance/wiki_lint_report.json',
      '.knowledge/maps/wiki_graph.json',
      '.knowledge/maintenance/quality_report.json'
    ]);

    runTool(divergentRepo, 'build-visual-inspector.js', ['--quiet']);
    const inspectorData = JSON.parse(fs.readFileSync(path.join(fixtureKnowledgeRoot, 'inspector', 'data.json'), 'utf8'));
    assert(inspectorData.wikiStatus === 'structurally_broken', 'Inspector data downgraded divergent broken graph');
    checkpoint('D-after-inspector', 'structurally_broken', inspectorData.wikiStatus, [
      '.knowledge/maintenance/wiki_lint_report.json',
      '.knowledge/maps/wiki_graph.json',
      '.knowledge/inspector/data.json'
    ]);

    runTool(divergentRepo, 'generate-pr-summary.js');
    const prSummary = fs.readFileSync(path.join(fixtureKnowledgeRoot, 'maintenance', 'pr_summary.md'), 'utf8');
    assert(/Wiki lint: structurally_broken/.test(prSummary), 'PR summary downgraded divergent broken graph');
    checkpoint('E-after-pr-summary', 'structurally_broken', /Wiki lint: structurally_broken/.test(prSummary) ? 'structurally_broken' : 'downgraded', [
      '.knowledge/maintenance/wiki_lint_report.json',
      '.knowledge/maps/wiki_graph.json',
      '.knowledge/maintenance/pr_summary.md'
    ]);

    const facts = collectFieldReportFacts({
      stateRoot: fixtureKnowledgeRoot,
      systemRoot: fixtureKnowledgeRoot,
      targetRoot: divergentRepo,
      mode: 'repo',
      branch: null,
      headSha: null
    });
    assert(facts.values.wiki_structural_status.value === 'structurally_broken' &&
      facts.values.wiki_structural_status.kind === 'derived',
    'Field Report collector downgraded divergent broken graph');
    writeJson(path.join(fixtureKnowledgeRoot, 'maintenance', 'field-report-facts.json'), facts);
    checkpoint('F-after-field-report', 'structurally_broken', facts.values.wiki_structural_status.value, [
      '.knowledge/maintenance/wiki_lint_report.json',
      '.knowledge/maps/wiki_graph.json',
      '.knowledge/maintenance/quality_report.json',
      '.knowledge/inspector/data.json',
      '.knowledge/maintenance/pr_summary.md',
      '.knowledge/maintenance/field-report-facts.json'
    ]);

    checks.push({
      name: 'cross_consumer_divergence_fail_closed',
      routing: routing.schema_version,
      doctor: quality.structural_status,
      inspector: inspectorData.wikiStatus,
      pr_summary: 'structurally_broken',
      field_report: facts.values.wiki_structural_status.value
      , checkpoints
    });
  });

  console.log(JSON.stringify({ status: 'pass', checks }, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
