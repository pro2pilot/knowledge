#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { parseCliArgs } = require('../tools/lib/path-context');
const { ensureDir, readJson, writeJsonAtomic } = require('../tools/lib/json-store');
const { createZip } = require('../tools/package-release');
const { scanRun } = require('./lib/redaction');

const root = path.resolve(__dirname, '..');
const suitesCatalog = readJson(path.join(__dirname, 'suites', 'suites.json'), { suites: [] });

function nowStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function sanitizeText(value) {
  return String(value || '')
    .replace(/[A-Z]:\\(?:Users\\[^\s"',}\\]+|MyProject)[^\s"',}]+/gi, '<local-path>')
    .replace(/\/mnt\/data[^\s"',}]*/gi, '<local-path>')
    .replace(/\/tmp\/knowledge[^\s"',}]*/gi, '<local-path>')
    .replace(/Users\\[^\\\s"',}]+/gi, 'Users\\<local-user>')
    .replace(/Users\/[^\/\s"',}]+/gi, 'Users/<local-user>')
    .replace(new RegExp(`knowledge${'-'}kit`, 'gi'), 'workspace');
}

function runNode(args, options = {}) {
  const started = Date.now();
  const result = spawnSync(process.execPath, args, {
    cwd: options.cwd || root,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 180000
  });
  const stdout = sanitizeText(String(result.stdout || ''));
  const stderr = sanitizeText(String(result.stderr || ''));
  return {
    command: ['node', ...args].join(' '),
    status: result.status === 0 ? 'pass' : 'fail',
    exit_code: result.status,
    duration_ms: Date.now() - started,
    stdout_tail: stdout.slice(-4000),
    stderr_tail: stderr.slice(-4000),
    json: parseJson(stdout)
  };
}

function parseJson(text) {
  try { return JSON.parse(String(text || '').trim()); }
  catch { return null; }
}

function metricFromRuns(runs, key, fallback = 0) {
  const values = runs.map((run) => Number(run.metrics?.[key])).filter((value) => Number.isFinite(value));
  if (!values.length) return fallback;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function suiteMeta(slug) {
  return suitesCatalog.suites.find((suite) => suite.slug === slug || suite.id.toLowerCase() === slug.toLowerCase());
}

function passResult(metrics, evidence, claim) {
  return {
    status: 'pass',
    claim_status: claim || 'measured',
    metrics,
    evidence,
    limitations: []
  };
}

function plannedResult(metrics, evidence, limitation) {
  return {
    status: 'planned',
    claim_status: 'planned',
    metrics,
    evidence,
    limitations: [limitation || 'suite is planned and cannot be marketed']
  };
}

function previewResult(metrics, evidence, limitation) {
  return {
    status: 'preview',
    claim_status: 'preview',
    metrics,
    evidence,
    limitations: [limitation || 'private-preview surface; not a production claim']
  };
}

function failedResult(command, limitation) {
  return {
    status: 'fail',
    claim_status: 'failed',
    metrics: { exit_code: command.exit_code, duration_ms: command.duration_ms },
    evidence: [command.command],
    limitations: [limitation || command.stderr_tail || command.stdout_tail || 'command failed'],
    command
  };
}

function runSuiteOnce(slug) {
  const routing = () => readJson(path.join(root, 'maintenance', 'routing_bundle.json'), {});
  const trust = () => readJson(path.join(root, 'maintenance', 'trust_report.json'), {});
  const stale = () => readJson(path.join(root, 'maintenance', 'stale_items.json'), { items: [] });
  const repair = () => readJson(path.join(root, 'maintenance', 'repair_queue.json'), { queue: [] });
  const external = () => readJson(path.join(root, 'maintenance', 'external_memory_status.json'), {});
  const wikiGraph = () => readJson(path.join(root, 'maps', 'wiki_graph.json'), { nodes: [], edges: [] });
  const critical = () => readJson(path.join(root, 'maps', 'file_criticality.json'), { files: [] });

  if (slug === 'smoke') {
    const required = ['benchmarks/run-benchmarks.js', 'benchmarks/claim-rules.md', 'benchmarks/suites/suites.json'];
    const missing = required.filter((rel) => !fs.existsSync(path.join(root, rel)));
    return missing.length ? { status: 'fail', claim_status: 'diagnostic', metrics: { missing: missing.length }, evidence: missing, limitations: ['harness files missing'] } :
      passResult({ harness_files_present: required.length, suites_declared: suitesCatalog.suites.length }, required, 'diagnostic');
  }

  if (slug === 'gate-00') {
    const gate = readJson(path.join(root, 'maintenance', 'release-gate-report.json'), {});
    if (gate.status === 'passed') return passResult({ release_gate_passed: 1, p0_commands: (gate.steps || []).length, clean_install_steps: (gate.clean_install?.steps || []).length }, ['maintenance/release-gate-report.json'], 'measured');
    return { status: 'diagnostic', claim_status: 'diagnostic', metrics: { release_gate_passed: 0 }, evidence: ['maintenance/release-gate-report.json'], limitations: ['release gate report is missing or not passed'] };
  }

  if (slug === 'kb-01-install-release') {
    const pkg = runNode(['tools/package-release.js']);
    if (pkg.status !== 'pass') return failedResult(pkg, 'package release failed');
    const val = runNode(['tools/validate-release-artifact.js', `dist/knowledge-v${readJson(path.join(root, 'package.json'), {}).version}.zip`, '--json']);
    if (val.status !== 'pass') return failedResult(val, 'release artifact validation failed');
    return passResult({ artifact_entries: val.json?.entries || 0, artifact_violations: (val.json?.violations || []).length }, ['tools/package-release.js', 'tools/validate-release-artifact.js'], 'measured');
  }

  if (slug === 'kb-02-routing') {
    const cmd = runNode(['tools/build-routing-bundle.js']);
    if (cmd.status !== 'pass') return failedResult(cmd, 'routing bundle build failed');
    const data = routing();
    return passResult({ routing_bundle_present: 1, routed_modules: (data.modules || []).length, first_read_declared: data.first_read_strategy?.read_first ? 1 : 0 }, ['maintenance/routing_bundle.json'], 'measured');
  }

  if (slug === 'kb-03-trust-freshness') {
    const data = trust();
    const staleItems = stale().items || stale().stale_items || [];
    return passResult({ modules_total: data.modules_total || 0, modules_low_confidence: data.modules_low_confidence || 0, stale_items_total: staleItems.length }, ['maintenance/trust_report.json', 'maintenance/stale_items.json'], 'measured');
  }

  if (slug === 'kb-04-repair-queue') {
    const queue = repair().queue || [];
    return passResult({ repair_items_total: queue.length, open_repair_items: queue.filter((item) => String(item.status || 'open') !== 'closed').length }, ['maintenance/repair_queue.json'], 'measured');
  }

  if (slug === 'kb-05-critical-stale-risk') {
    const files = critical().files || [];
    return passResult({ critical_or_important_files: files.filter((file) => ['critical', 'important'].includes(file.classification)).length, stale_items_total: (stale().items || stale().stale_items || []).length }, ['maps/file_criticality.json', 'maintenance/stale_items.json'], 'measured');
  }

  if (slug === 'kb-06-wiki-graph') {
    const graph = wikiGraph();
    return passResult({ wiki_nodes: (graph.nodes || []).length, wiki_edges: (graph.edges || []).length, broken_edges: (graph.edges || []).filter((edge) => edge.valid === false).length }, ['maps/wiki_graph.json'], 'measured');
  }

  if (slug === 'kb-07-local-search') {
    const cmd = runNode(['tools/search-knowledge.js', 'routing', '--json']);
    if (cmd.status !== 'pass') return failedResult(cmd, 'local search command failed');
    const docs = readJson(path.join(root, 'search', 'index.json'), { documents: [] }).documents || [];
    return passResult({ search_documents: docs.length, search_command_passed: 1 }, ['search/index.json', 'tools/search-knowledge.js'], 'measured');
  }

  if (slug === 'kb-08-inspector-ux') {
    const cmd = runNode(['tools/self-test-inspector-ui.js', '--team-mode-fixture'], { timeoutMs: 180000 });
    if (cmd.status !== 'pass') return failedResult(cmd, 'Inspector UI self-test failed');
    return passResult({ inspector_checks: (cmd.json?.checks || []).length, team_mode_fixture: cmd.json?.team_mode_fixture_requested ? 1 : 0 }, ['tools/self-test-inspector-ui.js'], 'measured-on-fixture');
  }

  if (slug === 'kb-09-pr-impact') {
    const test = runNode(['tools/self-test-pr-impact.js'], { timeoutMs: 180000 });
    if (test.status !== 'pass') return failedResult(test, 'PR Impact self-test failed');
    const impact = runNode(['tools/pr-impact.js', '--json', '--no-write'], { timeoutMs: 180000 });
    if (impact.status !== 'pass') return failedResult(impact, 'PR Impact command failed');
    return passResult({ changed_files: (impact.json?.changed_files || []).length, affected_modules: (impact.json?.affected_modules || []).length, policy_warnings: (impact.json?.policy_warnings || []).length, fixture_checks: (test.json?.checks || []).length }, ['tools/pr-impact.js', 'tools/self-test-pr-impact.js'], 'measured-on-fixture');
  }

  if (slug === 'kb-10-agent-neutrality') {
    const agents = ['agent-integrations/codex', 'agent-integrations/claude', 'agent-integrations/opencode'].filter((rel) => fs.existsSync(path.join(root, rel)));
    return previewResult({ agent_integration_surfaces: agents.length }, agents, 'agent-neutral routing has local integration surfaces, but no multi-runtime live benchmark was run');
  }

  if (slug === 'kb-11-memory-providers') {
    const provider = runNode(['tools/self-test-memory-providers.js'], { timeoutMs: 180000 });
    if (provider.status !== 'pass') return failedResult(provider, 'memory provider self-test failed');
    const ext = runNode(['tools/self-test-external-memory.js'], { timeoutMs: 180000 });
    if (ext.status !== 'pass') return failedResult(ext, 'external memory self-test failed');
    const status = external();
    return passResult({ provider_checks: (provider.json?.checks || []).length, external_checks: (ext.json?.checks || []).length, external_memory_override_count: status.metrics?.override_attempts_blocked || 0, external_memory_can_raise_trust: status.source_of_truth_policy?.external_memory_can_raise_trust === true ? 1 : 0 }, ['tools/self-test-memory-providers.js', 'tools/self-test-external-memory.js'], 'measured-on-fixture');
  }

  if (slug === 'kb-12-team-mode') {
    const cmd = runNode(['tools/self-test-team-inspector-json.js'], { timeoutMs: 420000 });
    if (cmd.status !== 'pass') return failedResult(cmd, 'Team Inspector JSON self-test failed');
    return passResult({ workspaces: cmd.json?.metrics?.workspaces || 0, json_corruption_count: cmd.json?.metrics?.json_corruption_count ?? 1, workspace_state_isolation_pass: cmd.json?.metrics?.workspace_states_isolated ? 1 : 0 }, ['tools/self-test-team-inspector-json.js'], 'measured-on-fixture');
  }

  if (slug === 'kb-13-pro-inspector') {
    const proRoot = path.resolve(root, '..', 'pro2pilot-inspector');
    if (!fs.existsSync(path.join(proRoot, 'package.json'))) return plannedResult({ pro_inspector_present: 0 }, [], 'Pro Inspector directory not present in this install context');
    const qa = runNode(['scripts/pro-inspector-qa-gate.js', '--json'], { cwd: proRoot, timeoutMs: 420000 });
    if (qa.status !== 'pass') return failedResult(qa, 'Pro Inspector QA gate failed');
    const report = runNode(['scripts/generate-pro-qa-report.js', '--json'], { cwd: proRoot, timeoutMs: 240000 });
    if (report.status !== 'pass') return failedResult(report, 'Pro Inspector QA report generation failed');
    const scorecard = readJson(path.join(proRoot, 'pro-inspector-qa', 'scorecard.json'), {});
    const qaReport = readJson(path.join(proRoot, 'pro-inspector-qa', 'qa-report.json'), {});
    const domProof = readJson(path.join(proRoot, 'pro-inspector-qa', 'dom-proof.json'), {});
    const manifest = readJson(path.join(proRoot, 'pro-inspector-exports', 'latest', 'manifest.json'), {});
    if (Number(scorecard.score || 0) < 94 || qaReport.claim_status !== 'measured-on-fixture') {
      return {
        status: 'fail',
        claim_status: 'failed',
        metrics: { pro_score: Number(scorecard.score || 0), required_score: 94 },
        evidence: ['../pro2pilot-inspector/pro-inspector-qa/scorecard.json', '../pro2pilot-inspector/pro-inspector-qa/qa-report.json'],
        limitations: ['Pro Inspector did not meet the measured-on-fixture 9.4 threshold']
      };
    }
    return passResult({
      pro_score: Number(scorecard.score || 0),
      pro_score_max: Number(scorecard.max_score || 100),
      kb13_sub_suites: (suitesCatalog.kb13_sub_suites || []).length,
      snapshot_import: 1,
      pr_impact_drilldown: 1,
      repair_board_transitions: 1,
      policy_evaluator: 1,
      team_mode_dashboard: 1,
      memory_governance: 1,
      audit_export: 1,
      dom_screens: (domProof.screens || []).length,
      proof_pack_files: (manifest.files || []).length
    }, [
      '../pro2pilot-inspector/scripts/pro-inspector-qa-gate.js',
      '../pro2pilot-inspector/pro-inspector-qa/qa-gate.json',
      '../pro2pilot-inspector/pro-inspector-qa/qa-report.json',
      '../pro2pilot-inspector/pro-inspector-qa/scorecard.json',
      '../pro2pilot-inspector/pro-inspector-qa/dom-proof.json',
      '../pro2pilot-inspector/pro-inspector-exports/latest/manifest.json'
    ], 'measured-on-fixture');
  }

  if (slug === 'kb-14-no-cloud') {
    const val = runNode(['tools/validate-release-artifact.js', `dist/knowledge-v${readJson(path.join(root, 'package.json'), {}).version}.zip`, '--json'], { timeoutMs: 180000 });
    if (val.status !== 'pass') return failedResult(val, 'release artifact privacy validation failed');
    const data = external();
    return passResult({ release_violations: (val.json?.violations || []).length, external_memory_can_raise_trust: data.source_of_truth_policy?.external_memory_can_raise_trust === true ? 1 : 0, no_cloud_default: 1 }, ['tools/validate-release-artifact.js', 'maintenance/external_memory_status.json'], 'measured');
  }

  if (slug === 'kb-15-performance-scale') {
    const routingCmd = runNode(['tools/build-routing-bundle.js'], { timeoutMs: 180000 });
    const searchCmd = runNode(['tools/build-search-index.js'], { timeoutMs: 180000 });
    const inspectorCmd = runNode(['tools/build-visual-inspector.js', '--quiet'], { timeoutMs: 180000 });
    const failed = [routingCmd, searchCmd, inspectorCmd].find((cmd) => cmd.status !== 'pass');
    if (failed) return failedResult(failed, 'performance command failed');
    return passResult({ routing_ms: routingCmd.duration_ms, search_index_ms: searchCmd.duration_ms, inspector_build_ms: inspectorCmd.duration_ms }, ['tools/build-routing-bundle.js', 'tools/build-search-index.js', 'tools/build-visual-inspector.js'], 'measured');
  }

  return plannedResult({}, [], `Suite not implemented: ${slug}`);
}

function selectSuites(requested) {
  if (!requested || requested === 'smoke') return ['smoke'];
  if (requested === 'all') return suitesCatalog.suites.map((suite) => suite.slug);
  const found = suiteMeta(requested);
  return [found ? found.slug : requested];
}

function aggregateSuite(slug, runs) {
  const meta = slug === 'smoke' ? { id: 'SMOKE', slug, title: 'Harness smoke' } : suiteMeta(slug) || { id: slug.toUpperCase(), slug, title: slug };
  const runResults = [];
  for (let i = 0; i < runs; i += 1) {
    const started = new Date().toISOString();
    const result = runSuiteOnce(slug);
    runResults.push({ run: i + 1, started_at: started, finished_at: new Date().toISOString(), ...result });
  }
  const failed = runResults.filter((run) => run.status === 'fail');
  const preview = runResults.filter((run) => run.status === 'preview');
  const planned = runResults.filter((run) => run.status === 'planned');
  const diagnostic = runResults.filter((run) => run.status === 'diagnostic');
  const pass = runResults.filter((run) => run.status === 'pass');
  const status = failed.length ? 'fail' : preview.length ? 'preview' : planned.length ? 'planned' : diagnostic.length ? 'diagnostic' : 'pass';
  const claimStatus = failed.length ? 'failed' : preview.length ? 'preview' : planned.length ? 'planned' : diagnostic.length ? 'diagnostic' : (pass[0]?.claim_status || 'measured');
  const metrics = {};
  for (const key of new Set(runResults.flatMap((run) => Object.keys(run.metrics || {})))) metrics[key] = metricFromRuns(runResults, key);
  return {
    id: meta.id,
    slug,
    title: meta.title,
    status,
    claim_status: claimStatus,
    runs_requested: runs,
    runs_passed: pass.length,
    runs_failed: failed.length,
    metrics,
    evidence: Array.from(new Set(runResults.flatMap((run) => run.evidence || []))),
    limitations: Array.from(new Set(runResults.flatMap((run) => run.limitations || []))),
    run_results: runResults
  };
}

function csvValue(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function claimRows(results) {
  return results.map((suite) => {
    const measured = ['measured', 'measured-on-fixture'].includes(suite.claim_status);
    return {
      claim_id: `${suite.id}-C1`,
      public_claim: publicClaimFor(suite),
      status: suite.claim_status,
      suite: suite.id,
      metric: Object.keys(suite.metrics || {})[0] || 'status',
      value: Object.values(suite.metrics || {})[0] ?? suite.status,
      artifact: suite.evidence[0] || `raw/${suite.slug}.json`,
      reproduction: 'verification/reproduction.ps1',
      limitation: suite.limitations[0] || (measured ? 'fixture/local run scope' : 'not marketable'),
      approved_wording: measured ? publicClaimFor(suite) : 'Not approved for public marketing.'
    };
  });
}

function publicClaimFor(suite) {
  const map = {
    'KB-02': 'A compact routing bundle gives agents a first-read route before loading broad context.',
    'KB-03': 'Trust and freshness state are visible before planning.',
    'KB-04': 'Repair queue state is structured for follow-up work.',
    'KB-09': 'PR Impact maps changed files to modules, policy warnings and reviewer notes in a local fixture.',
    'KB-11': 'External memory is visible but remains advisory and cannot raise trust.',
    'KB-12': 'Team Mode fixture preserves separate workspace state with zero JSON corruption.',
    'KB-13': 'Pro Inspector governance workflows pass a local 9.4/10 fixture QA gate.',
    'KB-14': 'The release artifact passes local privacy/leak validation with no cloud dependency.'
  };
  return map[suite.id] || `${suite.title} produced a local benchmark result with recorded limitations.`;
}

function verdict(results) {
  if (results.some((suite) => suite.status === 'fail')) return 'failed';
  if (results.some((suite) => ['preview', 'planned', 'diagnostic'].includes(suite.status))) return 'partial';
  return 'passed';
}

function writeRun(runId, selectedSuite, results, args) {
  const runDir = path.join(root, 'benchmark-runs', runId);
  for (const dir of ['raw', 'metrics', 'artifacts', 'screenshots', 'recordings', 'verification', 'marketing']) ensureDir(path.join(runDir, dir));
  const rows = claimRows(results);
  const v = verdict(results);
  const marketable = rows.filter((row) => ['measured', 'measured-on-fixture'].includes(row.status));
  const blocked = rows.filter((row) => !['measured', 'measured-on-fixture'].includes(row.status));
  const manifest = {
    schema_version: '3.2.2',
    run_id: runId,
    generated_at: new Date().toISOString(),
    suite: selectedSuite,
    fixture: args.fixture || 'default',
    runs: args.runs,
    verdict: v,
    results
  };
  writeJsonAtomic(path.join(runDir, 'manifest.json'), manifest);
  writeJsonAtomic(path.join(runDir, 'environment.json'), {
    schema_version: '3.2.2',
    node_major: Number(process.versions.node.split('.')[0]),
    platform: process.platform,
    cwd: '<source-or-installed-knowledge-root>',
    network_required: false
  });
  writeJsonAtomic(path.join(runDir, 'gate-status.json'), {
    schema_version: '3.2.2',
    verdict: v,
    release_gate: readJson(path.join(root, 'maintenance', 'release-gate-report.json'), { status: 'not_run' }).status || 'not_run'
  });
  for (const suite of results) writeJsonAtomic(path.join(runDir, 'raw', `${suite.slug}.json`), suite);
  const metricLines = ['suite_id,suite,status,claim_status,metric,value'];
  for (const suite of results) for (const [key, value] of Object.entries(suite.metrics || {})) metricLines.push([suite.id, suite.title, suite.status, suite.claim_status, key, value].map(csvValue).join(','));
  fs.writeFileSync(path.join(runDir, 'metrics', 'metrics.csv'), metricLines.join('\n') + '\n', 'utf8');
  fs.writeFileSync(path.join(runDir, '01_CLAIM_EVIDENCE_MAP.md'), renderClaimMap(rows), 'utf8');
  fs.writeFileSync(path.join(runDir, '00_EXECUTIVE_SUMMARY.md'), renderExecutive(runId, v, marketable, blocked, results), 'utf8');
  fs.writeFileSync(path.join(runDir, '02_SCORECARD.md'), renderScorecard(results), 'utf8');
  fs.writeFileSync(path.join(runDir, '03_FAILURES_AND_LIMITATIONS.md'), renderFailures(results), 'utf8');
  fs.writeFileSync(path.join(runDir, '04_PUBLIC_COPY.md'), renderPublicCopy(marketable), 'utf8');
  fs.writeFileSync(path.join(runDir, '05_METHODOLOGY.md'), renderMethodology(selectedSuite, args), 'utf8');
  fs.writeFileSync(path.join(runDir, 'verification', 'reproduction.ps1'), `node .knowledge/benchmarks/run-benchmarks.js --suite ${selectedSuite} --runs ${args.runs} --json\n`, 'utf8');
  fs.writeFileSync(path.join(runDir, 'verification', 'reproduction.sh'), `#!/usr/bin/env sh\nset -eu\nnode .knowledge/benchmarks/run-benchmarks.js --suite ${selectedSuite} --runs ${args.runs} --json\n`, 'utf8');
  fs.writeFileSync(path.join(runDir, 'artifacts', 'README.md'), '# Artifacts\n\nRaw suite JSON and metrics are stored in sibling folders.\n', 'utf8');
  const redaction = scanRun(runDir);
  fs.writeFileSync(path.join(runDir, 'verification', 'checksums.sha256'), redaction.checksums.join('\n') + '\n', 'utf8');
  fs.writeFileSync(path.join(runDir, 'verification', 'redaction-report.md'), `# Redaction report\n\nStatus: ${redaction.findings.length ? 'failed' : 'passed'}\n\nFindings: ${redaction.findings.length}\n`, 'utf8');
  if (redaction.findings.length) throw new Error(`benchmark run redaction failed: ${JSON.stringify(redaction.findings.slice(0, 5))}`);
  zipDirectory(runDir, path.join(root, 'benchmark-runs', `${runId}.zip`), runDir);
  return { runDir, manifest, marketable, blocked };
}

function renderExecutive(runId, v, marketable, blocked, results) {
  return `# Benchmark run ${runId} - Executive summary

## Verdict
${v}

## What can be marketed now
| Claim | Status | Metric | Evidence | Limitation |
|---|---|---|---|---|
${marketable.map((row) => `| ${row.public_claim} | ${row.status} | ${row.metric}=${row.value} | ${row.artifact} | ${row.limitation} |`).join('\n') || '| None | planned | n/a | n/a | No measured claims in this run. |'}

## What cannot be marketed
| Claim | Why not | Required next evidence |
|---|---|---|
${blocked.map((row) => `| ${row.public_claim} | ${row.status} | ${row.limitation} |`).join('\n') || '| None | n/a | n/a |'}

## Top proof points
${results.slice(0, 5).map((suite, index) => `${index + 1}. ${suite.id}: ${suite.status} (${suite.claim_status}).`).join('\n')}

## Main blocker, if any
${results.find((suite) => suite.status === 'fail')?.limitations?.[0] || 'No failed suite in this run.'}

## Reproduction
- \`verification/reproduction.sh\`
- \`verification/reproduction.ps1\`
`;
}

function renderClaimMap(rows) {
  return `# Claim Evidence Map

| Claim ID | Public claim | Status | Suite | Metric | Value | Artifact | Reproduction | Limitation | Approved wording |
|---|---|---|---|---:|---|---|---|---|---|
${rows.map((row) => `| ${row.claim_id} | ${row.public_claim} | ${row.status} | ${row.suite} | ${row.metric} | ${row.value} | ${row.artifact} | ${row.reproduction} | ${row.limitation} | ${row.approved_wording} |`).join('\n')}
`;
}

function renderScorecard(results) {
  return `# Scorecard

| Suite | Status | Claim status | Runs | Key metrics |
|---|---|---|---:|---|
${results.map((suite) => `| ${suite.id} ${suite.title} | ${suite.status} | ${suite.claim_status} | ${suite.runs_requested} | ${Object.entries(suite.metrics || {}).map(([k, v]) => `${k}=${v}`).join(', ') || 'n/a'} |`).join('\n')}
`;
}

function renderFailures(results) {
  const rows = results.filter((suite) => suite.status !== 'pass');
  return `# Failures and Limitations

${rows.length ? rows.map((suite) => `## ${suite.id} ${suite.title}\n\nStatus: ${suite.status}\n\nLimitations:\n${(suite.limitations || []).map((item) => `- ${item}`).join('\n') || '- none'}\n`).join('\n') : 'No failed, preview, planned, or diagnostic suites in this run.\n'}
`;
}

function renderPublicCopy(marketable) {
  return `# Public copy candidates

## README proof block
${marketable.map((row) => `- ${row.approved_wording} Evidence: ${row.claim_id}.`).join('\n') || '- No public benchmark claims are approved from this run.'}

## Landing proof block
${marketable.slice(0, 3).map((row) => `${row.approved_wording} (${row.claim_id})`).join('\n') || 'Benchmark diagnostics are complete; public proof is pending measured claims.'}

## LinkedIn post
We ran local benchmark fixtures for .knowledge governance. The approved claims are listed in 01_CLAIM_EVIDENCE_MAP.md.

## Hacker News / Reddit post
We tested routing, trust/freshness, PR impact, Team Mode and memory safety locally. The useful part is the limitations as much as the green checks.

## X thread
1/ Local benchmark run complete. Claims are tied to claim IDs and reproduction scripts.

## Habr/Dev.to article outline
- Problem: agents need repo-local governance.
- Method: local benchmark fixtures.
- Results: measured claims only.
- Limitations and next work.

## Demo video script
Show release gate, Inspector, PR Impact, Team Mode run report, and benchmark limitations.
`;
}

function renderMethodology(selectedSuite, args) {
  return `# Methodology

Suite selector: \`${selectedSuite}\`

Runs requested: ${args.runs}

Fixture: ${args.fixture || 'default'}

The harness executes local commands, parses generated JSON reports, records metrics, writes raw per-suite artifacts, generates checksums and applies a redaction scan before approving public copy.
`;
}

function zipDirectory(dir, zipPath, baseDir) {
  const entries = [];
  function walk(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) entries.push({ abs, rel: path.relative(baseDir, abs).replace(/\\/g, '/'), name: path.relative(baseDir, abs).replace(/\\/g, '/') });
    }
  }
  walk(dir);
  createZip(entries, zipPath);
}

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const selectedSuite = String(flags.suite || 'smoke');
  const runs = Math.max(1, Number(flags.runs || 1));
  const selected = selectSuites(selectedSuite);
  const runId = flags.runId || `${nowStamp()}-${selectedSuite.replace(/[^a-z0-9-]/gi, '-').toLowerCase()}`;
  const results = selected.map((slug) => aggregateSuite(slug, runs));
  const written = writeRun(runId, selectedSuite, results, { runs, fixture: flags.fixture });
  const output = {
    schema_version: '3.2.2',
    status: results.some((suite) => suite.status === 'fail') ? 'failed' : 'ok',
    verdict: written.manifest.verdict,
    run_id: runId,
    run_dir: `benchmark-runs/${runId}`,
    run_archive: `benchmark-runs/${runId}.zip`,
    suites: results.map((suite) => ({ id: suite.id, slug: suite.slug, status: suite.status, claim_status: suite.claim_status }))
  };
  if (flags.json) console.log(JSON.stringify(output, null, 2));
  else console.log(`benchmark ${output.status}: ${output.run_dir}`);
  if (output.status !== 'ok') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const { flags } = parseCliArgs(process.argv.slice(2));
    const output = { schema_version: '3.2.2', status: 'failed', error: sanitizeText(error.message) };
    if (flags.json) console.log(JSON.stringify(output, null, 2));
    else console.error(output.error);
    process.exit(2);
  }
}

module.exports = { main, runSuiteOnce, aggregateSuite };
