#!/usr/bin/env node
'use strict';

// Source-only black-box verifier. It intentionally does not import the routing
// estimator, Field Report collector, renderer, or state implementation.
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

function sha(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function parseArgs(argv) {
  const flags = {};
  for (const arg of argv) {
    if (!arg.startsWith('--')) throw new Error(`Unexpected argument: ${arg}`);
    const index = arg.indexOf('=');
    const key = (index === -1 ? arg.slice(2) : arg.slice(2, index))
      .replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    flags[key] = index === -1 ? true : arg.slice(index + 1);
  }
  if (!flags.candidate) throw new Error('--candidate=<zip> is required');
  return flags;
}

function run(file, args, options = {}) {
  const result = childProcess.spawnSync(file, args, {
    cwd: options.cwd,
    env: { ...process.env, KNOWLEDGE_FLOW_NO_OPEN: '1', ...options.env },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 180000,
    maxBuffer: 32 * 1024 * 1024
  });
  return {
    command: [file, ...args],
    exit_code: result.status === null ? 124 : result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    signal: result.signal || null,
    error: result.error ? result.error.message : null
  };
}

function runNode(repo, relative, args, options = {}) {
  return run(process.execPath, [path.join(repo, relative), ...args], { ...options, cwd: repo });
}

function jsonOutput(result) {
  const text = result.stdout.trim();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function fileJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

function inventoryTree(root) {
  const rows = [];
  const walk = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) rows.push({
        path: path.relative(root, full).replace(/\\/g, '/'),
        bytes: fs.statSync(full).size,
        sha256: sha(fs.readFileSync(full))
      });
    }
  };
  walk(root);
  return sha(Buffer.from(JSON.stringify(rows)));
}

function sleep(milliseconds) {
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, milliseconds);
}

function extractCandidate(candidate, destination) {
  fs.mkdirSync(destination, { recursive: true });
  const code = [
    'import pathlib,sys,zipfile',
    'src=pathlib.Path(sys.argv[1]).resolve()',
    'dst=pathlib.Path(sys.argv[2]).resolve()',
    'z=zipfile.ZipFile(src)',
    'names=z.namelist()',
    "bad=[n for n in names if pathlib.PurePosixPath(n).is_absolute() or '..' in pathlib.PurePosixPath(n).parts]",
    "assert not bad, 'unsafe zip entries: '+repr(bad)",
    'z.testzip() is None or (_ for _ in ()).throw(AssertionError("bad zip member"))',
    'z.extractall(dst)',
    'print(len(names))'
  ].join(';');
  let result = run('python', ['-c', code, candidate, destination], { cwd: destination });
  if (result.exit_code !== 0) result = run('python3', ['-c', code, candidate, destination], { cwd: destination });
  if (result.exit_code !== 0) throw new Error(`Python zipfile extraction failed: ${result.stderr || result.stdout}`);
  return Number(result.stdout.trim());
}

function initialiseRepository(repo) {
  fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
  fs.writeFileSync(path.join(repo, 'src', 'app.js'), "'use strict';\nmodule.exports = 1;\n", 'utf8');
  fs.writeFileSync(path.join(repo, 'README.md'), '# Routing verifier fixture\n', 'utf8');
  for (const args of [
    ['init'],
    ['config', 'user.email', 'routing-audit@example.invalid'],
    ['config', 'user.name', 'Routing Audit'],
    ['add', '.'],
    ['commit', '-m', 'fixture']
  ]) {
    const result = run('git', args, { cwd: repo });
    if (result.exit_code !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  }
  const imported = runNode(repo, '.knowledge/tools/flow.js', ['import', '--json'], { timeout: 360000 });
  if (imported.exit_code !== 0) throw new Error(`public import failed: ${imported.stderr || imported.stdout}`);
  return imported;
}

function makeTrusted(repo) {
  const file = path.join(repo, '.knowledge', 'maintenance', 'trust_report.json');
  const report = fileJson(file);
  report.modules_low_confidence = 0;
  report.modules.trusted = ['src'];
  report.modules.low_confidence = [];
  report.module_statuses = (report.module_statuses || []).map((row) => row.module_id === 'src'
    ? { ...row, confidence: 'high', trust_status: 'trusted', reasons: { changed_or_missing_important_files: [], open_contradictions: [], uncovered_important_files: [] } }
    : row);
  writeJson(file, report);
  const qualityFile = path.join(repo, '.knowledge', 'maintenance', 'quality_report.json');
  const quality = fileJson(qualityFile);
  quality.contradictions = (quality.contradictions || []).filter((item) => item.module_id !== 'src');
  quality.issues = (quality.issues || []).filter((item) => item.module_id !== 'src');
  writeJson(qualityFile, quality);
}

function answers() {
  return {
    answers: {
      'project-context': 'An anonymized JavaScript repository used for a routing contract check.',
      'keep-using': 'yes',
      'quick-summary': 'The routing evidence selected the intended files.',
      'installation-method': 'Physical release asset',
      'workflow-fit': 'few_extra_steps',
      'agent-intervention': 'once_or_twice',
      'workflow-notes': 'The test followed the public CLI workflow.',
      'main-scenario': 'A localized source change with objective tests.',
      'accuracy-change': 'slightly_improved',
      'accuracy-example': 'The expected source file was selected.',
      'accuracy-basis': 'objective_test_result',
      'accuracy-sample-count': 3,
      'speed-scope': 'first_useful_response',
      'response-speed-change': 'slightly_faster',
      'response-speed-percent': 1,
      'response-speed-basis': 'estimated_from_comparable_tasks',
      'response-speed-sample-count': 3,
      'response-speed-notes': 'No speed claim is made.',
      'useful-parts': 'Routing provenance and limitation handling.',
      'observed-results': 'The public CLI produced auditable artifacts.',
      'what-did-not-work': 'No product limitation is inferred from this fixture.',
      'previous-workflow-comparison': 'No comparative product claim is made.',
      'final-assessment': 'Useful as a contract exercise.',
      'github-publication-permission': 'github_publication_allowed',
      'publication-permission': 'link_and_quote_with_attribution'
    }
  };
}

function createRoute(repo, extra = []) {
  const result = runNode(repo, '.knowledge/tools/task-routing.js', [
    'create', '--task=routing verifier task', '--scope-module=src', ...extra, '--json'
  ]);
  const value = jsonOutput(result);
  if (result.exit_code !== 0 || !value?.task_scope_hash) {
    throw new Error(`public task-routing create failed: ${result.stderr || result.stdout}`);
  }
  return { result, value };
}

function startReport(repo, taskId, suffix) {
  const answerFile = path.join(repo, `.routing-r6-answers-${suffix}.json`);
  writeJson(answerFile, answers());
  const started = runNode(repo, '.knowledge/tools/field-report.js', [
    'start', '--new', `--routing-task-id=${taskId}`, '--language=en', '--public-language=en', '--anonymize', '--json'
  ]);
  const startValue = jsonOutput(started);
  if (started.exit_code !== 0 || !startValue?.report_id) {
    throw new Error(`public Field Report start failed: ${started.stderr || started.stdout}`);
  }
  const ingested = runNode(repo, '.knowledge/tools/field-report.js', [
    'ingest', `--report-id=${startValue.report_id}`, `--answers=${answerFile}`, '--json'
  ]);
  if (ingested.exit_code !== 0) throw new Error(`public Field Report ingest failed: ${ingested.stderr || ingested.stdout}`);
  return startValue.report_id;
}

function reportWorkflow(repo, taskId, suffix) {
  const reportId = startReport(repo, taskId, suffix);
  const render = runNode(repo, '.knowledge/tools/field-report.js', ['render', `--report-id=${reportId}`, '--json']);
  if (render.exit_code !== 0) return { reportId, render, approve: null, preview: null };
  sleep(2100);
  const approve = runNode(repo, '.knowledge/tools/field-report.js', [
    'approve', `--report-id=${reportId}`, '--yes', '--tester-actor=routing-auditor', '--json'
  ]);
  if (approve.exit_code !== 0) return { reportId, render, approve, preview: null };
  sleep(2100);
  const preview = runNode(repo, '.knowledge/tools/field-report.js', [
    'publish', `--report-id=${reportId}`, '--dry-run', '--yes', '--tester-actor=routing-auditor', '--json'
  ]);
  return { reportId, render, approve, preview };
}

function main() {
  const flags = parseArgs(process.argv.slice(2));
  const candidate = path.resolve(flags.candidate);
  if (!fs.existsSync(candidate)) throw new Error(`Candidate not found: ${candidate}`);
  const workRoot = path.resolve(flags.workRoot || path.join(process.cwd(), '.routing-r6-verifier-work'));
  fs.mkdirSync(workRoot, { recursive: true });
  const runRoot = path.join(workRoot, `run-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  const repo = path.join(runRoot, 'repo');
  const results = [];
  const evidence = {};
  const check = (id, pass, details = {}) => results.push({ id, status: pass ? 'passed' : 'failed', ...details });

  const entries = extractCandidate(candidate, repo);
  evidence.candidate = { path: candidate, sha256: sha(fs.readFileSync(candidate)), entries };
  evidence.import = initialiseRepository(repo);
  makeTrusted(repo);

  const initial = createRoute(repo);
  const taskId = initial.value.task_scope_hash;
  const scope = initial.value.scope;
  const project = fileJson(path.join(repo, '.knowledge', 'project_index.json'));
  const huge = path.join(repo, 'arbitrary-unrelated-baseline.bin');
  fs.writeFileSync(huge, Buffer.alloc(1024 * 1024, 0x58));
  const customBaselineFile = path.join(repo, '.knowledge', 'maintenance', 'routing_bundle.json');
  const adversarialBaseline = (targetScope) => ({
    schema_version: 'knowledge-routing-baseline.v2',
    workspace_id: String(project.workspace_id || project.workspace?.id || sha(Buffer.from(path.resolve(repo)))),
    repository_id: targetScope.repository_id,
    task_scope_hash: targetScope.task_scope_hash,
    snapshot_marker: 'verifier-custom',
    method: 'task_first_read_baseline.v2',
    measurement_payload: {
      files: [{ path: 'arbitrary-unrelated-baseline.bin', sha256: sha(fs.readFileSync(huge)) }],
      policy_inputs: []
    },
    provenance: { generated_at: 'verifier', generated_by: 'independent-verifier' }
  });
  writeJson(customBaselineFile, adversarialBaseline(scope));
  const refreshed = runNode(repo, '.knowledge/tools/task-routing.js', ['refresh', `--task-id=${taskId}`, '--json']);
  const refreshedValue = jsonOutput(refreshed);
  evidence.custom_baseline_refresh = refreshed;
  const diagnostic = runNode(repo, '.knowledge/tools/task-routing.js', [
    'baseline', `--task-id=${taskId}`, `--custom-baseline=${customBaselineFile}`, '--json'
  ]);
  const diagnosticValue = jsonOutput(diagnostic);
  evidence.custom_baseline_diagnostic = diagnostic;
  const customRejected = diagnostic.exit_code === 0 && diagnosticValue?.claim_eligible === false &&
    diagnosticValue?.claim_ineligible_reason === 'custom_baseline_not_claim_eligible';
  check('arbitrary_baseline_is_never_claim_eligible', customRejected, {
    diagnostic_exit: diagnostic.exit_code,
    observed_claim_eligible: diagnosticValue?.claim_eligible ?? null,
    observed_reason: diagnosticValue?.claim_ineligible_reason ?? null
  });

  const currentFile = path.join(repo, '.knowledge', 'routing', 'tasks', taskId, 'current.json');
  const current = fileJson(currentFile);
  const baselineFile = current.baseline_hash
    ? path.join(repo, '.knowledge', 'routing', 'tasks', taskId, 'baselines', current.baseline_hash, 'baseline.json')
    : null;
  const baseline = baselineFile && fs.existsSync(baselineFile) ? fileJson(baselineFile) : null;
  check('production_canonical_v2_baseline_writer', Boolean(
    baseline && baseline.schema_version === 'knowledge-routing-baseline.v2' &&
    baseline.generator === 'pro2pilot.task-routing.canonical-baseline' &&
    baseline.recipe === 'task-first-read.v1' && baseline.claim_eligible === true &&
    Array.isArray(baseline.roles) && baseline.roles.length > 0
  ), { baseline_path: baselineFile, baseline_schema: baseline?.schema_version || null });

  const comparisonFile = current.metrics_comparison_hash
    ? path.join(repo, '.knowledge', 'routing', 'tasks', taskId, 'comparisons', current.metrics_comparison_hash, 'metrics.json')
    : null;
  const snapshotMetrics = path.join(repo, '.knowledge', 'routing', 'tasks', taskId, 'snapshots', current.routing_snapshot_hash || current.snapshot_hash, 'metrics.json');
  check('comparison_is_physically_separate', Boolean(
    current.routing_snapshot_hash && current.baseline_hash && current.metrics_comparison_hash &&
    comparisonFile && fs.existsSync(comparisonFile) && !fs.existsSync(snapshotMetrics)
  ), { current, comparison_path: comparisonFile, snapshot_metrics_present: fs.existsSync(snapshotMetrics) });

  const oldRouteHash = current.routing_snapshot_hash;
  const oldBaselineHash = current.baseline_hash;
  const oldComparisonHash = current.metrics_comparison_hash;
  fs.appendFileSync(path.join(repo, '.knowledge', 'wiki', 'index.md'), '\nR6 comparison-only refresh marker.\n', 'utf8');
  const comparisonRefresh = runNode(repo, '.knowledge/tools/task-routing.js', ['refresh', `--task-id=${taskId}`, '--json']);
  const comparisonRefreshValue = jsonOutput(comparisonRefresh);
  const comparisonStatus = runNode(repo, '.knowledge/tools/task-routing.js', ['status', `--task-id=${taskId}`, '--json']);
  const comparisonStatusValue = jsonOutput(comparisonStatus);
  check('baseline_only_change_persists_new_comparison', Boolean(
    comparisonRefresh.exit_code === 0 && comparisonStatus.exit_code === 0 &&
    comparisonRefreshValue?.routing_snapshot_hash === oldRouteHash &&
    comparisonRefreshValue?.baseline_hash !== oldBaselineHash &&
    comparisonRefreshValue?.current_metrics_comparison_hash !== oldComparisonHash &&
    comparisonStatusValue?.metrics_comparison_hash === comparisonRefreshValue?.current_metrics_comparison_hash
  ), {
    old_route: oldRouteHash,
    new_route: comparisonRefreshValue?.routing_snapshot_hash || null,
    old_baseline: oldBaselineHash,
    new_baseline: comparisonRefreshValue?.baseline_hash || null,
    old_comparison: oldComparisonHash,
    new_comparison: comparisonRefreshValue?.current_metrics_comparison_hash || null,
    reconciled_comparison: comparisonStatusValue?.metrics_comparison_hash || null
  });

  const ineligible = createRoute(repo, ['--scope-source=inferred']);
  const ineligibleFlow = reportWorkflow(repo, ineligible.value.task_scope_hash, 'ineligible');
  const ineligiblePublic = path.join(repo, '.knowledge', 'reports', 'field-reports', ineligibleFlow.reportId, 'public.md');
  const ineligibleBody = fs.existsSync(ineligiblePublic) ? fs.readFileSync(ineligiblePublic, 'utf8') : '';
  check('ineligible_route_keeps_field_report_workflow', Boolean(
    ineligibleFlow.render.exit_code === 0 && ineligibleFlow.approve?.exit_code === 0 &&
    ineligibleFlow.preview?.exit_code === 0 &&
    /requires_explicit_frozen_scope|not claim-eligible|not comparable/i.test(ineligibleBody) &&
    !/estimated local first-read context (?:reduction|overhead):[^\n]*\([+-]?[0-9.]+%\)/i.test(ineligibleBody)
  ), {
    render_exit: ineligibleFlow.render.exit_code,
    approve_exit: ineligibleFlow.approve?.exit_code ?? null,
    preview_exit: ineligibleFlow.preview?.exit_code ?? null,
    render_error: ineligibleFlow.render.stderr.trim()
  });

  // Use a fresh explicit route so the delayed approval workflow is independent
  // of the deliberately custom diagnostic file above.
  const eligible = createRoute(repo, ['--task-class=delayed']);
  writeJson(customBaselineFile, adversarialBaseline(eligible.value.scope));
  const eligibleRefresh = runNode(repo, '.knowledge/tools/task-routing.js', [
    'refresh', `--task-id=${eligible.value.task_scope_hash}`, '--json'
  ]);
  evidence.eligible_refresh_after_adversarial_baseline = eligibleRefresh;
  const delayedFlow = reportWorkflow(repo, eligible.value.task_scope_hash, 'delayed');
  check('volatile_collection_metadata_does_not_invalidate_approval', Boolean(
    delayedFlow.render.exit_code === 0 && delayedFlow.approve?.exit_code === 0 && delayedFlow.preview?.exit_code === 0
  ), {
    render_exit: delayedFlow.render.exit_code,
    approve_exit: delayedFlow.approve?.exit_code ?? null,
    preview_exit: delayedFlow.preview?.exit_code ?? null,
    approve_error: delayedFlow.approve?.stderr.trim() || null,
    preview_error: delayedFlow.preview?.stderr.trim() || null
  });

  const driftRoute = createRoute(repo, ['--task-class=drift-recovery']);
  const driftReportId = startReport(repo, driftRoute.value.task_scope_hash, 'drift');
  const driftRender = runNode(repo, '.knowledge/tools/field-report.js', ['render', `--report-id=${driftReportId}`, '--json']);
  const driftApprove = runNode(repo, '.knowledge/tools/field-report.js', [
    'approve', `--report-id=${driftReportId}`, '--yes', '--tester-actor=routing-auditor', '--json'
  ]);
  fs.appendFileSync(path.join(repo, 'src', 'app.js'), '\nmodule.exports.changed = true;\n', 'utf8');
  const driftPreview = runNode(repo, '.knowledge/tools/field-report.js', [
    'publish', `--report-id=${driftReportId}`, '--dry-run', '--yes', '--tester-actor=routing-auditor', '--json'
  ]);
  const driftManifestPath = path.join(repo, '.knowledge', 'reports', 'field-reports', driftReportId, 'manifest.json');
  const invalidatedManifest = fileJson(driftManifestPath);
  check('relevant_source_drift_invalidates_approval', Boolean(
    driftRender.exit_code === 0 && driftApprove.exit_code === 0 && driftPreview.exit_code !== 0 &&
    invalidatedManifest.approval?.approved_by_tester === false &&
    /live_relevant_input_drift|routing.*stale/i.test(driftPreview.stderr)
  ), { preview_exit: driftPreview.exit_code, preview_error: driftPreview.stderr.trim() });

  const driftRefresh = runNode(repo, '.knowledge/tools/task-routing.js', [
    'refresh', `--task-id=${driftRoute.value.task_scope_hash}`, '--json'
  ]);
  const recoveryRender = runNode(repo, '.knowledge/tools/field-report.js', ['render', `--report-id=${driftReportId}`, '--json']);
  const recoveryApprove = runNode(repo, '.knowledge/tools/field-report.js', [
    'approve', `--report-id=${driftReportId}`, '--yes', '--tester-actor=routing-auditor', '--json'
  ]);
  fs.mkdirSync(path.join(repo, 'unrelated'), { recursive: true });
  fs.writeFileSync(path.join(repo, 'unrelated', 'note.txt'), 'unrelated drift\n', 'utf8');
  const recoveryPreview = runNode(repo, '.knowledge/tools/field-report.js', [
    'publish', `--report-id=${driftReportId}`, '--dry-run', '--yes', '--tester-actor=routing-auditor', '--json'
  ]);
  check('reroute_render_approve_restores_and_unrelated_drift_survives', Boolean(
    driftRefresh.exit_code === 0 && recoveryRender.exit_code === 0 && recoveryApprove.exit_code === 0 && recoveryPreview.exit_code === 0
  ), {
    refresh_exit: driftRefresh.exit_code,
    render_exit: recoveryRender.exit_code,
    approve_exit: recoveryApprove.exit_code,
    preview_exit: recoveryPreview.exit_code,
    preview_error: recoveryPreview.stderr.trim()
  });

  const staleRoute = createRoute(repo, ['--task-class=stale-report']);
  const invalidatedRoute = runNode(repo, '.knowledge/tools/task-routing.js', [
    'invalidate', `--task-id=${staleRoute.value.task_scope_hash}`, '--reason=verifier-stale-route', '--json'
  ]);
  const staleFlow = reportWorkflow(repo, staleRoute.value.task_scope_hash, 'stale');
  check('stale_route_keeps_field_report_workflow', Boolean(
    invalidatedRoute.exit_code === 0 && staleFlow.render.exit_code === 0 &&
    staleFlow.approve?.exit_code === 0 && staleFlow.preview?.exit_code === 0
  ), {
    invalidate_exit: invalidatedRoute.exit_code,
    render_exit: staleFlow.render.exit_code,
    approve_exit: staleFlow.approve?.exit_code ?? null,
    preview_exit: staleFlow.preview?.exit_code ?? null
  });

  const beforeHelp = inventoryTree(path.join(repo, '.knowledge'));
  const help = runNode(repo, '.knowledge/tools/field-report.js', ['--help']);
  const afterHelp = inventoryTree(path.join(repo, '.knowledge'));
  const unknown = runNode(repo, '.knowledge/tools/field-report.js', ['--definitely-unknown-r6-flag']);
  const afterUnknown = inventoryTree(path.join(repo, '.knowledge'));
  check('field_report_help_and_unknown_flag_have_no_side_effects', Boolean(
    help.exit_code === 0 && unknown.exit_code === 2 && beforeHelp === afterHelp && afterHelp === afterUnknown
  ), { help_exit: help.exit_code, unknown_exit: unknown.exit_code, state_unchanged: beforeHelp === afterUnknown });

  const release = runNode(repo, '.knowledge/tools/flow.js', ['release', '--json'], { timeout: 360000 });
  const tasksRoot = path.join(repo, '.knowledge', 'routing', 'tasks');
  const taskPointers = fs.existsSync(tasksRoot)
    ? fs.readdirSync(tasksRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name))
      .map((entry) => fileJson(path.join(tasksRoot, entry.name, 'current.json')))
    : [];
  const finalized = taskPointers.every((pointer) => {
    const taskRoot = path.join(tasksRoot, pointer.task_scope_hash);
    return fs.existsSync(path.join(taskRoot, 'snapshots', pointer.routing_snapshot_hash, 'complete.json')) &&
      fs.existsSync(path.join(taskRoot, 'baselines', pointer.baseline_hash, 'baseline.json')) &&
      fs.existsSync(path.join(taskRoot, 'comparisons', pointer.metrics_comparison_hash, 'metrics.json'));
  });
  check('release_finalizes_canonical_baseline_and_comparison_for_all_tasks', Boolean(
    release.exit_code === 0 && taskPointers.length >= 1 && finalized
  ), { release_exit: release.exit_code, tasks_total: taskPointers.length, finalized });

  const summary = {
    schema_version: 'knowledge-routing-rc4-r6-independent-verifier.v1',
    candidate: evidence.candidate,
    work_root: runRoot,
    checks_total: results.length,
    passed: results.filter((item) => item.status === 'passed').length,
    failed: results.filter((item) => item.status === 'failed').length,
    status: results.every((item) => item.status === 'passed') ? 'passed' : 'failed',
    results,
    evidence
  };
  const output = flags.output ? path.resolve(flags.output) : path.join(runRoot, 'verification.json');
  writeJson(output, summary);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  process.exitCode = summary.status === 'passed' ? 0 : 1;
}

try { main(); } catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 2;
}
