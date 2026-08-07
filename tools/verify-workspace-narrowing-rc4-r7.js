#!/usr/bin/env node
'use strict';

// Source-only physical verifier. It does not import production routing,
// baseline, eligibility, formatter, or Field Report implementation modules.
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function sha(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function parseArgs(argv) {
  const flags = {};
  for (const argument of argv) {
    if (!argument.startsWith('--')) throw new Error(`Unexpected argument: ${argument}`);
    const equals = argument.indexOf('=');
    const name = (equals === -1 ? argument.slice(2) : argument.slice(2, equals))
      .replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    flags[name] = equals === -1 ? true : argument.slice(equals + 1);
  }
  if (!flags.candidate) throw new Error('--candidate=<zip> is required');
  return flags;
}

function run(file, args, options = {}) {
  const result = childProcess.spawnSync(file, args, {
    cwd: options.cwd,
    env: { ...process.env, CI: 'true', KNOWLEDGE_FLOW_NO_OPEN: '1', ...options.env },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 360000,
    maxBuffer: 64 * 1024 * 1024
  });
  return {
    command: [file, ...args],
    exit_code: result.status === null ? 124 : result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error ? result.error.message : null
  };
}

function runNode(repo, relative, args, options = {}) {
  return run(process.execPath, [path.join(repo, ...relative.split('/')), ...args], { ...options, cwd: repo });
}

function jsonOutput(result) {
  try { return JSON.parse(String(result.stdout || '').trim()); } catch { return null; }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function extractCandidate(candidate, destination) {
  fs.mkdirSync(destination, { recursive: true });
  const program = [
    'import pathlib,sys,zipfile',
    'src=pathlib.Path(sys.argv[1]).resolve()',
    'dst=pathlib.Path(sys.argv[2]).resolve()',
    'z=zipfile.ZipFile(src)',
    'names=z.namelist()',
    "bad=[n for n in names if pathlib.PurePosixPath(n).is_absolute() or '..' in pathlib.PurePosixPath(n).parts]",
    "assert not bad, 'unsafe zip entries: '+repr(bad)",
    'assert z.testzip() is None',
    'z.extractall(dst)',
    'print(len(names))'
  ].join(';');
  let result = run('python', ['-c', program, candidate, destination], { cwd: destination });
  if (result.exit_code !== 0) result = run('python3', ['-c', program, candidate, destination], { cwd: destination });
  if (result.exit_code !== 0) throw new Error(result.stderr || result.stdout || 'candidate extraction failed');
  return Number(result.stdout.trim());
}

function git(repo, args) {
  const result = run('git', args, { cwd: repo });
  if (result.exit_code !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  return result;
}

function commitIfChanged(repo, message) {
  git(repo, ['add', '.']);
  const status = run('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: repo });
  if (status.exit_code !== 0) throw new Error(`git status failed: ${status.stderr}`);
  if (status.stdout) git(repo, ['commit', '-m', message]);
}

function publicJson(repo, relative, args, options = {}) {
  const result = runNode(repo, relative, args, options);
  const value = jsonOutput(result);
  if (result.exit_code !== 0 || !value) {
    throw new Error(`${relative} ${args.join(' ')} failed: ${result.stderr || result.stdout}`);
  }
  return { result, value };
}

function initialise(repo) {
  fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
  fs.writeFileSync(path.join(repo, 'src', 'app.js'), "'use strict';\nmodule.exports = 1;\n", 'utf8');
  fs.writeFileSync(path.join(repo, 'README.md'), '# Workspace narrowing verifier\n', 'utf8');
  git(repo, ['init']);
  git(repo, ['config', 'user.email', 'routing-audit@example.invalid']);
  git(repo, ['config', 'user.name', 'Routing Audit']);
  git(repo, ['add', '.']);
  git(repo, ['commit', '-m', 'physical candidate fixture']);
  const install = runNode(repo, '.knowledge/tools/install-check.js', ['--json'], { timeout: 360000 });
  const imported = runNode(repo, '.knowledge/tools/flow.js', ['import', '--json'], { timeout: 600000 });
  makeModuleTrusted(repo, 'src');
  git(repo, ['add', '.']);
  git(repo, ['commit', '-m', 'imported trusted fixture']);
  return { install, imported };
}

function makeModuleTrusted(repo, moduleId) {
  const trustFile = path.join(repo, '.knowledge', 'maintenance', 'trust_report.json');
  const trust = readJson(trustFile);
  trust.modules_low_confidence = 0;
  trust.modules = trust.modules || {};
  trust.modules.trusted = [moduleId];
  trust.modules.low_confidence = [];
  trust.modules.suspect = [];
  trust.module_statuses = (trust.module_statuses || []).map((row) => row.module_id === moduleId ? {
    ...row,
    confidence: 'high',
    freshness_status: 'fresh',
    trust_status: 'trusted',
    reasons: { changed_or_missing_important_files: [], open_contradictions: [], uncovered_important_files: [] }
  } : row);
  writeJson(trustFile, trust);
  const qualityFile = path.join(repo, '.knowledge', 'maintenance', 'quality_report.json');
  const quality = readJson(qualityFile);
  quality.issues = [];
  quality.contradictions = [];
  writeJson(qualityFile, quality);
}

function createRoute(repo, suffix) {
  return publicJson(repo, '.knowledge/tools/task-routing.js', [
    'create', `--task=workspace narrowing ${suffix}`, `--task-class=${suffix}`,
    '--scope-module=src', '--scope-path=src/', '--json'
  ]).value;
}

function attemptCreateRoute(repo, suffix) {
  const result = runNode(repo, '.knowledge/tools/task-routing.js', [
    'create', `--task=workspace narrowing ${suffix}`, `--task-class=${suffix}`,
    '--scope-module=src', '--scope-path=src/', '--json'
  ]);
  const value = jsonOutput(result);
  if (result.exit_code !== 0 || !value?.task_scope_hash) {
    return { rejected: true, result, value };
  }
  return { rejected: false, result, value, artifacts: currentArtifacts(repo, value.task_scope_hash) };
}

function currentArtifacts(repo, taskId) {
  const root = path.join(repo, '.knowledge', 'routing', 'tasks', taskId);
  const current = readJson(path.join(root, 'current.json'));
  const snapshotHash = current.routing_snapshot_hash || current.snapshot_hash;
  const comparisonHash = current.metrics_comparison_hash;
  const snapshotRoot = path.join(root, 'snapshots', snapshotHash);
  return {
    current,
    bundle: readJson(path.join(snapshotRoot, 'bundle.json')),
    decision: readJson(path.join(snapshotRoot, 'decision.json')),
    provenance: readJson(path.join(snapshotRoot, 'provenance.json')),
    metrics: readJson(path.join(root, 'comparisons', comparisonHash, 'metrics.json'))
  };
}

function reportAnswers() {
  return { answers: {
    'project-context': 'An anonymized repository used for a routing contract verification.',
    'keep-using': 'yes',
    'quick-summary': 'The physical candidate was exercised through public CLIs.',
    'installation-method': 'Physical release asset',
    'workflow-fit': 'few_extra_steps',
    'agent-intervention': 'once_or_twice',
    'workflow-notes': 'The verifier inspected generated artifacts directly.',
    'main-scenario': 'A workspace-scoped routing contract test.',
    'accuracy-change': 'slightly_improved',
    'accuracy-example': 'No accuracy claim is made.',
    'accuracy-basis': 'objective_test_result',
    'accuracy-sample-count': 3,
    'speed-scope': 'first_useful_response',
    'response-speed-change': 'slightly_faster',
    'response-speed-percent': 1,
    'response-speed-basis': 'estimated_from_comparable_tasks',
    'response-speed-sample-count': 3,
    'response-speed-notes': 'No speed claim is made.',
    'useful-parts': 'Routing provenance and fail-closed publication.',
    'observed-results': 'The public workflow generated auditable artifacts.',
    'what-did-not-work': 'No product performance conclusion is drawn.',
    'previous-workflow-comparison': 'No version comparison was performed.',
    'final-assessment': 'Useful as a routing contract exercise.',
    'github-publication-permission': 'github_publication_allowed',
    'publication-permission': 'link_and_quote_with_attribution'
  } };
}

function stalePublicReport(repo, taskId) {
  publicJson(repo, '.knowledge/tools/task-routing.js', [
    'invalidate', `--task-id=${taskId}`, '--reason=verifier_stale_route', '--json'
  ]);
  const started = publicJson(repo, '.knowledge/tools/field-report.js', [
    'start', '--new', `--routing-task-id=${taskId}`, '--language=en', '--public-language=en', '--anonymize', '--json'
  ]).value;
  const answersFile = path.join(repo, '.routing-r7-verifier-answers.json');
  writeJson(answersFile, reportAnswers());
  publicJson(repo, '.knowledge/tools/field-report.js', [
    'ingest', `--report-id=${started.report_id}`, `--answers=${answersFile}`, '--json'
  ]);
  publicJson(repo, '.knowledge/tools/field-report.js', [
    'render', `--report-id=${started.report_id}`, '--json'
  ]);
  const body = fs.readFileSync(path.join(repo, '.knowledge', 'reports', 'field-reports', started.report_id, 'public.md'), 'utf8');
  return { report_id: started.report_id, body };
}

function renderPublicReport(repo, taskId, suffix) {
  const started = publicJson(repo, '.knowledge/tools/field-report.js', [
    'start', '--new', `--routing-task-id=${taskId}`, '--language=en', '--public-language=en', '--anonymize', '--json'
  ]).value;
  const answersFile = path.join(repo, `.routing-r7-verifier-answers-${suffix}.json`);
  writeJson(answersFile, reportAnswers());
  publicJson(repo, '.knowledge/tools/field-report.js', [
    'ingest', `--report-id=${started.report_id}`, `--answers=${answersFile}`, '--json'
  ]);
  const rendered = publicJson(repo, '.knowledge/tools/field-report.js', [
    'render', `--report-id=${started.report_id}`, '--json'
  ]);
  const body = fs.readFileSync(path.join(repo, '.knowledge', 'reports', 'field-reports', started.report_id, 'public.md'), 'utf8');
  return { report_id: started.report_id, body, rendered };
}

function diagnosticFormat(repo, runRoot, id, metrics, state) {
  const metricsFile = path.join(runRoot, 'formatter', `${id}-metrics.json`);
  const stateFile = path.join(runRoot, 'formatter', `${id}-state.json`);
  writeJson(metricsFile, metrics);
  writeJson(stateFile, state);
  const result = runNode(repo, '.knowledge/tools/task-routing.js', [
    'format', `--metrics=${metricsFile}`, `--state=${stateFile}`, '--json'
  ]);
  return { result, value: jsonOutput(result), text: jsonOutput(result)?.public_text || '' };
}

function runAllPublicSelfTests(pristineKnowledge, runRoot) {
  const tests = fs.readdirSync(path.join(pristineKnowledge, 'tools'))
    .filter((name) => /^self-test-.*\.js$/.test(name)).sort();
  const results = [];
  for (const name of tests) {
    const root = path.join(runRoot, 'isolated-self-tests', name.replace(/\.js$/, ''));
    fs.mkdirSync(root, { recursive: true });
    fs.cpSync(pristineKnowledge, path.join(root, '.knowledge'), { recursive: true });
    const result = runNode(root, `.knowledge/tools/${name}`, [], { timeout: 600000 });
    results.push({ id: name, status: result.exit_code === 0 ? 'passed' : 'failed', exit_code: result.exit_code, stdout_tail: result.stdout.slice(-2000), stderr_tail: result.stderr.slice(-2000) });
  }
  return results;
}

function main() {
  const flags = parseArgs(process.argv.slice(2));
  const candidate = path.resolve(flags.candidate);
  if (!fs.existsSync(candidate)) throw new Error(`Candidate not found: ${candidate}`);
  const workRoot = path.resolve(flags.workRoot || path.join(process.cwd(), '.workspace-narrowing-r7-verifier'));
  fs.mkdirSync(workRoot, { recursive: true });
  const runRoot = path.join(workRoot, `run-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  const repo = path.join(runRoot, 'repo');
  const pristineKnowledge = path.join(runRoot, 'pristine-candidate-knowledge');
  const results = [];
  const check = (id, pass, details = {}) => results.push({ id, status: pass ? 'passed' : 'failed', ...details });

  const entries = extractCandidate(candidate, repo);
  fs.cpSync(path.join(repo, '.knowledge'), pristineKnowledge, { recursive: true });
  const workflow = initialise(repo);

  const initial = createRoute(repo, 'methodology');
  const initialArtifacts = currentArtifacts(repo, initial.task_scope_hash);
  const interpretation = String(initialArtifacts.metrics.estimator_interpretation || '');
  check('01_comparison_kind_workspace_narrowing', initialArtifacts.metrics.comparison_kind === 'workspace_to_task_first_read_narrowing', { observed: initialArtifacts.metrics.comparison_kind || null });
  check('02_no_same_scope_wording', !/same.?scope|same frozen task scope/i.test(interpretation), { interpretation });
  check('03_no_version_comparison_wording', !/3\.2\.11|3\.3\.0|version comparison/i.test(interpretation), { interpretation });
  check('04_actual_model_usage_unavailable', initialArtifacts.metrics.actual_model_usage?.available === false, { actual_model_usage: initialArtifacts.metrics.actual_model_usage || null });

  const baselinePath = path.join(repo, '.knowledge', 'routing', 'workspace-baselines', initialArtifacts.current.baseline_hash, 'baseline.json');
  const physicalBaseline = fs.existsSync(baselinePath) ? readJson(baselinePath) : null;
  check('05_production_workspace_baseline_created', Boolean(physicalBaseline && physicalBaseline.generator === 'pro2pilot.workspace-baseline.canonical-generator'), { baseline_path: baselinePath, generator: physicalBaseline?.generator || null });
  check('06_required_workspace_roles_present_and_valid', Boolean(
    physicalBaseline?.roles?.filter((item) => item.required).length >= 4 &&
    physicalBaseline.roles.filter((item) => item.required).every((item) => item.valid === true && item.projection_hash)
  ), { roles: physicalBaseline?.roles || [] });

  const projectIndexFile = path.join(repo, '.knowledge', 'project_index.json');
  const validProjectIndex = fs.readFileSync(projectIndexFile);
  fs.writeFileSync(projectIndexFile, '{"foo":"bar"}\n', 'utf8');
  const invalidRole = createRoute(repo, 'invalid-project-index');
  const invalidRoleArtifacts = currentArtifacts(repo, invalidRole.task_scope_hash);
  check('07_invalid_project_index_rejected', Boolean(
    invalidRoleArtifacts.metrics.workspace_baseline_complete === false &&
    invalidRoleArtifacts.metrics.comparison_contract_valid === false &&
    invalidRoleArtifacts.metrics.claim_eligible === false &&
    invalidRoleArtifacts.metrics.assessment === 'not_comparable'
  ), {
    baseline_complete: invalidRoleArtifacts.metrics.workspace_baseline_complete ?? invalidRoleArtifacts.metrics.baseline_complete ?? null,
    comparison_contract_valid: invalidRoleArtifacts.metrics.comparison_contract_valid ?? null,
    claim_eligible: invalidRoleArtifacts.metrics.claim_eligible,
    assessment: invalidRoleArtifacts.metrics.assessment
  });
  fs.writeFileSync(projectIndexFile, validProjectIndex);

  const registryFile = path.join(repo, '.knowledge', 'modules', 'module_registry.json');
  const validRegistry = fs.readFileSync(registryFile);
  fs.writeFileSync(registryFile, '{"modules":[{"module_id":"broken"}]}\n', 'utf8');
  const invalidRegistryArtifacts = currentArtifacts(repo, createRoute(repo, 'invalid-module-registry').task_scope_hash);
  check('08_invalid_module_registry_rejected', invalidRegistryArtifacts.metrics.claim_eligible === false && invalidRegistryArtifacts.metrics.comparison_contract_valid === false, { claim_reasons: invalidRegistryArtifacts.metrics.claim_ineligible_reasons || [] });
  fs.writeFileSync(registryFile, validRegistry);

  const trustFile = path.join(repo, '.knowledge', 'maintenance', 'trust_report.json');
  const validTrust = fs.readFileSync(trustFile);
  fs.writeFileSync(trustFile, '{"foo":"bar"}\n', 'utf8');
  const invalidTrustAttempt = attemptCreateRoute(repo, 'invalid-trust-summary');
  const invalidTrustArtifacts = invalidTrustAttempt.artifacts || null;
  check('09_invalid_trust_summary_rejected', invalidTrustAttempt.rejected || (
    invalidTrustArtifacts.metrics.claim_eligible === false &&
    invalidTrustArtifacts.metrics.workspace_baseline_complete === false
  ), {
    rejected_by_cli: invalidTrustAttempt.rejected,
    exit_code: invalidTrustAttempt.result.exit_code,
    claim_reasons: invalidTrustArtifacts?.metrics?.claim_ineligible_reasons || []
  });
  fs.writeFileSync(trustFile, validTrust);

  fs.writeFileSync(path.join(repo, 'arbitrary-unrelated-baseline.bin'), Buffer.alloc(1024 * 1024, 0x58));
  const arbitraryFileArtifacts = currentArtifacts(repo, createRoute(repo, 'arbitrary-file').task_scope_hash);
  check('10_arbitrary_file_excluded_from_baseline', arbitraryFileArtifacts.current.baseline_hash === initialArtifacts.current.baseline_hash, { before: initialArtifacts.current.baseline_hash, after: arbitraryFileArtifacts.current.baseline_hash });
  const unknownProject = readJson(projectIndexFile);
  unknownProject.unknown_padding = 'x'.repeat(1024 * 1024);
  writeJson(projectIndexFile, unknownProject);
  const unknownFieldArtifacts = currentArtifacts(repo, createRoute(repo, 'unknown-field').task_scope_hash);
  check('11_unknown_field_does_not_inflate_baseline', unknownFieldArtifacts.current.baseline_hash === initialArtifacts.current.baseline_hash, { before: initialArtifacts.current.baseline_hash, after: unknownFieldArtifacts.current.baseline_hash });
  fs.writeFileSync(projectIndexFile, validProjectIndex);

  const oversizedRegistry = readJson(registryFile);
  oversizedRegistry.modules[0].purpose = 'x'.repeat(1024 * 1024);
  writeJson(registryFile, oversizedRegistry);
  const oversizedArtifacts = currentArtifacts(repo, createRoute(repo, 'oversized-purpose').task_scope_hash);
  check('12_oversized_canonical_field_blocks_claim', oversizedArtifacts.metrics.claim_eligible === false && (oversizedArtifacts.metrics.claim_ineligible_reasons || []).includes('workspace_baseline_role_size_anomaly'), { claim_reasons: oversizedArtifacts.metrics.claim_ineligible_reasons || [] });
  fs.writeFileSync(registryFile, validRegistry);

  const growthRegistry = readJson(registryFile);
  growthRegistry.modules.push({ module_id: 'legitimate_new_project', name: 'Legitimate new project', path: 'legitimate_new_project/', card: '.knowledge/modules/legitimate_new_project.json', purpose: 'Bounded legitimate workspace project', key_files: [] });
  writeJson(registryFile, growthRegistry);
  writeJson(path.join(repo, '.knowledge', 'modules', 'legitimate_new_project.json'), { module_id: 'legitimate_new_project', key_files: [] });
  const growthProject = readJson(projectIndexFile);
  growthProject.modules.push({ module_id: 'legitimate_new_project', card: '.knowledge/modules/legitimate_new_project.json', confidence: 'high' });
  writeJson(projectIndexFile, growthProject);
  const growthTrust = readJson(trustFile);
  growthTrust.modules_total = Number(growthTrust.modules_total || growthRegistry.modules.length - 1) + 1;
  growthTrust.modules = growthTrust.modules || {};
  growthTrust.modules.trusted = [...new Set([...(growthTrust.modules.trusted || []), 'legitimate_new_project'])];
  growthTrust.module_statuses.push({ module_id: 'legitimate_new_project', confidence: 'high', freshness_status: 'fresh', trust_status: 'trusted', reasons: { changed_or_missing_important_files: [], open_contradictions: [], uncovered_important_files: [] } });
  writeJson(trustFile, growthTrust);
  const growth = publicJson(repo, '.knowledge/tools/task-routing.js', ['refresh', `--task-id=${initial.task_scope_hash}`, '--json']).value;
  const growthArtifacts = currentArtifacts(repo, initial.task_scope_hash);
  check('13_legitimate_project_changes_workspace_baseline', growthArtifacts.current.baseline_hash !== initialArtifacts.current.baseline_hash && growthArtifacts.metrics.workspace_narrowing?.modules_total > initialArtifacts.metrics.workspace_narrowing?.modules_total, { before: initialArtifacts.current.baseline_hash, after: growthArtifacts.current.baseline_hash });
  check('14_legitimate_project_keeps_task_route_scoped', growthArtifacts.current.routing_snapshot_hash === initialArtifacts.current.routing_snapshot_hash && growthArtifacts.bundle.selected_modules?.length === 1 && growthArtifacts.bundle.selected_modules[0] === 'src', { refresh: growth, selected_modules: growthArtifacts.bundle.selected_modules || [] });
  commitIfChanged(repo, 'valid workspace growth fixture');

  const registry = readJson(registryFile);
  const sourceModule = registry.modules.find((item) => item.module_id === 'src');
  const cardFile = path.join(repo, '.knowledge', 'modules', 'src.json');
  const card = readJson(cardFile);
  const existingRequired = createRoute(repo, 'existing-required-source');
  const existingRequiredArtifacts = currentArtifacts(repo, existingRequired.task_scope_hash);
  check('15_existing_required_key_file_ready', existingRequiredArtifacts.metrics.required_sources_complete === true && existingRequiredArtifacts.bundle.task_readiness === 'ready', { required_sources: existingRequiredArtifacts.bundle.required_sources || null });
  sourceModule.key_files = ['src/missing-required.js'];
  writeJson(registryFile, registry);
  card.key_files = ['src/missing-required.js'];
  writeJson(cardFile, card);
  const missingSource = createRoute(repo, 'missing-required-source');
  const missingArtifacts = currentArtifacts(repo, missingSource.task_scope_hash);
  const missingReceipt = (missingArtifacts.provenance.read_set || []).find((item) => item.path === 'src/missing-required.js');
  check('16_missing_required_key_file_blocks', Boolean(
    missingArtifacts.bundle.task_readiness !== 'ready' &&
    missingArtifacts.metrics.claim_eligible === false &&
    missingReceipt?.required === true && missingReceipt?.path_state === 'missing'
  ), {
    task_readiness: missingArtifacts.bundle.task_readiness,
    claim_eligible: missingArtifacts.metrics.claim_eligible,
    receipt: missingReceipt || null
  });
  sourceModule.key_files = ['src/app.js'];
  writeJson(registryFile, registry);
  card.key_files = ['src/app.js'];
  writeJson(cardFile, card);
  commitIfChanged(repo, 'restore required source fixture');

  fs.appendFileSync(path.join(repo, 'src', 'app.js'), 'module.exports.modified = true;\n', 'utf8');
  const modified = createRoute(repo, 'git-modified');
  const modifiedArtifacts = currentArtifacts(repo, modified.task_scope_hash);
  const modifiedPath = (modifiedArtifacts.bundle.relevant_changed_or_stale_paths || [])
    .find((item) => item.path === 'src/app.js');
  check('21_first_unstaged_modified_record_preserved', Boolean(
    modifiedPath && modifiedPath.status === 'modified'
  ), {
    raw_git_status: git(repo, ['status', '--porcelain=v1', '--untracked-files=all']).stdout,
    observed_paths: modifiedArtifacts.bundle.relevant_changed_or_stale_paths || []
  });
  git(repo, ['add', 'src/app.js']);
  git(repo, ['commit', '-m', 'modified source baseline']);
  fs.unlinkSync(path.join(repo, 'src', 'app.js'));
  const deleted = createRoute(repo, 'git-deleted');
  const deletedArtifacts = currentArtifacts(repo, deleted.task_scope_hash);
  const deletedPath = (deletedArtifacts.bundle.relevant_changed_or_stale_paths || [])
    .find((item) => item.path === 'src/app.js');
  check('22_first_unstaged_deleted_record_preserved', Boolean(
    deletedPath && deletedPath.status === 'deleted' &&
    deletedPath.path === 'src/app.js'
  ), {
    raw_git_status: git(repo, ['status', '--porcelain=v1', '--untracked-files=all']).stdout,
    observed_paths: deletedArtifacts.bundle.relevant_changed_or_stale_paths || [],
    task_readiness: deletedArtifacts.bundle.task_readiness,
    claim_eligible: deletedArtifacts.metrics.claim_eligible
  });
  check('17_deleted_required_key_file_blocks', deletedArtifacts.bundle.task_readiness !== 'ready' && deletedArtifacts.metrics.claim_eligible === false, { task_readiness: deletedArtifacts.bundle.task_readiness, claim_eligible: deletedArtifacts.metrics.claim_eligible });
  fs.writeFileSync(path.join(repo, 'src', 'app.js'), "'use strict';\nmodule.exports = 2;\n", 'utf8');
  git(repo, ['add', 'src/app.js']);
  git(repo, ['commit', '-m', 'restore source after deletion fixture']);

  const optionalRegistry = readJson(registryFile);
  optionalRegistry.modules.find((item) => item.module_id === 'src').evidence_files = [{ path: 'src/optional-missing.md', required: false }];
  writeJson(registryFile, optionalRegistry);
  const optionalArtifacts = currentArtifacts(repo, createRoute(repo, 'optional-missing-source').task_scope_hash);
  check('18_optional_missing_pointer_non_blocking', optionalArtifacts.bundle.task_readiness === 'ready' && optionalArtifacts.metrics.claim_eligible === true, { task_readiness: optionalArtifacts.bundle.task_readiness, claim_eligible: optionalArtifacts.metrics.claim_eligible });
  optionalRegistry.modules.find((item) => item.module_id === 'src').evidence_files = [];
  writeJson(registryFile, optionalRegistry);

  const unsafeRegistry = readJson(registryFile);
  unsafeRegistry.modules.find((item) => item.module_id === 'src').key_files = ['../escape.js'];
  writeJson(registryFile, unsafeRegistry);
  card.key_files = ['../escape.js']; writeJson(cardFile, card);
  const unsafeArtifacts = currentArtifacts(repo, createRoute(repo, 'unsafe-required-source').task_scope_hash);
  const unsafeReceipt = unsafeArtifacts.provenance.read_set.find((item) => item.path === '../escape.js');
  check('19_unsafe_required_path_blocks', unsafeArtifacts.bundle.task_readiness !== 'ready' && unsafeArtifacts.metrics.claim_eligible === false && unsafeReceipt?.path_state === 'unsafe', { receipt: unsafeReceipt || null });
  unsafeRegistry.modules.find((item) => item.module_id === 'src').key_files = ['src/app.js'];
  writeJson(registryFile, unsafeRegistry); card.key_files = ['src/app.js']; writeJson(cardFile, card);

  const dependencyRegistry = readJson(registryFile);
  dependencyRegistry.modules.find((item) => item.module_id === 'src').dependencies = ['missing_dependency'];
  dependencyRegistry.modules.push({ module_id: 'missing_dependency', name: 'Missing dependency', path: 'missing_dependency/', card: '.knowledge/modules/missing_dependency.json', purpose: 'Dependency fixture', key_files: ['missing_dependency/missing.js'] });
  writeJson(registryFile, dependencyRegistry);
  writeJson(path.join(repo, '.knowledge', 'modules', 'missing_dependency.json'), { module_id: 'missing_dependency', key_files: ['missing_dependency/missing.js'] });
  const dependencyProject = readJson(projectIndexFile); dependencyProject.modules.push({ module_id: 'missing_dependency', card: '.knowledge/modules/missing_dependency.json', confidence: 'high' }); writeJson(projectIndexFile, dependencyProject);
  const dependencyTrust = readJson(trustFile); dependencyTrust.modules_total += 1; dependencyTrust.modules.trusted.push('missing_dependency'); dependencyTrust.module_statuses.push({ module_id: 'missing_dependency', confidence: 'high', freshness_status: 'fresh', trust_status: 'trusted' }); writeJson(trustFile, dependencyTrust);
  const dependencyArtifacts = currentArtifacts(repo, createRoute(repo, 'missing-dependency-source').task_scope_hash);
  check('20_missing_dependency_source_blocks', dependencyArtifacts.bundle.selected_modules.includes('missing_dependency') && dependencyArtifacts.bundle.task_readiness !== 'ready' && dependencyArtifacts.metrics.claim_eligible === false, { selected_modules: dependencyArtifacts.bundle.selected_modules, required_sources: dependencyArtifacts.bundle.required_sources || null });
  dependencyRegistry.modules = dependencyRegistry.modules.filter((item) => item.module_id !== 'missing_dependency'); dependencyRegistry.modules.find((item) => item.module_id === 'src').dependencies = []; writeJson(registryFile, dependencyRegistry);
  dependencyProject.modules = dependencyProject.modules.filter((item) => item.module_id !== 'missing_dependency'); writeJson(projectIndexFile, dependencyProject);
  dependencyTrust.modules_total -= 1; dependencyTrust.modules.trusted = dependencyTrust.modules.trusted.filter((id) => id !== 'missing_dependency'); dependencyTrust.module_statuses = dependencyTrust.module_statuses.filter((item) => item.module_id !== 'missing_dependency'); writeJson(trustFile, dependencyTrust);
  commitIfChanged(repo, 'restore dependency fixture');

  fs.writeFileSync(path.join(repo, 'src', 'added.js'), 'added\n'); git(repo, ['add', 'src/added.js']);
  const addedArtifacts = currentArtifacts(repo, createRoute(repo, 'git-added').task_scope_hash);
  check('23_added_status_preserved', addedArtifacts.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'src/added.js' && item.status === 'added'), { paths: addedArtifacts.bundle.relevant_changed_or_stale_paths });
  git(repo, ['commit', '-m', 'added fixture']);
  fs.writeFileSync(path.join(repo, 'src', 'untracked.js'), 'untracked\n');
  const untrackedArtifacts = currentArtifacts(repo, createRoute(repo, 'git-untracked').task_scope_hash);
  check('24_untracked_status_preserved', untrackedArtifacts.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'src/untracked.js' && item.status === 'untracked'), { paths: untrackedArtifacts.bundle.relevant_changed_or_stale_paths });
  commitIfChanged(repo, 'untracked fixture baseline');
  git(repo, ['mv', 'src/added.js', 'src/renamed.js']);
  const renamedArtifacts = currentArtifacts(repo, createRoute(repo, 'git-renamed').task_scope_hash);
  check('25_renamed_status_preserved', renamedArtifacts.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'src/renamed.js' && item.status === 'renamed'), { paths: renamedArtifacts.bundle.relevant_changed_or_stale_paths });
  git(repo, ['commit', '-m', 'renamed fixture']);
  fs.writeFileSync(path.join(repo, 'src', 'file with spaces.js'), 'one\n'); fs.writeFileSync(path.join(repo, 'src', 'файл.js'), 'one\n'); commitIfChanged(repo, 'special filenames baseline');
  fs.appendFileSync(path.join(repo, 'src', 'file with spaces.js'), 'two\n'); fs.appendFileSync(path.join(repo, 'src', 'файл.js'), 'two\n');
  const specialArtifacts = currentArtifacts(repo, createRoute(repo, 'git-special-filenames').task_scope_hash);
  check('26_filename_with_spaces_preserved', specialArtifacts.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'src/file with spaces.js' && item.status === 'modified'), { paths: specialArtifacts.bundle.relevant_changed_or_stale_paths });
  check('27_unicode_filename_preserved', specialArtifacts.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'src/файл.js' && item.status === 'modified'), { paths: specialArtifacts.bundle.relevant_changed_or_stale_paths });
  commitIfChanged(repo, 'special filenames modified baseline');
  fs.appendFileSync(path.join(repo, 'src', 'app.js'), 'relevant\n'); fs.appendFileSync(path.join(repo, 'README.md'), 'unrelated\n');
  const distinctionArtifacts = currentArtifacts(repo, createRoute(repo, 'git-relevance').task_scope_hash);
  check('28_relevant_unrelated_git_distinction', distinctionArtifacts.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'src/app.js') && !distinctionArtifacts.bundle.relevant_changed_or_stale_paths.some((item) => item.path === 'README.md'), { paths: distinctionArtifacts.bundle.relevant_changed_or_stale_paths });
  commitIfChanged(repo, 'relevance fixture baseline');

  const narrowingFormat = diagnosticFormat(repo, runRoot, 'narrowing', { assessment: 'estimated_narrowing', signed_delta_percent: 25, workspace_baseline: { estimated_tokens: 400 }, task_context: { estimated_tokens: 300 } }, { effective_claim_eligible: true });
  const overheadFormat = diagnosticFormat(repo, runRoot, 'overhead', { assessment: 'estimated_overhead', signed_delta_percent: -5, workspace_baseline: { estimated_tokens: 400 }, task_context: { estimated_tokens: 420 } }, { effective_claim_eligible: true });
  const neutralFormat = diagnosticFormat(repo, runRoot, 'neutral', { assessment: 'neutral', signed_delta_percent: 0, workspace_baseline: { estimated_tokens: 400 }, task_context: { estimated_tokens: 400 } }, { effective_claim_eligible: true });
  const notComparableFormat = diagnosticFormat(repo, runRoot, 'not-comparable', { assessment: 'not_comparable' }, { effective_claim_eligible: true });
  const staleFormat = diagnosticFormat(repo, runRoot, 'stale', { assessment: 'estimated_narrowing', signed_delta_percent: 99 }, { effective_claim_eligible: false, claim_ineligible_reasons: ['task_routing_snapshot_stale'] });
  check('29_public_eligible_narrowing', narrowingFormat.result.exit_code === 0 && /Estimated workspace-to-task first-read narrowing/.test(narrowingFormat.text), { text: narrowingFormat.text });
  check('30_public_eligible_overhead', overheadFormat.result.exit_code === 0 && /first-read overhead/.test(overheadFormat.text), { text: overheadFormat.text });
  check('31_public_neutral', neutralFormat.result.exit_code === 0 && /No material estimated workspace-to-task/.test(neutralFormat.text), { text: neutralFormat.text });
  check('32_public_not_comparable', notComparableFormat.result.exit_code === 0 && /^No public workspace-narrowing estimate/.test(notComparableFormat.text), { text: notComparableFormat.text });
  check('33_public_stale', staleFormat.result.exit_code === 0 && /task_routing_snapshot_stale/.test(staleFormat.text), { text: staleFormat.text });
  check('34_public_raw_assessment_absent', !/estimated_narrowing|estimated_savings|estimated_overhead/.test(staleFormat.text), { text: staleFormat.text });
  check('35_public_overhead_has_no_saving_zero', !/saving\s*=\s*0|saved|reduction/.test(overheadFormat.text), { text: overheadFormat.text });
  check('36_public_ineligible_has_no_percentage', !/\b\d+(?:\.\d+)?%\b/.test(staleFormat.text), { text: staleFormat.text });

  const contextRouteA = createRoute(repo, 'context-a');
  const contextRouteB = createRoute(repo, 'context-b');
  const explicitSummary = publicJson(repo, '.knowledge/tools/generate-pr-summary.js', [`--task-id=${contextRouteA.task_scope_hash}`]).value;
  check('37_multi_task_explicit_selection', explicitSummary.task_routing_resolution?.source === 'explicit_task_id' && explicitSummary.task_routing_resolution.task_scope_hash === contextRouteA.task_scope_hash, { resolution: explicitSummary.task_routing_resolution || null });
  writeJson(path.join(repo, '.knowledge', 'sessions', 'agent-registry.json'), { sessions: [{ session_id: 'verifier-session', task_id: contextRouteB.task_scope_hash, status: 'running' }] });
  const sessionSummary = publicJson(repo, '.knowledge/tools/generate-pr-summary.js', ['--session-id=verifier-session']).value;
  check('38_multi_task_agent_session_selection', sessionSummary.task_routing_resolution?.source === 'agent_session' && sessionSummary.task_routing_resolution.task_scope_hash === contextRouteB.task_scope_hash, { resolution: sessionSummary.task_routing_resolution || null });
  writeJson(path.join(repo, '.knowledge', 'sessions', 'agent-registry.json'), { sessions: [] });
  writeJson(path.join(repo, '.knowledge', 'routing', 'pr-task-map.json'), { mappings: [{ pr_number: 77, task_scope_hash: contextRouteA.task_scope_hash }] });
  const prSummary = publicJson(repo, '.knowledge/tools/generate-pr-summary.js', ['--pr-number=77']).value;
  check('39_multi_task_pr_mapping_selection', prSummary.task_routing_resolution?.source === 'pr_mapping' && prSummary.task_routing_resolution.task_scope_hash === contextRouteA.task_scope_hash, { resolution: prSummary.task_routing_resolution || null });
  const ambiguousSummary = publicJson(repo, '.knowledge/tools/generate-pr-summary.js', []).value;
  const ambiguousBody = fs.readFileSync(path.join(repo, '.knowledge', 'maintenance', 'pr_summary.md'), 'utf8');
  check('40_multi_task_ambiguous_blocks_percentage', ambiguousSummary.task_routing_resolution?.reason === 'task_routing_context_ambiguous' && !/\b\d+(?:\.\d+)?%\b/.test(ambiguousBody), { resolution: ambiguousSummary.task_routing_resolution || null });

  check('41_physical_clean_install', workflow.install.exit_code === 0, { exit_code: workflow.install.exit_code, stdout: workflow.install.stdout.slice(-2000), stderr: workflow.install.stderr.slice(-2000) });
  check('42_physical_import', workflow.imported.exit_code === 0, { exit_code: workflow.imported.exit_code });
  const release = runNode(repo, '.knowledge/tools/flow.js', ['release', '--json'], { timeout: 900000 });
  check('43_physical_release', release.exit_code === 0, { exit_code: release.exit_code, stdout_tail: release.stdout.slice(-3000), stderr_tail: release.stderr.slice(-3000) });
  const physicalRoute = createRoute(repo, 'physical-final-route');
  const physicalRouteArtifacts = currentArtifacts(repo, physicalRoute.task_scope_hash);
  check('44_physical_task_route', physicalRouteArtifacts.metrics.comparison_kind === 'workspace_to_task_first_read_narrowing' && physicalRouteArtifacts.bundle.selected_modules?.includes('src'), { metrics: physicalRouteArtifacts.metrics, bundle: physicalRouteArtifacts.bundle });
  const fieldReport = renderPublicReport(repo, physicalRoute.task_scope_hash, 'physical');
  check('45_physical_field_report', /Workspace-to-task first-read narrowing|No public workspace-narrowing estimate/.test(fieldReport.body) && !/Routing estimator assessment|estimated_savings/.test(fieldReport.body), { report_id: fieldReport.report_id, body: fieldReport.body });
  const finalPr = publicJson(repo, '.knowledge/tools/generate-pr-summary.js', [`--task-id=${physicalRoute.task_scope_hash}`]).value;
  const finalPrBody = fs.readFileSync(path.join(repo, '.knowledge', 'maintenance', 'pr_summary.md'), 'utf8');
  check('46_physical_pr_summary', finalPr.task_routing_resolution?.task_scope_hash === physicalRoute.task_scope_hash && /workspace-to-task first-read|No public workspace-narrowing estimate/i.test(finalPrBody), { resolution: finalPr.task_routing_resolution || null, body: finalPrBody });
  const inspector = runNode(repo, '.knowledge/tools/build-visual-inspector.js', ['--quiet'], { timeout: 360000 });
  const inspectorFile = path.join(repo, '.knowledge', 'inspector', 'index.html');
  const inspectorBody = fs.existsSync(inspectorFile) ? fs.readFileSync(inspectorFile, 'utf8') : '';
  check('47_physical_inspector_data', inspector.exit_code === 0 && /workspace_to_task_first_read_narrowing|Workspace comparison/.test(inspectorBody), { exit_code: inspector.exit_code, inspector_path: inspectorFile });
  const publicSelfTests = runAllPublicSelfTests(pristineKnowledge, runRoot);
  check('48_all_public_self_tests', publicSelfTests.length >= 30 && publicSelfTests.every((item) => item.status === 'passed'), { checks_total: publicSelfTests.length, results: publicSelfTests });

  if (results.length !== 48) throw new Error(`Verifier invariant: expected 48 results, received ${results.length}`);

  const summary = {
    schema_version: 'knowledge-workspace-narrowing-rc4-r7-verifier.v1',
    phase: flags.phase || 'full',
    candidate: { path: candidate, sha256: sha(fs.readFileSync(candidate)), entries },
    run_root: runRoot,
    checks_total: results.length,
    passed: results.filter((item) => item.status === 'passed').length,
    failed: results.filter((item) => item.status === 'failed').length,
    status: results.every((item) => item.status === 'passed') ? 'passed' : 'failed',
    results
  };
  const output = path.resolve(flags.output || path.join(runRoot, 'verification.json'));
  writeJson(output, summary);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  process.exitCode = summary.status === 'passed' ? 0 : 1;
}

try { main(); } catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 2;
}
