#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildRoutingDecision, repoClass } = require('./lib/adaptive-routing');
const {
  targetRelativeGitChangedFiles
} = require('./build-routing-bundle');

const systemRoot = path.resolve(__dirname, '..');
const SIZE_FIXTURES = {
  XS: { files: 80, bytes: 80 },
  S: { files: 200, bytes: 3 * 1024 * 1024 },
  M: { files: 800, bytes: 20 * 1024 * 1024 },
  L: { files: 4000, bytes: 100 * 1024 * 1024 },
  XL: { files: 20000, bytes: 500 * 1024 * 1024 }
};
const TASKS = {
  simple_edit: 'edit billing invoice formatting',
  security_review: 'security review of authentication and secrets',
  migration: 'migrate billing schema to version four',
  architecture_audit: 'architecture audit',
  incident_analysis: 'incident root cause diagnostic',
  cross_module_refactor: 'cross-module refactor of billing',
  pr_review: 'PR review for billing changes',
  security_review_ru: 'проверка безопасности аутентификации и секретов',
  migration_ru: 'миграция схемы данных',
  cross_module_migration_ru: 'миграция схемы между модулями',
  architecture_audit_ru: 'аудит архитектуры всего репозитория',
  incident_analysis_ru: 'анализ инцидента и первопричины сбоя в продакшене'
};
const GRAPH_STATES = ['healthy', 'usable_with_warnings', 'structurally_broken'];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function write(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, typeof value === 'string' ? value : JSON.stringify(value, null, 2), 'utf8');
}

function modulesFixture() {
  const modules = [];
  for (let index = 0; index < 8; index += 1) {
    const id = index === 7 ? 'billing' : `module-${index}`;
    modules.push({
      module_id: id,
      name: index === 7 ? 'Billing invoices' : `Module ${index}`,
      path: `src/${id}/`,
      card: `.knowledge/modules/${id}.json`,
      key_files: [`src/${id}/index.js`],
      keywords: index === 7 ? ['billing', 'invoice', 'payment'] : [`topic-${index}`],
      dependencies: index === 7 ? ['module-6'] : []
    });
  }
  return modules;
}

function trustFixture(modules, variant = 'normal') {
  const statuses = modules.map((item) => ({
    module_id: item.module_id,
    confidence: 'high',
    trust_status: 'trusted',
    freshness_status: 'fresh',
    reasons: { open_contradictions: [] }
  }));
  const target = statuses.find((item) => item.module_id === 'module-6');
  if (variant === 'suspect' || variant === 'critical-path') target.trust_status = 'suspect';
  if (variant === 'stale') target.freshness_status = 'stale';
  if (variant === 'low-confidence') {
    target.trust_status = 'low_confidence';
    target.confidence = 'low';
  }
  if (variant === 'contradiction') target.reasons.open_contradictions = [{ id: 'open-1' }];
  return {
    modules: {
      trusted: statuses.filter((item) => item.trust_status === 'trusted').map((item) => item.module_id),
      suspect: statuses.filter((item) => item.trust_status === 'suspect').map((item) => item.module_id),
      low_confidence: statuses.filter((item) => item.trust_status === 'low_confidence').map((item) => item.module_id)
    },
    module_statuses: statuses
  };
}

function decision(overrides = {}) {
  const modules = overrides.modules || modulesFixture();
  const variant = overrides.variant || 'normal';
  const trustReport = overrides.trustReport || trustFixture(modules, variant);
  const changedFiles = [...(overrides.changedFiles || [])];
  if (variant === 'changed') changedFiles.push({ path: 'src/module-6/index.js', status: 'changed', source: 'fixture' });
  if (variant === 'security-sensitive') {
    const target = modules.find((item) => item.module_id === 'module-6');
    target.security_sensitive = true;
    target.keywords = ['security', 'authentication', 'secrets'];
  }
  const criticalPaths = {
    paths: (variant === 'critical-path' || overrides.critical)
      ? [{ id: 'checkout', modules: ['module-6'], start_with: ['src/module-6/index.js'] }]
      : []
  };
  return buildRoutingDecision({
    size: overrides.size || SIZE_FIXTURES.XS,
    task: overrides.task || TASKS.simple_edit,
    override: overrides.override || null,
    contextBudgetBytes: overrides.contextBudgetBytes || null,
    registry: { modules },
    statusByModule: trustReport.module_statuses,
    trustReport,
    freshness: overrides.freshness || { tracked_files: [] },
    changedFiles,
    criticalPaths,
    taskRouting: [{
      route_id: 'billing',
      keywords: ['billing', 'invoice', 'payment'],
      target_modules: ['billing'],
      start_with: ['src/billing/index.js']
    }],
    wikiLint: {
      status: overrides.graph || 'healthy',
      structural_status: overrides.graph || 'healthy'
    },
    wikiGraph: {
      structural_status: overrides.graph || 'healthy',
      broken_edge_count: overrides.graph === 'structurally_broken' ? 1 : 0
    },
    quality: overrides.quality || { issues: [] },
    repairQueue: overrides.repairQueue || { queue: [] }
  });
}

function physicalSize(sizeClass) {
  return {
    XS: 1024,
    S: 3 * 1024 * 1024,
    M: 20 * 1024 * 1024,
    L: 100 * 1024 * 1024,
    XL: 500 * 1024 * 1024
  }[sizeClass];
}

function createRepo(options = {}) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-routing-v2-'));
  const modules = modulesFixture();
  const variant = options.variant || 'normal';
  const trustReport = trustFixture(modules, variant);
  if (variant === 'security-sensitive') {
    const target = modules.find((item) => item.module_id === 'module-6');
    target.security_sensitive = true;
    target.keywords = ['security', 'authentication', 'secrets'];
  }
  const registryModules = options.dependenciesInCardsOnly
    ? modules.map(({ dependencies, depends_on, related_modules, ...moduleInfo }) => moduleInfo)
    : modules;
  fs.mkdirSync(path.join(repo, 'data'), { recursive: true });
  const sparse = path.join(repo, 'data', 'repo-size.bin');
  fs.closeSync(fs.openSync(sparse, 'w'));
  fs.truncateSync(sparse, physicalSize(options.sizeClass || 'XS'));
  for (const moduleInfo of modules) {
    write(path.join(repo, moduleInfo.key_files[0]), `module.exports = '${moduleInfo.module_id}';\n`);
    write(path.join(repo, moduleInfo.card), {
      ...moduleInfo,
      module_id: options.cardIdMismatch && moduleInfo.module_id === 'billing'
        ? 'forged-module-id'
        : moduleInfo.module_id
    });
  }
  write(path.join(repo, '.knowledge', 'project_index.json'), {
    project_name: 'routing-fixture',
    task_routing: [{
      route_id: 'billing',
      keywords: ['billing', 'invoice', 'payment'],
      target_modules: ['billing'],
      start_with: ['src/billing/index.js']
    }]
  });
  write(path.join(repo, '.knowledge', 'modules', 'module_registry.json'), { modules: registryModules });
  write(path.join(repo, '.knowledge', 'maintenance', 'trust_report.json'), trustReport);
  write(path.join(repo, '.knowledge', 'maintenance', 'quality_report.json'), { issues: [] });
  write(path.join(repo, '.knowledge', 'maintenance', 'repair_queue.json'), { queue: [] });
  const graph = options.graph || 'healthy';
  write(path.join(repo, '.knowledge', 'maintenance', 'wiki_lint_report.json'), {
    status: graph,
    structural_status: graph,
    quality_score: graph === 'healthy' ? 100 : 80
  });
  write(path.join(repo, '.knowledge', 'maps', 'wiki_graph.json'), {
    edge_count: 1,
    broken_edge_count: graph === 'structurally_broken' ? 1 : 0,
    structural_status: graph
  });
  write(path.join(repo, '.knowledge', 'maps', 'critical_paths.json'), {
    paths: variant === 'critical-path' ? [{ id: 'checkout', modules: ['module-6'] }] : []
  });
  write(path.join(repo, '.knowledge', 'maps', 'file_criticality.json'), { files: [] });
  const trackedFiles = options.changedOverflow
    ? [
        ...Array.from({ length: 105 }, (_, index) => ({
          path: `docs/generated-${String(index).padStart(3, '0')}.md`,
          status: 'changed'
        })),
        { path: 'src/module-6/index.js', status: 'changed' }
      ]
    : (variant === 'changed'
        ? [{ path: 'src/module-6/index.js', status: 'changed' }]
        : []);
  write(path.join(repo, '.knowledge', 'freshness.json'), { tracked_files: trackedFiles });
  return repo;
}

function routePhysical(options = {}) {
  const repo = createRepo(options);
  try {
    const fixtureKnowledgeRoot = path.join(repo, '.knowledge');
    const args = [
      path.join(systemRoot, 'tools', 'build-routing-bundle.js'),
      '--system-root', fixtureKnowledgeRoot,
      '--target-root', repo,
      '--task', options.task || TASKS.simple_edit,
      '--quiet'
    ];
    if (options.override) args.push('--routing-mode', options.override);
    if (options.contextBudgetBytes) args.push('--context-budget-bytes', String(options.contextBudgetBytes));
    const result = spawnSync(process.execPath, args, {
      encoding: 'utf8',
      windowsHide: true,
      env: {
        ...process.env,
        KNOWLEDGE_AGENT_ID: 'adaptive-routing-self-test',
        KNOWLEDGE_SYSTEM_ROOT: fixtureKnowledgeRoot,
        KNOWLEDGE_TARGET_ROOT: repo
      }
    });
    assert(result.status === 0, `physical routing failed: ${result.stderr || result.stdout}`);
    const bundle = JSON.parse(fs.readFileSync(path.join(repo, '.knowledge', 'maintenance', 'routing_bundle.json'), 'utf8'));
    const latest = JSON.parse(fs.readFileSync(path.join(repo, '.knowledge', 'maintenance', 'routing_decision.json'), 'utf8'));
    const log = fs.readFileSync(path.join(repo, '.knowledge', 'maintenance', 'routing_decisions.ndjson'), 'utf8').trim().split(/\r?\n/).map(JSON.parse).at(-1);
    return { bundle, latest, log };
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
}

function verifyMatrix() {
  let cases = 0;
  for (const [sizeName, size] of Object.entries(SIZE_FIXTURES)) {
    assert(repoClass(size) === sizeName, `size fixture ${sizeName} classified as ${repoClass(size)}`);
    for (const [taskName, task] of Object.entries(TASKS)) {
      for (const graph of GRAPH_STATES) {
        const result = decision({ size, task, graph });
        cases += 1;
        assert(result.omitted_relevant_high_risk_modules.length === 0, `${sizeName}/${taskName}/${graph}: high-risk omission`);
        assert(result.selected_modules.length > 0, `${sizeName}/${taskName}/${graph}: empty payload`);
        if (graph === 'structurally_broken') {
          assert(result.mode === 'full', `${sizeName}/${taskName}: broken graph must force full`);
          assert(result.selected_modules.length === result.candidate_modules.length, 'full mode must include every candidate');
        }
        if (graph !== 'structurally_broken' && ['L', 'XL'].includes(sizeName) && taskName === 'simple_edit') {
          assert(result.mode === 'compact', `${sizeName} localized task must be bounded compact`);
        }
        if (graph === 'healthy' && ['XS', 'S'].includes(sizeName) && ['security_review', 'migration'].includes(taskName)) {
          assert(result.mode !== 'minimal', `${sizeName}/${taskName} must not be minimal`);
        }
      }
    }
  }
  return cases;
}

function verifyModuleVariants() {
  const variants = ['normal', 'changed', 'suspect', 'stale', 'low-confidence', 'critical-path', 'security-sensitive', 'contradiction'];
  const checks = [];
  for (const variant of variants) {
    const task = variant === 'security-sensitive' ? TASKS.security_review : 'edit module-6 behavior';
    const result = decision({ variant, task, critical: variant === 'critical-path' });
    if (variant !== 'normal') assert(result.selected_modules.includes('module-6'), `${variant}: affected module omitted`);
    assert(result.omitted_relevant_high_risk_modules.length === 0, `${variant}: invariant failed`);
    checks.push({ variant, mode: result.mode, selected: result.selected_modules });
  }
  return checks;
}

function verifyRequiredFixtures() {
  const checks = [];
  const relevantLast = routePhysical({ task: 'fix billing invoice rounding' });
  assert(relevantLast.latest.candidate_modules[0].module_id === 'billing', 'relevant module at end of registry was not ranked first');
  assert(relevantLast.latest.candidate_modules[0].reasons.some((reason) => reason.startsWith('task_')), 'selected module lacks task reason');
  checks.push('relevant_last_ranked_first');

  const criticalBeyondFive = routePhysical({ variant: 'critical-path', task: 'edit module-6 checkout' });
  assert(criticalBeyondFive.latest.selected_modules.includes('module-6'), 'critical module beyond first five omitted');
  checks.push('critical_beyond_first_five');

  const smallSecurity = routePhysical({ variant: 'security-sensitive', task: TASKS.security_review });
  assert(smallSecurity.latest.mode === 'compact', 'small security task must use compact');
  assert(smallSecurity.latest.selected_modules.includes('module-6'), 'security-sensitive module omitted');
  checks.push('small_security');

  const smallSecurityRu = routePhysical({ variant: 'security-sensitive', task: TASKS.security_review_ru });
  assert(smallSecurityRu.latest.mode === 'compact', 'Russian small security task must use compact');
  assert(smallSecurityRu.latest.selected_modules.includes('module-6'), 'Russian security-sensitive module omitted');
  checks.push('small_security_ru');

  const migrationRu = routePhysical({ task: TASKS.migration_ru });
  assert(migrationRu.latest.mode === 'compact', 'Russian migration must not use minimal');
  checks.push('migration_ru');

  const crossMigrationRu = routePhysical({ task: TASKS.cross_module_migration_ru });
  assert(crossMigrationRu.latest.mode === 'full', 'Russian cross-module migration must use full');
  checks.push('cross_module_migration_ru');

  const architectureRu = routePhysical({ task: TASKS.architecture_audit_ru });
  assert(architectureRu.latest.mode === 'full', 'Russian repository-wide architecture audit must use full');
  checks.push('architecture_audit_ru');

  const incidentRu = routePhysical({ task: TASKS.incident_analysis_ru });
  assert(incidentRu.latest.mode === 'full', 'Russian incident diagnostic must use full');
  checks.push('incident_analysis_ru');

  const broken = routePhysical({ graph: 'structurally_broken', task: TASKS.simple_edit });
  assert(broken.latest.mode === 'full', 'broken graph did not force full');
  assert(broken.latest.selected_modules.length === 8, 'broken graph full payload was truncated');
  checks.push('broken_graph_full');

  const localizedLarge = routePhysical({ sizeClass: 'L', task: 'fix billing invoice rounding' });
  assert(localizedLarge.latest.mode === 'compact', 'L localized task should be compact');
  assert(localizedLarge.latest.context_budget.bytes !== null, 'L compact task must remain budget bounded');
  checks.push('large_localized_bounded');

  const changedXL = routePhysical({ sizeClass: 'XL', variant: 'changed', task: 'edit module-6 behavior' });
  assert(changedXL.latest.mode === 'compact', 'XL one-module task should be compact');
  assert(changedXL.latest.selected_modules.includes('module-6'), 'XL changed module omitted');
  checks.push('xl_one_changed');

  const contradiction = decision({ variant: 'contradiction', task: 'unrelated docs edit' });
  assert(contradiction.mode === 'compact', 'unresolved contradiction should prevent minimal');
  assert(contradiction.selected_modules.includes('module-6'), 'contradiction module omitted');
  checks.push('unresolved_contradiction');

  const manual = routePhysical({ override: 'full', task: TASKS.simple_edit });
  assert(manual.latest.mode === 'full' && manual.latest.selection === 'manual', 'manual full override failed');
  checks.push('manual_full');

  const exhausted = routePhysical({ variant: 'security-sensitive', task: TASKS.security_review, contextBudgetBytes: 1 });
  assert(exhausted.latest.context_budget.safety_overrun === true, 'budget exhaustion must record safety overrun');
  assert(exhausted.latest.omitted_relevant_high_risk_modules.length === 0, 'budget exhaustion omitted relevant high-risk module');
  assert(/safety_budget_overrun/.test(exhausted.latest.truncation_reason), 'budget exhaustion reason missing');
  checks.push('budget_exhaustion_fail_closed');

  const fallback = routePhysical({ task: 'zzzz-no-module-match-zzzz' });
  assert(fallback.latest.fallback_behavior === 'ranked_high_risk_then_stable_tiebreak', 'no-relevance fallback not recorded');
  assert(fallback.latest.selected_modules.length > 0, 'no-relevance fallback returned empty payload');
  checks.push('no_relevance_fallback');

  const cardDependency = routePhysical({
    task: 'fix billing invoice rounding',
    dependenciesInCardsOnly: true
  });
  const dependencyCandidate = cardDependency.latest.candidate_modules.find((item) => item.module_id === 'module-6');
  assert(dependencyCandidate?.reasons.includes('dependency_distance:1'), 'card-only dependency was not hydrated into production routing');
  assert(dependencyCandidate?.selected === true, 'card-only dependency was not selected');
  checks.push('card_dependency_hydrated');

  const mismatchedCard = routePhysical({
    task: 'fix billing invoice rounding',
    dependenciesInCardsOnly: true,
    cardIdMismatch: true
  });
  const mismatchWarning = mismatchedCard.latest.input_warnings.find((item) =>
    item.code === 'routing_module_card_id_mismatch' &&
    item.module_id === 'billing'
  );
  const mismatchedDependency = mismatchedCard.latest.candidate_modules.find(
    (item) => item.module_id === 'module-6'
  );
  assert(mismatchWarning, 'module-card identity mismatch was not reported');
  assert(
    !mismatchedDependency?.reasons.includes('dependency_distance:1'),
    'routing hydrated dependency metadata from a mismatched module card'
  );
  checks.push('mismatched_card_metadata_fail_closed');

  const highRiskCardDependency = routePhysical({
    variant: 'stale',
    task: 'fix billing invoice rounding',
    dependenciesInCardsOnly: true,
    contextBudgetBytes: 1
  });
  const highRiskDependency = highRiskCardDependency.latest.candidate_modules.find((item) => item.module_id === 'module-6');
  assert(highRiskDependency?.relevant === true && highRiskDependency?.high_risk === true &&
    highRiskDependency?.selected === true, 'high-risk card dependency was omitted under budget exhaustion');
  assert(highRiskCardDependency.latest.omitted_relevant_high_risk_modules.length === 0,
    'card dependency caused a high-risk omission');
  checks.push('high_risk_card_dependency_fail_closed');

  const overflow = routePhysical({
    task: 'edit module-6 behavior',
    changedOverflow: true
  });
  assert(overflow.latest.changed_files.length === 106, 'full changed-file decision provenance was truncated');
  assert(overflow.latest.changed_files.some((item) => item.path === 'src/module-6/index.js'),
    'high-risk changed file after the old first-100 boundary was not preserved');
  checks.push('changed_file_overflow_high_risk_preserved');

  const russianCorpusModules = modulesFixture();
  const russianSecurityModule = russianCorpusModules.find((item) => item.module_id === 'module-6');
  russianSecurityModule.name = 'Аутентификация';
  russianSecurityModule.purpose = 'Проверка секретов и безопасности';
  russianSecurityModule.keywords = [];
  const russianCorpus = decision({
    modules: russianCorpusModules,
    task: TASKS.security_review_ru
  });
  const russianCorpusCandidate = russianCorpus.candidate_modules.find((item) => item.module_id === 'module-6');
  assert(russianCorpusCandidate?.flags.security_sensitive === true &&
    russianCorpusCandidate?.relevant === true &&
    russianCorpusCandidate?.selected === true, 'Russian module security metadata was not classified');
  checks.push('russian_security_module_corpus');

  const dependencyChainModules = [
    { module_id: 'alpha', name: 'Alpha', path: 'src/alpha/', card: '.knowledge/modules/alpha.json', dependencies: ['beta'] },
    { module_id: 'beta', name: 'Beta', path: 'src/beta/', card: '.knowledge/modules/beta.json', dependencies: ['gamma'] },
    { module_id: 'gamma', name: 'Gamma', path: 'src/gamma/', card: '.knowledge/modules/gamma.json', dependencies: ['delta'] },
    { module_id: 'delta', name: 'Delta', path: 'src/delta/', card: '.knowledge/modules/delta.json', dependencies: ['epsilon'] },
    { module_id: 'epsilon', name: 'Epsilon', path: 'src/epsilon/', card: '.knowledge/modules/epsilon.json', dependencies: [] }
  ];
  const dependencyChain = decision({ modules: dependencyChainModules, task: 'edit alpha behavior' });
  const chainById = Object.fromEntries(dependencyChain.candidate_modules.map((item) => [item.module_id, item]));
  assert(chainById.beta.reasons.includes('dependency_distance:1'), 'distance one missing');
  assert(chainById.gamma.reasons.includes('dependency_distance:2'), 'distance two missing');
  assert(chainById.delta.reasons.includes('dependency_distance:3'), 'distance three missing');
  assert(!chainById.epsilon.reasons.some((reason) => reason.startsWith('dependency_distance:')), 'distance four must not be boosted');
  checks.push('dependency_distance_1_2_3_bounded');

  const duplicateChangedRows = [
    { path: 'src\\module-6\\index.js', status: 'changed', source: 'current_diff' },
    { path: 'src/module-6/index.js', status: 'changed', source: 'explicit_scope' }
  ];
  const dedupedChanged = decision({
    task: 'edit module-6 behavior',
    changedFiles: duplicateChangedRows,
    freshness: {
      tracked_files: [{ path: 'src/module-6/index.js', status: 'stale' }]
    }
  });
  const dedupedCandidate = dedupedChanged.candidate_modules.find((item) => item.module_id === 'module-6');
  assert(dedupedChanged.changed_files.length === 1 && dedupedCandidate.changed_files.length === 1,
    'changed-file path variants were not deduplicated');
  assert(dedupedChanged.changed_files[0].source === 'explicit_scope' &&
    dedupedChanged.changed_files[0].status === 'stale', 'changed-file source/status priority mismatch');
  assert(dedupedChanged.changed_files[0].sources.length === 3 &&
    dedupedChanged.changed_files[0].statuses.length === 2, 'changed-file provenance sets are incomplete');
  checks.push('changed_file_provenance_deduped');

  const caseDistinctChanged = decision({
    task: 'edit module-6 behavior',
    changedFiles: [
      { path: 'src/module-6/Case.js', status: 'changed', source: 'current_diff' },
      { path: 'src/module-6/case.js', status: 'changed', source: 'current_diff' }
    ]
  });
  assert(
    caseDistinctChanged.changed_files.length === 2 &&
    caseDistinctChanged.changed_files.some((item) => item.path.endsWith('/Case.js')) &&
    caseDistinctChanged.changed_files.some((item) => item.path.endsWith('/case.js')),
    'case-distinct repository paths were collapsed in changed-file provenance'
  );
  checks.push('case_distinct_changed_paths_preserved');

  const intentVariants = [
    ['upgrade billing schema', 'migration'],
    ['обновление версии схемы', 'migration'],
    ['переход на версию пять', 'migration'],
    ['credential encryption review', 'security_review'],
    ['проверка учетных данных и паролей', 'security_review']
  ];
  for (const [task, expectedType] of intentVariants) {
    const routed = decision({ task });
    assert(routed.task.type === expectedType, `${task}: expected ${expectedType}, got ${routed.task.type}`);
  }
  checks.push('english_russian_intent_variants');

  assert(manual.latest.schema_version === 'adaptive-routing-decision.v2', 'latest decision artifact missing schema');
  assert(manual.log.selected_modules.length === manual.latest.selected_modules.length, 'NDJSON decision does not match latest artifact');
  checks.push('decision_artifact_complete');

  const hostRoot = path.join(os.tmpdir(), 'routing-host-root');
  const nestedTarget = path.join(
    hostRoot,
    'release-source-3.3.0-primary-reviewed'
  );
  const nestedPrefix = path.relative(
    hostRoot,
    nestedTarget
  ).replace(/\\/g, '/');
  const projectedGitChanges = targetRelativeGitChangedFiles({
    is_git_repo: true,
    worktree_root: hostRoot,
    changed_files: [
      `${nestedPrefix}/src/auth.js`,
      nestedPrefix,
      'unrelated/project.js'
    ]
  }, nestedTarget);
  assert(
    JSON.stringify(projectedGitChanges) ===
      JSON.stringify(['src/auth.js', '.']) &&
    targetRelativeGitChangedFiles({
      is_git_repo: true,
      worktree_root: hostRoot,
      changed_files: ['src/auth.js']
    }, path.join(os.tmpdir(), 'outside-routing-root')).length === 0,
    'ancestor Git changes were not projected into the target namespace'
  );
  checks.push('git_changes_rebased_to_target_root');
  return checks;
}

function verifyOrderInvariance() {
  const normalModules = modulesFixture();
  const reversedModules = [...normalModules].reverse();
  const first = decision({ modules: normalModules, task: 'billing invoice review' });
  const second = decision({ modules: reversedModules, task: 'billing invoice review' });
  assert(JSON.stringify(first.selected_modules) === JSON.stringify(second.selected_modules), 'selection changes with registry input order');
  const scores = (result) => Object.fromEntries(result.candidate_modules.map((item) => [item.module_id, item.score]).sort(([a], [b]) => a.localeCompare(b)));
  assert(JSON.stringify(scores(first)) === JSON.stringify(scores(second)), 'scores change with registry input order');
  const changedRows = [
    { path: 'src/module-6/index.js', status: 'changed', source: 'current_diff' },
    { path: 'src\\module-6\\index.js', status: 'stale', source: 'freshness' }
  ];
  const changedFirst = decision({ task: 'edit module-6', changedFiles: changedRows });
  const changedSecond = decision({ task: 'edit module-6', changedFiles: [...changedRows].reverse() });
  assert(JSON.stringify(changedFirst.changed_files) === JSON.stringify(changedSecond.changed_files),
    'changed-file provenance changes with input order');
  assert(JSON.stringify(scores(changedFirst)) === JSON.stringify(scores(changedSecond)),
    'changed-file scores change with input order');
  return true;
}

function main() {
  const matrixCases = verifyMatrix();
  const moduleVariants = verifyModuleVariants();
  // Keep physical fixtures as release evidence.  Task routing consumes this
  // safety decision; it does not supersede its required adaptive tests.
  const requiredFixtures = verifyRequiredFixtures();
  verifyOrderInvariance();
  console.log(JSON.stringify({
    status: 'pass',
    matrix_cases: matrixCases,
    module_variants: moduleVariants.length,
    required_fixtures: requiredFixtures,
    registry_order_invariant: true,
    omitted_relevant_high_risk_modules: 0
  }, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
