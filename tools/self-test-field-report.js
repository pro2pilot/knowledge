#!/usr/bin/env node
'use strict';

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  run,
  __test: fieldReportTest
} = require('./field-report');
const {
  DEFAULT_SCHEMA,
  FIELDS,
  PUBLIC_LANGUAGE,
  canonicalHash,
  generateGithubForm,
  missingQuestions,
  normalizePublicLanguage,
  translationRequired,
  unwrap,
  validateAnswers,
  validateContract
} = require('./lib/field-report/contract');
const {
  collect,
  collectRepositoryProfile,
  repositoryProfilePathExcluded
} = require('./lib/field-report/collector');
const {
  generalizeInternalOrganization,
  redactText,
  scanEnglishLanguage,
  scanPublication
} = require('./lib/field-report/redactor');
const {
  buildDiscussionTitle,
  claimSafetyFindings,
  publicAnswerLanguageFindings,
  relationshipDisclosure,
  releaseIdentity,
  render,
  renderEvidence,
  repositoryProfileRows,
  systemStateRows,
  scopeDisclosure,
  systemObservations,
  truncateDiscussionTitle,
  verifiedOutcomeRows
} = require('./lib/field-report/renderer');
const {
  inspectTaskResults,
  mergeTaskResultsFacts,
  snapshotFromFacts,
  taskResultsTemplate,
  validateTaskResults
} = require('./lib/field-report/task-results');
const fieldReportState = require('./lib/field-report/state');
const { acquireContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function expectThrow(fn, pattern, message) {
  let caught = null;
  try { fn(); } catch (error) { caught = error; }
  assert(caught, message || 'expected operation to fail');
  if (pattern) assert(pattern.test(caught.message), `unexpected error: ${caught.message}`);
  return caught;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function validAnswers(overrides = {}) {
  return {
    'project-context': 'An anonymized medium JavaScript repository tested for one week.',
    'report-relationship': 'first_party_maintainer',
    'keep-using': 'yes',
    'quick-summary': 'The routing evidence helped the agent choose the correct files.',
    'installation-method': 'Physical release asset',
    'workflow-fit': 'few_extra_steps',
    'agent-intervention': 'once_or_twice',
    'workflow-notes': 'The agent rechecked a stale module before editing it.',
    'main-scenario': 'A localized authorization change with objective tests.',
    'accuracy-change': 'slightly_improved',
    'accuracy-example': 'The first edit touched the expected module and all objective tests passed.',
    'accuracy-basis': 'objective_test_result',
    'accuracy-sample-count': 3,
    'speed-scope': 'first_useful_response',
    'response-speed-change': 'slightly_faster',
    'response-speed-percent': 12,
    'response-speed-basis': 'estimated_from_comparable_tasks',
    'response-speed-sample-count': 3,
    'response-speed-notes': 'Comparable tasks were used; this is explicitly an estimate.',
    'useful-parts': 'Trust routing and repair provenance.',
    'observed-results': 'Three comparable tasks completed without wrong-file edits.',
    'what-did-not-work': 'The first setup required one clarification.',
    'previous-workflow-comparison': 'Plain code search was simpler for trivial one-file edits.',
    'final-assessment': 'Useful for repositories with changing cross-module context.',
    'github-publication-permission': 'github_publication_allowed',
    'publication-permission': 'link_and_quote_with_attribution',
    ...overrides
  };
}


function englishTranslatedAnswers(source) {
  const fieldTypes = new Map(FIELDS.map((field) => [field.id, field.type]));
  const translated = {};
  for (const [id, raw] of Object.entries(source || {})) {
    const value = unwrap(raw);
    translated[id] = fieldTypes.get(id) === 'string'
      ? `English publication response for ${id}. The original meaning and uncertainty are preserved.`
      : value;
  }
  return translated;
}

function setupArtifacts(stateRoot) {
  ensureDir(stateRoot);
  writeJson(path.join(stateRoot, 'maintenance', 'trust_report.json'), {
    stale_artifacts_total: 3,
    modules: {
      trusted: [],
      suspect: ['auth', 'billing'],
      low_confidence: []
    }
  });
  writeJson(path.join(stateRoot, 'maintenance', 'repair_queue.json'), {
    queue: [
      { id: 'open', status: 'open' },
      { id: 'closed', status: 'closed' },
      { id: 'reopened', status: 'reopened' },
      { id: 'legacy-unmanaged' }
    ]
  });
  writeJson(path.join(stateRoot, 'maintenance', 'quality_report.json'), {
    quality_score: 97,
    status: 'usable_with_warnings',
    structural_status: 'usable_with_warnings',
    issues: [
      { id: 'current', status: 'open', severity: 'warning' },
      { id: 'closed', status: 'closed', severity: 'critical' }
    ]
  });
  const taskScope = {
    schema_version: 'knowledge-task-scope.v1',
    task_id: 'field-report-self-test-task',
    session_id: 'field-report-self-test-session',
    user_task: 'Exercise Field Report collector telemetry binding.',
    direct_modules: ['field-report'],
    direct_artifacts: ['.knowledge/tools/field-report.js'],
    dependency_modules: [],
    dependency_artifacts: []
  };
  taskScope.scope_hash = canonicalHash(taskScope);
  writeJson(path.join(stateRoot, 'maintenance', 'repair_opportunities.json'), {
    schema_version: 'knowledge-repair-opportunities.v1',
    generated_at: '2026-07-29T00:00:00.000Z',
    task_scope: taskScope,
    repair_on_touch: {
      configured_mode: 'scoped',
      effective_mode: 'scoped',
      effective_mode_source: 'built-in default',
      hard_safety: { edit_source_for_health: false }
    },
    global: { score: 93, status: 'healthy_with_debt' },
    task_readiness: {
      score: 78,
      status: 'needs_verification',
      relevant_findings_open: 1,
      relevant_findings_closed: 0
    },
    summary: {
      findings_considered: 2,
      findings_selected: 1,
      findings_deferred: 1
    },
    budget: {
      limits: { max_findings: 2, max_minutes: 5, max_context_percent: 10 },
      selected: { findings: 1, estimated_minutes: 2, estimated_context_percent: 4 },
      exhausted: false
    },
    opportunities: [
      {
        lifecycle_id: 'LC-0123456789abcdef',
        code: 'suspect_module',
        module_id: 'field-report',
        affected_artifacts: ['.knowledge/tools/field-report.js'],
        score_cost: 7,
        repair_class: 'verify_on_touch',
        required_checks: ['read_current_source', 'run_relevant_tests'],
        resolution_predicate: 'source_and_relevant_tests_confirm_claim',
        relation_to_current_task: 'direct_overlap',
        safe_during_current_task: true,
        requires_confirmation: false,
        decision_reason: 'verified_and_exact_finding_closed',
        status: 'repaired'
      },
      {
        lifecycle_id: 'LC-fedcba9876543210',
        code: 'suspect_module',
        module_id: 'unrelated',
        affected_artifacts: ['src/unrelated.js'],
        score_cost: 7,
        repair_class: 'verify_on_touch',
        required_checks: ['read_current_source', 'run_relevant_tests'],
        resolution_predicate: 'source_and_relevant_tests_confirm_claim',
        relation_to_current_task: 'no_overlap',
        safe_during_current_task: true,
        requires_confirmation: false,
        decision_reason: 'outside_task_scope',
        status: 'deferred'
      }
    ]
  });
  writeJson(path.join(stateRoot, 'maintenance', 'repair_on_touch_telemetry.json'), {
    schema_version: 'knowledge-repair-on-touch-telemetry.v1',
    generated_at: '2026-07-29T00:00:00.000Z',
    task_id: taskScope.task_id,
    session_id: taskScope.session_id,
    task_scope_sha256: taskScope.scope_hash,
    repair_on_touch_enabled: true,
    repair_mode: 'scoped',
    repair_findings_considered: 2,
    repair_findings_selected: 1,
    repair_findings_closed: 1,
    repair_findings_deferred: 1,
    repair_lifecycle_ids_considered: [
      'LC-0123456789abcdef',
      'LC-fedcba9876543210'
    ],
    repair_lifecycle_ids_closed: ['LC-0123456789abcdef'],
    repair_extra_wall_time_ms: 100,
    repair_extra_input_tokens: 10,
    repair_extra_output_tokens: 2,
    doctor_before: 93,
    doctor_after: 96,
    task_readiness_before: 78,
    task_readiness_after: 100,
    token_values: 'actual_only'
  });
  writeJson(path.join(stateRoot, 'maintenance', 'wiki_lint_report.json'), {
    quality_score: 96,
    status: 'usable_with_warnings',
    structural_status: 'usable_with_warnings'
  });
  writeJson(path.join(stateRoot, 'maps', 'wiki_graph.json'), {
    nodes: [{ id: 'a' }, { id: 'b' }],
    edges: [{ from: 'a', to: 'b' }],
    broken_edge_count: 0,
    broken_edges: []
  });
  writeJson(path.join(stateRoot, 'modules', 'module_registry.json'), {
    schema_version: 'knowledge-module-registry.v1',
    modules: [
      { module_id: 'app' },
      { module_id: 'functions' },
      { module_id: 'content' }
    ]
  });
  writeJson(path.join(stateRoot, 'search', 'index.json'), {
    documents: [{ id: 'a' }, { id: 'b' }, { id: 'c' }]
  });
  writeJson(path.join(stateRoot, 'sessions', 'agent-registry.json'), {
    sessions: [
      { id: '1', status: 'done', runtime: 'codex-spark' },
      { id: '2', status: 'completed', runtime: 'codex-spark' },
      { id: '3', status: 'running', runtime: 'codex' },
      { id: '4', status: 'waiting', runtime: 'codex' }
    ]
  });
  writeJson(path.join(stateRoot, 'maintenance', 'verification_receipts', 'index.json'), {
    schema_version: 'knowledge-verification-receipt-index.v1',
    receipts: [
      { receipt_id: `KVR-${'1'.repeat(64)}`, content_sha256: 'a'.repeat(64), path: 'maintenance/verification_receipts/receipt-one.json' },
      { receipt_id: `KVR-${'2'.repeat(64)}`, content_sha256: 'b'.repeat(64), path: 'maintenance/verification_receipts/receipt-two.json' }
    ]
  });
  writeJson(path.join(stateRoot, 'maintenance', 'field-report-task-check.json'), {
    schema_version: 'field-report-self-test-check.v1',
    status: 'pass',
    passed: 1,
    failed: 0,
    total: 1
  });
  writeJson(path.join(stateRoot, 'maintenance', 'flow-logs', 'release-one.json'), {
    flow: 'release'
  });
  writeJson(path.join(stateRoot, 'maintenance', 'flow-logs', 'scan-one.json'), {
    flow: 'scan'
  });
  ensureDir(path.join(stateRoot, 'maintenance'));
  fs.writeFileSync(path.join(stateRoot, 'maintenance', 'pr_summary.md'), '# PR summary\n');
}

function makeContext(systemRoot, stateRoot, overrides = {}) {
  return {
    systemRoot,
    targetRoot: overrides.targetRoot || stateRoot,
    projectKnowledgeRoot: overrides.projectKnowledgeRoot || stateRoot,
    stateRoot,
    repoId: overrides.repoId || `self-test-${path.basename(stateRoot)}`,
    mode: overrides.mode || 'repo',
    branch: overrides.branch || 'main',
    headSha: overrides.headSha || 'abcdef1234567890',
    workspaceId: overrides.workspaceId || null,
    teamRoot: overrides.teamRoot || null,
    agentId: overrides.agentId || 'field-report-self-test',
    warnings: []
  };
}

function git(root, args) {
  const result = childProcess.spawnSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr || result.stdout}`);
  }
  return String(result.stdout || '').trim();
}

function initCleanGitProject(root, files = {}) {
  ensureDir(root);
  const defaults = {
    '.gitignore': '.knowledge/\n',
    'README.md': '# Test project\n',
    'src/index.js': "module.exports = { ok: true };\n"
  };
  for (const [relative, body] of Object.entries({ ...defaults, ...files })) {
    const file = path.join(root, relative);
    ensureDir(path.dirname(file));
    fs.writeFileSync(file, body, 'utf8');
  }
  git(root, ['init', '-q']);
  git(root, ['config', 'user.name', 'Field Report Self Test']);
  git(root, ['config', 'user.email', 'field-report-self-test@example.invalid']);
  git(root, ['add', '.']);
  git(root, ['commit', '-qm', 'baseline']);
  return git(root, ['rev-parse', 'HEAD']);
}

function testAdapter(actor = 'tester-a', options = {}) {
  const remote = options.remote || {
    discussions: [],
    lookup_calls: 0,
    publish_calls: 0
  };
  return {
    testOnly: options.testOnly !== false,
    authenticate(payload) {
      return {
        actor,
        repository: options.repository || payload.repository,
        category_slug: options.category || payload.category_slug
      };
    },
    lookup(payload, authentication, lookupOptions = {}) {
      remote.lookup_calls += 1;
      if (options.lookupFail) {
        const error = new Error('injected lookup failure');
        error.code = 'publish_reconcile';
        throw error;
      }
      const marker = lookupOptions.idempotencyMarker || payload.idempotency_marker;
      return remote.discussions.find((discussion) =>
        discussion.body.includes(marker)
      ) || null;
    },
    publish(payload, authentication) {
      remote.publish_calls += 1;
      if (options.fail) {
        const error = new Error('injected failure');
        error.code = 'publish_network';
        throw error;
      }
      const result = {
        discussion_id: options.id || 'discussion-1',
        url: options.url || 'https://example.test/discussions/1',
        actor: options.resultActor || authentication.actor,
        repository: payload.repository,
        category_slug: payload.category_slug,
        title: payload.title,
        body: payload.body,
        ...(options.resultExtras || {})
      };
      remote.discussions.push(result);
      if (options.outcomeUnknownAfterCreate && !remote.outcome_lost) {
        remote.outcome_lost = true;
        const error = new Error('response lost after remote success');
        error.code = 'publish_outcome_unknown';
        throw error;
      }
      return result;
    }
  };
}

function fileSha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function validTaskResults(context, reportId, overrides = {}) {
  const evidencePath = path.join(context.stateRoot, 'maintenance', 'field-report-task-check.json');
  const base = {
    schema_version: 'knowledge-field-report-task-results.v1',
    report_id: reportId,
    task: {
      title: 'Verify a scoped repository change',
      outcome: 'pass',
      summary: 'The requested change and its evidence-backed verification completed successfully.'
    },
    results: [
      {
        id: 'objective-tests',
        label: 'Objective tests',
        category: 'tests',
        status: 'pass',
        public_summary: 'The attached test report completed without failures.',
        interpretation: 'This verifies the stated test result; it does not prove model accuracy or speed.',
        public: true,
        metrics: { passed: 1, failed: 0, total: 1 },
        evidence: {
          kind: 'automated_report',
          label: 'Objective test report',
          root_kind: 'state',
          path: 'maintenance/field-report-task-check.json',
          sha256: fileSha256(evidencePath)
        }
      }
    ]
  };
  return {
    ...base,
    ...overrides,
    task: { ...base.task, ...(overrides.task || {}) },
    results: overrides.results || base.results
  };
}

function attachTaskResults(context, reportId, overrides = {}) {
  return run(['results-ingest', `--report-id=${reportId}`], {
    context,
    taskResults: validTaskResults(context, reportId, overrides)
  });
}

function createRendered(context, answers = validAnswers(), startFlags = []) {
  const started = run(['start', '--new', ...startFlags], { context });
  run(['ingest', `--report-id=${started.report_id}`], { context, answers });
  attachTaskResults(context, started.report_id);
  const rendered = run(['render', `--report-id=${started.report_id}`], { context });
  return { reportId: started.report_id, rendered };
}

function createApproved(context, answers = validAnswers(), startFlags = [], actor = 'tester-a') {
  const result = createRendered(context, answers, startFlags);
  run([
    'approve',
    `--report-id=${result.reportId}`,
    '--yes',
    `--tester-actor=${actor}`
  ], { context });
  return result;
}

function createTranslationReady(context, translatorActor = 'translation-transaction') {
  const started = run([
    'start',
    '--new',
    '--language=es',
    '--public-language=en'
  ], { context });
  run(['ingest', `--report-id=${started.report_id}`], {
    context,
    answers: validAnswers({
      'quick-summary': 'La evidencia de ruta ayudó durante una tarea comparable.',
      'what-did-not-work': 'Una tarea ambigua todavía necesitó una aclaración.'
    })
  });
  const exported = run([
    'translation-export',
    `--report-id=${started.report_id}`
  ], { context });
  const translated = englishTranslatedAnswers(exported.original_answers);
  run(['translation-ingest', `--report-id=${started.report_id}`], {
    context,
    translation: {
      original_hash: exported.original_hash,
      exported_answers_hash: exported.exported_answers_hash,
      translator: {
        provider: 'test-runtime',
        model: 'junior-test-model',
        actor: translatorActor
      },
      attestations: {
        adds_no_facts: true,
        negative_answers_not_softened: true,
        uncertainty_preserved: true
      },
      translated_answers: translated
    }
  });
  attachTaskResults(context, started.report_id);
  return started.report_id;
}

function copyInstalledFile(systemRoot, installedRoot, relative) {
  const source = path.join(systemRoot, relative);
  const target = path.join(installedRoot, relative);
  ensureDir(path.dirname(target));
  fs.copyFileSync(source, target);
}

function main() {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-field-report-v2-'));
  const systemRoot = path.resolve(__dirname, '..');
  const projectRoot = path.join(temporaryRoot, 'project');
  const stateRoot = path.join(projectRoot, '.knowledge');
  setupArtifacts(stateRoot);
  writeJson(path.join(projectRoot, 'package.json'), { name: 'fixture' });
  const context = makeContext(systemRoot, stateRoot, { targetRoot: projectRoot });
  const checks = [];
  const check = (name, fn) => {
    fn();
    checks.push(name);
  };
  const previousCi = process.env.CI;

  try {
    check('contract: canonical schema and optional bundled GitHub form agree bidirectionally', () => {
      const result = validateContract(systemRoot);
      assert(result.valid, JSON.stringify(result));
      if (result.form_status === 'validated') {
        assert(result.canonical_form_match, JSON.stringify(result));
        assert(result.missing.length === 0 && result.unknown.length === 0, 'form field parity');
      } else {
        assert(result.form_status === 'form_not_bundled', JSON.stringify(result));
        assert(!fs.existsSync(path.join(systemRoot, '.github', 'DISCUSSION_TEMPLATE', 'field-reports.yml')), 'bundled form was not validated');
      }
    });

    check('contract: schema projects required CLI questions', () => {
      const expected = DEFAULT_SCHEMA.fields
        .filter((field) => field.required && field.agent_prompt)
        .map((field) => field.id)
        .sort();
      const actual = missingQuestions({}).map((question) => question.id).sort();
      assert(JSON.stringify(actual) === JSON.stringify(expected), 'CLI question projection drift');
    });

    check('contract: schema and GitHub form required flags are identical', () => {
      for (const field of DEFAULT_SCHEMA.fields.filter((item) => item.github_form)) {
        assert(
          field.required === field.github_form.required,
          `${field.id} required parity`
        );
      }
    });

    check('contract: project context is required but auto-collected version is not asked', () => {
      const questions = missingQuestions({}).map((question) => question.id);
      assert(questions.includes('project-context'), 'project-context must be required');
      assert(!questions.includes('knowledge-version'), 'auto-collected version was asked');
      const incomplete = validAnswers();
      delete incomplete['project-context'];
      assert(!validateAnswers(incomplete).valid, 'project-context validation');
    });

    check('contract: public output language is fixed to English', () => {
      assert(PUBLIC_LANGUAGE === 'en', PUBLIC_LANGUAGE);
      assert(normalizePublicLanguage('en-US') === 'en', 'English locale canonicalization');
      assert(!translationRequired('en-US', 'en'), 'English source should not require translation');
      assert(translationRequired('ru-RU', 'en'), 'non-English source should require translation');
      expectThrow(
        () => normalizePublicLanguage('ru-RU'),
        /fixed to English/,
        'non-English public output was accepted'
      );
    });

    check('contract: report relationship is required and has deterministic disclosures', () => {
      const incomplete = validAnswers();
      delete incomplete['report-relationship'];
      const result = validateAnswers(incomplete);
      assert(!result.valid && result.errors.some((error) => error.includes('report-relationship')), 'relationship was optional');
      for (const relationship of [
        'first_party_maintainer',
        'independent_user',
        'internal_qa',
        'controlled_comparison'
      ]) {
        const answers = validAnswers({ 'report-relationship': relationship });
        assert(validateAnswers(answers).valid, relationship);
        const disclosure = relationshipDisclosure(answers);
        assert(typeof disclosure === 'string' && disclosure.length > 40, relationship);
      }
      assert(
        relationshipDisclosure(validAnswers()).includes('first-party maintainer dogfooding'),
        'maintainer disclosure missing'
      );
    });

    check('contract: every field has renderer and policy mappings', () => {
      for (const field of DEFAULT_SCHEMA.fields) {
        assert(field.renderer?.section && Number.isFinite(field.renderer?.order), field.id);
        assert(field.public_section && field.redaction_policy && field.omission_policy, field.id);
      }
    });

    check('contract: GitHub form uses labels rather than raw enum IDs', () => {
      const form = generateGithubForm(DEFAULT_SCHEMA);
      assert(form.includes('Clearly improved'), 'human label absent');
      assert(!form.includes('        - "clearly_improved"'), 'raw enum leaked into form options');
      assert(form.includes('Starting with `.knowledge` 3.3.0'), 'wrong availability version');
    });

    check('contract: supported 3.2.11 answer aliases migrate', () => {
      const legacy = validAnswers();
      delete legacy['accuracy-example'];
      delete legacy['response-speed-change'];
      delete legacy['github-publication-permission'];
      delete legacy['publication-permission'];
      legacy['accuracy-evidence'] = 'Legacy concrete evidence.';
      legacy['response-speed'] = 'slightly_faster';
      legacy.publication_permission = 'github_publication_allowed';
      legacy.external_reuse_permission = 'link_and_quote_with_attribution';
      const result = validateAnswers(legacy);
      assert(result.valid && result.migrations.length === 4, JSON.stringify(result.errors));
    });

    check('state machine: command handlers cannot bypass legal transitions', () => {
      const commandSource = fs.readFileSync(path.join(systemRoot, 'tools', 'field-report.js'), 'utf8');
      assert(!/\bmanifest\.status\s*=(?!=)/.test(commandSource), 'command handler directly assigns manifest.status');
      expectThrow(
        () => fieldReportState.transition({ status: 'published' }, 'draft_ready'),
        /Illegal Field Report transition/,
        'published report transitioned back to draft'
      );
      const retry = { status: 'publish_failed' };
      fieldReportState.transition(retry, 'published');
      assert(retry.status === 'published', 'successful retry could not enter published state');
    });

    check('state: report IDs and publication targets are validated before filesystem mutation', () => {
      expectThrow(
        () => fieldReportState.paths(context, '../../outside'),
        /Invalid Field Report ID/,
        'report ID traversal'
      );
      const reportsRoot = fieldReportState.reportRoot(context);
      const before = fs.existsSync(reportsRoot)
        ? fs.readdirSync(reportsRoot).filter((name) =>
          fieldReportState.REPORT_ID_PATTERN.test(name)).length
        : 0;
      expectThrow(() => run([
        'start',
        '--new',
        '--discussion-repo=owner/repo;calc',
        '--discussion-category=field-reports'
      ], { context }), /safe GitHub/, 'unsafe repository target');
      const after = fs.existsSync(reportsRoot)
        ? fs.readdirSync(reportsRoot).filter((name) =>
          fieldReportState.REPORT_ID_PATTERN.test(name)).length
        : 0;
      assert(after === before, 'invalid target left a report directory');
    });

    check('state: non-English public language is rejected before report creation', () => {
      const reportsRoot = fieldReportState.reportRoot(context);
      const before = fs.existsSync(reportsRoot)
        ? fs.readdirSync(reportsRoot).filter((name) => fieldReportState.REPORT_ID_PATTERN.test(name)).length
        : 0;
      expectThrow(
        () => run(['start', '--new', '--language=ru-RU', '--public-language=ru-RU'], { context }),
        /fixed to English/,
        'non-English public language was accepted'
      );
      const after = fs.existsSync(reportsRoot)
        ? fs.readdirSync(reportsRoot).filter((name) => fieldReportState.REPORT_ID_PATTERN.test(name)).length
        : 0;
      assert(after === before, 'rejected public language left report state');
    });

    check('state: mutable legacy reports migrate to the English publication contract', () => {
      const started = run(['start', '--new', '--language=ru-RU'], { context });
      run(['ingest', `--report-id=${started.report_id}`], {
        context,
        answers: validAnswers({
          'quick-summary': 'Тестовый итог на русском языке.',
          'what-did-not-work': 'Потребовалась дополнительная проверка.'
        })
      });
      const reportPaths = fieldReportState.paths(context, started.report_id);
      const legacy = JSON.parse(fs.readFileSync(reportPaths.manifest, 'utf8'));
      legacy.contract_version = '2.1.0';
      legacy.public_language = 'ru-RU';
      legacy.status = 'draft_ready';
      legacy.translation = {
        status: 'translation_not_required',
        source_language: 'ru-RU',
        target_language: 'ru-RU',
        original_hash: canonicalHash(JSON.parse(fs.readFileSync(reportPaths.answers_original, 'utf8'))),
        translated_hash: null,
        translator: null,
        reviewer: null,
        approved_by_tester: false,
        approved_at: null
      };
      legacy.approval = {
        approved_by_tester: true,
        approved_by: 'tester-a',
        approved_at: '2026-01-01T00:00:00.000Z',
        content_hash: 'a'.repeat(64)
      };
      writeJson(reportPaths.manifest, legacy);
      const status = run(['status', `--report-id=${started.report_id}`], { context });
      const migrated = JSON.parse(fs.readFileSync(reportPaths.manifest, 'utf8'));
      assert(migrated.contract_version === DEFAULT_SCHEMA.contract_version, migrated.contract_version);
      assert(migrated.public_language === 'en', migrated.public_language);
      assert(migrated.translation.status === 'translation_required', migrated.translation.status);
      assert(migrated.translation.target_language === 'en', migrated.translation.target_language);
      assert(migrated.status === 'translation_required', migrated.status);
      assert(migrated.approval.approved_by_tester === false, JSON.stringify(migrated.approval));
      assert(status.translation_status === 'translation_required', JSON.stringify(status));
    });

    check('accuracy: categorical assessment requires example and basis', () => {
      const incomplete = validAnswers();
      delete incomplete['accuracy-example'];
      assert(!validateAnswers(incomplete).valid, 'accuracy example must be required');
      assert(!Object.keys(incomplete).some((key) => key.includes('accuracy-percent')), 'percent field');
    });

    check('speed: positive percent cannot mean slower', () => {
      const result = validateAnswers(validAnswers({
        'response-speed-change': 'slightly_slower',
        'response-speed-percent': 20
      }));
      assert(!result.valid && result.errors.some((error) => error.includes('positive')), 'sign gate');
    });

    check('speed: negative percent cannot mean faster', () => {
      const result = validateAnswers(validAnswers({
        'response-speed-change': 'slightly_faster',
        'response-speed-percent': -15
      }));
      assert(!result.valid && result.errors.some((error) => error.includes('negative')), 'sign gate');
    });

    check('speed: measured basis requires raw durations and sample count', () => {
      const missing = validateAnswers(validAnswers({
        'response-speed-basis': 'measured',
        'response-speed-percent': 20
      }));
      assert(!missing.valid && missing.errors.some((error) => error.includes('raw durations')), 'raw');
      const valid = validateAnswers(validAnswers({
        'response-speed-basis': 'measured',
        'response-speed-change': 'slightly_faster',
        'response-speed-percent': 20,
        'response-speed-sample-count': 2,
        'baseline-duration-ms': 1000,
        'knowledge-duration-ms': 800
      }));
      assert(valid.valid, valid.errors.join('; '));
    });

    check('accuracy: not-enough-data basis cannot support an improvement claim', () => {
      const contradictory = validateAnswers(validAnswers({
        'accuracy-change': 'clearly_improved',
        'accuracy-basis': 'not_enough_data',
        'accuracy-sample-count': null
      }));
      assert(
        !contradictory.valid &&
        contradictory.errors.some((error) => error.includes('not_enough_data')),
        'contradictory accuracy claim was accepted'
      );
      const honest = validateAnswers(validAnswers({
        'accuracy-change': 'not_enough_evidence',
        'accuracy-basis': 'not_enough_data',
        'accuracy-sample-count': null
      }));
      assert(honest.valid, honest.errors.join('; '));
    });

    check('speed: no-clear-change cannot hide a material measured change', () => {
      const contradictory = validateAnswers(validAnswers({
        'response-speed-change': 'no_clear_change',
        'response-speed-basis': 'measured',
        'response-speed-percent': 99.9,
        'response-speed-sample-count': 2,
        'baseline-duration-ms': 1000,
        'knowledge-duration-ms': 1
      }));
      assert(
        !contradictory.valid &&
        contradictory.errors.some((error) => error.includes('no_clear_change')),
        'contradictory measured speed claim was accepted'
      );
    });

    check('speed: zero percent and equal measured durations cannot claim faster or slower', () => {
      const zeroPercent = validateAnswers(validAnswers({
        'response-speed-change': 'slightly_faster',
        'response-speed-percent': 0
      }));
      assert(
        !zeroPercent.valid &&
        zeroPercent.errors.some((error) => error.includes('zero response-speed-percent')),
        'zero percent speed claim was accepted'
      );
      const equalDurations = validateAnswers(validAnswers({
        'response-speed-change': 'slightly_faster',
        'response-speed-basis': 'measured',
        'response-speed-percent': 0,
        'response-speed-sample-count': 2,
        'baseline-duration-ms': 1000,
        'knowledge-duration-ms': 1000
      }));
      assert(
        !equalDurations.valid &&
        equalDurations.errors.some((error) => error.includes('equal measured durations')),
        'equal measured durations were accepted as faster'
      );
    });

    check('contract: manual GitHub form can supply measured raw durations', () => {
      const form = generateGithubForm(DEFAULT_SCHEMA);
      assert(form.includes('id: baseline-duration-ms'), 'baseline duration missing from form');
      assert(form.includes('id: knowledge-duration-ms'), '.knowledge duration missing from form');
    });

    const facts = collect(context);
    const packageVersion = JSON.parse(
      fs.readFileSync(path.join(systemRoot, 'package.json'), 'utf8')
    ).version;

    check('collector: version comes from .knowledge/package.json', () => {
      assert(facts.values.knowledge_version.value === packageVersion, 'version source');
      assert(facts.values.knowledge_version.source === '.knowledge/package.json', 'version path');
    });


    check('collector: producer-compatible repair telemetry remains observable', () => {
      assert(facts.values.repair_on_touch_enabled.value === true, JSON.stringify(facts.values.repair_on_touch_enabled));
      assert(facts.values.repair_mode.value === 'scoped', JSON.stringify(facts.values.repair_mode));
      assert(facts.values.repair_findings_considered.value === 2, JSON.stringify(facts.values.repair_findings_considered));
      assert(facts.values.repair_findings_closed.value === 1, JSON.stringify(facts.values.repair_findings_closed));
      assert(!facts.warnings.some((warning) => warning.includes('repair_on_touch_telemetry.json')), facts.warnings.join('; '));
    });

    check('collector: stale and suspect paths use current trust schema', () => {
      assert(facts.values.stale_artifacts_total.value === 3, 'stale count');
      assert(facts.values.modules_suspect.value === 2, 'suspect count');
      assert(facts.values.modules_low_confidence.value === 0, 'low-confidence count');
      assert(facts.values.modules_needing_recheck.value === 2, 'recheck count');
    });

    check('collector: trust buckets stay distinct and recheck IDs are unique', () => {
      const trustState = path.join(temporaryRoot, 'distinct-trust-buckets');
      setupArtifacts(trustState);
      writeJson(path.join(trustState, 'maintenance', 'trust_report.json'), {
        stale_artifacts_total: 7,
        modules: {
          suspect: ['root', 'root'],
          low_confidence: ['src', 'root'],
          needs_recheck: ['docs', 'src']
        },
        module_statuses: [
          { module_id: 'root', trust_status: 'suspect' },
          { module_id: 'src', trust_status: 'low_confidence' },
          { module_id: 'docs', trust_status: 'needs_recheck' },
          { module_id: 'root', trust_status: 'suspect' }
        ]
      });
      const distinct = collect(makeContext(systemRoot, trustState));
      assert(distinct.values.stale_artifacts_total.value === 7, 'stale count');
      assert(distinct.values.modules_suspect.value === 1, 'suspect was merged');
      assert(distinct.values.modules_low_confidence.value === 2, 'low-confidence was merged');
      assert(distinct.values.modules_needing_recheck.value === 3, 'recheck IDs were not unique');
      for (const id of [
        'stale_artifacts_total',
        'modules_suspect',
        'modules_low_confidence',
        'modules_needing_recheck'
      ]) assert(distinct.values[id].kind === 'observed', `${id} is unavailable`);
    });

    check('collector: repair statuses remain separate', () => {
      assert(facts.values.repair_open.value === 1, 'open');
      assert(facts.values.repair_closed.value === 1, 'closed');
      assert(facts.values.repair_reopened.value === 1, 'reopened');
      assert(facts.values.repair_unmanaged.value === 1, 'unmanaged');
    });

    check('collector: done and completed both count as completed', () => {
      assert(facts.values.completed_sessions.value === 2, 'completed');
      assert(facts.values.running_sessions.value === 1, 'running');
      assert(facts.values.waiting_sessions.value === 1, 'waiting');
    });

    check('collector: runtimes, release flows, and PR summaries are captured', () => {
      assert(facts.values.agent_runtimes.value.join(',') === 'codex,codex-spark', 'runtimes');
      assert(facts.values.release_flow_count.value === 1, 'release flows');
      assert(facts.values.pr_summary_count.value === 1, 'PR summaries');
    });

    check('collector: unavailable facts are null and not observed', () => {
      const emptyState = path.join(temporaryRoot, 'missing-state');
      ensureDir(emptyState);
      const missingFacts = collect(makeContext(systemRoot, emptyState));
      assert(missingFacts.values.completed_sessions.kind === 'unavailable', 'kind');
      assert(missingFacts.values.completed_sessions.value === null, 'null');
      assert(missingFacts.facts_unavailable > 0, 'unavailable count');
      const observed = Object.values(missingFacts.values)
        .filter((item) => item.kind === 'observed').length;
      assert(observed === missingFacts.facts_observed, 'observed count');
    });

    check('collector: parseable registry with non-array sessions is unavailable, not zero', () => {
      const malformedState = path.join(temporaryRoot, 'malformed-registry');
      setupArtifacts(malformedState);
      writeJson(path.join(malformedState, 'sessions', 'agent-registry.json'), {
        sessions: { first: { status: 'done' } }
      });
      const malformed = collect(makeContext(systemRoot, malformedState));
      for (const id of [
        'agent_sessions',
        'completed_sessions',
        'running_sessions',
        'waiting_sessions',
        'agent_runtimes'
      ]) {
        assert(malformed.values[id].kind === 'unavailable', `${id} kind`);
        assert(malformed.values[id].value === null, `${id} value`);
      }
      assert(
        malformed.warnings.some((item) => item.includes('semantically invalid artifact')),
        'semantic warning'
      );
    });

    check('collector: unknown registry status makes dependent session facts unavailable', () => {
      const malformedState = path.join(temporaryRoot, 'unknown-registry-status');
      setupArtifacts(malformedState);
      writeJson(path.join(malformedState, 'sessions', 'agent-registry.json'), {
        sessions: [{ id: 'one', status: 'probably-finished' }]
      });
      const malformed = collect(makeContext(systemRoot, malformedState));
      for (const id of [
        'agent_sessions',
        'completed_sessions',
        'running_sessions',
        'waiting_sessions',
        'agent_runtimes'
      ]) {
        assert(malformed.values[id].kind === 'unavailable', `${id} kind`);
        assert(malformed.values[id].value === null, `${id} value`);
      }
    });

    check('collector: invalid repair queue enum makes all repair counts unavailable', () => {
      const malformedState = path.join(temporaryRoot, 'malformed-repair-queue');
      setupArtifacts(malformedState);
      writeJson(path.join(malformedState, 'maintenance', 'repair_queue.json'), {
        queue: [{ id: 'bad', status: 'definitely_fixed' }]
      });
      const malformed = collect(makeContext(systemRoot, malformedState));
      for (const id of [
        'repair_open',
        'repair_closed',
        'repair_reopened',
        'repair_unmanaged'
      ]) {
        assert(malformed.values[id].kind === 'unavailable', `${id} kind`);
        assert(malformed.values[id].value === null, `${id} value`);
      }
    });

    check('collector: malformed telemetry types and counts are unavailable and secret-safe', () => {
      const malformedState = path.join(temporaryRoot, 'malformed-telemetry');
      setupArtifacts(malformedState);
      const privateMode = ['', 'opt', 'private-customer', 'mode'].join('/');
      writeJson(path.join(
        malformedState,
        'maintenance',
        'repair_on_touch_telemetry.json'
      ), {
        schema_version: 'knowledge-repair-on-touch-telemetry.v1',
        repair_on_touch_enabled: 'true',
        repair_mode: privateMode,
        repair_findings_considered: 1,
        repair_findings_selected: 2,
        repair_findings_closed: -1,
        repair_findings_deferred: 1,
        repair_extra_wall_time_ms: -5,
        repair_extra_input_tokens: '10',
        repair_extra_output_tokens: null,
        doctor_before: 101,
        doctor_after: 90,
        task_readiness_before: 80,
        task_readiness_after: 90,
        token_values: 'estimated'
      });
      const malformed = collect(makeContext(systemRoot, malformedState));
      for (const id of [
        'repair_on_touch_enabled',
        'repair_mode',
        'repair_findings_considered',
        'repair_findings_selected',
        'repair_findings_closed',
        'repair_findings_deferred',
        'repair_extra_wall_time_ms',
        'repair_extra_input_tokens',
        'repair_extra_output_tokens'
      ]) {
        assert(malformed.values[id].kind === 'unavailable', `${id} kind`);
        assert(malformed.values[id].value === null, `${id} value`);
      }
      assert(
        malformed.values.knowledge_version.kind === 'observed',
        'unrelated fact was invalidated'
      );
      assert(!malformed.warnings.join('\n').includes(privateMode), 'private value leaked');
    });

    check('collector: parseable malformed quality, trust, graph, package, and receipt state is unavailable', () => {
      const malformedState = path.join(temporaryRoot, 'malformed-core-facts');
      const malformedSystem = path.join(temporaryRoot, 'malformed-system');
      setupArtifacts(malformedState);
      writeJson(path.join(malformedSystem, 'package.json'), { version: -7 });
      writeJson(path.join(malformedState, 'maintenance', 'quality_report.json'), {
        quality_score: '100'
      });
      writeJson(path.join(malformedState, 'maintenance', 'trust_report.json'), {
        stale_artifacts_total: -1,
        modules_suspect: 'many'
      });
      writeJson(path.join(malformedState, 'maps', 'wiki_graph.json'), {
        nodes: 'two',
        edges: -3
      });
      writeJson(
        path.join(malformedState, 'maintenance', 'verification_receipts', 'index.json'),
        {
          schema_version: 'knowledge-verification-receipt-index.v1',
          receipts: [{ receipt_id: 'made-up', path: '../../outside' }]
        }
      );
      const malformed = collect(makeContext(malformedSystem, malformedState));
      for (const id of [
        'knowledge_version',
        'doctor_score',
        'stale_artifacts_total',
        'modules_suspect',
        'wiki_nodes',
        'wiki_edges',
        'verification_receipts'
      ]) {
        assert(malformed.values[id].kind === 'unavailable', `${id} kind`);
        assert(malformed.values[id].value === null, `${id} value`);
      }
      assert(
        malformed.warnings.filter((item) => item.includes('semantically invalid artifact')).length >= 5,
        'semantic warnings missing'
      );
    });

    check('collector: canonical status whitespace and case are counted consistently', () => {
      const statusState = path.join(temporaryRoot, 'status-normalization');
      setupArtifacts(statusState);
      writeJson(path.join(statusState, 'sessions', 'agent-registry.json'), {
        sessions: [
          { status: ' Done ' },
          { status: 'COMPLETED' },
          { status: ' Running ' },
          { status: ' Waiting ' }
        ]
      });
      writeJson(path.join(statusState, 'maintenance', 'repair_queue.json'), {
        queue: [
          { status: ' Open ' },
          { status: 'CLOSED' },
          { status: ' Reopened ' }
        ]
      });
      const normalized = collect(makeContext(systemRoot, statusState));
      assert(normalized.values.completed_sessions.value === 2, 'completed normalization');
      assert(normalized.values.running_sessions.value === 1, 'running normalization');
      assert(normalized.values.waiting_sessions.value === 1, 'waiting normalization');
      assert(normalized.values.repair_open.value === 1, 'repair open normalization');
      assert(normalized.values.repair_closed.value === 1, 'repair closed normalization');
      assert(normalized.values.repair_reopened.value === 1, 'repair reopened normalization');
    });

    check('collector: contradictory trust aliases are unavailable instead of precedence-picked', () => {
      const trustState = path.join(temporaryRoot, 'contradictory-trust');
      setupArtifacts(trustState);
      writeJson(path.join(trustState, 'maintenance', 'trust_report.json'), {
        stale_artifacts_total: 9,
        stale_items: [{ id: 'one' }],
        modules: { suspect: ['a'] },
        modules_suspect: 4
      });
      const contradictory = collect(makeContext(systemRoot, trustState));
      assert(contradictory.values.stale_artifacts_total.kind === 'unavailable', 'stale trust');
      assert(contradictory.values.modules_suspect.kind === 'unavailable', 'suspect trust');
    });

    check('collector: Repair telemetry mode and task-scope contradictions fail closed', () => {
      for (const [name, mutate] of [
        ['disabled-scoped', (value) => {
          value.repair_on_touch_enabled = false;
          value.repair_mode = 'scoped';
        }],
        ['enabled-off-work', (value) => {
          value.repair_on_touch_enabled = true;
          value.repair_mode = 'off';
        }],
        ['wrong-task', (value) => {
          value.task_id = 'unrelated-task';
        }]
      ]) {
        const telemetryState = path.join(temporaryRoot, `telemetry-${name}`);
        setupArtifacts(telemetryState);
        const telemetryPath = path.join(
          telemetryState,
          'maintenance',
          'repair_on_touch_telemetry.json'
        );
        const telemetry = JSON.parse(fs.readFileSync(telemetryPath, 'utf8'));
        mutate(telemetry);
        writeJson(telemetryPath, telemetry);
        const result = collect(makeContext(systemRoot, telemetryState));
        for (const id of [
          'repair_on_touch_enabled',
          'repair_mode',
          'repair_findings_considered',
          'repair_findings_closed'
        ]) {
          assert(result.values[id].kind === 'unavailable', `${name}: ${id}`);
        }
      }
    });

    check('collector: enabled flag must match off mode even with zero recorded work', () => {
      const telemetryState = path.join(temporaryRoot, 'telemetry-enabled-off-zero');
      setupArtifacts(telemetryState);
      const telemetryPath = path.join(
        telemetryState,
        'maintenance',
        'repair_on_touch_telemetry.json'
      );
      const opportunitiesPath = path.join(
        telemetryState,
        'maintenance',
        'repair_opportunities.json'
      );
      const telemetry = JSON.parse(fs.readFileSync(telemetryPath, 'utf8'));
      Object.assign(telemetry, {
        repair_on_touch_enabled: true,
        repair_mode: 'off',
        repair_findings_considered: 0,
        repair_findings_selected: 0,
        repair_findings_closed: 0,
        repair_findings_deferred: 0,
        repair_lifecycle_ids_considered: [],
        repair_lifecycle_ids_closed: [],
        repair_extra_wall_time_ms: 0,
        repair_extra_input_tokens: 0,
        repair_extra_output_tokens: 0
      });
      const opportunities = JSON.parse(fs.readFileSync(opportunitiesPath, 'utf8'));
      opportunities.repair_on_touch.effective_mode = 'off';
      opportunities.opportunities = [];
      writeJson(telemetryPath, telemetry);
      writeJson(opportunitiesPath, opportunities);
      const result = collect(makeContext(systemRoot, telemetryState));
      assert(result.values.repair_on_touch_enabled.kind === 'unavailable', 'enabled/off accepted');
      assert(result.values.repair_mode.kind === 'unavailable', 'off mode accepted');
    });

    check('collector: telemetry must match the current opportunity outcomes exactly', () => {
      const telemetryState = path.join(temporaryRoot, 'telemetry-opportunity-mismatch');
      setupArtifacts(telemetryState);
      const opportunitiesPath = path.join(
        telemetryState,
        'maintenance',
        'repair_opportunities.json'
      );
      const opportunities = JSON.parse(fs.readFileSync(opportunitiesPath, 'utf8'));
      opportunities.opportunities[0].status = 'selected';
      writeJson(opportunitiesPath, opportunities);
      const result = collect(makeContext(systemRoot, telemetryState));
      for (const id of [
        'repair_findings_considered',
        'repair_findings_selected',
        'repair_findings_closed',
        'repair_findings_deferred'
      ]) {
        assert(result.values[id].kind === 'unavailable', `${id} survived outcome mismatch`);
      }
    });

    check('collector: forged opportunity schema or task-scope identity is unavailable', () => {
      for (const [name, mutate] of [
        ['schema', (value) => { value.schema_version = 'forged-contract.v0'; }],
        ['scope', (value) => { delete value.task_scope.scope_hash; }]
      ]) {
        const forgedState = path.join(temporaryRoot, `forged-opportunities-${name}`);
        setupArtifacts(forgedState);
        const opportunitiesPath = path.join(
          forgedState,
          'maintenance',
          'repair_opportunities.json'
        );
        const opportunities = JSON.parse(fs.readFileSync(opportunitiesPath, 'utf8'));
        mutate(opportunities);
        writeJson(opportunitiesPath, opportunities);
        const result = collect(makeContext(systemRoot, forgedState));
        for (const id of [
          'repair_on_touch_enabled',
          'repair_mode',
          'repair_findings_considered',
          'repair_findings_selected',
          'repair_findings_closed',
          'repair_findings_deferred'
        ]) {
          assert(result.values[id].kind === 'unavailable', `${name}: forged ${id} observed`);
          assert(result.values[id].value === null, `${name}: forged ${id} retained a value`);
        }
      }
    });

    check('collector: every fact has typed provenance and a safe relative source', () => {
      for (const item of Object.values(facts.values)) {
        for (const key of [
          'value', 'kind', 'source', 'schema_path', 'collected_at', 'confidence', 'warning'
        ]) assert(Object.prototype.hasOwnProperty.call(item, key), key);
        assert(!path.isAbsolute(item.source) && !item.source.includes('..'), item.source);
      }
    });

    check('collector: repository profile excludes generated, system, dependency, and secret-like paths', () => {
      for (const excluded of [
        '.knowledge/maintenance/report.json',
        '.git/config',
        'node_modules/pkg/index.js',
        'dist/app.js',
        'coverage/report.json',
        '.env.local',
        'config/client-secret.json',
        'credentials.prod.json'
      ]) {
        assert(repositoryProfilePathExcluded(excluded), `not excluded: ${excluded}`);
      }
      for (const included of [
        'src/app.js',
        'docs/README.md',
        '.env.example',
        'config/public-settings.json'
      ]) {
        assert(!repositoryProfilePathExcluded(included), `falsely excluded: ${included}`);
      }
    });

    check('collector: Git repository profile reports tracked and source content without reading excluded files', () => {
      const root = path.join(temporaryRoot, 'repository-profile-git');
      const files = {
        'package.json': '{"name":"profile-fixture"}\n',
        'src/app.js': 'module.exports = 1;\n',
        'scripts/build.ps1': 'Write-Output build\n',
        'docs/README.md': '# Fixture\n',
        '.env.local': 'TOP_SECRET_PROFILE_VALUE=never-read\n',
        '.knowledge/runtime.json': '{"private":true}\n',
        'dist/bundle.js': 'generated\n',
        'node_modules/pkg/index.js': 'dependency\n'
      };
      for (const [relative, body] of Object.entries(files)) {
        const file = path.join(root, ...relative.split('/'));
        ensureDir(path.dirname(file));
        fs.writeFileSync(file, body, 'utf8');
      }
      for (const args of [
        ['init'],
        ['config', 'user.name', 'Field Report Test'],
        ['config', 'user.email', 'field-report@example.invalid'],
        ['add', '-f', '.'],
        ['commit', '-m', 'profile fixture']
      ]) {
        const result = childProcess.spawnSync('git', args, { cwd: root, encoding: 'utf8' });
        assert(result.status === 0, `${args.join(' ')}: ${result.stderr}`);
      }
      fs.appendFileSync(path.join(root, 'src', 'app.js'), '// dirty snapshot\n');
      const warnings = [];
      const profile = collectRepositoryProfile(root, warnings);
      assert(profile.available && profile.basis === 'git_index_worktree', JSON.stringify(profile));
      assert(profile.tracked_files === 4, JSON.stringify(profile));
      assert(profile.source_files === 2, JSON.stringify(profile));
      assert(profile.excluded_files === 4, JSON.stringify(profile));
      assert(profile.dirty === true, JSON.stringify(profile));
      assert(profile.tracked_bytes > profile.source_bytes && profile.source_bytes > 0, JSON.stringify(profile));
      assert(!JSON.stringify(profile).includes('TOP_SECRET_PROFILE_VALUE'), 'secret content entered profile');
      assert(warnings.length === 0, warnings.join('; '));
    });

    check('collector: non-Git repository profile uses a filtered fallback', () => {
      const root = path.join(temporaryRoot, 'repository-profile-fallback');
      ensureDir(path.join(root, 'src'));
      ensureDir(path.join(root, 'node_modules', 'pkg'));
      fs.writeFileSync(path.join(root, 'src', 'index.ts'), 'export const value = 1;\n');
      fs.writeFileSync(path.join(root, 'README.md'), '# fallback\n');
      fs.writeFileSync(path.join(root, 'node_modules', 'pkg', 'index.js'), 'dependency\n');
      fs.writeFileSync(path.join(root, '.env.local'), 'SECRET=never-read\n');
      const warnings = [];
      const profile = collectRepositoryProfile(root, warnings);
      assert(profile.available && profile.basis === 'filtered_worktree_fallback', JSON.stringify(profile));
      assert(profile.tracked_files === 2, JSON.stringify(profile));
      assert(profile.source_files === 1, JSON.stringify(profile));
      assert(profile.excluded_files >= 2, JSON.stringify(profile));
      assert(warnings.some((warning) => warning.includes('filtered filesystem fallback')), warnings.join('; '));
    });


    check('collector: an untracked file marks a Git repository profile dirty without entering size totals', () => {
      const root = path.join(temporaryRoot, 'repository-profile-untracked');
      ensureDir(path.join(root, 'src'));
      fs.writeFileSync(path.join(root, 'src', 'index.js'), 'module.exports = 1;\n');
      for (const args of [
        ['init'],
        ['config', 'user.name', 'Field Report Test'],
        ['config', 'user.email', 'field-report@example.invalid'],
        ['add', '.'],
        ['commit', '-m', 'profile fixture']
      ]) {
        const result = childProcess.spawnSync('git', args, { cwd: root, encoding: 'utf8' });
        assert(result.status === 0, `${args.join(' ')}: ${result.stderr}`);
      }
      const before = collectRepositoryProfile(root, []);
      fs.writeFileSync(path.join(root, 'untracked-note.txt'), 'not part of the tracked profile\n');
      const after = collectRepositoryProfile(root, []);
      assert(before.dirty === false, JSON.stringify(before));
      assert(after.dirty === true, JSON.stringify(after));
      assert(after.tracked_files === before.tracked_files, JSON.stringify(after));
      assert(after.tracked_bytes === before.tracked_bytes, JSON.stringify(after));
    });

    check('renderer: non-Git profile labels do not claim that fallback files are Git tracked', () => {
      const rows = repositoryProfileRows({ values: {
        repository_profile_basis: { value: 'filtered_worktree_fallback', kind: 'derived' },
        repository_tracked_files: { value: 7, kind: 'derived' },
        repository_tracked_bytes: { value: 2048, kind: 'derived' },
        repository_source_files: { value: 3, kind: 'derived' },
        repository_source_bytes: { value: 1024, kind: 'derived' }
      }});
      const text = JSON.stringify(rows);
      assert(text.includes('Filtered repository files'), text);
      assert(!text.includes('Tracked repository files'), text);
      assert(text.includes('not Git-tracked files'), text);
    });

    check('collector and renderer: installed release-candidate identity is observed from package metadata', () => {
      const collected = collect(context);
      assert(collected.values.knowledge_release_channel.value === 'release_candidate', JSON.stringify(collected.values.knowledge_release_channel));
      assert(collected.values.knowledge_candidate_label.value === 'RC58', JSON.stringify(collected.values.knowledge_candidate_label));
      assert(collected.values.knowledge_candidate_name.value === 'knowledge-v3.3.0-step1-rc4-r58.zip', JSON.stringify(collected.values.knowledge_candidate_name));
      const identity = releaseIdentity(collected);
      assert(identity.display === '3.3.0 RC58', JSON.stringify(identity));
    });

    check('task results: content-addressed evidence, metrics, and repository snapshot validate together', () => {
      const reportId = 'fr_20260807_a1b2c3d4';
      const liveFacts = collect(context);
      const validation = validateTaskResults(validTaskResults(context, reportId), {
        context,
        reportId,
        facts: liveFacts,
        captureSnapshot: true
      });
      assert(validation.valid, validation.errors.join('; '));
      assert(validation.value.snapshot?.snapshot_sha256, JSON.stringify(validation.value.snapshot));
      assert(validation.value.results[0].evidence.length === 1, JSON.stringify(validation.value.results[0]));
      assert(validation.value.results[0].metrics.total === 1, JSON.stringify(validation.value.results[0]));
      const merged = mergeTaskResultsFacts(liveFacts, validation.value);
      const rows = verifiedOutcomeRows(merged, validAnswers());
      assert(rows.some((row) => row.check === 'Engineering task'), JSON.stringify(rows));
      assert(rows.some((row) => row.check === 'Overall outcome' && row.result.includes('Passed')), JSON.stringify(rows));
      assert(rows.some((row) => row.check === 'Objective tests' && row.result.includes('1/1 passed')), JSON.stringify(rows));
    });

    check('task results: secret-like paths, changed hashes, and unsupported pass claims fail closed', () => {
      const reportId = 'fr_20260807_b1b2c3d4';
      const liveFacts = collect(context);
      const secretPath = validTaskResults(context, reportId);
      secretPath.results[0].evidence.path = '.env.local';
      const secret = validateTaskResults(secretPath, { context, reportId, facts: liveFacts, captureSnapshot: true });
      assert(!secret.valid && secret.errors.some((error) => /secret-like/.test(error)), JSON.stringify(secret));
      const wrongHash = validTaskResults(context, reportId);
      wrongHash.results[0].evidence.sha256 = '0'.repeat(64);
      const changed = validateTaskResults(wrongHash, { context, reportId, facts: liveFacts, captureSnapshot: true });
      assert(!changed.valid && changed.errors.some((error) => /sha256 does not match/.test(error)), JSON.stringify(changed));
      const failingEvidencePath = path.join(context.stateRoot, 'maintenance', 'field-report-failing-check.json');
      writeJson(failingEvidencePath, { status: 'fail', failed: 1, total: 1 });
      const unsupportedPass = validTaskResults(context, reportId, {
        results: [{
          ...validTaskResults(context, reportId).results[0],
          evidence: {
            kind: 'automated_report',
            label: 'Failing check report',
            root_kind: 'state',
            path: 'maintenance/field-report-failing-check.json',
            sha256: fileSha256(failingEvidencePath)
          }
        }]
      });
      const unsupported = validateTaskResults(unsupportedPass, { context, reportId, facts: liveFacts, captureSnapshot: true });
      assert(!unsupported.valid && unsupported.errors.some((error) => /failing evidence/.test(error)), JSON.stringify(unsupported));
    });

    check('task results: a repository change makes the bound result snapshot stale', () => {
      const project = path.join(temporaryRoot, 'task-results-stale-project');
      const state = path.join(project, '.knowledge');
      setupArtifacts(state);
      ensureDir(path.join(project, 'src'));
      fs.writeFileSync(path.join(project, 'package.json'), '{"name":"task-results-stale"}\n');
      fs.writeFileSync(path.join(project, 'src', 'app.js'), 'module.exports = 1;\n');
      for (const args of [
        ['init'],
        ['config', 'user.name', 'Field Report Test'],
        ['config', 'user.email', 'field-report@example.invalid'],
        ['add', '.'],
        ['commit', '-m', 'clean baseline']
      ]) {
        const result = childProcess.spawnSync('git', args, { cwd: project, encoding: 'utf8' });
        assert(result.status === 0, `${args.join(' ')}: ${result.stderr}`);
      }
      const staleContext = makeContext(systemRoot, state, { targetRoot: project, repoId: 'task-results-stale' });
      const reportId = 'fr_20260807_c1b2c3d4';
      const captured = validateTaskResults(validTaskResults(staleContext, reportId), {
        context: staleContext,
        reportId,
        facts: collect(staleContext),
        captureSnapshot: true
      });
      assert(captured.valid, captured.errors.join('; '));
      fs.appendFileSync(path.join(project, 'src', 'app.js'), '// changed after evidence binding\n');
      const inspection = inspectTaskResults(staleContext, collect(staleContext), captured.value);
      assert(inspection.status === 'stale' && inspection.reason === 'repository_snapshot_changed', JSON.stringify(inspection));
    });

    check('repair telemetry: current, stale, invalid, and unavailable states are distinct and fail closed', () => {
      const current = collect(context);
      assert(current.values.repair_telemetry_status.value === 'current', JSON.stringify(current.values.repair_telemetry_status));
      assert(current.values.repair_findings_closed.value === 1, JSON.stringify(current.values.repair_findings_closed));

      const staleState = path.join(temporaryRoot, 'repair-telemetry-stale', '.knowledge');
      setupArtifacts(staleState);
      const staleOpportunities = JSON.parse(fs.readFileSync(path.join(staleState, 'maintenance', 'repair_opportunities.json'), 'utf8'));
      staleOpportunities.task_scope.task_id = 'new-current-task';
      staleOpportunities.task_scope.scope_hash = canonicalHash({
        ...staleOpportunities.task_scope,
        scope_hash: undefined
      });
      // canonicalHash omits undefined object values differently from the producer; rewrite through the same helper shape.
      const scopeForHash = JSON.parse(JSON.stringify(staleOpportunities.task_scope));
      delete scopeForHash.scope_hash;
      staleOpportunities.task_scope.scope_hash = canonicalHash(scopeForHash);
      staleOpportunities.generated_at = '2026-07-30T00:00:00.000Z';
      writeJson(path.join(staleState, 'maintenance', 'repair_opportunities.json'), staleOpportunities);
      const staleFacts = collect(makeContext(systemRoot, staleState));
      assert(staleFacts.values.repair_telemetry_status.value === 'stale', JSON.stringify(staleFacts.values.repair_telemetry_status));
      assert(staleFacts.values.repair_findings_closed.kind === 'unavailable', JSON.stringify(staleFacts.values.repair_findings_closed));

      const invalidState = path.join(temporaryRoot, 'repair-telemetry-invalid', '.knowledge');
      setupArtifacts(invalidState);
      const invalidTelemetry = JSON.parse(fs.readFileSync(path.join(invalidState, 'maintenance', 'repair_on_touch_telemetry.json'), 'utf8'));
      invalidTelemetry.repair_findings_closed = 99;
      writeJson(path.join(invalidState, 'maintenance', 'repair_on_touch_telemetry.json'), invalidTelemetry);
      const invalidFacts = collect(makeContext(systemRoot, invalidState));
      assert(invalidFacts.values.repair_telemetry_status.value === 'invalid', JSON.stringify(invalidFacts.values.repair_telemetry_status));
      assert(invalidFacts.values.repair_findings_closed.kind === 'unavailable', JSON.stringify(invalidFacts.values.repair_findings_closed));

      const unavailableState = path.join(temporaryRoot, 'repair-telemetry-unavailable', '.knowledge');
      setupArtifacts(unavailableState);
      fs.rmSync(path.join(unavailableState, 'maintenance', 'repair_on_touch_telemetry.json'));
      const unavailableFacts = collect(makeContext(systemRoot, unavailableState));
      assert(unavailableFacts.values.repair_telemetry_status.value === 'unavailable', JSON.stringify(unavailableFacts.values.repair_telemetry_status));
      assert(unavailableFacts.values.repair_findings_closed.kind === 'unavailable', JSON.stringify(unavailableFacts.values.repair_findings_closed));
    });

    check('renderer: structured task title creates a concise complete Discussion title', () => {
      const liveFacts = collect(context);
      const reportId = 'fr_20260807_d1b2c3d4';
      const validated = validateTaskResults(validTaskResults(context, reportId, {
        task: {
          title: 'Migrate the website into a standalone repository',
          outcome: 'pass',
          summary: 'The migration and its required checks completed successfully.'
        }
      }), { context, reportId, facts: liveFacts, captureSnapshot: true });
      assert(validated.valid, validated.errors.join('; '));
      const rendered = render({ anonymized: false }, mergeTaskResultsFacts(liveFacts, validated.value), validAnswers({
        'github-publication-permission': 'local_draft_only'
      }));
      assert(rendered.title === '[Field report] Migrate the website into a standalone repository — maintainer dogfooding', rendered.title);
      assert(Array.from(rendered.title).length <= 96, rendered.title);
      assert(!/[,:;\-]$/.test(rendered.title), rendered.title);
    });

    let primaryReport;

    check('collector: standalone repository scope is explicit and independent of module count', () => {
      const facts = collect(context);
      assert(facts.values.workspace_scope_kind.value === 'standalone_repository', 'standalone scope kind');
      assert(facts.values.workspace_repositories_total.value === 1, 'standalone repository count');
      const copy = JSON.parse(JSON.stringify(facts));
      copy.values.functional_modules_total = { value: 8, kind: 'derived', source: '.knowledge/modules/module_registry.json' };
      copy.values.modules_total = { value: 8, kind: 'observed', source: '.knowledge/routing/tasks/example/metrics.json' };
      copy.values.routing_task_bound_to_report = { value: true, kind: 'observed', source: '.knowledge/routing/tasks/example/current.json' };
      copy.values.modules_selected = { value: 1, kind: 'observed', source: '.knowledge/routing/tasks/example/metrics.json' };
      copy.values.paths_selected = { value: 4, kind: 'observed', source: '.knowledge/routing/tasks/example/metrics.json' };
      const disclosure = scopeDisclosure(copy);
      assert(disclosure.includes('standalone repository'), disclosure);
      assert(disclosure.includes('8 functional modules'), disclosure);
      assert(disclosure.includes('1 selected module'), disclosure);
      assert(!disclosure.includes('multi-project'), disclosure);
    });

    check('collector: team workspace repository count comes from team registry, not modules', () => {
      const teamRoot = path.join(temporaryRoot, 'team-scope');
      for (const repoId of ['repo-a', 'repo-b']) {
        writeJson(path.join(teamRoot, 'repos', repoId, 'repo.json'), {
          schema_version: '3.3.0', repoId, status: 'active'
        });
      }
      writeJson(path.join(teamRoot, 'repos', 'repo-archived', 'repo.json'), {
        schema_version: '3.3.0', repoId: 'repo-archived', status: 'archived'
      });
      const teamContext = makeContext(systemRoot, stateRoot, {
        mode: 'team', teamRoot, repoId: 'repo-a', workspaceId: 'workspace-a'
      });
      const facts = collect(teamContext);
      assert(facts.values.workspace_scope_kind.value === 'multi_repository_workspace', 'team scope kind');
      assert(facts.values.workspace_repositories_total.value === 2, 'active team repository count');
      const copy = JSON.parse(JSON.stringify(facts));
      copy.values.functional_modules_total = { value: 1, kind: 'derived', source: '.knowledge/modules/module_registry.json' };
      copy.values.modules_total = { value: 1, kind: 'observed', source: '.knowledge/routing/tasks/example/metrics.json' };
      copy.values.routing_task_bound_to_report = { value: true, kind: 'observed', source: '.knowledge/routing/tasks/example/current.json' };
      copy.values.modules_selected = { value: 1, kind: 'observed', source: '.knowledge/routing/tasks/example/metrics.json' };
      const disclosure = scopeDisclosure(copy);
      assert(disclosure.includes('registered 2 repositories'), disclosure);
      assert(disclosure.includes('current repository contained 1 functional module'), disclosure);
    });

    check('collector: unknown team repository count stays unavailable instead of guessing', () => {
      const teamContext = makeContext(systemRoot, stateRoot, {
        mode: 'team',
        teamRoot: path.join(temporaryRoot, 'empty-team'),
        repoId: 'repo-a',
        workspaceId: 'workspace-a'
      });
      const facts = collect(teamContext);
      assert(facts.values.workspace_scope_kind.kind === 'unavailable', 'unknown scope kind');
      assert(facts.values.workspace_repositories_total.kind === 'unavailable', 'unknown repository count');
      const copy = JSON.parse(JSON.stringify(facts));
      copy.values.modules_total = { value: 8, kind: 'observed', source: '.knowledge/routing/tasks/example/metrics.json' };
      const disclosure = scopeDisclosure(copy);
      assert(disclosure.includes('Repository count for this team workspace was unavailable'), disclosure);
      assert(disclosure.includes('No explicit task-routing snapshot was bound to this report.'), disclosure);
      assert(!disclosure.includes('0 selected'), disclosure);
      assert(!disclosure.includes('multi-project'), disclosure);
    });

    check('renderer: unavailable counts are not rendered as zero', () => {
      const facts = { values: {
        mode: { value: 'repo', kind: 'observed', source: 'runtime/context' },
        workspace_scope_kind: { value: 'standalone_repository', kind: 'derived', source: 'runtime/context' },
        modules_total: { value: null, kind: 'unavailable', source: 'fixture' },
        modules_selected: { value: null, kind: 'unavailable', source: 'fixture' },
        paths_selected: { value: null, kind: 'unavailable', source: 'fixture' }
      }};
      const disclosure = scopeDisclosure(facts);
      assert(disclosure === 'This standalone repository. No explicit task-routing snapshot was bound to this report.', disclosure);
      assert(!disclosure.includes('0 functional modules'), disclosure);
      assert(!disclosure.includes('0 selected'), disclosure);
    });

    check('workflow: start emits split fact counts and a resumable template', () => {
      const started = run(['start', '--new'], { context });
      primaryReport = started.report_id;
      assert(started.schema_version === 'knowledge-field-report.v2', 'schema');
      assert(Number.isFinite(started.facts_observed), 'observed');
      assert(Number.isFinite(started.facts_derived), 'derived');
      assert(Number.isFinite(started.facts_unavailable), 'unavailable');
      assert(!Object.prototype.hasOwnProperty.call(started, 'facts_collected'), 'legacy conflation');
      assert(fs.existsSync(started.answer_template_path), 'answer template');
      const manifest = JSON.parse(fs.readFileSync(
        fieldReportState.paths(context, primaryReport).manifest,
        'utf8'
      ));
      assert(manifest.language === 'auto', 'default source language must remain unresolved until answers are complete');
      assert(manifest.public_language === 'en', 'public language default');
      const questions = JSON.parse(fs.readFileSync(
        fieldReportState.paths(context, primaryReport).questions,
        'utf8'
      ));
      assert(Array.isArray(questions.question_catalog), 'question audit catalog missing');
      assert(questions.question_catalog.every((item) => item.status === 'missing'), 'initial question statuses');
    });

    check('workflow: partial ingest resumes without inventing answers', () => {
      const result = run(['ingest', `--report-id=${primaryReport}`], {
        context,
        answers: { 'quick-summary': 'Partial tester observation.' }
      });
      assert(result.missing_required_fields > 0, 'must remain incomplete');
      const resumed = run(['questions', `--report-id=${primaryReport}`], { context });
      assert(resumed.report_id === primaryReport, 'resume id');
    });

    let primaryRendered;
    check('workflow: complete ingest and render create distinct draft and public files', () => {
      run(['ingest', `--report-id=${primaryReport}`], {
        context,
        answers: validAnswers()
      });
      const completedStatus = run(['status', `--report-id=${primaryReport}`], { context });
      const completedManifest = fieldReportState.load(context, primaryReport);
      assert(completedManifest.language === 'en', JSON.stringify(completedManifest));
      assert(completedStatus.translation_status === 'translation_not_required', JSON.stringify(completedStatus));
      const questionAudit = JSON.parse(fs.readFileSync(
        fieldReportState.paths(context, primaryReport).questions,
        'utf8'
      ));
      assert(questionAudit.questions.length === 0, JSON.stringify(questionAudit));
      assert(questionAudit.question_catalog.length > 0, JSON.stringify(questionAudit));
      assert(questionAudit.question_catalog.every((item) => item.status === 'answered'), JSON.stringify(questionAudit));
      attachTaskResults(context, primaryReport);
      primaryRendered = run(['render', `--report-id=${primaryReport}`], { context });
      assert(primaryRendered.status === 'draft_ready', primaryRendered.status);
      const draft = fs.readFileSync(primaryRendered.draft_path, 'utf8');
      const publicBody = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(draft !== publicBody, 'draft and public must differ');
      assert(draft.includes('Collected fact provenance'), 'draft provenance');
      assert(!publicBody.includes('Collected fact provenance'), 'public debug leak');
    });

    check('workflow: default auto language keeps substantial Russian answers on the translation path and rejects a false English override', () => {
      const started = run(['start', '--new'], { context });
      const answers = validAnswers({
        'project-context': 'Это отдельный репозиторий сайта, проверенный в реальной задаче переноса и обновления.',
        'quick-summary': 'Главным результатом стал проверяемый проект с понятными границами и сохранёнными доказательствами.',
        'workflow-notes': 'Потребовались дополнительные шаги проверки и ручное подтверждение итогового текста.',
        'main-scenario': 'Проект был перенесён в отдельный репозиторий, после чего были выполнены сборка и проверка ссылок.',
        'accuracy-example': 'Контролируемого сравнения точности не проводилось, поэтому вывод о росте точности не делается.',
        'useful-parts': 'Полезными были проверка состояния, готовность задачи и сохранение доказательств.',
        'what-did-not-work': 'Процесс добавил накладные расходы на настройку и сбор доказательств.',
        'previous-workflow-comparison': 'Предыдущий процесс был проще для маленькой изолированной правки.',
        'final-assessment': 'Система полезна для проверяемых миграций, но может быть избыточной для тривиальных изменений.'
      });
      run(['ingest', `--report-id=${started.report_id}`], { context, answers });
      const status = run(['status', `--report-id=${started.report_id}`], { context });
      const manifest = fieldReportState.load(context, started.report_id);
      assert(manifest.language === 'auto', JSON.stringify(manifest));
      assert(status.translation_status === 'translation_required', JSON.stringify(status));
      expectThrow(() => run([
        'translation-export',
        `--report-id=${started.report_id}`,
        '--language=en'
      ], { context }), /conflicts|non-English/, 'false English source language');
      const exported = run([
        'translation-export',
        `--report-id=${started.report_id}`,
        '--language=ru'
      ], { context });
      assert(exported.status === 'translation_required' && exported.source_language === 'ru', JSON.stringify(exported));
    });

    check('renderer: public outcome tables explain metrics without leaking internal paths', () => {
      const body = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(body.includes('## Repository profile'), 'repository profile heading');
      assert(body.includes('## Verified engineering outcome'), 'verified outcome heading');
      assert(body.includes('## System state at collection'), 'system state heading');
      assert(body.includes('## System observations'), 'system observations heading');
      assert(body.includes('| Repository Doctor |'), 'Doctor outcome absent');
      assert(body.includes('| Wiki integrity |'), 'wiki outcome absent');
      assert(body.includes('| Stored verification evidence |'), 'verification outcome absent');
      assert(body.includes('The Doctor score is not model accuracy'), 'Doctor interpretation absent');
      assert(body.includes('evidence volume, not a task count or success rate'), 'receipt interpretation absent');
      assert(body.includes('Doctor report'), 'generic evidence label absent');
      assert(body.includes('Repair-on-touch telemetry'), 'repair evidence label absent');
      assert(!body.includes('.knowledge/maintenance/'), 'internal evidence path leaked');
      assert(!body.includes(stateRoot), 'absolute path leak');
      assert(!body.includes('| Open repair items |'), 'opaque repair counter leaked into the main table');
      assert(!body.includes('| Stale artifacts |'), 'opaque stale counter leaked into the main table');
      assert(!body.includes('excluded path entr'), 'internal exclusion counter leaked into public output');
    });

    check('renderer: every public numeric outcome has an interpretation and generic evidence label', () => {
      const currentFacts = JSON.parse(fs.readFileSync(
        fieldReportState.paths(context, primaryReport).facts,
        'utf8'
      ));
      const rows = verifiedOutcomeRows(currentFacts, validAnswers());
      assert(rows.length >= 3, JSON.stringify(rows));
      for (const row of rows) {
        assert(typeof row.check === 'string' && row.check, JSON.stringify(row));
        assert(typeof row.result === 'string' && row.result, JSON.stringify(row));
        assert(typeof row.interpretation === 'string' && row.interpretation.length > 20, JSON.stringify(row));
        assert(typeof row.evidence === 'string' && row.evidence, JSON.stringify(row));
        assert(!row.evidence.includes('.knowledge/'), JSON.stringify(row));
      }
      const profile = repositoryProfileRows(currentFacts);
      assert(profile.length === 4, JSON.stringify(profile));
      assert(profile.every((row) => row.interpretation && row.evidence), JSON.stringify(profile));
    });

    check('renderer: core outcome rows remain explicit when evidence is unavailable', () => {
      const rows = systemStateRows({ values: {} });
      const byName = new Map(rows.map((row) => [row.check, row]));
      for (const name of [
        'Task readiness',
        'Repository Doctor',
        'Wiki integrity',
        'Stored verification evidence'
      ]) {
        assert(byName.get(name)?.result === 'Unavailable', JSON.stringify(rows));
        assert(/no current|no .* available/i.test(byName.get(name)?.interpretation || ''), JSON.stringify(rows));
      }
    });

    check('renderer: noticeable Doctor, queue, stale, and receipt counts are explained', () => {
      const currentFacts = JSON.parse(fs.readFileSync(
        fieldReportState.paths(context, primaryReport).facts,
        'utf8'
      ));
      currentFacts.values.doctor_score.value = 93;
      currentFacts.values.doctor_active_findings.value = 1;
      currentFacts.values.doctor_critical_findings.value = 0;
      currentFacts.values.repair_open.value = 44;
      currentFacts.values.stale_artifacts_total.value = 43;
      currentFacts.values.verification_receipts.value = 3;
      const observations = systemObservations(currentFacts).join(' ');
      assert(observations.includes('93/100'), observations);
      assert(observations.includes('not model accuracy'), observations);
      assert(observations.includes('44 open rows'), observations);
      assert(observations.includes('not the number of current blockers'), observations);
      assert(observations.includes('43 artifacts'), observations);
      assert(observations.includes('not a count of failed tasks'), observations);
      assert(observations.includes('3 verification receipts'), observations);
      assert(observations.includes('evidence volume'), observations);
    });

    check('renderer: report relationship controls a deterministic English disclosure and title', () => {
      const reportPaths = fieldReportState.paths(context, primaryReport);
      const manifest = fieldReportState.load(context, primaryReport);
      const currentFacts = JSON.parse(fs.readFileSync(reportPaths.facts, 'utf8'));
      for (const relationship of [
        'first_party_maintainer',
        'independent_user',
        'internal_qa',
        'controlled_comparison'
      ]) {
        const output = render(
          manifest,
          currentFacts,
          validAnswers({
            'report-relationship': relationship,
            'quick-summary': 'A deterministic English summary.'
          })
        );
        assert(output.title.startsWith('[Field report] Verify a scoped repository change — '), output.title);
        assert(!output.title.includes('A localized authorization change'), output.title);
        assert(!output.title.includes('A deterministic English summary'), output.title);
        assert(Array.from(output.title).length <= 96, output.title);
        assert(output.public.includes('> **Disclosure:**'), relationship);
        assert(output.redaction.status !== 'blocked', JSON.stringify(output.redaction));
      }
    });

    check('privacy: internal workspace, client, and organization labels are generalized', () => {
      const source = 'The project moved from workspace Design and client Acme Corp. The internal team Atlas reviewed it.';
      const generalized = generalizeInternalOrganization(source);
      assert(
        generalizeInternalOrganization(generalized.text).text === generalized.text,
        'organization generalization is not idempotent'
      );
      assert(!generalized.text.includes('Design'), generalized.text);
      assert(!generalized.text.includes('Acme'), generalized.text);
      assert(!generalized.text.includes('Atlas'), generalized.text);
      assert(generalized.text.includes('a larger local multi-project workspace'), generalized.text);
      assert(generalized.text.includes('an internal client organization'), generalized.text);
      assert(generalized.text.includes('an internal organization'), generalized.text);
      assert(
        generalizeInternalOrganization('The GitHub Actions workspace was temporary.').text ===
          'The GitHub Actions workspace was temporary.',
        'public platform label was generalized'
      );
      assert(
        generalizeInternalOrganization('The Design workspace contained the site.').text ===
          'A larger local multi-project workspace contained the site.',
        'leading article or grammar was broken during generalization'
      );
      assert(
        generalizeInternalOrganization('The workspace contained one repository.').text ===
          'The workspace contained one repository.',
        'ordinary workspace prose was mistaken for an internal label'
      );
      assert(
        generalizeInternalOrganization('The site moved from workspace design.').text ===
          'The site moved from a larger local multi-project workspace.',
        'lowercase workspace label was not generalized'
      );
      assert(
        generalizeInternalOrganization(
          'The site was separated from workspace Design for client Acme Corp. The stack uses JavaScript.'
        ).text ===
          'The site was separated from a larger local multi-project workspace for an internal client organization. The stack uses JavaScript.',
        'adjacent workspace/client labels produced duplicated or broken prose'
      );

      assert(
        generalizeInternalOrganization(
          'Any workspace-to-task context number is a deterministic local estimate. This workspace contained one repository.'
        ).text ===
          'Any workspace-to-task context number is a deterministic local estimate. This workspace contained one repository.',
        'generic workspace prose was mistaken for an internal label'
      );
      assert(
        generalizeInternalOrganization(
          'The project was evaluated in a local non-Git workspace.'
        ).text ===
          'The project was evaluated in a local non-Git workspace.',
        'non-Git workspace terminology was mistaken for an internal label'
      );
      assert(
        generalizeInternalOrganization(
          'An anonymized product workspace containing a mobile client and a backend service.'
        ).text ===
          'An anonymized product workspace containing a mobile client and a backend service.',
        'ordinary workspace-containing prose was mistaken for an internal label'
      );
      const report = createRendered(context, validAnswers({
        'project-context': 'The project moved from workspace Design and client Acme Corp.'
      }));
      const body = fs.readFileSync(report.rendered.public_path, 'utf8');
      assert(!body.includes('Design') && !body.includes('Acme'), body);
      assert(body.includes('a larger local multi-project workspace'), body);
    });

    check('language gate: English passes while Russian and Spanish publication prose are blocked', () => {
      assert(scanEnglishLanguage('This report describes a real repository workflow with objective checks.').status === 'pass', 'English blocked');
      assert(scanEnglishLanguage('Этот отчёт описывает реальную работу с репозиторием и проверками.').status === 'blocked', 'Russian passed');
      assert(scanEnglishLanguage('La evidencia de ruta ayudó durante una tarea comparable y una revisión completa.').status === 'blocked', 'Spanish passed');
      const findings = publicAnswerLanguageFindings(validAnswers({
        'quick-summary': 'Этот итог всё ещё написан по-русски.'
      }));
      assert(findings.some((finding) => finding.field === 'quick-summary'), JSON.stringify(findings));
    });

    check('renderer: a non-English answer cannot hide inside an otherwise English report', () => {
      const reportPaths = fieldReportState.paths(context, primaryReport);
      const output = render(
        fieldReportState.load(context, primaryReport),
        JSON.parse(fs.readFileSync(reportPaths.facts, 'utf8')),
        validAnswers({ 'quick-summary': 'Этот итог нельзя публиковать без перевода.' })
      );
      assert(output.redaction.status === 'blocked', JSON.stringify(output.redaction));
      assert(
        output.redaction.answer_language_scan.findings.some((finding) => finding.field === 'quick-summary'),
        JSON.stringify(output.redaction)
      );
    });


    check('claim safety: unsupported routing effectiveness and routing-use claims are blocked without a bound snapshot', () => {
      const baseFacts = collect(context);
      const effectiveness = claimSafetyFindings(baseFacts, validAnswers({
        'main-scenario': '.knowledge limited the scope and selected the correct files.'
      }));
      assert(effectiveness.some((finding) => finding.rule === 'unsupported_routing_claim'), JSON.stringify(effectiveness));
      const usage = claimSafetyFindings(baseFacts, validAnswers({
        'previous-workflow-comparison': '.knowledge added routing, trust checks, and an audit trail.'
      }));
      assert(usage.some((finding) => finding.rule === 'unsupported_routing_claim'), JSON.stringify(usage));
      const safe = claimSafetyFindings(baseFacts, validAnswers({
        'main-scenario': '.knowledge helped make the repository and task boundaries explicit.'
      }));
      assert(!safe.some((finding) => /routing/.test(finding.rule)), JSON.stringify(safe));
    });

    check('claim safety: a bound but ineligible routing comparison cannot support narrowing claims', () => {
      const routedFacts = collect(context);
      routedFacts.values.routing_task_bound_to_report = { value: true, kind: 'observed', source: 'fixture' };
      routedFacts.values.routing_claim_eligible = { value: false, kind: 'observed', source: 'fixture' };
      const findings = claimSafetyFindings(routedFacts, validAnswers({
        'main-scenario': 'The workflow narrowed the context and excluded unrelated paths.'
      }));
      assert(findings.some((finding) => finding.rule === 'ineligible_routing_effect_claim'), JSON.stringify(findings));
      const usageOnly = claimSafetyFindings(routedFacts, validAnswers({
        'main-scenario': 'The workflow used routing and recorded the selected task scope.'
      }));
      assert(!usageOnly.some((finding) => finding.rule === 'ineligible_routing_effect_claim'), JSON.stringify(usageOnly));
    });

    check('claim safety: unsupported provider usage, accuracy, and speed claims fail closed while explicit uncertainty remains allowed', () => {
      const baseFacts = collect(context);
      const unsafe = claimSafetyFindings(baseFacts, validAnswers({
        'accuracy-change': 'not_enough_evidence',
        'response-speed-change': 'not_enough_data',
        'quick-summary': 'The system saved 25% of model tokens, improved accuracy, and made the agent faster.'
      }));
      for (const rule of [
        'unsupported_provider_usage_claim',
        'unsupported_accuracy_claim',
        'unsupported_speed_claim'
      ]) assert(unsafe.some((finding) => finding.rule === rule), `${rule}: ${JSON.stringify(unsafe)}`);
      const safe = claimSafetyFindings(baseFacts, validAnswers({
        'accuracy-change': 'not_enough_evidence',
        'response-speed-change': 'not_enough_data',
        'quick-summary': 'No token savings were measured. Improvements in accuracy or speed remain unconfirmed.',
        'github-publication-permission': 'local_draft_only'
      }));
      assert(safe.length === 0, JSON.stringify(safe));
    });

    check('claim safety: current candidate identity mismatches are blocked and explicit historical baselines are allowed', () => {
      const baseFacts = collect(context);
      const mismatch = claimSafetyFindings(baseFacts, validAnswers({
        'project-context': 'This report was produced with .knowledge 3.3.0 RC56.'
      }));
      assert(mismatch.some((finding) => finding.rule === 'candidate_identity_mismatch'), JSON.stringify(mismatch));
      const historical = claimSafetyFindings(baseFacts, validAnswers({
        'project-context': 'The project was upgraded from RC56 to RC58 before this report was collected.'
      }));
      assert(!historical.some((finding) => finding.rule === 'candidate_identity_mismatch'), JSON.stringify(historical));
    });

    check('renderer: raw enum IDs are absent and human labels are present', () => {
      const body = fs.readFileSync(primaryRendered.public_path, 'utf8');
      for (const field of DEFAULT_SCHEMA.fields) {
        for (const raw of field.allowed_values || []) {
          if (!raw.includes('_')) continue;
          assert(!body.includes(raw), `raw enum leaked: ${raw}`);
        }
      }
      assert(body.includes('Slightly improved'), 'accuracy label');
      assert(body.includes('Allowed to publish on GitHub'), 'publication label');
    });

    check('renderer: tester prose, code, links, and tables are byte-preserved', () => {
      const prose = [
        'no comparable baseline',
        'there was no performance conclusion',
        'turned off manually',
        'yes, but only after review',
        'the issue remains open',
        'the old workflow was closed manually',
        'the result was not clearly improved',
        'we used the off mode once',
        '`no_clear_change`',
        '```text\\nclearly_improved\\n```',
        '[workflow](https://example.invalid/no_clear_change)',
        '| Status | Note |\\n|---|---|\\n| no_clear_change | unchanged prose |'
      ].join('\\n');
      const report = createRendered(context, validAnswers({
        'quick-summary': prose,
        'workflow-notes': prose,
        'what-did-not-work': prose
      }));
      const body = fs.readFileSync(report.rendered.public_path, 'utf8');
      assert(body.includes(prose), 'tester prose was mutated');
      assert(body.includes('Slightly improved'), 'typed enum was not humanized');
      assert(!body.includes('**Accuracy assessment:** slightly_improved'), 'raw typed enum leaked');
    });

    check('renderer: empty optional sections are omitted', () => {
      const body = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(!body.includes('## Supporting material'), 'empty optional section');
      assert(!body.includes('Additional scenario'), 'empty optional field');
    });

    check('renderer: estimated speed remains explicitly labeled', () => {
      const body = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(body.includes('+12% (Estimated from comparable tasks, n=3)'), 'estimate label');
      assert(!body.includes('flow duration'), 'flow duration proxy');
    });

    check('renderer: routing evidence omits the irrelevant zero saving or overhead row', () => {
      const baseFacts = collect(context);
      const withOverhead = JSON.parse(JSON.stringify(baseFacts));
      withOverhead.values.routing_task_bound_to_report = {
        value: true, kind: 'observed', source: 'routing/tasks/example/current.json'
      };
      withOverhead.values.routing_claim_eligible = {
        value: true, kind: 'derived', source: 'routing/tasks/example/current.json'
      };
      withOverhead.values.routing_estimator_assessment = {
        value: 'estimated_overhead', kind: 'derived', source: 'routing/tasks/example/comparisons/example/metrics.json'
      };
      withOverhead.values.routing_comparison_kind = {
        value: 'workspace_to_task_first_read_narrowing', kind: 'derived', source: 'routing/tasks/example/comparisons/example/metrics.json'
      };
      withOverhead.values.routing_workspace_baseline_estimated_tokens = {
        value: 300, kind: 'derived', source: 'routing/tasks/example/comparisons/example/metrics.json'
      };
      withOverhead.values.routing_task_estimated_tokens = {
        value: 312, kind: 'derived', source: 'routing/tasks/example/comparisons/example/metrics.json'
      };
      withOverhead.values.routing_signed_delta_percent = {
        value: -4, kind: 'derived', source: 'routing/tasks/example/comparisons/example/metrics.json'
      };
      withOverhead.values.routing_estimated_tokens_saved = {
        value: 0, kind: 'derived', source: 'routing/tasks/example/current.json'
      };
      withOverhead.values.routing_estimated_tokens_overhead = {
        value: 12, kind: 'derived', source: 'routing/tasks/example/current.json'
      };
      withOverhead.values.routing_estimated_percent_overhead = {
        value: 4, kind: 'derived', source: 'routing/tasks/example/current.json'
      };
      const overheadRow = systemStateRows(withOverhead).find((row) => row.check === 'Workspace-to-task first-read estimate');
      const overheadRows = JSON.stringify(overheadRow || {});
      assert(!/saving|reduction/i.test(overheadRows), 'overhead branch must not claim saving');
      assert(overheadRows.includes('Estimated workspace-to-task first-read overhead: 312 estimated tokens'), 'overhead row must remain');
      assert(!overheadRows.includes('estimated_overhead'), 'raw overhead assessment leaked');
      const withSaving = JSON.parse(JSON.stringify(withOverhead));
      withSaving.values.routing_estimated_tokens_saved.value = 9;
      withSaving.values.routing_estimated_percent_saved = { value: 3, kind: 'derived', source: 'routing/tasks/example/current.json' };
      withSaving.values.routing_estimated_tokens_overhead.value = 0;
      withSaving.values.routing_estimator_assessment.value = 'estimated_narrowing';
      withSaving.values.routing_workspace_baseline_estimated_tokens.value = 300;
      withSaving.values.routing_task_estimated_tokens.value = 291;
      withSaving.values.routing_signed_delta_percent.value = 3;
      const savingRow = systemStateRows(withSaving).find((row) => row.check === 'Workspace-to-task first-read estimate');
      const savingRows = JSON.stringify(savingRow || {});
      assert(savingRows.includes('Estimated workspace-to-task first-read narrowing: 300 estimated tokens'), 'narrowing row must remain');
      assert(!savingRows.includes('first-read overhead'), 'zero overhead row must be omitted');
      assert(!savingRows.includes('estimated_narrowing'), 'raw narrowing assessment leaked');
    });


    check('renderer: publication footer reflects the actual tester approval state', () => {
      const body = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(body.includes('Publication requires explicit tester review and approval.'), 'approval requirement absent');
      assert(!body.includes('reviewed by the tester before publication'), 'unperformed tester review was claimed');
      assert(!body.includes('explicitly approved by the tester for this exact public draft'), 'unperformed exact-draft approval was claimed');
      assert(body.includes('**GitHub publication:** Allowed to publish on GitHub'), body);

      const reportPaths = fieldReportState.paths(context, primaryReport);
      const approvedManifest = JSON.parse(JSON.stringify(fieldReportState.load(context, primaryReport)));
      approvedManifest.approval = {
        ...(approvedManifest.approval || {}),
        approved_by_tester: true,
        approved_at: '2026-01-01T00:00:00.000Z',
        content_hash: 'a'.repeat(64)
      };
      const approvedFacts = JSON.parse(fs.readFileSync(reportPaths.facts, 'utf8'));
      const approvedAnswers = JSON.parse(fs.readFileSync(reportPaths.answers_original, 'utf8'));
      const approvedBody = render(approvedManifest, approvedFacts, approvedAnswers).public;
      assert(approvedBody.includes('explicitly approved by the tester for this exact public draft.'), 'approved exact-draft footer absent');
      assert(!approvedBody.includes('Publication requires explicit tester review and approval.'), 'pre-approval footer survived approval');
    });

    check('renderer: discussion titles are word-safe, Unicode-safe, and bounded', () => {
      const title = truncateDiscussionTitle(
        '[Field report] Private project + coding agent — alpha beta charlie delta epsilon',
        64
      );
      assert(Array.from(title).length <= 64, `title length ${Array.from(title).length}`);
      assert(title.endsWith('…'), title);
      assert(!title.endsWith('char…'), title);
      assert(!/\s…$/.test(title), title);
      const unicodeTitle = truncateDiscussionTitle('😀😀😀 alpha beta gamma delta', 12);
      assert(Array.from(unicodeTitle).length <= 12, `unicode title length ${Array.from(unicodeTitle).length}`);
      const titleWithoutEllipsis = unicodeTitle.slice(0, -1);
      const lastCodeUnit = titleWithoutEllipsis.charCodeAt(titleWithoutEllipsis.length - 1);
      assert(!(lastCodeUnit >= 0xD800 && lastCodeUnit <= 0xDBFF), 'title ended with an unpaired high surrogate');
    });


    check('task results: any failed engineering check yields a failed task outcome', () => {
      const rows = [
        { status: 'pass' },
        { status: 'fail' },
        { status: 'warning' }
      ];
      const { deriveOutcome } = require('./lib/field-report/task-results');
      assert(deriveOutcome(rows) === 'fail', deriveOutcome(rows));
      assert(deriveOutcome([{ status: 'warning' }]) === 'incomplete', deriveOutcome([{ status: 'warning' }]));
      assert(deriveOutcome([{ status: 'not_run' }]) === 'not_verified', deriveOutcome([{ status: 'not_run' }]));
    });

    check('task results: informational not-run rows stay visible without downgrading a successful task', () => {
      const { deriveOutcome } = require('./lib/field-report/task-results');
      const rows = [
        { status: 'pass', outcome_relevant: true },
        { status: 'not_run', outcome_relevant: false }
      ];
      assert(deriveOutcome(rows) === 'pass', deriveOutcome(rows));
      assert(deriveOutcome([{ status: 'warning', outcome_relevant: true }]) === 'incomplete');
    });

    check('task results: numeric failures and warnings cannot hide behind a pass status', () => {
      const reportId = 'fr_20260807_aa58aa58';
      const liveFacts = collect(context);
      const base = validTaskResults(context, reportId);
      const failedMetrics = JSON.parse(JSON.stringify(base));
      failedMetrics.results[0].metrics = { passed: 4, failed: 1, total: 5 };
      const failed = validateTaskResults(failedMetrics, {
        context, reportId, facts: liveFacts, captureSnapshot: true
      });
      assert(!failed.valid && failed.errors.some((error) => /metrics reports failures/.test(error)), JSON.stringify(failed));
      const warningMetrics = JSON.parse(JSON.stringify(base));
      warningMetrics.results[0].metrics = { passed: 4, warnings: 1, total: 5 };
      const warned = validateTaskResults(warningMetrics, {
        context, reportId, facts: liveFacts, captureSnapshot: true
      });
      assert(!warned.valid && warned.errors.some((error) => /metrics reports warnings/.test(error)), JSON.stringify(warned));
    });

    check('task results: evidence-bound rows derive the task outcome and capture a repository snapshot', () => {
      const started = run(['start', '--new'], { context });
      run(['ingest', `--report-id=${started.report_id}`], { context, answers: validAnswers() });
      const ingested = attachTaskResults(context, started.report_id);
      assert(ingested.status === 'task_results_ready', JSON.stringify(ingested));
      const stored = JSON.parse(fs.readFileSync(
        fieldReportState.paths(context, started.report_id).task_results,
        'utf8'
      ));
      assert(stored.task.outcome === 'pass', JSON.stringify(stored));
      assert(stored.snapshot?.snapshot_sha256 === snapshotFromFacts(collect(context)).snapshot_sha256, JSON.stringify(stored.snapshot));
      assert(/^[a-f0-9]{64}$/.test(stored.content_sha256), stored.content_sha256);
      const inspection = inspectTaskResults(context, collect(context), stored);
      assert(inspection.status === 'current', JSON.stringify(inspection));
      const rendered = run(['render', `--report-id=${started.report_id}`], { context });
      const body = fs.readFileSync(rendered.public_path, 'utf8');
      assert(body.includes('| Engineering task | Verify a scoped repository change |'), body);
      assert(body.includes('| Overall outcome | Passed —'), body);
      assert(body.includes('| Objective tests | Passed —'), body);
      assert(body.indexOf('## Verified engineering outcome') < body.indexOf('## System state at collection'), body);
    });

    check('task results: a pass claim cannot conflict with failing or changed evidence', () => {
      const reportId = 'fr_20260807_abcdef01';
      const base = validTaskResults(context, reportId);
      const conflicting = JSON.parse(JSON.stringify(base));
      conflicting.results[0].status = 'fail';
      const conflict = validateTaskResults(conflicting, {
        context,
        reportId,
        facts: collect(context),
        captureSnapshot: true
      });
      assert(!conflict.valid && conflict.errors.some((error) => error.includes('does not support a failed row status')), JSON.stringify(conflict));
      const tampered = JSON.parse(JSON.stringify(base));
      tampered.results[0].evidence.sha256 = '0'.repeat(64);
      const tamper = validateTaskResults(tampered, {
        context,
        reportId,
        facts: collect(context),
        captureSnapshot: true
      });
      assert(!tamper.valid && tamper.errors.some((error) => error.includes('sha256 does not match')), JSON.stringify(tamper));
      const generic = JSON.parse(JSON.stringify(base));
      generic.task.title = 'Task';
      const genericResult = validateTaskResults(generic, {
        context,
        reportId,
        facts: collect(context),
        captureSnapshot: true
      });
      assert(!genericResult.valid && genericResult.errors.some((error) => error.includes('concise, specific')), JSON.stringify(genericResult));
    });

    check('task results: changed evidence blocks rendering as stale', () => {
      const report = createRendered(context, validAnswers({
        'github-publication-permission': 'local_draft_only'
      }));
      const evidenceFile = path.join(context.stateRoot, 'maintenance', 'field-report-task-check.json');
      const original = fs.readFileSync(evidenceFile);
      writeJson(evidenceFile, { status: 'fail', passed: 0, failed: 1, total: 1 });
      const error = expectThrow(
        () => run(['render', `--report-id=${report.reportId}`], { context }),
        /task-result evidence|evidence_changed|sha256 does not match/,
        'changed evidence did not block render'
      );
      assert(error.code === 'task_results_stale', error.code);
      fs.writeFileSync(evidenceFile, original);
    });

    check('snapshot: a dirty Git repository blocks GitHub publication but remains available as a local draft', () => {
      const repo = path.join(temporaryRoot, 'dirty-public-project');
      const headSha = initCleanGitProject(repo);
      const state = path.join(repo, '.knowledge');
      setupArtifacts(state);
      const dirtyContext = makeContext(systemRoot, state, { targetRoot: repo, headSha });
      fs.writeFileSync(path.join(repo, 'scratch.txt'), 'untracked evidence\n', 'utf8');

      const publicStarted = run(['start', '--new'], { context: dirtyContext });
      run(['ingest', `--report-id=${publicStarted.report_id}`], {
        context: dirtyContext,
        answers: validAnswers({ 'github-publication-permission': 'github_publication_allowed' })
      });
      attachTaskResults(dirtyContext, publicStarted.report_id);
      const publicRender = run(['render', `--report-id=${publicStarted.report_id}`], { context: dirtyContext });
      assert(publicRender.status === 'redaction_required', JSON.stringify(publicRender));
      const publicRedaction = publicRender.redaction;
      assert(publicRedaction.unresolved_findings.some((finding) => finding.rule === 'dirty_final_snapshot_publication'), JSON.stringify(publicRedaction));
      const publicBody = fs.readFileSync(publicRender.public_path, 'utf8');
      assert(publicBody.includes('Requested by the tester, but blocked until the final Git working tree is clean'), publicBody);
      assert(!publicBody.includes('**GitHub publication:** Allowed to publish on GitHub'), publicBody);

      const localStarted = run(['start', '--new'], { context: dirtyContext });
      run(['ingest', `--report-id=${localStarted.report_id}`], {
        context: dirtyContext,
        answers: validAnswers({ 'github-publication-permission': 'local_draft_only' })
      });
      attachTaskResults(dirtyContext, localStarted.report_id);
      const localRender = run(['render', `--report-id=${localStarted.report_id}`], { context: dirtyContext });
      assert(localRender.status === 'draft_ready', JSON.stringify(localRender));
      const body = fs.readFileSync(localRender.public_path, 'utf8');
      assert(body.includes('Dirty untracked'), body);
      assert(body.includes('1 untracked file'), body);
    });

    check('snapshot: a repository mutation after results ingestion invalidates the task-result snapshot', () => {
      const repo = path.join(temporaryRoot, 'snapshot-drift-project');
      const headSha = initCleanGitProject(repo);
      const state = path.join(repo, '.knowledge');
      setupArtifacts(state);
      const snapshotContext = makeContext(systemRoot, state, { targetRoot: repo, headSha });
      const started = run(['start', '--new'], { context: snapshotContext });
      run(['ingest', `--report-id=${started.report_id}`], {
        context: snapshotContext,
        answers: validAnswers({ 'github-publication-permission': 'local_draft_only' })
      });
      attachTaskResults(snapshotContext, started.report_id);
      fs.appendFileSync(path.join(repo, 'src', 'index.js'), '// changed after evidence capture\n');
      const error = expectThrow(
        () => run(['render', `--report-id=${started.report_id}`], { context: snapshotContext }),
        /repository_snapshot_changed|repository snapshot is stale/,
        'snapshot drift did not block rendering'
      );
      assert(error.code === 'task_results_stale', error.code);
    });

    check('repair telemetry: current, stale, invalid, and unavailable states are rendered without unsupported effects', () => {
      const currentFacts = collect(context);
      const currentRow = systemStateRows(currentFacts).find((row) => row.check === 'Repair-on-touch telemetry');
      assert(currentFacts.values.repair_telemetry_status.value === 'current', JSON.stringify(currentFacts.values.repair_telemetry_status));
      assert(currentRow.result.includes('Current — validated') && currentRow.result.includes('1 closed'), JSON.stringify(currentRow));

      const staleState = path.join(temporaryRoot, 'stale-repair-telemetry');
      setupArtifacts(staleState);
      const staleFile = path.join(staleState, 'maintenance', 'repair_on_touch_telemetry.json');
      const staleTelemetry = JSON.parse(fs.readFileSync(staleFile, 'utf8'));
      staleTelemetry.task_scope_sha256 = '0'.repeat(64);
      writeJson(staleFile, staleTelemetry);
      const staleFacts = collect(makeContext(systemRoot, staleState));
      const staleRow = systemStateRows(staleFacts).find((row) => row.check === 'Repair-on-touch telemetry');
      assert(staleFacts.values.repair_telemetry_status.value === 'stale', JSON.stringify(staleFacts.values.repair_telemetry_status));
      assert(staleRow.result === 'Stale — metrics withheld', JSON.stringify(staleRow));
      const repairClaims = claimSafetyFindings(staleFacts, validAnswers({
        'workflow-notes': 'Repair-on-touch fixed the stale module during the task.',
        'github-publication-permission': 'local_draft_only'
      }));
      assert(repairClaims.some((finding) => finding.rule === 'unsupported_repair_effect_claim'), JSON.stringify(repairClaims));

      const invalidState = path.join(temporaryRoot, 'invalid-repair-telemetry');
      setupArtifacts(invalidState);
      const invalidFile = path.join(invalidState, 'maintenance', 'repair_on_touch_telemetry.json');
      const invalidTelemetry = JSON.parse(fs.readFileSync(invalidFile, 'utf8'));
      invalidTelemetry.repair_findings_closed = 99;
      writeJson(invalidFile, invalidTelemetry);
      const invalidFacts = collect(makeContext(systemRoot, invalidState));
      const invalidRow = systemStateRows(invalidFacts).find((row) => row.check === 'Repair-on-touch telemetry');
      assert(invalidFacts.values.repair_telemetry_status.value === 'invalid', JSON.stringify(invalidFacts.values.repair_telemetry_status));
      assert(invalidRow.result === 'Invalid — metrics withheld', JSON.stringify(invalidRow));

      const absentState = path.join(temporaryRoot, 'absent-repair-telemetry');
      setupArtifacts(absentState);
      fs.rmSync(path.join(absentState, 'maintenance', 'repair_on_touch_telemetry.json'));
      const absentFacts = collect(makeContext(systemRoot, absentState));
      const absentRow = systemStateRows(absentFacts).find((row) => row.check === 'Repair-on-touch telemetry');
      assert(absentFacts.values.repair_telemetry_status.value === 'unavailable', JSON.stringify(absentFacts.values.repair_telemetry_status));
      assert(absentRow.result === 'Unavailable', JSON.stringify(absentRow));
    });

    check('renderer: task-focused Discussion titles preserve a useful subject and relationship suffix', () => {
      const cases = [
        ['Migrate a customer portal to a standalone repository', 'maintainer dogfooding'],
        ['Validate an API schema migration', 'independent user'],
        ['Audit a desktop plugin package', 'internal QA'],
        ['Compare two repository-review workflows', 'controlled comparison']
      ];
      for (const [subject, relationship] of cases) {
        const title = buildDiscussionTitle(subject, relationship, 96);
        assert(title.startsWith(`[Field report] ${subject}`), title);
        assert(title.endsWith(`— ${relationship}`), title);
        assert(Array.from(title).length <= 96, title);
        assert(!title.includes('The real engineering task was to'), title);
      }
      const long = buildDiscussionTitle(
        'Validate a very long multi-module authorization migration without breaking compatibility or privacy',
        'maintainer dogfooding',
        96
      );
      assert(Array.from(long).length <= 96, long);
      assert(long.endsWith('— maintainer dogfooding'), long);
      assert(!/\s…\s—/.test(long), long);
    });

    check('renderer: same-language reports do not claim translation', () => {
      const body = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(!body.includes('agent-assisted and approved by the tester'), 'false claim');
    });

    check('privacy: Windows, Linux, and macOS local paths are anonymized', () => {
      const windowsPath = ['C:', 'Users', 'alice', 'private', 'file.js'].join('\\');
      const posixPath = (...parts) => `/${parts.join('/')}`;
      for (const localPath of [
        windowsPath,
        posixPath('home', 'alice', 'private', 'file.js'),
        posixPath('Users', 'alice', 'private', 'file.js'),
        posixPath('srv', 'acme', 'private', 'file.js'),
        posixPath('opt', 'acme', 'internal', 'file.js'),
        posixPath('custom-root', 'acme', 'private', 'file.js')
      ]) {
        const result = redactText(localPath, false);
        assert(!result.text.includes(localPath), localPath);
      }
      assert(redactText('https://example.com/api/v1/items', false).text ===
        'https://example.com/api/v1/items', 'safe HTTPS URL was treated as a local path');
    });

    check('privacy: loopback, metadata-service, and private IPv6 addresses are redacted', () => {
      for (const address of [
        '127.0.0.1',
        '169.254.169.254',
        '::1',
        'fc00::1234',
        'fe80::1'
      ]) {
        const result = redactText(`endpoint=${address}`, false);
        assert(!result.text.includes(address), `private address leaked: ${address}`);
      }
    });

    check('privacy: repository-relative paths are preserved', () => {
      for (const relativePath of [
        '.knowledge/maintenance/repair_queue.json',
        'docs/release/3.3.0/test-evidence/report.json',
        'maintenance/flow-logs/release-one.json',
        './docs/field-report.md',
        '../workspace/docs/field-report.md'
      ]) {
        const result = redactText(relativePath, false);
        assert(result.text === relativePath, `relative path changed: ${relativePath}`);
        assert(
          !result.redactions.some((item) => item.rule === 'absolute_posix_path'),
          `relative path classified as absolute: ${relativePath}`
        );
      }
      const absolutePath = `/${['opt', 'acme', 'internal', 'file.js'].join('/')}`;
      assert(
        redactText(`source: ${absolutePath}`, false).text.includes(
          '[REDACTED:absolute_posix_path]'
        ),
        'absolute POSIX path was not redacted'
      );
    });

    check('privacy: title, body, supporting material, and generated links are scanned', () => {
      const token = `ghp_${'A'.repeat(40)}`;
      const fileUri = ['file:', '', '', 'Users', 'alice', 'evidence'].join('/');
      const serverPath = `/${['srv', 'acme', 'private.txt'].join('/')}`;
      const result = scanPublication({
        title: token,
        body: 'body',
        supporting_material: `${fileUri} and ${serverPath}`,
        generated_links: ['javascript:alert(1)']
      });
      assert(result.report.status === 'blocked', 'final scan must block');
      assert(result.report.scanned_fields.length === 4, 'scan coverage');
      assert(!result.title.includes(token), 'title secret');
      assert(!result.supporting_material.includes(serverPath), 'supporting material path');
    });

    check('privacy: secret in tester answer blocks approval but not redacted public output', () => {
      const token = `ghp_${'B'.repeat(40)}`;
      const secret = createRendered(context, validAnswers({ 'quick-summary': token }));
      assert(secret.rendered.status === 'redaction_required', 'secret state');
      const body = fs.readFileSync(secret.rendered.public_path, 'utf8');
      assert(!body.includes(token) && body.includes('[REDACTED:github_token]'), 'redaction');
      expectThrow(
        () => run(['approve', `--report-id=${secret.reportId}`, '--yes'], { context }),
        /blocked/,
        'approval should block'
      );
    });

    check('privacy: anonymized approval, preview, and copy expose no local identity', () => {
      const privatePath = [
        'C:',
        'Users',
        'UniquePrivateActor',
        'SecretWorkspace42',
        'src',
        'private.js'
      ].join('\\');
      const report = createApproved(
        context,
        validAnswers({
          'quick-summary': `The comparable result was recorded at ${privatePath}.`
        }),
        ['--anonymize']
      );
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes'
      ], {
        context,
        publisher: testAdapter('tester-a')
      });
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      const exposed = [
        status.paths.draft,
        status.paths.public,
        status.paths.discussion_title,
        status.paths.discussion_body,
        status.paths.discussion_payload,
        status.paths.publication_helpers,
        preview.preview_path
      ].map((file) => fs.readFileSync(file, 'utf8')).join('\n');
      for (const privateValue of [
        privatePath,
        'UniquePrivateActor',
        'SecretWorkspace42'
      ]) {
        assert(!exposed.includes(privateValue), `anonymized artifact leaked ${privateValue}`);
      }
      const helpers = JSON.parse(fs.readFileSync(status.paths.publication_helpers, 'utf8'));
      assert(
        helpers.discussion_url.startsWith(
          'https://github.com/pro2pilot/knowledge/discussions/new?category=field-reports'
        ),
        'trusted publication destination was redacted or changed'
      );
      const copied = run([
        'copy',
        `--report-id=${report.reportId}`,
        `--confirm-preview=${preview.preview_hash}`,
        '--yes'
      ], { context });
      assert(!copied.body.includes(privatePath), 'copy body leaked local path');
      assert(!copied.body.includes('UniquePrivateActor'), 'copy body leaked local actor');
    });

    check('translation: export scans wrapper metadata before exposing original answers', () => {
      const token = `ghp_${'C'.repeat(40)}`;
      const started = run([
        'start',
        '--new',
        '--language=es',
        '--public-language=en'
      ], { context });
      const answers = validAnswers();
      answers['quick-summary'] = {
        value: 'Resumen seguro.',
        private_note: token
      };
      run(['ingest', `--report-id=${started.report_id}`], { context, answers });
      const error = expectThrow(() => run([
        'translation-export',
        `--report-id=${started.report_id}`
      ], { context }), /removed|redacted|workspace/, 'translation export privacy gate');
      assert(!error.message.includes(token), 'translation privacy error leaked the secret');
    });

    check('translation: export generalizes internal organization labels without exposing them', () => {
      const started = run([
        'start',
        '--new',
        '--language=es',
        '--public-language=en'
      ], { context });
      run(['ingest', `--report-id=${started.report_id}`], {
        context,
        answers: validAnswers({
          'project-context': 'El sitio estaba dentro de workspace Design para client Acme Corp',
          'quick-summary': 'La evidencia ayudó a verificar el cambio.'
        })
      });
      const exported = run([
        'translation-export',
        `--report-id=${started.report_id}`
      ], { context });
      const publicSource = Object.values(exported.original_answers)
        .map((raw) => String(unwrap(raw) || ''))
        .join('\n');
      assert(exported.status === 'translation_required', exported.status);
      assert(exported.export_privacy.redactions >= 2, 'expected organization generalizations');
      assert(!/Design|Acme Corp/.test(publicSource), 'translation export leaked internal labels');
      assert(
        /larger local multi-project workspace/.test(publicSource) &&
        /internal client organization/.test(publicSource),
        'translation export did not use generic descriptions'
      );
      const status = run(['status', `--report-id=${started.report_id}`], { context });
      const internalOriginal = fs.readFileSync(status.paths.answers_original, 'utf8');
      assert(
        internalOriginal.includes('Design') && internalOriginal.includes('Acme Corp'),
        'internal original answers were not preserved'
      );
    });

    let translationReport;
    let translationExported;
    let originalBytes;
    check('translation: differing languages require a translation contract', () => {
      const started = run([
        'start',
        '--new',
        '--language=auto',
        '--public-language=en'
      ], { context });
      translationReport = started.report_id;
      run(['ingest', `--report-id=${translationReport}`], {
        context,
        answers: validAnswers({
          'quick-summary': 'La evidencia ayudó, pero todavía había una limitación.',
          'what-did-not-work': 'No fue suficiente para una tarea ambigua.'
        })
      });
      const manifest = run(['status', `--report-id=${translationReport}`], { context });
      assert(manifest.translation_status === 'translation_required', 'translation state');
      expectThrow(() => run([
        'render',
        `--report-id=${translationReport}`
      ], { context }), /approved translation|tester-approved/, 'auto render gate');
      expectThrow(() => run([
        'translation-export',
        `--report-id=${translationReport}`
      ], { context }), /source language|BCP47/, 'auto language resolution');
      expectThrow(() => run([
        'translation-export',
        `--report-id=${translationReport}`,
        '--language=not_a_locale'
      ], { context }), /BCP47/, 'invalid language tag');
      translationExported = run([
        'translation-export',
        `--report-id=${translationReport}`,
        '--language=es'
      ], { context });
      assert(translationExported.original_hash, 'original hash');
      assert(translationExported.exported_answers_hash, 'exported answers hash');
      assert(
        translationExported.source_language.toLowerCase() === 'es',
        'resolved source language'
      );
      const originalPath = manifest.paths.answers_original;
      originalBytes = fs.readFileSync(originalPath);
    });

    check('translation: ingest requires the exact privacy-stable export binding', () => {
      const started = run([
        'start',
        '--new',
        '--language=es',
        '--public-language=en'
      ], { context });
      run(['ingest', `--report-id=${started.report_id}`], {
        context,
        answers: validAnswers({ 'quick-summary': 'Una respuesta breve para traducir.' })
      });
      const translated = englishTranslatedAnswers(validAnswers());
      expectThrow(() => run([
        'translation-ingest',
        `--report-id=${started.report_id}`
      ], {
        context,
        translation: {
          original_hash: '0'.repeat(64),
          exported_answers_hash: '1'.repeat(64),
          translator: { provider: 'test-runtime', model: 'test-model', actor: 'translation-test' },
          attestations: {
            adds_no_facts: true,
            negative_answers_not_softened: true,
            uncertainty_preserved: true
          },
          translated_answers: translated
        }
      }), /Export the current privacy-stable|export/i, 'missing exact export');

      const exported = run([
        'translation-export',
        `--report-id=${started.report_id}`
      ], { context });
      const validTranslated = englishTranslatedAnswers(exported.original_answers);
      expectThrow(() => run([
        'translation-ingest',
        `--report-id=${started.report_id}`
      ], {
        context,
        translation: {
          original_hash: exported.original_hash,
          exported_answers_hash: 'f'.repeat(64),
          translator: { provider: 'test-runtime', model: 'test-model', actor: 'translation-test' },
          attestations: {
            adds_no_facts: true,
            negative_answers_not_softened: true,
            uncertainty_preserved: true
          },
          translated_answers: validTranslated
        }
      }), /exported_answers_hash|privacy-stable source export/i, 'stale export binding');
    });

    check('translation: extra facts and changed enum judgments are rejected', () => {
      const translated = {};
      for (const [id, raw] of Object.entries(translationExported.original_answers)) {
        translated[id] = unwrap(raw);
      }
      translated['keep-using'] = 'no';
      translated['new-fact'] = 'invented';
      expectThrow(() => run([
        'translation-ingest',
        `--report-id=${translationReport}`
      ], {
        context,
        translation: {
          original_hash: translationExported.original_hash,
          exported_answers_hash: translationExported.exported_answers_hash,
          attestations: {
            adds_no_facts: true,
            negative_answers_not_softened: true,
            uncertainty_preserved: true
          },
          translated_answers: translated
        }
      }), /translation|unknown|non-text/, 'invalid translation');
    });

    check('translation: translator identity is mandatory and complete', () => {
      const translated = {};
      for (const [id, raw] of Object.entries(translationExported.original_answers)) {
        translated[id] = unwrap(raw);
      }
      expectThrow(() => run([
        'translation-ingest',
        `--report-id=${translationReport}`
      ], {
        context,
        translation: {
          original_hash: translationExported.original_hash,
          exported_answers_hash: translationExported.exported_answers_hash,
          translator: { provider: 'test-runtime', actor: 'translation-test' },
          attestations: {
            adds_no_facts: true,
            negative_answers_not_softened: true,
            uncertainty_preserved: true
          },
          translated_answers: translated
        }
      }), /translator\.model/, 'incomplete translator identity');
    });

    check('translation: ingest never overwrites original answers', () => {
      const translated = englishTranslatedAnswers(translationExported.original_answers);
      const result = run([
        'translation-ingest',
        `--report-id=${translationReport}`
      ], {
        context,
        translation: {
          original_hash: translationExported.original_hash,
          exported_answers_hash: translationExported.exported_answers_hash,
          translator: {
            provider: 'test-runtime',
            model: 'junior-test-model',
            actor: 'translation-test'
          },
          attestations: {
            adds_no_facts: true,
            negative_answers_not_softened: true,
            uncertainty_preserved: true
          },
          translated_answers: translated
        }
      });
      assert(result.status === 'translation_ready', result.status);
      const status = run(['status', `--report-id=${translationReport}`], { context });
      assert(
        Buffer.compare(originalBytes, fs.readFileSync(status.paths.answers_original)) === 0,
        'original changed'
      );
      const provenance = JSON.parse(fs.readFileSync(status.paths.translation_provenance, 'utf8'));
      assert(
        provenance.exported_answers_hash === translationExported.exported_answers_hash &&
        provenance.export_privacy && provenance.export_privacy.status !== 'blocked',
        'translation provenance lost the privacy-stable export binding'
      );
    });

    check('translation: public render is blocked before tester review', () => {
      expectThrow(
        () => run(['render', `--report-id=${translationReport}`], { context }),
        /approved translation|tester-approved/,
        'render should block'
      );
    });

    check('translation: approval rejects language provenance drift before mutation', () => {
      const status = run(['status', `--report-id=${translationReport}`], { context });
      const provenanceBytes = fs.readFileSync(status.paths.translation_provenance);
      const reviewBytes = fs.readFileSync(status.paths.translation_review);
      const provenance = JSON.parse(provenanceBytes.toString('utf8'));
      provenance.target_language = 'fr';
      writeJson(status.paths.translation_provenance, provenance);
      expectThrow(() => run([
        'translation-approve',
        `--report-id=${translationReport}`,
        '--yes',
        '--tester-actor=tester-a'
      ], { context }), /pre-approval|stale|translation/, 'language drift');
      assert(
        Buffer.compare(reviewBytes, fs.readFileSync(status.paths.translation_review)) === 0,
        'failed language review mutated approval'
      );
      fs.writeFileSync(status.paths.translation_provenance, provenanceBytes);
    });

    check('translation: rehashed non-text judgment tamper is still rejected', () => {
      const status = run(['status', `--report-id=${translationReport}`], { context });
      const translatedBytes = fs.readFileSync(status.paths.answers_translated);
      const provenanceBytes = fs.readFileSync(status.paths.translation_provenance);
      const reviewBytes = fs.readFileSync(status.paths.translation_review);
      const translated = JSON.parse(translatedBytes.toString('utf8'));
      translated['accuracy-change'].value = 'clearly_improved';
      const forgedHash = canonicalHash(translated);
      const provenance = JSON.parse(provenanceBytes.toString('utf8'));
      const review = JSON.parse(reviewBytes.toString('utf8'));
      provenance.translated_hash = forgedHash;
      review.translated_hash = forgedHash;
      writeJson(status.paths.answers_translated, translated);
      writeJson(status.paths.translation_provenance, provenance);
      writeJson(status.paths.translation_review, review);
      expectThrow(() => run([
        'translation-approve',
        `--report-id=${translationReport}`,
        '--yes',
        '--tester-actor=tester-a'
      ], { context }), /non-text|translation/, 'rehashed judgment tamper');
      fs.writeFileSync(status.paths.answers_translated, translatedBytes);
      fs.writeFileSync(status.paths.translation_provenance, provenanceBytes);
      fs.writeFileSync(status.paths.translation_review, reviewBytes);
    });

    check('translation: approval requires an explicit independent tester actor', () => {
      expectThrow(() => run([
        'translation-approve',
        `--report-id=${translationReport}`,
        '--yes'
      ], { context }), /tester-actor/, 'explicit reviewer');
      expectThrow(() => run([
        'translation-approve',
        `--report-id=${translationReport}`,
        '--yes',
        '--tester-actor=translation-test'
      ], { context }), /independent/, 'independent reviewer');
      expectThrow(() => run([
        'translation-approve',
        `--report-id=${translationReport}`,
        '--yes',
        '--tester-actor=bad actor'
      ], { context }), /valid|tester-actor/, 'invalid reviewer actor');
    });

    check('translation: committed approval crash recovers review and manifest together', () => {
      const reportId = createTranslationReady(context);
      expectThrow(() => run([
        'translation-approve',
        `--report-id=${reportId}`,
        '--yes',
        '--tester-actor=tester-transaction'
      ], {
        context,
        translationApprovalFaultAt: 'after_promote_0'
      }), /after_promote_0/, 'translation approval fault');
      const recovered = run([
        'translation-approve',
        `--report-id=${reportId}`,
        '--yes',
        '--tester-actor=tester-transaction'
      ], { context });
      assert(
        recovered.status === 'translation_approved' && recovered.idempotent === true,
        'translation approval did not recover idempotently'
      );
      const status = run(['status', `--report-id=${reportId}`], { context });
      const manifest = JSON.parse(fs.readFileSync(status.paths.manifest, 'utf8'));
      const review = JSON.parse(fs.readFileSync(status.paths.translation_review, 'utf8'));
      assert(
        manifest.translation.status === 'translation_approved' &&
        review.status === 'translation_approved' &&
        manifest.translation.reviewer === 'tester-transaction' &&
        review.reviewer === 'tester-transaction' &&
        manifest.translation.approved_at === review.approved_at,
        'translation approval recovered a mixed state'
      );
    });

    check('translation: tester approval enables an evidence-backed public claim', () => {
      run([
        'translation-approve',
        `--report-id=${translationReport}`,
        '--yes',
        '--tester-actor=tester-a'
      ], { context });
      const rendered = run(['render', `--report-id=${translationReport}`], { context });
      const body = fs.readFileSync(rendered.public_path, 'utf8');
      assert(body.includes('agent-assisted and approved by the tester'), 'translation claim');
      assert(body.includes('English publication version'), 'English publication wording');
      const status = run(['status', `--report-id=${translationReport}`], { context });
      const review = JSON.parse(fs.readFileSync(status.paths.translation_review, 'utf8'));
      assert(
        review.status === 'translation_approved' &&
        review.approved_by_tester &&
        review.reviewer === 'tester-a' &&
        review.translator.actor === 'translation-test',
        'review'
      );
    });

    check('translation: tampered identity provenance blocks public rendering', () => {
      const status = run(['status', `--report-id=${translationReport}`], { context });
      const bytes = fs.readFileSync(status.paths.translation_provenance);
      const provenance = JSON.parse(bytes.toString('utf8'));
      provenance.translator.actor = 'tester-a';
      writeJson(status.paths.translation_provenance, provenance);
      expectThrow(
        () => run(['render', `--report-id=${translationReport}`], { context }),
        /identities|translation/,
        'tampered identity'
      );
      fs.writeFileSync(status.paths.translation_provenance, bytes);
    });

    check('translation: tampered safety attestations block public rendering', () => {
      const status = run(['status', `--report-id=${translationReport}`], { context });
      const bytes = fs.readFileSync(status.paths.translation_provenance);
      const provenance = JSON.parse(bytes.toString('utf8'));
      provenance.attestations.adds_no_facts = false;
      writeJson(status.paths.translation_provenance, provenance);
      expectThrow(
        () => run(['render', `--report-id=${translationReport}`], { context }),
        /identities|translation/,
        'tampered attestations'
      );
      fs.writeFileSync(status.paths.translation_provenance, bytes);
    });

    check('translation: resolving auto to the public language needs no translation', () => {
      const started = run([
        'start',
        '--new',
        '--language=auto',
        '--public-language=en'
      ], { context });
      run(['ingest', `--report-id=${started.report_id}`], {
        context,
        answers: validAnswers()
      });
      const resolved = run([
        'translation-export',
        `--report-id=${started.report_id}`,
        '--language=en'
      ], { context });
      assert(resolved.status === 'translation_not_required', resolved.status);
      attachTaskResults(context, started.report_id);
      const rendered = run(['render', `--report-id=${started.report_id}`], { context });
      assert(rendered.status === 'draft_ready', rendered.status);
      const status = run(['status', `--report-id=${started.report_id}`], { context });
      const manifestBytes = fs.readFileSync(status.paths.manifest);
      const manifest = JSON.parse(manifestBytes.toString('utf8'));
      manifest.translation.status = 'translation_approved';
      manifest.translation.approved_by_tester = true;
      writeJson(status.paths.manifest, manifest);
      const forged = run(['render', `--report-id=${started.report_id}`], { context });
      const body = fs.readFileSync(forged.public_path, 'utf8');
      assert(
        !body.includes('agent-assisted and approved by the tester'),
        'same-language forged translation claim'
      );
      fs.writeFileSync(status.paths.manifest, manifestBytes);
    });

    check('approval: unchanged render passes and records one exact tester actor', () => {
      const report = createRendered(context);
      const approved = run([
        'approve',
        `--report-id=${report.reportId}`,
        '--yes',
        '--tester-actor=tester-a'
      ], { context });
      assert(
        approved.status === 'approved' &&
        approved.approved_by === 'tester-a' &&
        approved.body_sha256,
        'unchanged render approval'
      );
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      const manifest = JSON.parse(fs.readFileSync(status.paths.manifest, 'utf8'));
      const payload = JSON.parse(fs.readFileSync(status.paths.discussion_payload, 'utf8'));
      assert(
        manifest.approval.approved_by === 'tester-a' &&
        payload.approved_by === 'tester-a',
        'approval actor binding'
      );
    });

    check('approval: missing or invalid tester actor is atomic', () => {
      for (const actorArg of [
        null,
        '--tester-actor=bad actor',
        '--tester-actor=bad-'
      ]) {
        const report = createRendered(context);
        const status = run(['status', `--report-id=${report.reportId}`], { context });
        const manifestBefore = fs.readFileSync(status.paths.manifest);
        const payloadBefore = fs.readFileSync(status.paths.discussion_payload);
        const argv = ['approve', `--report-id=${report.reportId}`, '--yes'];
        if (actorArg) argv.push(actorArg);
        expectThrow(() => run(argv, { context }), /actor|GitHub login/, 'approval actor');
        assert(
          Buffer.compare(manifestBefore, fs.readFileSync(status.paths.manifest)) === 0,
          'failed actor approval mutated manifest'
        );
        assert(
          Buffer.compare(payloadBefore, fs.readFileSync(status.paths.discussion_payload)) === 0,
          'failed actor approval mutated payload'
        );
      }
    });

    check('approval: committed crash recovers payload and manifest together', () => {
      const report = createRendered(context);
      expectThrow(() => run([
        'approve',
        `--report-id=${report.reportId}`,
        '--yes',
        '--tester-actor=tester-transaction'
      ], {
        context,
        approvalFaultAt: 'after_promote_0'
      }), /after_promote_0/, 'approval fault');
      const recovered = run([
        'approve',
        `--report-id=${report.reportId}`,
        '--yes',
        '--tester-actor=tester-transaction'
      ], { context });
      assert(
        recovered.status === 'approved' && recovered.idempotent === true,
        'approval did not recover idempotently'
      );
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      const manifest = JSON.parse(fs.readFileSync(status.paths.manifest, 'utf8'));
      const payload = JSON.parse(fs.readFileSync(status.paths.discussion_payload, 'utf8'));
      assert(
        manifest.approval.approved_by === 'tester-transaction' &&
        payload.approved_by === 'tester-transaction' &&
        manifest.approval.approved_at === payload.approved_at &&
        manifest.approval.content_hash === fieldReportState.hashFiles(status.paths),
        'approval recovered a mixed or unbound state'
      );
    });

    check('approval: one report cannot recover another live preparing transaction', () => {
      const first = createRendered(context);
      const second = createRendered(context);
      expectThrow(() => run([
        'approve',
        `--report-id=${first.reportId}`,
        '--yes',
        '--tester-actor=tester-isolated'
      ], {
        context,
        approvalFaultAt: 'after_initial_manifest'
      }), /after_initial_manifest/, 'preparing approval fault');
      const transactionsRoot = path.join(
        context.stateRoot,
        'maintenance',
        'transactions'
      );
      const firstPrefix = `field-report-approval-${first.reportId}-`;
      const firstTransaction = fs.readdirSync(transactionsRoot)
        .find((name) => name.startsWith(firstPrefix));
      assert(firstTransaction, 'preparing transaction was not retained');
      const firstTransactionRoot = path.join(transactionsRoot, firstTransaction);
      assert(
        !fs.existsSync(path.join(firstTransactionRoot, 'terminal.json')),
        'preparing transaction was already terminal'
      );
      const secondStatus = run(['status', `--report-id=${second.reportId}`], { context });
      assert(secondStatus.status === 'draft_ready', 'unrelated report status changed');
      assert(
        !fs.existsSync(path.join(firstTransactionRoot, 'terminal.json')),
        'unrelated report recovered a live foreign transaction'
      );
      const recovered = run([
        'approve',
        `--report-id=${first.reportId}`,
        '--yes',
        '--tester-actor=tester-isolated'
      ], { context });
      assert(recovered.status === 'approved', 'own report did not recover and retry');
      const terminal = JSON.parse(fs.readFileSync(
        path.join(firstTransactionRoot, 'terminal.json'),
        'utf8'
      ));
      assert(
        terminal.status === 'rolled_back' &&
        terminal.recovery_action === 'restored_old_state',
        'own preparing transaction did not roll back safely'
      );
    });

    check('approval: descriptor drift is rejected before approval', () => {
      const cases = [
        ['payload report', 'discussion_payload', (value) => { value.report_id = 'fr_20000101_deadbeef'; }],
        ['payload repository', 'discussion_payload', (value) => { value.repository = 'other/repo'; }],
        ['payload category', 'discussion_payload', (value) => { value.category_slug = 'other'; }],
        ['payload title', 'discussion_payload', (value) => { value.title += ' changed'; }],
        ['payload hash', 'discussion_payload', (value) => { value.body_sha256 = '0'.repeat(64); }],
        ['helper URL', 'publication_helpers', (value) => {
          value.discussion_url = 'https://github.com/other/repo/discussions/new?category=other';
        }],
        ['helper title path', 'publication_helpers', (value) => { value.title_path = '../title'; }],
        ['helper body path', 'publication_helpers', (value) => { value.body_path = '../body'; }]
      ];
      for (const [name, pathKey, mutate] of cases) {
        const report = createRendered(context);
        const status = run(['status', `--report-id=${report.reportId}`], { context });
        const value = JSON.parse(fs.readFileSync(status.paths[pathKey], 'utf8'));
        mutate(value);
        writeJson(status.paths[pathKey], value);
        expectThrow(() => run([
          'approve',
          `--report-id=${report.reportId}`,
          '--yes',
          '--tester-actor=tester-a'
        ], { context }), /drifted/, name);
        const after = run(['status', `--report-id=${report.reportId}`], { context });
        assert(!after.approved, `${name} became approved`);
      }
    });

    check('publication: external reuse permission cannot substitute for GitHub permission', () => {
      const localOnly = createApproved(context, validAnswers({
        'github-publication-permission': 'local_draft_only',
        'publication-permission': 'link_and_quote_with_attribution'
      }));
      expectThrow(() => run([
        'publish',
        `--report-id=${localOnly.reportId}`,
        '--dry-run',
        '--yes'
      ], {
        context,
        publisher: testAdapter()
      }), /local draft/, 'permission split');
    });

    check('publication: copy/open cannot bypass the actor-bound preview', () => {
      const report = createApproved(context);
      let opened = false;
      expectThrow(() => run([
        'open',
        `--report-id=${report.reportId}`,
        '--yes'
      ], {
        context,
        openUrl() { opened = true; }
      }), /actor-bound publication preview/, 'open before preview');
      expectThrow(() => run([
        'copy',
        `--report-id=${report.reportId}`
      ], { context }), /actor-bound publication preview/, 'copy before preview');
      assert(!opened, 'pre-preview helper opened a browser');
    });

    check('publication: a different actor cannot inherit another tester approval', () => {
      const report = createApproved(context, validAnswers(), [], 'tester-a');
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      const manifestBefore = fs.readFileSync(status.paths.manifest);
      expectThrow(() => run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes',
        '--tester-actor=tester-b'
      ], {
        context,
        publisher: testAdapter('tester-b')
      }), /approved actor|does not match/, 'cross-actor preview');
      assert(
        Buffer.compare(manifestBefore, fs.readFileSync(status.paths.manifest)) === 0,
        'cross-actor preview mutated manifest'
      );
      assert(
        !fs.existsSync(status.paths.publication_preview),
        'cross-actor preview wrote a preview receipt'
      );
    });

    check('publication: safe anonymized destination remains previewable', () => {
      const report = createApproved(context, validAnswers(), ['--anonymize']);
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes'
      ], { context, publisher: testAdapter('tester-a') });
      assert(preview.status === 'preview_ready', 'anonymized preview blocked');
    });

    let publicationReport;
    let publicationPreview;
    check('publication: preview binds actor, target, title, body, and redaction', () => {
      publicationReport = createApproved(context);
      publicationPreview = run([
        'publish',
        `--report-id=${publicationReport.reportId}`,
        '--dry-run',
        '--yes'
      ], {
        context,
        publisher: testAdapter('tester-a')
      });
      assert(publicationPreview.status === 'preview_ready', publicationPreview.status);
      const preview = JSON.parse(fs.readFileSync(publicationPreview.preview_path, 'utf8'));
      for (const key of [
        'authenticated_actor', 'target_repository', 'discussion_category', 'title',
        'title_sha256', 'source_body_sha256', 'body_sha256', 'body_hash',
        'payload_sha256', 'idempotency_key', 'approval_content_sha256',
        'approval_render_sha256', 'report_id', 'timestamp',
        'redaction_status', 'preview_hash'
      ]) assert(Object.prototype.hasOwnProperty.call(preview, key), key);
      assert(preview.authenticated_actor === 'tester-a', 'actor');
      assert(preview.preview_hash === publicationPreview.preview_hash, 'hash');
    });

    check('publication: default dry-run is offline and explicit remote verification is opt-in', () => {
      const report = createApproved(context);
      let authenticateCalls = 0;
      const adapter = {
        testOnly: true,
        authenticate(payload) {
          authenticateCalls += 1;
          return { actor: 'tester-a', repository: payload.repository, category_slug: payload.category_slug };
        },
        lookup() { return null; },
        publish() { throw new Error('publication must not run during dry-run'); }
      };
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes'
      ], { context, publisher: adapter });
      assert(preview.status === 'preview_ready', preview.status);
      assert(authenticateCalls === 0, 'offline dry-run contacted the publisher');
      const remotePreview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes',
        '--verify-remote'
      ], { context, publisher: adapter });
      assert(remotePreview.status === 'preview_ready', remotePreview.status);
      assert(authenticateCalls === 1, 'explicit remote verification was not used');
    });

    check('publication: --yes without exact preview hash is insufficient', () => {
      expectThrow(() => run([
        'publish',
        `--report-id=${publicationReport.reportId}`,
        '--yes'
      ], {
        context,
        publisher: testAdapter('tester-a')
      }), /confirm-preview/, 'preview hash required');
    });

    check('publication: final explicit actor cannot contradict the bound preview', () => {
      const status = run(['status', `--report-id=${publicationReport.reportId}`], { context });
      const remote = { discussions: [], lookup_calls: 0, publish_calls: 0 };
      expectThrow(() => run([
        'publish',
        `--report-id=${publicationReport.reportId}`,
        '--yes',
        '--tester-actor=tester-b',
        `--confirm-preview=${publicationPreview.preview_hash}`
      ], {
        context,
        publisher: testAdapter('tester-a', { remote })
      }), /approved actor|does not match/, 'contradictory final actor');
      assert(remote.lookup_calls === 0 && remote.publish_calls === 0, 'actor mismatch reached remote');
      assert(!fs.existsSync(status.paths.publication), 'actor mismatch wrote publication journal');
    });

    check('publication: authenticated actor mismatch is blocked', () => {
      expectThrow(() => run([
        'publish',
        `--report-id=${publicationReport.reportId}`,
        '--yes',
        `--confirm-preview=${publicationPreview.preview_hash}`
      ], {
        context,
        publisher: testAdapter('tester-b')
      }), /actor/, 'actor mismatch');
    });

    check('publication: manifest target drift cannot retarget an approval', () => {
      const report = createApproved(context);
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      const manifest = JSON.parse(fs.readFileSync(status.paths.manifest, 'utf8'));
      manifest.target = { repository: 'other/repository', category_slug: 'field-reports' };
      writeJson(status.paths.manifest, manifest);
      let authenticateCalls = 0;
      const adapter = {
        testOnly: true,
        authenticate() {
          authenticateCalls += 1;
          return {
            actor: 'tester-a',
            repository: 'other/repository',
            category_slug: 'field-reports'
          };
        }
      };
      expectThrow(() => run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes'
      ], { context, publisher: adapter }), /payload|helpers|identity|target|body|marker/, 'target drift');
      assert(authenticateCalls === 0, 'adapter saw a retargeted approval');
    });

    check('publication: remote result must include the exact repository and category', () => {
      for (const missing of ['repository', 'category_slug']) {
        const report = createApproved(context);
        const remote = { discussions: [], lookup_calls: 0, publish_calls: 0 };
        const adapter = testAdapter('tester-a', {
          remote,
          resultExtras: { [missing]: undefined }
        });
        const preview = run([
          'publish',
          `--report-id=${report.reportId}`,
          '--dry-run',
          '--yes'
        ], { context, publisher: adapter });
        expectThrow(() => run([
          'publish',
          `--report-id=${report.reportId}`,
          '--yes',
          `--confirm-preview=${preview.preview_hash}`
        ], { context, publisher: adapter }), /target|outcome|match/, `missing ${missing}`);
        const unresolved = run(['status', `--report-id=${report.reportId}`], { context });
        assert(unresolved.status === 'reconciliation_required', `${missing} state`);
        assert(remote.publish_calls === 1, `${missing} create count`);
      }
    });

    check('publication: explicit test-only publisher works when CI=true', () => {
      process.env.CI = 'true';
      const result = run([
        'publish',
        `--report-id=${publicationReport.reportId}`,
        '--yes',
        `--confirm-preview=${publicationPreview.preview_hash}`
      ], {
        context,
        publisher: testAdapter('tester-a')
      });
      assert(result.status === 'published', result.status);
    });

    check('publication: common CI truthy variants are recognized', () => {
      for (const value of ['1', ' true ', 'YES', 'on']) {
        assert(fieldReportTest.ciEnvironmentDetected({ CI: value }), `CI=${value}`);
      }
      for (const key of ['GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'BUILDKITE', 'TF_BUILD']) {
        assert(fieldReportTest.ciEnvironmentDetected({ [key]: 'true' }), key);
      }
      assert(fieldReportTest.ciEnvironmentDetected({ JENKINS_URL: 'https://ci.invalid' }), 'Jenkins');
      assert(fieldReportTest.ciEnvironmentDetected({ BUILD_BUILDID: '123' }), 'Azure Pipelines');
      assert(!fieldReportTest.ciEnvironmentDetected({ CI: 'false' }), 'CI=false');
    });

    check('publication: duplicate publication is blocked', () => {
      expectThrow(() => run([
        'publish',
        `--report-id=${publicationReport.reportId}`,
        '--yes',
        `--confirm-preview=${publicationPreview.preview_hash}`
      ], {
        context,
        publisher: testAdapter('tester-a')
      }), /already published|duplicate/, 'duplicate');
    });

    check('publication: unknown response after remote success reconciles without duplicate', () => {
      const report = createApproved(context, validAnswers(), [], 'tester-crash');
      const remote = { discussions: [], lookup_calls: 0, publish_calls: 0 };
      const adapter = testAdapter('tester-crash', {
        remote,
        outcomeUnknownAfterCreate: true
      });
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes',
        '--tester-actor=tester-crash'
      ], { context, publisher: adapter });
      expectThrow(() => run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], { context, publisher: adapter }), /uncertain|Reconcile/, 'unknown outcome');
      const unresolved = run(['status', `--report-id=${report.reportId}`], { context });
      assert(unresolved.status === 'reconciliation_required', unresolved.status);
      const journal = JSON.parse(fs.readFileSync(unresolved.paths.publication, 'utf8'));
      assert(
        journal.schema_version === 'knowledge-field-report-publication.v3' &&
        journal.status === 'reconciliation_required' &&
        journal.idempotency_key &&
        journal.payload_sha256,
        'write-ahead journal'
      );
      const recovered = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], { context, publisher: adapter });
      assert(recovered.status === 'published' && recovered.reconciled, 'reconciled');
      assert(remote.publish_calls === 1, `duplicate creates: ${remote.publish_calls}`);
      assert(remote.lookup_calls === 1, `lookup calls: ${remote.lookup_calls}`);
      const receipt = JSON.parse(fs.readFileSync(unresolved.paths.publication, 'utf8'));
      for (const key of [
        'preview_hash',
        'idempotency_key',
        'approval_content_sha256',
        'title_sha256',
        'source_body_sha256',
        'body_sha256',
        'payload_sha256'
      ]) {
        assert(receipt[key] === journal[key], `${key} changed`);
      }
    });

    check('publication: unknown outcome plus repeated null lookup never recreates', () => {
      const report = createApproved(context, validAnswers(), [], 'tester-null');
      const remote = { discussions: [], lookup_calls: 0, publish_calls: 0 };
      const failing = testAdapter('tester-null', { remote, fail: true });
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes',
        '--tester-actor=tester-null'
      ], { context, publisher: failing });
      expectThrow(() => run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], { context, publisher: failing }), /uncertain|Reconcile/, 'initial unknown');
      const reconciliation = testAdapter('tester-null', { remote });
      for (let attempt = 0; attempt < 2; attempt += 1) {
        expectThrow(() => run([
          'publish',
          `--report-id=${report.reportId}`,
          '--yes',
          `--confirm-preview=${preview.preview_hash}`
        ], { context, publisher: reconciliation }), /unknown|blocked|match|visible/i, `null retry ${attempt}`);
        const status = run(['status', `--report-id=${report.reportId}`], { context });
        assert(status.status === 'reconciliation_required', `null retry state ${attempt}`);
      }
      assert(remote.publish_calls === 1, `null lookup recreated ${remote.publish_calls} times`);
      assert(remote.lookup_calls === 2, `null lookup attempts: ${remote.lookup_calls}`);
    });

    check('publication: ambiguous or hash-mismatched reconciliation never creates again', () => {
      for (const mode of ['lookup-failure', 'content-mismatch']) {
        const report = createApproved(
          context,
          validAnswers(),
          [],
          `tester-${mode}`
        );
        const remote = { discussions: [], lookup_calls: 0, publish_calls: 0 };
        const initialAdapter = testAdapter(`tester-${mode}`, {
          remote,
          outcomeUnknownAfterCreate: true
        });
        const preview = run([
          'publish',
          `--report-id=${report.reportId}`,
          '--dry-run',
          '--yes',
          `--tester-actor=tester-${mode}`
        ], { context, publisher: initialAdapter });
        expectThrow(() => run([
          'publish',
          `--report-id=${report.reportId}`,
          '--yes',
          `--confirm-preview=${preview.preview_hash}`
        ], { context, publisher: initialAdapter }), /uncertain|Reconcile/, `${mode} initial`);
        if (mode === 'content-mismatch') {
          remote.discussions[0].body += '\nremote edit';
        }
        const retryAdapter = mode === 'lookup-failure'
          ? testAdapter(`tester-${mode}`, { remote, lookupFail: true })
          : initialAdapter;
        expectThrow(() => run([
          'publish',
          `--report-id=${report.reportId}`,
          '--yes',
          `--confirm-preview=${preview.preview_hash}`
        ], { context, publisher: retryAdapter }), /reconcil|match|complete/i, `${mode} retry`);
        assert(remote.publish_calls === 1, `${mode} duplicate creates: ${remote.publish_calls}`);
        const unresolved = run(['status', `--report-id=${report.reportId}`], { context });
        assert(unresolved.status === 'reconciliation_required', `${mode} state`);
      }
    });

    check('publication: published journal finalizes a stale manifest without network', () => {
      const report = createApproved(context, validAnswers(), [], 'tester-local-finalize');
      const adapter = testAdapter('tester-local-finalize');
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes',
        '--tester-actor=tester-local-finalize'
      ], { context, publisher: adapter });
      run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], { context, publisher: adapter });
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      const manifest = JSON.parse(fs.readFileSync(status.paths.manifest, 'utf8'));
      manifest.status = 'publishing';
      delete manifest.published_at;
      writeJson(status.paths.manifest, manifest);
      const noNetworkAdapter = {
        testOnly: true,
        authenticate() {
          throw new Error('network must not be used');
        }
      };
      const recovered = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], { context, publisher: noNetworkAdapter });
      assert(recovered.status === 'published' && recovered.reconciled, 'local finalize');
    });

    check('publication: adapter result cannot overwrite authoritative receipt provenance', () => {
      const report = createApproved(context, validAnswers(), [], 'tester-authoritative');
      const adapter = testAdapter('tester-authoritative', {
        resultExtras: {
          schema_version: 'forged',
          status: 'forged',
          preview_hash: 'forged',
          idempotency_key: 'forged'
        }
      });
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes',
        '--tester-actor=tester-authoritative'
      ], { context, publisher: adapter });
      run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], { context, publisher: adapter });
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      const receipt = JSON.parse(fs.readFileSync(status.paths.publication, 'utf8'));
      assert(receipt.schema_version === 'knowledge-field-report-publication.v3', 'schema');
      assert(receipt.status === 'published', 'status');
      assert(receipt.preview_hash === preview.preview_hash, 'preview provenance');
      assert(receipt.idempotency_key !== 'forged', 'idempotency provenance');
    });

    check('publication: real/non-test publisher is blocked in CI', () => {
      const report = createApproved(context, validAnswers(), [], 'tester-real');
      const adapter = testAdapter('tester-real', { testOnly: false });
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes',
        '--tester-actor=tester-real'
      ], { context, publisher: adapter });
      expectThrow(() => run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], {
        context,
        publisher: adapter,
        testOnlyPublisher: true
      }), /blocked in CI/, 'CI boolean bypass');
    });

    check('publication: edits after approval invalidate approval and preview', () => {
      process.env.CI = '';
      const report = createApproved(context);
      const status = run(['status', `--report-id=${report.reportId}`], { context });
      fs.appendFileSync(status.paths.discussion_body, '\npost-approval edit\n');
      expectThrow(() => run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes'
      ], {
        context,
        publisher: testAdapter()
      }), /changed after approval/, 'content edit');
      const after = run(['status', `--report-id=${report.reportId}`], { context });
      assert(!after.approved && after.preview_hash === null, 'invalidation');
    });

    check('publication: approval hash binds internal draft and provenance artifacts', () => {
      for (const pathKey of ['draft', 'translation_provenance']) {
        const report = createApproved(context);
        const status = run(['status', `--report-id=${report.reportId}`], { context });
        fs.appendFileSync(status.paths[pathKey], '\npost-approval provenance edit\n');
        expectThrow(() => run([
          'publish',
          `--report-id=${report.reportId}`,
          '--dry-run',
          '--yes'
        ], {
          context,
          publisher: testAdapter()
        }), /changed after approval/, `${pathKey} hash binding`);
      }
    });

    check('approval: semantic facts exclude collection timestamps but retain semantic values', () => {
      const started = run(['start', '--new'], { context });
      const reportPaths = fieldReportState.paths(context, started.report_id);
      const original = JSON.parse(fs.readFileSync(reportPaths.facts, 'utf8'));
      const before = fieldReportState.semanticFactsHash(reportPaths.facts);
      original.collected_at = '2099-01-01T00:00:00.000Z';
      for (const item of Object.values(original.values || {})) item.collected_at = '2099-01-01T00:00:00.000Z';
      writeJson(reportPaths.facts, original);
      assert(fieldReportState.semanticFactsHash(reportPaths.facts) === before, 'timestamp changed semantic facts identity');
      original.values.knowledge_version.value = 'semantic-drift';
      writeJson(reportPaths.facts, original);
      assert(fieldReportState.semanticFactsHash(reportPaths.facts) !== before, 'semantic value did not change facts identity');
    });

    check('publication: post-preview mutation cannot reach copy or open side effects', () => {
      for (const command of ['copy', 'open']) {
        const report = createApproved(context);
        const preview = run([
          'publish',
          `--report-id=${report.reportId}`,
          '--dry-run',
          '--yes'
        ], {
          context,
          publisher: testAdapter()
        });
        const status = run(['status', `--report-id=${report.reportId}`], { context });
        const secret = `ghp_${'0123456789abcdefghijklmnopqrstuvwxyzABCD'}`;
        fs.appendFileSync(
          status.paths.discussion_body,
          `\npost-preview token ${secret}\n`,
          'utf8'
        );
        let opened = false;
        const error = expectThrow(() => run([
          command,
          `--report-id=${report.reportId}`,
          `--confirm-preview=${preview.preview_hash}`,
          '--yes'
        ], {
          context,
          openUrl() { opened = true; }
        }), /changed after approval/, `${command} accepted a post-preview mutation`);
        assert(!error.message.includes(secret), `${command} error leaked mutated secret`);
        assert(!opened, `${command} opened a URL after mutation`);
        assert(!fs.existsSync(status.paths.publication), `${command} wrote a publication journal`);
      }
    });

    check('routing: live routing is revalidated before render, approval, preview, and final publication', () => {
      const staleRoutingId = 'a'.repeat(64);
      const setStaleRouting = (reportId) => {
        const reportPaths = fieldReportState.paths(context, reportId);
        const manifest = fieldReportState.load(context, reportId);
        manifest.routing_task_id = staleRoutingId;
        writeJson(reportPaths.manifest, manifest);
      };

      const renderOnly = run(['start', '--new', `--routing-task-id=${staleRoutingId}`], { context });
      run(['ingest', `--report-id=${renderOnly.report_id}`], { context, answers: validAnswers() });
      expectThrow(
        () => run(['render', `--report-id=${renderOnly.report_id}`], { context }),
        /live routing state/,
        'stale routing must block render'
      );

      const approved = createApproved(context);
      setStaleRouting(approved.reportId);
      expectThrow(
        () => run(['approve', `--report-id=${approved.reportId}`, '--yes', '--tester-actor=tester-a'], { context }),
        /live routing state/,
        'stale routing must block idempotent approval'
      );

      const previewOnly = createApproved(context);
      setStaleRouting(previewOnly.reportId);
      expectThrow(
        () => run(['publish', `--report-id=${previewOnly.reportId}`, '--dry-run', '--yes'], { context }),
        /live routing state/,
        'stale routing must block preview'
      );

      const finalOnly = createApproved(context);
      const preview = run([
        'publish', `--report-id=${finalOnly.reportId}`, '--dry-run', '--yes'
      ], { context });
      setStaleRouting(finalOnly.reportId);
      expectThrow(
        () => run([
          'publish', `--report-id=${finalOnly.reportId}`, '--yes',
          `--confirm-preview=${preview.preview_hash}`
        ], { context, publisher: testAdapter() }),
        /live routing state/,
        'stale routing must block final publication'
      );
    });

    check('workflow: cancel is terminal and idempotent', () => {
      const started = run(['start', '--new'], { context });
      const cancelled = run([
        'cancel',
        `--report-id=${started.report_id}`,
        '--reason=usability-test'
      ], { context });
      assert(cancelled.status === 'cancelled', cancelled.status);
      const again = run(['cancel', `--report-id=${started.report_id}`], { context });
      assert(again.status === 'cancelled', 'idempotent cancel');
      expectThrow(
        () => run(['render', `--report-id=${started.report_id}`], { context }),
        /cancelled/,
        'cancel terminal'
      );
    });

    check('usability: copy and Discussion URL helpers are available', () => {
      const report = createApproved(context);
      const remote = { discussions: [], lookup_calls: 0, publish_calls: 0 };
      const adapter = testAdapter('tester-a', { remote });
      const preview = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--dry-run',
        '--yes'
      ], { context, publisher: adapter });
      const copied = run([
        'copy',
        `--report-id=${report.reportId}`,
        `--confirm-preview=${preview.preview_hash}`
      ], { context });
      assert(
        copied.title &&
        copied.body.includes(`knowledge-field-report-idempotency:${copied.idempotency_key}`) &&
        (copied.body.match(/knowledge-field-report-idempotency:/g) || []).length === 1,
        'copy payload'
      );
      const pending = run(['status', `--report-id=${report.reportId}`], { context });
      assert(pending.status === 'reconciliation_required', 'manual copy reconciliation gate');
      expectThrow(() => run([
        'copy',
        `--report-id=${report.reportId}`,
        `--confirm-preview=${preview.preview_hash}`
      ], { context }), /already exposed|reconcile/, 'second manual copy');
      let opened = null;
      const result = run([
        'open',
        `--report-id=${report.reportId}`,
        '--yes'
      ], {
        context,
        openUrl(value) { opened = value; }
      });
      assert(result.opened && opened.includes('/discussions/new'), 'open helper');
      remote.discussions.push({
        discussion_id: 'manual-discussion',
        url: 'https://example.test/discussions/manual',
        actor: 'tester-a',
        repository: 'pro2pilot/knowledge',
        category_slug: 'field-reports',
        title: copied.title,
        body: copied.body
      });
      const reconciled = run([
        'publish',
        `--report-id=${report.reportId}`,
        '--yes',
        `--confirm-preview=${preview.preview_hash}`
      ], { context, publisher: adapter });
      assert(reconciled.status === 'published' && reconciled.reconciled, 'manual reconciliation');
      assert(remote.publish_calls === 0, 'manual reconciliation called create');
      assert(remote.lookup_calls === 1, 'manual reconciliation lookup count');
    });

    check('usability: Windows URL opening avoids command-shell interpretation', () => {
      const url = 'https://github.com/owner/repository/discussions/categories/field-reports';
      const command = fieldReportTest.openCommand(url, 'win32');
      assert(command.file === 'rundll32.exe', JSON.stringify(command));
      assert(
        JSON.stringify(command.args) === JSON.stringify(['url.dll,FileProtocolHandler', url]),
        JSON.stringify(command.args)
      );
      assert(!/cmd(?:\.exe)?$/i.test(command.file), 'Windows opener uses a command shell');
    });

    check('locking: a stale-looking live local owner is not reclaimed', () => {
      const root = path.join(temporaryRoot, 'locks', 'live-local');
      ensureDir(root);
      const request = { context: { stateRoot: root }, rootKind: 'state', rootPath: root, lockName: 'field-report', purpose: LOCKS['field-report'].purpose, timeoutMs: 50, staleMs: 1, retryMs: 2 };
      const handle = acquireContainedLock(request);
      const old = new Date(Date.now() - 60_000);
      fs.utimesSync(handle.path, old, old);
      expectThrow(
        () => acquireContainedLock({ ...request, timeoutMs: 20 }),
        /Lock "field-report" is held/,
        'live lock was reclaimed'
      );
      handle.release();
      assert(!fs.existsSync(handle.path), 'owned live lock was not released');
    });

    check('locking: a stale foreign-host owner is preserved when liveness is unknown', () => {
      const root = path.join(temporaryRoot, 'locks', 'foreign-host');
      ensureDir(root);
      const request = { context: { stateRoot: root }, rootKind: 'state', rootPath: root, lockName: 'field-report', purpose: LOCKS['field-report'].purpose, timeoutMs: 20, staleMs: 1 };
      const seeded = acquireContainedLock(request);
      const ownerPath = path.join(seeded.path, 'owner.json');
      const owner = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
      owner.pid = 424242;
      owner.hostname = 'remote-build-host.invalid';
      owner.agent_id = 'remote-agent';
      owner.process_started_at = new Date(Date.now() - 60_000).toISOString();
      owner.acquired_at = new Date(Date.now() - 60_000).toISOString();
      writeJson(ownerPath, owner);
      const old = new Date(Date.now() - 60_000);
      fs.utimesSync(seeded.path, old, old);
      expectThrow(
        () => acquireContainedLock(request),
        /Lock "field-report" is held/,
        'foreign-host lock was reclaimed'
      );
      const current = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
      assert(current.lock_id === owner.lock_id, 'foreign owner changed');
      fs.rmSync(seeded.path, { recursive: true, force: true });
    });

    check('locking: a confirmed dead local owner is reclaimed atomically', () => {
      const root = path.join(temporaryRoot, 'locks', 'dead-local');
      ensureDir(root);
      const request = { context: { stateRoot: root }, rootKind: 'state', rootPath: root, lockName: 'field-report', purpose: LOCKS['field-report'].purpose, timeoutMs: 100, staleMs: 1, retryMs: 2 };
      const seeded = acquireContainedLock(request);
      const ownerPath = path.join(seeded.path, 'owner.json');
      const owner = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
      const deadLockId = owner.lock_id;
      owner.pid = 2147483647;
      owner.hostname = os.hostname();
      owner.agent_id = 'dead-agent';
      owner.process_started_at = new Date(Date.now() - 60_000).toISOString();
      owner.acquired_at = new Date(Date.now() - 60_000).toISOString();
      writeJson(ownerPath, owner);
      const old = new Date(Date.now() - 60_000);
      fs.utimesSync(seeded.path, old, old);
      const replacement = acquireContainedLock(request);
      const current = JSON.parse(fs.readFileSync(path.join(replacement.path, 'owner.json'), 'utf8'));
      assert(current.lock_id && current.lock_id !== deadLockId, 'dead lock was not replaced');
      replacement.release();
      assert(!fs.existsSync(replacement.path), 'reclaimed lock was not released');
    });

    check('locking: releasing an old handle cannot delete a replacement owner', () => {
      const root = path.join(temporaryRoot, 'locks', 'replacement-owner');
      ensureDir(root);
      const handle = acquireContainedLock({ context: { stateRoot: root }, rootKind: 'state', rootPath: root, lockName: 'field-report', purpose: LOCKS['field-report'].purpose, timeoutMs: 50, staleMs: 60_000, retryMs: 2 });
      const ownerPath = path.join(handle.path, 'owner.json');
      const replacement = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
      replacement.lock_id = crypto.randomUUID();
      replacement.nonce = crypto.randomBytes(32).toString('hex');
      writeJson(ownerPath, replacement);
      expectThrow(() => handle.release(), /ownership changed/, 'replacement ownership was not detected');
      assert(fs.existsSync(handle.path), 'old release removed a replacement lock');
      const current = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
      assert(current.lock_id === replacement.lock_id, 'replacement owner changed');
      fs.rmSync(handle.path, { recursive: true, force: true });
    });

    check('modes: team state remains under its isolated stateRoot', () => {
      const teamRoot = path.join(temporaryRoot, 'team-state');
      setupArtifacts(teamRoot);
      const team = makeContext(systemRoot, teamRoot, {
        mode: 'team',
        repoId: 'team-repo',
        workspaceId: 'workspace-a',
        agentId: 'agent-a'
      });
      const started = run(['start', '--new'], { context: team });
      const status = run(['status', `--report-id=${started.report_id}`], { context: team });
      assert(status.paths.manifest.startsWith(teamRoot), 'team path');
    });

    check('CLI: JSON stdout is one v2 object and stderr stays empty', () => {
      const cliState = path.join(temporaryRoot, 'cli-state');
      const environment = {
        ...process.env,
        CI: '',
        KNOWLEDGE_SYSTEM_ROOT: systemRoot,
        KNOWLEDGE_TARGET_ROOT: temporaryRoot,
        KNOWLEDGE_STATE_ROOT: cliState
      };
      const result = childProcess.spawnSync(process.execPath, [
        path.join(systemRoot, 'tools', 'field-report.js'),
        'start',
        '--new',
        '--json'
      ], { encoding: 'utf8', env: environment, windowsHide: true });
      assert(result.status === 0, result.stderr);
      assert(result.stderr === '', result.stderr);
      const parsed = JSON.parse(result.stdout);
      assert(parsed.schema_version === 'knowledge-field-report.v2', result.stdout);
      context.cliReportId = parsed.report_id;
      context.cliState = cliState;
    });

    check('CLI: explicit context flags override environment and isolate stateRoot', () => {
      const explicitState = path.join(temporaryRoot, 'cli-explicit-state');
      const environmentState = path.join(temporaryRoot, 'cli-environment-state');
      const explicitTarget = path.join(temporaryRoot, 'cli-explicit-target');
      ensureDir(explicitTarget);
      writeJson(path.join(explicitTarget, 'package.json'), {
        name: 'field-report-explicit-target',
        private: true
      });
      const result = childProcess.spawnSync(process.execPath, [
        path.join(systemRoot, 'tools', 'field-report.js'),
        'start',
        '--new',
        '--json',
        `--system-root=${systemRoot}`,
        `--target-root=${explicitTarget}`,
        `--state-root=${explicitState}`
      ], {
        encoding: 'utf8',
        windowsHide: true,
        env: {
          ...process.env,
          CI: '',
          KNOWLEDGE_SYSTEM_ROOT: path.join(temporaryRoot, 'invalid-system-root'),
          KNOWLEDGE_TARGET_ROOT: path.join(temporaryRoot, 'environment-target'),
          KNOWLEDGE_STATE_ROOT: environmentState
        }
      });
      assert(result.status === 0, result.stderr);
      const parsed = JSON.parse(result.stdout);
      const reportRoot = path.join(
        explicitState,
        'reports',
        'field-reports',
        parsed.report_id
      );
      assert(fs.existsSync(path.join(reportRoot, 'manifest.json')), 'explicit stateRoot');
      assert(!fs.existsSync(path.join(
        environmentState,
        'reports',
        'field-reports',
        parsed.report_id,
        'manifest.json'
      )), 'environment stateRoot unexpectedly won');
      const facts = JSON.parse(fs.readFileSync(path.join(reportRoot, 'facts.json'), 'utf8'));
      assert(
        facts.values.project_type.value === 'JavaScript or TypeScript project',
        'explicit targetRoot was ignored'
      );
    });

    check('CLI: quiet and no-color emit no stdout decoration', () => {
      const environment = {
        ...process.env,
        CI: '',
        KNOWLEDGE_SYSTEM_ROOT: systemRoot,
        KNOWLEDGE_TARGET_ROOT: temporaryRoot,
        KNOWLEDGE_STATE_ROOT: context.cliState
      };
      const result = childProcess.spawnSync(process.execPath, [
        path.join(systemRoot, 'tools', 'field-report.js'),
        'status',
        `--report-id=${context.cliReportId}`,
        '--quiet',
        '--no-color'
      ], { encoding: 'utf8', env: environment, windowsHide: true });
      assert(result.status === 0 && result.stdout === '', result.stderr);
      assert(!/\x1b\[/.test(result.stderr), 'ANSI output');
    });

    check('CLI: help and unknown flags exit before context or state side effects', () => {
      const inertState = path.join(temporaryRoot, 'cli-help-must-not-exist');
      const environment = {
        ...process.env,
        KNOWLEDGE_SYSTEM_ROOT: path.join(temporaryRoot, 'missing-system-root'),
        KNOWLEDGE_TARGET_ROOT: path.join(temporaryRoot, 'missing-target-root'),
        KNOWLEDGE_STATE_ROOT: inertState
      };
      const help = childProcess.spawnSync(process.execPath, [
        path.join(systemRoot, 'tools', 'field-report.js'), '--help'
      ], { encoding: 'utf8', env: environment, windowsHide: true });
      assert(help.status === 0 && /field-report/.test(help.stdout), help.stderr);
      assert(!fs.existsSync(inertState), 'help created state');
      const unknown = childProcess.spawnSync(process.execPath, [
        path.join(systemRoot, 'tools', 'field-report.js'), '--unknown-r6-flag'
      ], { encoding: 'utf8', env: environment, windowsHide: true });
      assert(unknown.status === 2 && /Unknown flag/.test(unknown.stderr), unknown.stderr);
      assert(!fs.existsSync(inertState), 'unknown flag created state');
    });

    check('clean install: the physically copied Field Report runtime starts', () => {
      const installedRoot = path.join(temporaryRoot, 'installed', '.knowledge');
      const files = [
        'package.json',
        'schemas/field-report.schema.json',
        'schemas/field-report-task-results.schema.json',
        'tools/field-report.js',
        'tools/lib/json-store.js',
        'tools/lib/contained-lock-manager.js',
        'tools/lib/lock-owner-schema.js',
        'tools/lib/lock-policy.js',
        'tools/lib/strict-temp-cleanup.js',
        'tools/lib/json-transaction.js',
        'tools/lib/path-context.js',
        'tools/lib/git-context.js',
        'tools/lib/export-sanitizer.js',
        'tools/lib/wiki-status.js',
        'tools/lib/routing-estimate-formatter.js',
        'tools/lib/field-report/contract.js',
        'tools/lib/field-report/collector.js',
        'tools/lib/field-report/state.js',
        'tools/lib/field-report/task-results.js',
        'tools/lib/field-report/renderer.js',
        'tools/lib/field-report/redactor.js',
        'tools/lib/field-report/publisher.js'
      ];
      if (fs.existsSync(path.join(systemRoot, '.github', 'DISCUSSION_TEMPLATE', 'field-reports.yml'))) {
        files.push('.github/DISCUSSION_TEMPLATE/field-reports.yml');
      }
      for (const file of files) copyInstalledFile(systemRoot, installedRoot, file);
      const result = childProcess.spawnSync(process.execPath, [
        path.join(installedRoot, 'tools', 'field-report.js'),
        'start',
        '--new',
        '--json'
      ], {
        encoding: 'utf8',
        windowsHide: true,
        env: {
          ...process.env,
          CI: '',
          KNOWLEDGE_SYSTEM_ROOT: installedRoot,
          KNOWLEDGE_TARGET_ROOT: temporaryRoot,
          KNOWLEDGE_STATE_ROOT: path.join(temporaryRoot, 'installed-state')
        }
      });
      assert(result.status === 0, result.stderr);
      assert(JSON.parse(result.stdout).status === 'needs_user_input', result.stdout);
    });

    check('contract drift: a changed generated form is rejected', () => {
      const driftRoot = path.join(temporaryRoot, 'drift', '.knowledge');
      copyInstalledFile(systemRoot, driftRoot, 'schemas/field-report.schema.json');
      const form = path.join(
        driftRoot,
        '.github',
        'DISCUSSION_TEMPLATE',
        'field-reports.yml'
      );
      ensureDir(path.dirname(form));
      const sourceForm = path.join(systemRoot, '.github', 'DISCUSSION_TEMPLATE', 'field-reports.yml');
      fs.writeFileSync(
        form,
        fs.existsSync(sourceForm) ? fs.readFileSync(sourceForm, 'utf8') : generateGithubForm(DEFAULT_SCHEMA),
        'utf8'
      );
      fs.appendFileSync(form, '\n# drift\n');
      const result = validateContract(driftRoot);
      assert(!result.valid && !result.canonical_form_match, 'drift must fail');
    });

    return {
      schema_version: 'knowledge-field-report-self-test.v2',
      status: 'pass',
      checks_total: checks.length,
      checks
    };
  } finally {
    if (previousCi === undefined) delete process.env.CI;
    else process.env.CI = previousCi;
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    process.stdout.write(`${JSON.stringify(main(), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = main;
