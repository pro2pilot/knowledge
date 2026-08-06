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
  canonicalHash,
  generateGithubForm,
  missingQuestions,
  unwrap,
  validateAnswers,
  validateContract
} = require('./lib/field-report/contract');
const {
  collect
} = require('./lib/field-report/collector');
const {
  redactText,
  scanPublication
} = require('./lib/field-report/redactor');
const { renderEvidence } = require('./lib/field-report/renderer');
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
    structural_status: 'usable_with_warnings'
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
    task_scope_sha256: crypto.createHash('sha256')
      .update(JSON.stringify(taskScope))
      .digest('hex'),
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
    edges: [{ from: 'a', to: 'b' }]
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
    targetRoot: stateRoot,
    projectKnowledgeRoot: stateRoot,
    stateRoot,
    repoId: overrides.repoId || `self-test-${path.basename(stateRoot)}`,
    mode: overrides.mode || 'repo',
    branch: 'main',
    headSha: 'abcdef1234567890',
    workspaceId: overrides.workspaceId || null,
    agentId: overrides.agentId || 'field-report-self-test',
    warnings: []
  };
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

function createRendered(context, answers = validAnswers(), startFlags = []) {
  const started = run(['start', '--new', ...startFlags], { context });
  run(['ingest', `--report-id=${started.report_id}`], { context, answers });
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
  const fieldTypes = new Map(FIELDS.map((field) => [field.id, field.type]));
  const translated = {};
  for (const [id, raw] of Object.entries(exported.original_answers)) {
    const value = unwrap(raw);
    translated[id] = fieldTypes.get(id) === 'string'
      ? `${value} [public translation]`
      : value;
  }
  run(['translation-ingest', `--report-id=${started.report_id}`], {
    context,
    translation: {
      original_hash: exported.original_hash,
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
  const stateRoot = path.join(temporaryRoot, 'state');
  setupArtifacts(stateRoot);
  writeJson(path.join(stateRoot, 'package.json'), { name: 'fixture' });
  const context = makeContext(systemRoot, stateRoot);
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

    let primaryReport;
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
      assert(manifest.language === manifest.public_language, 'default source language');
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
      primaryRendered = run(['render', `--report-id=${primaryReport}`], { context });
      assert(primaryRendered.status === 'draft_ready', primaryRendered.status);
      const draft = fs.readFileSync(primaryRendered.draft_path, 'utf8');
      const publicBody = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(draft !== publicBody, 'draft and public must differ');
      assert(draft.includes('Collected fact provenance'), 'draft provenance');
      assert(!publicBody.includes('Collected fact provenance'), 'public debug leak');
    });

    check('renderer: public evidence table uses safe relative sources', () => {
      const body = fs.readFileSync(primaryRendered.public_path, 'utf8');
      assert(body.includes('## Automatically collected evidence'), 'evidence heading');
      assert(body.includes('| .knowledge version |'), 'version row');
      assert(body.includes('`.knowledge/package.json`'), 'safe source');
      assert(
        body.includes('`.knowledge/maintenance/repair_on_touch_telemetry.json`'),
        'nested relative evidence source was changed'
      );
      assert(
        !body.includes('.knowledge[REDACTED:absolute_posix_path]'),
        'relative evidence source was falsely redacted'
      );
      assert(!body.includes(stateRoot), 'absolute path leak');
      assert(body.includes('| Repair-on-touch mode | scoped |'), 'valid repair mode absent');
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
      const overheadRows = renderEvidence(withOverhead);
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
      const savingRows = renderEvidence(withSaving);
      assert(savingRows.includes('Estimated workspace-to-task first-read narrowing: 300 estimated tokens'), 'narrowing row must remain');
      assert(!savingRows.includes('first-read overhead'), 'zero overhead row must be omitted');
      assert(!savingRows.includes('estimated_narrowing'), 'raw narrowing assessment leaked');
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
      assert(
        translationExported.source_language.toLowerCase() === 'es',
        'resolved source language'
      );
      const originalPath = manifest.paths.answers_original;
      originalBytes = fs.readFileSync(originalPath);
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
      const fieldTypes = new Map(FIELDS.map((field) => [field.id, field.type]));
      const translated = {};
      for (const [id, raw] of Object.entries(translationExported.original_answers)) {
        const value = unwrap(raw);
        translated[id] = fieldTypes.get(id) === 'string' ? `${value} [translated]` : value;
      }
      const result = run([
        'translation-ingest',
        `--report-id=${translationReport}`
      ], {
        context,
        translation: {
          original_hash: translationExported.original_hash,
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
      assert(body.includes('public-language version'), 'target-neutral translation wording');
      assert(!body.includes('English version'), 'hard-coded English translation claim');
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
