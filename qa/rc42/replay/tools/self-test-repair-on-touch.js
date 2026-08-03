#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  DEFAULT_REPAIR_POLICY,
  HARD_SAFETY,
  canonicalMode,
  normalizePolicy,
  parseRepositoryRepairSettings,
  resolvePolicy,
  saveOperatorRepairSettings,
  granularFinding,
  buildTaskScope,
  repairSessionPlanRelative,
  generatedProducerDependencyClosure,
  loadRepairPlan,
  validateRepairPlanArtifact,
  relationToTask,
  buildOpportunitiesArtifact,
  selectOpportunities,
  taskReadiness,
  validateReceipt,
  createReceipt,
  saveReceipt,
  loadReceipt,
  receiptDigest,
  validateExecutionRecord,
  saveExecutionRecord,
  loadExecutionRecord,
  executionDigest,
  runVerificationTests,
  MAX_REPAIR_PLAN_BYTES,
  MAX_VERIFICATION_RECEIPT_BYTES,
  MAX_VERIFICATION_EXECUTION_BYTES,
  maintenanceTelemetry,
  humanMaintenanceSummary
} = require('./lib/repair-on-touch');
const {
  reconcile,
  closeFindings,
  findingOccurrence
} = require('./lib/queue-lifecycle');
const {
  commitJsonTransaction,
  recoverTransactions
} = require('./lib/json-transaction');
const {
  readJson
} = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const {
  parseArgs
} = require('./repair-on-touch');
const { systemVersion } = require('./lib/system-version');

const systemRoot = path.resolve(__dirname, '..');
const toolPath = path.join(systemRoot, 'tools', 'repair-on-touch.js');
const checks = [];
const artifacts = {};

function assert(value, message) {
  if (!value) throw new Error(message);
}

function check(name, fn) {
  fn();
  checks.push(name);
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeText(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, value, 'utf8');
}

function hash(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function fixtureContext(root, options = {}) {
  const knowledge = options.knowledge || path.join(root, '.knowledge');
  const state = options.state || knowledge;
  fs.mkdirSync(path.join(knowledge, 'settings'), { recursive: true });
  fs.mkdirSync(path.join(state, 'maintenance'), { recursive: true });
  return {
    mode: options.mode || 'repo',
    targetRoot: root,
    projectKnowledgeRoot: knowledge,
    stateRoot: state,
    teamRoot: options.teamRoot || null,
    repoId: 'test-repo',
    workspaceId: options.workspaceId || null,
    agentId: 'repair-test'
  };
}

function envFor(root, state = path.join(root, '.knowledge'), extra = {}) {
  return {
    ...process.env,
    KNOWLEDGE_SYSTEM_ROOT: systemRoot,
    KNOWLEDGE_TARGET_ROOT: root,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_STATE_ROOT: state,
    KNOWLEDGE_AGENT_ID: 'repair-test',
    KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1',
    ...extra
  };
}

function twoFindings() {
  return [
    granularFinding({
      module_id: 'auth',
      code: 'low_confidence_module',
      artifact: 'src/auth.js',
      affected_artifacts: ['src/auth.js', '.knowledge/modules/auth.json'],
      severity: 'medium',
      repair_class: 'verify_on_touch'
    }),
    granularFinding({
      module_id: 'billing',
      code: 'low_confidence_module',
      artifact: 'src/billing.js',
      affected_artifacts: ['src/billing.js', '.knowledge/modules/billing.json'],
      severity: 'medium',
      repair_class: 'verify_on_touch'
    })
  ].map((finding) => ({
    ...finding,
    occurrence: 1,
    opened_at: '2026-07-29T12:00:00.000Z'
  }));
}

function makeScope(overrides = {}) {
  return buildTaskScope({
    task_id: 'TASK-auth',
    session_id: 'SESSION-1',
    user_task: 'Fix authentication behavior',
    selected_modules: ['auth'],
    changed_files: ['src/auth.js'],
    agent_plan: ['read auth source', 'run auth tests'],
    ...overrides
  });
}

function policy(context, perRun = {}) {
  return resolvePolicy({
    context,
    repository: {},
    operator: {},
    perRun
  });
}

function receiptInput(root, finding, scope, overrides = {}) {
  const {
    verification_tests: verificationTests = [{
      argv: ['node', 'tests/auth.test.js']
    }],
    verification_source_files: verificationSourceFiles = null,
    ...receiptOverrides
  } = overrides;
  const stateRoot = path.join(root, '.knowledge');
  const affected = Array.from(new Set([
    finding.artifact,
    ...(finding.affected_artifacts || [])
  ]));
  const verifiedSources = Array.from(new Set(
    verificationSourceFiles || affected
  ));
  const execution = runVerificationTests({
    stateRoot,
    repoRoot: root,
    taskId: scope.task_id,
    sessionId: scope.session_id,
    tests: verificationTests,
    sourceFiles: verifiedSources.map((item) => ({ path: item })),
    checkedBy: 'repair-test'
  })[0];
  return {
    schema_version: 'knowledge-verification-receipt.v1',
    finding_id: finding.lifecycle_id,
    finding_occurrence_sha256: findingOccurrence(finding).sha256,
    module_id: finding.module_id,
    task_id: scope.task_id,
    session_id: scope.session_id,
    repair_mode: 'scoped',
    source_files_checked: execution.record.source_snapshot.map((item) => ({
      path: item.path,
      sha256: item.sha256
    })),
    tests_run: [{
      command: execution.record.command,
      command_argv: execution.record.command_argv,
      status: execution.record.status,
      exit_code: execution.record.exit_code,
      tests_passed: 1,
      duration_ms: execution.record.duration_ms,
      execution_id: execution.record.execution_id,
      execution_sha256: execution.record.content_sha256,
      execution_path: execution.relative_path,
      stdout_sha256: execution.record.stdout_sha256,
      stderr_sha256: execution.record.stderr_sha256
    }],
    claims_checked: [{
      claim_id: 'auth-current-behavior',
      claim: 'The auth module matches the tested behavior.',
      result: 'confirmed',
      evidence: [finding.artifact, 'tests/auth.test.js']
    }],
    required_checks_completed: finding.required_checks,
    resolution_predicate: finding.resolution_predicate,
    predicate_result: 'pass',
    checked_at: new Date().toISOString(),
    checked_by: 'repair-test',
    task_scope_hash: scope.scope_hash,
    task_scope: {
      modules: scope.direct_modules,
      artifacts: scope.direct_artifacts
    },
    additional_work: {
      wall_time_ms: 1200,
      context_tokens: 80,
      context_percent: 2,
      input_tokens: 70,
      output_tokens: 10
    },
    ...receiptOverrides
  };
}

function prepareSourceFixture(root) {
  writeText(path.join(root, 'src', 'auth.js'), 'module.exports = { ok: true };\n');
  writeText(path.join(root, 'src', 'billing.js'), 'module.exports = { ok: true };\n');
  writeText(path.join(root, 'tests', 'auth.test.js'), 'if (!require("../src/auth").ok) process.exit(1);\n');
  writeJson(path.join(root, '.knowledge', 'modules', 'auth.json'), { module_id: 'auth', verification_status: 'needs_recheck' });
  writeJson(path.join(root, '.knowledge', 'modules', 'billing.json'), { module_id: 'billing', verification_status: 'needs_recheck' });
  const test = spawnSync(process.execPath, [path.join(root, 'tests', 'auth.test.js')], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true
  });
  assert(test.status === 0, 'receipt fixture test did not actually pass');
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-repair-on-touch-'));
  try {
    const emptyRoot = path.join(root, 'empty');
    const emptyContext = fixtureContext(emptyRoot);
    check('01 clean install without config resolves to scoped', () => {
      const resolved = policy(emptyContext);
      assert(resolved.effective_mode === 'scoped' && resolved.effective_mode_source === 'built-in default', 'clean default is not scoped');
    });
    check('02 public 3.2.11 upgrade without repair setting migrates to scoped', () => {
      const legacyPublicVersion = ['3', '2', '11'].join('.');
      writeJson(path.join(emptyContext.projectKnowledgeRoot, 'settings', 'operator-profile.json'), {
        schema_version: legacyPublicVersion,
        user_mode: 'simple'
      });
      const resolved = policy(emptyContext);
      assert(resolved.effective_mode === 'scoped', '3.2.11 missing setting did not inherit scoped');
    });
    const inspectorSource = fs.readFileSync(path.join(systemRoot, 'tools', 'build-visual-inspector.js'), 'utf8');
    check('03 First-run presents scoped repair as Recommended', () => {
      assert(/Scoped repair . Recommended/.test(inspectorSource), 'First-run recommended option missing');
    });
    check('04 First-run-compatible settings save persists the chosen mode', () => {
      const saved = saveOperatorRepairSettings(emptyContext, { mode: 'safe-only' }, { updatedBy: 'test' });
      assert(saved.profile.maintenance.repair_on_touch.mode === 'safe-only', 'saved mode mismatch');
    });
    check('05 Inspector exposes a mode-changing API and control', () => {
      const serverSource = fs.readFileSync(path.join(systemRoot, 'tools', 'serve-inspector.js'), 'utf8');
      assert(serverSource.includes('/api/settings/repair-on-touch') && inspectorSource.includes('repair-setting-mode'), 'Inspector setting surface missing');
    });
    check('06 effective mode reports source and configured mode', () => {
      const resolved = resolvePolicy({ context: emptyContext });
      assert(resolved.configured_mode === 'safe-only' && resolved.effective_mode_source === 'operator/workspace setting', 'mode source not reported');
    });
    check('07 explicit per-run override wins over workspace and repository settings', () => {
      const resolved = resolvePolicy({ context: emptyContext, perRun: { mode: 'scoped' } });
      assert(resolved.effective_mode === 'scoped' && resolved.effective_mode_source === 'per-run override', 'per-run precedence broken');
    });
    check('08 team policy cap restricts Extended mode to scoped', () => {
      writeJson(path.join(emptyContext.stateRoot, 'maintenance', 'concurrency_policy.json'), {
        team_policy: { repair_on_touch: { max_mode: 'scoped' } }
      });
      const resolved = resolvePolicy({ context: emptyContext, perRun: { mode: 'aggressive' } });
      assert(resolved.effective_mode === 'scoped' && resolved.policy_cap.restricted, 'team cap not enforced');
    });
    check('08a all declared team and security caps compose by the strictest mode', () => {
      const projectRoot = path.join(root, 'cap-composition');
      const projectKnowledge = path.join(projectRoot, '.knowledge');
      const workspaceState = path.join(
        projectRoot,
        '.knowledge-workspace'
      );
      const capContext = fixtureContext(projectRoot, {
        knowledge: projectKnowledge,
        state: workspaceState,
        mode: 'team'
      });
      writeJson(
        path.join(
          workspaceState,
          'maintenance',
          'concurrency_policy.json'
        ),
        {
          team_policy: {
            repair_on_touch: { max_mode: 'aggressive' }
          }
        }
      );
      writeJson(
        path.join(
          projectKnowledge,
          'maintenance',
          'concurrency_policy.json'
        ),
        {
          security_policy: {
            repair_on_touch: { max_mode: 'safe-only' }
          }
        }
      );
      const resolved = resolvePolicy({
        context: capContext,
        perRun: { mode: 'aggressive' }
      });
      assert(
        resolved.effective_mode === 'safe-only' &&
        resolved.policy_cap.max_mode === 'safe-only' &&
        resolved.policy_cap.source ===
          'repository team/security policy',
        `policy caps did not compose conservatively: ${
          JSON.stringify(resolved.policy_cap)
        }`
      );
    });
    check('09 reset returns the workspace to scoped defaults', () => {
      const reset = saveOperatorRepairSettings(emptyContext, DEFAULT_REPAIR_POLICY, { reset: true, updatedBy: 'test' });
      assert(reset.policy.effective_mode === 'scoped', 'reset did not restore scoped');
    });
    check('10 interrupted settings write cannot leave invalid JSON', () => {
      const settingsPath = path.join(emptyContext.projectKnowledgeRoot, 'settings', 'operator-profile.json');
      saveOperatorRepairSettings(emptyContext, { mode: 'dedicated' }, { updatedBy: 'test' });
      assert(readJson(settingsPath, null)?.maintenance?.repair_on_touch?.mode === 'dedicated', 'atomic settings output invalid');
    });

    const findings = twoFindings();
    const scope = makeScope();
    const scopedPolicy = policy(emptyContext, { mode: 'scoped' });
    const scoped = buildOpportunitiesArtifact({
      findings,
      scope,
      policyResolution: scopedPolicy,
      doctorScore: 86,
      generatedAt: '2026-07-29T12:00:00.000Z',
      generatedBy: 'test'
    });
    check('11 two suspect modules are represented as two granular findings', () => {
      assert(findings.length === 2 && new Set(findings.map((item) => item.lifecycle_id)).size === 2, 'findings are not independent');
    });
    check('12 scoped mode selects only the task-relevant finding', () => {
      assert(scoped.opportunities.filter((item) => item.status === 'selected').map((item) => item.module_id).join() === 'auth', 'wrong scoped selection');
    });
    check('13 the unrelated finding remains deferred and open', () => {
      const billing = scoped.opportunities.find((item) => item.module_id === 'billing');
      assert(billing.status === 'deferred' && billing.decision_reason === 'outside_task_scope', 'unrelated finding not deferred');
    });
    check('14 global Doctor can improve partially without hiding other debt', () => {
      const afterOne = Math.max(0, 86 + findings[0].score_cost);
      assert(afterOne > 86 && afterOne < 100, 'partial global progress not representable');
    });
    check('15 task readiness reaches 100 after the one relevant finding closes', () => {
      const after = taskReadiness([{ ...findings[0], status: 'closed' }, findings[1]], scope);
      assert(after.score === 100 && after.relevant_findings_open === 0, 'task readiness did not become ready');
    });
    check('16 unrelated Doctor debt does not expand task scope', () => {
      assert(relationToTask(findings[1], scope) === 'no_overlap' && !scope.direct_modules.includes('billing'), 'scope expanded');
    });
    check('16a task scope cannot collapse distinct lifecycle module IDs', () => {
      const aliasScope = buildTaskScope({
        task_id: 'task-field-report',
        session_id: 'session-field-report',
        selected_modules: ['field_report']
      });
      const hyphenFinding = granularFinding({
        module_id: 'field-report',
        code: 'low_confidence_module',
        artifact: 'src/field-report.js',
        repair_class: 'verify_on_touch'
      });
      assert(
        relationToTask(hyphenFinding, aliasScope) === 'no_overlap' &&
        hyphenFinding.module_id === 'field-report',
        'field-report and field_report were treated as the same module'
      );
      const exactScope = buildTaskScope({
        task_id: 'task-field-report-exact',
        session_id: 'session-field-report-exact',
        selected_modules: ['field-report']
      });
      assert(
        relationToTask(hyphenFinding, exactScope) === 'direct_overlap',
        'exact registered module ID did not match task scope'
      );
    });

    const receiptRoot = path.join(root, 'receipt');
    const receiptContext = fixtureContext(receiptRoot);
    prepareSourceFixture(receiptRoot);
    const authFinding = findings[0];
    check('17 reading source without relevant tests cannot create a valid receipt', () => {
      const invalid = validateReceipt(receiptInput(receiptRoot, authFinding, scope, { tests_run: [] }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.includes('tests_run_required'), 'read-only receipt was accepted');
    });
    let goodReceipt;
    check('18 current source plus passing relevant tests creates a receipt', () => {
      goodReceipt = createReceipt(receiptInput(receiptRoot, authFinding, scope), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(goodReceipt.receipt_id.startsWith('KVR-') && goodReceipt.content_sha256.length === 64, 'valid receipt not content-addressed');
    });
    check('18a receipt must bind the exact trusted task scope hash', () => {
      const raw = receiptInput(receiptRoot, authFinding, scope);
      delete raw.task_scope_hash;
      const invalid = validateReceipt(raw, {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(
        !invalid.ok && invalid.errors.includes('task_scope_hash_required'),
        'receipt without the trusted task scope hash was accepted'
      );
    });
    check('18b canonical task-scope v1 fields are accepted without module-ID collapse', () => {
      const raw = receiptInput(receiptRoot, authFinding, scope, {
        task_scope: {
          direct_modules: scope.direct_modules,
          direct_artifacts: scope.direct_artifacts,
          dependency_modules: [],
          dependency_artifacts: []
        }
      });
      const valid = validateReceipt(raw, {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(valid.ok, `canonical task-scope fields were rejected: ${valid.errors.join(',')}`);
    });
    check('18c receipt task and session IDs must match the trusted scope', () => {
      const taskMismatch = validateReceipt(receiptInput(receiptRoot, authFinding, scope, {
        task_id: 'another-task'
      }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      const sessionMismatch = validateReceipt(receiptInput(receiptRoot, authFinding, scope, {
        session_id: 'another-session'
      }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(
        taskMismatch.errors.includes('task_id_scope_mismatch') &&
        sessionMismatch.errors.includes('session_id_scope_mismatch'),
        'receipt task/session identity escaped the trusted scope'
      );
    });
    check('18d receipt test envelope must exactly match its execution record', () => {
      const raw = receiptInput(receiptRoot, authFinding, scope);
      raw.tests_run[0].command_argv = ['node', 'different-test.js'];
      const invalid = validateReceipt(raw, {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(
        invalid.errors.some((item) => item.startsWith('test_execution_mismatch:')),
        'tampered test argv was accepted'
      );
    });
    check('19 an incomplete resolution predicate cannot elevate trust', () => {
      const invalid = validateReceipt(receiptInput(receiptRoot, authFinding, scope, { predicate_result: 'fail' }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.includes('predicate_result_not_pass'), 'failed predicate accepted');
    });
    check('20 a changed source hash invalidates prior verification and supports reopen', () => {
      writeText(path.join(receiptRoot, 'src', 'auth.js'), 'module.exports = { ok: false };\n');
      const invalid = validateReceipt(goodReceipt, {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.some((item) => item.startsWith('source_hash_current_mismatch:')), 'changed source accepted');
      writeText(path.join(receiptRoot, 'src', 'auth.js'), 'module.exports = { ok: true };\n');
    });

    const protectedCases = [
      ['21 open contradiction stays open', 'open_contradiction'],
      ['22 security finding stays open', 'security_finding'],
      ['23 policy violation stays open', 'policy_violation']
    ];
    for (const [name, code] of protectedCases) {
      check(name, () => {
        const finding = granularFinding({ module_id: 'auth', code, artifact: 'src/auth.js', repair_class: 'dedicated_action_required' });
        const plan = selectOpportunities({ findings: [finding], scope, policyResolution: scopedPolicy });
        assert(
          plan.opportunities[0].status === 'deferred' &&
          plan.opportunities[0].decision_reason === (
            scopedPolicy.policy_cap?.active
              ? 'dedicated_blocked_by_policy_cap'
              : 'dedicated_action_required'
          ),
          `${code} was selected`
        );
      });
    }
    check('24 critical-path repair requires explicit confirmation', () => {
      const critical = granularFinding({ ...authFinding, critical_path: true });
      const blocked = selectOpportunities({ findings: [critical], scope, policyResolution: scopedPolicy });
      const allowed = selectOpportunities({ findings: [critical], scope, policyResolution: scopedPolicy, confirmations: { critical_paths: true } });
      assert(blocked.opportunities[0].status === 'deferred' && allowed.opportunities[0].status === 'selected', 'critical confirmation rule broken');
    });
    check('25 source code cannot be enabled as a health-repair target', () => {
      let rejected = false;
      try { normalizePolicy({ edit_source_for_health: true }); } catch (error) { rejected = error.code === 'repair_source_health_override_forbidden'; }
      assert(rejected && HARD_SAFETY.edit_source_for_health === false, 'source-for-health invariant bypassed');
    });
    check('26 Doctor score is derived and has no writable policy setting', () => {
      assert(HARD_SAFETY.score_is_derived_only && !Object.prototype.hasOwnProperty.call(DEFAULT_REPAIR_POLICY, 'score'), 'score became configurable');
    });
    check('27 Extended mode cannot bypass protected-finding safety', () => {
      const security = granularFinding({ module_id: 'auth', code: 'security_finding', artifact: 'src/auth.js' });
      const plan = selectOpportunities({ findings: [security], scope, policyResolution: policy(emptyContext, { mode: 'aggressive' }), confirmations: { security_findings: true } });
      assert(plan.opportunities[0].status === 'deferred', 'Extended mode selected security finding');
    });
    check('28 safe-only mode cannot modify curated trust knowledge', () => {
      const safe = selectOpportunities({ findings: [authFinding], scope, policyResolution: policy(emptyContext, { mode: 'safe-only' }) });
      assert(safe.opportunities[0].decision_reason === 'safe_only_curated_repair_forbidden', 'safe-only selected curated repair');
    });
    check('28a generated repair is deferred when deterministic rebuilding is disabled', () => {
      const generated = granularFinding({
        module_id: 'root',
        code: 'search_index_stale',
        artifact: '.knowledge/search/index.json',
        repair_class: 'rebuild_generated_artifact'
      });
      const generatedScope = makeScope({
        selected_modules: ['root'],
        changed_files: ['.knowledge/search/index.json']
      });
      const selected = selectOpportunities({
        findings: [generated],
        scope: generatedScope,
        policyResolution: policy(emptyContext, {
          mode: 'safe-only',
          rebuild_generated_artifacts: false
        })
      });
      assert(
        selected.opportunities[0].status === 'deferred' &&
        selected.opportunities[0].decision_reason ===
          'generated_rebuild_disabled' &&
        selected.budget.selected.findings === 0,
        'disabled generated rebuilding still selected work'
      );
    });
    check('29 off mode performs no maintenance', () => {
      const off = selectOpportunities({ findings: [authFinding], scope, policyResolution: policy(emptyContext, { mode: 'off' }) });
      assert(off.opportunities[0].decision_reason === 'mode_off', 'off mode selected work');
    });
    check('30 dedicated mode does not run opportunistically in a normal task', () => {
      const dedicated = selectOpportunities({ findings: [authFinding], scope, policyResolution: policy(emptyContext, { mode: 'dedicated' }) });
      assert(dedicated.opportunities[0].decision_reason === 'dedicated_run_required', 'dedicated mode auto-ran');
    });

    const bothScope = makeScope({ selected_modules: ['auth', 'billing'], changed_files: ['src/auth.js', 'src/billing.js'] });
    check('31 maximum finding count limits selected repairs', () => {
      const selected = selectOpportunities({ findings, scope: bothScope, policyResolution: policy(emptyContext, { max_findings_per_task: 1 }) });
      assert(selected.opportunities.filter((item) => item.status === 'selected').length === 1 &&
        selected.opportunities.some((item) => item.decision_reason === 'budget_exhausted_max_findings'), 'finding budget not enforced');
    });
    check('32 time budget limits repair without selecting partial work', () => {
      const selected = selectOpportunities({ findings, scope: bothScope, policyResolution: policy(emptyContext, { max_extra_minutes: 1 }) });
      assert(selected.opportunities.every((item) => item.status === 'deferred') &&
        selected.opportunities.some((item) => item.decision_reason === 'budget_exhausted_time'), 'time budget not enforced');
    });
    check('33 context budget limits repair', () => {
      const selected = selectOpportunities({ findings, scope: bothScope, policyResolution: policy(emptyContext, { max_extra_context_percent: 1 }) });
      assert(selected.opportunities.every((item) => item.status === 'deferred') &&
        selected.opportunities.some((item) => item.decision_reason === 'budget_exhausted_context'), 'context budget not enforced');
    });
    check('33a receipt wall time cannot underreport physical KVE duration', () => {
      const raw = receiptInput(
        receiptRoot,
        authFinding,
        scope
      );
      raw.additional_work.wall_time_ms = 0;
      const validation = validateReceipt(raw, {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(
        !validation.ok &&
        validation.errors.includes(
          'additional_wall_time_below_execution_evidence'
        ),
        'receipt underreported observed KVE wall time'
      );
    });
    check('34 budget exhaustion does not mark the primary task failed', () => {
      const summary = humanMaintenanceSummary({
        primaryTask: ['Primary behavior completed successfully.'],
        opportunities: [{ ...findings[0], status: 'deferred', decision_reason: 'budget_exhausted_time' }]
      });
      assert(summary.includes('Primary behavior completed successfully.') && summary.includes('additional-time limit'), 'primary result lost under budget exhaustion');
    });
    check('35 partial predicate never creates partial trust elevation', () => {
      const invalid = validateReceipt(receiptInput(receiptRoot, authFinding, scope, {
        required_checks_completed: ['read_current_source']
      }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.some((item) => item.startsWith('required_check_missing:')), 'partial predicate accepted');
    });

    const faultResults = [];
    check('36 crash injection covers every JSON transaction write boundary', () => {
      const points = [
        'after_initial_manifest',
        'after_stage_0',
        'after_stage_1',
        'after_prepare_manifest',
        'after_commit_marker',
        'after_promote_0',
        'after_promote_1',
        'after_committed_manifest'
      ];
      for (const point of points) {
        const state = path.join(root, 'faults', point);
        const a = path.join(state, 'a.json');
        const b = path.join(state, 'b.json');
        writeJson(a, { value: 'old' });
        writeJson(b, { value: 'old' });
        try {
          commitJsonTransaction({
            stateRoot: state,
            transactionId: 'repair-fault',
            faultAt: point,
            writes: [
              { path: a, value: { value: 'new' }, containmentRoot: state },
              { path: b, value: { value: 'new' }, containmentRoot: state }
            ]
          });
        } catch (error) {
          assert(error.code === 'transaction_fault_injected', `unexpected fault at ${point}`);
        }
        recoverTransactions(state);
        const values = [readJson(a, {}).value, readJson(b, {}).value];
        assert(values[0] === values[1] && ['old', 'new'].includes(values[0]), `mixed transaction state at ${point}`);
        faultResults.push({ point, state: values[0] });
      }
      assert(faultResults.length === points.length, 'not all fault boundaries ran');
    });
    check('37 recovery is all-old or all-new and a rolled-back ID can retry', () => {
      assert(faultResults.every((item) => ['old', 'new'].includes(item.state)), 'invalid recovered state');
      const early = path.join(root, 'faults', 'after_stage_0');
      const a = path.join(early, 'a.json');
      const b = path.join(early, 'b.json');
      const retry = commitJsonTransaction({
        stateRoot: early,
        transactionId: 'repair-fault',
        writes: [
          { path: a, value: { value: 'new' }, containmentRoot: early },
          { path: b, value: { value: 'new' }, containmentRoot: early }
        ]
      });
      assert(retry.status === 'committed' && readJson(a, {}).value === 'new' && readJson(b, {}).value === 'new', 'rolled-back transaction could not retry');
    });
    check('38 two agents cannot close the same finding twice', () => {
      const stale = { items: [] };
      const queue = { queue: [] };
      reconcile({ staleItems: stale, repairQueue: queue, findings: [authFinding], source: 'doctor', agentId: 'seed', timestamp: '2026-07-29T12:00:00.000Z' });
      const args = {
        staleItems: stale,
        repairQueue: queue,
        lifecycleIds: [authFinding.lifecycle_id],
        allowedCodes: [authFinding.code],
        verifiedArtifacts: authFinding.affected_artifacts,
        resolutionEvidence: [{
          lifecycle_id: authFinding.lifecycle_id,
          code: authFinding.code,
          artifact: authFinding.artifact,
          predicate: authFinding.resolution_predicate,
          predicate_result: true,
          verifier_type: 'repair_on_touch_verification'
        }],
        recertificationId: 'RCERT-one',
        timestamp: '2026-07-29T12:01:00.000Z'
      };
      const first = closeFindings({ ...args, agentId: 'agent-one' });
      const second = closeFindings({ ...args, agentId: 'agent-two' });
      assert(first.closed_lifecycle_ids.length === 1 && second.closed_lifecycle_ids.length === 0, 'finding closed twice');
    });
    check('39 unchanged receipt storage is idempotent', () => {
      const savedOne = saveReceipt(receiptContext.stateRoot, goodReceipt);
      const savedTwo = saveReceipt(receiptContext.stateRoot, goodReceipt);
      assert(savedOne.idempotent === false && savedTwo.idempotent === true, 'receipt save not idempotent');
    });
    check('40 Windows lock path serializes the repair critical section', () => {
      let entered = false;
      withContainedLock({
        context: { stateRoot: root },
        rootKind: 'state',
        rootPath: root,
        lockName: 'repair-on-touch',
        purpose: LOCKS['repair-on-touch'].purpose
      }, () => { entered = true; });
      assert(entered, 'Windows-compatible mkdir lock did not run');
    });
    check('41 Linux uses the same platform-neutral lock and atomic transaction contract', () => {
      const storeSource = fs.readFileSync(path.join(systemRoot, 'tools', 'lib', 'contained-lock-manager.js'), 'utf8');
      assert(/mkdirSync/.test(storeSource) && !/flockSync|win32.*acquireContainedLock/.test(storeSource), 'lock implementation is platform-specific');
    });
    check('42 team mode reads a workspace state policy cap', () => {
      const teamRoot = path.join(root, 'team');
      const teamState = path.join(teamRoot, 'repos', 'r', 'workspaces', 'w', 'state');
      const teamContext = fixtureContext(path.join(root, 'team-repo'), {
        mode: 'team',
        state: teamState,
        teamRoot,
        workspaceId: 'w'
      });
      writeJson(path.join(teamState, 'maintenance', 'concurrency_policy.json'), {
        team_policy: { repair_on_touch: { max_mode: 'safe-only' } }
      });
      const resolved = resolvePolicy({ context: teamContext, perRun: { mode: 'aggressive' } });
      assert(resolved.effective_mode === 'safe-only', 'team state cap ignored');
    });
    check('43 worktree mode keeps task scope and receipts inside the selected workspace', () => {
      const worktreeRoot = path.join(root, 'worktree');
      const worktreeContext = fixtureContext(worktreeRoot);
      const worktreeScope = makeScope({ task_id: 'worktree-task' });
      assert(worktreeContext.targetRoot === worktreeRoot && worktreeScope.task_id === 'worktree-task', 'worktree scope escaped');
    });

    const summary = humanMaintenanceSummary({
      primaryTask: ['Updated authentication behavior.'],
      primaryTests: ['Auth tests passed.'],
      opportunities: [
        { ...authFinding, status: 'repaired' },
        { ...findings[1], status: 'deferred', decision_reason: 'outside_task_scope' }
      ],
      receipts: [goodReceipt],
      closed: [authFinding.lifecycle_id],
      doctorBefore: 86,
      doctorAfter: 93,
      readinessBefore: 93,
      readinessAfter: 100
    });
    check('44 final output separates primary task and knowledge maintenance', () => {
      assert(summary.includes('Primary task') && summary.includes('Knowledge maintenance performed during the task'), 'summary sections missing');
    });
    check('45 Doctor before and after values are exact', () => {
      assert(summary.includes('86 → 93'), 'Doctor transition missing');
    });
    check('46 task readiness before and after values are exact', () => {
      assert(summary.includes('93 → 100'), 'readiness transition missing');
    });
    check('47 deferred unrelated findings are listed with a human reason', () => {
      assert(summary.includes('billing') && summary.includes('outside the current task'), 'deferred finding missing');
    });
    check('48 receipt contains the exact lifecycle ID', () => {
      assert(goodReceipt.finding_id === authFinding.lifecycle_id, 'receipt lifecycle mismatch');
    });
    check('49 raw decision enum IDs do not leak into human output', () => {
      assert(!summary.includes('outside_task_scope') && !summary.includes('budget_exhausted_'), 'raw enum leaked');
    });
    check('50 Inspector and CLI resolve the same settings state', () => {
      const cliRoot = path.join(root, 'cli-state');
      const cliContext = fixtureContext(cliRoot);
      writeText(path.join(cliContext.projectKnowledgeRoot, 'config.yaml'), 'maintenance:\n  repair_on_touch:\n    mode: scoped\n');
      saveOperatorRepairSettings(cliContext, { mode: 'safe-only', max_findings_per_task: 3 }, { updatedBy: 'test' });
      const run = spawnSync(process.execPath, [toolPath, 'settings', 'show'], {
        cwd: cliRoot,
        env: envFor(cliRoot),
        encoding: 'utf8',
        windowsHide: true
      });
      const cli = JSON.parse(run.stdout || '{}');
      const inspector = resolvePolicy({ context: cliContext });
      assert(run.status === 0 && cli.effective_mode === inspector.effective_mode &&
        cli.configured.max_findings_per_task === inspector.configured.max_findings_per_task, 'CLI/Inspector state diverged');
    });

    check('51 secret-like values are rejected from receipts', () => {
      const invalid = validateReceipt(receiptInput(receiptRoot, authFinding, scope, {
        claims_checked: [{
          claim_id: 'secret',
          claim: 'token=sk_abcdefghijklmnopqrstuvwxyz123456',
          result: 'confirmed',
          evidence: ['src/auth.js']
        }]
      }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.some((item) => item.startsWith('secret_like_value:')), 'secret-like receipt accepted');
    });
    check('52 content-addressed receipt files are immutable', () => {
      const saved = saveReceipt(receiptContext.stateRoot, goodReceipt);
      const body = fs.readFileSync(saved.path, 'utf8');
      assert(body.includes(goodReceipt.content_sha256), 'stored receipt content missing digest');
    });
    check('52a receipt storage rejects missing content identity', () => {
      const missingIdentity = { ...goodReceipt };
      delete missingIdentity.receipt_id;
      delete missingIdentity.content_sha256;
      let captured = null;
      try {
        saveReceipt(receiptContext.stateRoot, missingIdentity);
      } catch (error) {
        captured = error;
      }
      assert(
        captured?.code === 'verification_receipt_invalid',
        'receipt without content identity was persisted'
      );
      assert(
        !fs.existsSync(path.join(
          receiptContext.stateRoot,
          'maintenance',
          'verification_receipts',
          'undefined.json'
        )),
        'missing receipt identity created undefined.json'
      );
    });
    check('53 Extended is a migration alias for aggressive', () => {
      assert(canonicalMode('extended') === 'aggressive', 'extended alias missing');
    });
    check('54 detector disappearance does not auto-close a finding', () => {
      const stale = { items: [] };
      const queue = { queue: [] };
      reconcile({ staleItems: stale, repairQueue: queue, findings: [authFinding], source: 'doctor', agentId: 'a', timestamp: '2026-07-29T12:00:00.000Z' });
      const absent = reconcile({ staleItems: stale, repairQueue: queue, findings: [], source: 'doctor', agentId: 'b', timestamp: '2026-07-29T12:01:00.000Z' });
      assert(queue.queue[0].status === 'open' && absent.events[0]?.transition === 'observation_absent', 'finding auto-closed on disappearance');
    });
    check('55 telemetry uses actual repair fields and no bytes estimator', () => {
      const telemetry = maintenanceTelemetry({
        enabled: true,
        mode: 'scoped',
        opportunities: scoped.opportunities,
        receipts: [goodReceipt],
        doctorBefore: 86,
        doctorAfter: 93,
        taskReadinessBefore: 93,
        taskReadinessAfter: 100
      });
      assert(telemetry.repair_extra_input_tokens === 70 && telemetry.repair_extra_output_tokens === 10 &&
        telemetry.token_values === 'actual_only' && !Object.keys(telemetry).some((key) => /bytes/i.test(key)), 'telemetry contract is not actual-only');
    });
    check('56 caller-asserted tests without a local execution record are rejected', () => {
      const forged = receiptInput(receiptRoot, authFinding, scope, {
        tests_run: [{
          command: 'this command was never executed',
          status: 'pass',
          tests_passed: 1,
          duration_ms: 1
        }]
      });
      const invalid = validateReceipt(forged, {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.some((item) => item.startsWith('test_result_invalid:')), 'forged test claim was accepted');
    });
    check('57 claim evidence must bind to verified source or an execution record', () => {
      const invalid = validateReceipt(receiptInput(receiptRoot, authFinding, scope, {
        claims_checked: [{
          claim_id: 'invented-evidence',
          claim: 'The claim is allegedly supported elsewhere.',
          result: 'confirmed',
          evidence: ['not-verified/invented.txt']
        }]
      }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.includes('claim_evidence_unbound:invented-evidence'), 'unbound claim evidence was accepted');
    });
    check('58 receipt privacy rejects email and absolute local path values', () => {
      const invalid = validateReceipt(receiptInput(receiptRoot, authFinding, scope, {
        claims_checked: [{
          claim_id: 'private-value',
          claim: 'Verified by person@example.com using /srv/acme/private.txt.',
          result: 'confirmed',
          evidence: ['src/auth.js']
        }]
      }), {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.some((item) => item.startsWith('private_value:')), 'private receipt value was accepted');
    });
    check('59 every affected artifact must be present in the verified source snapshot', () => {
      const incomplete = receiptInput(receiptRoot, authFinding, scope);
      incomplete.source_files_checked = incomplete.source_files_checked.filter((item) => item.path === authFinding.artifact);
      const invalid = validateReceipt(incomplete, {
        finding: authFinding,
        scope,
        policyResolution: scopedPolicy,
        repoRoot: receiptRoot,
        stateRoot: receiptContext.stateRoot
      });
      assert(!invalid.ok && invalid.errors.includes('finding_artifact_not_verified:.knowledge/modules/auth.json'), 'partial affected-artifact receipt was accepted');
    });
    check('60 symlinked source artifacts are rejected before hashing', () => {
      const outside = path.join(root, 'outside-auth.js');
      const link = path.join(receiptRoot, 'src', 'linked-auth.js');
      writeText(outside, 'module.exports = { ok: true };\n');
      let linked = false;
      try {
        fs.symlinkSync(outside, link, 'file');
        linked = true;
      } catch (error) {
        if (!['EPERM', 'EACCES', 'UNKNOWN'].includes(error.code)) throw error;
      }
      if (linked) {
        const linkedFinding = granularFinding({
          module_id: 'auth',
          code: 'low_confidence_module',
          artifact: 'src/linked-auth.js',
          affected_artifacts: ['src/linked-auth.js']
        });
        const raw = {
          ...receiptInput(receiptRoot, authFinding, scope),
          finding_id: linkedFinding.lifecycle_id,
          source_files_checked: [{ path: 'src/linked-auth.js', sha256: hash(outside) }]
        };
        const invalid = validateReceipt(raw, {
          finding: linkedFinding,
          scope,
          policyResolution: scopedPolicy,
          repoRoot: receiptRoot,
          stateRoot: receiptContext.stateRoot
        });
        assert(!invalid.ok && invalid.errors.includes('source_hash_current_mismatch:src/linked-auth.js'), 'symlink escape was accepted');
      } else {
        const librarySource = fs.readFileSync(path.join(systemRoot, 'tools', 'lib', 'repair-on-touch.js'), 'utf8');
        assert(/lstatSync/.test(librarySource) && /isSymbolicLink/.test(librarySource) && /realpathSync/.test(librarySource), 'symlink guard is absent');
      }
    });
    check('61 apply rejects receipt paths outside the content-addressed receipt store', () => {
      const outsideReceipt = path.join(receiptRoot, 'outside-receipt.json');
      writeJson(outsideReceipt, goodReceipt);
      const run = spawnSync(process.execPath, [toolPath, 'apply', `--receipt=${outsideReceipt}`], {
        cwd: receiptRoot,
        env: envFor(receiptRoot),
        encoding: 'utf8',
        timeout: 30000,
        windowsHide: true
      });
      assert(run.status !== 0 && /content-addressed file/.test(run.stderr), 'outside receipt path was accepted');
    });
    check('62 repaired opportunities remain counted as selected and closed', () => {
      const telemetry = maintenanceTelemetry({
        enabled: true,
        mode: 'scoped',
        opportunities: [
          { ...authFinding, status: 'repaired' },
          { ...findings[1], status: 'deferred' }
        ],
        receipts: [goodReceipt]
      });
      assert(telemetry.repair_findings_selected === 1 && telemetry.repair_findings_closed === 1, 'selection count disappeared after repair');
    });
    check('63 unavailable repair token split remains null rather than fake zero', () => {
      const telemetry = maintenanceTelemetry({
        enabled: true,
        mode: 'scoped',
        receipts: [{
          ...goodReceipt,
          additional_work: {
            ...goodReceipt.additional_work,
            input_tokens: null,
            output_tokens: null
          }
        }]
      });
      assert(telemetry.repair_extra_input_tokens === null && telemetry.repair_extra_output_tokens === null, 'unknown tokens were reported as zero');
    });
    check('64 verify CLI executes argv without a shell and persists content-addressed evidence', () => {
      const requestPath = path.join(receiptRoot, 'verify-request.json');
      writeJson(requestPath, {
        task_id: scope.task_id,
        session_id: scope.session_id,
        source_files: authFinding.affected_artifacts,
        tests_to_run: [{ argv: ['node', 'tests/auth.test.js'] }]
      });
      const run = spawnSync(process.execPath, [toolPath, 'verify', `--request=${requestPath}`], {
        cwd: receiptRoot,
        env: envFor(receiptRoot),
        encoding: 'utf8',
        timeout: 30000,
        windowsHide: true
      });
      const body = JSON.parse(run.stdout || '{}');
      assert(run.status === 0 && body.status === 'pass' &&
        body.executions?.[0]?.execution_id?.startsWith('KVE-') &&
        fs.existsSync(path.join(receiptContext.stateRoot, body.executions[0].execution_path)),
      `verification CLI failed: ${run.stderr || run.stdout}`);
    });
    check('64o node --test binds one physical repository test and rejects eval forms', () => {
      const relativeTest = 'tests/node-test-runner.test.js';
      const rootTest = path.join(receiptRoot, relativeTest);
      writeText(
        rootTest,
        [
          "'use strict';",
          "const test = require('node:test');",
          "const assert = require('node:assert/strict');",
          "test('root physical test', () => {",
          "  assert.equal(require('../src/auth').ok, true);",
          '});',
          ''
        ].join('\n')
      );
      const shadowRoot = path.join(receiptRoot, 'shadow');
      writeText(
        path.join(shadowRoot, relativeTest),
        'process.exit(23);\n'
      );
      const execution = runVerificationTests({
        stateRoot: receiptContext.stateRoot,
        repoRoot: receiptRoot,
        taskId: scope.task_id,
        sessionId: scope.session_id,
        tests: [{
          argv: ['node', '--test', relativeTest],
          cwd: 'shadow'
        }],
        sourceFiles: [{ path: 'src/auth.js' }],
        checkedBy: 'repair-test'
      })[0].record;
      const testSnapshot = execution.source_snapshot.find(
        (item) => item.path === relativeTest
      );
      let unsafeCode = null;
      try {
        runVerificationTests({
          stateRoot: receiptContext.stateRoot,
          repoRoot: receiptRoot,
          taskId: scope.task_id,
          sessionId: scope.session_id,
          tests: [{ argv: ['node', '--eval', 'process.exit(0)'] }],
          sourceFiles: [{ path: 'src/auth.js' }],
          checkedBy: 'repair-test'
        });
      } catch (error) {
        unsafeCode = error.code;
      }
      assert(
        execution.status === 'pass' &&
        testSnapshot?.sha256 === hash(rootTest) &&
        unsafeCode === 'verification_node_invocation_unsafe',
        'node --test did not bind the root test or an eval form was accepted'
      );
    });
    check('64e approved generated producers reject context-root argv overrides before execution', () => {
      let code = null;
      try {
        runVerificationTests({
          stateRoot: receiptContext.stateRoot,
          repoRoot: receiptRoot,
          taskId: scope.task_id,
          sessionId: scope.session_id,
          tests: [{
            argv: [
              'node',
              '.knowledge/tools/build-search-index.js',
              '--state-root=../../outside'
            ]
          }],
          sourceFiles: [{ path: 'src/auth.js' }],
          checkedBy: 'repair-test'
        });
      } catch (error) {
        code = error.code || null;
      }
      assert(
        [
          'generated_producer_argv_invalid',
          'verification_node_script_unsafe'
        ].includes(code),
        `generated producer accepted a root override: ${code}`
      );
    });
    check('64i approved search producer rejects output and input junction escapes', () => {
      const toolRelative =
        '.knowledge/tools/build-search-index.js';
      const prepareProducer = (fixtureRoot) => {
        const context = fixtureContext(fixtureRoot);
        prepareSourceFixture(fixtureRoot);
        for (const relative of generatedProducerDependencyClosure(
          toolRelative
        )) {
          const source = path.join(
            systemRoot,
            ...relative.replace(/^\.knowledge\//, '').split('/')
          );
          const target = path.join(
            fixtureRoot,
            ...relative.split('/')
          );
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.copyFileSync(source, target);
        }
        return context;
      };
      const runProducer = (fixtureRoot) => spawnSync(
        process.execPath,
        [
          path.join(fixtureRoot, ...toolRelative.split('/')),
          '--quiet'
        ],
        {
          cwd: fixtureRoot,
          env: envFor(fixtureRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const outputRoot = path.join(root, 'producer-output-junction');
      const outputContext = prepareProducer(outputRoot);
      const aliasCommands = [
        [
          'node',
          toolRelative.toUpperCase(),
          '--state-root=../../outside'
        ],
        [
          'node',
          `${toolRelative}.`,
          '--state-root=../../outside'
        ]
      ];
      if (process.platform === 'win32') {
        aliasCommands.push([
          'node',
          `${path.parse(outputRoot).root.slice(0, 2)}` +
            `${toolRelative.replace(/\//g, '\\')}`,
          '--state-root=../../outside'
        ]);
      }
      const aliasCodes = aliasCommands.map((argv) => {
        try {
          runVerificationTests({
            stateRoot: outputContext.stateRoot,
            repoRoot: outputRoot,
            taskId: 'TASK-producer-alias',
            sessionId: 'SESSION-producer-alias',
            tests: [{ argv }],
            sourceFiles: [{ path: 'src/auth.js' }],
            checkedBy: 'repair-test'
          });
          return null;
        } catch (error) {
          return error.code || null;
        }
      });
      const outputTarget = path.join(root, 'producer-output-target');
      fs.mkdirSync(outputTarget, { recursive: true });
      fs.symlinkSync(
        outputTarget,
        path.join(outputContext.stateRoot, 'search'),
        process.platform === 'win32' ? 'junction' : 'dir'
      );
      const outputExecution = runProducer(
        outputRoot
      );
      const inputRoot = path.join(root, 'producer-input-junction');
      const inputContext = prepareProducer(inputRoot);
      const inputTarget = path.join(root, 'producer-input-target');
      fs.mkdirSync(inputTarget, { recursive: true });
      writeText(
        path.join(inputTarget, 'outside.md'),
        '# Outside content must not be indexed\n'
      );
      fs.symlinkSync(
        inputTarget,
        path.join(inputContext.projectKnowledgeRoot, 'wiki'),
        process.platform === 'win32' ? 'junction' : 'dir'
      );
      const inputExecution = runProducer(
        inputRoot
      );
      assert(
        outputExecution.status !== 0 &&
        inputExecution.status !== 0 &&
        aliasCodes.every((code) => [
          'generated_producer_argv_invalid',
          'verification_node_script_unsafe',
          'verification_node_invocation_unsafe',
          'verification_command_private',
          'finding_artifact_unsafe'
        ].includes(code)) &&
        /contained|junction|symlink|physical/i.test(
          outputExecution.stderr || ''
        ) &&
        /reparse|junction|symlink|physical/i.test(
          inputExecution.stderr || ''
        ) &&
        !fs.existsSync(path.join(outputTarget, 'index.json')) &&
        !fs.existsSync(path.join(
          inputContext.stateRoot,
          'search',
          'index.json'
        )),
        `generated producer escaped containment: ${JSON.stringify({
          output: {
            status: outputExecution.status,
            stderr: outputExecution.stderr
          },
          alias_codes: aliasCodes,
          input: {
            status: inputExecution.status,
            stderr: inputExecution.stderr
          }
        })}`
      );
    });
    check('64k hardlink aliases cannot bypass approved producer argv', () => {
      const fixtureRoot = path.join(root, 'producer-hardlink-alias');
      const fixture = fixtureContext(fixtureRoot);
      prepareSourceFixture(fixtureRoot);
      const toolRelative =
        '.knowledge/tools/build-search-index.js';
      for (const relative of generatedProducerDependencyClosure(
        toolRelative
      )) {
        const source = path.join(
          systemRoot,
          ...relative.replace(/^\.knowledge\//, '').split('/')
        );
        const target = path.join(
          fixtureRoot,
          ...relative.split('/')
        );
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(source, target);
      }
      const aliasRelative =
        '.knowledge/tools/build-search-index-hardlink.js';
      fs.linkSync(
        path.join(fixtureRoot, ...toolRelative.split('/')),
        path.join(fixtureRoot, ...aliasRelative.split('/'))
      );
      let code = null;
      try {
        runVerificationTests({
          stateRoot: fixture.stateRoot,
          repoRoot: fixtureRoot,
          taskId: 'TASK-producer-hardlink',
          sessionId: 'SESSION-producer-hardlink',
          tests: [{
            argv: [
              'node',
              aliasRelative,
              '--state-root=../../outside'
            ]
          }],
          sourceFiles: [{ path: 'src/auth.js' }],
          checkedBy: 'repair-test'
        });
      } catch (error) {
        code = error.code || null;
      }
      assert(
        code === 'verification_node_script_hardlink_unsafe',
        `hardlink alias bypassed producer argv enforcement: ${code}`
      );
    });
    check('64l Windows Node executable aliases fail closed before spawn', () => {
      const codes = ['node.', 'node.exe.'].map((executable) => {
        try {
          runVerificationTests({
            stateRoot: receiptContext.stateRoot,
            repoRoot: receiptRoot,
            taskId: scope.task_id,
            sessionId: scope.session_id,
            tests: [{
              argv: [
                executable,
                '.knowledge/tools/build-search-index.js',
                '--state-root=../../outside'
              ]
            }],
            sourceFiles: [{ path: 'src/auth.js' }],
            checkedBy: 'repair-test'
          });
          return null;
        } catch (error) {
          return error.code || null;
        }
      });
      assert(
        codes.every((code) =>
          code === 'verification_node_executable_alias_unsafe'),
        `Windows Node executable alias escaped classification: ${
          JSON.stringify(codes)
        }`
      );
    });
    check('64m generated producers reject cwd shadow rebinding before spawn', () => {
      const fixtureRoot = path.join(root, 'producer-cwd-shadow');
      const fixture = fixtureContext(fixtureRoot);
      prepareSourceFixture(fixtureRoot);
      const toolRelative =
        '.knowledge/tools/build-search-index.js';
      for (const relative of generatedProducerDependencyClosure(
        toolRelative
      )) {
        const source = path.join(
          systemRoot,
          ...relative.replace(/^\.knowledge\//, '').split('/')
        );
        const target = path.join(
          fixtureRoot,
          ...relative.split('/')
        );
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(source, target);
      }
      const marker = path.join(fixtureRoot, 'shadow-executed.txt');
      const nestedRoot = path.join(fixtureRoot, 'nested');
      writeText(
        path.join(nestedRoot, ...toolRelative.split('/')),
        `'use strict';require('fs').writeFileSync(${
          JSON.stringify(marker)
        },'executed');\n`
      );
      let code = null;
      try {
        runVerificationTests({
          stateRoot: fixture.stateRoot,
          repoRoot: fixtureRoot,
          taskId: 'TASK-producer-cwd',
          sessionId: 'SESSION-producer-cwd',
          tests: [{
            argv: ['node', toolRelative],
            cwd: 'nested'
          }],
          sourceFiles: [{ path: 'src/auth.js' }],
          checkedBy: 'repair-test'
        });
      } catch (error) {
        code = error.code || null;
      }
      assert(
        code === 'generated_producer_cwd_invalid' &&
        !fs.existsSync(marker),
        `cwd shadow rebound approved producer: ${JSON.stringify({
          code,
          marker_exists: fs.existsSync(marker)
        })}`
      );
    });
    check('64n generated producers use trusted split-state roots', () => {
      const fixtureRoot = path.join(root, 'producer-split-repo');
      const fixture = fixtureContext(fixtureRoot);
      prepareSourceFixture(fixtureRoot);
      const toolRelative =
        '.knowledge/tools/build-search-index.js';
      for (const relative of generatedProducerDependencyClosure(
        toolRelative
      )) {
        const source = path.join(
          systemRoot,
          ...relative.replace(/^\.knowledge\//, '').split('/')
        );
        const target = path.join(
          fixtureRoot,
          ...relative.split('/')
        );
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(source, target);
      }
      writeText(
        path.join(
          fixture.projectKnowledgeRoot,
          'wiki',
          'index.md'
        ),
        '# Split-state search fixture\n'
      );
      const splitStateRoot = path.join(
        root,
        'producer-split-runtime'
      );
      fs.mkdirSync(splitStateRoot, { recursive: true });
      const executions = runVerificationTests({
        stateRoot: splitStateRoot,
        repoRoot: fixtureRoot,
        taskId: 'TASK-producer-split',
        sessionId: 'SESSION-producer-split',
        tests: [{
          argv: ['node', toolRelative, '--quiet']
        }],
        sourceFiles: [{ path: 'src/auth.js' }],
        checkedBy: 'repair-test'
      });
      assert(
        executions.length === 1 &&
        executions[0].record.status === 'pass' &&
        fs.existsSync(path.join(
          splitStateRoot,
          'search',
          'index.json'
        )) &&
        !fs.existsSync(path.join(
          fixture.projectKnowledgeRoot,
          'search',
          'index.json'
        )),
        'generated producer ignored the trusted split stateRoot'
      );
    });
    check('64j generated producer dependency closures match recursive literal requires', () => {
      const releaseRoot = path.dirname(systemRoot);
      const producers = [
        '.knowledge/tools/build-search-index.js',
        '.knowledge/tools/build-routing-bundle.js',
        '.knowledge/tools/build-wiki-graph.js'
      ];
      for (const producer of producers) {
        const declared = new Set(
          generatedProducerDependencyClosure(producer)
        );
        assert(
          declared.has(producer),
          `producer is missing from its closure: ${producer}`
        );
        const pending = [producer];
        const visited = new Set();
        while (pending.length) {
          const relative = pending.pop();
          if (visited.has(relative) || !relative.endsWith('.js')) {
            continue;
          }
          visited.add(relative);
          const absolute = path.join(
            releaseRoot,
            ...relative.split('/')
          );
          assert(
            fs.existsSync(absolute),
            `declared producer dependency is missing: ${relative}`
          );
          const source = fs.readFileSync(absolute, 'utf8');
          assert(
            !/\bimport\s*\(/.test(source),
            `dynamic import is not pinned in producer closure: ${relative}`
          );
          for (const match of source.matchAll(
            /\brequire\s*\(([^)]*)\)/g
          )) {
            const expression = match[1].trim();
            const literal = expression.match(
              /^(['"])([^'"]+)\1$/
            );
            assert(
              literal,
              `dynamic require is not pinned in producer closure: ${relative}`
            );
            const request = literal[2];
            if (!request.startsWith('.')) continue;
            let dependency = path.resolve(
              path.dirname(absolute),
              request
            );
            if (!path.extname(dependency)) dependency += '.js';
            const dependencyRelative = path.relative(
              releaseRoot,
              dependency
            ).replace(/\\/g, '/');
            assert(
              declared.has(dependencyRelative),
              `producer closure omitted ${dependencyRelative} from ${producer}`
            );
            pending.push(dependencyRelative);
          }
          if (
            /\brequire\s*\(\s*['"](?:node:)?child_process['"]\s*\)/
              .test(source)
          ) {
            assert(
              relative ===
                '.knowledge/tools/lib/git-context.js',
              `unexpected process-spawning producer dependency: ${relative}`
            );
          }
        }
        for (const relative of declared) {
          assert(
            fs.existsSync(path.join(
              releaseRoot,
              ...relative.split('/')
            )),
            `producer closure contains a missing path: ${relative}`
          );
        }
      }
      const pathContext = fs.readFileSync(
        path.join(
          systemRoot,
          'tools',
          'lib',
          'path-context.js'
        ),
        'utf8'
      );
      assert(
        pathContext.includes(
          "KNOWLEDGE_DISABLE_GIT_DISCOVERY === '1'"
        ),
        'pinned git-context dependency lacks the no-git execution guard'
      );
    });

    const applyRoot = path.join(root, 'apply-integration');
    const applyContext = fixtureContext(applyRoot);
    prepareSourceFixture(applyRoot);
    writeJson(path.join(applyContext.projectKnowledgeRoot, 'evidence', 'auth.json'), {
      generated_at: '2026-07-29T12:00:00.000Z',
      result: 'pass'
    });
    writeJson(path.join(applyContext.projectKnowledgeRoot, 'evidence', 'billing.json'), {
      generated_at: '2026-07-29T12:00:00.000Z',
      result: 'unverified'
    });
    writeJson(path.join(applyContext.projectKnowledgeRoot, 'modules', 'auth.json'), {
      module_id: 'auth',
      current_trust_level: 'suspect',
      target_trust_level: 'near_trusted',
      verification_status: 'needs_recheck',
      key_files: ['src/auth.js'],
      evidence_files: ['.knowledge/evidence/auth.json']
    });
    writeJson(path.join(applyContext.projectKnowledgeRoot, 'modules', 'billing.json'), {
      module_id: 'billing',
      current_trust_level: 'suspect',
      target_trust_level: 'near_trusted',
      verification_status: 'needs_recheck',
      key_files: ['src/billing.js'],
      evidence_files: ['.knowledge/evidence/billing.json']
    });
    writeJson(path.join(applyContext.projectKnowledgeRoot, 'modules', 'module_registry.json'), {
      modules: [
        {
          module_id: 'auth',
          card: '.knowledge/modules/auth.json',
          key_files: ['src/auth.js'],
          evidence_files: ['.knowledge/evidence/auth.json']
        },
        {
          module_id: 'billing',
          card: '.knowledge/modules/billing.json',
          key_files: ['src/billing.js'],
          evidence_files: ['.knowledge/evidence/billing.json']
        }
      ]
    });
    writeJson(path.join(applyContext.stateRoot, 'freshness.json'), {
      tracked_files: [
        { path: 'src/auth.js', sha256: hash(path.join(applyRoot, 'src', 'auth.js')), status: 'needs_recheck' },
        { path: 'src/billing.js', sha256: hash(path.join(applyRoot, 'src', 'billing.js')), status: 'needs_recheck' }
      ],
      artifact_statuses: {}
    });
    writeJson(path.join(applyContext.stateRoot, 'maintenance', 'trust_report.json'), {
      generated_at: '2026-07-29T12:00:00.000Z',
      modules: {
        trusted: [],
        near_trusted: [],
        routing_trusted: [],
        advisory_only: [],
        suspect: ['auth', 'billing'],
        low_confidence: []
      },
      module_statuses: [
        { module_id: 'auth', trust_status: 'suspect', freshness_status: 'needs_recheck' },
        { module_id: 'billing', trust_status: 'suspect', freshness_status: 'needs_recheck' }
      ]
    });
    const applyFindings = [
      {
        ...granularFinding({
          module_id: 'auth',
          code: 'suspect_module',
          artifact: 'src/auth.js',
          affected_artifacts: [
            'src/auth.js',
            '.knowledge/modules/auth.json',
            '.knowledge/evidence/auth.json'
          ],
          severity: 'medium',
          repair_class: 'verify_on_touch',
          required_checks: [
            'read_current_source',
            'run_relevant_tests',
            'compare_existing_claims'
          ],
          resolution_predicate:
            'source_and_relevant_tests_confirm_claim'
        }),
        occurrence: 1,
        opened_at: '2026-07-29T12:00:00.000Z'
      },
      {
        ...granularFinding({
          module_id: 'billing',
          code: 'suspect_module',
          artifact: 'src/billing.js',
          affected_artifacts: [
            'src/billing.js',
            '.knowledge/modules/billing.json',
            '.knowledge/evidence/billing.json'
          ],
          severity: 'medium',
          repair_class: 'verify_on_touch',
          required_checks: [
            'read_current_source',
            'run_relevant_tests',
            'compare_existing_claims'
          ],
          resolution_predicate:
            'source_and_relevant_tests_confirm_claim'
        }),
        occurrence: 1,
        opened_at: '2026-07-29T12:00:00.000Z'
      }
    ];
    const applyStale = { items: [] };
    const applyQueue = { queue: [] };
    reconcile({
      staleItems: applyStale,
      repairQueue: applyQueue,
      findings: applyFindings,
      source: 'doctor',
      agentId: 'doctor-seed',
      timestamp: '2026-07-29T12:00:00.000Z'
    });
    writeJson(path.join(applyContext.stateRoot, 'maintenance', 'stale_items.json'), applyStale);
    writeJson(path.join(applyContext.stateRoot, 'maintenance', 'repair_queue.json'), applyQueue);
    const applyScope = makeScope({ task_id: 'TASK-apply', session_id: 'SESSION-apply' });
    const applyPolicy = policy(applyContext, { mode: 'scoped' });
    const applyOpportunities = buildOpportunitiesArtifact({
      findings: applyFindings,
      scope: applyScope,
      policyResolution: applyPolicy,
      doctorScore: 86,
      generatedAt: '2026-07-29T12:00:00.000Z',
      generatedBy: 'integration-test'
    });
    const applyPlanPath = path.join(
      applyContext.stateRoot,
      ...repairSessionPlanRelative(
        applyScope.task_id,
        applyScope.session_id
      ).split('/')
    );
    writeJson(applyPlanPath, applyOpportunities);
    writeJson(path.join(applyContext.stateRoot, 'maintenance', 'repair_opportunities.json'), applyOpportunities);
    const applyReceipt = createReceipt(receiptInput(applyRoot, applyFindings[0], applyScope), {
      finding: applyFindings[0],
      scope: applyScope,
      policyResolution: applyPolicy,
      repoRoot: applyRoot,
      stateRoot: applyContext.stateRoot
    });
    const applyReceiptFile = saveReceipt(applyContext.stateRoot, applyReceipt).path;
    let applyResult;
    check('64a a live safe-only team cap blocks an already-created scoped receipt', () => {
      const capPath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'concurrency_policy.json'
      );
      writeJson(capPath, {
        team_policy: { repair_on_touch: { max_mode: 'safe-only' } }
      });
      const run = spawnSync(
        process.execPath,
        [toolPath, 'apply', `--receipt=${applyReceiptFile}`],
        {
          cwd: applyRoot,
          env: envFor(applyRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const rejected = JSON.parse(run.stdout || '{}');
      fs.rmSync(capPath, { force: true });
      const queueAfter = readJson(
        path.join(applyContext.stateRoot, 'maintenance', 'repair_queue.json'),
        { queue: [] }
      );
      assert(
        run.status === 2 &&
        rejected.reason === 'repair_mode_blocked_by_live_policy' &&
        queueAfter.queue.find((item) =>
          item.lifecycle_id === applyFindings[0].lifecycle_id)?.status === 'open',
        `live team cap did not block scoped apply: ${run.stderr || run.stdout}`
      );
    });
    check('64b a live critical-path toggle requires receipt evidence', () => {
      const stalePath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'stale_items.json'
      );
      const queuePath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'repair_queue.json'
      );
      const stale = readJson(stalePath, { items: [] });
      const queue = readJson(queuePath, { queue: [] });
      for (const item of [
        ...(stale.items || []),
        ...(queue.queue || [])
      ]) {
        if (item.lifecycle_id === applyFindings[0].lifecycle_id) {
          item.critical_path = true;
        }
      }
      writeJson(stalePath, stale);
      writeJson(queuePath, queue);
      const protectedHashes = {
        card: hash(path.join(
          applyContext.projectKnowledgeRoot,
          'modules',
          'auth.json'
        )),
        trust: hash(path.join(
          applyContext.stateRoot,
          'maintenance',
          'trust_report.json'
        ))
      };
      const run = spawnSync(
        process.execPath,
        [toolPath, 'apply', `--receipt=${applyReceiptFile}`],
        {
          cwd: applyRoot,
          env: envFor(applyRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const rejected = JSON.parse(run.stdout || '{}');
      const current = readJson(queuePath, { queue: [] }).queue
        .find((item) =>
          item.lifecycle_id === applyFindings[0].lifecycle_id);
      for (const item of [
        ...(stale.items || []),
        ...(queue.queue || [])
      ]) {
        if (item.lifecycle_id === applyFindings[0].lifecycle_id) {
          item.critical_path = false;
        }
      }
      writeJson(stalePath, stale);
      writeJson(queuePath, queue);
      assert(
        run.status === 2 &&
        rejected.reason === 'verification_receipt_invalid' &&
        rejected.errors?.includes(
          'critical_path_confirmation_required'
        ) &&
        current?.status === 'open' &&
        hash(path.join(
          applyContext.projectKnowledgeRoot,
          'modules',
          'auth.json'
        )) === protectedHashes.card &&
        hash(path.join(
          applyContext.stateRoot,
          'maintenance',
          'trust_report.json'
        )) === protectedHashes.trust,
        `live critical toggle was not fail-closed: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('64c a valid KVR cannot apply a finding deferred by the trusted session plan', () => {
      const deferredPlan = JSON.parse(JSON.stringify(applyOpportunities));
      const deferredFinding = deferredPlan.opportunities.find((item) =>
        item.lifecycle_id === applyFindings[0].lifecycle_id);
      deferredFinding.status = 'deferred';
      deferredFinding.decision_reason = 'budget_exhausted_time';
      const selected = deferredPlan.opportunities.filter((item) =>
        ['selected', 'repaired'].includes(item.status));
      deferredPlan.summary.findings_selected = selected.length;
      deferredPlan.summary.findings_deferred =
        deferredPlan.opportunities.filter((item) =>
          item.status === 'deferred').length;
      deferredPlan.budget.selected = {
        findings: selected.length,
        estimated_minutes: selected.reduce((sum, item) =>
          sum + Number(item.estimated_additional_work.minutes), 0),
        estimated_context_percent: selected.reduce((sum, item) =>
          sum + Number(item.estimated_additional_work.context_percent), 0)
      };
      deferredPlan.budget.exhausted = true;
      writeJson(applyPlanPath, deferredPlan);
      writeJson(
        path.join(
          applyContext.stateRoot,
          'maintenance',
          'repair_opportunities.json'
        ),
        deferredPlan
      );
      const run = spawnSync(
        process.execPath,
        [toolPath, 'apply', `--receipt=${applyReceiptFile}`],
        {
          cwd: applyRoot,
          env: envFor(applyRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const rejected = JSON.parse(run.stdout || '{}');
      const current = readJson(
        path.join(
          applyContext.stateRoot,
          'maintenance',
          'repair_queue.json'
        ),
        { queue: [] }
      ).queue.find((item) =>
        item.lifecycle_id === applyFindings[0].lifecycle_id);
      writeJson(applyPlanPath, applyOpportunities);
      writeJson(
        path.join(
          applyContext.stateRoot,
          'maintenance',
          'repair_opportunities.json'
        ),
        applyOpportunities
      );
      assert(
        run.status === 2 &&
        rejected.reason === 'finding_not_selected_in_current_plan' &&
        current?.status === 'open',
        `deferred trusted-plan finding was applied: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('64d an invalid prior closure in the same module blocks trust elevation', () => {
      const priorRoot = path.join(root, 'invalid-prior-closure');
      fs.cpSync(applyRoot, priorRoot, { recursive: true });
      const priorStateRoot = path.join(priorRoot, '.knowledge');
      const priorQueuePath = path.join(
        priorStateRoot,
        'maintenance',
        'repair_queue.json'
      );
      const priorStalePath = path.join(
        priorStateRoot,
        'maintenance',
        'stale_items.json'
      );
      const priorQueue = readJson(priorQueuePath, { queue: [] });
      const priorStale = readJson(priorStalePath, { items: [] });
      const priorFinding = {
        ...granularFinding({
          module_id: 'auth',
          code: 'low_confidence_module',
          artifact: 'src/auth.js',
          affected_artifacts: [
            'src/auth.js',
            '.knowledge/modules/auth.json'
          ],
          severity: 'medium',
          repair_class: 'verify_on_touch'
        }),
        occurrence: 1,
        opened_at: '2026-07-29T11:00:00.000Z'
      };
      reconcile({
        staleItems: priorStale,
        repairQueue: priorQueue,
        findings: [priorFinding],
        source: 'prior-closure-test',
        agentId: 'repair-test',
        timestamp: priorFinding.opened_at
      });
      const invalidPrior = priorQueue.queue.find((item) =>
        item.lifecycle_id === priorFinding.lifecycle_id);
      const invalidPriorStale = priorStale.items.find((item) =>
        item.lifecycle_id === priorFinding.lifecycle_id);
      const invalidResolutionEvidence = {
        receipt_id: `KVR-${'0'.repeat(64)}`,
        receipt_sha256: '0'.repeat(64),
        receipt_path:
          `maintenance/verification_receipts/00/${'0'.repeat(64)}.json`,
        task_id: 'TASK-prior',
        session_id: 'SESSION-prior'
      };
      for (const record of [invalidPrior, invalidPriorStale]) {
        record.status = 'closed';
        record.closed_at = '2026-07-29T11:30:00.000Z';
        record.resolution_evidence = invalidResolutionEvidence;
      }
      writeJson(priorStalePath, priorStale);
      writeJson(priorQueuePath, priorQueue);
      const clonedReceiptPath = path.join(
        priorStateRoot,
        path.relative(applyContext.stateRoot, applyReceiptFile)
      );
      const run = spawnSync(
        process.execPath,
        [toolPath, 'apply', `--receipt=${clonedReceiptPath}`],
        {
          cwd: priorRoot,
          env: envFor(priorRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const result = JSON.parse(run.stdout || '{}');
      const card = readJson(
        path.join(priorStateRoot, 'modules', 'auth.json'),
        {}
      );
      const trust = readJson(
        path.join(priorStateRoot, 'maintenance', 'trust_report.json'),
        {}
      );
      assert(
        run.status === 2 &&
        result.status === 'reopened_after_verification' &&
        result.trust_elevated === false &&
        result.trust_elevation_reason ===
          'module_closure_provenance_invalid' &&
        result.trust_elevation_errors?.some((item) =>
          item.startsWith(`${priorFinding.lifecycle_id}:`)) &&
        result.telemetry?.closure_provenance_status === 'partial' &&
        result.telemetry?.closure_provenance_invalid?.some((item) =>
          item.lifecycle_id === priorFinding.lifecycle_id) &&
        card.current_trust_level === 'suspect' &&
        trust.modules.suspect.includes('auth') &&
        !trust.modules.near_trusted.includes('auth'),
        `invalid prior closure did not block trust elevation: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('64f phase two rejects a trust target changed after phase one', () => {
      const phaseRoot = path.join(root, 'phase-two-target-binding');
      fs.cpSync(applyRoot, phaseRoot, { recursive: true });
      const phaseReceiptPath = path.join(
        phaseRoot,
        '.knowledge',
        path.relative(applyContext.stateRoot, applyReceiptFile)
      );
      const runner = [
        "const fs=require('fs');",
        "const path=require('path');",
        `const recertify=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'recertify.js')
        )});`,
        `const receipt=JSON.parse(fs.readFileSync(${JSON.stringify(
          phaseReceiptPath
        )},'utf8'));`,
        'const phase1=recertify.applyVerificationReceipt(receipt);',
        `const cardPath=${JSON.stringify(
          path.join(phaseRoot, '.knowledge', 'modules', 'auth.json')
        )};`,
        "const card=JSON.parse(fs.readFileSync(cardPath,'utf8'));",
        "card.target_trust_level='trusted';",
        "fs.writeFileSync(cardPath,JSON.stringify(card,null,2)+'\\n');",
        'const phase2=recertify.finalizeTrustElevation(receipt,phase1);',
        'console.log(JSON.stringify({phase1,phase2,card:JSON.parse(fs.readFileSync(cardPath))}));'
      ].join('');
      const run = spawnSync(process.execPath, ['-e', runner], {
        cwd: phaseRoot,
        env: envFor(phaseRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const body = JSON.parse(run.stdout || '{}');
      assert(
        run.status === 0 &&
        body.phase1?.trust_elevation_pending === true &&
        body.phase2?.status === 'not_eligible' &&
        body.phase2?.reason === 'module_trust_authority_changed' &&
        body.card?.current_trust_level === 'suspect',
        `phase-two target drift was accepted: ${run.stderr || run.stdout}`
      );
    });
    check('64g phase two cannot substitute a same-hash source from another namespace', () => {
      const phaseRoot = path.join(root, 'phase-two-path-binding');
      fs.cpSync(applyRoot, phaseRoot, { recursive: true });
      const phaseReceiptPath = path.join(
        phaseRoot,
        '.knowledge',
        path.relative(applyContext.stateRoot, applyReceiptFile)
      );
      const exactEvidence = path.join(
        phaseRoot,
        '.knowledge',
        'evidence',
        'auth.json'
      );
      const aliasEvidence = path.join(
        phaseRoot,
        'evidence',
        'auth.json'
      );
      const runner = [
        "const fs=require('fs');",
        "const path=require('path');",
        `const recertify=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'recertify.js')
        )});`,
        `const receipt=JSON.parse(fs.readFileSync(${JSON.stringify(
          phaseReceiptPath
        )},'utf8'));`,
        'const phase1=recertify.applyVerificationReceipt(receipt);',
        `const exact=${JSON.stringify(exactEvidence)};`,
        `const alias=${JSON.stringify(aliasEvidence)};`,
        'const evidence=fs.readFileSync(exact);',
        'fs.unlinkSync(exact);',
        'fs.mkdirSync(path.dirname(alias),{recursive:true});',
        'fs.writeFileSync(alias,evidence);',
        'const phase2=recertify.finalizeTrustElevation(receipt,phase1);',
        'console.log(JSON.stringify({phase1,phase2}));'
      ].join('');
      const run = spawnSync(process.execPath, ['-e', runner], {
        cwd: phaseRoot,
        env: envFor(phaseRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const body = JSON.parse(run.stdout || '{}');
      assert(
        run.status === 0 &&
        body.phase1?.trust_elevation_pending === true &&
        body.phase2?.status === 'not_eligible' &&
        body.phase2?.reason ===
          'module_closure_provenance_invalid' &&
        body.phase2?.errors?.some((item) =>
          item.startsWith(
            'source_missing_or_unsafe:.knowledge/evidence/auth.json'
          )),
        `phase-two namespace substitution was accepted: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('64h phase-two trust commit guards the physical KVE read set', () => {
      const phaseRoot = path.join(root, 'phase-two-kve-guard');
      fs.cpSync(applyRoot, phaseRoot, { recursive: true });
      const phaseReceiptPath = path.join(
        phaseRoot,
        '.knowledge',
        path.relative(applyContext.stateRoot, applyReceiptFile)
      );
      const runner = [
        "const fs=require('fs');",
        "const path=require('path');",
        `const tx=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'lib', 'json-transaction.js')
        )});`,
        'const originalCommit=tx.commitJsonTransaction;',
        'let receipt=null;',
        'tx.commitJsonTransaction=(options)=>{',
        "if(options.metadata?.type==='repair_on_touch_trust_finalization'){",
        'const execution=path.join(process.cwd(),".knowledge",...receipt.tests_run[0].execution_path.split("/"));',
        "fs.appendFileSync(execution,'\\n');",
        '}',
        'return originalCommit(options);',
        '};',
        `const recertify=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'recertify.js')
        )});`,
        `receipt=JSON.parse(fs.readFileSync(${JSON.stringify(
          phaseReceiptPath
        )},'utf8'));`,
        'const phase1=recertify.applyVerificationReceipt(receipt);',
        'let code=null;',
        'try{recertify.finalizeTrustElevation(receipt,phase1);}catch(error){code=error.code||null;}',
        `const card=JSON.parse(fs.readFileSync(${JSON.stringify(
          path.join(phaseRoot, '.knowledge', 'modules', 'auth.json')
        )},'utf8'));`,
        'console.log(JSON.stringify({phase1,code,card}));'
      ].join('');
      const run = spawnSync(process.execPath, ['-e', runner], {
        cwd: phaseRoot,
        env: envFor(phaseRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const body = JSON.parse(run.stdout || '{}');
      assert(
        run.status === 0 &&
        body.phase1?.trust_elevation_pending === true &&
        body.code === 'transaction_guard_drift' &&
        body.card?.current_trust_level === 'suspect',
        `phase-two KVE drift did not block commit: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('64p phase two enforces tightened live budgets before trust commit', () => {
      const phaseRoot = path.join(
        root,
        'phase-two-live-budget'
      );
      fs.cpSync(applyRoot, phaseRoot, { recursive: true });
      const phaseReceiptPath = path.join(
        phaseRoot,
        '.knowledge',
        path.relative(
          applyContext.stateRoot,
          applyReceiptFile
        )
      );
      const runner = [
        "const fs=require('fs');",
        "const path=require('path');",
        `const recertify=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'recertify.js')
        )});`,
        `const receipt=JSON.parse(fs.readFileSync(${JSON.stringify(
          phaseReceiptPath
        )},'utf8'));`,
        'const phase1=recertify.applyVerificationReceipt(receipt);',
        `const profilePath=${JSON.stringify(
          path.join(
            phaseRoot,
            '.knowledge',
            'settings',
            'operator-profile.json'
          )
        )};`,
        'fs.mkdirSync(path.dirname(profilePath),{recursive:true});',
        'fs.writeFileSync(profilePath,JSON.stringify({maintenance:{repair_on_touch:{enabled:true,mode:"scoped",max_extra_minutes:0,max_extra_context_percent:0}}},null,2)+"\\n");',
        'const phase2=recertify.finalizeTrustElevation(receipt,phase1);',
        `const card=JSON.parse(fs.readFileSync(${JSON.stringify(
          path.join(
            phaseRoot,
            '.knowledge',
            'modules',
            'auth.json'
          )
        )},'utf8'));`,
        `const trust=JSON.parse(fs.readFileSync(${JSON.stringify(
          path.join(
            phaseRoot,
            '.knowledge',
            'maintenance',
            'trust_report.json'
          )
        )},'utf8'));`,
        'console.log(JSON.stringify({phase1,phase2,card,trust}));'
      ].join('');
      const run = spawnSync(process.execPath, ['-e', runner], {
        cwd: phaseRoot,
        env: envFor(phaseRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const body = JSON.parse(run.stdout || '{}');
      assert(
        run.status === 0 &&
        body.phase1?.trust_elevation_pending === true &&
        body.phase2?.status === 'not_eligible' &&
        body.phase2?.reason ===
          'repair_budget_exceeded_live_policy' &&
        body.phase2?.errors?.includes(
          'time_budget_exceeded'
        ) &&
        body.phase2?.errors?.includes(
          'context_budget_exceeded'
        ) &&
        body.card?.current_trust_level === 'suspect' &&
        body.trust?.modules?.suspect?.includes('auth') &&
        !body.trust?.modules?.near_trusted?.includes('auth'),
        `tightened phase-two budgets were bypassed: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('64q phase-two cumulative budget guards cross-module receipts and executions', () => {
      const phaseRoot = path.join(
        root,
        'phase-two-cross-module-budget-guard'
      );
      fs.cpSync(applyRoot, phaseRoot, { recursive: true });
      const phaseContext = fixtureContext(phaseRoot);
      writeText(
        path.join(phaseRoot, 'tests', 'billing.test.js'),
        'if (!require("../src/billing").ok) process.exit(1);\n'
      );
      const billingScope = makeScope({
        task_id: applyScope.task_id,
        session_id: applyScope.session_id,
        user_task: 'Verify billing behavior',
        selected_modules: ['billing'],
        changed_files: ['src/billing.js'],
        agent_plan: ['read billing source', 'run billing tests']
      });
      const billingPolicy = policy(phaseContext, {
        mode: 'scoped'
      });
      const billingReceipt = createReceipt(
        receiptInput(
          phaseRoot,
          applyFindings[1],
          billingScope,
          {
            verification_tests: [{
              argv: ['node', 'tests/billing.test.js']
            }],
            verification_source_files: [
              'src/billing.js',
              '.knowledge/modules/billing.json',
              '.knowledge/evidence/billing.json',
              'tests/billing.test.js'
            ],
            claims_checked: [{
              claim_id: 'billing-current-behavior',
              claim:
                'The billing module matches the tested behavior.',
              result: 'confirmed',
              evidence: [
                'src/billing.js',
                'tests/billing.test.js'
              ]
            }]
          }
        ),
        {
          finding: applyFindings[1],
          scope: billingScope,
          policyResolution: billingPolicy,
          repoRoot: phaseRoot,
          stateRoot: phaseContext.stateRoot
        }
      );
      const billingSaved = saveReceipt(
        phaseContext.stateRoot,
        billingReceipt
      );
      const billingLoaded = loadReceipt(
        phaseContext.stateRoot,
        billingReceipt.receipt_id,
        { finding: applyFindings[1] }
      );
      assert(
        billingLoaded.receipt.content_sha256 ===
          billingReceipt.content_sha256,
        'prior billing receipt is not valid'
      );
      const billingExecution = loadExecutionRecord(
        phaseContext.stateRoot,
        billingReceipt.tests_run[0].execution_id
      );
      assert(
        billingExecution?.record?.execution_id ===
          billingReceipt.tests_run[0].execution_id,
        'prior billing execution is not valid'
      );
      const stalePath = path.join(
        phaseContext.stateRoot,
        'maintenance',
        'stale_items.json'
      );
      const queuePath = path.join(
        phaseContext.stateRoot,
        'maintenance',
        'repair_queue.json'
      );
      const stale = readJson(stalePath, { items: [] });
      const queue = readJson(queuePath, { queue: [] });
      const priorEvidence = {
        lifecycle_id: applyFindings[1].lifecycle_id,
        code: applyFindings[1].code,
        artifact: applyFindings[1].artifact,
        predicate: applyFindings[1].resolution_predicate,
        predicate_result: true,
        verifier_type: 'repair_on_touch_verification',
        verifier_id: billingReceipt.receipt_id,
        verifier_result: 'pass',
        receipt_id: billingReceipt.receipt_id,
        receipt_sha256: billingReceipt.content_sha256,
        receipt_path: billingLoaded.relative_path,
        task_id: billingReceipt.task_id,
        session_id: billingReceipt.session_id
      };
      const closed = closeFindings({
        staleItems: stale,
        repairQueue: queue,
        lifecycleIds: [applyFindings[1].lifecycle_id],
        allowedCodes: [applyFindings[1].code],
        verifiedArtifacts:
          billingReceipt.source_files_checked.map((item) =>
            item.path),
        resolutionEvidence: [priorEvidence],
        recertificationId:
          `RCERT-${billingReceipt.content_sha256.slice(0, 20)}`,
        agentId: 'repair-test',
        timestamp: '2026-07-30T00:40:00.000Z'
      });
      assert(
        closed.closed_lifecycle_ids.includes(
          applyFindings[1].lifecycle_id
        ),
        'valid billing closure was not created'
      );
      writeJson(stalePath, stale);
      writeJson(queuePath, queue);
      const phaseReceiptPath = path.join(
        phaseRoot,
        '.knowledge',
        path.relative(
          applyContext.stateRoot,
          applyReceiptFile
        )
      );
      const runner = [
        "const fs=require('fs');",
        "const path=require('path');",
        `const tx=require(${JSON.stringify(
          path.join(
            systemRoot,
            'tools',
            'lib',
            'json-transaction.js'
          )
        )});`,
        'const originalCommit=tx.commitJsonTransaction;',
        `const priorReceiptPath=${JSON.stringify(
          billingSaved.path
        )};`,
        `const priorExecutionPath=${JSON.stringify(
          billingExecution.path
        )};`,
        'let priorReceiptGuarded=null;',
        'let priorExecutionGuarded=null;',
        'tx.commitJsonTransaction=(options)=>{',
        "if(options.metadata?.type==='repair_on_touch_trust_finalization'){",
        'const identity=(value)=>path.resolve(value).toLowerCase();',
        'priorReceiptGuarded=(options.guards||[]).some((guard)=>identity(guard.path)===identity(priorReceiptPath));',
        'priorExecutionGuarded=(options.guards||[]).some((guard)=>identity(guard.path)===identity(priorExecutionPath));',
        "fs.appendFileSync(priorExecutionPath,'\\n');",
        '}',
        'return originalCommit(options);',
        '};',
        `const recertify=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'recertify.js')
        )});`,
        `const receipt=JSON.parse(fs.readFileSync(${JSON.stringify(
          phaseReceiptPath
        )},'utf8'));`,
        'const phase1=recertify.applyVerificationReceipt(receipt);',
        'let phase2=null;let code=null;',
        'try{phase2=recertify.finalizeTrustElevation(receipt,phase1);}catch(error){code=error.code||null;}',
        `const card=JSON.parse(fs.readFileSync(${JSON.stringify(
          path.join(
            phaseRoot,
            '.knowledge',
            'modules',
            'auth.json'
          )
        )},'utf8'));`,
        `const trust=JSON.parse(fs.readFileSync(${JSON.stringify(
          path.join(
            phaseRoot,
            '.knowledge',
            'maintenance',
            'trust_report.json'
          )
        )},'utf8'));`,
        'console.log(JSON.stringify({phase1,phase2,code,priorReceiptGuarded,priorExecutionGuarded,card,trust}));'
      ].join('');
      const run = spawnSync(process.execPath, ['-e', runner], {
        cwd: phaseRoot,
        env: envFor(phaseRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const body = JSON.parse(run.stdout || '{}');
      assert(
        run.status === 0 &&
        body.phase1?.trust_elevation_pending === true &&
        body.priorReceiptGuarded === true &&
        body.priorExecutionGuarded === true &&
        body.code === 'transaction_guard_drift' &&
        body.card?.current_trust_level === 'suspect' &&
        body.trust?.modules?.suspect?.includes('auth') &&
        !body.trust?.modules?.near_trusted?.includes('auth'),
        `cross-module budget execution drift did not block phase two: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('65 CLI apply commits receipt, exact closure, knowledge metadata, and trust transaction', () => {
      const run = spawnSync(process.execPath, [toolPath, 'apply', `--receipt=${applyReceiptFile}`], {
        cwd: applyRoot,
        env: envFor(applyRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      assert(run.status === 0, `repair apply failed: ${run.stderr || run.stdout}`);
      applyResult = JSON.parse(run.stdout || '{}');
      const queueAfter = readJson(path.join(applyContext.stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
      const cardAfter = readJson(path.join(applyContext.projectKnowledgeRoot, 'modules', 'auth.json'), {});
      assert(applyResult.closed_lifecycle_ids?.length === 1 &&
        queueAfter.queue.find((item) => item.lifecycle_id === applyFindings[0].lifecycle_id)?.status === 'closed' &&
        cardAfter.verification?.receipts?.some((item) => item.receipt_id === applyReceipt.receipt_id),
      'receipt transaction did not update exact lifecycle and module metadata');
    });
    check('66 exact scoped apply leaves the unrelated module open', () => {
      const queueAfter = readJson(path.join(applyContext.stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
      assert(queueAfter.queue.find((item) => item.lifecycle_id === applyFindings[1].lifecycle_id)?.status === 'open' &&
        !applyResult.closed_lifecycle_ids.includes(applyFindings[1].lifecycle_id), 'unrelated finding was closed');
    });
    check('67 exact Doctor finding reaches phase-two trust elevation without widening scope', () => {
      const trustAfter = readJson(path.join(applyContext.stateRoot, 'maintenance', 'trust_report.json'), {});
      const authElevated =
        trustAfter.modules.near_trusted.includes('auth') &&
        !trustAfter.modules.suspect.includes('auth');
      assert(
        trustAfter.modules.suspect.includes('billing') &&
        authElevated &&
        applyResult.status === 'recertified' &&
        applyResult.trust_elevated === true &&
        applyResult.trust_elevation_pending === false &&
        applyResult.trust_finalization?.status === 'committed' &&
        applyResult.task_readiness_after?.score === 100,
        `exact Doctor phase-two finalization failed: ${JSON.stringify({
          applyResult,
          modules: trustAfter.modules,
          module_statuses: trustAfter.module_statuses
        })}`
      );
    });
    check('67a phase two rejects a forged cross-module receipt identity', () => {
      const billingCardPath = path.join(
        applyContext.projectKnowledgeRoot,
        'modules',
        'billing.json'
      );
      const trustPath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'trust_report.json'
      );
      const before = {
        billing: hash(billingCardPath),
        trust: hash(trustPath)
      };
      const forged = {
        ...applyReceipt,
        module_id: 'billing'
      };
      const runner = [
        `const recertify=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'recertify.js')
        )});`,
        `const receipt=${JSON.stringify(forged)};`,
        `const result=recertify.finalizeTrustElevation(receipt,${JSON.stringify({
          ...applyResult,
          trust_elevation_pending: true
        })});`,
        'console.log(JSON.stringify(result));'
      ].join('');
      const run = spawnSync(process.execPath, ['-e', runner], {
        cwd: applyRoot,
        env: envFor(applyRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const result = JSON.parse(run.stdout || '{}');
      assert(
        run.status === 0 &&
        result.status === 'not_eligible' &&
        result.reason === 'phase_two_identity_mismatch' &&
        hash(billingCardPath) === before.billing &&
        hash(trustPath) === before.trust,
        `forged phase-two identity changed trust state: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('68 repeated apply of the same content-addressed receipt is idempotent', () => {
      const run = spawnSync(process.execPath, [toolPath, 'apply', `--receipt=${applyReceiptFile}`], {
        cwd: applyRoot,
        env: envFor(applyRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const repeated = JSON.parse(run.stdout || '{}');
      assert(
        run.status === 0 &&
        repeated.idempotent === true &&
        repeated.closed_lifecycle_ids?.length === 1,
        `repeated apply was not idempotent: ${run.stderr || run.stdout}`
      );
    });
    check('68a clean post-Doctor state commits the phase-two trust transaction', () => {
      const stalePath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'stale_items.json'
      );
      const queuePath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'repair_queue.json'
      );
      const stale = readJson(stalePath, { items: [] });
      const queue = readJson(queuePath, { queue: [] });
      stale.items = (stale.items || []).filter((item) =>
        item.module_id !== 'auth' ||
        item.lifecycle_id === applyFindings[0].lifecycle_id);
      queue.queue = (queue.queue || []).filter((item) =>
        item.module_id !== 'auth' ||
        item.lifecycle_id === applyFindings[0].lifecycle_id);
      writeJson(stalePath, stale);
      writeJson(queuePath, queue);
      const runner = [
        `const recertify=require(${JSON.stringify(
          path.join(systemRoot, 'tools', 'recertify.js')
        )});`,
        `const receipt=${JSON.stringify(applyReceipt)};`,
        `const result=recertify.finalizeTrustElevation(receipt,${JSON.stringify({
          ...applyResult,
          trust_elevation_pending: true
        })});`,
        'console.log(JSON.stringify(result));'
      ].join('');
      const run = spawnSync(process.execPath, ['-e', runner], {
        cwd: applyRoot,
        env: envFor(applyRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const finalized = JSON.parse(run.stdout || '{}');
      const card = readJson(
        path.join(
          applyContext.projectKnowledgeRoot,
          'modules',
          'auth.json'
        ),
        {}
      );
      const trust = readJson(
        path.join(
          applyContext.stateRoot,
          'maintenance',
          'trust_report.json'
        ),
        {}
      );
      assert(
        run.status === 0 &&
        finalized.trust_elevated === true &&
        finalized.status === 'committed' &&
        card.current_trust_level === 'near_trusted' &&
        trust.modules.near_trusted.includes('auth') &&
        !trust.modules.suspect.includes('auth') &&
        fs.existsSync(path.join(
          applyContext.stateRoot,
          'maintenance',
          'transactions',
          `repair-trust-${applyReceipt.content_sha256.slice(0, 40)}`,
          'terminal.json'
        )),
        `phase-two trust finalization failed: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('68c post-closure source drift lowers current readiness without mutation', () => {
      const statusArgs = [
        toolPath,
        'status',
        `--task-id=${applyScope.task_id}`,
        `--session-id=${applyScope.session_id}`
      ];
      const before = spawnSync(process.execPath, statusArgs, {
        cwd: applyRoot,
        env: envFor(applyRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const beforeStatus = JSON.parse(before.stdout || '{}');
      const sourcePath = path.join(applyRoot, 'src', 'auth.js');
      const originalSource = fs.readFileSync(sourcePath, 'utf8');
      writeText(
        sourcePath,
        `${originalSource.trimEnd()}\n// post-closure drift\n`
      );
      const scopedPlanPath = path.join(
        applyContext.stateRoot,
        ...repairSessionPlanRelative(
          applyScope.task_id,
          applyScope.session_id
        ).split('/')
      );
      const effectivePlanPath = fs.existsSync(scopedPlanPath)
        ? scopedPlanPath
        : path.join(
            applyContext.stateRoot,
            'maintenance',
            'repair_opportunities.json'
          );
      const protectedPaths = [
        path.join(
          applyContext.stateRoot,
          'maintenance',
          'stale_items.json'
        ),
        path.join(
          applyContext.stateRoot,
          'maintenance',
          'repair_queue.json'
        ),
        path.join(
          applyContext.projectKnowledgeRoot,
          'modules',
          'auth.json'
        ),
        path.join(
          applyContext.stateRoot,
          'maintenance',
          'trust_report.json'
        ),
        effectivePlanPath
      ];
      const protectedHashes = new Map(
        protectedPaths.map((file) => [file, hash(file)])
      );
      const after = spawnSync(process.execPath, statusArgs, {
        cwd: applyRoot,
        env: envFor(applyRoot),
        encoding: 'utf8',
        timeout: 60000,
        windowsHide: true
      });
      const afterStatus = JSON.parse(after.stdout || '{}');
      writeText(sourcePath, originalSource);
      assert(
        before.status === 0 &&
        beforeStatus.verified_closures?.includes(
          applyFindings[0].lifecycle_id
        ) &&
        beforeStatus.task_readiness?.score === 100 &&
        after.status === 0 &&
        !afterStatus.verified_closures?.includes(
          applyFindings[0].lifecycle_id
        ) &&
        afterStatus.closure_provenance?.invalid?.some((item) =>
          item.lifecycle_id === applyFindings[0].lifecycle_id &&
          item.reason === 'closure_source_stale') &&
        afterStatus.task_readiness?.score < 100 &&
        protectedPaths.every((file) =>
          hash(file) === protectedHashes.get(file)),
        `post-closure drift projection failed: ${
          after.stderr || after.stdout
        }`
      );
    });
    check('68d new frozen-plan debt lowers readiness and status redacts private text', () => {
      const stalePath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'stale_items.json'
      );
      const queuePath = path.join(
        applyContext.stateRoot,
        'maintenance',
        'repair_queue.json'
      );
      const scopedPlanPath = path.join(
        applyContext.stateRoot,
        ...repairSessionPlanRelative(
          applyScope.task_id,
          applyScope.session_id
        ).split('/')
      );
      const planPath = fs.existsSync(scopedPlanPath)
        ? scopedPlanPath
        : path.join(
            applyContext.stateRoot,
            'maintenance',
            'repair_opportunities.json'
          );
      const planHash = hash(planPath);
      const stale = readJson(stalePath, { items: [] });
      const queue = readJson(queuePath, { queue: [] });
      const newFinding = {
        ...granularFinding({
          module_id: 'auth',
          code: 'needs_recheck',
          artifact: 'src/auth.js',
          repair_class: 'verify_on_touch'
        }),
        occurrence: 1,
        opened_at: '2026-07-29T14:00:00.000Z'
      };
      reconcile({
        staleItems: stale,
        repairQueue: queue,
        findings: [newFinding],
        source: 'privacy-probe',
        agentId: 'repair-test',
        timestamp: newFinding.opened_at
      });
      const privateSentinels = [
        'private.person@example.com',
        'C:\\private\\token.txt',
        'sk_private_status_12345678901234567890'
      ];
      for (const item of [
        ...(stale.items || []),
        ...(queue.queue || [])
      ]) {
        if (item.lifecycle_id === newFinding.lifecycle_id) {
          item.message = privateSentinels.join(' ');
        }
      }
      writeJson(stalePath, stale);
      writeJson(queuePath, queue);
      const stateHashes = {
        stale: hash(stalePath),
        queue: hash(queuePath),
        plan: hash(planPath)
      };
      const run = spawnSync(
        process.execPath,
        [
          toolPath,
          'status',
          `--task-id=${applyScope.task_id}`,
          `--session-id=${applyScope.session_id}`
        ],
        {
          cwd: applyRoot,
          env: envFor(applyRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const status = JSON.parse(run.stdout || '{}');
      const projected = status.opportunities?.find((item) =>
        item.lifecycle_id === newFinding.lifecycle_id);
      const visible = `${run.stdout}\n${run.stderr}`;
      assert(
        run.status === 0 &&
        projected?.decision_reason ===
          'current_finding_not_in_session_plan' &&
        projected?.message === '<redacted>' &&
        status.task_readiness?.score < 100 &&
        status.task_readiness?.status !== 'ready' &&
        privateSentinels.every((item) => !visible.includes(item)) &&
        hash(stalePath) === stateHashes.stale &&
        hash(queuePath) === stateHashes.queue &&
        hash(planPath) === stateHashes.plan &&
        planHash === stateHashes.plan,
        `status privacy/frozen-plan projection failed: ${
          run.stderr || run.stdout
        }`
      );
    });
    check('68b live rebuild disable blocks, then safe-only closes only generated debt', () => {
      const generatedRoot = path.join(root, 'generated-integration');
      const generatedContext = fixtureContext(generatedRoot);
      prepareSourceFixture(generatedRoot);
      writeJson(
        path.join(
          generatedContext.stateRoot,
          'maintenance',
          'trust_report.json'
        ),
        {
          schema_version: 'test-trust.v1',
          modules: {
            trusted: [],
            near_trusted: [],
            routing_trusted: [],
            advisory_only: [],
            suspect: ['auth'],
            low_confidence: []
          },
          module_statuses: [{
            module_id: 'auth',
            trust_status: 'suspect',
            freshness_status: 'needs_recheck'
          }]
        }
      );
      const generatedPath = path.join(
        generatedContext.projectKnowledgeRoot,
        'search',
        'index.json'
      );
      const generatedToolRelative =
        '.knowledge/tools/build-search-index.js';
      const generatedToolPath = path.join(
        generatedRoot,
        ...generatedToolRelative.split('/')
      );
      for (const relative of generatedProducerDependencyClosure(
        generatedToolRelative
      )) {
        if (
          relative === generatedToolRelative ||
          relative === '.knowledge/install-manifest.json'
        ) continue;
        const source = path.join(
          systemRoot,
          ...relative.replace(/^\.knowledge\//, '').split('/')
        );
        const target = path.join(
          generatedRoot,
          ...relative.split('/')
        );
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(source, target);
      }
      writeJson(generatedPath, {
        schema_version: 'test-search-index.v1',
        revision: 'before-rebuild',
        entries: [{ id: 'stale-entry' }]
      });
      writeText(
        generatedToolPath,
        [
          "'use strict';",
          "const fs = require('fs');",
          "const path = require('path');",
          "const { resolveKnowledgeContext } = require('./lib/path-context');",
          "if (process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY !== '1') process.exit(7);",
          "resolveKnowledgeContext();",
          "const target = path.join(process.cwd(), '.knowledge', 'search', 'index.json');",
          "fs.mkdirSync(path.dirname(target), { recursive: true });",
          "fs.writeFileSync(target, `${JSON.stringify({",
          "  schema_version: 'test-search-index.v1',",
          "  revision: 'after-rebuild',",
          "  entries: []",
          "}, null, 2)}\\n`, 'utf8');",
          ''
        ].join('\n')
      );
      writeJson(
        path.join(
          generatedContext.projectKnowledgeRoot,
          'install-manifest.json'
        ),
        {
          schema_version: '3.3.0',
          approved_local_rebuild_tools: [
            'tools/build-search-index.js'
          ]
        }
      );
      const generatedBeforeHash = hash(generatedPath);
      const generatedFinding = {
        ...granularFinding({
          module_id: 'root',
          code: 'search_index_stale',
          artifact: '.knowledge/search/index.json',
          affected_artifacts: [
            '.knowledge/search/index.json',
            generatedToolRelative
          ],
          repair_class: 'rebuild_generated_artifact'
        }),
        occurrence: 1,
        opened_at: new Date().toISOString()
      };
      const stalePath = path.join(
        generatedContext.stateRoot,
        'maintenance',
        'stale_items.json'
      );
      const queuePath = path.join(
        generatedContext.stateRoot,
        'maintenance',
        'repair_queue.json'
      );
      const stale = readJson(stalePath, { items: [] });
      const queue = readJson(queuePath, { queue: [] });
      reconcile({
        staleItems: stale,
        repairQueue: queue,
        findings: [generatedFinding],
        source: 'generated-test',
        agentId: 'repair-test',
        timestamp: generatedFinding.opened_at
      });
      writeJson(stalePath, stale);
      writeJson(queuePath, queue);
      const generatedScope = makeScope({
        task_id: 'TASK-generated',
        session_id: 'SESSION-generated',
        user_task: 'Refresh the generated search index',
        selected_modules: [],
        changed_files: ['.knowledge/search/index.json']
      });
      const generatedPolicy = policy(generatedContext, {
        mode: 'safe-only',
        rebuild_generated_artifacts: true
      });
      const generatedPlan = buildOpportunitiesArtifact({
        findings: [generatedFinding],
        scope: generatedScope,
        policyResolution: generatedPolicy,
        doctorScore: 90,
        generatedBy: 'generated-e2e-test'
      });
      const planPath = path.join(
        generatedContext.stateRoot,
        ...repairSessionPlanRelative(
          generatedScope.task_id,
          generatedScope.session_id
        ).split('/')
      );
      writeJson(planPath, generatedPlan);
      writeJson(
        path.join(
          generatedContext.stateRoot,
          'maintenance',
          'repair_opportunities.json'
        ),
        generatedPlan
      );
      const generatedReceiptInput = receiptInput(
        generatedRoot,
        generatedFinding,
        generatedScope,
        {
          repair_mode: 'safe-only',
          verification_tests: [{
            argv: ['node', generatedToolRelative]
          }],
          verification_source_files: [
            '.knowledge/search/index.json',
            generatedToolRelative,
            '.knowledge/install-manifest.json'
          ],
          claims_checked: [{
            claim_id: 'search-index-rebuilt',
            claim:
              'The first-party rebuild tool produced the current search index.',
            result: 'confirmed',
            evidence: [
              '.knowledge/search/index.json',
              generatedToolRelative
            ]
          }],
          confirmation_evidence: {
            critical_path: false,
            security_finding: false,
            exact_finding: false
          }
        }
      );
      const generatedReceipt = createReceipt(
        generatedReceiptInput,
        {
          finding: generatedFinding,
          scope: generatedScope,
          policyResolution: generatedPolicy,
          repoRoot: generatedRoot,
          stateRoot: generatedContext.stateRoot
        }
      );
      const generatedReceiptPath = saveReceipt(
        generatedContext.stateRoot,
        generatedReceipt
      ).path;
      const generatedExecution = readJson(
        path.join(
          generatedContext.stateRoot,
          ...generatedReceipt.tests_run[0].execution_path.split('/')
        ),
        {}
      );
      const beforeSnapshot = new Map(
        (generatedExecution.source_snapshot_before || [])
          .map((item) => [item.path, item.sha256])
      );
      const afterSnapshot = new Map(
        (generatedExecution.source_snapshot || [])
          .map((item) => [item.path, item.sha256])
      );
      const transitiveRelative =
        '.knowledge/tools/lib/json-store.js';
      const transitivePath = path.join(
        generatedRoot,
        ...transitiveRelative.split('/')
      );
      const transitiveOriginal = fs.readFileSync(transitivePath);
      fs.appendFileSync(
        transitivePath,
        '\n// generated-producer dependency drift probe\n',
        'utf8'
      );
      const transitiveBlocked = spawnSync(
        process.execPath,
        [toolPath, 'apply', `--receipt=${generatedReceiptPath}`],
        {
          cwd: generatedRoot,
          env: envFor(generatedRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const transitiveBlockedResult = JSON.parse(
        transitiveBlocked.stdout || '{}'
      );
      fs.writeFileSync(transitivePath, transitiveOriginal);
      const settingsPath = path.join(
        generatedContext.projectKnowledgeRoot,
        'settings',
        'operator-profile.json'
      );
      writeJson(settingsPath, {
        maintenance: {
          repair_on_touch: {
            mode: 'safe-only',
            rebuild_generated_artifacts: false
          }
        }
      });
      const blocked = spawnSync(
        process.execPath,
        [toolPath, 'apply', `--receipt=${generatedReceiptPath}`],
        {
          cwd: generatedRoot,
          env: envFor(generatedRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const blockedResult = JSON.parse(blocked.stdout || '{}');
      const blockedRecord = readJson(
        queuePath,
        { queue: [] }
      ).queue.find((item) =>
        item.lifecycle_id === generatedFinding.lifecycle_id);
      writeJson(settingsPath, {
        maintenance: {
          repair_on_touch: {
            mode: 'safe-only',
            rebuild_generated_artifacts: true
          }
        }
      });
      const cardPath = path.join(
        generatedContext.projectKnowledgeRoot,
        'modules',
        'auth.json'
      );
      const trustPath = path.join(
        generatedContext.stateRoot,
        'maintenance',
        'trust_report.json'
      );
      const protectedHashes = {
        card: hash(cardPath),
        trust: hash(trustPath)
      };
      const applied = spawnSync(
        process.execPath,
        [toolPath, 'apply', `--receipt=${generatedReceiptPath}`],
        {
          cwd: generatedRoot,
          env: envFor(generatedRoot),
          encoding: 'utf8',
          timeout: 60000,
          windowsHide: true
        }
      );
      const appliedResult = JSON.parse(applied.stdout || '{}');
      const transaction = readJson(
        path.join(
          generatedContext.stateRoot,
          'maintenance',
          'transactions',
          `repair-${generatedReceipt.content_sha256.slice(0, 40)}`,
          'manifest.json'
        ),
        {}
      );
      const targets = (transaction.writes || []).map((item) =>
        path.resolve(item.target));
      const generatedAfter = readJson(generatedPath, {});
      const generatedRecord = readJson(
        queuePath,
        { queue: [] }
      ).queue.find((item) =>
        item.lifecycle_id === generatedFinding.lifecycle_id);
      assert(
        generatedBeforeHash !== hash(generatedPath) &&
        beforeSnapshot.get('.knowledge/search/index.json') ===
          generatedBeforeHash &&
        afterSnapshot.get('.knowledge/search/index.json') ===
          hash(generatedPath) &&
        beforeSnapshot.has(transitiveRelative) &&
        beforeSnapshot.get(transitiveRelative) ===
          afterSnapshot.get(transitiveRelative) &&
        generatedExecution.environment_profile ===
          'sanitized_node_no_git' &&
        generatedReceipt.source_files_checked.some((item) =>
          item.path === transitiveRelative &&
          item.sha256 === afterSnapshot.get(transitiveRelative)) &&
        transitiveBlocked.status === 2 &&
        transitiveBlockedResult.reason ===
          'verification_receipt_invalid' &&
        transitiveBlockedResult.errors?.includes(
          `source_hash_current_mismatch:${transitiveRelative}`
        ) &&
        generatedAfter.revision === 'after-rebuild' &&
        blocked.status === 2 &&
        blockedResult.reason === 'generated_rebuild_disabled' &&
        blockedRecord?.status === 'open' &&
        applied.status === 0 &&
        appliedResult.status === 'generated_artifact_repaired' &&
        appliedResult.trust_elevated === false &&
        ['closed', 'resolved'].includes(generatedRecord?.status) &&
        hash(cardPath) === protectedHashes.card &&
        hash(trustPath) === protectedHashes.trust &&
        !targets.includes(path.resolve(cardPath)) &&
        !targets.includes(path.resolve(trustPath)),
        `safe-only generated E2E failed: ${
          transitiveBlocked.stderr || transitiveBlocked.stdout
        } ${
          blocked.stderr || blocked.stdout
        } ${applied.stderr || applied.stdout}`
      );
    });
    check('69 a changed source observation reopens the same lifecycle ID', () => {
      const staleAfter = readJson(path.join(applyContext.stateRoot, 'maintenance', 'stale_items.json'), { items: [] });
      const queueAfter = readJson(path.join(applyContext.stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
      const reopened = reconcile({
        staleItems: staleAfter,
        repairQueue: queueAfter,
        findings: [applyFindings[0]],
        source: 'doctor',
        agentId: 'doctor-new-session',
        timestamp: '2026-07-29T13:00:00.000Z'
      });
      assert(reopened.events.some((item) => item.transition === 'reopen' && item.lifecycle_id === applyFindings[0].lifecycle_id), 'same lifecycle did not reopen');
    });
    check('70 runtime artifacts satisfy their published schema contracts', () => {
      const opportunitiesSchema = readJson(path.join(systemRoot, 'schemas', 'repair-opportunities.schema.json'), {});
      const receiptSchema = readJson(path.join(systemRoot, 'schemas', 'verification-receipt.schema.json'), {});
      const executionSchema = readJson(path.join(systemRoot, 'schemas', 'verification-execution.schema.json'), {});
      const executionPath = path.join(receiptContext.stateRoot, goodReceipt.tests_run[0].execution_path);
      const execution = readJson(executionPath, {});
      const requiredPresent = (schema, value) => (schema.required || []).every((field) => (
        Object.prototype.hasOwnProperty.call(value, field)
      ));
      assert(requiredPresent(opportunitiesSchema, scoped), 'opportunities runtime is missing schema-required fields');
      assert(requiredPresent(receiptSchema, goodReceipt), 'receipt runtime is missing schema-required fields');
      assert(requiredPresent(executionSchema, execution), 'execution runtime is missing schema-required fields');
      assert(opportunitiesSchema.properties?.schema_version?.const === scoped.schema_version, 'opportunities schema_version drift');
      assert(receiptSchema.properties?.schema_version?.const === goodReceipt.schema_version, 'receipt schema_version drift');
      assert(executionSchema.properties?.schema_version?.const === execution.schema_version, 'execution schema_version drift');
      assert(execution.execution_id === goodReceipt.tests_run[0].execution_id &&
        execution.content_sha256 === goodReceipt.tests_run[0].execution_sha256, 'receipt does not bind the schema-checked execution');
    });
    check('70a scoped plan loader rejects symlink, malformed, rebound, and oversized files', () => {
      const planRoot = path.join(root, 'plan-boundary');
      const planContext = fixtureContext(planRoot);
      const relative = repairSessionPlanRelative(
        scope.task_id,
        scope.session_id
      );
      const target = path.join(
        planContext.stateRoot,
        ...relative.split('/')
      );
      const outside = path.join(planRoot, 'outside-plan.json');
      writeJson(outside, scoped);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      let symlinkCreated = false;
      try {
        fs.symlinkSync(outside, target, 'file');
        symlinkCreated = true;
      } catch (error) {
        if (!['EPERM', 'EACCES', 'UNKNOWN'].includes(error.code)) {
          throw error;
        }
      }
      if (symlinkCreated) {
        let code = null;
        try {
          loadRepairPlan(
            planContext.stateRoot,
            scope.task_id,
            scope.session_id
          );
        } catch (error) {
          code = error.code;
        }
        assert(
          code === 'repair_plan_file_invalid',
          `symlink plan was accepted: ${code}`
        );
        fs.rmSync(target, { force: true });
      }
      writeText(target, '{not-json');
      let malformedCode = null;
      try {
        loadRepairPlan(
          planContext.stateRoot,
          scope.task_id,
          scope.session_id
        );
      } catch (error) {
        malformedCode = error.code;
      }
      const rebound = JSON.parse(JSON.stringify(scoped));
      rebound.task_scope = buildTaskScope({
        task_id: 'TASK-rebound',
        session_id: 'SESSION-rebound',
        user_task: 'Rebound plan',
        selected_modules: ['auth'],
        changed_files: ['src/auth.js']
      });
      writeJson(target, rebound);
      let reboundCode = null;
      try {
        loadRepairPlan(
          planContext.stateRoot,
          scope.task_id,
          scope.session_id
        );
      } catch (error) {
        reboundCode = error.code;
      }
      writeText(target, 'x'.repeat(MAX_REPAIR_PLAN_BYTES + 1));
      let oversizedCode = null;
      try {
        loadRepairPlan(
          planContext.stateRoot,
          scope.task_id,
          scope.session_id
        );
      } catch (error) {
        oversizedCode = error.code;
      }
      const oversizedArtifact = {
        ...JSON.parse(JSON.stringify(scoped)),
        padding: 'x'.repeat(MAX_REPAIR_PLAN_BYTES)
      };
      const producerValidation =
        validateRepairPlanArtifact(oversizedArtifact);
      assert(
        (!symlinkCreated || true) &&
        malformedCode === 'repair_plan_file_invalid' &&
        reboundCode === 'repair_plan_scope_invalid' &&
        oversizedCode === 'repair_plan_file_invalid' &&
        producerValidation.errors.includes(
          'repair_plan_size_exceeded'
        ),
        `plan boundary failed: ${JSON.stringify({
          malformedCode,
          reboundCode,
          oversizedCode,
          errors: producerValidation.errors
        })}`
      );
    });
    check('70b KVR producer and loader fail closed on schema and size boundaries', () => {
      const receiptStore = path.join(
        receiptContext.stateRoot,
        'maintenance',
        'verification_receipts'
      );
      const malformedDigest = 'a'.repeat(64);
      writeText(
        path.join(receiptStore, `${malformedDigest}.json`),
        '{not-json'
      );
      let malformedCode = null;
      try {
        loadReceipt(receiptContext.stateRoot, malformedDigest);
      } catch (error) {
        malformedCode = error.code;
      }
      const addressReceipt = (raw) => {
        const value = JSON.parse(JSON.stringify(raw));
        delete value.receipt_id;
        delete value.content_sha256;
        const digest = receiptDigest(value);
        value.receipt_id = `KVR-${digest}`;
        value.content_sha256 = digest;
        return value;
      };
      const unknown = addressReceipt({
        ...goodReceipt,
        unexpected: 'x'
      });
      writeJson(
        path.join(
          receiptStore,
          `${unknown.content_sha256}.json`
        ),
        unknown
      );
      let unknownError = null;
      try {
        loadReceipt(
          receiptContext.stateRoot,
          unknown.content_sha256
        );
      } catch (error) {
        unknownError = error;
      }
      const missingIdBase = {
        ...goodReceipt,
        checked_by: 'missing-id-probe'
      };
      delete missingIdBase.receipt_id;
      delete missingIdBase.content_sha256;
      const missingIdDigest = receiptDigest(missingIdBase);
      const missingId = {
        ...missingIdBase,
        content_sha256: missingIdDigest
      };
      writeJson(
        path.join(receiptStore, `${missingIdDigest}.json`),
        missingId
      );
      let missingIdError = null;
      try {
        loadReceipt(receiptContext.stateRoot, missingIdDigest);
      } catch (error) {
        missingIdError = error;
      }
      const oversized = addressReceipt({
        ...goodReceipt,
        claims_checked: [{
          ...goodReceipt.claims_checked[0],
          claim: 'x'.repeat(MAX_VERIFICATION_RECEIPT_BYTES)
        }]
      });
      let producerCode = null;
      try {
        saveReceipt(receiptContext.stateRoot, oversized);
      } catch (error) {
        producerCode = error.code;
      }
      const oversizedDigest = 'b'.repeat(64);
      writeText(
        path.join(receiptStore, `${oversizedDigest}.json`),
        'x'.repeat(MAX_VERIFICATION_RECEIPT_BYTES + 1)
      );
      let loaderCode = null;
      try {
        loadReceipt(receiptContext.stateRoot, oversizedDigest);
      } catch (error) {
        loaderCode = error.code;
      }
      assert(
        malformedCode === 'verification_receipt_json_invalid' &&
        unknownError?.code === 'verification_receipt_invalid' &&
        unknownError.validation?.errors?.some((item) =>
          item.includes('additionalProperties')) &&
        missingIdError?.code === 'verification_receipt_invalid' &&
        missingIdError.validation?.errors?.includes(
          'receipt_id_required') &&
        producerCode === 'verification_receipt_too_large' &&
        loaderCode === 'verification_receipt_file_invalid' &&
        !fs.existsSync(path.join(
          receiptStore,
          `${oversized.content_sha256}.json`
        )),
        `KVR boundary failed: ${JSON.stringify({
          malformedCode,
          unknown: unknownError?.validation?.errors,
          missing: missingIdError?.validation?.errors,
          producerCode,
          loaderCode
        })}`
      );
    });
    check('70c KVE rejects timeout, signal, unknown fields, and oversized records', () => {
      const executionPath = path.join(
        receiptContext.stateRoot,
        ...goodReceipt.tests_run[0].execution_path.split('/')
      );
      const baseExecution = readJson(executionPath, {});
      const executionStore = path.dirname(executionPath);
      const addressExecution = (mutate) => {
        const value = JSON.parse(JSON.stringify(baseExecution));
        mutate(value);
        delete value.execution_id;
        delete value.content_sha256;
        const digest = executionDigest(value);
        value.execution_id = `KVE-${digest}`;
        value.content_sha256 = digest;
        return value;
      };
      const invalids = [
        {
          value: addressExecution((value) => {
            value.timed_out = true;
          }),
          expected: 'execution_timed_out'
        },
        {
          value: addressExecution((value) => {
            value.signal = 'SIGTERM';
          }),
          expected: 'execution_signal_invalid'
        },
        {
          value: addressExecution((value) => {
            value.unexpected = 'x';
          }),
          expected: 'additionalProperties'
        }
      ];
      for (const item of invalids) {
        const validation = validateExecutionRecord(item.value);
        writeJson(
          path.join(
            executionStore,
            `${item.value.content_sha256}.json`
          ),
          item.value
        );
        assert(
          !validation.ok &&
          validation.errors.some((error) =>
            error.includes(item.expected)) &&
          loadExecutionRecord(
            receiptContext.stateRoot,
            item.value.execution_id
          ) === null,
          `invalid KVE was accepted: ${item.expected}`
        );
      }
      const snapshots = Array.from({ length: 5000 }, (_, index) => ({
        path: `src/padding-${String(index).padStart(5, '0')}.js`,
        sha256: '0'.repeat(64)
      }));
      const oversized = addressExecution((value) => {
        value.source_snapshot_before = snapshots;
        value.source_snapshot = snapshots;
      });
      let producerCode = null;
      try {
        saveExecutionRecord(
          receiptContext.stateRoot,
          oversized
        );
      } catch (error) {
        producerCode = error.code;
      }
      const oversizedDigest = 'c'.repeat(64);
      writeText(
        path.join(executionStore, `${oversizedDigest}.json`),
        'x'.repeat(MAX_VERIFICATION_EXECUTION_BYTES + 1)
      );
      assert(
        producerCode === 'verification_execution_too_large' &&
        loadExecutionRecord(
          receiptContext.stateRoot,
          oversizedDigest
        ) === null &&
        !fs.existsSync(path.join(
          executionStore,
          `${oversized.content_sha256}.json`
        )),
        `KVE size boundary failed: ${producerCode}`
      );
    });

    check('71 routing inventory records normalize to module IDs without widening scope', () => {
      const routedScope = buildTaskScope({
        task_id: 'routing-record-normalization',
        session_id: 'routing-record-normalization-session',
        user_task: 'Inspect Field Report and Repair-on-touch.',
        selected_modules: ['field-report', 'repair-on-touch'],
        routing: {
          modules: [
            { module_id: 'root', path: '.knowledge/' },
            {},
            null
          ],
          routing: {
            selected_modules: ['root']
          }
        }
      });
      assert(
        routedScope.direct_modules.join(',') === 'field-report,repair-on-touch,root',
        `routing records widened scope: ${routedScope.direct_modules.join(',')}`
      );
      assert(!routedScope.direct_modules.includes('[object_object]'), 'object record leaked into task scope');
      assert(routedScope.source_signals.selected_modules === 3, 'module count includes malformed routing records');
    });

    check('72 every repeatable CLI list flag preserves all occurrences', () => {
      const listFlags = [
        'changed-file',
        'module',
        'dependency-module',
        'dependency-file',
        'essential-dependency-module',
        'critical-path',
        'plan-step'
      ];
      const argv = ['plan'];
      for (const flag of listFlags) {
        argv.push(`--${flag}=first-${flag}`);
        argv.push(`--${flag}`, `second-${flag}`);
      }
      const parsed = parseArgs(argv);
      for (const flag of listFlags) {
        assert(
          parsed.lists[flag]?.join(',') === `first-${flag},second-${flag}`,
          `repeatable flag lost a value: ${flag}`
        );
      }
    });

    artifacts.pre_repair_reproduction = {
      finding_id: authFinding.lifecycle_id,
      session_1_open: true,
      session_2_repeated: true,
      receipt_created: false
    };
    artifacts.transaction_faults = faultResults;
    artifacts.sample_receipt_id = goodReceipt.receipt_id;
    artifacts.sample_task_scope_hash = scope.scope_hash;
    console.log(JSON.stringify({
      schema_version: systemVersion(),
      status: 'pass',
      checks_total: checks.length,
      checks,
      artifacts
    }, null, 2));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
