#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const {
  readJson,
  writeJsonAtomic,
  getAgentId
} = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const {
  commitJsonTransaction,
  recoverTransactions
} = require('./lib/json-transaction');
const { resolveKnowledgeContext } = require('./lib/path-context');
const {
  DEFAULT_REPAIR_POLICY,
  resolvePolicy,
  saveOperatorRepairSettings,
  buildTaskScope,
  buildOpportunitiesArtifact,
  granularFinding,
  relationToTask,
  taskReadiness,
  repairSessionKey,
  repairSessionPlanRelative,
  loadRepairPlan: loadRepairPlanFromStore,
  validateRepairPlanArtifact,
  createReceipt,
  saveReceipt,
  loadReceipt,
  validateReceipt,
  loadExecutionRecord,
  runVerificationTests,
  safeRelativeFile,
  sha256,
  maintenanceTelemetry,
  humanMaintenanceSummary,
  canonicalMode,
  policyAllowsReceiptMode,
  restrictPolicyBudgets,
  secureStateStore
} = require('./lib/repair-on-touch');
const {
  dedicatedRequirementFor,
  lifecycleById,
  reconcile
} = require('./lib/queue-lifecycle');
const {
  createDedicatedReceipt,
  saveDedicatedReceipt,
  loadDedicatedReceipt,
  verifyDedicatedEvidence
} = require('./lib/dedicated-verification');
const recertify = require('./recertify');
const doctor = require('./doctor');

const context = resolveKnowledgeContext();
const stateRoot = context.stateRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const REPAIR_LOCK = Object.freeze({
  context,
  rootKind: 'state',
  rootPath: stateRoot,
  lockName: 'repair-on-touch',
  purpose: LOCKS['repair-on-touch'].purpose
});

function parseArgs(argv) {
  const parsed = { command: null, positionals: [], flags: {}, lists: {} };
  const listNames = new Set([
    'changed-file',
    'module',
    'dependency-module',
    'dependency-file',
    'essential-dependency-module',
    'critical-path',
    'plan-step',
    'confirm-finding'
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      if (!parsed.command) parsed.command = arg;
      else parsed.positionals.push(arg);
      continue;
    }
    const equal = arg.indexOf('=');
    const name = arg.slice(2, equal === -1 ? undefined : equal);
    let value = equal === -1 ? true : arg.slice(equal + 1);
    if (equal === -1 && argv[index + 1] && !argv[index + 1].startsWith('--')) value = argv[++index];
    if (listNames.has(name)) {
      parsed.lists[name] = parsed.lists[name] || [];
      parsed.lists[name].push(value);
    } else {
      parsed.flags[name] = value;
    }
  }
  parsed.command = parsed.command || 'status';
  return parsed;
}

function boolFlag(value, fallback = false) {
  if (value === undefined) return fallback;
  if (typeof value === 'boolean') return value;
  return String(value).toLowerCase() === 'true' || value === '1';
}

function numberFlag(value) {
  if (value === undefined || value === null || value === '') return undefined;
  return Number(value);
}

function readRequest(file) {
  if (!file) return {};
  const absolute = path.resolve(String(file));
  const value = readJson(absolute, null);
  if (!value || typeof value !== 'object') throw new Error(`Unable to read request JSON: ${absolute}`);
  return value;
}

function perRunPolicy(flags) {
  const raw = {};
  if (flags.mode !== undefined) raw.mode = canonicalMode(flags.mode);
  if (flags.enabled !== undefined) raw.enabled = boolFlag(flags.enabled);
  if (flags['max-findings'] !== undefined) raw.max_findings_per_task = numberFlag(flags['max-findings']);
  if (flags['max-extra-minutes'] !== undefined) raw.max_extra_minutes = numberFlag(flags['max-extra-minutes']);
  if (flags['max-extra-context-percent'] !== undefined) raw.max_extra_context_percent = numberFlag(flags['max-extra-context-percent']);
  if (flags['rebuild-generated-artifacts'] !== undefined) raw.rebuild_generated_artifacts = boolFlag(flags['rebuild-generated-artifacts']);
  if (flags['confirm-critical'] !== undefined) raw.require_confirmation_for_critical_paths = true;
  if (Object.prototype.hasOwnProperty.call(flags, 'edit-source-for-health')) {
    const error = new Error('edit_source_for_health cannot be set through CLI');
    error.code = 'repair_source_health_override_forbidden';
    throw error;
  }
  return raw;
}

function settingsInput(flags, body = {}) {
  const nested = body.maintenance?.repair_on_touch || body.repair_on_touch || body;
  return {
    ...nested,
    ...(flags.mode !== undefined ? { mode: canonicalMode(flags.mode) } : {}),
    ...(flags.enabled !== undefined ? { enabled: boolFlag(flags.enabled) } : {}),
    ...(flags['max-findings'] !== undefined ? { max_findings_per_task: numberFlag(flags['max-findings']) } : {}),
    ...(flags['max-extra-minutes'] !== undefined ? { max_extra_minutes: numberFlag(flags['max-extra-minutes']) } : {}),
    ...(flags['max-extra-context-percent'] !== undefined ? { max_extra_context_percent: numberFlag(flags['max-extra-context-percent']) } : {}),
    ...(flags['rebuild-generated-artifacts'] !== undefined
      ? { rebuild_generated_artifacts: boolFlag(flags['rebuild-generated-artifacts']) }
      : {})
  };
}

function taskInput(parsed, body = {}) {
  const routing = readJson(path.join(stateRoot, 'maintenance', 'routing_bundle.json'), {});
  const prImpact = readJson(path.join(stateRoot, 'maintenance', 'pr_impact.json'), {});
  const criticality = readJson(path.join(stateRoot, 'maps', 'file_criticality.json'), {});
  return {
    ...body,
    task_id: parsed.flags['task-id'] || body.task_id,
    session_id: parsed.flags['session-id'] || body.session_id || process.env.KNOWLEDGE_SESSION_ID,
    user_task: parsed.flags.task || body.user_task || body.task,
    changed_files: [...(body.changed_files || []), ...(parsed.lists['changed-file'] || [])],
    selected_modules: [...(body.selected_modules || []), ...(parsed.lists.module || [])],
    dependency_modules: [...(body.dependency_modules || []), ...(parsed.lists['dependency-module'] || [])],
    dependency_files: [...(body.dependency_files || []), ...(parsed.lists['dependency-file'] || [])],
    essential_dependency_modules: [
      ...(body.essential_dependency_modules || []),
      ...(parsed.lists['essential-dependency-module'] || [])
    ],
    essential_dependency_reason: parsed.flags['essential-dependency-reason'] || body.essential_dependency_reason,
    critical_paths: [...(body.critical_paths || []), ...(parsed.lists['critical-path'] || [])],
    agent_plan: [...(body.agent_plan || []), ...(parsed.lists['plan-step'] || [])],
    routing: body.routing || routing,
    pr_impact: body.pr_impact || prImpact,
    critical_path_map: body.critical_path_map || criticality,
    diff: body.diff || ''
  };
}

function findReceipt(raw) {
  if (!raw) throw new Error('--receipt=<path-or-id> is required');
  const reference = String(raw);
  const looksLikePath =
    path.isAbsolute(reference) ||
    reference.includes('/') ||
    reference.includes('\\') ||
    reference.toLowerCase().endsWith('.json');
  if (!looksLikePath) return loadReceipt(stateRoot, reference).receipt;
  const directory = secureStateStore(
    stateRoot,
    'maintenance/verification_receipts'
  );
  const absolute = path.resolve(reference);
  const filename = path.basename(absolute);
  const match = filename.match(/^([a-f0-9]{64})\.json$/i);
  const parentIdentity = process.platform === 'win32'
    ? path.dirname(absolute).toLowerCase()
    : path.dirname(absolute);
  const directoryIdentity = process.platform === 'win32'
    ? directory.toLowerCase()
    : directory;
  if (!match || parentIdentity !== directoryIdentity) {
    const error = new Error(
      'Receipt path must be the exact content-addressed file in maintenance/verification_receipts'
    );
    error.code = 'verification_receipt_path_invalid';
    throw error;
  }
  return loadReceipt(stateRoot, match[1]).receipt;
}

function output(value, options = {}) {
  if (options.human) console.log(String(value));
  else console.log(JSON.stringify(value, null, 2));
  return value;
}

function receiptMatchesScope(entry, taskScope = {}) {
  const taskId = taskScope.task_id || null;
  const sessionId = taskScope.session_id || null;
  return Boolean(taskId && sessionId) &&
    entry.task_id === taskId &&
    entry.session_id === sessionId;
}

function repairPlanLocation(taskId, sessionId, { create = false } = {}) {
  const relative_path = repairSessionPlanRelative(taskId, sessionId);
  const directory = secureStateStore(
    stateRoot,
    'maintenance/repair_sessions',
    { create }
  );
  return {
    plan_id: `KRPS-${repairSessionKey(taskId, sessionId)}`,
    relative_path,
    path: path.join(directory, path.basename(relative_path))
  };
}

function loadRepairPlan(taskId, sessionId, { allowExactLegacy = true } = {}) {
  return loadRepairPlanFromStore(
    stateRoot,
    taskId,
    sessionId,
    { allowExactLegacy }
  );
}

function validatedReceiptsForScope(taskScope = {}) {
  if (!taskScope.task_id || !taskScope.session_id) {
    return { receipts: [], invalid: [], status: 'scope_unavailable' };
  }
  const index = readJson(
    path.join(
      stateRoot,
      'maintenance',
      'verification_receipts',
      'index.json'
    ),
    { receipts: [] }
  );
  const receipts = [];
  const invalid = [];
  const seen = new Set();
  for (const entry of index.receipts || []) {
    if (!receiptMatchesScope(entry, taskScope)) continue;
    if (!entry.receipt_id || seen.has(entry.receipt_id)) continue;
    seen.add(entry.receipt_id);
    try {
      const loaded = loadReceipt(stateRoot, entry.receipt_id);
      if (
        loaded.receipt.task_id !== taskScope.task_id ||
        loaded.receipt.session_id !== taskScope.session_id ||
        entry.content_sha256 !== loaded.receipt.content_sha256 ||
        entry.path !== loaded.relative_path
      ) {
        throw new Error('receipt index binding mismatch');
      }
      receipts.push(loaded.receipt);
    } catch (error) {
      invalid.push({
        receipt_id: /^KVR-[a-f0-9]{64}$/.test(
          String(entry.receipt_id || '')
        )
          ? entry.receipt_id
          : null,
        reason: error.code || 'receipt_index_binding_mismatch'
      });
    }
  }
  return {
    receipts,
    invalid,
    status: invalid.length ? 'partial' : 'verified'
  };
}

function validatedClosures(opportunities = null) {
  const artifact = opportunities || null;
  if (!artifact?.task_scope?.task_id || !artifact?.task_scope?.session_id) {
    return {
      lifecycle_ids: [],
      receipts: [],
      dedicated_receipts: [],
      invalid: [],
      status: 'scope_unavailable'
    };
  }
  let records;
  try {
    records = lifecycleById(
      readJson(
        path.join(stateRoot, 'maintenance', 'stale_items.json'),
        { items: [] }
      ),
      readJson(
        path.join(stateRoot, 'maintenance', 'repair_queue.json'),
        { queue: [] }
      )
    );
  } catch (error) {
    return {
      lifecycle_ids: [],
      receipts: [],
      dedicated_receipts: [],
      invalid: [{ lifecycle_id: null, reason: error.code || 'lifecycle_invalid' }],
      status: 'invalid'
    };
  }
  const lifecycleIds = [];
  const receipts = [];
  const dedicatedReceipts = [];
  const invalid = [];
  for (const opportunity of artifact.opportunities || []) {
    const record = records.get(String(opportunity.lifecycle_id || ''));
    if (!record || !['closed', 'resolved'].includes(record.status)) continue;
    const evidence = record.resolution_evidence || {};
    try {
      const loaded = loadReceipt(stateRoot, evidence.receipt_id, {
        finding: record,
        scope: artifact.task_scope,
        policyResolution: artifact.repair_on_touch
      });
      if (
        evidence.receipt_id !== loaded.receipt.receipt_id ||
        evidence.receipt_sha256 !== loaded.receipt.content_sha256 ||
        evidence.receipt_path !== loaded.relative_path
      ) {
        throw new Error('closure KVR evidence mismatch');
      }
      const sourceErrors = recertify.validateClosedReceiptSources(
        loaded.receipt,
        record
      );
      if (sourceErrors.length) {
        const error = new Error(sourceErrors.join(', '));
        error.code = 'closure_source_stale';
        throw error;
      }
      if (dedicatedRequirementFor(record)) {
        const dedicated = verifyDedicatedEvidence({
          stateRoot,
          evidence,
          verificationReceipt: loaded.receipt,
          finding: record
        });
        dedicatedReceipts.push({
          receipt_id: dedicated.receipt_id,
          content_sha256: dedicated.receipt_sha256,
          path: dedicated.receipt_path,
          lifecycle_id: record.lifecycle_id
        });
      }
      lifecycleIds.push(record.lifecycle_id);
      receipts.push(loaded.receipt);
    } catch (error) {
      invalid.push({
        lifecycle_id: record.lifecycle_id,
        reason: error.code || 'closure_provenance_invalid'
      });
    }
  }
  const relevantModules = new Set([
    ...(artifact.opportunities || []).map((item) => item.module_id),
    ...(artifact.task_scope?.direct_modules || []),
    ...(artifact.task_scope?.dependency_modules || []),
    ...(artifact.task_scope?.essential_dependency_modules || [])
  ].filter(Boolean).map(String));
  for (const moduleId of relevantModules) {
    for (const item of recertify.validatePriorModuleClosures(
      records,
      moduleId,
      null
    )) {
      if (!invalid.some((existing) =>
        existing.lifecycle_id === item.lifecycle_id &&
        existing.reason === item.reason)) {
        invalid.push(item);
      }
    }
  }
  return {
    lifecycle_ids: lifecycleIds,
    receipts,
    dedicated_receipts: dedicatedReceipts,
    invalid,
    status: invalid.length ? 'partial' : 'verified'
  };
}

function sanitizedOpportunityProjection(artifact, provenance = null) {
  const closureState = provenance || validatedClosures(artifact);
  const closed = new Set(closureState.lifecycle_ids);
  const plannedOpportunities = (artifact?.opportunities || []).map((item) => {
    if (closed.has(item.lifecycle_id)) return { ...item, status: 'repaired' };
    if (item.status === 'repaired') {
      return {
        ...item,
        status: 'deferred',
        decision_reason: 'closure_provenance_invalid',
        receipt_id: null,
        receipt_path: null,
        dedicated_receipt_id: null,
        dedicated_receipt_path: null,
        dedicated_receipt_sha256: null
      };
    }
    return { ...item };
  });
  const before = plannedOpportunities.map((item) => (
    item.status === 'repaired'
      ? { ...item, status: 'selected' }
      : item
  ));
  let currentFindings = null;
  let currentLifecycleStatus = 'verified';
  try {
    const records = lifecycleById(
      readJson(
        path.join(stateRoot, 'maintenance', 'stale_items.json'),
        { items: [] }
      ),
      readJson(
        path.join(stateRoot, 'maintenance', 'repair_queue.json'),
        { queue: [] }
      )
    );
    currentFindings = Array.from(records.values()).map((record) => {
      if (!['closed', 'resolved'].includes(record.status)) return { ...record };
      if (closed.has(record.lifecycle_id)) return { ...record, status: 'closed' };
      return {
        ...record,
        status: 'open',
        closure_provenance: 'invalid_or_unavailable'
      };
    });
  } catch {
    currentLifecycleStatus = 'invalid';
  }
  const currentReadiness =
    currentFindings && artifact?.task_scope
      ? taskReadiness(currentFindings, artifact.task_scope)
      : null;
  const plannedIds = new Set(
    plannedOpportunities.map((item) => item.lifecycle_id)
  );
  const relevantCurrentIds = new Set(
    currentReadiness?.relevant_lifecycle_ids || []
  );
  const newlyObserved = (currentFindings || [])
    .filter((item) =>
      relevantCurrentIds.has(item.lifecycle_id) &&
      !plannedIds.has(item.lifecycle_id)
    )
    .map((raw) => {
      const item = granularFinding(raw);
      return {
        ...item,
        relation_to_current_task: relationToTask(
          item,
          artifact.task_scope
        ),
        status: ['closed', 'resolved'].includes(raw.status)
          ? 'repaired'
          : 'deferred',
        decision_reason: 'current_finding_not_in_session_plan',
        requires_confirmation: false,
        confirmation_evidence: {
          critical_path: false,
          security_finding: false,
          exact_finding: false
        }
      };
    });
  const opportunities = [...plannedOpportunities, ...newlyObserved];
  return {
    opportunities,
    current_findings: currentFindings,
    current_lifecycle_status: currentLifecycleStatus,
    task_readiness_before: artifact?.task_scope
      ? taskReadiness(before, artifact.task_scope)
      : null,
    task_readiness_after: currentReadiness,
    provenance: closureState
  };
}

function exactFindingConfirmed(parsed, lifecycleId) {
  return (parsed.lists['confirm-finding'] || []).map(String).includes(String(lifecycleId));
}

function dedicatedPolicyAllows(policy) {
  const cap = policy?.policy_cap || {};
  return policy?.effective_mode === 'dedicated' &&
    policy?.effective?.enabled === true &&
    (!cap.active || ['dedicated', 'aggressive'].includes(cap.max_mode));
}

function currentTelemetry(opportunities = null, settings = null) {
  const artifact = opportunities || {
    task_scope: null,
    opportunities: []
  };
  const resolved = settings || artifact.repair_on_touch || resolvePolicy({ context });
  const provenance = validatedClosures(artifact);
  const projection = sanitizedOpportunityProjection(artifact, provenance);
  const telemetry = maintenanceTelemetry({
    enabled: resolved.effective?.enabled ?? resolved.configured?.enabled ?? false,
    mode: resolved.effective_mode || resolved.effective?.mode || 'off',
    opportunities: projection.opportunities,
    receipts: provenance.receipts,
    doctorBefore: artifact.global?.score ?? null,
    doctorAfter: provenance.status === 'verified'
      ? artifact.global_after?.score ?? null
      : null,
    taskReadinessBefore:
      projection.task_readiness_before?.score ?? null,
    taskReadinessAfter:
      projection.task_readiness_after?.score ?? null
  });
  return {
    task_id: artifact.task_scope?.task_id || null,
    session_id: artifact.task_scope?.session_id || null,
    task_scope_sha256: artifact.task_scope?.scope_hash || null,
    closure_provenance_status: provenance.status,
    closure_provenance_invalid: provenance.invalid,
    current_lifecycle_status: projection.current_lifecycle_status,
    task_readiness_provenance:
      'recomputed_from_plan_findings_and_validated_closures',
    doctor_snapshot: {
      authority: 'advisory_doctor_snapshot',
      before: artifact.global?.score ?? null,
      after: artifact.global_after?.score ?? null
    },
    dedicated_receipt_ids: provenance.dedicated_receipts
      .map((item) => item.receipt_id)
      .sort(),
    ...telemetry
  };
}

function persistTelemetry(opportunities = null, settings = null) {
  const telemetry = currentTelemetry(opportunities, settings);
  const target = path.join(stateRoot, 'maintenance', 'repair_on_touch_telemetry.json');
  const body = {
    schema_version: 'knowledge-repair-on-touch-telemetry.v1',
    generated_at: new Date().toISOString(),
    ...telemetry
  };
  writeJsonAtomic(target, body);
  let sessionTarget = null;
  if (telemetry.task_id && telemetry.session_id) {
    const directory = secureStateStore(
      stateRoot,
      'maintenance/repair_sessions',
      { create: true }
    );
    sessionTarget = path.join(
      directory,
      `${repairSessionKey(telemetry.task_id, telemetry.session_id)}.telemetry.json`
    );
    writeJsonAtomic(sessionTarget, body);
  }
  return { telemetry, target, session_target: sessionTarget };
}

function commandSettings(parsed) {
  const action = parsed.positionals[0] || 'show';
  if (action === 'show') return output(resolvePolicy({ context, perRun: perRunPolicy(parsed.flags) }));
  if (action === 'reset') {
    return output(withContainedLock(REPAIR_LOCK, () =>
      saveOperatorRepairSettings(context, DEFAULT_REPAIR_POLICY, {
        reset: true,
        updatedBy: getAgentId()
      })));
  }
  if (action !== 'set') throw new Error('Usage: repair-on-touch.js settings [show|set|reset]');
  if (canonicalMode(parsed.flags.mode, null) === 'aggressive' && !boolFlag(parsed.flags.confirm)) {
    const error = new Error('Extended repair requires --confirm=true');
    error.code = 'aggressive_confirmation_required';
    throw error;
  }
  const body = readRequest(parsed.flags.request);
  return output(withContainedLock(REPAIR_LOCK, () =>
    saveOperatorRepairSettings(
      context,
      settingsInput(parsed.flags, body),
      { updatedBy: getAgentId() }
    )));
}

function commandPlan(parsed) {
  const body = readRequest(parsed.flags.request);
  const scope = buildTaskScope(taskInput(parsed, body));
  const latestTarget = path.join(
    stateRoot,
    'maintenance',
    'repair_opportunities.json'
  );
  const plan = repairPlanLocation(
    scope.task_id,
    scope.session_id,
    { create: true }
  );
  const planned = withContainedLock(REPAIR_LOCK, () => {
    const policy = resolvePolicy({
      context,
      perRun: perRunPolicy(parsed.flags)
    });
    const quality = doctor({
      quiet: true,
      taskScope: scope,
      skipLock: true
    });
    const artifact = buildOpportunitiesArtifact({
      findings: quality.findings || quality.issues || [],
      scope,
      policyResolution: policy,
      doctorScore: quality.quality_score,
      dedicatedRun: boolFlag(parsed.flags['dedicated-run']),
      confirmations: {
        critical_paths: boolFlag(parsed.flags['confirm-critical']),
        security_findings: boolFlag(parsed.flags['confirm-security']),
        findings: parsed.lists['confirm-finding'] || []
      },
      generatedBy: getAgentId()
    });
    const artifactValidation = validateRepairPlanArtifact(artifact);
    if (!artifactValidation.ok) {
      const error = new Error(
        `Generated repair plan is invalid: ${artifactValidation.errors.join(', ')}`
      );
      error.code = 'repair_plan_schema_invalid';
      error.validation = artifactValidation;
      throw error;
    }
    writeJsonAtomic(plan.path, artifact);
    writeJsonAtomic(latestTarget, artifact);
    return {
      artifact,
      telemetry: persistTelemetry(artifact, policy)
    };
  });
  const { artifact, telemetry } = planned;
  return output({
    status: 'planned',
    plan_id: plan.plan_id,
    plan_artifact: plan.relative_path,
    artifact: path.relative(stateRoot, latestTarget).replace(/\\/g, '/'),
    telemetry_artifact: path.relative(
      stateRoot,
      telemetry.session_target || telemetry.target
    ).replace(/\\/g, '/'),
    latest_advisory_artifact: path.relative(
      stateRoot,
      latestTarget
    ).replace(/\\/g, '/'),
    ...artifact
  });
}

function receiptTestEntry(loaded) {
  const execution = loaded.record;
  return {
    command: execution.command,
    command_argv: execution.command_argv,
    status: execution.status,
    exit_code: execution.exit_code,
    tests_passed: execution.status === 'pass' && execution.exit_code === 0 ? 1 : 0,
    duration_ms: execution.duration_ms,
    execution_id: execution.execution_id,
    execution_sha256: execution.content_sha256,
    execution_path: path.relative(stateRoot, loaded.path).replace(/\\/g, '/'),
    stdout_sha256: execution.stdout_sha256,
    stderr_sha256: execution.stderr_sha256
  };
}

function verificationExecutions(body, taskId, sessionId) {
  const sourceFiles = body.source_files_checked || body.source_files || [];
  const testsToRun = body.tests_to_run || body.verification_commands || [];
  const references = Array.from(new Set([
    ...(body.test_execution_ids || []),
    ...((body.tests_run || []).map((item) => item.execution_id).filter(Boolean))
  ]));
  const executed = testsToRun.length
    ? runVerificationTests({
      stateRoot,
      repoRoot: context.targetRoot,
      taskId,
      sessionId,
      tests: testsToRun,
      sourceFiles,
      checkedBy: getAgentId()
    })
    : [];
  const loaded = [
    ...executed.map((item) => ({ record: item.record, path: item.path })),
    ...references.map((reference) => loadExecutionRecord(stateRoot, reference))
  ];
  if (!loaded.length || loaded.some((item) => !item)) {
    const error = new Error('Receipt requires real verification executions; use tests_to_run or test_execution_ids');
    error.code = 'verification_execution_required';
    throw error;
  }
  for (const item of loaded) {
    if (item.record.status !== 'pass' || item.record.exit_code !== 0) {
      const error = new Error(`Verification command failed: ${item.record.command}`);
      error.code = 'verification_execution_failed';
      throw error;
    }
  }
  return loaded;
}

function checkedSourceFiles(body) {
  const requested = body.source_files_checked || body.source_files || [];
  const paths = Array.from(new Set(requested.map((item) => String(item.path || item))));
  if (!paths.length) {
    const error = new Error('Receipt requires source_files or source_files_checked');
    error.code = 'verification_source_required';
    throw error;
  }
  return paths.map((relative) => {
    const absolute = safeRelativeFile(context.targetRoot, relative);
    if (!absolute) {
      const error = new Error(`Verification source is missing or unsafe: ${relative}`);
      error.code = 'verification_source_unsafe';
      throw error;
    }
    return {
      path: relative.replace(/\\/g, '/'),
      sha256: sha256(fs.readFileSync(absolute))
    };
  });
}

function commandVerify(parsed) {
  const body = readRequest(parsed.flags.request);
  const taskId = parsed.flags['task-id'] || body.task_id;
  const sessionId = parsed.flags['session-id'] || body.session_id || process.env.KNOWLEDGE_SESSION_ID;
  const tests = body.tests_to_run || body.verification_commands || body.tests || [];
  const sourceFiles = body.source_files_checked || body.source_files || [];
  const executions = runVerificationTests({
    stateRoot,
    repoRoot: context.targetRoot,
    taskId,
    sessionId,
    tests,
    sourceFiles,
    checkedBy: getAgentId()
  });
  return output({
    status: executions.every((item) => item.record.status === 'pass') ? 'pass' : 'fail',
    schema_version: 'knowledge-verification-execution-batch.v1',
    task_id: taskId,
    session_id: sessionId,
    executions: executions.map((item) => ({
      ...receiptTestEntry({ record: item.record, path: item.path }),
      execution_path: item.relative_path,
      idempotent: item.idempotent
    }))
  });
}

function commandReceipt(parsed) {
  const body = readRequest(parsed.flags.request);
  const requestedTaskId = body.task_id || parsed.flags['task-id'];
  const requestedSessionId =
    body.session_id ||
    parsed.flags['session-id'] ||
    process.env.KNOWLEDGE_SESSION_ID;
  if (!requestedTaskId || !requestedSessionId) {
    const error = new Error(
      'Receipt creation requires an explicit task_id and session_id'
    );
    error.code = 'repair_plan_scope_required';
    throw error;
  }
  const plan = loadRepairPlan(requestedTaskId, requestedSessionId);
  const opportunities = plan.artifact;
  if (!opportunities) throw new Error('Run repair-on-touch plan before creating a receipt');
  const findingId = body.finding_id || parsed.flags['finding-id'];
  const plannedFinding = (opportunities.opportunities || [])
    .find((item) => item.lifecycle_id === findingId);
  if (!plannedFinding) throw new Error(`Selected finding not found in current plan: ${findingId}`);
  if (plannedFinding.status !== 'selected') {
    throw new Error(`Finding is not selected for this task: ${plannedFinding.decision_reason}`);
  }
  const finding = currentLifecycleFinding(findingId);
  if (!finding || ['closed', 'resolved'].includes(finding.status)) {
    const error = new Error(`Current open lifecycle finding not found: ${findingId}`);
    error.code = 'lifecycle_not_open';
    throw error;
  }
  const policy = opportunities.repair_on_touch || resolvePolicy({ context });
  const dedicatedRequirement = dedicatedRequirementFor(finding);
  const requestedMode = dedicatedRequirement
    ? 'dedicated'
    : (body.repair_mode || policy.effective_mode);
  const livePolicy = resolvePolicy({
    context,
    ...(dedicatedRequirement
      ? { perRun: { mode: 'dedicated', enabled: true } }
      : {})
  });
  const strictPolicy = restrictPolicyBudgets(policy, livePolicy);
  if (!policyAllowsReceiptMode(livePolicy, requestedMode)) {
    const error = new Error('Receipt creation is blocked by the current effective policy');
    error.code = dedicatedRequirement
      ? 'dedicated_mode_blocked_by_policy'
      : 'repair_mode_blocked_by_live_policy';
    throw error;
  }
  if (dedicatedRequirement) {
    if (!boolFlag(parsed.flags['dedicated-run'])) {
      const error = new Error('Protected finding receipts require --dedicated-run');
      error.code = 'dedicated_run_required';
      throw error;
    }
    if (!exactFindingConfirmed(parsed, finding.lifecycle_id)) {
      const error = new Error(
        `Protected finding receipt requires --confirm-finding=${finding.lifecycle_id}`
      );
      error.code = 'dedicated_exact_confirmation_required';
      throw error;
    }
    if (!dedicatedPolicyAllows(policy) || !dedicatedPolicyAllows(livePolicy)) {
      const error = new Error('Dedicated receipt creation is blocked by the effective policy');
      error.code = 'dedicated_mode_blocked_by_policy';
      throw error;
    }
  }
  const taskId = requestedTaskId;
  const sessionId = requestedSessionId;
  const exactConfirmed = exactFindingConfirmed(parsed, finding.lifecycle_id);
  const plannedConfirmation =
    plannedFinding.confirmation_evidence || {};
  const confirmationEvidence = {
    critical_path: Boolean(
      plannedConfirmation.critical_path ||
      boolFlag(parsed.flags['confirm-critical']) ||
      exactConfirmed
    ),
    security_finding: Boolean(
      plannedConfirmation.security_finding ||
      boolFlag(parsed.flags['confirm-security']) ||
      exactConfirmed
    ),
    exact_finding: Boolean(
      plannedConfirmation.exact_finding ||
      exactConfirmed
    )
  };
  const sources = checkedSourceFiles(body);
  const executionBody = { ...body, source_files_checked: sources };
  const executions = verificationExecutions(executionBody, taskId, sessionId);
  const receipt = createReceipt({
    ...body,
    tests_to_run: undefined,
    verification_commands: undefined,
    test_execution_ids: undefined,
    source_files: undefined,
    source_files_checked: sources,
    tests_run: executions.map(receiptTestEntry),
    schema_version: 'knowledge-verification-receipt.v1',
    finding_id: finding.lifecycle_id,
    module_id: finding.module_id,
    task_id: taskId,
    session_id: sessionId,
    repair_mode: requestedMode,
    confirmation_evidence: confirmationEvidence,
    resolution_predicate: body.resolution_predicate || finding.resolution_predicate,
    task_scope_hash: opportunities.task_scope.scope_hash,
    task_scope: body.task_scope || {
      modules: opportunities.task_scope.direct_modules,
      artifacts: opportunities.task_scope.direct_artifacts
    }
  }, {
    finding,
    scope: opportunities.task_scope,
    policyResolution: strictPolicy,
    repoRoot: context.targetRoot,
    stateRoot,
    checkedBy: getAgentId()
  });
  const saved = saveReceipt(stateRoot, receipt);
  return output({
    status: 'receipt_saved',
    idempotent: saved.idempotent,
    receipt_path: path.relative(stateRoot, saved.path).replace(/\\/g, '/'),
    receipt
  });
}

function currentLifecycleFinding(lifecycleId) {
  const staleItems = readJson(
    path.join(stateRoot, 'maintenance', 'stale_items.json'),
    { items: [] }
  );
  const repairQueue = readJson(
    path.join(stateRoot, 'maintenance', 'repair_queue.json'),
    { queue: [] }
  );
  return lifecycleById(staleItems, repairQueue).get(String(lifecycleId || '')) || null;
}

function readJsonTransactionSnapshot(file, fallback) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return {
      value: JSON.parse(JSON.stringify(fallback)),
      guard: {
        path: file,
        expected_exists: false,
        containmentRoot: stateRoot
      }
    };
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    const error = new Error(
      `Repair state input is not a safe regular file: ${file}`
    );
    error.code = 'repair_read_set_invalid';
    throw error;
  }
  const body = fs.readFileSync(file);
  return {
    value: JSON.parse(
      body.toString('utf8').replace(/^\uFEFF/, '')
    ),
    guard: {
      path: file,
      expected_sha256: sha256(body),
      containmentRoot: stateRoot
    }
  };
}

function reopenUnsustainedClosure(receipt, blockingLifecycleIds = []) {
  const stalePath = path.join(
    stateRoot,
    'maintenance',
    'stale_items.json'
  );
  const queuePath = path.join(
    stateRoot,
    'maintenance',
    'repair_queue.json'
  );
  const staleSnapshot = readJsonTransactionSnapshot(
    stalePath,
    { items: [] }
  );
  const queueSnapshot = readJsonTransactionSnapshot(
    queuePath,
    { queue: [] }
  );
  const staleItems = staleSnapshot.value;
  const repairQueue = queueSnapshot.value;
  const current = lifecycleById(staleItems, repairQueue)
    .get(String(receipt.finding_id || ''));
  if (!current) {
    const error = new Error(
      `Unsustained closure lifecycle is missing: ${receipt.finding_id}`
    );
    error.code = 'unsustained_closure_lifecycle_missing';
    throw error;
  }
  if (!['closed', 'resolved'].includes(current.status)) {
    return {
      status: 'already_open',
      reopened: true,
      lifecycle_id: current.lifecycle_id,
      transaction_id: null
    };
  }
  const evidence = current.resolution_evidence || {};
  if (
    evidence.receipt_id !== receipt.receipt_id ||
    evidence.receipt_sha256 !== receipt.content_sha256
  ) {
    const error = new Error(
      'Unsustained closure no longer belongs to the applied receipt'
    );
    error.code = 'unsustained_closure_evidence_drift';
    throw error;
  }
  const previousOccurrence = Number(current.occurrence || 1);
  const timestamp = new Date().toISOString();
  const reconciled = reconcile({
    staleItems,
    repairQueue,
    findings: [current],
    source: 'repair_on_touch_post_verification',
    agentId: getAgentId(),
    timestamp
  });
  const reopened = reconciled.lifecycle.find((item) =>
    item.lifecycle_id === current.lifecycle_id);
  if (
    !reopened ||
    ['closed', 'resolved'].includes(reopened.status) ||
    reopened.occurrence !== previousOccurrence + 1
  ) {
    const error = new Error(
      'Unsustained closure did not produce a new open occurrence'
    );
    error.code = 'unsustained_closure_reopen_failed';
    throw error;
  }
  const transaction = commitJsonTransaction({
    stateRoot,
    transactionId:
      `repair-unsustained-${receipt.content_sha256.slice(0, 40)}`,
    allowedContainmentRoots: [stateRoot],
    guards: [
      staleSnapshot.guard,
      queueSnapshot.guard
    ],
    metadata: {
      type: 'repair_on_touch_unsustained_reopen',
      lifecycle_id: receipt.finding_id,
      receipt_id: receipt.receipt_id,
      blocking_lifecycle_ids: Array.from(
        new Set(blockingLifecycleIds.map(String))
      ).sort()
    },
    writes: [
      {
        path: stalePath,
        value: staleItems,
        containmentRoot: stateRoot
      },
      {
        path: queuePath,
        value: repairQueue,
        containmentRoot: stateRoot
      }
    ]
  });
  return {
    status: transaction.status,
    reopened: true,
    lifecycle_id: current.lifecycle_id,
    transaction_id: transaction.transaction_id
  };
}

function commandDedicatedReview(parsed) {
  const body = readRequest(parsed.flags.request);
  const receipt = findReceipt(parsed.flags.receipt || parsed.positionals[0]);
  const finding = currentLifecycleFinding(receipt.finding_id);
  if (!finding) {
    const error = new Error(`Lifecycle finding not found: ${receipt.finding_id}`);
    error.code = 'lifecycle_not_found';
    throw error;
  }
  if (!dedicatedRequirementFor(finding)) {
    const error = new Error(`Finding does not require dedicated review: ${finding.lifecycle_id}`);
    error.code = 'dedicated_receipt_not_required';
    throw error;
  }
  if (!boolFlag(parsed.flags.yes)) {
    const error = new Error('Dedicated review requires explicit --yes confirmation');
    error.code = 'dedicated_review_confirmation_required';
    throw error;
  }
  if (!boolFlag(parsed.flags['dedicated-run'])) {
    const error = new Error('Dedicated review requires --dedicated-run');
    error.code = 'dedicated_run_required';
    throw error;
  }
  if (!exactFindingConfirmed(parsed, finding.lifecycle_id)) {
    const error = new Error(
      `Dedicated review requires --confirm-finding=${finding.lifecycle_id}`
    );
    error.code = 'dedicated_exact_confirmation_required';
    throw error;
  }
  if (String(parsed.flags.result || body.result || '') !== 'pass') {
    const error = new Error('Dedicated review requires an explicit --result=pass verdict');
    error.code = 'dedicated_review_pass_required';
    throw error;
  }
  const dedicatedVerifierId = String(
    parsed.flags['verifier-id'] || body.dedicated_verifier_id || ''
  );
  const reviewedBy = String(parsed.flags['reviewed-by'] || body.reviewed_by || '');
  if (!dedicatedVerifierId || !reviewedBy) {
    const error = new Error('Dedicated review requires --verifier-id and --reviewed-by');
    error.code = 'dedicated_reviewer_identity_required';
    throw error;
  }
  if (reviewedBy === receipt.checked_by) {
    const error = new Error('Dedicated reviewer must differ from the verification receipt actor');
    error.code = 'dedicated_reviewer_not_independent';
    throw error;
  }
  const opportunities = loadRepairPlan(
    receipt.task_id,
    receipt.session_id
  ).artifact;
  const policy = opportunities?.repair_on_touch || resolvePolicy({
    context,
    perRun: { mode: 'dedicated', enabled: true }
  });
  const livePolicy = resolvePolicy({
    context,
    perRun: { mode: 'dedicated', enabled: true }
  });
  const strictPolicy = restrictPolicyBudgets(policy, livePolicy);
  if (!dedicatedPolicyAllows(policy) || !dedicatedPolicyAllows(livePolicy)) {
    const error = new Error('Dedicated review is blocked by the effective policy');
    error.code = 'dedicated_mode_blocked_by_policy';
    throw error;
  }
  const validation = validateReceipt(receipt, {
    finding,
    scope: opportunities?.task_scope || null,
    policyResolution: strictPolicy,
    repoRoot: context.targetRoot,
    stateRoot,
    requireIdentity: true
  });
  if (!validation.ok || receipt.repair_mode !== 'dedicated') {
    const error = new Error(
      `Verification receipt is not valid for dedicated review: ${validation.errors.join(', ')}`
    );
    error.code = 'verification_receipt_invalid';
    error.validation = validation;
    throw error;
  }
  const dedicatedReceipt = createDedicatedReceipt({
    verificationReceipt: receipt,
    finding,
    confirmedLifecycleId: finding.lifecycle_id,
    dedicatedVerifierId,
    reviewedBy
  });
  const saved = saveDedicatedReceipt(stateRoot, dedicatedReceipt, {
    verificationReceipt: receipt,
    finding
  });
  return output({
    status: 'dedicated_receipt_saved',
    idempotent: saved.idempotent,
    receipt_path: saved.relative_path,
    receipt: dedicatedReceipt
  });
}

function applyReceiptAndFinalize(receipt, request = {}) {
  const finalized = withContainedLock(REPAIR_LOCK, () => {
    const recovered = recoverTransactions(stateRoot, {
      allowedContainmentRoots: [
        stateRoot,
        context.projectKnowledgeRoot,
        context.targetRoot
      ],
      transactionIdPrefixes: ['repair-']
    });
    const applied = recertify.applyVerificationReceipt(receipt, {
      ...request
    });
    applied.recovered_transactions = recovered;
    const succeeded =
      String(applied.status).startsWith('recertified') ||
      applied.status === 'generated_artifact_repaired';
    if (
      !succeeded ||
      (
        applied.idempotent === true &&
        applied.trust_elevation_pending !== true
      )
    ) {
      return { result: applied };
    }
    const plan = loadRepairPlan(receipt.task_id, receipt.session_id);
    const opportunities = plan.artifact;
    const pendingBeforeDoctor =
      applied.trust_elevation_pending === true;
    const plannedFinding = (
      opportunities?.opportunities || []
    ).find((item) => item.lifecycle_id === receipt.finding_id);
    const generatedRepair = Boolean(
      plannedFinding &&
      [
        'rebuild_generated_artifact',
        'regenerate_index',
        'regenerate_graph',
        'regenerate_report'
      ].includes(plannedFinding.repair_class)
    );
    const overlaps = (left, right) => {
      const a = String(left || '').replace(/\\/g, '/').toLowerCase();
      const b = String(right || '').replace(/\\/g, '/').toLowerCase();
      return Boolean(a && b) && (
        a === b ||
        a.startsWith(`${b}/`) ||
        b.startsWith(`${a}/`)
      );
    };
    let quality = doctor({
      quiet: true,
      taskScope: opportunities?.task_scope || null,
      skipLock: true,
      ...(pendingBeforeDoctor
        ? {
            pendingTrustClosures: [{
              lifecycle_id: receipt.finding_id,
              receipt_id: receipt.receipt_id,
              receipt_sha256: receipt.content_sha256,
              task_id: receipt.task_id,
              session_id: receipt.session_id
            }]
          }
        : {})
    });
    let blockingLifecycleIds = [];
    const closureIsSustained = () => {
      const current = currentLifecycleFinding(receipt.finding_id);
      const evidence = current?.resolution_evidence || {};
      const exact = Boolean(
        current &&
        ['closed', 'resolved'].includes(current.status) &&
        evidence.receipt_id === receipt.receipt_id &&
        evidence.receipt_sha256 === receipt.content_sha256
      );
      blockingLifecycleIds = [];
      if (generatedRepair) {
        const repairedArtifacts = [
          plannedFinding.artifact,
          ...(plannedFinding.affected_artifacts || [])
        ];
        const records = lifecycleById(
          readJson(
            path.join(
              stateRoot,
              'maintenance',
              'stale_items.json'
            ),
            { items: [] }
          ),
          readJson(
            path.join(
              stateRoot,
              'maintenance',
              'repair_queue.json'
            ),
            { queue: [] }
          )
        );
        blockingLifecycleIds = Array.from(records.values())
          .filter((item) =>
            item.lifecycle_id !== receipt.finding_id &&
            item.module_id === plannedFinding.module_id &&
            !['closed', 'resolved'].includes(item.status) &&
            [
              item.artifact,
              ...(item.affected_artifacts || [])
            ].some((artifact) =>
              repairedArtifacts.some((candidate) =>
                overlaps(artifact, candidate)))
          )
          .map((item) => item.lifecycle_id)
          .sort();
      }
      return exact && blockingLifecycleIds.length === 0;
    };
    let sustained = closureIsSustained();
    if (sustained && pendingBeforeDoctor) {
      const trustFinalization =
        recertify.finalizeTrustElevation(receipt, applied);
      applied.trust_finalization = trustFinalization;
      applied.trust_elevated =
        trustFinalization.trust_elevated === true;
      applied.trust_elevation_pending = false;
      applied.status = applied.trust_elevated
        ? 'recertified'
        : 'recertified_with_open_findings';
      if (!applied.trust_elevated) {
        applied.trust_elevation_reason =
          trustFinalization.reason || 'trust_finalization_not_eligible';
        quality = doctor({
          quiet: true,
          taskScope: opportunities?.task_scope || null,
          skipLock: true
        });
        sustained = closureIsSustained();
      }
    }
    if (!sustained) {
      applied.status = generatedRepair
        ? 'generated_repair_not_sustained'
        : 'reopened_after_verification';
      applied.reason = generatedRepair
        ? 'generated_artifact_still_has_open_debt'
        : 'recertification_not_sustained';
      applied.closed_lifecycle_ids = [];
      applied.blocking_lifecycle_ids = Array.from(
        new Set(blockingLifecycleIds)
      ).sort();
      const reopen = reopenUnsustainedClosure(
        receipt,
        applied.blocking_lifecycle_ids
      );
      applied.reopen_transaction = reopen;
      applied.reopened_lifecycle_ids = reopen.reopened
        ? [receipt.finding_id]
        : [];
      applied.trust_elevated = false;
      applied.trust_elevation_pending = false;
      for (const item of opportunities?.opportunities || []) {
        if (item.lifecycle_id !== receipt.finding_id) continue;
        item.status = 'deferred';
        item.decision_reason =
          'verification_did_not_clear_finding';
        item.receipt_id = null;
        item.receipt_path = null;
        item.dedicated_receipt_id = null;
        item.dedicated_receipt_path = null;
        item.dedicated_receipt_sha256 = null;
        delete item.closed_at;
      }
      const items = opportunities?.opportunities || [];
      const selected = items.filter((item) =>
        ['selected', 'repaired'].includes(item.status));
      const deferred = items.filter((item) =>
        item.status === 'deferred');
      if (opportunities?.summary) {
        opportunities.summary.findings_considered = items.length;
        opportunities.summary.findings_selected = selected.length;
        opportunities.summary.findings_deferred = deferred.length;
      }
      if (opportunities?.budget?.selected) {
        opportunities.budget.selected.findings = selected.length;
        opportunities.budget.selected.estimated_minutes =
          selected.reduce((sum, item) =>
            sum + Number(item.estimated_additional_work?.minutes || 0)
          , 0);
        opportunities.budget.selected.estimated_context_percent =
          selected.reduce((sum, item) =>
            sum + Number(
              item.estimated_additional_work?.context_percent || 0
            )
          , 0);
      }
      quality = doctor({
        quiet: true,
        taskScope: opportunities?.task_scope || null,
        skipLock: true
      });
    }
    for (const item of opportunities?.opportunities || []) {
      if (item.lifecycle_id === receipt.finding_id) {
        item.trust_elevation_pending =
          applied.trust_elevation_pending === true;
        item.trust_elevated = applied.trust_elevated === true;
      }
    }
    if (opportunities) {
      const previousDoctorAt = Date.parse(
        String(opportunities.doctor_after_generated_at || '')
      );
      const currentDoctorAt = Date.parse(String(quality.generated_at || ''));
      if (
        !Number.isFinite(previousDoctorAt) ||
        !Number.isFinite(currentDoctorAt) ||
        currentDoctorAt >= previousDoctorAt
      ) {
        opportunities.global_after = {
          score: quality.quality_score,
          status: quality.global?.status || quality.status
        };
        opportunities.task_readiness_after =
          quality.task_readiness ||
          opportunities.task_readiness_after ||
          null;
        opportunities.doctor_after_generated_at = quality.generated_at;
      }
      opportunities.global_after_pending_doctor = false;
      const planValidation = validateRepairPlanArtifact(opportunities);
      if (!planValidation.ok) {
        const error = new Error(
          `Final repair plan is invalid: ${planValidation.errors.join(', ')}`
        );
        error.code = 'repair_plan_schema_invalid';
        error.validation = planValidation;
        throw error;
      }
      writeJsonAtomic(plan.path, opportunities);
    }
    const latestPath = path.join(
      stateRoot,
      'maintenance',
      'repair_opportunities.json'
    );
    const latest = readJson(latestPath, null);
    if (
      opportunities &&
      !plan.legacy &&
      latest?.task_scope?.task_id === receipt.task_id &&
      latest?.task_scope?.session_id === receipt.session_id
    ) {
      writeJsonAtomic(latestPath, opportunities);
    }
    const telemetry = persistTelemetry(opportunities || null);
    applied.doctor_after = quality.quality_score;
    applied.task_readiness_after =
      quality.task_readiness || applied.task_readiness_after;
    applied.telemetry = telemetry.telemetry;
    applied.telemetry_artifact = path.relative(
      stateRoot,
      telemetry.session_target || telemetry.target
    ).replace(/\\/g, '/');
    return { result: applied };
  });
  return output(finalized.result);
}

function commandApply(parsed) {
  const receipt = findReceipt(parsed.flags.receipt || parsed.positionals[0]);
  return applyReceiptAndFinalize(receipt, {
    dedicatedRun: boolFlag(parsed.flags['dedicated-run']),
    faultAt: parsed.flags['fault-at'] || null
  });
}

function commandApplyDedicated(parsed) {
  const receipt = findReceipt(parsed.flags.receipt || parsed.positionals[0]);
  if (!boolFlag(parsed.flags.yes)) {
    const error = new Error('Dedicated apply requires explicit --yes confirmation');
    error.code = 'dedicated_apply_confirmation_required';
    throw error;
  }
  if (!boolFlag(parsed.flags['dedicated-run'])) {
    const error = new Error('Dedicated apply requires --dedicated-run');
    error.code = 'dedicated_run_required';
    throw error;
  }
  if (!exactFindingConfirmed(parsed, receipt.finding_id)) {
    const error = new Error(
      `Dedicated apply requires --confirm-finding=${receipt.finding_id}`
    );
    error.code = 'dedicated_exact_confirmation_required';
    throw error;
  }
  const dedicatedReference = parsed.flags['dedicated-receipt'];
  const dedicatedLoaded = loadDedicatedReceipt(stateRoot, dedicatedReference);
  return applyReceiptAndFinalize(receipt, {
    explicitDedicatedApply: true,
    dedicatedRun: true,
    confirmedFindingId: receipt.finding_id,
    dedicatedReceiptId: dedicatedLoaded.receipt.receipt_id,
    faultAt: parsed.flags['fault-at'] || null
  });
}

function commandStatus(parsed) {
  const settings = resolvePolicy({ context });
  const quality = readJson(path.join(stateRoot, 'maintenance', 'quality_report.json'), {});
  const taskId = parsed.flags['task-id'];
  const sessionId = parsed.flags['session-id'];
  if (!taskId || !sessionId) {
    const error = new Error(
      'Status requires explicit --task-id and --session-id'
    );
    error.code = 'repair_plan_scope_required';
    throw error;
  }
  const scoped = loadRepairPlan(taskId, sessionId);
  const opportunities = scoped.artifact;
  if (!opportunities) {
    const error = new Error('Session-scoped repair plan not found');
    error.code = 'repair_plan_not_found';
    throw error;
  }
  const receipts = validatedReceiptsForScope(opportunities?.task_scope || {});
  const closures = validatedClosures(opportunities);
  const projection = sanitizedOpportunityProjection(opportunities, closures);
  return output({
    schema_version: 'knowledge-repair-on-touch-status.v1',
    scope_source: 'explicit_session',
    plan_id: scoped.plan_id,
    settings,
    global_doctor_snapshot: {
      authority: 'advisory_doctor_snapshot',
      value: quality.global || {
        score: quality.quality_score ?? null,
        status: quality.status || 'unknown'
      }
    },
    task_readiness: projection.task_readiness_after,
    task_readiness_provenance:
      'recomputed_from_plan_findings_and_validated_closures',
    opportunities: projection.opportunities,
    current_lifecycle_status: projection.current_lifecycle_status,
    advisory_projection: opportunities ? {
      authority: 'plan_snapshot_not_closure_authority',
      plan: opportunities
    } : null,
    verification_receipts: {
      status: receipts.status,
      receipts: receipts.receipts.map((receipt) => ({
        receipt_id: receipt.receipt_id,
        content_sha256: receipt.content_sha256,
        task_id: receipt.task_id,
        session_id: receipt.session_id
      })),
      invalid: receipts.invalid
    },
    verified_closures: closures.lifecycle_ids,
    dedicated_verification_receipts: closures.dedicated_receipts,
    closure_provenance: {
      status: closures.status,
      invalid: closures.invalid
    }
  });
}

function commandTelemetry(parsed) {
  const taskId = parsed.flags['task-id'];
  const sessionId = parsed.flags['session-id'];
  if (!taskId || !sessionId) {
    const error = new Error(
      'Telemetry requires explicit --task-id and --session-id'
    );
    error.code = 'repair_plan_scope_required';
    throw error;
  }
  const persisted = withContainedLock(REPAIR_LOCK, () => {
    const plan = loadRepairPlan(taskId, sessionId);
    if (!plan.artifact) {
      const error = new Error('Session-scoped repair plan not found');
      error.code = 'repair_plan_not_found';
      throw error;
    }
    return persistTelemetry(plan.artifact);
  });
  return output({
    ...persisted.telemetry,
    scope_source: 'explicit_session',
    telemetry_artifact: path.relative(
      stateRoot,
      persisted.session_target || persisted.target
    ).replace(/\\/g, '/')
  });
}

function commandSummary(parsed) {
  const body = readRequest(parsed.flags.request);
  const taskId = parsed.flags['task-id'] || body.task_id;
  const sessionId = parsed.flags['session-id'] || body.session_id;
  if (!taskId || !sessionId) {
    const error = new Error('Summary requires an explicit task_id and session_id');
    error.code = 'repair_plan_scope_required';
    throw error;
  }
  const plan = loadRepairPlan(taskId, sessionId);
  if (!plan.artifact) {
    const error = new Error('Session-scoped repair plan not found');
    error.code = 'repair_plan_not_found';
    throw error;
  }
  const opportunities = plan.artifact;
  const provenance = validatedClosures(opportunities);
  const projection = sanitizedOpportunityProjection(
    opportunities,
    provenance
  );
  return output(humanMaintenanceSummary({
    primaryTask: body.primary_task || [],
    primaryTests: body.primary_tests || [],
    opportunities: projection.opportunities,
    receipts: provenance.receipts,
    dedicatedReceipts: provenance.dedicated_receipts,
    closed: provenance.lifecycle_ids,
    doctorBefore: opportunities.global?.score ?? null,
    doctorAfter: provenance.status === 'verified'
      ? opportunities.global_after?.score ?? null
      : null,
    readinessBefore:
      projection.task_readiness_before?.score ?? null,
    readinessAfter:
      projection.task_readiness_after?.score ?? null,
    provenanceStatus: provenance.status,
    doctorSnapshotAuthority: 'advisory'
  }), { human: true });
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseArgs(argv);
  if (parsed.command === 'settings') return commandSettings(parsed);
  if (parsed.command === 'plan') return commandPlan(parsed);
  if (parsed.command === 'verify') return commandVerify(parsed);
  if (parsed.command === 'receipt') return commandReceipt(parsed);
  if (parsed.command === 'dedicated-review') return commandDedicatedReview(parsed);
  if (parsed.command === 'apply') return commandApply(parsed);
  if (parsed.command === 'apply-dedicated') return commandApplyDedicated(parsed);
  if (parsed.command === 'status') return commandStatus(parsed);
  if (parsed.command === 'telemetry') return commandTelemetry(parsed);
  if (parsed.command === 'summary') return commandSummary(parsed);
  throw new Error(
    'Usage: repair-on-touch.js ' +
    '<settings|plan|verify|receipt|dedicated-review|apply|apply-dedicated|status|telemetry|summary>'
  );
}

module.exports = {
  main,
  parseArgs,
  perRunPolicy,
  settingsInput,
  taskInput,
  findReceipt,
  receiptTestEntry,
  verificationExecutions,
  currentLifecycleFinding,
  commandDedicatedReview,
  commandApplyDedicated,
  exactFindingConfirmed,
  dedicatedPolicyAllows,
  receiptMatchesScope,
  repairPlanLocation,
  loadRepairPlan,
  validatedReceiptsForScope,
  validatedClosures,
  sanitizedOpportunityProjection,
  currentTelemetry,
  persistTelemetry
};

if (require.main === module) {
  try {
    const result = main();
    if (
      result &&
      (
        result.status === 'rejected' ||
        result.status === 'reopened_after_verification' ||
        result.status === 'generated_repair_not_sustained'
      )
    ) process.exitCode = 2;
  } catch (error) {
    console.error(JSON.stringify({
      status: 'error',
      code: error.code || 'repair_on_touch_error',
      message: error.message,
      validation: error.validation || null
    }, null, 2));
    process.exit(1);
  }
}
