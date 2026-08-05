#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const {
  resolvePolicy,
  granularFinding,
  buildTaskScope,
  buildOpportunitiesArtifact,
  repairSessionPlanRelative,
  createReceipt,
  saveReceipt,
  runVerificationTests
} = require('./lib/repair-on-touch');
const {
  reconcile,
  identitySha256
} = require('./lib/queue-lifecycle');
const {
  RECEIPT_KEYS,
  receiptDigest,
  validateDedicatedReceipt,
  createDedicatedReceipt,
  saveDedicatedReceipt,
  loadDedicatedReceipt
} = require('./lib/dedicated-verification');

const systemRoot = path.resolve(__dirname, '..');
const toolPath = path.join(systemRoot, 'tools', 'repair-on-touch.js');
const checks = [];
const artifacts = {};
let cliEmptyExitRetries = 0;

function assert(value, message) {
  if (!value) throw new Error(message);
}

function check(name, fn) {
  fn();
  checks.push(name);
}

async function checkAsync(name, fn) {
  await fn();
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

function readJson(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return fallback;
  }
}

function fileHash(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function treeHashes(root) {
  const hashes = {};
  if (!fs.existsSync(root)) return hashes;
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) {
        hashes[path.relative(root, absolute).replace(/\\/g, '/')] =
          fileHash(absolute);
      }
    }
  };
  walk(root);
  return hashes;
}

function contextFor(root) {
  const knowledge = path.join(root, '.knowledge');
  return {
    mode: 'repo',
    targetRoot: root,
    projectKnowledgeRoot: knowledge,
    stateRoot: knowledge,
    teamRoot: null,
    repoId: 'dedicated-test-repo',
    workspaceId: null,
    agentId: 'verification-operator'
  };
}

function envFor(root) {
  return {
    ...process.env,
    KNOWLEDGE_SYSTEM_ROOT: systemRoot,
    KNOWLEDGE_TARGET_ROOT: root,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_STATE_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_AGENT_ID: 'verification-operator',
    KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1'
  };
}

function parseCommandJson(result) {
  const body = String(result.stdout || result.stderr || '').trim();
  try {
    return JSON.parse(body || '{}');
  } catch {
    throw new Error(`CLI returned non-JSON output: ${body}`);
  }
}

function runCliRaw(root, args) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const result = spawnSync(process.execPath, [toolPath, ...args], {
      cwd: root,
      env: envFor(root),
      encoding: 'utf8',
      timeout: 60000,
      windowsHide: true
    });
    const unexplainedEmptyExit = result.status === 1 &&
      result.signal === null && !result.error &&
      String(result.stdout || '') === '' &&
      String(result.stderr || '') === '';
    if (!unexplainedEmptyExit) return result;
    cliEmptyExitRetries += 1;
    if (attempt < 3) {
      const until = Date.now() + 50 * attempt;
      while (Date.now() < until) {
        // Bounded synchronous backoff in the physical self-test harness.
      }
    }
  }
  const error = new Error(
    `Persistent unexplained empty CLI exit for: ${args.join(' ')}`
  );
  error.code = 'dedicated_cli_empty_exit_persistent';
  throw error;
}

function runCli(root, args) {
  const result = runCliRaw(root, args);
  return { ...result, json: parseCommandJson(result) };
}

function runCliAsync(root, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [toolPath, ...args], {
      cwd: root,
      env: envFor(root),
      windowsHide: true
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (status, signal) => {
      try {
        resolve({
          status,
          signal,
          stdout,
          stderr,
          json: parseCommandJson({ stdout, stderr })
        });
      } catch (error) {
        reject(error);
      }
    });
  });
}

function findingFor({
  moduleId = 'auth',
  code = 'security_finding',
  artifact = 'src/auth.js',
  card = '.knowledge/modules/auth.json',
  repairClass = 'dedicated_action_required',
  predicate = 'source_and_relevant_tests_confirm_resolution',
  securitySensitive = code === 'security_finding'
} = {}) {
  return granularFinding({
    module_id: moduleId,
    code,
    artifact,
    affected_artifacts: [artifact, card],
    severity: 'high',
    repair_class: repairClass,
    resolution_predicate: predicate,
    security_sensitive: securitySensitive
  });
}

function createProjectFiles(root, delayMs = 0) {
  writeText(path.join(root, 'src', 'auth.js'), 'module.exports = { ok: true };\n');
  writeText(path.join(root, 'src', 'billing.js'), 'module.exports = { ok: true };\n');
  writeText(
    path.join(root, 'tests', 'auth.test.js'),
    `const delayMs = Number(process.argv[2] || ${Number(delayMs) || 0});\n` +
      'const until = process.hrtime.bigint() + BigInt(Math.max(0, delayMs)) * 1000000n;\n' +
      'while (process.hrtime.bigint() < until) {}\n' +
      'if (!require("../src/auth").ok) process.exit(1);\n'
  );
  writeJson(path.join(root, '.knowledge', 'evidence', 'auth.json'), {
    generated_at: '2026-07-29T12:00:00.000Z',
    result: 'pass'
  });
  writeJson(path.join(root, '.knowledge', 'evidence', 'billing.json'), {
    generated_at: '2026-07-29T12:00:00.000Z',
    result: 'unverified'
  });
  writeJson(path.join(root, '.knowledge', 'modules', 'auth.json'), {
    module_id: 'auth',
    current_trust_level: 'suspect',
    target_trust_level: 'near_trusted',
    verification_status: 'needs_recheck',
    key_files: ['src/auth.js'],
    evidence_files: ['.knowledge/evidence/auth.json']
  });
  writeJson(path.join(root, '.knowledge', 'modules', 'billing.json'), {
    module_id: 'billing',
    current_trust_level: 'suspect',
    target_trust_level: 'near_trusted',
    verification_status: 'needs_recheck',
    key_files: ['src/billing.js'],
    evidence_files: ['.knowledge/evidence/billing.json']
  });
  writeJson(path.join(root, '.knowledge', 'modules', 'module_registry.json'), {
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
  writeJson(path.join(root, '.knowledge', 'freshness.json'), {
    tracked_files: [
      {
        path: 'src/auth.js',
        sha256: fileHash(path.join(root, 'src', 'auth.js')),
        status: 'needs_recheck'
      },
      {
        path: 'src/billing.js',
        sha256: fileHash(path.join(root, 'src', 'billing.js')),
        status: 'needs_recheck'
      }
    ],
    artifact_statuses: {}
  });
  writeJson(path.join(root, '.knowledge', 'maintenance', 'trust_report.json'), {
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
}

function makeVerificationReceipt(root, finding, scope, policy, options = {}) {
  const stateRoot = path.join(root, '.knowledge');
  const affected = Array.from(new Set([
    finding.artifact || finding.primary_artifact,
    ...(finding.affected_artifacts || [])
  ].filter(Boolean))).sort();
  const executionStartedNs = process.hrtime.bigint();
  const execution = runVerificationTests({
    stateRoot,
    repoRoot: root,
    taskId: scope.task_id,
    sessionId: scope.session_id,
    tests: [{ argv: ['node', 'tests/auth.test.js', String(options.delayMs || 0)] }],
    sourceFiles: affected.map((item) => ({ path: item })),
    checkedBy: 'verification-operator'
  })[0];
  const executionFinishedNs = process.hrtime.bigint();
  const verificationStartedNs = process.hrtime.bigint();
  const executionDurationMs = Number(executionFinishedNs - executionStartedNs) / 1e6;
  const receipt = createReceipt({
    schema_version: 'knowledge-verification-receipt.v1',
    finding_id: finding.lifecycle_id,
    module_id: finding.module_id,
    task_id: scope.task_id,
    session_id: scope.session_id,
    repair_mode: 'dedicated',
    source_files_checked: affected.map((item) => ({
      path: item,
      sha256: fileHash(path.join(root, item))
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
      claim_id: `${finding.module_id}-resolution`,
      claim: 'The current source and relevant tests support the resolution predicate.',
      result: 'confirmed',
      evidence: [finding.artifact || finding.primary_artifact]
    }],
    required_checks_completed: finding.required_checks.filter(
      (item) => item !== 'dedicated_review'
    ),
    resolution_predicate: finding.resolution_predicate,
    predicate_result: 'pass',
    checked_at: '2026-07-29T12:00:00.000Z',
    checked_by: 'verification-operator',
    task_scope_hash: scope.scope_hash,
    task_scope: {
      modules: scope.direct_modules,
      artifacts: scope.direct_artifacts
    },
    confirmation_evidence: {
      critical_path: Boolean(finding.critical_path),
      security_finding: Boolean(finding.security_sensitive),
      exact_finding: true
    },
    additional_work: {
      wall_time_ms: Number(Math.max(executionDurationMs, execution.record.duration_ms, 0).toFixed(3)),
      context_tokens: 30,
      context_percent: 1,
      input_tokens: 25,
      output_tokens: 5
    }
  }, {
    finding,
    scope,
    policyResolution: policy,
    repoRoot: root,
    stateRoot,
    checkedBy: 'verification-operator'
  });
  const verificationFinishedNs = process.hrtime.bigint();
  return {
    receipt,
    path: saveReceipt(stateRoot, receipt).path,
    timing: {
      execution_started_ns: executionStartedNs.toString(),
      execution_finished_ns: executionFinishedNs.toString(),
      execution_duration_ms: Number(executionDurationMs.toFixed(3)),
      verification_started_ns: verificationStartedNs.toString(),
      verification_finished_ns: verificationFinishedNs.toString(),
      total_repair_wall_time_ms: Number((Number(verificationFinishedNs - executionStartedNs) / 1e6).toFixed(3))
    }
  };
}

function createFixture(root, options = {}) {
  createProjectFiles(root, options.delayMs || 0);
  const context = contextFor(root);
  const plannedFinding = findingFor(options.finding || {});
  const plannedUnrelated = findingFor({
    moduleId: 'billing',
    code: 'policy_violation',
    artifact: 'src/billing.js',
    card: '.knowledge/modules/billing.json',
    predicate: 'source_and_relevant_tests_confirm_policy_resolution'
  });
  const staleItems = { items: [] };
  const repairQueue = { queue: [] };
  reconcile({
    staleItems,
    repairQueue,
    findings: [plannedFinding, plannedUnrelated],
    source: 'doctor',
    agentId: 'doctor-seed',
    timestamp: '2026-07-29T12:00:00.000Z'
  });
  writeJson(path.join(root, '.knowledge', 'maintenance', 'stale_items.json'), staleItems);
  writeJson(path.join(root, '.knowledge', 'maintenance', 'repair_queue.json'), repairQueue);
  const finding = repairQueue.queue.find(
    (item) => item.lifecycle_id === plannedFinding.lifecycle_id
  );
  const unrelated = repairQueue.queue.find(
    (item) => item.lifecycle_id === plannedUnrelated.lifecycle_id
  );
  const scope = buildTaskScope({
    task_id: options.taskId || 'TASK-dedicated',
    session_id: options.sessionId || 'SESSION-dedicated',
    user_task: 'Verify and resolve the exact auth security finding',
    selected_modules: ['auth'],
    changed_files: ['src/auth.js'],
    agent_plan: ['read current source', 'run relevant tests', 'perform dedicated review']
  });
  const policy = resolvePolicy({
    context,
    repository: {},
    operator: {},
    perRun: { mode: 'dedicated', enabled: true }
  });
  const opportunities = buildOpportunitiesArtifact({
    findings: [finding, unrelated],
    scope,
    policyResolution: policy,
    doctorScore: 80,
    dedicatedRun: true,
    confirmations: { findings: [finding.lifecycle_id] },
    generatedAt: '2026-07-29T12:00:00.000Z',
    generatedBy: 'dedicated-e2e-test'
  });
  assert(
    opportunities.opportunities.find((item) =>
      item.lifecycle_id === finding.lifecycle_id)?.status === 'selected',
    'fixture protected finding was not selected'
  );
  writeJson(
    path.join(root, '.knowledge', 'maintenance', 'repair_opportunities.json'),
    opportunities
  );
  writeJson(
    path.join(
      root,
      '.knowledge',
      ...repairSessionPlanRelative(scope.task_id, scope.session_id).split('/')
    ),
    opportunities
  );
  const verification = makeVerificationReceipt(root, finding, scope, policy, options);
  return {
    root,
    context,
    finding,
    unrelated,
    scope,
    policy,
    opportunities,
    verification
  };
}

function reviewArgs(fixture, overrides = {}) {
  return [
    'dedicated-review',
    `--receipt=${fixture.verification.path}`,
    '--yes',
    '--dedicated-run',
    `--confirm-finding=${fixture.finding.lifecycle_id}`,
    '--result=pass',
    `--verifier-id=${overrides.verifierId || 'SECURITY-GATE-1'}`,
    `--reviewed-by=${overrides.reviewedBy || 'security-reviewer'}`
  ];
}

function applyArgs(fixture, dedicatedReceipt, overrides = {}) {
  const args = [
    'apply-dedicated',
    `--receipt=${fixture.verification.path}`,
    `--dedicated-receipt=${dedicatedReceipt.receipt_id}`,
    '--yes',
    '--dedicated-run',
    `--confirm-finding=${fixture.finding.lifecycle_id}`
  ];
  if (overrides.faultAt) args.push(`--fault-at=${overrides.faultAt}`);
  return args;
}

function queueRecord(fixture, lifecycleId = fixture.finding.lifecycle_id) {
  return readJson(
    path.join(fixture.root, '.knowledge', 'maintenance', 'repair_queue.json'),
    { queue: [] }
  ).queue.find((item) => item.lifecycle_id === lifecycleId);
}

function readdress(raw) {
  const copy = JSON.parse(JSON.stringify(raw));
  delete copy.receipt_id;
  delete copy.content_sha256;
  const digest = receiptDigest(copy);
  return {
    ...copy,
    receipt_id: `KDVR-${digest}`,
    content_sha256: digest
  };
}

function safeCleanup(root) {
  const resolved = path.resolve(root);
  const tempRoot = path.resolve(os.tmpdir());
  if (
    !resolved.startsWith(`${tempRoot}${path.sep}`) ||
    !path.basename(resolved).startsWith('knowledge-dedicated-verification-')
  ) {
    throw new Error(`Refusing unsafe self-test cleanup: ${resolved}`);
  }
  fs.rmSync(resolved, { recursive: true, force: true });
}

async function main() {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'knowledge-dedicated-verification-')
  );
  try {
    const primary = createFixture(path.join(root, 'primary'));
    check('00 measured receipt timing is monotonic and covers the execution evidence', () => {
      assert(
        primary.verification.receipt.additional_work.wall_time_ms >= primary.verification.timing.execution_duration_ms &&
        BigInt(primary.verification.timing.execution_finished_ns) >= BigInt(primary.verification.timing.execution_started_ns) &&
        BigInt(primary.verification.timing.verification_finished_ns) >= BigInt(primary.verification.timing.verification_started_ns),
        'receipt timing did not cover the measured execution interval'
      );
    });
    const delayed = createFixture(path.join(root, 'injected-delay'), { delayMs: 800 });
    check('00a injected child delay above 750 ms keeps the measured receipt valid', () => {
      assert(
        delayed.verification.receipt.additional_work.wall_time_ms >= 750 &&
        delayed.verification.timing.execution_duration_ms >= 750,
        'injected-delay receipt did not use measured wall time'
      );
    });
    const noConfirmation = buildOpportunitiesArtifact({
      findings: [primary.finding],
      scope: primary.scope,
      policyResolution: primary.policy,
      doctorScore: 80,
      dedicatedRun: true,
      confirmations: {}
    });
    check('01 protected finding stays deferred without exact lifecycle confirmation', () => {
      const item = noConfirmation.opportunities[0];
      assert(
        item.status === 'deferred' &&
        item.decision_reason === 'dedicated_exact_confirmation_required',
        `unexpected decision: ${item.decision_reason}`
      );
    });
    check('02 exact lifecycle confirmation satisfies the protected security confirmation gate', () => {
      const item = primary.opportunities.opportunities.find(
        (entry) => entry.lifecycle_id === primary.finding.lifecycle_id
      );
      assert(item.status === 'selected', `finding was not selected: ${item.decision_reason}`);
    });
    check('03 verification receipt keeps objective checks separate from dedicated review', () => {
      const completed = primary.verification.receipt.required_checks_completed;
      assert(
        !completed.includes('dedicated_review') &&
        ['read_current_source', 'run_relevant_tests', 'compare_existing_claims']
          .every((item) => completed.includes(item)),
        'verification and dedicated-review predicates were not separated'
      );
    });
    const secondSessionLatest = {
      ...JSON.parse(JSON.stringify(primary.opportunities)),
      task_scope: {
        ...primary.opportunities.task_scope,
        task_id: 'TASK-other-agent',
        session_id: 'SESSION-other-agent'
      }
    };
    writeJson(
      path.join(
        primary.root,
        '.knowledge',
        'maintenance',
        'repair_opportunities.json'
      ),
      secondSessionLatest
    );
    const productionReceiptRequest = path.join(
      primary.root,
      'dedicated-receipt-request.json'
    );
    writeJson(productionReceiptRequest, {
      task_id: primary.scope.task_id,
      session_id: primary.scope.session_id,
      finding_id: primary.finding.lifecycle_id,
      source_files: [
        primary.finding.artifact || primary.finding.primary_artifact,
        ...(primary.finding.affected_artifacts || [])
      ],
      test_execution_ids: [
        primary.verification.receipt.tests_run[0].execution_id
      ],
      claims_checked: [{
        claim_id: 'auth-resolution',
        claim: 'The current source and relevant tests support the resolution predicate.',
        result: 'confirmed',
        evidence: [primary.finding.artifact || primary.finding.primary_artifact]
      }],
      required_checks_completed:
        primary.verification.receipt.required_checks_completed,
      predicate_result: 'pass',
      additional_work: {
        wall_time_ms: primary.verification.receipt.additional_work.wall_time_ms,
        context_tokens: 30,
        context_percent: 1,
        input_tokens: 25,
        output_tokens: 5
      }
    });
    const productionReceipt = runCli(primary.root, [
      'receipt',
      `--request=${productionReceiptRequest}`,
      `--finding-id=${primary.finding.lifecycle_id}`,
      '--dedicated-run',
      `--confirm-finding=${primary.finding.lifecycle_id}`
    ]);
    check('03a receipt creation resolves the explicit task/session plan, not the latest pointer', () => {
      assert(
        productionReceipt.status === 0 &&
        productionReceipt.json.receipt.task_id === primary.scope.task_id &&
        productionReceipt.json.receipt.session_id === primary.scope.session_id,
        `session-scoped receipt routing failed: ${productionReceipt.stderr || productionReceipt.stdout}`
      );
    });
    primary.verification = {
      receipt: productionReceipt.json.receipt,
      path: path.join(
        primary.root,
        '.knowledge',
        ...productionReceipt.json.receipt_path.split('/')
      )
    };
    check('03b production receipt metadata is authoritative and occurrence-bound', () => {
      assert(
        primary.verification.receipt.checked_by === 'verification-operator' &&
        primary.verification.receipt.finding_occurrence_sha256 &&
        primary.verification.receipt.checked_at <= new Date(
          Date.now() + 5 * 60 * 1000
        ).toISOString(),
        'production receipt accepted spoofable actor/time or omitted occurrence'
      );
    });

    const firstReview = runCli(primary.root, reviewArgs(primary));
    let firstDedicated;
    check('04 production dedicated-review creates a strict content-addressed receipt', () => {
      firstDedicated = firstReview.json.receipt;
      assert(
        firstReview.status === 0 &&
        firstReview.json.status === 'dedicated_receipt_saved' &&
        firstDedicated.receipt_id === `KDVR-${firstDedicated.content_sha256}` &&
        Object.keys(firstDedicated).sort().join('|') === [...RECEIPT_KEYS].sort().join('|'),
        `dedicated review failed: ${firstReview.stderr || firstReview.stdout}`
      );
      const stored = loadDedicatedReceipt(
        path.join(primary.root, '.knowledge'),
        firstDedicated.receipt_id,
        {
          verificationReceipt: primary.verification.receipt,
          finding: queueRecord(primary)
        }
      );
      assert(
        stored.relative_path ===
          `maintenance/dedicated_verification_receipts/${firstDedicated.content_sha256}.json`,
        'dedicated receipt was not saved at the exact content-addressed path'
      );
    });

    const secondReview = runCli(
      primary.root,
      reviewArgs(primary, { verifierId: 'SECURITY-GATE-2', reviewedBy: 'security-reviewer-2' })
    );
    const secondDedicated = secondReview.json.receipt;
    check('05 independent review identity must differ from the verification actor', () => {
      const rejected = runCli(
        primary.root,
        reviewArgs(primary, { reviewedBy: 'verification-operator' })
      );
      assert(
        rejected.status === 1 &&
        rejected.json.code === 'dedicated_reviewer_not_independent',
        'self-review was accepted'
      );
    });
    check('05a the core receipt API rejects self-review without relying on CLI checks', () => {
      let rejected = false;
      try {
        createDedicatedReceipt({
          verificationReceipt: primary.verification.receipt,
          finding: queueRecord(primary),
          confirmedLifecycleId: primary.finding.lifecycle_id,
          dedicatedVerifierId: 'SECURITY-GATE-SELF',
          reviewedBy: primary.verification.receipt.checked_by
        });
      } catch (error) {
        rejected =
          error.code === 'dedicated_verification_receipt_invalid' &&
          error.validation?.errors?.includes('dedicated_reviewer_not_independent');
      }
      assert(rejected, 'library caller bypassed reviewer independence');
    });
    check('06 a second valid physical dedicated receipt can exist before closure', () => {
      assert(
        secondReview.status === 0 &&
        secondDedicated.receipt_id !== firstDedicated.receipt_id,
        'competing pre-closure review receipt was not created'
      );
    });

    const normalApply = runCli(primary.root, [
      'apply',
      `--receipt=${primary.verification.path}`,
      '--dedicated-run'
    ]);
    check('07 normal apply cannot close a protected finding', () => {
      const normalApplyObservation = {
        exit_code: normalApply.status,
        result: normalApply.json,
        queue_status: queueRecord(primary).status
      };
      assert(
        normalApply.status === 2 &&
        normalApply.json.reason === 'protected_finding_requires_explicit_dedicated_apply' &&
        queueRecord(primary).status === 'open',
        `normal apply crossed the protected-finding boundary: ${JSON.stringify(normalApplyObservation)}`
      );
    });
    const missingConfirmation = runCli(primary.root, [
      'apply-dedicated',
      `--receipt=${primary.verification.path}`,
      `--dedicated-receipt=${firstDedicated.receipt_id}`,
      '--yes',
      '--dedicated-run'
    ]);
    check('08 dedicated apply requires the exact lifecycle confirmation', () => {
      const missingConfirmationObservation = {
        exit_code: missingConfirmation.status,
        result: missingConfirmation.json,
        queue_status: queueRecord(primary).status
      };
      assert(
        missingConfirmation.status === 1 &&
        missingConfirmation.json.code === 'dedicated_exact_confirmation_required' &&
        queueRecord(primary).status === 'open',
        `dedicated apply accepted a missing exact confirmation: ${JSON.stringify(missingConfirmationObservation)}`
      );
    });
    const wrongReference = runCli(primary.root, [
      'apply-dedicated',
      `--receipt=${primary.verification.path}`,
      '--dedicated-receipt=../outside.json',
      '--yes',
      '--dedicated-run',
      `--confirm-finding=${primary.finding.lifecycle_id}`
    ]);
    check('09 dedicated apply rejects path and traversal references', () => {
      const wrongReferenceObservation = {
        exit_code: wrongReference.status,
        result: wrongReference.json
      };
      assert(
        wrongReference.status === 1 &&
        wrongReference.json.code === 'dedicated_receipt_reference_invalid',
        `path-like dedicated receipt reference was accepted: ${JSON.stringify(wrongReferenceObservation)}`
      );
    });

    const applied = runCli(primary.root, applyArgs(primary, firstDedicated));
    check('10 exact production apply closes only the confirmed protected finding', () => {
      assert(
        applied.status === 0 &&
        applied.json.closed_lifecycle_ids?.length === 1 &&
        applied.json.closed_lifecycle_ids[0] === primary.finding.lifecycle_id &&
        queueRecord(primary).status === 'closed' &&
        queueRecord(primary, primary.unrelated.lifecycle_id).status === 'open',
        `exact dedicated apply failed: ${applied.stderr || applied.stdout}`
      );
    });
    check('10a applying session A does not overwrite session B latest-plan advisory state', () => {
      const latest = readJson(
        path.join(
          primary.root,
          '.knowledge',
          'maintenance',
          'repair_opportunities.json'
        ),
        {}
      );
      assert(
        latest.task_scope?.session_id === 'SESSION-other-agent',
        'session A apply overwrote session B latest-plan pointer'
      );
    });
    check('11 stored closure evidence binds both receipts and the trusted loader authority', () => {
      const evidence = queueRecord(primary).resolution_evidence;
      assert(
        evidence.receipt_id === primary.verification.receipt.receipt_id &&
        evidence.receipt_sha256 === primary.verification.receipt.content_sha256 &&
        evidence.dedicated_receipt_id === firstDedicated.receipt_id &&
        evidence.dedicated_receipt_sha256 === firstDedicated.content_sha256 &&
        evidence.dedicated_verifier_validated === true &&
        evidence.dedicated_authority_id ===
          'first_party_content_addressed_dedicated_receipt_loader.v1',
        'trusted KVR/KDVR closure binding is incomplete'
      );
    });
    const repeated = runCli(primary.root, applyArgs(primary, firstDedicated));
    check('12 the exact KVR plus KDVR pair is idempotent after full validation', () => {
      assert(
        repeated.status === 0 &&
        repeated.json.idempotent === true &&
        repeated.json.closed_lifecycle_ids?.[0] === primary.finding.lifecycle_id,
        `repeat apply was not idempotent: ${repeated.stderr || repeated.stdout}`
      );
    });
    check('12a exact replay remains read-only after live policy is lowered', () => {
      const capPath = path.join(
        primary.root,
        '.knowledge',
        'maintenance',
        'concurrency_policy.json'
      );
      writeJson(capPath, {
        team_policy: {
          repair_on_touch: { max_mode: 'off' }
        }
      });
      const stateFiles = [
        '.knowledge/maintenance/stale_items.json',
        '.knowledge/maintenance/repair_queue.json',
        '.knowledge/modules/auth.json',
        '.knowledge/maintenance/trust_report.json',
        '.knowledge/freshness.json',
        '.knowledge/maintenance/verification_receipts/index.json',
        '.knowledge/maintenance/repair_opportunities.json',
        `.knowledge/${repairSessionPlanRelative(
          primary.scope.task_id,
          primary.scope.session_id
        )}`
      ].map((relative) => path.join(
        primary.root,
        ...relative.split('/')
      )).filter((file) => fs.existsSync(file));
      const before = Object.fromEntries(
        stateFiles.map((file) => [file, fileHash(file)])
      );
      const replay = runCli(
        primary.root,
        applyArgs(primary, firstDedicated)
      );
      const after = Object.fromEntries(
        stateFiles.map((file) => [file, fileHash(file)])
      );
      fs.rmSync(capPath, { force: true });
      assert(
        replay.status === 0 &&
        replay.json.idempotent === true &&
        replay.json.closed_lifecycle_ids?.[0] ===
          primary.finding.lifecycle_id &&
        JSON.stringify(after) === JSON.stringify(before),
        `policy-lowered replay mutated state: ${
          replay.stderr || replay.stdout
        }`
      );
    });
    const competing = runCli(primary.root, applyArgs(primary, secondDedicated));
    check('13 a competing dedicated receipt cannot replace closure evidence', () => {
      assert(
        competing.status === 2 &&
        competing.json.reason === 'finding_already_closed_by_other_evidence' &&
        queueRecord(primary).resolution_evidence.dedicated_receipt_id ===
          firstDedicated.receipt_id,
        `competing dedicated evidence replaced the first closure: ${JSON.stringify({
          status: competing.status,
          reason: competing.json?.reason,
          stored: queueRecord(primary).resolution_evidence?.dedicated_receipt_id,
          expected: firstDedicated.receipt_id
        })}`
      );
    });
    check('14 tampering with the stored verification receipt breaks idempotent replay', () => {
      const original = fs.readFileSync(primary.verification.path, 'utf8');
      const tampered = JSON.parse(original);
      tampered.checked_by = 'tampered-operator';
      writeJson(primary.verification.path, tampered);
      const rejected = runCli(primary.root, applyArgs(primary, firstDedicated));
      fs.writeFileSync(primary.verification.path, original, 'utf8');
      assert(
        rejected.status !== 0 &&
        (
          rejected.json.reason === 'verification_receipt_invalid' ||
          rejected.json.code === 'verification_receipt_invalid'
        ) &&
        queueRecord(primary).resolution_evidence.receipt_id ===
          primary.verification.receipt.receipt_id,
        'tampered KVR was accepted on the idempotent path'
      );
    });

    const sourceMutation = createFixture(path.join(root, 'source-mutation'), {
      taskId: 'TASK-source-mutation',
      sessionId: 'SESSION-source-mutation'
    });
    const sourceReview = runCli(sourceMutation.root, reviewArgs(sourceMutation));
    writeText(
      path.join(sourceMutation.root, 'src', 'auth.js'),
      'module.exports = { ok: false };\n'
    );
    const sourceRejected = runCli(
      sourceMutation.root,
      applyArgs(sourceMutation, sourceReview.json.receipt)
    );
    check('15 source mutation after review rejects closure without state mutation', () => {
      assert(
        sourceRejected.status === 2 &&
        sourceRejected.json.reason === 'verification_receipt_invalid' &&
        queueRecord(sourceMutation).status === 'open',
        'stale source/KVR/KDVR evidence closed the finding'
      );
    });

    const capped = createFixture(path.join(root, 'policy-cap'), {
      taskId: 'TASK-policy-cap',
      sessionId: 'SESSION-policy-cap'
    });
    const cappedReview = runCli(capped.root, reviewArgs(capped));
    writeJson(
      path.join(capped.root, '.knowledge', 'maintenance', 'concurrency_policy.json'),
      { team_policy: { repair_on_touch: { max_mode: 'scoped' } } }
    );
    const cappedPolicy = resolvePolicy({
      context: capped.context,
      perRun: { mode: 'dedicated', enabled: true }
    });
    const cappedPlan = buildOpportunitiesArtifact({
      findings: [capped.finding],
      scope: capped.scope,
      policyResolution: cappedPolicy,
      doctorScore: 80,
      dedicatedRun: true,
      confirmations: { findings: [capped.finding.lifecycle_id] }
    });
    check('16 a scoped team cap explicitly blocks dedicated planning', () => {
      const item = cappedPlan.opportunities[0];
      assert(
        item.status === 'deferred' &&
        item.decision_reason === 'dedicated_blocked_by_policy_cap',
        `policy-cap decision was ambiguous: ${item.decision_reason}`
      );
    });
    const cappedReviewRejected = runCli(
      capped.root,
      reviewArgs(capped, { verifierId: 'SECURITY-GATE-CAPPED' })
    );
    check('17 the live team cap blocks new dedicated reviews', () => {
      assert(
        cappedReviewRejected.status === 1 &&
        cappedReviewRejected.json.code === 'dedicated_mode_blocked_by_policy',
        'live policy cap did not block dedicated review'
      );
    });
    const cappedApplyRejected = runCli(
      capped.root,
      applyArgs(capped, cappedReview.json.receipt)
    );
    check('18 the live team cap blocks dedicated apply after a prior review', () => {
      assert(
        cappedApplyRejected.status === 2 &&
        cappedApplyRejected.json.reason === 'dedicated_mode_blocked_by_policy' &&
        queueRecord(capped).status === 'open',
        'live policy cap did not block dedicated apply'
      );
    });

    check('19 strict KDVR validation rejects unknown fields and duplicate artifacts', () => {
      const unknown = readdress({ ...firstDedicated, notes: 'not allowed' });
      const duplicate = readdress({
        ...firstDedicated,
        affected_artifacts: [
          ...firstDedicated.affected_artifacts,
          firstDedicated.affected_artifacts[0]
        ]
      });
      const unknownValidation = validateDedicatedReceipt(unknown);
      const duplicateValidation = validateDedicatedReceipt(duplicate);
      assert(
        unknownValidation.errors.includes('dedicated_receipt_field_unknown:notes') &&
        duplicateValidation.errors.includes('dedicated_affected_artifacts_noncanonical'),
        'KDVR shape smuggling was accepted'
      );
    });
    check('20 KDVR validation binds verifier type, predicate, KVR, lifecycle, and identity', () => {
      const wrongRequirement = readdress({
        ...firstDedicated,
        dedicated_verifier_type: 'policy_review'
      });
      const wrongKvr = readdress({
        ...firstDedicated,
        verification_receipt_id: `KVR-${'a'.repeat(64)}`,
        verification_receipt_sha256: 'a'.repeat(64)
      });
      const wrongLifecycle = readdress({
        ...firstDedicated,
        lifecycle_id: `LC-${'b'.repeat(16)}`,
        confirmed_lifecycle_id: `LC-${'b'.repeat(16)}`
      });
      const wrongIdentity = readdress({
        ...firstDedicated,
        finding_identity_sha256: 'c'.repeat(64)
      });
      const options = {
        verificationReceipt: primary.verification.receipt,
        finding: queueRecord(primary)
      };
      assert(
        validateDedicatedReceipt(wrongRequirement, options).errors
          .includes('dedicated_verifier_requirement_invalid') &&
        validateDedicatedReceipt(wrongKvr, options).errors
          .includes('dedicated_verification_receipt_mismatch') &&
        validateDedicatedReceipt(wrongLifecycle, options).errors
          .includes('dedicated_lifecycle_id_mismatch') &&
        validateDedicatedReceipt(wrongIdentity, options).errors
          .includes('dedicated_finding_identity_mismatch'),
        'KDVR binding validation missed a mismatched authority input'
      );
    });
    check('21 KDVR loader rejects directories and oversized regular files', () => {
      const store = path.join(
        primary.root,
        '.knowledge',
        'maintenance',
        'dedicated_verification_receipts'
      );
      const directoryDigest = 'd'.repeat(64);
      fs.mkdirSync(path.join(store, `${directoryDigest}.json`), { recursive: true });
      let directoryRejected = false;
      try {
        loadDedicatedReceipt(path.join(primary.root, '.knowledge'), directoryDigest);
      } catch (error) {
        directoryRejected = error.code === 'dedicated_receipt_file_invalid';
      }
      const oversizedDigest = 'e'.repeat(64);
      fs.writeFileSync(
        path.join(store, `${oversizedDigest}.json`),
        Buffer.alloc(64 * 1024 + 1, 0x20)
      );
      let oversizedRejected = false;
      try {
        loadDedicatedReceipt(path.join(primary.root, '.knowledge'), oversizedDigest);
      } catch (error) {
        oversizedRejected = error.code === 'dedicated_receipt_file_invalid';
      }
      assert(directoryRejected && oversizedRejected, 'unsafe KDVR store entries were accepted');
    });
    check('21a KDVR save rejects a symlink or junction receipt store', () => {
      const linkStateRoot = path.join(root, 'store-link', '.knowledge');
      const maintenance = path.join(linkStateRoot, 'maintenance');
      const outside = path.join(root, 'store-link-outside');
      fs.mkdirSync(maintenance, { recursive: true });
      fs.mkdirSync(outside, { recursive: true });
      fs.symlinkSync(
        outside,
        path.join(maintenance, 'dedicated_verification_receipts'),
        'junction'
      );
      let rejected = false;
      try {
        saveDedicatedReceipt(linkStateRoot, firstDedicated, {
          verificationReceipt: primary.verification.receipt,
          finding: queueRecord(primary)
        });
      } catch (error) {
        rejected = error.code === 'dedicated_receipt_store_unsafe';
      }
      assert(
        rejected &&
        !fs.existsSync(path.join(outside, `${firstDedicated.content_sha256}.json`)),
        'symlinked KDVR store permitted an out-of-root write'
      );
    });

    const faulted = createFixture(path.join(root, 'fault-recovery'), {
      taskId: 'TASK-fault-recovery',
      sessionId: 'SESSION-fault-recovery'
    });
    const faultReview = runCli(faulted.root, reviewArgs(faulted));
    const faultRun = runCli(
      faulted.root,
      applyArgs(faulted, faultReview.json.receipt, { faultAt: 'after_promote_0' })
    );
    check('22 injected promotion fault does not report success', () => {
      assert(faultRun.status !== 0, 'fault-injected apply incorrectly reported success');
    });
    check('22a report commands do not recover or rewrite a faulted trust transaction', () => {
      const transactionRoot = path.join(
        faulted.root,
        '.knowledge',
        'maintenance',
        'transactions',
        `repair-${faulted.verification.receipt.content_sha256.slice(0, 40)}`
      );
      const protectedPaths = [
        path.join(
          faulted.root,
          '.knowledge',
          'maintenance',
          'stale_items.json'
        ),
        path.join(
          faulted.root,
          '.knowledge',
          'maintenance',
          'repair_queue.json'
        ),
        path.join(
          faulted.root,
          '.knowledge',
          'modules',
          'auth.json'
        ),
        path.join(
          faulted.root,
          '.knowledge',
          'maintenance',
          'trust_report.json'
        )
      ];
      const transactionBefore = treeHashes(transactionRoot);
      const protectedBefore = Object.fromEntries(
        protectedPaths.map((target) => [target, fileHash(target)])
      );
      const reportRuns = [
        runCli(faulted.root, [
          'status',
          `--task-id=${faulted.scope.task_id}`,
          `--session-id=${faulted.scope.session_id}`
        ]),
        runCli(faulted.root, [
          'telemetry',
          `--task-id=${faulted.scope.task_id}`,
          `--session-id=${faulted.scope.session_id}`
        ]),
        runCliRaw(faulted.root, [
          'summary',
          `--task-id=${faulted.scope.task_id}`,
          `--session-id=${faulted.scope.session_id}`
        ])
      ];
      const protectedAfter = Object.fromEntries(
        protectedPaths.map((target) => [target, fileHash(target)])
      );
      assert(
        JSON.stringify(treeHashes(transactionRoot)) ===
          JSON.stringify(transactionBefore) &&
        JSON.stringify(protectedAfter) === JSON.stringify(protectedBefore) &&
        reportRuns.every((result) => result.status === 0) &&
        reportRuns.slice(0, 2).every((result) =>
          result.json && typeof result.json === 'object') &&
        String(reportRuns[2].stdout || '').trim().length > 0,
        'report-only commands mutated or recovered a faulted trust transaction'
      );
    });
    const faultRetry = runCli(
      faulted.root,
      applyArgs(faulted, faultReview.json.receipt)
    );
    check('23 retry recovers the transaction to a single all-new closure', () => {
      const card = readJson(path.join(faulted.root, '.knowledge', 'modules', 'auth.json'), {});
      assert(
        faultRetry.status === 0 &&
        queueRecord(faulted).status === 'closed' &&
        card.verification.receipts.filter((item) =>
          item.receipt_id === faulted.verification.receipt.receipt_id).length === 1,
        `fault recovery failed: ${faultRetry.stderr || faultRetry.stdout}`
      );
    });

    const concurrent = createFixture(path.join(root, 'concurrent'), {
      taskId: 'TASK-concurrent',
      sessionId: 'SESSION-concurrent'
    });
    const concurrentReview = runCli(concurrent.root, reviewArgs(concurrent));
    await checkAsync('24 concurrent exact applies serialize to one closure and one card reference', async () => {
      const args = applyArgs(concurrent, concurrentReview.json.receipt);
      const results = await Promise.all([
        runCliAsync(concurrent.root, args),
        runCliAsync(concurrent.root, args)
      ]);
      const card = readJson(
        path.join(concurrent.root, '.knowledge', 'modules', 'auth.json'),
        {}
      );
      assert(
        results.every((item) => item.status === 0) &&
        results.some((item) => item.json.idempotent === true) &&
        queueRecord(concurrent).status === 'closed' &&
        card.verification.receipts.filter((item) =>
          item.receipt_id === concurrent.verification.receipt.receipt_id).length === 1,
        `concurrent apply did not serialize: ${JSON.stringify(results.map((item) => item.json))}`
      );
    });

    const manual = createFixture(path.join(root, 'generic-manual'), {
      taskId: 'TASK-generic-manual',
      sessionId: 'SESSION-generic-manual',
      finding: {
        code: 'custom_manual_review',
        repairClass: 'manual_review',
        securitySensitive: false,
        predicate: 'source_and_relevant_tests_confirm_manual_resolution'
      }
    });
    const manualReview = runCli(
      manual.root,
      reviewArgs(manual, {
        verifierId: 'MANUAL-GATE-1',
        reviewedBy: 'manual-reviewer'
      })
    );
    const manualApply = runCli(
      manual.root,
      applyArgs(manual, manualReview.json.receipt)
    );
    check('25 generic manual-review findings require and accept the same trusted KDVR path', () => {
      const evidence = queueRecord(manual).resolution_evidence;
      assert(
        manualReview.status === 0 &&
        manualReview.json.receipt.dedicated_verifier_type === 'manual_review' &&
        manualApply.status === 0 &&
        evidence.dedicated_receipt_id === manualReview.json.receipt.receipt_id,
        `generic manual-review path failed: ${manualReview.stderr || manualApply.stderr}`
      );
    });

    const newIdentity = {
      ...findingFor({
        code: 'security_finding',
        artifact: 'src/auth-v2.js',
        card: '.knowledge/modules/auth.json',
        predicate: 'a_new_resolution_predicate'
      }),
      occurrence: 1,
      opened_at: queueRecord(primary).opened_at
    };
    check('26 old dedicated evidence cannot validate a new finding identity', () => {
      assert(
        identitySha256(newIdentity) !== identitySha256(primary.finding),
        'fixture did not create a new finding identity'
      );
      const validation = validateDedicatedReceipt(firstDedicated, {
        verificationReceipt: primary.verification.receipt,
        finding: newIdentity
      });
      assert(
        !validation.ok &&
        (
          validation.errors.includes('dedicated_resolution_predicate_mismatch') ||
          validation.errors.includes('dedicated_finding_identity_mismatch')
        ),
        'old KDVR validated against a new finding identity'
      );
    });

    const replay = createFixture(path.join(root, 'reopen-replay'), {
      taskId: 'TASK-reopen-replay',
      sessionId: 'SESSION-reopen-replay'
    });
    const originalReplayCard = fs.readFileSync(
      path.join(replay.root, '.knowledge', 'modules', 'auth.json'),
      'utf8'
    );
    const replayReview = runCli(replay.root, reviewArgs(replay));
    const replayApply = runCli(
      replay.root,
      applyArgs(replay, replayReview.json.receipt)
    );
    const replayStalePath = path.join(
      replay.root,
      '.knowledge',
      'maintenance',
      'stale_items.json'
    );
    const replayQueuePath = path.join(
      replay.root,
      '.knowledge',
      'maintenance',
      'repair_queue.json'
    );
    const replayStale = readJson(replayStalePath, { items: [] });
    const replayQueue = readJson(replayQueuePath, { queue: [] });
    reconcile({
      staleItems: replayStale,
      repairQueue: replayQueue,
      findings: [replay.finding],
      source: 'doctor',
      agentId: 'doctor-reopen',
      timestamp: '2026-07-29T13:00:00.000Z'
    });
    writeJson(replayStalePath, replayStale);
    writeJson(replayQueuePath, replayQueue);
    fs.writeFileSync(
      path.join(replay.root, '.knowledge', 'modules', 'auth.json'),
      originalReplayCard,
      'utf8'
    );
    const oldPairReplay = runCli(
      replay.root,
      applyArgs(replay, replayReview.json.receipt)
    );
    check('27 an old KVR/KDVR pair cannot close a reopened occurrence', () => {
      assert(
        replayApply.status === 0 &&
        queueRecord(replay).occurrence === 2 &&
        queueRecord(replay).status === 'open' &&
        oldPairReplay.status === 2 &&
        oldPairReplay.json.reason === 'verification_receipt_invalid' &&
        oldPairReplay.json.errors?.includes('finding_occurrence_mismatch'),
        `stale occurrence replay was not rejected: ${oldPairReplay.stdout}`
      );
    });
    const oldKvrNewReview = runCli(
      replay.root,
      reviewArgs(replay, {
        verifierId: 'SECURITY-GATE-REOPEN',
        reviewedBy: 'security-reviewer-reopen'
      })
    );
    check('28 an old KVR cannot mint a new KDVR after reopen', () => {
      assert(
        oldKvrNewReview.status === 1 &&
        oldKvrNewReview.json.code === 'verification_receipt_invalid' &&
        oldKvrNewReview.json.validation?.errors?.includes(
          'finding_occurrence_mismatch'
        ) &&
        queueRecord(replay).status === 'open',
        `pre-occurrence verification minted a new review: ${oldKvrNewReview.stderr}`
      );
    });

    artifacts.primary_kvr = primary.verification.receipt.receipt_id;
    artifacts.primary_kdvr = firstDedicated.receipt_id;
    artifacts.primary_lifecycle = primary.finding.lifecycle_id;
    artifacts.fault_retry_idempotent = Boolean(faultRetry.json.idempotent);
    artifacts.measured_timing = primary.verification.timing;
    artifacts.injected_delay_timing = delayed.verification.timing;
    artifacts.cli_empty_exit_retries = cliEmptyExitRetries;
    process.stdout.write(`${JSON.stringify({
      schema_version: '3.3.0',
      status: 'pass',
      checks_total: checks.length,
      checks,
      artifacts
    }, null, 2)}\n`);
  } finally {
    safeCleanup(root);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error.message);
    process.exit(1);
  });
}

module.exports = {
  main
};
