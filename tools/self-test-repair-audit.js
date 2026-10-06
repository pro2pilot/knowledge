#!/usr/bin/env node
'use strict';

// Physical regression scenarios added by the 3.4.3 prerelease audit.
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const repair = require('./lib/repair-on-touch');
const lifecycle = require('./lib/queue-lifecycle');
const workflow = require('./lib/agent-task-workflow');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const systemRoot = path.resolve(__dirname, '..');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-repair-audit-'));
const checks = [];
const sha = (body) => crypto.createHash('sha256').update(body).digest('hex');
const read = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
function text(file, body) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
}
function json(file, body) { text(file, `${JSON.stringify(body, null, 2)}\n`); }
function check(name, fn) {
  try { fn(); checks.push({ name, status: 'pass' }); }
  catch (error) { checks.push({ name, status: 'fail', error: error.message }); }
}
function envFor(repo) {
  return {
    ...process.env,
    KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1',
    KNOWLEDGE_SYSTEM_ROOT: systemRoot,
    KNOWLEDGE_TARGET_ROOT: repo,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(repo, '.knowledge'),
    KNOWLEDGE_STATE_ROOT: path.join(repo, '.knowledge'),
    KNOWLEDGE_AGENT_ID: 'repair-audit',
    KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1'
  };
}
function fixture(name, testBody) {
  const repo = path.join(root, name);
  text(path.join(repo, 'src/probe.js'), 'module.exports = { ok: true };\n');
  text(path.join(repo, 'tests/probe.js'), testBody || 'if (!require("../src/probe").ok) process.exit(1);\n');
  fs.mkdirSync(path.join(repo, '.knowledge'), { recursive: true });
  return repo;
}
function disableUpdates(repo) {
  const config = path.join(repo, '.knowledge/config.yaml');
  const body = fs.readFileSync(config, 'utf8');
  text(config, body.replace(/(^updates:\s*\r?\n\s{2}enabled:)\s*true/m, '$1 false'));
  assert(!/^updates:\s*\r?\n\s{2}enabled:\s*true/m.test(fs.readFileSync(config, 'utf8')));
}
function verify(repo, sources = ['src/probe.js'], tests = [{ argv: ['node', 'tests/probe.js'] }]) {
  return repair.runVerificationTests({
    stateRoot: path.join(repo, '.knowledge'), repoRoot: repo,
    taskId: 'TASK-audit', sessionId: 'SESSION-audit',
    sourceFiles: sources, tests, checkedBy: 'repair-audit'
  });
}
function rejectedVerification(repo, sources) {
  assert.throws(() => verify(repo, sources), (error) =>
    error.code === 'verification_execution_invalid' &&
    /execution_source_changed_during_verification/.test(error.message));
  const store = path.join(repo, '.knowledge/maintenance/verification_executions');
  assert(!fs.existsSync(store) || fs.readdirSync(store).length === 0,
    'Unstable verification left an accepted KVE');
}
function producerFixture(name) {
  const repo = fixture(name);
  const tool = '.knowledge/tools/build-search-index.js';
  for (const relative of repair.generatedProducerDependencyClosure(tool)) {
    const target = path.join(repo, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(systemRoot, relative.replace(/^\.knowledge\//, '')), target);
  }
  return { repo, tool };
}
function verifyWorkflowBudget(name, timeouts, expectedTimeouts) {
  const repo = fixture(name, 'setTimeout(() => process.exit(0), 10);\n');
  const stateRoot = path.join(repo, '.knowledge');
  const context = { mode: 'repo', targetRoot: repo, projectKnowledgeRoot: stateRoot,
    stateRoot, systemRoot, agentId: 'repair-audit', repoId: 'repair-audit' };
  const firstRead = '# Probe\n';
  const route = {
    task_scope_hash: 'a'.repeat(64), snapshot_hash: 'b'.repeat(64),
    scope: { task: 'Verify probe', modules: ['probe'], paths: ['src/probe.js'], scope_source: 'explicit' },
    state: { current_status: 'current', task_readiness: 'ready', effective_claim_eligible: false,
      metrics: {}, bundle: { selected_modules: ['probe'] } },
    first_read: { path: 'first-read.md', content: firstRead, sha256: sha(firstRead), bytes: Buffer.byteLength(firstRead) }
  };
  let actualExecutions = 0;
  const dependencies = {
    taskRoute: () => route,
    doctor: () => ({ quality_score: 100, status: 'healthy', structural_status: 'healthy', task_readiness: { score: 100 } }),
    resolveEffectiveTaskRoutingState: () => ({ current_status: 'current', snapshot_hash: 'b'.repeat(64) }),
    runTool: (_context, tool, args, options = {}) => {
      const record = { tool, args, duration_ms: 1, exit_code: 0 };
      if (tool === 'agent-session.js') return { record, output: { session: { status: 'done' } } };
      if (args[0] === 'plan') return { record, output: { opportunities: [], task_readiness: { score: 100 } } };
      if (args[0] === 'status') return { record, output: { opportunities: [], verified_closures: [] } };
      assert.equal(args[0], 'verify');
      const request = read(args[args.indexOf('--request') + 1]);
      assert.deepEqual(request.tests_to_run.map((item) => item.timeout_ms), expectedTimeouts,
        'Finish did not persist the effective child timeout values');
      const executions = repair.runVerificationTests({ repoRoot: repo, stateRoot,
        taskId: request.task_id, sessionId: request.session_id, sourceFiles: request.source_files,
        tests: request.tests_to_run, checkedBy: 'repair-audit' });
      actualExecutions = executions.length;
      // Assert the worst permitted sequential runtime against the executor
      // deadline. The real child commands above complete quickly; this is a
      // budget contract check, not a claim that the long deadline was elapsed.
      const allowedSequentialRuntime = expectedTimeouts.reduce((total, value) => total + value, 0);
      assert(options.timeoutMs >= allowedSequentialRuntime + 30000,
        `Executor deadline ${options.timeoutMs} cannot cover sequential budget ${allowedSequentialRuntime} plus overhead`);
      return { record, output: { status: 'pass', executions: executions.map((item) => ({
        execution_id: item.record.execution_id, status: item.record.status,
        exit_code: item.record.exit_code, duration_ms: item.record.duration_ms
      })) } };
    }
  };
  const begun = workflow.begin(context, { task: 'Verify probe', modules: ['probe'], paths: ['src/probe.js'] }, dependencies);
  const result = workflow.finish(context, begun.workflow_id, {
    route_first_read_sha256: route.first_read.sha256,
    source_files: ['src/probe.js', 'tests/probe.js'], changed_files: ['src/probe.js'],
    tests_to_run: timeouts.map((timeout_ms) => ({ argv: ['node', 'tests/probe.js'], timeout_ms })),
    run_release_flow: false
  }, dependencies);
  assert.equal(actualExecutions, timeouts.length);
  assert.equal(result.primary_verification.execution_count, timeouts.length);
}
function seedClosure(repo, mutation = 'card') {
  const stateRoot = path.join(repo, '.knowledge');
  const context = { mode: 'repo', targetRoot: repo, projectKnowledgeRoot: stateRoot,
    stateRoot, systemRoot, agentId: 'repair-audit' };
  const card = { module_id: 'probe', key_files: ['src/probe.js'],
    summary: 'The current source returns ok true.', current_trust_level: 'suspect',
    target_trust_level: 'near_trusted', verification_status: 'needs_recheck' };
  json(path.join(stateRoot, 'modules/probe.json'), card);
  json(path.join(stateRoot, 'modules/module_registry.json'), { modules: [{
    module_id: 'probe', card: '.knowledge/modules/probe.json', key_files: ['src/probe.js']
  }] });
  json(path.join(stateRoot, 'freshness.json'), { tracked_files: [{ path: 'src/probe.js',
    sha256: sha(fs.readFileSync(path.join(repo, 'src/probe.js'))), status: 'needs_recheck' }], artifact_statuses: {} });
  json(path.join(stateRoot, 'maintenance/trust_report.json'), { modules: {
    trusted: [], near_trusted: [], routing_trusted: [], advisory_only: [], suspect: ['probe'], low_confidence: []
  }, module_statuses: [{ module_id: 'probe', trust_status: 'suspect', freshness_status: 'needs_recheck' }] });
  const finding = { ...repair.granularFinding({ module_id: 'probe', code: 'suspect_module',
    artifact: 'src/probe.js', affected_artifacts: ['src/probe.js', '.knowledge/modules/probe.json'],
    severity: 'medium', repair_class: 'verify_on_touch' }), occurrence: 1, opened_at: '2026-07-29T12:00:00.000Z' };
  const stale = { items: [] }, queue = { queue: [] };
  lifecycle.reconcile({ staleItems: stale, repairQueue: queue, findings: [finding],
    source: 'doctor', agentId: 'repair-audit', timestamp: finding.opened_at });
  json(path.join(stateRoot, 'maintenance/stale_items.json'), stale);
  json(path.join(stateRoot, 'maintenance/repair_queue.json'), queue);
  const scope = repair.buildTaskScope({ task_id: 'TASK-audit', session_id: 'SESSION-audit',
    user_task: 'Verify probe module', selected_modules: ['probe'], changed_files: ['src/probe.js'] });
  const policyResolution = repair.resolvePolicy({ context, repository: {}, operator: {}, perRun: { mode: 'scoped' } });
  const plan = repair.buildOpportunitiesArtifact({ findings: [finding], scope, policyResolution,
    doctorScore: 86, generatedAt: new Date().toISOString(), generatedBy: 'repair-audit' });
  json(path.join(stateRoot, repair.repairSessionPlanRelative(scope.task_id, scope.session_id)), plan);
  json(path.join(stateRoot, 'maintenance/repair_opportunities.json'), plan);
  const execution = verify(repo, finding.affected_artifacts)[0];
  const record = execution.record;
  const receipt = repair.createReceipt({ schema_version: repair.RECEIPT_SCHEMA,
    finding_id: finding.lifecycle_id, module_id: finding.module_id,
    finding_occurrence_sha256: lifecycle.findingOccurrence(finding).sha256,
    task_id: scope.task_id, session_id: scope.session_id, repair_mode: 'scoped',
    source_files_checked: record.source_snapshot,
    tests_run: [{ command: record.command, command_argv: record.command_argv, status: record.status,
      exit_code: record.exit_code, tests_passed: 1, duration_ms: record.duration_ms,
      execution_id: record.execution_id, execution_sha256: record.content_sha256,
      execution_path: execution.relative_path, stdout_sha256: record.stdout_sha256, stderr_sha256: record.stderr_sha256 }],
    claims_checked: [{ claim_id: 'probe-current-behavior', claim: 'Source returns ok true.',
      result: 'confirmed', evidence: ['src/probe.js', 'tests/probe.js'] }],
    required_checks_completed: finding.required_checks,
    resolution_predicate: finding.resolution_predicate, predicate_result: 'pass',
    checked_by: 'repair-audit', checked_at: new Date().toISOString(), task_scope_hash: scope.scope_hash,
    task_scope: { modules: scope.direct_modules, artifacts: scope.direct_artifacts },
    additional_work: { wall_time_ms: Math.max(1, record.duration_ms), context_tokens: 0, context_percent: 0,
      input_tokens: null, output_tokens: null }
  }, { finding, scope, policyResolution, repoRoot: repo, stateRoot });
  repair.saveReceipt(stateRoot, receipt);
  const runner = path.join(repo, 'closure-probe.cjs');
  text(runner, `const fs = require('fs');\nconst path = require('path');\n` +
    `const recertify = require(${JSON.stringify(path.join(systemRoot, 'tools/recertify.js'))});\n` +
    `const receipt = ${JSON.stringify(receipt)};\n` +
    `const state = ${JSON.stringify(stateRoot)};\n` +
    `const result = recertify.applyVerificationReceipt(receipt);\n` +
    `if (!String(result.status).startsWith('recertified')) throw Error(JSON.stringify(result));\n` +
    `const cardPath = path.join(state,'modules/probe.json');\n` +
    `const finding = JSON.parse(fs.readFileSync(path.join(state,'maintenance/repair_queue.json'))).queue.find(x=>x.lifecycle_id===receipt.finding_id);\n` +
    `const before = recertify.validateClosedReceiptSources(receipt, finding);\n` +
    `const card = JSON.parse(fs.readFileSync(cardPath));\n` +
    (mutation === 'card'
      ? `card.summary = 'An unverified replacement claim.';\nfs.writeFileSync(cardPath, JSON.stringify(card,null,2)+'\\n');\n`
      : `finding.resolution_evidence.verified_by = 'uncommitted-verifier';\n`) +
    `const after = recertify.validateClosedReceiptSources(receipt, finding);\n` +
    `process.stdout.write(JSON.stringify({result,before,after}));\n`);
  return spawnSync(process.execPath, [runner], { cwd: repo, env: envFor(repo),
    encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
}

try {
  check('Stable source and physical test create a valid execution', () => {
    const run = verify(fixture('stable'))[0];
    assert.equal(run.record.status, 'pass');
    assert.deepEqual(run.record.source_snapshot_before, run.record.source_snapshot);
  });
  check('A successful test cannot certify source bytes it changed after assertions', () => {
    const repo = fixture('source-change', 'if (!require("../src/probe").ok) process.exit(1);\n' +
      'require("fs").writeFileSync("src/probe.js", "module.exports = { ok: false };\\n");\n');
    rejectedVerification(repo);
    assert(fs.readFileSync(path.join(repo, 'src/probe.js'), 'utf8').includes('false'),
      'Physical mutation scenario did not execute');
  });
  check('A test that rewrites itself cannot certify the replacement test', () => {
    const repo = fixture('test-change', 'require("fs").writeFileSync(__filename, "throw Error(\\"unverified\\");\\n");\n');
    rejectedVerification(repo);
  });
  check('A source created during an ordinary verification needs a new stable verification', () => {
    const repo = fixture('source-created', 'require("fs").writeFileSync("src/later.js", "module.exports = true;\\n");\n');
    rejectedVerification(repo, ['src/probe.js', 'src/later.js']);
  });
  check('Self-consistent imported execution evidence still rejects changed source snapshots', () => {
    const repo = fixture('forged-drift');
    const original = verify(repo)[0].record;
    const forged = JSON.parse(JSON.stringify(original));
    forged.source_snapshot_before[0].sha256 = '0'.repeat(64);
    forged.content_sha256 = repair.executionDigest(forged);
    forged.execution_id = `KVE-${forged.content_sha256}`;
    assert(repair.validateExecutionRecord(forged).errors.some((item) =>
      item.startsWith('execution_source_changed_during_verification:')));
  });
  check('An exact first-party rebuild can create its declared generated output', () => {
    const { repo, tool } = producerFixture('generated-output');
    const result = verify(repo, ['src/probe.js', '.knowledge/search/index.json'],
      [{ argv: ['node', tool] }])[0];
    assert.equal(result.record.status, 'pass');
    assert(!result.record.source_snapshot_before.some((item) => item.path === '.knowledge/search/index.json'));
    assert(result.record.source_snapshot.some((item) => item.path === '.knowledge/search/index.json'));
  });
  check('A generated producer cannot certify a change to unrelated source', () => {
    const { repo, tool } = producerFixture('generated-source-change');
    fs.appendFileSync(path.join(repo, tool), '\nrequire("fs").writeFileSync("src/probe.js", "module.exports = { ok: false };\\n");\n');
    assert.throws(() => verify(repo, ['src/probe.js', '.knowledge/search/index.json'],
      [{ argv: ['node', tool] }]), (error) => error.code === 'verification_execution_invalid' &&
        error.message.includes('execution_source_changed_during_verification:src/probe.js'));
  });
  check('Retaining a KVR reference cannot authorize unverified module-card claims', () => {
    const run = seedClosure(fixture('card-change'));
    assert.equal(run.status, 0, run.stderr || run.stdout);
    const output = JSON.parse(run.stdout);
    assert.deepEqual(output.before, [], JSON.stringify(output));
    assert(output.after.some((item) => item.startsWith('source_hash_current_mismatch:.knowledge/modules/probe.json')),
      `Changed module card kept prior provenance: ${JSON.stringify(output)}`);
  });
  check('Primary closure evidence must equal the committed transaction evidence', () => {
    const run = seedClosure(fixture('primary-evidence-change'), 'evidence');
    assert.equal(run.status, 0, run.stderr || run.stdout);
    const output = JSON.parse(run.stdout);
    assert.deepEqual(output.before, [], JSON.stringify(output));
    assert(output.after.includes('closure_transaction_evidence_mismatch'),
      `Altered primary evidence remained accepted: ${JSON.stringify(output)}`);
  });
  check('Agent-task gives a sequential verification batch its combined deadline', () => {
    verifyWorkflowBudget('workflow-batch', [20000, 20000, 20000], [20000, 20000, 20000]);
  });
  check('Agent-task records the same effective timeout limits used by verification', () => {
    verifyWorkflowBudget('workflow-clamp', [10, 600000], [1000, 300000]);
  });
  check('Restore Trust rejects --safe=false before any maintenance write', () => {
    const repo = path.join(root, 'restore-false');
    fs.cpSync(systemRoot, path.join(repo, '.knowledge'), { recursive: true });
    disableUpdates(repo);
    const run = spawnSync(process.execPath, [path.join(systemRoot, 'tools/restore-trust.js'), '--safe=false', '--json'], {
      cwd: repo, env: envFor(repo), encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024
    });
    assert.notEqual(run.status, 0);
    assert(/requires --safe/i.test(run.stderr), run.stderr || run.stdout);
    assert(!fs.existsSync(path.join(repo, '.knowledge/maintenance/restore-trust-report.json')));
  });
  check('Restore Trust executes all nine tools from its selected system root', () => {
    const repo = path.join(root, 'restore-split');
    fs.cpSync(systemRoot, path.join(repo, '.knowledge'), { recursive: true });
    disableUpdates(repo);
    fs.rmSync(path.join(repo, '.knowledge/tools'), { recursive: true });
    const run = spawnSync(process.execPath, [path.join(systemRoot, 'tools/restore-trust.js'), '--safe', '--json'], {
      cwd: repo, env: envFor(repo), encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024
    });
    const output = JSON.parse(run.stdout || '{}');
    assert.equal(output.steps?.length, 9, run.stderr || run.stdout);
    assert(output.steps.every((step) => !/Cannot find module/.test(step.stderr_tail)), JSON.stringify(output.steps));
    assert.equal(output.status, 'passed', JSON.stringify(output.steps));
  });
} finally {
  try { removeTempDirStrict(root); }
  catch (error) { checks.push({ name: 'Fixture cleanup', status: 'fail', error: error.message }); }
}

const failed = checks.filter((item) => item.status === 'fail');
console.log(JSON.stringify({ schema_version: 'knowledge-repair-audit-self-test.v1',
  status: failed.length ? 'fail' : 'pass', checks, passed: checks.length - failed.length,
  failed: failed.length }, null, 2));
if (failed.length) process.exitCode = 1;
