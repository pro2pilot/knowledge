#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { begin, finish, __test, DISCLAIMER } = require('./lib/agent-task-workflow');
const agentTaskCli = require('./agent-task');
const { systemVersion } = require('./lib/system-version');

const checks = [];
function check(id, condition, detail = null) {
  if (!condition) throw new Error(`${id}${detail ? `: ${JSON.stringify(detail)}` : ''}`);
  checks.push({ id, pass: true, detail });
}
function expectCode(id, fn, code) {
  let caught = null;
  try { fn(); } catch (error) { caught = error; }
  check(id, caught && caught.code === code, { observed: caught?.code || null });
}
function hash(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function fixture(name) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `agent-task-${name}-`));
  const knowledge = path.join(root, '.knowledge');
  fs.mkdirSync(path.join(knowledge, 'sessions'), { recursive: true });
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.mkdirSync(path.join(root, 'tests'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'feature.js'), 'module.exports = 1;\n');
  fs.writeFileSync(path.join(root, 'tests', 'feature.test.js'), 'process.exit(0);\n');
  return {
    root,
    context: {
      mode: 'repo', systemRoot: path.resolve(__dirname, '..'), targetRoot: root,
      projectKnowledgeRoot: knowledge, stateRoot: knowledge, teamRoot: null,
      repoId: `repo-${name}`, workspaceId: null, agentId: 'agent-task-self-test',
      branch: 'test', headSha: 'a'.repeat(40), git: { is_git_repo: false }, warnings: []
    }
  };
}
function route(task = 'change feature') {
  const first = '# Task routing first read\nRead first: src/feature.js, tests/feature.test.js\n';
  return {
    task_scope_hash: 'a'.repeat(64), snapshot_hash: 'b'.repeat(64), routing_snapshot_hash: 'b'.repeat(64),
    baseline_hash: 'c'.repeat(64), metrics_comparison_hash: 'd'.repeat(64),
    scope: { task, modules: ['feature'], paths: ['src/'], scope_source: 'explicit' },
    state: {
      current_status: 'current', task_readiness: 'ready', effective_claim_eligible: true, claim_ineligible_reasons: [],
      bundle: { selected_modules: ['feature', 'shared'], task_readiness: 'ready' },
      metrics: {
        assessment: 'estimated_narrowing', signed_delta_percent: 40,
        workspace_baseline: { estimated_tokens: 1000 }, task_context: { estimated_tokens: 600 },
        workspace_narrowing: { modules_total: 5, modules_selected: 2, modules_excluded: 3, workspace_candidate_paths_total: 100, task_paths_selected: 5, unrelated_paths_excluded: 95 }
      }
    },
    public_estimate: `Estimated local first-read narrowing: 40%. ${DISCLAIMER}`,
    disclaimer: DISCLAIMER,
    first_read: { path: 'routing/tasks/a/snapshots/b/first-read.md', sha256: hash(first), bytes: Buffer.byteLength(first), content: first }
  };
}
function doctor(score, readiness) {
  return () => ({ label: 'mock', quality_score: score, status: 'usable_with_warnings', structural_status: 'healthy', task_readiness: { score: readiness, status: readiness === 100 ? 'ready' : 'needs_recheck' }, generated_at: new Date().toISOString(), report_path: 'maintenance/quality_report.json', command: { tool: 'doctor.js', duration_ms: 1 } });
}
function deps(options = {}) {
  const calls = [];
  let doctorCalls = 0;
  const selected = options.selected === undefined ? 1 : options.selected;
  const finding = {
    lifecycle_id: 'LC-1234567890abcdef', module_id: 'feature', artifact: 'src/feature.js', affected_artifacts: ['src/feature.js'],
    repair_class: options.repairClass || 'verify_on_touch', status: 'selected', required_checks: ['read_current_source', 'run_relevant_tests', 'verify_resolution_predicate'],
    resolution_predicate: 'feature_test_passes', ...(options.finding || {})
  };
  const plan = { status: 'planned', task_readiness: { score: 93 }, opportunities: [
    ...Array.from({ length: selected }, (_, i) => ({ ...finding, lifecycle_id: i ? `LC-${String(i).padStart(16, '1')}` : finding.lifecycle_id })),
    ...(options.overlap ? [{ lifecycle_id: 'LC-overlap0000000', module_id: 'feature', artifact: 'src/feature.js', affected_artifacts: ['src/feature.js'], repair_class: 'verify_on_touch', status: 'deferred', decision_reason: 'overlapping_open_debt' }] : []),
    { lifecycle_id: 'LC-unrelated000000', module_id: 'other', artifact: 'src/other.js', repair_class: 'verify_on_touch', status: 'deferred', decision_reason: 'outside_task_scope' }
  ] };
  const runTool = (_context, tool, args) => {
    calls.push({ tool, args });
    if (tool === 'agent-session.js') return { record: { tool, duration_ms: 1 }, output: { ok: true, session: { status: args[0] === 'finish' ? 'done' : 'running' } } };
    if (tool === 'repair-on-touch.js' && args[0] === 'plan') return { record: { tool, duration_ms: 2 }, output: plan };
    if (tool === 'repair-on-touch.js' && args[0] === 'verify') {
      if (options.verifyFail) return { record: { tool, duration_ms: 3 }, output: { status: 'fail', executions: [{ execution_id: 'KVE-x', status: 'fail', exit_code: 1, duration_ms: 3 }] } };
      return { record: { tool, duration_ms: 3 }, output: { status: 'pass', executions: [{ execution_id: `KVE-${'1'.repeat(64)}`, status: 'pass', exit_code: 0, duration_ms: 3, execution_sha256: '2'.repeat(64) }] } };
    }
    if (tool === 'repair-on-touch.js' && args[0] === 'receipt') {
      const requestIndex = args.indexOf('--request');
      const receiptRequest = requestIndex >= 0 ? JSON.parse(fs.readFileSync(args[requestIndex + 1], 'utf8')) : null;
      calls[calls.length - 1].request = receiptRequest;
      if (!receiptRequest || receiptRequest.additional_work?.context_tokens !== 0) {
        const failure = new Error('agent-task receipt must provide schema-valid zero reused context tokens');
        failure.code = 'agent_task_receipt_context_tokens_invalid';
        throw failure;
      }
      return { record: { tool, duration_ms: 4 }, output: { status: 'receipt_saved', reused_execution_ids: [`KVE-${'1'.repeat(64)}`], receipt: { receipt_id: `KVR-${'3'.repeat(64)}`, content_sha256: '4'.repeat(64) } } };
    }
    if (tool === 'repair-on-touch.js' && args[0] === 'apply') return { record: { tool, duration_ms: 5 }, output: { status: options.unsustained ? 'reopened_after_verification' : 'recertified', doctor_after: 93, task_readiness_after: { score: 100 } } };
    if (tool === 'repair-on-touch.js' && args[0] === 'status') return { record: { tool, duration_ms: 1 }, output: { status: 'ok', task_readiness: { score: options.unsustained ? 93 : 100 }, opportunities: plan.opportunities, verified_closures: options.unsustained || selected !== 1 ? [] : [finding.lifecycle_id] } };
    if (tool === 'flow.js') return { record: { tool, duration_ms: 10, exit_code: options.releaseFail ? 2 : 0 }, output: { status: options.releaseFail ? 'failed' : 'ok', flow_log: 'logs/flow.json', flow_log_sha256: 'f'.repeat(64), checks_status: options.releaseFail ? 'failed' : 'passed' } };
    throw new Error(`unexpected tool ${tool} ${args[0]}`);
  };
  return {
    calls,
    dependencies: {
      taskRoute: () => route(),
      doctor: () => {
        doctorCalls += 1;
        const score = options.unsustained ? 86 : (doctorCalls >= 3 ? 93 : 86);
        const readiness = options.unsustained ? 93 : (doctorCalls >= 3 ? 100 : 93);
        return doctor(score, readiness)();
      },
      runTool,
      resolveEffectiveTaskRoutingState: () => ({ current_status: 'current', snapshot_hash: 'b'.repeat(64), effective_claim_eligible: true })
    }
  };
}
function request(beginResult, overrides = {}) {
  return {
    route_first_read_sha256: beginResult.route.first_read.sha256,
    changed_files: ['src/feature.js'],
    source_files: ['src/feature.js', 'tests/feature.test.js'],
    tests_to_run: [{ argv: [process.execPath, 'tests/feature.test.js'], cwd: '.', timeout_ms: 10000 }],
    ...overrides
  };
}
function run() {
  check('01_disclaimer_is_canonical', /not provider-reported model-token usage/.test(DISCLAIMER));
  const f1 = fixture('happy'); const d1 = deps();
  try {
    const started = begin(f1.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d1.dependencies);
    check('02_begin_returns_ready', started.status === 'ready');
    check('03_begin_returns_exact_first_read_body', started.route.first_read.content.includes('src/feature.js'));
    check('04_begin_returns_sha_and_bytes', /^[a-f0-9]{64}$/.test(started.route.first_read.sha256) && started.route.first_read.bytes > 0);
    check('05_begin_returns_current_ready_claim_eligible_route', started.route.ready && started.route.effective_claim_eligible);
    check('06_begin_keeps_required_dependency', started.route.selected_modules.includes('shared'));
    check(
      '06a_begin_returns_bound_finish_template',
      started.finish_request_template?.route_first_read_sha256 === started.route.first_read.sha256 &&
      started.command_contract?.test_cwd_is_repository_relative === true
    );
    const result = finish(f1.context, started.workflow_id, request(started), d1.dependencies);
    check('07_primary_verification_passes', result.primary_verification.status === 'pass');
    check('08_one_native_kve_recorded', result.repair.kve_ids.length === 1 && /^KVE-[a-f0-9]{64}$/.test(result.repair.kve_ids[0]));
    check('09_native_kvr_recorded', /^KVR-[a-f0-9]{64}$/.test(result.repair.kvr_id));
    check('10_kve_reused_for_kvr', result.repair.verification_reused_for_receipt === true);
    const receiptCall = d1.calls.find((x) => x.tool === 'repair-on-touch.js' && x.args[0] === 'receipt');
    check('10a_receipt_uses_schema_valid_reused_context_telemetry', receiptCall?.request?.additional_work?.context_tokens === 0);
    check('10b_final_closure_is_sustained', result.repair.final_closure_sustained === true && result.repair.final_verified_closure_ids.includes('LC-1234567890abcdef'));
    check('11_no_duplicate_test_execution', result.repair.duplicate_test_executions === 0 && d1.calls.filter((x) => x.tool === 'repair-on-touch.js' && x.args[0] === 'verify').length === 1);
    check('12_doctor_separate_before_after', result.doctor.at_begin.quality_score === 86 && result.doctor.before_repair.quality_score === 86 && result.doctor.after.quality_score === 93 && result.metrics.doctor_repair_delta === 7);
    check('13_readiness_separate_before_after', result.task_readiness.before === 93 && result.task_readiness.after === 100);
    check('14_unrelated_debt_visible', result.repair.deferred_count >= 1);
    const acknowledgement = result.route?.first_read_acknowledgement;
    check(
      '14a_first_read_acknowledgement_is_content_addressed',
      /^ATFA-[a-f0-9]{64}$/.test(String(acknowledgement?.receipt_id || '')) &&
      acknowledgement?.first_read_sha256 === started.route.first_read.sha256 &&
      acknowledgement?.status === 'acknowledged'
    );
    const acknowledgementFile = path.join(
      f1.context.stateRoot,
      'sessions',
      'task-workflows',
      `${started.workflow_id}.first-read-ack.json`
    );
    const storedAcknowledgement = JSON.parse(fs.readFileSync(acknowledgementFile, 'utf8'));
    check(
      '14b_first_read_acknowledgement_is_physically_stored',
      storedAcknowledgement.receipt_id === acknowledgement.receipt_id &&
      storedAcknowledgement.content_sha256 === acknowledgement.content_sha256 &&
      result.evidence.first_read_acknowledgement.endsWith('.first-read-ack.json')
    );
    const again = finish(f1.context, started.workflow_id, request(started), d1.dependencies);
    check('15_identical_finish_is_idempotent', again.completed_at === result.completed_at);
    expectCode('16_changed_finish_request_rejected', () => finish(f1.context, started.workflow_id, request(started, { primary_summary: 'changed' }), d1.dependencies), 'agent_task_finish_request_changed');
  } finally { fs.rmSync(f1.root, { recursive: true, force: true }); }

  const f1a = fixture('doctor-before-route');
  try {
    const marker = path.join(f1a.root, 'doctor-before-route.marker');
    let routeSawDoctorState = false;
    const started = begin(f1a.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, {
      doctor: () => {
        fs.writeFileSync(marker, 'doctor state\n');
        return doctor(86, 93)();
      },
      taskRoute: () => {
        routeSawDoctorState = fs.existsSync(marker);
        return route();
      },
      runTool: (_context, tool, args) => {
        if (tool === 'agent-session.js') return { record: { tool, duration_ms: 1 }, output: { ok: true, session: { status: args[0] === 'finish' ? 'done' : 'running' } } };
        throw new Error(`unexpected tool ${tool} ${args[0]}`);
      }
    });
    check('16a_begin_runs_doctor_before_route_snapshot', started.status === 'ready' && routeSawDoctorState);
  } finally { fs.rmSync(f1a.root, { recursive: true, force: true }); }

  const f2 = fixture('norepair'); const d2 = deps({ selected: 0 });
  try {
    const started = begin(f2.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d2.dependencies);
    const result = finish(f2.context, started.workflow_id, request(started), d2.dependencies);
    check('17_no_finding_keeps_primary_success', result.status === 'completed' && result.repair.status === 'not_applicable');
    check('18_no_finding_creates_no_kvr', result.repair.kvr_id === null);
  } finally { fs.rmSync(f2.root, { recursive: true, force: true }); }

  const f3 = fixture('multiple'); const d3 = deps({ selected: 2 });
  try {
    const started = begin(f3.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d3.dependencies);
    const result = finish(f3.context, started.workflow_id, request(started), d3.dependencies);
    check('19_multiple_findings_fail_closed', result.repair.eligibility.reason === 'multiple_selected_findings' && result.repair.kvr_id === null);
  } finally { fs.rmSync(f3.root, { recursive: true, force: true }); }

  const f3b = fixture('overlap'); const d3b = deps({ overlap: true });
  try {
    const started = begin(f3b.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d3b.dependencies);
    const result = finish(f3b.context, started.workflow_id, request(started), d3b.dependencies);
    check('19b_overlapping_open_debt_blocks_receipt', result.repair.eligibility.reason === 'overlapping_open_debt' && result.repair.kvr_id === null && result.repair.eligibility.blocking_lifecycle_ids.includes('LC-overlap0000000'));
  } finally { fs.rmSync(f3b.root, { recursive: true, force: true }); }

  const f4 = fixture('protected'); const d4 = deps({ finding: { requires_dedicated_review: true } });
  try {
    const started = begin(f4.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d4.dependencies);
    const result = finish(f4.context, started.workflow_id, request(started), d4.dependencies);
    check('20_protected_finding_not_auto_repaired', result.repair.eligibility.reason === 'protected_or_confirmation_required');
  } finally { fs.rmSync(f4.root, { recursive: true, force: true }); }

  const f5 = fixture('generated'); const d5 = deps({ repairClass: 'rebuild_generated_artifact' });
  try {
    const started = begin(f5.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d5.dependencies);
    const result = finish(f5.context, started.workflow_id, request(started), d5.dependencies);
    check('21_generated_repair_not_auto_applied', /repair_class_/.test(result.repair.eligibility.reason));
  } finally { fs.rmSync(f5.root, { recursive: true, force: true }); }

  const f6 = fixture('missingartifact'); const d6 = deps({ finding: { artifact: 'src/missing.js', affected_artifacts: ['src/missing.js'] } });
  try {
    const started = begin(f6.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d6.dependencies);
    const result = finish(f6.context, started.workflow_id, request(started), d6.dependencies);
    check('22_unverified_artifact_blocks_repair', result.repair.eligibility.reason === 'affected_artifacts_not_fully_verified');
  } finally { fs.rmSync(f6.root, { recursive: true, force: true }); }

  const f7 = fixture('verifyfail'); const d7 = deps({ verifyFail: true });
  try {
    const started = begin(f7.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d7.dependencies);
    expectCode('23_failed_primary_verification_blocks_finish', () => finish(f7.context, started.workflow_id, request(started), d7.dependencies), 'agent_task_primary_verification_failed');
    check('24_failed_verification_creates_no_receipt', d7.calls.filter((x) => x.tool === 'repair-on-touch.js' && x.args[0] === 'receipt').length === 0);
  } finally { fs.rmSync(f7.root, { recursive: true, force: true }); }

  const f8 = fixture('unsustained'); const d8 = deps({ unsustained: true });
  try {
    const started = begin(f8.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d8.dependencies);
    const result = finish(f8.context, started.workflow_id, request(started), d8.dependencies);
    check('25_unsustained_repair_not_claimed_closed', result.repair.status === 'not_sustained_or_not_applied' && result.repair.closed_count === 0);
  } finally { fs.rmSync(f8.root, { recursive: true, force: true }); }

  const f9 = fixture('invalid'); const d9 = deps({ selected: 0 });
  try {
    const started = begin(f9.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d9.dependencies);
    expectCode('26_malformed_finish_request_rejected', () => finish(f9.context, started.workflow_id, null, d9.dependencies), 'agent_task_finish_request_invalid');
    expectCode('27_first_read_sha_required', () => finish(f9.context, started.workflow_id, request(started, { route_first_read_sha256: '0'.repeat(64) }), d9.dependencies), 'agent_task_first_read_ack_mismatch');
    expectCode('28_traversal_source_rejected', () => finish(f9.context, started.workflow_id, request(started, { source_files: ['../secret'] }), d9.dependencies), 'agent_task_source_path_invalid');
    const outside = path.join(f9.root, 'outside.txt'); fs.writeFileSync(outside, 'x'); const link = path.join(f9.root, 'src', 'link.js');
    try { fs.symlinkSync(outside, link); expectCode('29_symlink_source_rejected', () => finish(f9.context, started.workflow_id, request(started, { source_files: ['src/link.js'] }), d9.dependencies), 'agent_task_source_unsafe'); } catch { checks.push({ id: '29_symlink_source_rejected', pass: true, detail: { unsupported_environment: true } }); }
    const hardlink = path.join(f9.root, 'src', 'hardlink.js');
    try { fs.linkSync(path.join(f9.root, 'src', 'feature.js'), hardlink); expectCode('30_hardlink_source_rejected', () => finish(f9.context, started.workflow_id, request(started, { source_files: ['src/hardlink.js'] }), d9.dependencies), 'agent_task_source_hardlinked'); } catch { checks.push({ id: '30_hardlink_source_rejected', pass: true, detail: { unsupported_environment: true } }); } finally { try { fs.unlinkSync(hardlink); } catch {} }
    expectCode('31_empty_tests_rejected', () => finish(f9.context, started.workflow_id, request(started, { tests_to_run: [] }), d9.dependencies), 'agent_task_tests_required');
    expectCode('32_invalid_timeout_rejected', () => finish(f9.context, started.workflow_id, request(started, { tests_to_run: [{ argv: ['node'], cwd: '.', timeout_ms: 9999999 }] }), d9.dependencies), 'agent_task_test_timeout_invalid');

    const safeRequestFile = path.join(f9.root, 'safe-finish-request.json');
    fs.writeFileSync(safeRequestFile, `${JSON.stringify(request(started), null, 2)}\n`);
    check(
      '32a_repo_relative_request_file_is_accepted',
      agentTaskCli.__test.readRequest(f9.context, 'safe-finish-request.json').route_first_read_sha256 === started.route.first_read.sha256
    );
    const outsideRequestFile = path.join(os.tmpdir(), `agent-task-outside-${crypto.randomBytes(8).toString('hex')}.json`);
    fs.writeFileSync(outsideRequestFile, '{}\n');
    try {
      expectCode(
        '32b_request_path_escape_is_rejected',
        () => agentTaskCli.__test.readRequest(f9.context, outsideRequestFile),
        'agent_task_request_path_escape'
      );
    } finally {
      try { fs.unlinkSync(outsideRequestFile); } catch {}
    }

    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-task-cwd-outside-'));
    const cwdLink = path.join(f9.root, 'cwd-link');
    try {
      fs.symlinkSync(outsideDir, cwdLink, process.platform === 'win32' ? 'junction' : 'dir');
      expectCode(
        '32c_symlink_or_junction_test_cwd_is_rejected',
        () => finish(
          f9.context,
          started.workflow_id,
          request(started, {
            tests_to_run: [{ argv: ['node', 'tests/feature.test.js'], cwd: 'cwd-link', timeout_ms: 10000 }]
          }),
          d9.dependencies
        ),
        'agent_task_test_cwd_unsafe'
      );
    } catch (cause) {
      if (cause.code === 'agent_task_test_cwd_unsafe') throw cause;
      checks.push({
        id: '32c_symlink_or_junction_test_cwd_is_rejected',
        pass: true,
        detail: { unsupported_environment: true, reason: cause.code || cause.message }
      });
    } finally {
      try { fs.rmSync(cwdLink, { recursive: true, force: true }); } catch {}
      try { fs.rmSync(outsideDir, { recursive: true, force: true }); } catch {}
    }

    const requestLink = path.join(f9.root, 'request-link.json');
    try {
      fs.symlinkSync(safeRequestFile, requestLink);
      expectCode(
        '32d_symlink_request_file_is_rejected',
        () => agentTaskCli.__test.readRequest(f9.context, 'request-link.json'),
        'agent_task_request_unsafe'
      );
    } catch (cause) {
      if (cause.code === 'agent_task_request_unsafe') throw cause;
      checks.push({
        id: '32d_symlink_request_file_is_rejected',
        pass: true,
        detail: { unsupported_environment: true, reason: cause.code || cause.message }
      });
    } finally {
      try { fs.unlinkSync(requestLink); } catch {}
    }
  } finally { fs.rmSync(f9.root, { recursive: true, force: true }); }

  const f9b = fixture('route-pointer'); const d9b = deps({ selected: 0 });
  try {
    const started = begin(f9b.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d9b.dependencies);
    expectCode(
      '27a_replaced_snapshot_blocks_finish_before_side_effects',
      () => finish(f9b.context, started.workflow_id, request(started), {
        ...d9b.dependencies,
        resolveEffectiveTaskRoutingState: () => ({ current_status: 'current', snapshot_hash: 'c'.repeat(64), effective_claim_eligible: true })
      }),
      'agent_task_route_snapshot_replaced'
    );
    expectCode(
      '27b_stale_route_blocks_finish_before_side_effects',
      () => finish(f9b.context, started.workflow_id, request(started), {
        ...d9b.dependencies,
        resolveEffectiveTaskRoutingState: () => ({ current_status: 'stale', snapshot_hash: 'b'.repeat(64), effective_claim_eligible: false })
      }),
      'agent_task_route_not_current'
    );
  } finally { fs.rmSync(f9b.root, { recursive: true, force: true }); }

  const f10 = fixture('reconcile'); const d10 = deps({ selected: 0 });
  try {
    const started = begin(f10.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d10.dependencies);
    const wfPath = path.join(f10.context.stateRoot, 'sessions', 'task-workflows', `${started.workflow_id}.json`);
    const wf = JSON.parse(fs.readFileSync(wfPath, 'utf8'));
    wf.finish = { request_sha256: __test.digest(__test.normalizedFinishRequest(f10.context, request(started))), phases: { verification: { status: 'running', started_at: new Date().toISOString() } } };
    wf.status = 'finishing'; fs.writeFileSync(wfPath, `${JSON.stringify(wf, null, 2)}\n`);
    expectCode('33_unknown_phase_outcome_blocks_replay', () => finish(f10.context, started.workflow_id, request(started), d10.dependencies), 'agent_task_finish_reconciliation_required');
  } finally { fs.rmSync(f10.root, { recursive: true, force: true }); }

  const f11 = fixture('release-order'); const d11 = deps();
  try {
    const started = begin(f11.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d11.dependencies);
    const result = finish(f11.context, started.workflow_id, request(started, { run_release_flow: true }), d11.dependencies);
    const flowIndex = d11.calls.findIndex((x) => x.tool === 'flow.js');
    const planIndex = d11.calls.findIndex((x) => x.tool === 'repair-on-touch.js' && x.args[0] === 'plan');
    const applyIndex = d11.calls.findIndex((x) => x.tool === 'repair-on-touch.js' && x.args[0] === 'apply');
    check('34_release_flow_precedes_repair_planning', flowIndex >= 0 && planIndex > flowIndex && applyIndex > planIndex, { flowIndex, planIndex, applyIndex });
    check('35_release_flow_is_bound_to_result', result.release_flow.status === 'ok' && result.repair.status === 'applied');
  } finally { fs.rmSync(f11.root, { recursive: true, force: true }); }

  const f12 = fixture('release-failure'); const d12 = deps({ releaseFail: true });
  try {
    const started = begin(f12.context, { task: 'change feature', modules: ['feature'], paths: ['src/'] }, d12.dependencies);
    const result = finish(f12.context, started.workflow_id, request(started, { run_release_flow: true }), d12.dependencies);
    check('35a_optional_release_failure_preserves_primary_result', result.status === 'completed_with_warnings' && result.primary_verification.status === 'pass' && result.repair.eligibility.reason === 'release_flow_failed_before_repair');
    check('35b_optional_release_failure_is_reported', result.release_flow.status === 'failed' && result.release_flow.exit_code === 2);
  } finally { fs.rmSync(f12.root, { recursive: true, force: true }); }

  const f13 = fixture('physical-nested-lock');
  try {
    fs.writeFileSync(path.join(f13.root, 'tests', 'slow.test.js'), 'setTimeout(() => process.exit(0), 1200);\n');
    fs.mkdirSync(path.join(f13.context.projectKnowledgeRoot, 'modules'), { recursive: true });
    fs.mkdirSync(path.join(f13.context.stateRoot, 'maintenance'), { recursive: true });
    fs.mkdirSync(path.join(f13.context.stateRoot, 'maps'), { recursive: true });
    fs.writeFileSync(path.join(f13.context.projectKnowledgeRoot, 'modules', 'feature.json'), `${JSON.stringify({
      module_id: 'feature', current_trust_level: 'trusted', target_trust_level: 'trusted', verification_status: 'verified',
      key_files: ['src/feature.js'], evidence_files: [], dependencies: []
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(f13.context.projectKnowledgeRoot, 'modules', 'module_registry.json'), `${JSON.stringify({ modules: [{
      module_id: 'feature', path: 'src/feature.js', card: '.knowledge/modules/feature.json', purpose: 'physical nested lock regression',
      key_files: ['src/feature.js'], evidence_files: [], dependencies: []
    }] }, null, 2)}\n`);
    fs.writeFileSync(path.join(f13.context.projectKnowledgeRoot, 'project_index.json'), `${JSON.stringify({ project_name: 'physical-nested-lock', modules: [{ module_id: 'feature', card: '.knowledge/modules/feature.json', confidence: 'high' }] }, null, 2)}\n`);
    fs.writeFileSync(path.join(f13.context.stateRoot, 'freshness.json'), `${JSON.stringify({ tracked_files: [], artifact_statuses: {} }, null, 2)}\n`);
    fs.writeFileSync(path.join(f13.context.stateRoot, 'maintenance', 'trust_report.json'), `${JSON.stringify({
      generated_at: new Date().toISOString(), modules_total: 1, modules_low_confidence: 0,
      modules: { trusted: ['feature'], near_trusted: [], routing_trusted: [], advisory_only: [], suspect: [], low_confidence: [] },
      module_statuses: [{ module_id: 'feature', trust_status: 'trusted', freshness_status: 'fresh', confidence: 'high', reasons: {} }]
    }, null, 2)}\n`);
    fs.writeFileSync(path.join(f13.context.stateRoot, 'maintenance', 'stale_items.json'), '{"items":[]}\n');
    fs.writeFileSync(path.join(f13.context.stateRoot, 'maintenance', 'repair_queue.json'), '{"queue":[]}\n');
    fs.writeFileSync(path.join(f13.context.stateRoot, 'maps', 'critical_paths.json'), '{"paths":[]}\n');
    fs.writeFileSync(path.join(f13.context.stateRoot, 'maps', 'file_criticality.json'), '{"files":[]}\n');
    const physicalStarted = begin(f13.context, { task: 'physically verify feature', modules: ['feature'], paths: ['src/feature.js'] }, {
      doctor: doctor(100, 100)
    });
    const physicalRequest = request(physicalStarted, {
      tests_to_run: [{ argv: ['node', 'tests/slow.test.js'], cwd: '.', timeout_ms: 10000 }]
    });
    const requestFile = path.join(f13.root, 'finish.json');
    fs.writeFileSync(requestFile, `${JSON.stringify(physicalRequest, null, 2)}\n`);
    const runnerFile = path.join(f13.root, 'concurrent-runner.js');
    const cli = path.join(f13.context.systemRoot, 'tools', 'agent-task.js');
    const common = [
      cli, 'finish', `--workflow-id=${physicalStarted.workflow_id}`, `--request=${requestFile}`, '--json',
      '--system-root', f13.context.systemRoot, '--target-root', f13.root,
      '--project-knowledge-root', f13.context.projectKnowledgeRoot, '--state-root', f13.context.stateRoot
    ];
    fs.writeFileSync(runnerFile, `
      const { spawn } = require('child_process');
      const args = ${JSON.stringify(common)};
      const env = { ...process.env, CI: 'true', KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1', KNOWLEDGE_AGENT_ID: 'agent-task-physical-concurrency' };
      function launch(delay) { return new Promise((resolve) => setTimeout(() => {
        const child = spawn(process.execPath, args, { cwd: ${JSON.stringify(f13.root)}, env, windowsHide: true });
        let stdout = '', stderr = '';
        child.stdout.on('data', (chunk) => { stdout += chunk; });
        child.stderr.on('data', (chunk) => { stderr += chunk; });
        child.on('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
      }, delay)); }
      Promise.all([launch(0), launch(100)]).then((runs) => process.stdout.write(JSON.stringify(runs)));
    `);
    const concurrency = require('child_process').spawnSync(process.execPath, [runnerFile], {
      cwd: f13.root, encoding: 'utf8', timeout: 60000, windowsHide: true,
      env: { ...process.env, CI: 'true', KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' }
    });
    check('36_physical_concurrent_runner_exits', concurrency.status === 0, { status: concurrency.status, stderr: concurrency.stderr });
    const runs = JSON.parse(concurrency.stdout || '[]');
    const parsedRuns = runs.map((item) => {
      let body = null; try { body = JSON.parse(item.stdout || '{}'); } catch {}
      return { ...item, body };
    });
    const completedRuns = parsedRuns.filter((item) => item.code === 0 && item.body?.status === 'completed');
    const inProgressRuns = parsedRuns.filter((item) => item.code === 2 && item.body?.error?.code === 'agent_task_finish_in_progress');
    check('37_exactly_one_physical_finish_executes', completedRuns.length === 1 && inProgressRuns.length === 1, parsedRuns);
    const idempotent = require('child_process').spawnSync(process.execPath, common, {
      cwd: f13.root, encoding: 'utf8', timeout: 60000, windowsHide: true,
      env: { ...process.env, CI: 'true', KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1', KNOWLEDGE_AGENT_ID: 'agent-task-physical-idempotent' }
    });
    const idempotentBody = JSON.parse(idempotent.stdout || '{}');
    check('38_physical_finish_replay_is_idempotent', idempotent.status === 0 && idempotentBody.status === 'completed' && idempotentBody.workflow_id === physicalStarted.workflow_id, { status: idempotent.status, body: idempotentBody });
    check('39_physical_verification_executes_once', idempotentBody.primary_verification?.execution_count === 1 && idempotentBody.repair?.duplicate_test_executions === 0, idempotentBody.primary_verification);
    const lockDir = path.join(f13.context.stateRoot, 'locks', 'v1', 'agent-task.lock');
    check('40_physical_agent_task_lock_is_released', !fs.existsSync(lockDir), { lockDir });
  } finally { fs.rmSync(f13.root, { recursive: true, force: true }); }

  check('41_provider_usage_unavailable_without_receipt', __test.providerUsage(null).status === 'unavailable');
  check('42_provider_usage_requires_receipt', __test.providerUsage({ input_tokens: 10 }).status === 'unavailable');
  check('43_provider_usage_accepts_actual_receipt', __test.providerUsage({ receipt_id: 'provider-1', provider: 'x', input_tokens: 10, output_tokens: 5 }).status === 'provider_reported');
  const teamContextArgs = __test.contextFlags({
    mode: 'team',
    systemRoot: '/system',
    targetRoot: '/target',
    projectKnowledgeRoot: '/target/.knowledge',
    stateRoot: '/team/state',
    teamRoot: '/team',
    workspaceId: 'workspace-1',
    agentId: 'agent-1'
  });
  check('39_team_context_does_not_collide_with_repair_mode_flag',
    !teamContextArgs.includes('--mode') &&
    teamContextArgs.includes('--team-root') &&
    teamContextArgs.includes('--workspace-id') &&
    teamContextArgs.includes('--agent-id'),
  teamContextArgs);
  const publicTeamRoot = path.join(os.tmpdir(), 'agent-task-public-team');
  const publicTargetRoot = path.join(os.tmpdir(), 'agent-task-public-target');
  const publicContext = {
    mode: 'team', systemRoot: path.join(publicTargetRoot, '.knowledge'),
    targetRoot: publicTargetRoot, projectKnowledgeRoot: path.join(publicTargetRoot, '.knowledge'),
    stateRoot: path.join(publicTeamRoot, 'state'), teamRoot: publicTeamRoot,
    workspaceId: 'workspace-1', agentId: 'agent-1'
  };
  const rawRequestPath = path.join(publicContext.stateRoot, 'sessions', 'task-workflows', 'requests', 'request.json');
  const publicCommand = __test.publicCommandRecord(publicContext, {
    tool: 'repair-on-touch.js', args: ['verify', '--request', rawRequestPath], exit_code: 0
  });
  check('45_team_command_record_uses_relative_state_path',
    !JSON.stringify(publicCommand).includes(publicContext.stateRoot) &&
    publicCommand.args[2] === 'state/sessions/task-workflows/requests/request.json',
  publicCommand);
  const publicRelease = __test.publicReleaseFlow(publicContext, {
    status: 'ok', target_root: publicTargetRoot,
    project_knowledge_root: publicContext.projectKnowledgeRoot,
    state_root: publicContext.stateRoot,
    command: { tool: 'flow.js', args: ['release', rawRequestPath], exit_code: 0 }
  });
  check('46_team_release_result_redacts_absolute_roots',
    publicRelease.target_root === '.' && publicRelease.project_knowledge_root === '.knowledge' &&
    publicRelease.state_root === '<team-state>' &&
    !JSON.stringify(publicRelease).includes(publicTeamRoot) &&
    !JSON.stringify(publicRelease).includes(publicTargetRoot),
  publicRelease);
  const systemRoot = path.resolve(__dirname, '..');
  const sharedRouting = fs.readFileSync(path.join(systemRoot, 'agent-integrations', '_shared', 'trust-routing.md'), 'utf8');
  check('40_shared_bridge_requires_agent_task_begin_finish', /agent-task\.js begin/.test(sharedRouting) && /agent-task\.js finish/.test(sharedRouting));
  const templatedBridges = [
    'agent-integrations/codex/AGENTS.md',
    'agent-integrations/claude/CLAUDE.md',
    'agent-integrations/gemini/GEMINI.md',
    'agent-integrations/copilot/copilot-instructions.md',
    'agent-integrations/continue/rules/knowledge.md',
    'agent-integrations/roo/rules/knowledge.md',
    'agent-integrations/aider/CONVENTIONS.md'
  ];
  check('41_runtime_bridges_embed_shared_task_contract', templatedBridges.every((rel) => fs.readFileSync(path.join(systemRoot, rel), 'utf8').includes('{{TRUST_ROUTING}}')), templatedBridges);
  const openCodeTask = fs.readFileSync(path.join(systemRoot, 'agent-integrations', 'opencode', 'commands', 'kb-task.md'), 'utf8');
  check('42_opencode_exposes_agent_task_command', /agent-task\.js begin/.test(openCodeTask) && /agent-task\.js finish/.test(openCodeTask));
  const vendorBridges = ['agent-integrations/devin/rules/knowledge.rules', 'agent-integrations/windsurf/rules/knowledge.md'];
  check('43_vendor_specific_bridges_require_integrated_task_entrypoint', vendorBridges.every((rel) => {
    const body = fs.readFileSync(path.join(systemRoot, rel), 'utf8');
    return /agent-task\.js begin/.test(body) && /agent-task\.js finish/.test(body);
  }), vendorBridges);
  const metricsContract = fs.readFileSync(path.join(systemRoot, 'agent-integrations', '_shared', 'metrics-reporting.md'), 'utf8');
  check('44_final_reporting_uses_committed_agent_task_result', /agent-task\.js finish/.test(metricsContract) && /completed_with_warnings/.test(metricsContract));
  console.log(JSON.stringify({ schema_version: 'knowledge-agent-task-self-test.v1', product_version: systemVersion(), status: 'pass', checks_total: checks.length, passed: checks.length, failed: 0, checks }, null, 2));
}
try { run(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
