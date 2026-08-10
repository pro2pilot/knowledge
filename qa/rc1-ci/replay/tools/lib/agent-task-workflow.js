'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  ensureContainedDir,
  readJson,
  writeJsonAtomicContained,
  writeFileAtomicContained,
  normalizeRelative,
  containedPath,
  getAgentId
} = require('./json-store');
const { contextEnv } = require('./path-context');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');
const routing = require('./task-routing');
const { resolveEffectiveTaskRoutingState, formatTaskRoutingEstimate } = require('./task-routing-state');
const { systemVersion } = require('./system-version');

const WORKFLOW_SCHEMA = 'knowledge-agent-task-workflow.v1';
const RESULT_SCHEMA = 'knowledge-agent-task-result.v1';
const REQUEST_SCHEMA = 'knowledge-agent-task-finish-request.v1';
const ACK_SCHEMA = 'knowledge-agent-task-first-read-acknowledgement.v1';
const DISCLAIMER = 'This is a deterministic local first-read context estimate, not provider-reported model-token usage.';
const PHASES = Object.freeze([
  'flow_release',
  'doctor_pre_repair',
  'repair_plan',
  'verification',
  'repair_receipt',
  'repair_apply',
  'doctor_after',
  'repair_status',
  'session_finish'
]);

function now() { return new Date().toISOString(); }
function sha(value) {
  return crypto.createHash('sha256').update(Buffer.isBuffer(value) ? value : String(value)).digest('hex');
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}
function digest(value) { return sha(JSON.stringify(canonical(value))); }
function error(code, message, detail = null) {
  const out = new Error(message); out.code = code; if (detail !== null) out.detail = detail; return out;
}
function relativeInside(root, absolute) {
  const rel = path.relative(path.resolve(root), path.resolve(absolute)).replace(/\\/g, '/');
  return rel && rel !== '..' && !rel.startsWith('../') && !path.isAbsolute(rel) ? rel : null;
}
function publicPathArgument(context, value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) return value;
  const stateRelative = relativeInside(context.stateRoot, value);
  if (stateRelative) return `state/${stateRelative}`;
  const projectRelative = relativeInside(context.projectKnowledgeRoot, value);
  if (projectRelative) return `.knowledge/${projectRelative}`;
  const targetRelative = relativeInside(context.targetRoot, value);
  if (targetRelative) return targetRelative;
  const systemRelative = relativeInside(context.systemRoot, value);
  if (systemRelative) return `.knowledge/${systemRelative}`;
  return '<local-path>';
}
function publicCommandRecord(context, record) {
  if (!record || typeof record !== 'object') return record || null;
  return {
    ...record,
    args: Array.isArray(record.args)
      ? record.args.map((value) => publicPathArgument(context, value))
      : []
  };
}
function publicReleaseFlow(context, release) {
  if (!release || typeof release !== 'object') return release || null;
  const out = { ...release };
  if (Object.prototype.hasOwnProperty.call(out, 'target_root')) out.target_root = '.';
  if (Object.prototype.hasOwnProperty.call(out, 'project_knowledge_root')) out.project_knowledge_root = '.knowledge';
  if (Object.prototype.hasOwnProperty.call(out, 'state_root')) out.state_root = context.mode === 'team' ? '<team-state>' : '.knowledge';
  if (out.command) out.command = publicCommandRecord(context, out.command);
  return out;
}
function workflowsRoot(context, create = false) {
  const root = path.join(context.stateRoot, 'sessions', 'task-workflows');
  if (create) ensureContainedDir(context.stateRoot, root);
  return root;
}
function workflowPath(context, workflowId) {
  if (!/^ATW-[a-f0-9]{64}$/.test(String(workflowId || ''))) {
    throw error('agent_task_workflow_id_invalid', 'Workflow ID must be ATW- followed by a canonical SHA-256 hash.');
  }
  return path.join(workflowsRoot(context, true), `${workflowId}.json`);
}
function resultPath(context, workflowId) { return path.join(workflowsRoot(context, true), `${workflowId}.result.json`); }
function summaryPath(context, workflowId) { return path.join(workflowsRoot(context, true), `${workflowId}.summary.md`); }
function acknowledgementPath(context, workflowId) {
  return path.join(workflowsRoot(context, true), `${workflowId}.first-read-ack.json`);
}
function requestPath(context, workflowId, phase) {
  const root = path.join(workflowsRoot(context, true), 'requests');
  ensureContainedDir(context.stateRoot, root);
  return path.join(root, `${workflowId}.${phase}.json`);
}
function lockRequest(context) {
  return {
    context,
    rootKind: 'state',
    rootPath: context.stateRoot,
    lockName: 'agent-task',
    purpose: LOCKS['agent-task'].purpose
  };
}
function save(context, workflow) {
  workflow.updated_at = now();
  writeJsonAtomicContained(workflowPath(context, workflow.workflow_id), workflow, context.stateRoot);
  return workflow;
}
function load(context, workflowId) {
  const file = workflowPath(context, workflowId);
  const value = readJson(file, null);
  if (!value || value.schema_version !== WORKFLOW_SCHEMA || value.workflow_id !== workflowId) {
    throw error('agent_task_workflow_not_found', `Agent-task workflow not found: ${workflowId}`);
  }
  return value;
}
function cleanArray(value) { return [...new Set((Array.isArray(value) ? value : value ? [value] : []).map(String).map((v) => v.trim()).filter(Boolean))]; }
function contextFlags(context) {
  const args = [
    '--system-root', context.systemRoot,
    '--target-root', context.targetRoot,
    '--project-knowledge-root', context.projectKnowledgeRoot,
    '--state-root', context.stateRoot
  ];
  if (context.mode === 'team') {
    // Team context is inferred from team-root/workspace-id. Do not pass
    // `--mode=team`: repair-on-touch reserves --mode for its repair policy.
    args.push('--team-root', context.teamRoot, '--workspace-id', context.workspaceId, '--agent-id', context.agentId || getAgentId());
  }
  return args;
}
function parseJsonOutput(stdout, tool) {
  const text = String(stdout || '').trim();
  if (!text) throw error('agent_task_tool_output_empty', `${tool} returned empty stdout.`);
  try { return JSON.parse(text.replace(/^\uFEFF/, '')); }
  catch (cause) { throw error('agent_task_tool_output_invalid', `${tool} returned invalid JSON.`, { stdout: text.slice(-1000), cause: cause.message }); }
}
function runTool(context, tool, args = [], options = {}) {
  const toolPath = path.join(context.systemRoot, 'tools', tool);
  if (!fs.existsSync(toolPath)) throw error('agent_task_tool_missing', `Required tool is missing: tools/${tool}`);
  const started = process.hrtime.bigint();
  const child = spawnSync(process.execPath, [toolPath, ...args, ...contextFlags(context)], {
    cwd: context.targetRoot,
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 600000,
    maxBuffer: options.maxBuffer || 32 * 1024 * 1024,
    env: contextEnv(context, {
      KNOWLEDGE_AGENT_ID: context.agentId || process.env.KNOWLEDGE_AGENT_ID || 'agent-task-workflow',
      KNOWLEDGE_SESSION_ID: options.sessionId || process.env.KNOWLEDGE_SESSION_ID || ''
    })
  });
  const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
  const record = {
    tool,
    args,
    exit_code: child.status,
    signal: child.signal || null,
    duration_ms: Math.round(durationMs * 1000) / 1000,
    stdout_sha256: sha(child.stdout || ''),
    stderr_sha256: sha(child.stderr || ''),
    stdout_bytes: Buffer.byteLength(child.stdout || ''),
    stderr_bytes: Buffer.byteLength(child.stderr || '')
  };
  if (child.error) throw error('agent_task_tool_spawn_failed', `${tool} failed to start: ${child.error.message}`, record);
  let output = null;
  if (options.expectJson !== false && String(child.stdout || '').trim()) {
    try { output = parseJsonOutput(child.stdout, tool); }
    catch (parseError) {
      if (child.status === 0) throw parseError;
    }
  }
  if (child.status !== 0 && options.allowNonzero !== true) {
    throw error('agent_task_tool_failed', `${tool} exited with code ${child.status}.`, { ...record, output, stderr: String(child.stderr || '').slice(-2000) });
  }
  return { record, output, stdout: child.stdout || '', stderr: child.stderr || '' };
}
function writeRequest(context, workflowId, phase, body) {
  const file = requestPath(context, workflowId, phase);
  writeJsonAtomicContained(file, body, context.stateRoot);
  return file;
}
function doctor(context, workflowId, label) {
  const run = runTool(context, 'doctor.js', ['--quiet'], { expectJson: false, sessionId: workflowId });
  const reportPath = path.join(context.stateRoot, 'maintenance', 'quality_report.json');
  const report = readJson(reportPath, null);
  if (!report) throw error('agent_task_doctor_missing', 'Doctor did not create maintenance/quality_report.json.');
  return {
    label,
    quality_score: report.quality_score ?? null,
    status: report.status || null,
    structural_status: report.structural_status || null,
    task_readiness: report.task_readiness || null,
    generated_at: report.generated_at || null,
    report_path: relativeInside(context.stateRoot, reportPath),
    command: run.record
  };
}
function taskRoute(context, input) {
  const created = routing.create(context, {
    task: input.task,
    taskClass: input.taskClass || null,
    modules: cleanArray(input.modules),
    paths: cleanArray(input.paths),
    excludeModules: cleanArray(input.excludeModules),
    excludePaths: cleanArray(input.excludePaths),
    scopeSource: input.scopeSource || 'explicit',
    constraints: cleanArray(input.constraints)
  });
  const state = resolveEffectiveTaskRoutingState({ context, taskScopeHash: created.task_scope_hash, verifyLiveInputs: true });
  const snapshotRoot = routing.snapshotRoot(context, created.task_scope_hash, created.snapshot_hash);
  const firstReadPath = path.join(snapshotRoot, 'first-read.md');
  const firstRead = fs.readFileSync(firstReadPath, 'utf8');
  const firstReadRel = relativeInside(context.stateRoot, firstReadPath);
  if (!firstReadRel) throw error('agent_task_first_read_unsafe', 'Task first-read path escaped stateRoot.');
  return {
    task_scope_hash: created.task_scope_hash,
    snapshot_hash: created.snapshot_hash,
    routing_snapshot_hash: created.routing_snapshot_hash,
    baseline_hash: created.baseline_hash,
    metrics_comparison_hash: created.metrics_comparison_hash,
    scope: created.scope,
    state,
    public_estimate: formatTaskRoutingEstimate(state.metrics || {}, state),
    disclaimer: DISCLAIMER,
    first_read: {
      path: firstReadRel,
      sha256: sha(Buffer.from(firstRead, 'utf8')),
      bytes: Buffer.byteLength(firstRead, 'utf8'),
      content: firstRead
    }
  };
}
function routeModules(route) {
  const selected = cleanArray(route?.state?.bundle?.selected_modules);
  const direct = cleanArray(route?.scope?.modules);
  return { selected, direct, dependencies: selected.filter((id) => !direct.includes(id)) };
}
function safeFile(context, input, options = {}) {
  const rel = normalizeRelative(input);
  if (!rel || path.isAbsolute(rel) || rel.split('/').includes('..') || rel.includes('\0')) {
    throw error('agent_task_source_path_invalid', `Unsafe relative path: ${String(input)}`);
  }
  const absolute = path.resolve(context.targetRoot, rel);
  if (!containedPath(context.targetRoot, absolute)) throw error('agent_task_source_path_escape', `Path escapes target root: ${rel}`);
  let stat;
  try { stat = fs.lstatSync(absolute); } catch { throw error('agent_task_source_missing', `Required source/evidence file is missing: ${rel}`); }
  if (!stat.isFile() || stat.isSymbolicLink()) throw error('agent_task_source_unsafe', `Source/evidence path must be a regular non-symlink file: ${rel}`);
  if (Number(stat.nlink || 1) > 1) throw error('agent_task_source_hardlinked', `Hardlinked source/evidence file is rejected: ${rel}`);
  const real = fs.realpathSync(absolute);
  if (!containedPath(fs.realpathSync(context.targetRoot), real)) throw error('agent_task_source_escape', `Physical source/evidence path escapes target root: ${rel}`);
  const body = fs.readFileSync(absolute);
  if (options.maxBytes && body.length > options.maxBytes) throw error('agent_task_source_oversized', `Source/evidence file exceeds ${options.maxBytes} bytes: ${rel}`);
  return { path: rel, absolute, bytes: body.length, sha256: sha(body) };
}
function normalizeTests(context, tests) {
  if (!Array.isArray(tests) || !tests.length) throw error('agent_task_tests_required', 'At least one physical verification command is required.');
  return tests.map((item, index) => {
    if (!item || !Array.isArray(item.argv) || !item.argv.length || item.argv.some((part) => typeof part !== 'string' || !part.length)) {
      throw error('agent_task_test_invalid', `Test ${index + 1} requires a non-empty argv string array.`);
    }
    const cwd = normalizeRelative(item.cwd || '.');
    const absoluteCwd = path.resolve(context.targetRoot, cwd);
    if (!containedPath(context.targetRoot, absoluteCwd) || !fs.existsSync(absoluteCwd)) {
      throw error('agent_task_test_cwd_invalid', `Test ${index + 1} cwd is missing or outside target root.`);
    }
    const cwdStat = fs.lstatSync(absoluteCwd);
    if (!cwdStat.isDirectory() || cwdStat.isSymbolicLink()) {
      throw error('agent_task_test_cwd_unsafe', `Test ${index + 1} cwd must be a real directory inside target root.`);
    }
    const physicalTarget = fs.realpathSync(context.targetRoot);
    const physicalCwd = fs.realpathSync(absoluteCwd);
    if (!containedPath(physicalTarget, physicalCwd)) {
      throw error('agent_task_test_cwd_escape', `Test ${index + 1} cwd resolves outside target root.`);
    }
    const timeoutMs = Number(item.timeout_ms || 120000);
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) throw error('agent_task_test_timeout_invalid', `Test ${index + 1} timeout is invalid.`);
    return { argv: item.argv, cwd, timeout_ms: Math.trunc(timeoutMs) };
  });
}
function normalizedFinishRequest(context, request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw error('agent_task_finish_request_invalid', 'Finish request must be a JSON object.');
  const sourceFiles = cleanArray(request.source_files || request.source_files_checked);
  if (!sourceFiles.length) throw error('agent_task_sources_required', 'Finish request requires source_files.');
  const sourceSnapshot = sourceFiles.map((file) => safeFile(context, file, { maxBytes: 32 * 1024 * 1024 }));
  const changedFiles = cleanArray(request.changed_files || sourceFiles);
  for (const file of changedFiles) safeFile(context, file, { maxBytes: 32 * 1024 * 1024 });
  return {
    schema_version: REQUEST_SCHEMA,
    route_first_read_sha256: String(request.route_first_read_sha256 || '').toLowerCase(),
    source_files: sourceSnapshot.map((item) => item.path),
    source_snapshot: sourceSnapshot.map(({ path: p, bytes, sha256 }) => ({ path: p, bytes, sha256 })),
    changed_files: changedFiles,
    tests_to_run: normalizeTests(context, request.tests_to_run || request.tests),
    primary_outcome: String(request.primary_outcome || 'completed'),
    primary_summary: String(request.primary_summary || '').slice(0, 2000),
    run_release_flow: request.run_release_flow === true,
    provider_usage: request.provider_usage || null
  };
}
function finishOwner() {
  return {
    pid: process.pid,
    hostname: os.hostname(),
    nonce: crypto.randomBytes(16).toString('hex'),
    acquired_at: now()
  };
}
function sameOwner(left, right) {
  return Boolean(left && right &&
    Number(left.pid) === Number(right.pid) &&
    String(left.hostname || '').toLowerCase() === String(right.hostname || '').toLowerCase() &&
    String(left.nonce || '') === String(right.nonce || ''));
}
function ownerLiveness(owner) {
  if (!owner || !Number.isInteger(Number(owner.pid)) || Number(owner.pid) < 1) return false;
  if (String(owner.hostname || '').toLowerCase() !== os.hostname().toLowerCase()) return null;
  try {
    process.kill(Number(owner.pid), 0);
    return true;
  } catch (cause) {
    if (cause.code === 'ESRCH') return false;
    if (cause.code === 'EPERM') return true;
    return null;
  }
}
function runningPhase(workflow) {
  return Object.entries(workflow?.finish?.phases || {})
    .find(([, value]) => value?.status === 'running') || null;
}
function assertActiveOwner(workflow, owner) {
  if (!sameOwner(workflow?.finish?.active_owner, owner)) {
    throw error('agent_task_finish_owner_changed', 'Agent-task finish ownership changed before the phase could be committed.');
  }
}
function prepareFinish(context, workflowId, request, requestHash) {
  const owner = finishOwner();
  return withContainedLock(lockRequest(context), () => {
    const workflow = load(context, workflowId);
    if (workflow.status === 'completed') {
      if (workflow.finish?.request_sha256 !== requestHash) {
        throw error('agent_task_finish_request_changed', 'Workflow is complete and the finish request differs from the committed request.');
      }
      return { completed: true, result: readJson(resultPath(context, workflowId), workflow.finish.result) };
    }
    if (workflow.finish?.request_sha256 && workflow.finish.request_sha256 !== requestHash) {
      throw error('agent_task_finish_request_changed', 'A different finish request is already bound to this workflow.');
    }
    if (request.route_first_read_sha256 !== workflow.route.first_read.sha256) {
      throw error('agent_task_first_read_ack_mismatch', 'Finish request must acknowledge the exact begin-time first-read SHA-256.');
    }
    const active = workflow.finish?.active_owner || null;
    if (active && !sameOwner(active, owner)) {
      const live = ownerLiveness(active);
      const running = runningPhase(workflow);
      if (live === true) {
        throw error('agent_task_finish_in_progress', 'An identical finish operation is already running for this workflow.', { owner: { pid: active.pid, hostname: active.hostname } });
      }
      if (running || live === null) {
        workflow.status = 'reconciliation_required';
        workflow.finish.reconciliation_required = {
          phase: running?.[0] || null,
          reason: running ? 'prior_side_effect_outcome_unknown' : 'prior_finish_owner_liveness_unknown'
        };
        save(context, workflow);
        throw error('agent_task_finish_reconciliation_required', 'A prior finish owner has an unknown side-effect outcome; automatic replay is blocked.');
      }
    }
    const unknown = runningPhase(workflow);
    if (unknown) {
      workflow.status = 'reconciliation_required';
      workflow.finish.reconciliation_required = { phase: unknown[0], reason: 'prior_side_effect_outcome_unknown' };
      save(context, workflow);
      throw error('agent_task_finish_reconciliation_required', `Phase ${unknown[0]} has an unknown prior outcome; automatic replay is blocked.`);
    }
    workflow.status = 'finishing';
    workflow.finish = workflow.finish || { phases: {} };
    workflow.finish.phases = workflow.finish.phases || {};
    workflow.finish.request_sha256 = requestHash;
    workflow.finish.request = request;
    workflow.finish.started_at = workflow.finish.started_at || now();
    workflow.finish.active_owner = owner;
    workflow.finish.reconciliation_required = null;
    save(context, workflow);
    return { completed: false, workflow, owner };
  });
}
function assertBeginSnapshotStillCurrent(context, workflow, routeStateFn) {
  // The primary task may legitimately change live source files after begin.
  // This guard therefore checks the immutable routing pointer only, without
  // recomputing live-input freshness. A replaced or stale task snapshot must
  // stop before request binding, verification, repair or any other side effect.
  const state = routeStateFn({
    context,
    taskScopeHash: workflow.route.task_scope_hash,
    verifyLiveInputs: false
  });
  if (state.current_status !== 'current') {
    throw error('agent_task_route_not_current', 'The begin-time task route is no longer current. Start a new task workflow.', {
      current_status: state.current_status || 'missing'
    });
  }
  if (!state.snapshot_hash || state.snapshot_hash !== workflow.route.snapshot_hash) {
    throw error('agent_task_route_snapshot_replaced', 'The active task snapshot no longer matches the begin-time snapshot. Start a new task workflow.', {
      begin_snapshot_hash: workflow.route.snapshot_hash,
      current_snapshot_hash: state.snapshot_hash || null
    });
  }
  return state;
}
function releaseFinishOwner(context, workflowId, owner, cause = null) {
  try {
    return withContainedLock(lockRequest(context), () => {
      const workflow = load(context, workflowId);
      if (workflow.status === 'completed' || !sameOwner(workflow.finish?.active_owner, owner)) return workflow;
      workflow.finish.active_owner = null;
      if (workflow.status !== 'reconciliation_required') workflow.status = cause ? 'failed' : workflow.status;
      if (cause) {
        workflow.finish.last_error = {
          code: cause.code || 'agent_task_finish_failed',
          message: cause.message,
          at: now()
        };
      }
      save(context, workflow);
      return workflow;
    });
  } catch (cleanupError) {
    if (cause) cause.finish_owner_cleanup_error = cleanupError.code || 'finish_owner_cleanup_failed';
    return null;
  }
}
function runPhase(context, workflowId, owner, name, fn) {
  if (!PHASES.includes(name)) throw error('agent_task_phase_invalid', `Unknown workflow phase: ${name}`);
  const claimed = withContainedLock(lockRequest(context), () => {
    const workflow = load(context, workflowId);
    assertActiveOwner(workflow, owner);
    workflow.finish = workflow.finish || { phases: {} };
    workflow.finish.phases = workflow.finish.phases || {};
    const existing = workflow.finish.phases[name];
    if (existing?.status === 'completed') return { completed: true, result: existing.result };
    if (existing?.status === 'running') {
      workflow.status = 'reconciliation_required';
      workflow.finish.reconciliation_required = { phase: name, reason: 'prior_side_effect_outcome_unknown' };
      workflow.finish.active_owner = null;
      save(context, workflow);
      throw error('agent_task_finish_reconciliation_required', `Phase ${name} has an unknown prior outcome; automatic replay is blocked.`);
    }
    const executionNonce = crypto.randomBytes(16).toString('hex');
    workflow.finish.phases[name] = {
      status: 'running',
      started_at: now(),
      execution_nonce: executionNonce,
      owner: { pid: owner.pid, hostname: owner.hostname, nonce: owner.nonce }
    };
    save(context, workflow);
    return { completed: false, executionNonce };
  });
  if (claimed.completed) return claimed.result;
  try {
    const result = fn();
    return withContainedLock(lockRequest(context), () => {
      const workflow = load(context, workflowId);
      assertActiveOwner(workflow, owner);
      const current = workflow.finish?.phases?.[name];
      if (!current || current.status !== 'running' || current.execution_nonce !== claimed.executionNonce) {
        throw error('agent_task_phase_ownership_changed', `Phase ${name} ownership changed before completion.`);
      }
      workflow.finish.phases[name] = {
        status: 'completed',
        started_at: current.started_at,
        completed_at: now(),
        result
      };
      save(context, workflow);
      return result;
    });
  } catch (cause) {
    try {
      withContainedLock(lockRequest(context), () => {
        const workflow = load(context, workflowId);
        const current = workflow.finish?.phases?.[name];
        if (current?.status === 'running' && current.execution_nonce === claimed.executionNonce) {
          workflow.finish.phases[name] = {
            status: 'failed',
            started_at: current.started_at,
            failed_at: now(),
            error: { code: cause.code || 'agent_task_phase_failed', message: cause.message }
          };
          workflow.status = 'failed';
          if (sameOwner(workflow.finish?.active_owner, owner)) workflow.finish.active_owner = null;
          save(context, workflow);
        }
      });
    } catch (phaseCleanupError) {
      cause.phase_cleanup_error = phaseCleanupError.code || 'agent_task_phase_cleanup_failed';
    }
    throw cause;
  }
}
function artifactOverlap(left, right) {
  const a = normalizeRelative(left);
  const b = normalizeRelative(right);
  if (!a || !b) return false;
  return a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`);
}
function selectedRepair(plan, sourceFiles) {
  const selected = (plan?.opportunities || []).filter((item) => item.status === 'selected');
  if (selected.length !== 1) return { eligible: false, reason: selected.length ? 'multiple_selected_findings' : 'no_selected_finding', selected };
  const finding = selected[0];
  if (finding.repair_class !== 'verify_on_touch') return { eligible: false, reason: `repair_class_${finding.repair_class || 'unknown'}_not_automatic`, selected };
  if (finding.confirmation_required || finding.requires_dedicated_review || finding.protected || finding.manual_review) {
    return { eligible: false, reason: 'protected_or_confirmation_required', selected };
  }
  const covered = new Set(sourceFiles.map((item) => normalizeRelative(item)));
  const artifacts = cleanArray([finding.artifact, ...(finding.affected_artifacts || [])]);
  const missing = artifacts.filter((item) => !covered.has(normalizeRelative(item)));
  if (!artifacts.length || missing.length) return { eligible: false, reason: 'affected_artifacts_not_fully_verified', selected, missing };
  const overlappingOpen = (plan?.opportunities || []).filter((item) => {
    if (item === finding || item.lifecycle_id === finding.lifecycle_id) return false;
    if (['repaired', 'closed', 'resolved'].includes(String(item.status || ''))) return false;
    if (String(item.module_id || '') !== String(finding.module_id || '')) return false;
    const otherArtifacts = cleanArray([item.artifact, ...(item.affected_artifacts || [])]);
    return otherArtifacts.some((other) => artifacts.some((candidate) => artifactOverlap(other, candidate)));
  });
  if (overlappingOpen.length) {
    return {
      eligible: false,
      reason: 'overlapping_open_debt',
      selected,
      blocking_lifecycle_ids: overlappingOpen.map((item) => item.lifecycle_id).filter(Boolean).sort()
    };
  }
  return { eligible: true, finding, selected };
}
function providerUsage(value) {
  if (!value || typeof value !== 'object') return { status: 'unavailable', reason: 'provider_receipt_not_supplied', input_tokens: null, output_tokens: null, cached_tokens: null, cost: null };
  const hasReceipt = value.receipt_id && (Number.isFinite(Number(value.input_tokens)) || Number.isFinite(Number(value.output_tokens)));
  if (!hasReceipt) return { status: 'unavailable', reason: 'provider_receipt_invalid_or_incomplete', input_tokens: null, output_tokens: null, cached_tokens: null, cost: null };
  return {
    status: 'provider_reported', receipt_id: String(value.receipt_id), provider: value.provider || null, model: value.model || null,
    input_tokens: value.input_tokens ?? null, output_tokens: value.output_tokens ?? null, cached_tokens: value.cached_tokens ?? null, cost: value.cost ?? null
  };
}
function markdown(result) {
  const r = result.route || {};
  const repair = result.repair || {};
  const lines = [
    '# Agent task result', '',
    `- Status: **${result.status}**`,
    `- Task: ${result.task}`,
    `- Workflow: \`${result.workflow_id}\``,
    `- Primary verification: **${result.primary_verification?.status || 'unavailable'}**`,
    `- Route first-read acknowledged: **${result.route_first_read_acknowledged ? 'yes' : 'no'}**`,
    `- First-read acknowledgement receipt: ${r.first_read_acknowledgement?.receipt_id ? `\`${r.first_read_acknowledgement.receipt_id}\`` : 'unavailable'}`,
    `- Routing state: **${r.assessment || 'unavailable'}**`,
    `- Routing estimate: ${r.signed_delta_percent === null || r.signed_delta_percent === undefined ? 'unavailable' : `${r.signed_delta_percent}%`}`,
    `- Routing disclaimer: ${DISCLAIMER}`,
    `- Repair: **${repair.status || 'not_applied'}**`,
    `- Doctor during repair: ${result.doctor?.before_repair?.quality_score ?? result.doctor?.before?.quality_score ?? 'unavailable'} → ${result.doctor?.after?.quality_score ?? 'unavailable'}`,
    `- Task Readiness: ${result.task_readiness?.before ?? 'unavailable'} → ${result.task_readiness?.after ?? 'unavailable'}`,
    `- Deferred findings: ${repair.deferred_count ?? 'unavailable'}`,
    `- Provider usage: ${result.provider_usage?.status || 'unavailable'}`,
    '', '## Evidence',
    `- KVE IDs: ${(repair.kve_ids || []).map((id) => `\`${id}\``).join(', ') || 'none'}`,
    `- KVR ID: ${repair.kvr_id ? `\`${repair.kvr_id}\`` : 'none'}`,
    `- Duplicate verification executions: ${repair.duplicate_test_executions ?? 0}`
  ];
  return `${lines.join('\n')}\n`;
}
function begin(context, input = {}, dependencies = {}) {
  const routeFn = dependencies.taskRoute || taskRoute;
  const doctorFn = dependencies.doctor || doctor;
  const toolFn = dependencies.runTool || runTool;
  return withContainedLock(lockRequest(context), () => {
    if (!String(input.task || '').trim()) throw error('agent_task_task_required', 'begin requires --task.');
    // Doctor refreshes runtime maintenance artifacts used by the canonical
    // workspace baseline. Run it before routing so a just-created snapshot
    // records the same physical inputs that the worker receives.
    const workflowId = `ATW-${sha(`${String(input.task).trim()}:${process.pid}:${now()}:${crypto.randomBytes(16).toString('hex')}`)}`;
    const doctorBefore = doctorFn(context, workflowId, 'before');
    const route = routeFn(context, input);
    const modules = routeModules(route);
    const workflow = {
      schema_version: WORKFLOW_SCHEMA,
      product_version: systemVersion(context.systemRoot),
      workflow_id: workflowId,
      status: 'begun',
      created_at: now(), updated_at: now(),
      task: String(input.task),
      task_class: input.taskClass || null,
      context: { mode: context.mode, repo_id: context.repoId, workspace_id: context.workspaceId || null, branch: context.branch || null, head_sha: context.headSha || null },
      route,
      route_modules: modules,
      doctor_before: doctorBefore,
      finish: { phases: {} }
    };
    save(context, workflow);
    const sessionRun = toolFn(context, 'agent-session.js', ['start', '--task-id', route.task_scope_hash, '--session-id', workflowId, '--runtime', 'agent-task', '--json'], { sessionId: workflowId });
    workflow.agent_session = sessionRun.output?.session || null;
    save(context, workflow);
    return {
      status: 'ready', schema_version: WORKFLOW_SCHEMA, workflow_id: workflowId, task_id: route.task_scope_hash, session_id: workflowId,
      task: workflow.task, route: {
        task_scope_hash: route.task_scope_hash, snapshot_hash: route.snapshot_hash, current_status: route.state.current_status,
        ready: route.state.task_readiness === 'ready', effective_claim_eligible: route.state.effective_claim_eligible,
        claim_ineligible_reasons: route.state.claim_ineligible_reasons, selected_modules: route.state.bundle?.selected_modules || [],
        first_read: route.first_read, estimate: route.public_estimate, metrics: route.state.metrics, disclaimer: DISCLAIMER
      },
      doctor_before: doctorBefore,
      finish_request_template: {
        schema_version: REQUEST_SCHEMA,
        route_first_read_sha256: route.first_read.sha256,
        changed_files: [],
        source_files: [],
        tests_to_run: [{ argv: ['<physical-test-command>'], cwd: '.', timeout_ms: 120000 }],
        run_release_flow: true
      },
      command_contract: {
        repository_root: '.',
        test_cwd_is_repository_relative: true,
        request_file_must_be_inside_repository_or_stdin: true
      },
      next_action: 'Read route.first_read.content before broad repository exploration. Finish with the exact route_first_read_sha256 and physical source/test evidence.'
    };
  });
}
function finish(context, workflowId, rawRequest, dependencies = {}) {
  const toolFn = dependencies.runTool || runTool;
  const doctorFn = dependencies.doctor || doctor;
  const routeStateFn = dependencies.resolveEffectiveTaskRoutingState || resolveEffectiveTaskRoutingState;
  const request = normalizedFinishRequest(context, rawRequest);
  const requestHash = digest(request);
  const existing = load(context, workflowId);
  if (existing.status !== 'completed') assertBeginSnapshotStillCurrent(context, existing, routeStateFn);
  const prepared = prepareFinish(context, workflowId, request, requestHash);
  if (prepared.completed) return prepared.result;
  const workflow = prepared.workflow;
  const owner = prepared.owner;
  const startNs = process.hrtime.bigint();
  try {
    const release = runPhase(context, workflowId, owner, 'flow_release', () => {
      if (!request.run_release_flow) return { status: 'not_requested', exit_code: null };
      const run = toolFn(context, 'flow.js', ['release', '--json', '--no-color'], {
        sessionId: workflowId,
        timeoutMs: 600000,
        allowNonzero: true
      });
      if (!run.output || typeof run.output !== 'object') {
        throw error('agent_task_release_output_invalid', 'Release flow did not return a structured outcome.', run.record);
      }
      return { ...run.output, exit_code: run.record.exit_code, command: run.record };
    });
    const releaseSucceeded = release.status === 'not_requested' ||
      (release.exit_code === 0 && !['failed', 'blocked'].includes(String(release.status || '').toLowerCase()));
    const doctorPreRepair = runPhase(context, workflowId, owner, 'doctor_pre_repair', () => doctorFn(context, workflowId, 'before_repair'));

    const plan = runPhase(context, workflowId, owner, 'repair_plan', () => {
      const body = {
        task_id: workflow.route.task_scope_hash,
        session_id: workflow.workflow_id,
        user_task: workflow.task,
        changed_files: request.changed_files,
        selected_modules: workflow.route_modules.direct.length ? workflow.route_modules.direct : workflow.route_modules.selected,
        dependency_modules: workflow.route_modules.dependencies,
        agent_plan: ['read exact task first-read', 'complete primary task', 'run physical verification', 'apply only an exact safe scoped repair']
      };
      const file = writeRequest(context, workflowId, 'repair-plan', body);
      return toolFn(context, 'repair-on-touch.js', ['plan', '--request', file], { sessionId: workflowId }).output;
    });

    const verification = runPhase(context, workflowId, owner, 'verification', () => {
      const body = { task_id: workflow.route.task_scope_hash, session_id: workflow.workflow_id, source_files: request.source_files, tests_to_run: request.tests_to_run };
      const file = writeRequest(context, workflowId, 'verify', body);
      const run = toolFn(context, 'repair-on-touch.js', ['verify', '--request', file], { sessionId: workflowId, timeoutMs: Math.max(...request.tests_to_run.map((item) => item.timeout_ms)) + 30000 });
      const executions = run.output?.executions || [];
      if (run.output?.status !== 'pass' || !executions.length || executions.some((item) => item.status !== 'pass' || item.exit_code !== 0)) {
        throw error('agent_task_primary_verification_failed', 'Primary task verification failed.', run.output);
      }
      return { ...run.output, command: run.record };
    });

    const eligibility = request.run_release_flow && !releaseSucceeded
      ? { eligible: false, reason: 'release_flow_failed_before_repair', selected: (plan?.opportunities || []).filter((item) => item.status === 'selected') }
      : selectedRepair(plan, request.source_files);
    const receipt = runPhase(context, workflowId, owner, 'repair_receipt', () => {
      if (!eligibility.eligible) return {
        status: 'not_applicable',
        reason: eligibility.reason,
        selected_count: eligibility.selected?.length || 0,
        missing: eligibility.missing || [],
        blocking_lifecycle_ids: eligibility.blocking_lifecycle_ids || []
      };
      const finding = eligibility.finding;
      const executionIds = (verification.executions || []).map((item) => item.execution_id);
      const evidence = cleanArray([finding.artifact, ...(finding.affected_artifacts || []), ...request.source_files]);
      const body = {
        finding_id: finding.lifecycle_id,
        task_id: workflow.route.task_scope_hash,
        session_id: workflow.workflow_id,
        repair_mode: 'scoped',
        source_files: request.source_files,
        test_execution_ids: executionIds,
        claims_checked: [{ claim_id: `agent-task-${finding.lifecycle_id}`, claim: 'The task-relevant artifact matches the physically verified current behavior.', result: 'confirmed', evidence }],
        required_checks_completed: Array.isArray(finding.required_checks) && finding.required_checks.length ? finding.required_checks : ['read_current_source', 'run_relevant_tests', 'verify_resolution_predicate'],
        resolution_predicate: finding.resolution_predicate,
        predicate_result: 'pass',
        additional_work: {
          wall_time_ms: Math.max(1, Math.ceil((verification.executions || []).reduce((sum, item) => sum + Number(item.duration_ms || 0), 0))),
          context_tokens: 0, context_percent: 0, input_tokens: null, output_tokens: null
        }
      };
      const file = writeRequest(context, workflowId, 'repair-receipt', body);
      const run = toolFn(context, 'repair-on-touch.js', ['receipt', '--request', file], { sessionId: workflowId });
      return { ...run.output, command: run.record, reused_execution_ids: executionIds };
    });

    const applied = runPhase(context, workflowId, owner, 'repair_apply', () => {
      if (receipt.status !== 'receipt_saved') return { status: 'not_applicable', reason: receipt.reason || 'receipt_not_created' };
      const run = toolFn(context, 'repair-on-touch.js', ['apply', '--receipt', receipt.receipt.receipt_id], { sessionId: workflowId, allowNonzero: true });
      if (!run.output || typeof run.output !== 'object') {
        throw error('agent_task_repair_apply_output_invalid', 'Repair apply did not return a structured outcome.', run.record);
      }
      return { ...run.output, command: run.record };
    });

    const doctorAfter = runPhase(context, workflowId, owner, 'doctor_after', () => doctorFn(context, workflowId, 'after'));
    const repairStatus = runPhase(context, workflowId, owner, 'repair_status', () => {
      const run = toolFn(context, 'repair-on-touch.js', ['status', '--task-id', workflow.route.task_scope_hash, '--session-id', workflow.workflow_id], { sessionId: workflowId });
      return { ...run.output, command: run.record };
    });
    const sessionFinish = runPhase(context, workflowId, owner, 'session_finish', () => {
      const run = toolFn(context, 'agent-session.js', ['finish', '--session-id', workflowId, '--task-id', workflow.route.task_scope_hash, '--runtime', 'agent-task', '--status', 'done', '--json'], { sessionId: workflowId });
      return run.output;
    });

    const routeState = routeStateFn({ context, taskScopeHash: workflow.route.task_scope_hash, verifyLiveInputs: true });
    const metrics = workflow.route.state.metrics || {};
    const kveIds = (verification.executions || []).map((item) => item.execution_id).filter(Boolean);
    const kvrId = receipt.receipt?.receipt_id || null;
    const closed = cleanArray(repairStatus.verified_closures);
    const deferred = (repairStatus.opportunities || []).filter((item) => item.status !== 'repaired' && item.status !== 'closed');
    const applyReportedSuccess = ['recertified', 'recertified_idempotent', 'generated_artifact_repaired'].some((prefix) => String(applied.status || '').startsWith(prefix));
    const exactClosureSustained = Boolean(eligibility.finding?.lifecycle_id && closed.includes(eligibility.finding.lifecycle_id));
    const repairSucceeded = applyReportedSuccess && exactClosureSustained;
    const repairFinalStatus = repairSucceeded
      ? 'applied'
      : (receipt.status !== 'receipt_saved'
          ? 'not_applicable'
          : (applyReportedSuccess ? 'not_sustained_after_final_checks' : 'not_sustained_or_not_applied'));
    const finishElapsedMs = Number(process.hrtime.bigint() - startNs) / 1e6;
    const resultStatus = releaseSucceeded ? 'completed' : 'completed_with_warnings';
    const completedAt = now();
    const acknowledgementBody = {
      schema_version: ACK_SCHEMA,
      workflow_id: workflowId,
      task_id: workflow.route.task_scope_hash,
      first_read_sha256: workflow.route.first_read.sha256,
      finish_request_sha256: requestHash,
      acknowledged_at: completedAt,
      status: 'acknowledged'
    };
    const acknowledgementSha256 = digest(acknowledgementBody);
    const acknowledgement = {
      ...acknowledgementBody,
      receipt_id: `ATFA-${acknowledgementSha256}`,
      content_sha256: acknowledgementSha256
    };
    writeJsonAtomicContained(
      acknowledgementPath(context, workflowId),
      acknowledgement,
      context.stateRoot
    );
    const result = {
      schema_version: RESULT_SCHEMA,
      product_version: systemVersion(context.systemRoot),
      status: resultStatus, workflow_id: workflowId, task_id: workflow.route.task_scope_hash, session_id: workflowId,
      task: workflow.task, completed_at: completedAt,
      route_first_read_acknowledged: true,
      primary_verification: { status: verification.status, executions: verification.executions, execution_count: kveIds.length, command: publicCommandRecord(context, verification.command) },
      route: {
        begin_snapshot_hash: workflow.route.snapshot_hash,
        current_status_after: routeState.current_status,
        effective_claim_eligible_at_begin: workflow.route.state.effective_claim_eligible,
        effective_claim_eligible_after: routeState.effective_claim_eligible,
        assessment: metrics.assessment || null,
        signed_delta_percent: metrics.signed_delta_percent ?? null,
        workspace_estimated_tokens: metrics.workspace_baseline?.estimated_tokens ?? metrics.baseline?.estimated_tokens ?? null,
        task_estimated_tokens: metrics.task_context?.estimated_tokens ?? metrics.routing_total_estimated_tokens ?? null,
        workspace_narrowing: metrics.workspace_narrowing || null,
        selected_modules: workflow.route.state.bundle?.selected_modules || [],
        first_read: { path: workflow.route.first_read.path, sha256: workflow.route.first_read.sha256, bytes: workflow.route.first_read.bytes },
        first_read_acknowledgement: acknowledgement,
        disclaimer: DISCLAIMER,
        public_text: workflow.route.public_estimate
      },
      doctor: { at_begin: workflow.doctor_before, before_repair: doctorPreRepair, after: doctorAfter, before: doctorPreRepair },
      task_readiness: {
        before: plan.task_readiness_before?.score ?? plan.task_readiness?.score ?? workflow.doctor_before.task_readiness?.score ?? workflow.doctor_before.task_readiness ?? null,
        after: repairStatus.task_readiness?.score ?? repairStatus.task_readiness ?? doctorAfter.task_readiness?.score ?? doctorAfter.task_readiness ?? null
      },
      repair: {
        status: repairFinalStatus,
        eligibility: { eligible: eligibility.eligible, reason: eligibility.reason || null, blocking_lifecycle_ids: eligibility.blocking_lifecycle_ids || [] },
        selected_count: (plan.opportunities || []).filter((item) => item.status === 'selected').length,
        closed_count: closed.length,
        deferred_count: deferred.length,
        kve_ids: kveIds,
        kvr_id: kvrId,
        apply_status: applied.status || null,
        final_closure_sustained: exactClosureSustained,
        final_verified_closure_ids: closed,
        duplicate_test_executions: Math.max(0, ((receipt.reused_execution_ids || []).length + 0) - kveIds.length),
        verification_reused_for_receipt: Boolean(kvrId && (receipt.reused_execution_ids || []).length === kveIds.length),
        telemetry_artifact: applied.telemetry_artifact || null,
        deferred_findings: deferred.map((item) => ({ lifecycle_id: item.lifecycle_id || null, module_id: item.module_id || null, status: item.status, reason: item.decision_reason || null }))
      },
      release_flow: publicReleaseFlow(context, release),
      provider_usage: providerUsage(request.provider_usage),
      metrics: {
        begin_to_finish_wall_ms: Math.round((Date.now() - Date.parse(workflow.created_at)) * 1000) / 1000,
        finish_total_elapsed_ms: Math.round(finishElapsedMs * 1000) / 1000,
        verification_wall_ms: Math.round((verification.executions || []).reduce((sum, item) => sum + Number(item.duration_ms || 0), 0) * 1000) / 1000,
        repair_orchestration_wall_ms: [receipt.command?.duration_ms, applied.command?.duration_ms].filter(Number.isFinite).reduce((a, b) => a + b, 0),
        release_flow_wall_ms: release.command?.duration_ms ?? null,
        doctor_repair_delta: Number.isFinite(Number(doctorPreRepair.quality_score)) && Number.isFinite(Number(doctorAfter.quality_score))
          ? Number(doctorAfter.quality_score) - Number(doctorPreRepair.quality_score)
          : null
      },
      evidence: {
        workflow: relativeInside(context.stateRoot, workflowPath(context, workflowId)),
        result: relativeInside(context.stateRoot, resultPath(context, workflowId)),
        summary: relativeInside(context.stateRoot, summaryPath(context, workflowId)),
        first_read_acknowledgement: relativeInside(
          context.stateRoot,
          acknowledgementPath(context, workflowId)
        ),
        session: sessionFinish?.session || null
      }
    };
    return withContainedLock(lockRequest(context), () => {
      const current = load(context, workflowId);
      assertActiveOwner(current, owner);
      writeJsonAtomicContained(resultPath(context, workflowId), result, context.stateRoot);
      writeFileAtomicContained(summaryPath(context, workflowId), markdown(result), context.stateRoot);
      current.status = 'completed';
      current.completed_at = result.completed_at;
      current.finish.result = result;
      current.finish.completed_at = result.completed_at;
      current.finish.active_owner = null;
      save(context, current);
      return result;
    });
  } catch (cause) {
    releaseFinishOwner(context, workflowId, owner, cause);
    throw cause;
  }
}
function status(context, workflowId) {
  const workflow = load(context, workflowId);
  return { status: workflow.status, workflow_id: workflowId, workflow, result: readJson(resultPath(context, workflowId), null) };
}

module.exports = {
  WORKFLOW_SCHEMA,
  RESULT_SCHEMA,
  REQUEST_SCHEMA,
  ACK_SCHEMA,
  DISCLAIMER,
  begin,
  finish,
  status,
  __test: { sha, digest, artifactOverlap, selectedRepair, normalizedFinishRequest, providerUsage, runPhase, prepareFinish, ownerLiveness, taskRoute, routeModules, contextFlags, publicPathArgument, publicCommandRecord, publicReleaseFlow, acknowledgementPath }
};
