'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { MAX_CHILD_JSON_BYTES } = require('./semantic-json');
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
const { coveredTrackedRecheckSources } = require('./queue-lifecycle');
const { verificationTimeoutMs, recordingSecretPaths } = require('./repair-on-touch');
const recording = require('./recording-blockers');
const { copyInertData } = require('./json-transaction');
const { assertSafeContainedPath } = require('./json-store');
const { lifecycleById } = require('./queue-lifecycle');
const currencyBatch = require('./knowledge-currency-batch');
const currencyCore = require('./knowledge-currency');

const WORKFLOW_SCHEMA = 'knowledge-agent-task-workflow.v1';
const RESULT_SCHEMA = 'knowledge-agent-task-result.v1';
const REQUEST_SCHEMA = 'knowledge-agent-task-finish-request.v1';
const ACK_SCHEMA = 'knowledge-agent-task-first-read-acknowledgement.v1';
const DISCLAIMER = 'This is a deterministic local first-read context estimate, not provider-reported model-token usage.';
const PHASES = Object.freeze([
  'knowledge_maintenance_preflight',
  'flow_release',
  'doctor_pre_repair',
  'repair_plan',
  'verification',
  'currency_issuance',
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
  const out = new Error(message), descriptor = Object.create(null);
  descriptor.value = code; descriptor.enumerable = true; descriptor.writable = true; descriptor.configurable = true;
  Object.defineProperty(out, 'code', descriptor);
  if (detail !== null) { descriptor.value = detail; Object.defineProperty(out, 'detail', descriptor); }
  return out;
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
    maxBuffer: options.maxBuffer || MAX_CHILD_JSON_BYTES,
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
  if (child.signal) throw error('agent_task_tool_failed', `${tool} terminated by signal ${child.signal}.`, record);
  let output = null;
  if (options.expectJson !== false) {
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
    operational_readiness: report.operational_readiness || null,
    lock_safety: report.lock_safety || null,
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
    let timeoutMs;
    try { timeoutMs = verificationTimeoutMs(item.timeout_ms); }
    catch { throw error('agent_task_test_timeout_invalid', `Test ${index + 1} timeout is invalid.`); }
    return { argv: item.argv, cwd, timeout_ms: timeoutMs };
  });
}
function normalizedFinishRequest(context, request) {
  request = finishRequestData(request);
  const nativeExecution = require('./verification-policy').nativeExecutionRequest(request);
  const maintenanceOptions = normalizeMaintenanceOptions(request);
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
    ...(nativeExecution === undefined ? {} : { native_execution: nativeExecution }),
    ...(request.timeout_ms === undefined ? {} : { timeout_ms: verificationTimeoutMs(request.timeout_ms) }),
    ...(request.verification_policy === undefined ? {} : { verification_policy: (() => {
      require('./verification-policy').resolvePolicy(request.verification_policy, request.timeout_ms);
      return request.verification_policy;
    })() }),
    primary_outcome: String(request.primary_outcome || 'completed'),
    primary_summary: String(request.primary_summary || '').slice(0, 2000),
    run_release_flow: request.run_release_flow === true,
    provider_usage: request.provider_usage || null,
    ...(request.currency_updates === undefined ? {} : { currency_updates: request.currency_updates }),
    ...maintenanceOptions
  };
}
function finishRequestData(value) {
  try {
    const data = copyInertData(value);
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Expected a request object');
    return data;
  }
  catch { throw error('agent_task_finish_request_invalid', 'Finish request requires bounded inert own data; accessors, proxies and inherited caller policy are not accepted.'); }
}
function normalizeMaintenanceOptions(request) {
  const result = {};
  if (Object.hasOwn(request, 'repair_mode')) {
    if (!['guarded', 'report_only'].includes(request.repair_mode)) throw error('agent_task_repair_mode_invalid', 'repair_mode must be guarded or report_only.');
    result.repair_mode = request.repair_mode;
  }
  if (Object.hasOwn(request, 'currency_defer')) {
    const value = request.currency_defer;
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).length !== 2 || !Object.hasOwn(value, 'lifecycle_ids') || !Object.hasOwn(value, 'reason') ||
        !Array.isArray(value.lifecycle_ids) || !value.lifecycle_ids.length ||
        value.lifecycle_ids.some(id => typeof id !== 'string' || !/^LC-[a-f0-9]{16}$/.test(id)) ||
        new Set(value.lifecycle_ids).size !== value.lifecycle_ids.length ||
        typeof value.reason !== 'string' || !value.reason.trim() || value.reason.length > 2000 || /[\x00-\x1f\x7f]/.test(value.reason)) {
      throw error('agent_task_currency_defer_invalid', 'currency_defer requires exact unique lifecycle_ids and a nonempty plain-text reason.');
    }
    result.currency_defer = { lifecycle_ids: [...value.lifecycle_ids].sort(), reason: value.reason.trim() };
  }
  if (Object.hasOwn(request, 'currency_updates') && typeof request.currency_updates !== 'string') {
    throw error('agent_task_currency_updates_invalid', 'currency_updates must be one canonical relative batch request path.');
  }
  return result;
}
function maintenanceScope(workflow, request) {
  return {
    module_ids: cleanArray(workflow.route_modules.direct.length ? workflow.route_modules.direct : workflow.route_modules.selected).sort(),
    paths: cleanArray([...(workflow.route.scope?.paths || []), ...request.changed_files]).sort()
  };
}
function maintenanceRelevant(value, scope) {
  return [value.module_id, ...(value.module_ids || [])].some(id => scope.module_ids.includes(id)) ||
    [value.artifact, value.primary_artifact, ...(value.affected_artifacts || []), ...(value.changed_paths || [])]
      .filter(Boolean).some(file => scope.paths.some(candidate => artifactOverlap(file, candidate)));
}
function readMaintenanceProjection(context, relative, fallback) {
  const file = path.resolve(context.stateRoot, relative);
  assertSafeContainedPath(context.stateRoot, file, { allowMissing: true });
  let stat;
  try { stat = fs.lstatSync(file); }
  catch (cause) { if (cause.code === 'ENOENT') return fallback; throw cause; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 32 * 1024 * 1024) throw error('currency_projection_unsafe', 'Unsafe maintenance projection.');
  const value = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  assertSafeContainedPath(context.stateRoot, file);
  const after = fs.lstatSync(file);
  if (after.ino !== stat.ino || after.dev !== stat.dev || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) throw error('currency_projection_changed', 'Maintenance projection changed during read.');
  return value;
}
function inspectKnowledgeMaintenance(context, workflow, request) {
  const scope = maintenanceScope(workflow, request);
  const snapshot = { schema_version: 'knowledge-agent-task-maintenance-snapshot.v1', scope, currency_enabled: false,
    stale_units: [], deferrable_lifecycle_ids: [], protected_risk_lifecycle_ids: [], blocking_issues: [] };
  try {
    const staleItems = readMaintenanceProjection(context, 'maintenance/stale_items.json', { items: [] });
    const repairQueue = readMaintenanceProjection(context, 'maintenance/repair_queue.json', { queue: [] });
    const currency = currencyCore.evaluateCurrency(context, { staleItems, repairQueue });
    const records = lifecycleById(staleItems, repairQueue);
    snapshot.currency_enabled = currency.enabled;
    snapshot.protected_risk_lifecycle_ids = cleanArray((currency.assurance?.open_findings || [])
      .filter(row => maintenanceRelevant(row, scope)).map(row => row.lifecycle_id)).sort();
    const units = new Map();
    for (const issue of currency.issues || []) {
      if (!currencyCore.isNativeScopedCurrencyIssue(issue)) {
        snapshot.blocking_issues.push({ code: issue.code || 'currency_validation_failed', impact: 'global', receipt_id: issue.receipt_id || null });
        continue;
      }
      if (!maintenanceRelevant(issue, scope)) continue;
      let unit = units.get(issue.receipt_id);
      if (!unit) {
        unit = { receipt_id: issue.receipt_id, lifecycle_ids: [], module_ids: [], affected_artifacts: [], changed_paths: [], issue_codes: [] };
        units.set(issue.receipt_id, unit);
      }
      for (const key of ['lifecycle_ids', 'module_ids', 'affected_artifacts', 'changed_paths']) unit[key] = cleanArray([...unit[key], ...issue[key]]).sort();
      unit.issue_codes = cleanArray([...unit.issue_codes, issue.code]).sort();
    }
    const represented = new Set([...units.values()].flatMap(unit => unit.lifecycle_ids));
    for (const row of records.values()) {
      if (represented.has(row.lifecycle_id) || !currencyCore.isCurrencyEligibleFinding(row) ||
          currency.findings?.[row.lifecycle_id] || ['closed', 'resolved', 'repaired'].includes(row.status) || !maintenanceRelevant(row, scope)) continue;
      units.set(row.lifecycle_id, { receipt_id: null, lifecycle_ids: [row.lifecycle_id], module_ids: [row.module_id],
        affected_artifacts: cleanArray([row.primary_artifact, row.artifact, ...(row.affected_artifacts || [])]).sort(),
        changed_paths: [], issue_codes: ['currency_review_missing'] });
    }
    snapshot.stale_units = [...units.values()].sort((a, b) => String(a.receipt_id || a.lifecycle_ids[0]).localeCompare(String(b.receipt_id || b.lifecycle_ids[0])));
    if (!snapshot.blocking_issues.length) snapshot.deferrable_lifecycle_ids = cleanArray(snapshot.stale_units.flatMap(unit => unit.lifecycle_ids)
      .filter(id => { const row = records.get(id); return row && currencyCore.isCurrencyEligibleFinding(row) && !currency.findings?.[id] && maintenanceRelevant(row, scope); })).sort();
  } catch (cause) {
    snapshot.deferrable_lifecycle_ids = [];
    snapshot.blocking_issues.push({ code: cause.code || 'currency_projection_invalid', impact: 'global', receipt_id: null });
  }
  return snapshot;
}
function validateCurrencyDeferral(request, snapshot) {
  if (!request.currency_defer) return;
  if (snapshot.blocking_issues.length) throw error('agent_task_currency_defer_unavailable', 'Currency deferral cannot replace fresh native validation when currency evidence is globally blocked.');
  for (const id of request.currency_defer.lifecycle_ids) {
    if (snapshot.protected_risk_lifecycle_ids.includes(id)) throw error('agent_task_currency_defer_protected', 'Protected application risks cannot be deferred as factual currency maintenance.', { lifecycle_id: id });
    if (!snapshot.deferrable_lifecycle_ids.includes(id)) throw error('agent_task_currency_defer_not_stale', 'Currency deferral must name exact scope-relevant, currently stale, eligible lifecycle IDs.', { lifecycle_id: id });
  }
}
function knowledgeMaintenanceReport(before, after, request, currencyUpdate = { status: 'not_requested' }, preferredLanguage = 'en') {
  const staleIds = cleanArray(after.stale_units.flatMap(unit => unit.lifecycle_ids)).sort();
  const deferredIds = (request.currency_defer?.lifecycle_ids || []).filter(id => staleIds.includes(id));
  const pendingIds = staleIds.filter(id => !deferredIds.includes(id));
  const blocked = after.blocking_issues.length > 0;
  const renewed = !blocked && !staleIds.length && before.stale_units.length > 0 && currencyUpdate.status === 'committed';
  const status = blocked ? 'unavailable' : pendingIds.length || (after.stale_units.length && !staleIds.length) ? 'action_required' :
    deferredIds.length ? 'deferred' : renewed ? 'renewed' : 'not_required';
  const nextAction = status === 'unavailable' ? 'Inspect the native currency validation blockers; deferral cannot replace valid evidence.' :
    ['action_required', 'deferred'].includes(status) ? 'Supply independent reviewed v3 overlay child requests and a pinned batch via currency_updates, or explicitly defer exact eligible lifecycle_ids with a nonempty reason in currency_defer. Do not blindly rehash old claims.' : null;
  let notice = status === 'unavailable' ? 'Primary verification is separate: knowledge maintenance could not be established because native currency validation is blocked.' :
    status === 'action_required' ? `Knowledge maintenance requires independent review for ${pendingIds.length} lifecycle finding(s); primary verification does not renew currency evidence.` :
    status === 'deferred' ? `Knowledge maintenance was explicitly deferred for ${deferredIds.length} lifecycle finding(s): ${request.currency_defer.reason}. No closure or trust was granted by this deferral.` : null;
  if (String(preferredLanguage).toLowerCase().startsWith('ru')) {
    notice = status === 'unavailable' ? 'Результат основной проверки сохранён отдельно. Обслуживание knowledge заблокировано: не удалось проверить native currency evidence. Причины перечислены в blocking_issues.' :
      status === 'action_required' ? 'Обслуживание knowledge требует независимого review для ' + pendingIds.length + ' findings. Успешные тесты сами по себе не обновляют фактические утверждения.' :
      status === 'deferred' ? 'Обслуживание knowledge явно отложено для ' + deferredIds.length + ' findings: ' + request.currency_defer.reason + '. Это не закрывает findings и не повышает trust.' : null;
  }
  return { schema_version: 'knowledge-agent-task-knowledge-maintenance.v1', status,
    maintenance_succeeded: renewed ? true : ['unavailable', 'action_required', 'deferred'].includes(status) ? false : null,
    repair_mode: request.repair_mode || (request.currency_updates ? 'factual_only' : 'guarded'), currency_status: currencyUpdate.status,
    stale_units: after.stale_units, stale_units_before: before.stale_units,
    pending_lifecycle_ids: pendingIds, deferred_lifecycle_ids: deferredIds,
    currency_defer: request.currency_defer || null, protected_risk_lifecycle_ids: after.protected_risk_lifecycle_ids,
    blocking_issues: after.blocking_issues, chat_notice: notice, next_action: nextAction,
    deferral_grants_closure: false, deferral_grants_trust: false, security_certificate: false };
}
// Public finish shape: currency_updates: ".knowledge/evidence/batch.json".
// No object/array shorthand and no automatic semantic assertion.
function bindCurrencyFinish(context, request, workflow, batch = currencyBatch) {
  if (request.currency_updates === undefined) return request;
  if (typeof request.currency_updates !== 'string') throw error('agent_task_currency_updates_invalid', 'currency_updates must be one canonical relative batch request path.');
  const previous = workflow.finish?.request?.currency_binding;
  const phase = workflow.finish?.phases?.currency_issuance;
  const alreadyVerified = workflow.finish?.phases?.verification?.status === 'completed';
  const binding = previous && phase && alreadyVerified
    ? batch.assertBatchBindingCurrent(context, previous)
    : batch.prepareBatchForFinish(context, request.currency_updates, { taskId: workflow.route.task_scope_hash, sessionId: workflow.workflow_id, sourceFiles: request.source_files });
  if (binding.request_path !== request.currency_updates) throw error('agent_task_currency_updates_changed', 'Currency batch request path changed.');
  const argv = batch.checkBatchArgv(context, request.currency_updates);
  const matching = item => item.cwd === '.' && digest(item.argv) === digest(argv);
  // Preserve user tests, but execute the exact native batch check only once.
  const tests = request.tests_to_run.filter(item => !matching(item));
  tests.push({ argv, cwd: '.', timeout_ms: 120000 });
  return { ...request, currency_binding: binding, tests_to_run: tests };
}
function recoverableCurrencyPhase(workflow, request, running) {
  return Boolean(running?.[0] === 'currency_issuance' && request.currency_binding &&
    workflow.finish?.phases?.verification?.status === 'completed');
}
function recordingPreflight(context, value, sessionId, preferredLanguage) {
  const fields = recordingSecretPaths(value, { context, sessionId });
  if (!fields.length) return;
  const at = (field) => field.slice(2).replace(/\[(\d+)\]/g, '.$1').split('.').reduce((item, key) => item?.[key], value);
  const rows = fields.map((field) => recording.registerBlocker(context, {
    value: at(field), field, session_id: sessionId, language: preferredLanguage
  }).blocker);
  throw error('recording_blocked', rows[0].chat_notice, {
    recording_status: 'blocked', recording_blockers: rows,
    chat_notice: rows.map((row) => row.chat_notice).join('\n'),
    action_required: 'Relay chat_notice immediately in the user preferred language. Do not claim task recording completed.'
  });
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
      if ((running && !recoverableCurrencyPhase(workflow, request, running)) || live === null) {
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
    if (unknown && recoverableCurrencyPhase(workflow, request, unknown)) {
      workflow.finish.phases.currency_issuance = { ...unknown[1], status: 'failed', retry_reason: 'native_batch_reconciliation' };
    } else if (unknown) {
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
    if (coveredTrackedRecheckSources(item, finding, sourceFiles).length) return false;
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
    `- Knowledge maintenance: **${result.knowledge_maintenance?.status || 'unavailable'}** (separate from verification)`,
    `- Maintenance notice: ${result.knowledge_maintenance?.chat_notice || 'none'}`,
    `- Maintenance next action: ${result.knowledge_maintenance?.next_action || 'none'}`,
    `- Route first-read acknowledged: **${result.route_first_read_acknowledged ? 'yes' : 'no'}**`,
    `- First-read acknowledgement receipt: ${r.first_read_acknowledgement?.receipt_id ? `\`${r.first_read_acknowledgement.receipt_id}\`` : 'unavailable'}`,
    `- Routing state: **${r.assessment || 'unavailable'}**`,
    `- Routing estimate: ${r.signed_delta_percent === null || r.signed_delta_percent === undefined ? 'unavailable' : `${r.signed_delta_percent}%`}`,
    `- Routing disclaimer: ${DISCLAIMER}`,
    `- Repair: **${repair.status || 'not_applied'}**`,
    `- Doctor during repair: ${result.doctor?.before_repair?.quality_score ?? result.doctor?.before?.quality_score ?? 'unavailable'} → ${result.doctor?.after?.quality_score ?? 'unavailable'}`,
    `- Doctor operational snapshot: ${result.doctor?.after?.operational_readiness?.status || 'unavailable'} (state/project roots only; separate from task debt readiness)`,
    `- Task Readiness: ${result.task_readiness?.before ?? 'unavailable'} → ${result.task_readiness?.after ?? 'unavailable'}`,
    `- Readiness comparison: ${result.task_readiness?.comparison_status || 'unavailable'} (repair cohort)`,
    `- Current task debt readiness: ${result.task_readiness?.current ?? 'unavailable'}`,
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
  input = finishRequestData(input);
  recordingPreflight(context, { task: input.task, modules: input.modules || [], paths: input.paths || [] }, null, input.language);
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
      preferred_language: recording.language(context, input.language),
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
  rawRequest = finishRequestData(rawRequest);
  recordingPreflight(context, rawRequest, workflowId, rawRequest?.language || load(context, workflowId).preferred_language);
  const toolFn = dependencies.runTool || runTool;
  const doctorFn = dependencies.doctor || doctor;
  const routeStateFn = dependencies.resolveEffectiveTaskRoutingState || resolveEffectiveTaskRoutingState;
  const existing = load(context, workflowId);
  const normalizedRequest = normalizedFinishRequest(context, rawRequest);
  if (normalizedRequest.native_execution?.darwin?.enabled === true || normalizedRequest.native_execution?.linux?.enabled === true) {
    require('./verification-supervisor').assertContainmentAvailable(normalizedRequest.native_execution);
  }
  const admissionSnapshot = inspectKnowledgeMaintenance(context, existing, normalizedRequest);
  validateCurrencyDeferral(normalizedRequest, admissionSnapshot);
  const maintenanceBefore = existing.finish?.phases?.knowledge_maintenance_preflight?.result?.snapshot || admissionSnapshot;
  const request = bindCurrencyFinish(context, normalizedRequest, existing, dependencies.currencyBatch || currencyBatch);
  const requestHash = digest(request);
  if (existing.status !== 'completed') assertBeginSnapshotStillCurrent(context, existing, routeStateFn);
  const prepared = prepareFinish(context, workflowId, request, requestHash);
  if (prepared.completed) return prepared.result;
  const workflow = prepared.workflow;
  const owner = prepared.owner;
  const startNs = process.hrtime.bigint();
  try {
    runPhase(context, workflowId, owner, 'knowledge_maintenance_preflight', () => ({ status: 'observed', snapshot: maintenanceBefore }));
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
        // The immutable task route already defines this repair scope. Global
        // routing and PR summaries may describe unrelated projects or tasks.
        scope_source: 'explicit',
        routing: {},
        pr_impact: {},
        critical_path_map: {},
        agent_plan: ['read exact task first-read', 'complete primary task', 'run physical verification', 'apply only an exact safe scoped repair']
      };
      const file = writeRequest(context, workflowId, 'repair-plan', body);
      return toolFn(context, 'repair-on-touch.js', ['plan', '--request', file], { sessionId: workflowId }).output;
    });

    const verification = runPhase(context, workflowId, owner, 'verification', () => {
      const body = { task_id: workflow.route.task_scope_hash, session_id: workflow.workflow_id, source_files: request.source_files, tests_to_run: request.tests_to_run,
        ...(request.native_execution === undefined ? {} : { native_execution: request.native_execution }),
        ...(request.timeout_ms === undefined ? {} : { timeout_ms: request.timeout_ms }),
        ...(request.verification_policy === undefined ? {} : { verification_policy: request.verification_policy }) };
      const file = writeRequest(context, workflowId, 'verify', body);
      // The verification runner executes this batch sequentially. Its outer
      // deadline must cover every effective child budget plus orchestration.
      const timing = require('./verification-policy').resolvePolicy(request.verification_policy,
        request.timeout_ms ?? request.tests_to_run.reduce((total, item) => total + item.timeout_ms, 0));
      const timeoutMs = timing.work_budget_ms + timing.cleanup_budget_ms + 30000;
      const run = toolFn(context, 'repair-on-touch.js', ['verify', '--request', file], { sessionId: workflowId, timeoutMs });
      const executions = run.output?.executions || [];
      if (run.output?.status !== 'pass' || !executions.length || executions.some((item) => item.status !== 'pass' || item.exit_code !== 0)) {
        throw error('agent_task_primary_verification_failed', 'Primary task verification failed.', run.output);
      }
      require('./verification-finalization').requireFinalizedExecutions(context.stateRoot, executions.map(item => item.execution_id), run.output.verification_acceptances, 'caller_policy_required');
      return { ...run.output, command: run.record };
    });

    // Revalidate persisted verification on resume as well as a fresh run.
    const acceptedBatch = require('./verification-finalization').requireFinalizedExecutions(context.stateRoot, verification.executions.map(item => item.execution_id), verification.verification_acceptances, 'caller_policy_required');
    // A batch ACK proves completion, not a privacy exception. Recheck every
    // batch member with this workflow's exact recording context, including on
    // resume; an exception from another workflow must not authorize reuse.
    for (const record of acceptedBatch.execution_records) recordingPreflight(context, record, workflowId, workflow.preferred_language);
    if (verification.executions.length !== request.tests_to_run.length) throw error('agent_task_primary_binding_failed', 'Verification does not cover the requested command batch.');
    for (let index = 0; index < verification.executions.length; index++) {
      const record = acceptedBatch.execution_records.find(item => item.execution_id === verification.executions[index].execution_id);
      const expected = request.tests_to_run[index];
      if (!record || record.task_id !== workflow.route.task_scope_hash || record.session_id !== workflow.workflow_id ||
          JSON.stringify(record.command_argv) !== JSON.stringify(expected.argv) || record.cwd !== expected.cwd.replace(/\\/g, '/') ||
          request.source_files.some(file => !record.source_snapshot.some(pin => pin.path === file))) {
        throw error('agent_task_primary_binding_failed', 'Native verification is not bound to this workflow request.');
      }
    }

    const currencyUpdate = runPhase(context, workflowId, owner, 'currency_issuance', () => {
      if (!request.currency_updates) return { status: 'not_requested' };
      return (dependencies.currencyBatch || currencyBatch).issueBatch(context, request.currency_updates,
        verification.executions.map(item => item.execution_id), request.currency_binding, verification.verification_acceptances);
    });
    // Factual maintenance has no implicit operational closure authority.
    const eligibility = request.repair_mode === 'report_only' || request.currency_updates
      ? { eligible: false, reason: request.currency_updates ? 'factual_currency_only' : 'report_only', selected: [] }
      : request.run_release_flow && !releaseSucceeded
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
        verification_acceptances: verification.verification_acceptances,
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
    const maintenanceAfter = inspectKnowledgeMaintenance(context, workflow, request);
    const maintenanceReport = knowledgeMaintenanceReport(maintenanceBefore, maintenanceAfter, request, currencyUpdate, workflow.preferred_language);
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
      primary_verification: { status: verification.status, verification_acceptances: verification.verification_acceptances, executions: verification.executions, execution_count: kveIds.length, command: publicCommandRecord(context, verification.command) },
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
        before: repairStatus.task_readiness_comparison?.before?.score ?? null,
        after: repairStatus.task_readiness_comparison?.after?.score ?? null,
        comparison_status: repairStatus.task_readiness_comparison?.status || 'unavailable',
        comparison_reason: repairStatus.task_readiness_comparison?.reason || (repairStatus.task_readiness_comparison ? null : 'comparison_data_unavailable'),
        cohort_scope: 'repair_cohort',
        cohort_lifecycle_ids: repairStatus.task_readiness_comparison?.cohort_lifecycle_ids || [],
        observed_outside_cohort_lifecycle_ids: repairStatus.task_readiness_comparison?.observed_outside_cohort_lifecycle_ids || [],
        current: repairStatus.task_readiness?.score ?? null,
        at_plan: plan.task_readiness?.score ?? null
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
      knowledge_maintenance: maintenanceReport,
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
  __test: { finishRequestData, normalizeMaintenanceOptions, inspectKnowledgeMaintenance, validateCurrencyDeferral, knowledgeMaintenanceReport, bindCurrencyFinish, recoverableCurrencyPhase, sha, digest, artifactOverlap, selectedRepair, normalizedFinishRequest, providerUsage, runPhase, prepareFinish, ownerLiveness, taskRoute, routeModules, contextFlags, publicPathArgument, publicCommandRecord, publicReleaseFlow, acknowledgementPath }
};
