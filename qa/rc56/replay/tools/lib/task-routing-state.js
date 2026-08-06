'use strict';

// The only public-state interpreter for task routing consumers. Immutable
// metrics describe history; this module decides whether that history remains
// safe to present after checking the live workspace read-only.
const fs = require('fs');
const path = require('path');
const routing = require('./task-routing');
const { readJson } = require('./json-store');
const { formatTaskRoutingEstimate } = require('./routing-estimate-formatter');

function evaluateEffectiveRoutingClaimEligibility(input) {
  const reasons = [];
  const add = (condition, reason) => { if (!condition) reasons.push(reason); };
  add((input.immutable_metrics_claim_eligible ?? input.immutable_claim_eligible) === true, 'immutable_metrics_claim_ineligible');
  add(input.comparison_kind === 'workspace_to_task_first_read_narrowing', 'workspace_narrowing_comparison_kind_invalid');
  add(input.canonical_workspace_baseline === true, 'workspace_baseline_not_canonical');
  add(input.comparison_contract_valid === true, 'workspace_narrowing_comparison_contract_invalid');
  add(input.task_scope_explicit === true, 'requires_explicit_frozen_scope');
  add(input.current_status === 'current', input.current_status === 'stale' ? 'task_routing_snapshot_stale' : `task_routing_${input.current_status || 'missing'}`);
  add(input.snapshot_complete === true, 'task_routing_snapshot_incomplete');
  add(input.pointer_consistent === true, 'task_routing_pointer_inconsistent');
  add(input.live_inputs_match === true, 'live_relevant_input_drift');
  add(input.workspace_baseline_complete === true || input.baseline_complete === true, 'required_baseline_artifact_invalid');
  add(input.task_readiness === 'ready', `task_readiness_${input.task_readiness || 'unknown'}`);
  add(input.required_sources_complete === true, 'required_task_source_unavailable');
  add(input.relevant_git_diff_accounted === true, 'relevant_git_diff_unaccounted');
  add(Number(input.inaccessible_relevant_high_risk_paths || 0) === 0, 'inaccessible_high_risk_context');
  add(input.required_continuations_complete === true, 'required_high_risk_continuation_unresolved');
  add(input.estimator_method_claim_eligible !== false, 'estimator_method_ineligible');
  return { effective_claim_eligible: reasons.length === 0, claim_ineligible_reasons: [...new Set(reasons)] };
}

function resolveEffectiveTaskRoutingState({ context, taskScopeHash, verifyLiveInputs = true }) {
  if (!taskScopeHash) return { current_status: 'missing', snapshot_complete: false, pointer_consistent: false, live_inputs_match: false, baseline_complete: false, task_readiness: 'missing', immutable_claim_eligible: false, effective_claim_eligible: false, claim_ineligible_reasons: ['task_routing_context_ambiguous'] };
  const reconciled = routing.inspectTask(context, taskScopeHash);
  const current = reconciled?.status === 'ok' ? reconciled.current : null;
  const snapshotHash = current?.routing_snapshot_hash || current?.snapshot_hash;
  const snapshotPath = snapshotHash ? routing.snapshotRoot(context, taskScopeHash, snapshotHash) : null;
  const metrics = current?.metrics || {};
  const bundle = snapshotPath ? readJson(path.join(snapshotPath, 'bundle.json'), {}) : {};
  const continuation = snapshotPath ? readJson(path.join(snapshotPath, 'continuation.json'), {}) : {};
  let liveInputsMatch = Boolean(current);
  let rebuilt = null;
  if (liveInputsMatch && verifyLiveInputs) {
    try {
      rebuilt = routing.buildSnapshot(context, current.scope);
      liveInputsMatch = rebuilt.snapshot_hash === snapshotHash &&
        rebuilt.baseline?.baseline_hash === current.baseline_hash &&
        rebuilt.metrics?.metrics_comparison_hash === current.metrics_comparison_hash &&
        rebuilt.live_input_digest === metrics.live_input_digest;
    } catch { liveInputsMatch = false; }
  }
  const state = {
    task_scope_hash: taskScopeHash, snapshot_hash: snapshotHash || null, routing_snapshot_hash: snapshotHash || null,
    baseline_hash: current?.baseline_hash || null, metrics_comparison_hash: current?.metrics_comparison_hash || null,
    live_input_digest: rebuilt?.live_input_digest || metrics.live_input_digest || null,
    stored_live_input_digest: metrics.live_input_digest || null,
    current_status: current?.status || reconciled?.status || 'missing', snapshot_complete: Boolean(snapshotPath && routing.snapshotComplete(context, snapshotPath)),
    pointer_consistent: Boolean(current && reconciled?.status === 'ok'), live_inputs_match: liveInputsMatch,
    comparison_kind: metrics.comparison_kind || null,
    canonical_workspace_baseline: current?.baseline?.canonical === true,
    comparison_contract_valid: metrics.comparison_contract_valid === true,
    task_scope_explicit: metrics.task_scope_explicit === true,
    workspace_baseline_complete: metrics.workspace_baseline_complete === true,
    baseline_complete: metrics.workspace_baseline_complete === true || metrics.baseline_complete === true,
    scope_comparable: metrics.scope_comparable === true,
    task_readiness: bundle.task_readiness || 'missing', immutable_claim_eligible: metrics.claim_eligible === true,
    required_sources_complete: metrics.required_sources_complete === true && bundle.required_sources?.complete !== false,
    relevant_git_diff_accounted: metrics.relevant_git_diff_accounted === true,
    inaccessible_relevant_high_risk_paths: (continuation.inaccessible_paths || []).length,
    required_continuations_complete: metrics.mandatory_continuations_complete === true && continuation.required !== true,
    continuation_required: continuation.required === true,
    continuation_digest: metrics.comparison_receipt?.required_continuation_hashes?.[0] || null,
    estimator_method_claim_eligible: metrics.estimator_method === 'workspace_to_task_first_read_bytes_divided_by_four', metrics, bundle
  };
  return { ...state, ...evaluateEffectiveRoutingClaimEligibility(state) };
}

function resolveTaskRoutingContext({ context, manifests = [], explicitTaskId = null, sessionId = null, prNumber = null }) {
  const byId = new Map(manifests.map((item) => [item.task_scope_hash, item]));
  const select = (taskId, source) => taskId && byId.has(String(taskId))
    ? { status: 'resolved', source, task_scope_hash: String(taskId), manifest: byId.get(String(taskId)) }
    : null;
  const explicit = select(explicitTaskId, 'explicit_task_id');
  if (explicit) return explicit;

  const registry = readJson(path.join(context.stateRoot, 'sessions', 'agent-registry.json'), { sessions: [] });
  const requestedSession = sessionId || process.env.KNOWLEDGE_SESSION_ID || null;
  const activeSessions = (registry.sessions || []).filter((item) => ['running', 'waiting'].includes(String(item.status || 'running')));
  const sessionCandidates = requestedSession
    ? activeSessions.filter((item) => item.session_id === requestedSession)
    : activeSessions;
  const sessionTaskIds = [...new Set(sessionCandidates.map((item) => item.task_id).filter((id) => byId.has(String(id))).map(String))];
  if (sessionTaskIds.length === 1) return select(sessionTaskIds[0], 'agent_session');

  const requestedPr = prNumber ?? process.env.KNOWLEDGE_PR_NUMBER ?? null;
  if (requestedPr !== null && requestedPr !== '') {
    const mappingFiles = [
      path.join(context.stateRoot, 'routing', 'pr-task-map.json'),
      path.join(context.stateRoot, 'maintenance', 'pr_task_mapping.json')
    ];
    const mappedIds = [];
    for (const file of mappingFiles) {
      if (!fs.existsSync(file)) continue;
      const mapping = readJson(file, {});
      for (const row of mapping.mappings || mapping.items || []) {
        if (String(row.pr_number ?? row.pr ?? '') === String(requestedPr)) {
          const taskId = row.task_scope_hash || row.task_id;
          if (taskId && byId.has(String(taskId))) mappedIds.push(String(taskId));
        }
      }
    }
    const uniqueMapped = [...new Set(mappedIds)];
    if (uniqueMapped.length === 1) return select(uniqueMapped[0], 'pr_mapping');
  }

  const active = manifests.filter((item) => !['stale', 'invalidated', 'archived'].includes(String(item.status || '').toLowerCase()));
  if (active.length === 1) return select(active[0].task_scope_hash, 'unique_active_task');
  return {
    status: 'ambiguous',
    source: null,
    task_scope_hash: null,
    manifest: null,
    reason: manifests.length ? 'task_routing_context_ambiguous' : 'task_routing_context_missing',
    candidates: manifests.map((item) => item.task_scope_hash)
  };
}

module.exports = {
  evaluateEffectiveRoutingClaimEligibility,
  formatTaskRoutingEstimate,
  resolveEffectiveTaskRoutingState,
  resolveTaskRoutingContext
};
