'use strict';

const DISCLAIMER = 'This is a deterministic local context estimate, not actual provider-reported model-token usage.';

function number(value) {
  return Number.isFinite(Number(value)) ? new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 }).format(Number(value)) : 'unavailable';
}

function limitation(state, metrics) {
  const reasons = state.claim_ineligible_reasons || metrics.claim_ineligible_reasons || [
    metrics.baseline_incomplete_reason || 'workspace_narrowing_comparison_unavailable'
  ];
  return `No public workspace-narrowing estimate is available for this report: ${[...new Set(reasons.filter(Boolean))].join(', ')}.`;
}

function formatTaskRoutingEstimate(metrics = {}, state = {}) {
  if (!state.effective_claim_eligible) return limitation(state, metrics);
  const baseline = metrics.workspace_baseline?.estimated_tokens ?? metrics.baseline?.estimated_tokens;
  const task = metrics.task_context?.estimated_tokens ?? metrics.routing?.estimated_tokens ?? metrics.routing_total_estimated_tokens;
  const structural = metrics.workspace_narrowing || {};
  const structuralText = Number.isFinite(Number(structural.modules_total)) && Number.isFinite(Number(structural.modules_selected))
    ? ` The task route selected ${number(structural.modules_selected)} of ${number(structural.modules_total)} workspace modules and excluded ${number(structural.unrelated_paths_excluded || 0)} unrelated workspace paths from the first-read artifact.`
    : '';
  if (metrics.assessment === 'estimated_narrowing') {
    return `Estimated workspace-to-task first-read narrowing: ${number(baseline)} estimated tokens in the canonical workspace-wide first-read projection versus ${number(task)} in the task-scoped first-read, a ${number(Math.abs(metrics.signed_delta_percent))}% reduction.${structuralText} ${DISCLAIMER}`;
  }
  if (metrics.assessment === 'estimated_overhead') {
    return `Estimated workspace-to-task first-read overhead: ${number(task)} estimated tokens in the task-scoped first-read versus ${number(baseline)} in the canonical workspace-wide projection, a ${number(Math.abs(metrics.signed_delta_percent))}% overhead.${structuralText} ${DISCLAIMER}`;
  }
  if (metrics.assessment === 'neutral') {
    return `No material estimated workspace-to-task first-read difference.${structuralText} ${DISCLAIMER}`;
  }
  return limitation(state, metrics);
}

module.exports = { DISCLAIMER, formatTaskRoutingEstimate };
