#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const { readJson } = require('./lib/json-store');
const taskRouting = require('./lib/task-routing');
const { resolveTaskRoutingContext, resolveEffectiveTaskRoutingState, formatTaskRoutingEstimate } = require('./lib/task-routing-state');
const { systemVersion } = require('./lib/system-version');

function safeJson(file, fallback) {
  try { return readJson(file, fallback); } catch { return fallback; }
}

function trustState(context) {
  const trust = safeJson(path.join(context.stateRoot, 'maintenance', 'trust_report.json'), {});
  const stale = safeJson(path.join(context.stateRoot, 'maintenance', 'stale_items.json'), { items: [] });
  const repair = safeJson(path.join(context.stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
  const staleCount = (stale.items || stale.stale_items || []).length;
  const repairCount = (repair.queue || repair.items || []).length;
  const status = trust.status || (staleCount || repairCount ? 'Needs recheck' : 'Unknown');
  const why = [
    staleCount ? `${staleCount} stale item(s)` : null,
    repairCount ? `${repairCount} repair item(s)` : null
  ].filter(Boolean).join(', ') || 'No blocking stale/repair pressure in current reports.';
  return { status, why };
}

function estimateContext(context, settings = {}) {
  let manifests = [];
  try { manifests = taskRouting.listTasks(context); } catch { manifests = []; }
  const resolved = resolveTaskRoutingContext({
    context,
    manifests,
    explicitTaskId: settings.task_id || settings.taskId || null,
    sessionId: settings.session_id || settings.sessionId || null,
    prNumber: settings.pr_number || settings.prNumber || null
  });
  if (resolved.status !== 'resolved') {
    return {
      status: 'unavailable',
      task_scope_hash: null,
      public_text: 'Task routing estimate unavailable: no unambiguous current task is bound.',
      disclaimer: 'This is a deterministic local first-read context estimate, not provider-reported model-token usage.'
    };
  }
  const state = resolveEffectiveTaskRoutingState({ context, taskScopeHash: resolved.task_scope_hash, verifyLiveInputs: true });
  return {
    status: state.effective_claim_eligible ? 'available' : 'unavailable',
    task_scope_hash: resolved.task_scope_hash,
    state,
    public_text: formatTaskRoutingEstimate(state.metrics || {}, state),
    disclaimer: 'This is a deterministic local first-read context estimate, not provider-reported model-token usage.'
  };
}

function renderFooter(context, settings) {
  const trust = trustState(context);
  const metrics = estimateContext(context, settings);
  const mode = String(settings.mode || 'compact').toLowerCase();
  if (mode === 'off') return '';
  if (settings.only_when_trust_incomplete && !/recheck|stale|suspect|missing|conflict|blocked/i.test(trust.status)) return '';
  if (mode === 'compact') {
    return `.knowledge: Trust ${trust.status} · ${metrics.public_text}`;
  }
  return `## .knowledge report

Knowledge trust: ${trust.status}
Why: ${trust.why}
Task routing: ${metrics.public_text}
Routing disclaimer: ${metrics.disclaimer}

Suggested action:
${settings.show_restore_action === false ? 'Review current reports' : 'Restore trust in knowledge'}

Open Inspector:
node .knowledge/inspector.js
`;
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const context = resolveKnowledgeContext(parsed.flags);
  const settings = {
    ...safeJson(path.join(context.projectKnowledgeRoot, 'settings', 'report-footer.json'), {}),
    ...parsed.flags
  };
  const footer = renderFooter(context, settings);
  const result = {
    ok: true,
    schema_version: systemVersion(),
    mode: settings.mode || 'compact',
    footer
  };
  if (parsed.flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(footer);
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = { renderFooter, estimateContext, main };
