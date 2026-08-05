#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const { readJson } = require('./lib/json-store');
const { estimateForFile } = require('./lib/token-estimate');
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

function estimateContext(context) {
  const routingPath = path.join(context.stateRoot, 'maintenance', 'routing_bundle.json');
  const routing = estimateForFile(routingPath);
  const baseline = Math.max(routing.tokens_approx * 2, routing.tokens_approx + 1200, 1);
  const savedPct = Math.max(0, Math.min(99, Math.round((1 - routing.tokens_approx / baseline) * 100)));
  return {
    estimated_system_tokens_used: routing.tokens_approx,
    estimated_context_saved_pct: savedPct
  };
}

function renderFooter(context, settings) {
  const trust = trustState(context);
  const metrics = estimateContext(context);
  const mode = String(settings.mode || 'compact').toLowerCase();
  if (mode === 'off') return '';
  if (settings.only_when_trust_incomplete && !/recheck|stale|suspect|missing|conflict|blocked/i.test(trust.status)) return '';
  if (mode === 'compact') {
    return `.knowledge: Trust ${trust.status} · ~${metrics.estimated_system_tokens_used} estimated system tokens · ~${metrics.estimated_context_saved_pct}% estimated context saved`;
  }
  return `## .knowledge report

Knowledge trust: ${trust.status}
Why: ${trust.why}
.knowledge context used: ~${metrics.estimated_system_tokens_used} estimated system tokens
Estimated context saved: ~${metrics.estimated_context_saved_pct}%

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

module.exports = { renderFooter, main };
