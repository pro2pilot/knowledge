#!/usr/bin/env node
'use strict';

const path = require('path');
const { ensureDir, getAgentId, withLock } = require('./lib/json-store');
const { resolveKnowledgeContext } = require('./lib/path-context');
const { appendTeamEvent } = require('./lib/team-store');
const { buildExternalMemoryReport } = require('./lib/memory-providers');

const context = resolveKnowledgeContext();
const lockDir = path.join(context.stateRoot, '.lock');

function statusUnlocked(options = {}) {
  ensureDir(path.join(context.stateRoot, 'maintenance'));
  const report = buildExternalMemoryReport(context, { write: true });
  appendTeamEvent(context, 'external_memory_status_changed', {
    providers: report.providers.map((provider) => ({
      provider: provider.provider_id,
      enabled: provider.enabled,
      status: provider.status,
      mode: provider.mode,
      trust_role: provider.trust_role,
      warnings: provider.warnings || []
    })),
    legacy_providers_detected: report.legacy_providers_detected.length,
    warnings: report.warnings
  });
  report.generated_by = report.generated_by || getAgentId();
  if (!options.quiet) console.log(JSON.stringify(report, null, 2));
  return report;
}

function main(options = {}) {
  return options.skipLock ? statusUnlocked(options) : withLock(lockDir, () => statusUnlocked(options));
}

module.exports = main;

if (require.main === module) {
  try { main({ quiet: process.argv.includes('--quiet') }); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
