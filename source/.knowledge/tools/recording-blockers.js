#!/usr/bin/env node
'use strict';
const { resolveKnowledgeContext, parseCliArgs } = require('./lib/path-context');
const blockers = require('./lib/recording-blockers');
const { copyInertData } = require('./lib/json-transaction');
function main(argv = process.argv.slice(2)) {
  argv = copyInertData(argv);
  const parsed = parseCliArgs(argv), context = resolveKnowledgeContext(parsed.flags);
  const input = { id: parsed.flags.id, scope: parsed.flags.scope, reason: parsed.flags.reason, confirmed: parsed.flags.confirmed === 'true' };
  switch (parsed.positional[0] || 'list') {
    case 'list': return blockers.listBlockers(context);
    case 'resolve': return blockers.resolveBlocker(context, input);
    case 'revoke': return blockers.revokeOverride(context, input);
    default: return { status: 'rejected', reason: 'Usage: recording-blockers.js list|resolve|revoke --id=<id> --confirmed=true' };
  }
}
if (require.main === module) {
  try { const result = main(); console.log(JSON.stringify(result, null, 2)); if (result.status !== 'ok') process.exitCode = 2; }
  catch (error) { console.error(JSON.stringify({ status: 'rejected', reason: error.code || 'recording_registry_failed' })); process.exitCode = 2; }
}
module.exports = { main };
