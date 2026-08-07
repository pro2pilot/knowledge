#!/usr/bin/env node
'use strict';

const { parseCliArgs, resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { registerWorkspace } = require('./lib/team-store');

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  flags.mode = 'team';
  const context = resolveKnowledgeContext(flags);
  const workspace = registerWorkspace(context, {
    notes: flags.notes || null,
    prNumber: flags.prNumber || null
  });
  const out = {
    ok: true,
    command: 'workspace-register',
    context: jsonContext(context),
    workspace
  };
  console.log(JSON.stringify(out, null, 2));
  return out;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(JSON.stringify({ ok: false, error: error.message }, null, 2)); process.exit(1); }
}

module.exports = main;

