#!/usr/bin/env node
'use strict';

const { parseCliArgs, resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { initTeam } = require('./lib/team-store');

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  flags.mode = 'team';
  if (!flags.workspaceId) flags.workspaceId = flags.workspaceId || 'team-root';
  if (!flags.agentId) flags.agentId = flags.agentId || process.env.KNOWLEDGE_AGENT_ID || 'team-init';
  const context = resolveKnowledgeContext(flags);
  const result = initTeam(context);
  const out = {
    ok: true,
    command: 'team-init',
    context: jsonContext(context),
    registry: `${context.teamRoot}/registry.json`,
    repo: result.repo
  };
  console.log(JSON.stringify(out, null, 2));
  return out;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(JSON.stringify({ ok: false, error: error.message }, null, 2)); process.exit(1); }
}

module.exports = main;

