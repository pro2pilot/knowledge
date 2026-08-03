#!/usr/bin/env node
'use strict';

const path = require('path');
const { parseCliArgs } = require('./lib/path-context');
const { unregisterWorkspace } = require('./lib/team-store');

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const teamRoot = path.resolve(flags.teamRoot || process.env.KNOWLEDGE_TEAM_ROOT || '');
  const workspaceId = flags.workspaceId || process.env.KNOWLEDGE_WORKSPACE_ID;
  if (!teamRoot || teamRoot === path.resolve('')) throw new Error('workspace-unregister requires --team-root or KNOWLEDGE_TEAM_ROOT');
  if (!workspaceId) throw new Error('workspace-unregister requires --workspace-id or KNOWLEDGE_WORKSPACE_ID');
  const workspace = unregisterWorkspace(teamRoot, workspaceId);
  const out = { ok: true, command: 'workspace-unregister', teamRoot, workspace };
  console.log(JSON.stringify(out, null, 2));
  return out;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(JSON.stringify({ ok: false, error: error.message }, null, 2)); process.exit(1); }
}

module.exports = main;

