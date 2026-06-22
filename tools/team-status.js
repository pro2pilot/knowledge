#!/usr/bin/env node
'use strict';

const path = require('path');
const { parseCliArgs } = require('./lib/path-context');
const { listTeamStatus } = require('./lib/team-store');

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const rawTeamRoot = flags.teamRoot || process.env.KNOWLEDGE_TEAM_ROOT || '';
  if (!rawTeamRoot) {
    const out = {
      schema_version: '3.2.0',
      generated_at: new Date().toISOString(),
      mode: 'repo',
      safe_queue: { default: true, status: 'available_without_team_root' },
      merge_policy: { default: 'Manual Only', auto_merge: false },
      repos: [],
      active_agents: [],
      workspaces_total: 0,
      warnings: ['No team root configured; repo-local Safe Queue primitives remain available.']
    };
    console.log(JSON.stringify(out, null, 2));
    return out;
  }
  const teamRoot = path.resolve(rawTeamRoot);
  const status = listTeamStatus(teamRoot);
  console.log(JSON.stringify(status, null, 2));
  return status;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(JSON.stringify({ ok: false, error: error.message }, null, 2)); process.exit(1); }
}

module.exports = main;
