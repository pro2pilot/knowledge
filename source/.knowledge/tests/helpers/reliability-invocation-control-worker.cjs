'use strict';
const path = require('node:path');
const source = process.argv[2];
const input = JSON.parse(process.argv[3]);
const control = require(path.join(source, 'tools/lib/verification-control.js'));
const begun = control.beginAttempt(input.context, {
  request_sha256: 'a'.repeat(64),
  profile: { work_budget_ms: 60000, no_progress_ms: 0, cleanup_budget_ms: 5000 },
  invocation: input.invocation
});
if (input.intent) control.updateAttempt(input.context, begun.owner, { type: 'spawn_intent', role: 'authority' });
const attempt = control.readStatus(input.context).attempt;
process.stdout.write(JSON.stringify({ attempt, creator_namespace_pid: process.pid }));
