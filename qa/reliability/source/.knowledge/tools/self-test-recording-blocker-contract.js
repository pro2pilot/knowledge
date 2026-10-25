'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const normalize = (value) => value.replace(/[`*_]/g, '').replace(/\s+/g, ' ').trim();
const required = [
  ['shared trust routing', 'agent-integrations/_shared/trust-routing.md', [
    'recording-blockers.js list',
    'recording-blockers.js resolve --id=<id> --scope=once --reason=<reason> --confirmed=true',
    'recording-blockers.js resolve --id=<id> --scope=project --reason=<reason> --confirmed=true',
    'recording-blockers.js revoke',
    'blocked_by_user_scope',
    'do not write elsewhere',
    'never reveal',
    'not mechanically guarantee',
    'Если это не секрет, сообщите в чате или выберите действие в Inspector'
  ]],
  ['final report', 'agent-integrations/_shared/final-report-contract.md', [
    'specific blocked item and reason',
    'mask the value',
    'blocked_by_user_scope',
    'not guarantee that an arbitrary'
  ]],
  ['workflow guide', 'docs/agent-task-workflow.md', [
    'recording-blockers.js list',
    'recording-blockers.js resolve --id=<id> --scope=once --reason=<reason> --confirmed=true',
    'recording-blockers.js resolve --id=<id> --scope=project --reason=<reason> --confirmed=true',
    'recording-blockers.js revoke',
    'blocked_by_user_scope blocker is not',
    'never disclose the value'
  ]],
  ['Quick Start', 'Quick-Start.md', [
    'recording-blockers.js list',
    'blocked item and reason',
    'blocked_by_user_scope',
    'не секрет, сообщите в чате или выберите действие в Inspector'
  ]],
  ['Devin bridge', 'agent-integrations/devin/rules/knowledge.rules', [
    'recording-blockers.js list',
    'blocked_by_user_scope',
    'never bypass the scope'
  ]],
  ['Windsurf bridge', 'agent-integrations/windsurf/rules/knowledge.md', [
    'recording-blockers.js list',
    'blocked_by_user_scope',
    'never bypass the scope'
  ]],
  ['OpenCode task command', 'agent-integrations/opencode/commands/kb-task.md', [
    'recording-blockers.js list',
    'blocked_by_user_scope',
    'cannot mechanically guarantee'
  ]]
];

const checks = [];
for (const [label, relativePath, needles] of required) {
  const content = normalize(fs.readFileSync(path.join(root, relativePath), 'utf8'));
  for (const needle of needles) {
    checks.push({ label, needle, pass: content.includes(normalize(needle)) });
  }
}

const result = {
  schema_version: 'recording-blocker-contract-self-test.v1',
  checks_total: checks.length,
  checks_passed: checks.filter((check) => check.pass).length,
  status: checks.every((check) => check.pass) ? 'pass' : 'fail',
  checks
};
console.log(JSON.stringify(result, null, 2));
if (result.status !== 'pass') process.exitCode = 1;
