#!/usr/bin/env node
'use strict';

// Exercise the exact request expression supplied to the physical public
// caller through the real, pinned policy. No broker or user work is launched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
function argument(name) {
  const i = process.argv.indexOf(name);
  assert.ok(i > 1 && process.argv[i + 1], 'explicit ' + name + ' required');
  return path.resolve(process.argv[i + 1]);
}
const source = argument('--source');
const controller = argument('--controller');
const text = fs.readFileSync(controller, 'utf8');
const expressions = [...text.matchAll(/\bconst request = ([\s\S]*?\n    });/g)];
assert.equal(expressions.length, 1, 'one exact production request declaration');
const policy = require(path.join(source, 'tools/lib/verification-policy.js'));
const makeRequest = new Function('stateRoot', 'input', 'return ' + expressions[0][1]);
function request() {
  return makeRequest('/private/qa-project/.knowledge', { project: '/private/qa-project',
    config: { binary: '/Library/PrivilegedHelperTools/qa-broker', socket: '/var/run/qa-broker.sock' } });
}

test('physical public request satisfies the exact production Darwin copy contract', () => {
  const input = request();
  const actual = policy.nativeExecutionRequest(input);
  assert.equal(actual.darwin.enabled, true);
  assert.equal(actual.darwin.mode, 'isolated_copy');
  assert.deepEqual(actual.darwin.copy, { max_files: 20000, max_bytes: 1073741824, max_file_bytes: 67108864 });
  assert.deepEqual(input.nativeExecution.darwin.copy, {});
  assert.deepEqual(input.verificationPolicy, { work_budget_ms: 240000, no_progress_ms: 0, cleanup_budget_ms: 60000 });
  const timing = policy.resolvePolicy(input.verificationPolicy, 240000);
  assert.equal(timing.work_budget_ms, 240000);
  assert.equal(timing.cleanup_budget_ms, 60000);
  assert.equal(timing.automatic_work_budget_extension, false);
  assert.deepEqual(input.tests, [{ argv: ['node', 'run.js'], cwd: '.', timeout_ms: 180000 }]);
});

test('the real policy keeps rejecting an omitted copy key', () => {
  const input = request();delete input.nativeExecution.darwin.copy;
  assert.throws(() => policy.nativeExecutionRequest(input), { code: 'verification_darwin_config_invalid' });
});
