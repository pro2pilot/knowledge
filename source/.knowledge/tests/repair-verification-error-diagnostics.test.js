'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { verificationFailureDetails } = require('../tools/self-test-repair-on-touch').__test;

test('lock timeout assertion preserves the original lock and owner message and stack', () => {
  const error = Object.assign(new Error('Lock "verification-control" is held by pid 123 on host "fixture".'), {
    code: 'lock_timeout', owner_disposition: 'owner_pid_scope_mismatch', recovery_required: 'native_scope_evidence'
  });
  const result = verificationFailureDetails(error);
  assert.equal(result.code, 'lock_timeout');
  assert.equal(result.message, error.message);
  assert.equal(result.stack, error.stack);
  assert.equal(result.lock_release_error, null);
  assert.equal(result.lock_cleanup_error, null);
  assert.equal(result.owner_disposition, 'owner_pid_scope_mismatch');
  assert.equal(result.recovery_required, 'native_scope_evidence');
});

test('primary typed refusal and separate release or cleanup failure remain distinguishable', () => {
  const error = Object.assign(new Error('Typed alias refusal'), {
    code: 'verification_node_executable_alias_unsafe',
    lock_release_error: 'lock_ownership_changed',
    lock_cleanup_error: 'unsafe_lock_path'
  });
  const result = verificationFailureDetails(error);
  assert.equal(result.code, 'verification_node_executable_alias_unsafe');
  assert.equal(result.lock_release_error, 'lock_ownership_changed');
  assert.equal(result.lock_cleanup_error, 'unsafe_lock_path');
});

test('diagnostic formatting excludes arbitrary error payloads and remains JSON serializable', () => {
  const error = Object.assign(new Error('Original failure'), {
    code: 'lock_timeout', owner_token: 'must-not-be-printed',
    request: { private_value: 'must-not-be-printed' }, lock_release_error: { unexpected: true }
  });
  error.circular = error;
  const result = verificationFailureDetails(error);
  assert.deepEqual(Object.keys(result), ['code', 'message', 'stack', 'lock_release_error', 'lock_cleanup_error', 'owner_disposition', 'recovery_required']);
  assert.equal(result.lock_release_error, null);
  assert.equal(JSON.stringify(result).includes('must-not-be-printed'), false);
  assert.deepEqual(verificationFailureDetails(null), {
    code: null, message: null, stack: null, lock_release_error: null, lock_cleanup_error: null, owner_disposition: null, recovery_required: null
  });
});
