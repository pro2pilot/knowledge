#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');
const {
  acquireContainedLock,
  withContainedLock,
  inspectLockSafety,
  inspectAllLockSafety,
  lockPaths,
  __test,
} = require('./lib/contained-lock-manager');
const { canonicalOwnerText } = require('./lib/lock-owner-schema');
const { LOCKS } = require('./lib/lock-policy');
const { writeFileAtomicContained } = require('./lib/json-store');

const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-contained-locks-'));
const results = [];

function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function assert(condition, message) { if (!condition) throw new Error(message); }
function expectCode(fn, code) {
  let caught = null;
  try { fn(); } catch (error) { caught = error; }
  assert(caught, `expected ${code}, but no error was thrown`);
  assert(caught.code === code, `expected ${code}, got ${caught.code || caught.message}`);
  return caught;
}
function run(id, fn) {
  try { fn(); results.push({ id, pass: true }); }
  catch (error) { results.push({ id, pass: false, error: error.message, code: error.code || null }); }
}
function root(name) {
  const value = path.join(fixtureRoot, name);
  fs.mkdirSync(value, { recursive: true });
  return value;
}
function request(rootPath, lockName = 'doctor', options = {}) {
  const rootKind = options.rootKind || 'state';
  return {
    rootKind,
    rootPath,
    lockName,
    purpose: LOCKS[lockName].purpose,
    timeoutMs: options.timeoutMs || 25,
    staleMs: options.staleMs || 10,
    context: options.context || {
      ...(rootKind === 'state' ? { stateRoot: rootPath } : {}),
      ...(rootKind === 'project' ? { projectKnowledgeRoot: rootPath } : {}),
      ...(rootKind === 'system' ? { systemRoot: rootPath } : {}),
    },
  };
}
function owner(lockName = 'doctor', changes = {}) {
  const now = new Date().toISOString();
  return {
    schema_version: 'knowledge-lock-owner.v1',
    lock_id: '123e4567-e89b-42d3-a456-426614174000',
    lock_name: lockName,
    purpose: LOCKS[lockName].purpose,
    pid: process.pid,
    hostname: os.hostname(),
    agent_id: null,
    workspace_id: null,
    process_started_at: now,
    acquired_at: now,
    nonce: 'a'.repeat(64),
    ...changes,
  };
}
function seed(rootPath, lockName, text, ageMs = 0) {
  const paths = lockPaths(request(rootPath, lockName));
  fs.mkdirSync(paths.lockDir, { recursive: true });
  fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), text, 'utf8');
  if (ageMs > 0) {
    const old = new Date(Date.now() - ageMs);
    fs.utimesSync(paths.lockDir, old, old);
  }
  return paths;
}
function invalidOwner(rootPath, mutate, options = {}) {
  const value = owner('doctor');
  mutate(value);
  const text = options.raw || `${JSON.stringify(value, null, 2)}\n`;
  return seed(rootPath, 'doctor', text, options.ageMs || 60_000);
}

try {
  run('valid_state_acquire_release', () => {
    const r = root('valid-state');
    const handle = acquireContainedLock(request(r));
    assert(fs.existsSync(handle.path), 'lock was not created');
    assert(handle.release().status === 'released', 'lock was not released');
    assert(!fs.existsSync(handle.path), 'lock remains after release');
  });

  run('darwin_system_temp_alias_is_canonicalized', () => {
    if (process.platform !== 'darwin') return;
    const r = root('darwin-system-temp');
    const handle = acquireContainedLock(request(r));
    assert(lockPaths(request(r)).root === fs.realpathSync(r), 'macOS system temp root was not canonicalized');
    handle.release();
  });

  run('darwin_system_temp_context_alias_matches_physical_lock_root', () => {
    if (process.platform !== 'darwin') return;
    const r = root('darwin-system-context-alias');
    const physicalRoot = fs.realpathSync(r);
    const aliasRequest = {
      ...request(r),
      rootPath: physicalRoot,
      context: { stateRoot: r },
    };
    const handle = acquireContainedLock(aliasRequest);
    assert(lockPaths(aliasRequest).root === physicalRoot, 'physical macOS lock root was not retained');
    handle.release();
  });

  run('darwin_system_temp_atomic_write_uses_physical_containment', () => {
    if (process.platform !== 'darwin') return;
    const r = root('darwin-system-atomic-write');
    const physicalRoot = fs.realpathSync(r);
    const lexicalTarget = path.join(r, 'nested', 'state.json');
    writeFileAtomicContained(lexicalTarget, 'macOS system alias\n', physicalRoot);
    assert(fs.readFileSync(lexicalTarget, 'utf8') === 'macOS system alias\n', 'macOS lexical target was not written within its physical root');
  });

  run('missing_allowed_root_is_created_safely', () => {
    const r = path.join(root('missing-root-parent'), 'nested', 'state');
    const handle = acquireContainedLock(request(r));
    assert(fs.lstatSync(r).isDirectory(), 'missing allowed root was not created');
    handle.release();
  });

  run('valid_project_acquire_release', () => {
    const r = root('valid-project');
    const handle = acquireContainedLock(request(r, 'apply-template', { rootKind: 'project' }));
    handle.release();
  });

  run('unknown_root_kind_rejected', () => {
    const r = root('unknown-root');
    expectCode(() => acquireContainedLock({ ...request(r), rootKind: 'other' }), 'unknown_lock_root_kind');
  });

  run('unknown_lock_name_rejected', () => {
    const r = root('unknown-name');
    expectCode(() => acquireContainedLock({ ...request(r), lockName: 'not-allowlisted', purpose: 'x' }), 'unknown_lock_name');
  });

  run('relative_root_rejected', () => {
    expectCode(() => acquireContainedLock({ ...request('relative'), rootPath: 'relative' }), 'lock_path_outside_state_root');
  });

  run('context_root_mismatch_rejected', () => {
    const r = root('context-mismatch');
    const other = root('context-mismatch-other');
    expectCode(() => acquireContainedLock({ ...request(r), context: { stateRoot: other } }), 'lock_root_context_mismatch');
  });

  run('timeout_outside_policy_bounds_rejected', () => {
    const r = root('timeout-policy-bound');
    expectCode(() => acquireContainedLock(request(r, 'doctor', { timeoutMs: 600001 })), 'lock_policy_limit');
  });

  run('stale_threshold_outside_policy_bounds_rejected', () => {
    const r = root('stale-policy-bound');
    expectCode(() => acquireContainedLock(request(r, 'doctor', { staleMs: 604800001 })), 'lock_policy_limit');
  });

  run('traversal_lock_name_rejected', () => {
    const r = root('traversal-name');
    expectCode(() => acquireContainedLock({ ...request(r), lockName: '../doctor' }), 'lock_name_invalid');
  });

  run('absolute_lock_name_rejected', () => {
    const r = root('absolute-name');
    expectCode(() => acquireContainedLock({ ...request(r), lockName: path.resolve(r, 'doctor') }), 'lock_name_invalid');
  });

  run('symlink_root_rejected', () => {
    const target = root('symlink-root-target');
    const link = path.join(fixtureRoot, 'symlink-root-link');
    fs.symlinkSync(target, link, 'junction');
    expectCode(() => acquireContainedLock(request(link)), 'unsafe_lock_parent');
  });

  run('legacy_directory_symlink_is_unsafe', () => {
    const r = root('legacy-symlink');
    const target = root('legacy-symlink-target');
    fs.symlinkSync(target, path.join(r, '.lock'), 'junction');
    const status = inspectLockSafety(request(r));
    assert(status.status === 'unsafe', 'legacy link was not unsafe');
    assert(status.findings.some((item) => item.code === 'unsafe_lock_path'), 'legacy link finding missing');
  });

  run('owner_symlink_is_unsafe', () => {
    const r = root('owner-symlink');
    const paths = lockPaths(request(r));
    fs.mkdirSync(paths.lockDir, { recursive: true });
    const outside = path.join(r, 'outside-owner.json');
    fs.writeFileSync(outside, canonicalOwnerText(owner()), 'utf8');
    fs.symlinkSync(outside, path.join(paths.lockDir, 'owner.json'), 'file');
    const status = inspectLockSafety(request(r));
    assert(status.findings.some((item) => item.code === 'unsafe_lock_owner'), 'owner symlink finding missing');
  });

  run('owner_hardlink_is_unsafe', () => {
    const r = root('owner-hardlink');
    const paths = lockPaths(request(r));
    fs.mkdirSync(paths.lockDir, { recursive: true });
    const outside = path.join(r, 'hardlink-source.json');
    fs.writeFileSync(outside, canonicalOwnerText(owner()), 'utf8');
    fs.linkSync(outside, path.join(paths.lockDir, 'owner.json'));
    const status = inspectLockSafety(request(r));
    assert(status.findings.some((item) => item.code === 'lock_owner_hardlinked'), 'owner hardlink finding missing');
  });

  run('malformed_owner_rejected', () => {
    const r = root('malformed');
    seed(r, 'doctor', '{secret-raw-payload', 60_000);
    const error = expectCode(() => acquireContainedLock(request(r)), 'lock_owner_invalid');
    assert(!error.message.includes('secret-raw-payload'), 'malformed payload leaked');
  });

  run('oversized_owner_rejected', () => {
    const r = root('oversized');
    seed(r, 'doctor', 'x'.repeat(4097), 60_000);
    expectCode(() => acquireContainedLock(request(r)), 'lock_owner_oversized');
  });

  run('unknown_owner_field_rejected', () => {
    const r = root('unknown-field');
    invalidOwner(r, (value) => { value.secret = 'must-not-leak'; });
    const status = inspectLockSafety(request(r));
    assert(status.status === 'unsafe', 'unknown field was accepted');
  });

  run('invalid_pid_rejected', () => {
    const r = root('invalid-pid');
    invalidOwner(r, (value) => { value.pid = 0; });
    expectCode(() => acquireContainedLock(request(r)), 'lock_owner_invalid');
  });

  run('invalid_timestamp_rejected', () => {
    const r = root('invalid-time');
    invalidOwner(r, (value) => { value.acquired_at = 'yesterday'; });
    expectCode(() => acquireContainedLock(request(r)), 'lock_owner_invalid');
  });

  run('live_owner_times_out_redacted', () => {
    const r = root('live-timeout');
    seed(r, 'doctor', canonicalOwnerText(owner('doctor', { agent_id: 'SECRET-AGENT-VALUE' })), 60_000);
    const error = expectCode(() => acquireContainedLock(request(r, 'doctor', { timeoutMs: 8 })), 'lock_timeout');
    assert(!error.message.includes('SECRET-AGENT-VALUE'), 'agent secret leaked in timeout');
    assert(!error.message.includes('nonce'), 'nonce leaked in timeout');
  });

  run('dead_local_owner_recovered', () => {
    const r = root('dead-local');
    const paths = seed(r, 'doctor', canonicalOwnerText(owner('doctor', { pid: 2147483647 })), 60_000);
    const handle = acquireContainedLock(request(r, 'doctor', { staleMs: 1 }));
    handle.release();
    assert(!fs.existsSync(paths.lockDir), 'stale lock remained');
    assert(fs.readdirSync(paths.staleRoot).length === 0, 'stale quarantine was not cleaned');
  });

  run('remote_owner_is_conservative', () => {
    const r = root('remote-active');
    seed(r, 'doctor', canonicalOwnerText(owner('doctor', { hostname: 'remote.invalid', pid: 2147483647 })), 60_000);
    expectCode(() => acquireContainedLock(request(r, 'doctor', { timeoutMs: 8 })), 'lock_timeout');
  });

  run('consumer_cannot_weaken_remote_stale_policy', () => {
    const r = root('remote-override-blocked');
    seed(r, 'doctor', canonicalOwnerText(owner('doctor', { hostname: 'remote.invalid', pid: 2147483647 })), 60_000);
    expectCode(() => acquireContainedLock({ ...request(r, 'doctor', { timeoutMs: 8 }), remoteStaleMs: 1 }), 'lock_timeout');
  });

  run('expired_remote_owner_recovered', () => {
    const r = root('remote-stale');
    seed(r, 'doctor', canonicalOwnerText(owner('doctor', { hostname: 'remote.invalid', pid: 2147483647 })), 172_800_000);
    const handle = acquireContainedLock(request(r, 'doctor'));
    handle.release();
  });

  run('nonce_change_blocks_release', () => {
    const r = root('nonce-change');
    const handle = acquireContainedLock(request(r));
    const ownerPath = path.join(handle.path, 'owner.json');
    const value = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
    value.nonce = 'b'.repeat(64);
    fs.writeFileSync(ownerPath, canonicalOwnerText(value), 'utf8');
    expectCode(() => handle.release(), 'lock_ownership_changed');
  });

  run('lock_id_change_blocks_release', () => {
    const r = root('id-change');
    const handle = acquireContainedLock(request(r));
    const ownerPath = path.join(handle.path, 'owner.json');
    const value = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
    value.lock_id = '223e4567-e89b-42d3-a456-426614174000';
    fs.writeFileSync(ownerPath, canonicalOwnerText(value), 'utf8');
    expectCode(() => handle.release(), 'lock_ownership_changed');
  });

  run('callback_result_and_release', () => {
    const r = root('callback-result');
    const value = withContainedLock(request(r), () => 42);
    assert(value === 42, 'callback result changed');
    assert(!fs.existsSync(lockPaths(request(r)).lockDir), 'callback lock remains');
  });

  run('callback_error_and_release', () => {
    const r = root('callback-error');
    const error = expectCode(() => withContainedLock(request(r), () => {
      const failure = new Error('callback failed'); failure.code = 'EXPECTED_CALLBACK'; throw failure;
    }), 'EXPECTED_CALLBACK');
    assert(error.message === 'callback failed', 'callback error changed');
    assert(!fs.existsSync(lockPaths(request(r)).lockDir), 'callback error lock remains');
  });

  run('double_release_is_idempotent', () => {
    const r = root('double-release');
    const handle = acquireContainedLock(request(r));
    handle.release();
    assert(handle.release().status === 'already_released', 'second release not idempotent');
  });

  run('task_routing_resource_id_is_required', () => {
    const r = root('task-resource-required');
    expectCode(() => acquireContainedLock(request(r, 'task-routing')), 'lock_resource_id_invalid');
  });

  run('task_routing_resource_granularity_is_preserved', () => {
    const r = root('task-resource-granularity');
    const firstHash = 'a'.repeat(64);
    const secondHash = 'b'.repeat(64);
    const base = request(r, 'task-routing');
    const first = acquireContainedLock({ ...base, resourceId: firstHash });
    const second = acquireContainedLock({ ...base, resourceId: secondHash });
    expectCode(() => acquireContainedLock({ ...base, resourceId: firstHash, timeoutMs: 8 }), 'lock_timeout');
    second.release();
    first.release();
  });

  run('all_lock_safety_clean_root', () => {
    const r = root('inspect-all-safe');
    const status = inspectAllLockSafety({ rootPath: r, rootKind: 'state' });
    assert(status.status === 'safe' && status.findings.length === 0, 'clean root not safe');
  });

  run('unknown_layout_entry_is_unsafe', () => {
    const r = root('unknown-layout');
    const paths = lockPaths(request(r));
    fs.mkdirSync(paths.versionRoot, { recursive: true });
    fs.writeFileSync(path.join(paths.versionRoot, 'unexpected.txt'), 'x', 'utf8');
    const status = inspectAllLockSafety({ rootPath: r, rootKind: 'state' });
    assert(status.findings.some((item) => item.code === 'lock_layout_unsupported'), 'unknown entry not detected');
  });

  run('unsafe_owner_is_never_recovered', () => {
    const r = root('unsafe-no-recovery');
    const paths = seed(r, 'doctor', '{malformed-secret', 86_400_000);
    expectCode(() => acquireContainedLock(request(r, 'doctor', { staleMs: 1 })), 'lock_owner_invalid');
    assert(fs.existsSync(paths.lockDir), 'unsafe owner was destructively recovered');
  });

  run('sanitized_inspector_owner', () => {
    const r = root('sanitized-owner');
    const handle = acquireContainedLock(request(r, 'doctor', { context: { stateRoot: r, agentId: 'agent-safe', workspaceId: 'workspace-private' } }));
    const status = inspectLockSafety(request(r));
    assert(status.current.owner.agent_id === 'agent-safe', 'safe agent id missing');
    assert(!Object.prototype.hasOwnProperty.call(status.current.owner, 'nonce'), 'nonce exposed');
    assert(!Object.prototype.hasOwnProperty.call(status.current.owner, 'workspace_id'), 'workspace id exposed');
    handle.release();
  });

  run('concurrent_acquisition_serializes', () => {
    const r = root('concurrent');
    const modulePath = path.join(__dirname, 'lib', 'contained-lock-manager.js');
    const policyPath = path.join(__dirname, 'lib', 'lock-policy.js');
    const script = [
      "const { acquireContainedLock } = require(process.argv[1]);",
      "const { LOCKS } = require(process.argv[2]);",
      "const root = process.argv[3];",
      "const h = acquireContainedLock({context:{stateRoot:root},rootKind:'state',rootPath:root,lockName:'doctor',purpose:LOCKS.doctor.purpose,timeoutMs:2000});",
      "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,150);",
      "h.release();",
    ].join('');
    const child = spawn(process.execPath, ['-e', script, modulePath, policyPath, r], { stdio: 'ignore', windowsHide: true });
    const lockDir = lockPaths(request(r)).lockDir;
    const deadline = Date.now() + 2000;
    while (!fs.existsSync(path.join(lockDir, 'owner.json')) && Date.now() < deadline) sleep(5);
    assert(fs.existsSync(path.join(lockDir, 'owner.json')), 'child did not acquire lock');
    const started = Date.now();
    const handle = acquireContainedLock(request(r, 'doctor', { timeoutMs: 2000 }));
    const waited = Date.now() - started;
    handle.release();
    assert(waited >= 75, `concurrent acquisition did not wait (${waited}ms)`);
    if (child.exitCode === null && child.killed) throw new Error('child lock process was killed');
  });

  run('released_lock_disappearing_during_physical_check_is_missing', () => {
    const r = root('released-during-physical-check');
    const policy = request(r, 'doctor', { timeoutMs: 2000 });
    const original = acquireContainedLock(policy);
    const paths = lockPaths(policy);
    const originalRealpath = fs.realpathSync;
    let injected = false;
    try {
      fs.realpathSync = function injectedRealpath(candidate) {
        if (!injected && path.resolve(candidate) === path.resolve(paths.lockDir)) {
          injected = true;
          const released = path.join(paths.releaseRoot, 'synthetic-release');
          fs.renameSync(paths.lockDir, released);
          fs.rmSync(released, { recursive: true, force: true });
          const error = new Error('lock directory disappeared during physical check');
          error.code = 'ENOENT';
          throw error;
        }
        return originalRealpath.apply(fs, arguments);
      };
      const inspected = __test.inspectCurrent(policy, paths);
      assert(injected, 'did not inject the lstat-to-realpath release race');
      assert(inspected.status === 'missing', `expected missing, got ${inspected.status}`);
    } finally {
      fs.realpathSync = originalRealpath;
    }
    const replacement = acquireContainedLock(policy);
    replacement.release();
    assert(!fs.existsSync(paths.lockDir), 'replacement lock remains after release');
    // The synthetic release has already removed original.path; do not invoke
    // original.release(), which must fail closed on ownership disappearance.
    assert(original.path === paths.lockDir, 'unexpected lock path changed');
  });

  run('released_owner_disappearing_during_physical_read_is_missing', () => {
    const r = root('released-owner-during-physical-read');
    const policy = request(r, 'doctor', { timeoutMs: 2000 });
    const original = acquireContainedLock(policy);
    const paths = lockPaths(policy);
    const ownerPath = path.join(paths.lockDir, 'owner.json');
    const originalRealpath = fs.realpathSync;
    let injected = false;
    try {
      fs.realpathSync = function injectedRealpath(candidate) {
        if (!injected && path.resolve(candidate) === path.resolve(ownerPath)) {
          injected = true;
          const released = path.join(paths.releaseRoot, 'synthetic-release');
          fs.renameSync(paths.lockDir, released);
          fs.rmSync(released, { recursive: true, force: true });
          const error = new Error('lock owner disappeared during physical read');
          error.code = 'ENOENT';
          throw error;
        }
        return originalRealpath.apply(fs, arguments);
      };
      const inspected = __test.inspectCurrent(policy, paths);
      assert(injected, 'did not inject the owner lstat-to-realpath release race');
      assert(inspected.status === 'missing', `expected missing, got ${inspected.status}`);
    } finally {
      fs.realpathSync = originalRealpath;
    }
    const replacement = acquireContainedLock(policy);
    replacement.release();
    assert(!fs.existsSync(paths.lockDir), 'replacement lock remains after release');
    assert(original.path === paths.lockDir, 'unexpected lock path changed');
  });

  run('released_lock_disappearing_between_validation_and_owner_read_is_missing', () => {
    const r = root('released-between-validation-and-owner-read');
    const policy = request(r, 'doctor', { timeoutMs: 2000 });
    const original = acquireContainedLock(policy);
    const paths = lockPaths(policy);
    const originalRealpath = fs.realpathSync;
    let lockDirectoryRealpaths = 0;
    let injected = false;
    try {
      fs.realpathSync = function injectedRealpath(candidate) {
        if (path.resolve(candidate) === path.resolve(paths.lockDir)) {
          lockDirectoryRealpaths += 1;
          // The first validation owns two lock-directory realpaths. Remove
          // the lock as the repeated readStrictOwner validation begins.
          if (!injected && lockDirectoryRealpaths === 3) {
            injected = true;
            const released = path.join(paths.releaseRoot, 'synthetic-release');
            fs.renameSync(paths.lockDir, released);
            fs.rmSync(released, { recursive: true, force: true });
            const error = new Error('lock disappeared between validation and owner read');
            error.code = 'ENOENT';
            throw error;
          }
        }
        return originalRealpath.apply(fs, arguments);
      };
      const inspected = __test.inspectCurrent(policy, paths);
      assert(injected, 'did not inject the validation-to-owner-read release race');
      assert(inspected.status === 'missing', `expected missing, got ${inspected.status}`);
    } finally {
      fs.realpathSync = originalRealpath;
    }
    const replacement = acquireContainedLock(policy);
    replacement.release();
    assert(!fs.existsSync(paths.lockDir), 'replacement lock remains after release');
    assert(original.path === paths.lockDir, 'unexpected lock path changed');
  });
} finally {
  try { removeTempDirStrict(fixtureRoot); }
  catch (error) { results.push({ id: 'zero_fixture_leftovers', pass: false, error: error.message, code: error.code || null }); }
}

if (!results.some((item) => item.id === 'zero_fixture_leftovers')) {
  results.push({ id: 'zero_fixture_leftovers', pass: !fs.existsSync(fixtureRoot) });
}

const report = {
  schema_version: 'knowledge-contained-lock-self-test.v1',
  generated_at: new Date().toISOString(),
  platform: process.platform,
  node: process.version,
  checks_total: results.length,
  passed_total: results.filter((item) => item.pass).length,
  failed_total: results.filter((item) => !item.pass).length,
  status: results.every((item) => item.pass) ? 'pass' : 'fail',
  results,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (report.status !== 'pass') process.exitCode = 1;
