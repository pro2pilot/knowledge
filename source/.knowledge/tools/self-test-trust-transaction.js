#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const {
  commitJsonTransaction,
  recoverTransactions,
  __test
} = require('./lib/json-transaction');

function assert(value, message) {
  if (!value) throw new Error(message);
}
function json(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}
function read(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function state(files) {
  return files.map((file) => read(file).generation);
}
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
function prepareFault(root, name, faultAt, count = 1) {
  const stateRoot = path.join(root, name, '.knowledge');
  const files = Array.from({ length: count }, (_, index) =>
    path.join(stateRoot, index === 0 ? 'freshness.json' : `maintenance/state-${index}.json`));
  files.forEach((file) => json(file, { generation: 'old', file: path.basename(file) }));
  const transactionId = `tx-${name}`;
  let captured = null;
  try {
    commitJsonTransaction({
      stateRoot,
      transactionId,
      faultAt,
      writes: files.map((file) => ({
        path: file,
        containmentRoot: stateRoot,
        value: { generation: 'new', file: path.basename(file) }
      }))
    });
  } catch (error) {
    captured = error;
  }
  assert(captured?.code === 'transaction_fault_injected', `${name}: expected injected fault at ${faultAt}`);
  return {
    stateRoot,
    files,
    transactionId,
    txRoot: path.join(stateRoot, 'maintenance', 'transactions', transactionId)
  };
}
function expectRecoveryError(stateRoot, code, message) {
  let captured = null;
  try { recoverTransactions(stateRoot); } catch (error) { captured = error; }
  assert(captured?.code === code, `${message}: expected ${code}, received ${captured?.code || 'no error'}`);
  return captured;
}

function runFault(root, name, faultAt, expected) {
  const stateRoot = path.join(root, name, '.knowledge');
  const files = ['freshness.json', 'maintenance/repair_queue.json', 'maintenance/trust_report.json']
    .map((relative) => path.join(stateRoot, relative));
  files.forEach((file) => json(file, { generation: 'old', file: path.basename(file) }));
  let fault = null;
  try {
    commitJsonTransaction({
      stateRoot,
      transactionId: `tx-${name}`,
      faultAt,
      writes: files.map((file) => ({
        path: file,
        containmentRoot: stateRoot,
        value: { generation: 'new', file: path.basename(file) }
      }))
    });
  } catch (error) {
    fault = error;
  }
  assert(fault?.code === 'transaction_fault_injected', `${name}: expected injected fault at ${faultAt}`);
  const recovered = recoverTransactions(stateRoot);
  const actual = state(files);
  assert(actual.every((value) => value === expected), `${name}: recovery produced mixed or wrong state ${JSON.stringify(actual)}, expected ${expected}`);
  assert(recoverTransactions(stateRoot).length === 0, `${name}: replay was not idempotent`);
  return { fault_at: faultAt, recovered: recovered[0]?.recovery_action || 'already_committed', final_state: expected };
}

function junctionCase(root) {
  const stateRoot = path.join(root, 'junction', '.knowledge');
  const outside = path.join(root, 'outside');
  const link = path.join(stateRoot, 'maintenance', 'linked');
  fs.mkdirSync(outside, { recursive: true });
  fs.mkdirSync(path.dirname(link), { recursive: true });
  fs.symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
  let blocked = null;
  try {
    commitJsonTransaction({
      stateRoot,
      transactionId: 'tx-junction',
      writes: [{
        path: path.join(link, 'escaped.json'),
        containmentRoot: stateRoot,
        value: { unsafe: true }
      }]
    });
  } catch (error) {
    blocked = error;
  }
  assert(blocked?.code === 'transaction_reparse_path', `junction/reparse target was not blocked: ${blocked?.message || 'no error'}`);
  assert(!fs.existsSync(path.join(outside, 'escaped.json')), 'junction/reparse test wrote outside the state root');
  return { status: 'blocked', error_code: blocked.code };
}

function containmentRootJunctionCase(root) {
  const projectRoot = path.join(root, 'containment-root-junction');
  const stateRoot = path.join(projectRoot, '.knowledge');
  const outside = path.join(root, 'containment-root-outside');
  const linkedContainment = path.join(stateRoot, 'settings');
  fs.mkdirSync(stateRoot, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  fs.symlinkSync(
    outside,
    linkedContainment,
    process.platform === 'win32' ? 'junction' : 'dir'
  );
  let blocked = null;
  try {
    commitJsonTransaction({
      stateRoot,
      transactionId: 'tx-containment-root-junction',
      allowedContainmentRoots: [projectRoot],
      writes: [{
        path: path.join(linkedContainment, 'escaped.json'),
        containmentRoot: linkedContainment,
        value: { unsafe: true }
      }]
    });
  } catch (error) {
    blocked = error;
  }
  assert(
    blocked?.code === 'transaction_reparse_path',
    `junction containment root was not blocked: ${
      blocked?.message || 'no error'
    }`
  );
  assert(
    !fs.existsSync(path.join(outside, 'escaped.json')),
    'junction containment root wrote outside the trusted project root'
  );
  return { status: 'blocked', error_code: blocked.code };
}

function tamperedBackupCase(root) {
  const fixture = prepareFault(root, 'tampered-backup', 'after_prepare_manifest');
  fs.writeFileSync(path.join(fixture.txRoot, 'backups', '000.old'), JSON.stringify({ generation: 'tampered' }));
  expectRecoveryError(fixture.stateRoot, 'transaction_backup_corrupt', 'tampered backup was accepted');
  assert(state(fixture.files).every((value) => value === 'old'), 'tampered backup changed an old target');
  assert(read(path.join(fixture.txRoot, 'manifest.json')).status === 'prepared', 'tampered backup was marked rolled back');
  return { status: 'blocked', error_code: 'transaction_backup_corrupt', targets_mutated: 0 };
}

function invalidMarkerCase(root) {
  const fixture = prepareFault(root, 'invalid-marker', 'after_commit_marker');
  fs.writeFileSync(path.join(fixture.txRoot, 'commit.json'), '{invalid-json', 'utf8');
  expectRecoveryError(fixture.stateRoot, 'transaction_commit_marker_invalid', 'invalid commit marker was accepted');
  assert(state(fixture.files).every((value) => value === 'old'), 'invalid marker promoted a target');
  return { status: 'blocked', error_code: 'transaction_commit_marker_invalid', targets_mutated: 0 };
}

function markerIdentityMismatchCase(root) {
  const fixture = prepareFault(root, 'marker-id-mismatch', 'after_commit_marker');
  const markerPath = path.join(fixture.txRoot, 'commit.json');
  const marker = read(markerPath);
  marker.transaction_id = 'tx-other';
  json(markerPath, marker);
  expectRecoveryError(fixture.stateRoot, 'transaction_commit_marker_invalid', 'marker transaction-ID mismatch was accepted');
  assert(state(fixture.files).every((value) => value === 'old'), 'mismatched marker promoted a target');
  return { status: 'blocked', error_code: 'transaction_commit_marker_invalid', targets_mutated: 0 };
}

function manifestHashMismatchCase(root) {
  const fixture = prepareFault(root, 'manifest-hash-mismatch', 'after_commit_marker');
  const manifestPath = path.join(fixture.txRoot, 'manifest.json');
  const marker = read(path.join(fixture.txRoot, 'commit.json'));
  const manifest = read(manifestPath);
  manifest.prepared_at = '2026-07-29T00:00:00.000Z';
  json(manifestPath, manifest);
  const actualHash = sha256(fs.readFileSync(manifestPath));
  assert(actualHash !== marker.manifest_sha256, 'manifest tamper fixture did not change the marker-bound hash');
  expectRecoveryError(fixture.stateRoot, 'transaction_manifest_hash_mismatch', 'manifest hash mismatch was accepted');
  assert(state(fixture.files).every((value) => value === 'old'), 'manifest hash mismatch promoted a target');
  return { status: 'blocked', error_code: 'transaction_manifest_hash_mismatch', targets_mutated: 0 };
}

function untrustedContainmentCase(root) {
  const fixture = prepareFault(root, 'untrusted-containment', 'after_prepare_manifest');
  const outsideRoot = path.join(root, 'untrusted-containment-outside');
  const outsideTarget = path.join(outsideRoot, 'freshness.json');
  fs.mkdirSync(outsideRoot, { recursive: true });
  fs.copyFileSync(fixture.files[0], outsideTarget);
  const manifestFile = path.join(fixture.txRoot, 'manifest.json');
  const manifest = read(manifestFile);
  const forged = {
    ...manifest.intent.writes[0],
    target: outsideTarget,
    target_relative: 'freshness.json',
    containment_root: outsideRoot
  };
  manifest.writes[0] = { ...manifest.writes[0], ...forged };
  manifest.intent.writes[0] = forged;
  manifest.intent_sha256 = __test.intentHash(manifest.intent);
  json(manifestFile, manifest);
  expectRecoveryError(
    fixture.stateRoot,
    'transaction_containment_untrusted',
    'journal-controlled containment root escaped trusted recovery roots'
  );
  assert(read(outsideTarget).generation === 'old', 'untrusted containment recovery mutated an outside target');
  assert(state(fixture.files).every((value) => value === 'old'), 'untrusted containment recovery mutated a trusted target');
  return {
    status: 'blocked',
    error_code: 'transaction_containment_untrusted',
    outside_target_mutated: false
  };
}

function terminalStatusTamperCase(root) {
  const fixture = prepareFault(root, 'terminal-status-tamper', 'after_commit_marker');
  const manifestFile = path.join(fixture.txRoot, 'manifest.json');
  const manifest = read(manifestFile);
  manifest.status = 'committed';
  json(manifestFile, manifest);
  expectRecoveryError(
    fixture.stateRoot,
    'transaction_manifest_invalid',
    'terminal status without a terminal marker bypassed recovery'
  );
  assert(state(fixture.files).every((value) => value === 'old'), 'terminal-status tamper promoted a target');
  return {
    status: 'blocked',
    error_code: 'transaction_manifest_invalid',
    targets_mutated: 0
  };
}

function transactionIntentReplayCase(root) {
  const stateRoot = path.join(root, 'intent-replay', '.knowledge');
  const firstTarget = path.join(stateRoot, 'freshness.json');
  const secondTarget = path.join(stateRoot, 'maintenance', 'other.json');
  json(firstTarget, { generation: 'old' });
  json(secondTarget, { generation: 'old' });
  const transactionId = 'tx-intent-replay';
  const firstRequest = {
    stateRoot,
    transactionId,
    metadata: { purpose: 'intent-binding' },
    writes: [{
      path: firstTarget,
      containmentRoot: stateRoot,
      value: { generation: 'new-a' }
    }]
  };
  const committed = commitJsonTransaction(firstRequest);
  assert(committed.status === 'committed', 'intent replay fixture did not commit');
  const replay = commitJsonTransaction(firstRequest);
  assert(replay.idempotent === true, 'identical transaction intent was not idempotent');

  let bodyMismatch = null;
  try {
    commitJsonTransaction({
      ...firstRequest,
      writes: [{
        path: firstTarget,
        containmentRoot: stateRoot,
        value: { generation: 'new-b' }
      }]
    });
  } catch (error) {
    bodyMismatch = error;
  }
  assert(bodyMismatch?.code === 'transaction_intent_mismatch', 'same ID accepted a different body');

  let targetMismatch = null;
  try {
    commitJsonTransaction({
      ...firstRequest,
      writes: [{
        path: secondTarget,
        containmentRoot: stateRoot,
        value: { generation: 'new-a' }
      }]
    });
  } catch (error) {
    targetMismatch = error;
  }
  assert(targetMismatch?.code === 'transaction_intent_mismatch', 'same ID accepted a different target');
  assert(read(firstTarget).generation === 'new-a', 'intent mismatch changed the committed target');
  assert(read(secondTarget).generation === 'old', 'intent mismatch changed a different target');
  return {
    status: 'blocked',
    body_error_code: bodyMismatch.code,
    target_error_code: targetMismatch.code,
    identical_replay_idempotent: true
  };
}

function lateStagedCorruptionCase(root) {
  const fixture = prepareFault(root, 'late-staged-corrupt', 'after_commit_marker', 3);
  fs.writeFileSync(path.join(fixture.txRoot, 'staged', '002.new'), JSON.stringify({ generation: 'tampered' }));
  expectRecoveryError(fixture.stateRoot, 'transaction_staged_corrupt', 'late staged corruption was accepted');
  assert(state(fixture.files).every((value) => value === 'old'), 'preflight failure left a partially promoted transaction');
  return { status: 'blocked', error_code: 'transaction_staged_corrupt', targets_mutated: 0 };
}

function journalPathEscapeCase(root) {
  const fixture = prepareFault(root, 'journal-path-escape', 'after_prepare_manifest');
  const manifestPath = path.join(fixture.txRoot, 'manifest.json');
  const manifest = read(manifestPath);
  manifest.writes[0].backup = '../../outside.old';
  json(manifestPath, manifest);
  expectRecoveryError(fixture.stateRoot, 'transaction_manifest_invalid', 'journal path escape was accepted');
  assert(state(fixture.files).every((value) => value === 'old'), 'journal path escape changed a target');
  return { status: 'blocked', error_code: 'transaction_manifest_invalid', targets_mutated: 0 };
}

function precommitTargetDriftCase(root) {
  const fixture = prepareFault(root, 'precommit-target-drift', 'after_prepare_manifest');
  json(fixture.files[0], { generation: 'external-drift', file: path.basename(fixture.files[0]) });
  expectRecoveryError(fixture.stateRoot, 'transaction_precommit_target_drift', 'pre-commit target drift was overwritten');
  assert(state(fixture.files)[0] === 'external-drift', 'recovery rewrote a drifted pre-commit target from backup');
  return { status: 'blocked', error_code: 'transaction_precommit_target_drift', recovery_writes: 0 };
}

function postIntentTargetDriftCase(root) {
  const fixture = prepareFault(root, 'post-intent-target-drift', 'after_commit_marker');
  json(fixture.files[0], {
    generation: 'external-after-intent',
    file: path.basename(fixture.files[0])
  });
  expectRecoveryError(
    fixture.stateRoot,
    'transaction_recovery_target_drift',
    'post-intent external target drift was overwritten'
  );
  assert(
    state(fixture.files)[0] === 'external-after-intent',
    'recovery overwrote a post-intent external target'
  );
  return {
    status: 'blocked',
    error_code: 'transaction_recovery_target_drift',
    recovery_writes: 0
  };
}

function duplicateTargetCase(root) {
  const stateRoot = path.join(root, 'duplicate-target', '.knowledge');
  const target = path.join(stateRoot, 'freshness.json');
  json(target, { generation: 'old' });
  let captured = null;
  try {
    commitJsonTransaction({
      stateRoot,
      transactionId: 'tx-duplicate-target',
      writes: [
        { path: target, containmentRoot: stateRoot, value: { generation: 'new-a' } },
        {
          path: path.join(path.dirname(target), '.', path.basename(target)),
          containmentRoot: stateRoot,
          value: { generation: 'new-b' }
        }
      ]
    });
  } catch (error) {
    captured = error;
  }
  assert(
    captured?.code === 'transaction_duplicate_target',
    `duplicate target was not rejected: ${captured?.message || 'no error'}`
  );
  assert(read(target).generation === 'old', 'duplicate-target rejection mutated the target');
  assert(
    !fs.existsSync(path.join(stateRoot, 'maintenance', 'transactions', 'tx-duplicate-target')),
    'duplicate-target rejection created a partial journal'
  );
  return { status: 'blocked', error_code: captured.code, target_mutated: false };
}

function rolledBackRetryArchiveCase(root) {
  const stateRoot = path.join(root, 'rolled-back-retry-archive', '.knowledge');
  const target = path.join(stateRoot, 'freshness.json');
  json(target, { generation: 'old' });
  const request = {
    stateRoot,
    transactionId: 'tx-rolled-back-retry',
    writes: [{
      path: target,
      containmentRoot: stateRoot,
      value: { generation: 'new' }
    }]
  };
  let captured = null;
  try {
    commitJsonTransaction({
      ...request,
      faultAt: 'after_initial_manifest'
    });
  } catch (error) {
    captured = error;
  }
  assert(
    captured?.code === 'transaction_fault_injected',
    'rolled-back retry fixture did not stop before commit intent'
  );
  const retried = commitJsonTransaction(request);
  assert(retried.status === 'committed', 'rolled-back deterministic retry did not commit');
  assert(read(target).generation === 'new', 'rolled-back deterministic retry changed no target');
  const archiveRoot = path.join(
    stateRoot,
    'maintenance',
    'transactions',
    'archives'
  );
  const archives = fs.readdirSync(archiveRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory());
  assert(archives.length === 1, 'rolled-back transaction was not archived exactly once');
  const archivedRoot = path.join(archiveRoot, archives[0].name);
  assert(
    read(path.join(archivedRoot, 'manifest.json')).transaction_id === request.transactionId,
    'archive lost the original transaction identity'
  );
  assert(
    read(path.join(archivedRoot, 'terminal.json')).status === 'rolled_back',
    'archive is not terminally rolled back'
  );
  assert(
    recoverTransactions(stateRoot).length === 0,
    'generic recovery attempted to replay a rolled-back archive'
  );
  return {
    status: 'pass',
    retry_committed: true,
    archived_attempts: archives.length,
    subsequent_recovery_idempotent: true
  };
}

function reservedTransactionIdCase(root) {
  const stateRoot = path.join(root, 'reserved-transaction-id', '.knowledge');
  const target = path.join(stateRoot, 'freshness.json');
  json(target, { generation: 'old' });
  let captured = null;
  try {
    commitJsonTransaction({
      stateRoot,
      transactionId: 'Archives',
      faultAt: 'after_commit_marker',
      writes: [{
        path: target,
        containmentRoot: stateRoot,
        value: { generation: 'new' }
      }]
    });
  } catch (error) {
    captured = error;
  }
  assert(
    captured?.code === 'transaction_id_reserved',
    `reserved transaction ID was not rejected: ${captured?.message || 'no error'}`
  );
  assert(read(target).generation === 'old', 'reserved transaction ID mutated its target');
  assert(
    !fs.existsSync(path.join(stateRoot, 'maintenance', 'transactions')),
    'reserved transaction ID created a transaction registry'
  );
  return {
    status: 'blocked',
    error_code: captured.code,
    target_mutated: false
  };
}

function guardedReadSetDriftCase(root) {
  const stateRoot = path.join(root, 'guarded-read-set-drift', '.knowledge');
  const target = path.join(stateRoot, 'freshness.json');
  const guarded = path.join(root, 'guarded-read-set-drift', 'src', 'auth.js');
  json(target, { generation: 'old' });
  fs.mkdirSync(path.dirname(guarded), { recursive: true });
  fs.writeFileSync(guarded, 'module.exports = { ok: true };\n', 'utf8');
  const expected = crypto.createHash('sha256').update(fs.readFileSync(guarded)).digest('hex');
  const request = {
    stateRoot,
    transactionId: 'tx-guarded-read-set',
    allowedContainmentRoots: [path.dirname(path.dirname(guarded))],
    guards: [{
      path: guarded,
      containmentRoot: path.dirname(path.dirname(guarded)),
      expected_sha256: expected
    }],
    writes: [{
      path: target,
      containmentRoot: stateRoot,
      value: { generation: 'new' }
    }]
  };
  let injected = null;
  try {
    commitJsonTransaction({ ...request, faultAt: 'after_prepare_manifest' });
  } catch (error) {
    injected = error;
  }
  assert(
    injected?.code === 'transaction_fault_injected',
    'guarded transaction did not pause before commit intent'
  );
  fs.writeFileSync(guarded, 'module.exports = { ok: false };\n', 'utf8');
  let captured = null;
  try {
    commitJsonTransaction(request);
  } catch (error) {
    captured = error;
  }
  assert(
    captured?.code === 'transaction_guard_drift',
    `read-set drift was not rejected: ${captured?.message || 'no error'}`
  );
  assert(read(target).generation === 'old', 'read-set drift allowed a target mutation');
  return {
    status: 'blocked',
    error_code: captured.code,
    target_mutated: false
  };
}

function guardedRecoveryDriftCase(root) {
  const stateRoot = path.join(root, 'guarded-recovery-drift', '.knowledge');
  const target = path.join(stateRoot, 'freshness.json');
  const guarded = path.join(root, 'guarded-recovery-drift', 'src', 'auth.js');
  json(target, { generation: 'old' });
  fs.mkdirSync(path.dirname(guarded), { recursive: true });
  fs.writeFileSync(guarded, 'module.exports = { ok: true };\n', 'utf8');
  const repositoryRoot = path.dirname(path.dirname(guarded));
  const expected = crypto.createHash('sha256').update(fs.readFileSync(guarded)).digest('hex');
  let injected = null;
  try {
    commitJsonTransaction({
      stateRoot,
      transactionId: 'tx-guarded-recovery',
      allowedContainmentRoots: [repositoryRoot],
      guards: [{
        path: guarded,
        containmentRoot: repositoryRoot,
        expected_sha256: expected
      }],
      writes: [{
        path: target,
        containmentRoot: stateRoot,
        value: { generation: 'new' }
      }],
      faultAt: 'after_commit_marker'
    });
  } catch (error) {
    injected = error;
  }
  assert(
    injected?.code === 'transaction_fault_injected',
    'guarded recovery fixture did not stop after commit intent'
  );
  fs.writeFileSync(guarded, 'module.exports = { ok: false };\n', 'utf8');
  const recovered = recoverTransactions(stateRoot, {
    allowedContainmentRoots: [repositoryRoot]
  });
  assert(
    recovered.length === 1 &&
    recovered[0].status === 'guard_failed' &&
    recovered[0].recovery_action === 'rolled_back_guard_drift',
    'post-intent guard drift was not rolled back during recovery'
  );
  assert(
    read(target).generation === 'old',
    'post-intent guard drift recovered a stale trust transition'
  );
  const terminal = read(path.join(
    stateRoot,
    'maintenance',
    'transactions',
    'tx-guarded-recovery',
    'terminal.json'
  ));
  assert(terminal.status === 'guard_failed', 'guard failure was not terminally recorded');
  return {
    status: 'blocked',
    error_code: 'transaction_guard_drift',
    recovery_action: recovered[0].recovery_action,
    target_mutated: false
  };
}

function missingGuardTransitionCase(root) {
  const stateRoot = path.join(root, 'missing-guard-transition', '.knowledge');
  const repositoryRoot = path.dirname(stateRoot);
  const target = path.join(stateRoot, 'freshness.json');
  const guardedMissing = path.join(repositoryRoot, 'src', 'appeared.js');
  json(target, { generation: 'old' });
  const blockedRequest = {
    stateRoot,
    transactionId: 'tx-missing-guard-appeared',
    allowedContainmentRoots: [repositoryRoot],
    guards: [{
      path: guardedMissing,
      containmentRoot: repositoryRoot,
      expected_exists: false
    }],
    writes: [{
      path: target,
      containmentRoot: stateRoot,
      value: { generation: 'new' }
    }]
  };
  let injected = null;
  try {
    commitJsonTransaction({
      ...blockedRequest,
      faultAt: 'after_prepare_manifest'
    });
  } catch (error) {
    injected = error;
  }
  assert(
    injected?.code === 'transaction_fault_injected',
    'missing guard fixture did not pause before commit intent'
  );
  fs.mkdirSync(path.dirname(guardedMissing), { recursive: true });
  fs.writeFileSync(guardedMissing, 'appeared outside transaction\n', 'utf8');
  let appeared = null;
  try {
    commitJsonTransaction(blockedRequest);
  } catch (error) {
    appeared = error;
  }
  assert(
    appeared?.code === 'transaction_guard_drift' &&
    read(target).generation === 'old',
    'unexpected file appearance bypassed a missing-state guard'
  );

  const createdByTransaction = path.join(
    stateRoot,
    'maintenance',
    'new-runtime.json'
  );
  const committed = commitJsonTransaction({
    stateRoot,
    transactionId: 'tx-missing-guard-bound-write',
    guards: [{
      path: createdByTransaction,
      containmentRoot: stateRoot,
      expected_exists: false
    }],
    writes: [{
      path: createdByTransaction,
      containmentRoot: stateRoot,
      value: { generation: 'transaction-created' }
    }]
  });
  assert(
    committed.status === 'committed' &&
    read(createdByTransaction).generation === 'transaction-created',
    'bound transaction could not promote its own missing-state target'
  );
  return {
    status: 'pass',
    appeared_outside_transaction: 'blocked',
    appeared_error_code: appeared.code,
    bound_write_committed: true
  };
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-trust-transaction-'));
  const checks = [];
  try {
    const preCommit = [
      'after_initial_manifest',
      'after_stage_0',
      'after_stage_1',
      'after_stage_2',
      'after_prepare_manifest'
    ];
    const postCommit = [
      'after_commit_marker',
      'after_promote_0',
      'after_promote_1',
      'after_promote_2',
      'after_committed_manifest'
    ];
    preCommit.forEach((point, index) => checks.push(runFault(root, `old-${index}`, point, 'old')));
    postCommit.forEach((point, index) => checks.push(runFault(root, `new-${index}`, point, 'new')));
    checks.push({ junction_reparse: junctionCase(root) });
    const integrityChecks = {
      tampered_backup: tamperedBackupCase(root),
      invalid_marker: invalidMarkerCase(root),
      marker_identity_mismatch: markerIdentityMismatchCase(root),
      manifest_hash_mismatch: manifestHashMismatchCase(root),
      late_staged_corruption: lateStagedCorruptionCase(root),
      journal_path_escape: journalPathEscapeCase(root),
      precommit_target_drift: precommitTargetDriftCase(root),
      post_intent_target_drift: postIntentTargetDriftCase(root),
      duplicate_target: duplicateTargetCase(root),
      untrusted_containment: untrustedContainmentCase(root),
      terminal_status_tamper: terminalStatusTamperCase(root),
      transaction_intent_replay: transactionIntentReplayCase(root),
      rolled_back_retry_archive: rolledBackRetryArchiveCase(root),
      reserved_transaction_id: reservedTransactionIdCase(root),
      guarded_read_set_drift: guardedReadSetDriftCase(root),
      guarded_recovery_drift: guardedRecoveryDriftCase(root),
      missing_guard_transition: missingGuardTransitionCase(root),
      junction_containment_root: containmentRootJunctionCase(root)
    };
    checks.push({ integrity: integrityChecks });
    console.log(JSON.stringify({
      schema_version: 'knowledge-trust-transaction-test.v1',
      status: 'pass',
      fault_injection_points: preCommit.length + postCommit.length,
      partial_state_recoveries: preCommit.length + postCommit.length,
      integrity_tamper_checks: Object.keys(integrityChecks).length,
      mixed_states: 0,
      checks,
      fixture_cleaned: true
    }, null, 2));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
