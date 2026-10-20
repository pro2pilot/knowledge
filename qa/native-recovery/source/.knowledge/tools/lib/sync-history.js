'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertSafeContainedPath, containedPath } = require('./json-store');
const { commitJsonTransaction, copyInertData } = require('./json-transaction');

function readQueueSnapshot(stateRoot, filePath, fallback) {
  fallback = copyInertData(fallback);
  stateRoot = path.resolve(stateRoot);
  filePath = path.resolve(filePath);
  if (!containedPath(stateRoot, filePath)) {
    const error = new Error('Sync queue input is outside its state root.');
    error.code = 'sync_input_invalid';
    throw error;
  }
  assertSafeContainedPath(stateRoot, filePath, { allowMissing: true });
  let descriptor = null;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | Number(fs.constants.O_NOFOLLOW || 0));
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > 32n * 1024n * 1024n) {
      const error = new Error('Sync queue input must be a singly-linked contained physical file.');
      error.code = 'sync_input_invalid';
      throw error;
    }
    const body = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const live = fs.lstatSync(filePath, { bigint: true });
    assertSafeContainedPath(stateRoot, filePath);
    if (!live.isFile() || live.isSymbolicLink() || live.nlink !== 1n || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        after.dev !== live.dev || after.ino !== live.ino || after.size !== live.size ||
        after.mtimeNs !== live.mtimeNs || after.ctimeNs !== live.ctimeNs) {
      const error = new Error('Sync queue input changed while its raw read-set was captured.');
      error.code = 'sync_input_changed';
      throw error;
    }
    return {
      value: JSON.parse(body.toString('utf8').replace(/^\uFEFF/, '')),
      guard: { path: filePath, expected_sha256: crypto.createHash('sha256').update(body).digest('hex'), containmentRoot: stateRoot }
    };
  } catch (error) {
    if (error.code === 'ENOENT' && descriptor === null) return {
      value: fallback,
      guard: { path: filePath, expected_exists: false, containmentRoot: stateRoot }
    };
    throw error;
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
  }
}

function commitQueuePair(options) {
  let { stateRoot, stalePath, repairPath, staleSnapshot, repairSnapshot,
    staleItems, repairQueue, metadata = {}, transactionId, faultAt = null } = copyInertData(options);
  stateRoot = path.resolve(stateRoot);
  const exactWritePaths = [path.resolve(stalePath), path.resolve(repairPath)];
  if (exactWritePaths[0] === exactWritePaths[1] || exactWritePaths.some(file => !containedPath(stateRoot, file))) {
    const error = new Error('Sync queue transaction requires two distinct state-root outputs.');
    error.code = 'sync_write_set_invalid';
    throw error;
  }
  return commitJsonTransaction({
    stateRoot,
    transactionId: transactionId || `sync-queue-${Date.now()}-${process.pid}-${crypto.randomBytes(12).toString('hex')}`,
    allowedContainmentRoots: [stateRoot],
    allowedGuardRoots: [stateRoot],
    allowedWriteRoots: [stateRoot],
    exactWritePaths,
    guards: [staleSnapshot.guard, repairSnapshot.guard],
    metadata,
    ...(faultAt ? { faultAt } : {}),
    writes: [
      { path: exactWritePaths[0], value: staleItems, containmentRoot: stateRoot },
      { path: exactWritePaths[1], value: repairQueue, containmentRoot: stateRoot }
    ]
  });
}

function preserveHistoryRequest(argv) {
  argv = copyInertData(argv);
  if (!Array.isArray(argv) || argv.some(arg => typeof arg !== 'string')) {
    const error = new Error('Sync arguments must be an array of strings.');
    error.code = 'sync_preserve_history_argument_invalid'; throw error;
  }
  const suspicious = argv.some(arg => /^--[^=]*(?:preserv|history)/i.test(arg));
  if (!suspicious) return { preserveHistory: true, requested: null };
  const booleans = new Set(['--scan', '--discover', '--json', '--quiet', '--preserve-history']);
  const values = new Set(['--system-root', '--target-root', '--project-knowledge-root', '--state-root',
    '--mode', '--team-root', '--workspace-id', '--agent-id',
    '--systemRoot', '--targetRoot', '--projectKnowledgeRoot', '--stateRoot', '--teamRoot', '--workspaceId', '--agentId',
    '--routing-mode', '--routingMode', '--task', '--context-budget-bytes', '--contextBudgetBytes',
    '--changed-file', '--changedFile', '--changed-files', '--changedFiles']);
  const seen = new Set();
  const invalid = () => {
    const error = new Error('Invalid --preserve-history invocation: use the standalone boolean once, with only supported sync/context flags.');
    error.code = 'sync_preserve_history_argument_invalid';
    throw error;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (typeof arg !== 'string' || !arg.startsWith('--')) invalid();
    const equals = arg.indexOf('=');
    const key = equals < 0 ? arg : arg.slice(0, equals);
    if (seen.has(key)) invalid();
    seen.add(key);
    if (booleans.has(key)) {
      if (equals >= 0) invalid();
    } else if (values.has(key)) {
      const value = equals < 0 ? argv[++index] : arg.slice(equals + 1);
      if (typeof value !== 'string' || !value || value.startsWith('--')) invalid();
    } else invalid();
  }
  if (!seen.has('--preserve-history')) invalid();
  return { preserveHistory: true, requested: '--preserve-history' };
}

module.exports = { readQueueSnapshot, commitQueuePair, preserveHistoryRequest };
