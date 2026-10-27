'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const protocol = require('./command-windows-protocol');
const { readStableJson } = require('./stable-file');
const { assertSafeContainmentRoot, assertSafeContainedPath } = require('./json-store');
const failure = code => Object.assign(new Error(code), { code });
function createStore(scopeId) {
  if (process.platform !== 'win32' || !protocol.HEX.test(scopeId || '')) throw failure('command_windows_receipt_store_invalid');
  const temporary = assertSafeContainmentRoot(path.resolve(os.tmpdir()));
  const directory = path.join(temporary, `knowledge-command-receipt-${scopeId}`);
  fs.mkdirSync(directory, { mode: 0o700 });
  const stat = fs.lstatSync(directory, { bigint: true });
  const store = { directory, dev: String(stat.dev), ino: String(stat.ino), scope_id: scopeId };
  checkStore(store); return store;
}
function checkStore(store) {
  if (!protocol.validStore(store)) throw failure('command_windows_receipt_store_invalid');
  assertSafeContainmentRoot(store.directory);
  const st = fs.lstatSync(store.directory, { bigint: true });
  if (!st.isDirectory() || st.isSymbolicLink() || String(st.dev) !== store.dev || String(st.ino) !== store.ino) throw failure('command_windows_receipt_store_changed');
}
function readRole(scope, role) {
  if (!protocol.validateScope(scope) || !scope.descriptor.secondary || !['primary', 'secondary'].includes(role)) throw failure('command_windows_receipt_invalid');
  const store = scope.descriptor.receipt_store; checkStore(store);
  const value = readStableJson(store.directory, path.join(store.directory, `${role}.closed.json`), { maxBytes: protocol.MAX_BYTES });
  checkStore(store);
  if (!protocol.validateTerminal(value, scope) || value.body.role !== role) throw failure('command_windows_receipt_invalid');
  return value;
}
function readTerminal(scope) {
  const failures = [];
  for (const role of ['primary', 'secondary']) {
    try { const value = readRole(scope, role); return { status: 'completed', method: 'windows_job_object',
      basis: 'signed_terminal_receipt', receipt_sha256: protocol.digest(value), holder_role: role,
      root_exited: true, active_processes: 0, admission_sealed: true }; }
    catch (error) { failures.push({ role, code: error.code || 'command_windows_receipt_unconfirmed' }); }
  }
  return { status: 'unconfirmed', method: 'windows_job_object', code: 'command_windows_receipt_missing_or_invalid', observations: failures };
}
function publishTerminal(scope, role, observation, privateKey) {
  const value = protocol.signTerminal(scope, role, observation, privateKey);
  const store = scope.descriptor.receipt_store; checkStore(store);
  try { return readRole(scope, role); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const temporary = path.join(store.directory, `.${role}-${crypto.randomBytes(16).toString('hex')}.tmp`);
  const target = path.join(store.directory, `${role}.closed.json`);
  assertSafeContainedPath(store.directory, temporary, { allowMissing: true });
  assertSafeContainedPath(store.directory, target, { allowMissing: true });
  let fd, own;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
    own = fs.fstatSync(fd, { bigint: true });
    fs.writeFileSync(fd, protocol.canonical(value) + '\n'); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    checkStore(store);
    const current = fs.lstatSync(temporary, { bigint: true });
    if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1n || current.dev !== own.dev || current.ino !== own.ino) throw failure('command_windows_receipt_changed');
    // Exclusive publication never overwrites an existing unknown result.
    // A crash between link and unlink leaves a non-authoritative shared
    // temporary inode; the independent holder can still publish its file.
    fs.linkSync(temporary, target); fs.unlinkSync(temporary); own = undefined;
    const back = readRole(scope, role);
    if (protocol.canonical(back) !== protocol.canonical(value)) throw failure('command_windows_receipt_readback_mismatch');
    return back;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    if (own) {
      try {
        checkStore(store); const current = fs.lstatSync(temporary, { bigint: true });
        if (current.isFile() && !current.isSymbolicLink() && current.dev === own.dev && current.ino === own.ino) fs.unlinkSync(temporary);
      } catch {}
    }
  }
}
function cleanupTerminalStore(scope) {
  // Called only after the owning controller has observed both holder exits
  // and its caller has confirmed that no common lock still binds this scope.
  // Preflight every entry before deleting any. Incomplete/unknown files are
  // retained; a crashed writer's debris is not an automatic cleanup success.
  try {
    if (!protocol.validateScope(scope) || !scope.descriptor.secondary) throw failure('command_windows_receipt_invalid');
    const store = scope.descriptor.receipt_store; checkStore(store);
    const names = fs.readdirSync(store.directory).sort();
    if (!names.length || names.length > 2 || names.some(name => !['primary.closed.json', 'secondary.closed.json'].includes(name))) {
      throw failure('command_windows_receipt_store_unowned_entry');
    }
    const originals = names.map(name => {
      const file = path.join(store.directory, name), before = fs.lstatSync(file, { bigint: true });
      const role = name.split('.')[0]; readRole(scope, role);
      const after = fs.lstatSync(file, { bigint: true });
      if (!after.isFile() || after.isSymbolicLink() || after.nlink !== 1n ||
          !['dev', 'ino', 'size', 'mode', 'mtimeNs', 'ctimeNs'].every(key => before[key] === after[key])) throw failure('command_windows_receipt_changed');
      return { file, stat: after };
    });
    checkStore(store);
    if (JSON.stringify(fs.readdirSync(store.directory).sort()) !== JSON.stringify(names)) throw failure('command_windows_receipt_store_changed');
    for (const item of originals) {
      checkStore(store); const current = fs.lstatSync(item.file, { bigint: true });
      if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1n ||
          !['dev', 'ino', 'size', 'mode', 'mtimeNs', 'ctimeNs'].every(key => current[key] === item.stat[key])) throw failure('command_windows_receipt_changed');
      fs.unlinkSync(item.file);
    }
    checkStore(store); fs.rmdirSync(store.directory);
    return { status: 'completed', method: 'windows_terminal_receipt_store', files_removed: originals.length };
  } catch (error) {
    return { status: 'unconfirmed', method: 'windows_terminal_receipt_store', code: error.code || 'command_windows_receipt_cleanup_unconfirmed', retained_for_review: true };
  }
}
// Receipt files intentionally outlive a crash until common-lock recovery can
// consume their proof. This module never treats Job-name absence as closure,
// never garbage-collects unknown files and never recursively deletes a store.
module.exports = { createStore, checkStore, readRole, readTerminal, publishTerminal, cleanupTerminalStore };
