'use strict';

// Only an isolated preparer, fixed holder or readonly query process imports
// this loader. The responsive controller never performs these filesystem
// operations, loads a compiler, or resolves a helper through PATH.
const fs = require('fs');
const path = require('path');
const os = require('os');
const { readStableFile } = require('./stable-file');
const { assertSafeContainmentRoot, assertSafeContainedPath } = require('./json-store');
const protocol = require('./command-windows-protocol');
const failure = (code, error) => Object.assign(new Error(code), { code, os_code: error?.code });
const FILENAME = 'command-windows-job.node';
const fields = ['schema_version', 'platform', 'architecture', 'napi_version', 'source_sha256', 'binary_sha256', 'binary_bytes', 'binary'];
function read(root, name, maximum) { return readStableFile(root, name, { maxBytes: maximum }); }
function id(stat) { return { dev: String(stat.dev), ino: String(stat.ino) }; }
function same(stat, expected) { return String(stat.dev) === expected.dev && String(stat.ino) === expected.ino; }
function preparePackagedHelper({ onSnapshot, verifyLoad = true } = {}) {
  if (process.platform !== 'win32' || !['x64', 'arm64'].includes(process.arch) || Number(process.versions.napi) < 8) throw failure('command_windows_platform_unavailable');
  const root = assertSafeContainmentRoot(path.resolve(__dirname, '..'));
  const directory = path.join(__dirname, 'native', `win32-${process.arch}`);
  const manifest = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(read(root, path.join(directory, 'command-windows-job.manifest.json'), 16384)));
  if (!manifest || Object.keys(manifest).sort().join(',') !== [...fields].sort().join(',') ||
      manifest.schema_version !== 'knowledge-command-windows-binary.v1' || manifest.platform !== process.platform || manifest.architecture !== process.arch ||
      manifest.napi_version !== 8 || manifest.binary !== FILENAME || !protocol.HEX.test(manifest.source_sha256 || '') ||
      !protocol.HEX.test(manifest.binary_sha256 || '') || !Number.isSafeInteger(manifest.binary_bytes) || manifest.binary_bytes < 1 || manifest.binary_bytes > 16777216) throw failure('command_windows_manifest_invalid');
  const source = read(root, path.join(root, 'native', 'command-windows-job.c'), 262144);
  const binary = read(root, path.join(directory, FILENAME), 16777216);
  if (protocol.sha(source) !== manifest.source_sha256 || protocol.sha(binary) !== manifest.binary_sha256 || binary.length !== manifest.binary_bytes) throw failure('command_windows_binary_pin_mismatch');
  const temporary = assertSafeContainmentRoot(path.resolve(os.tmpdir()));
  const snapshotDirectory = fs.mkdtempSync(path.join(temporary, 'knowledge-command-native-'));
  fs.chmodSync(snapshotDirectory, 0o700);
  const record = { backend: 'windows_job_object', platform: 'win32', architecture: process.arch,
    source_sha256: manifest.source_sha256, binary_sha256: manifest.binary_sha256, binary_bytes: binary.length,
    executable: path.join(snapshotDirectory, FILENAME), snapshot: { directory: snapshotDirectory, ...id(fs.lstatSync(snapshotDirectory, { bigint: true })) } };
  onSnapshot?.(record);
  let fd;
  try {
    fd = fs.openSync(record.executable, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o500);
    record.snapshot.file = id(fs.fstatSync(fd, { bigint: true }));
    onSnapshot?.(record);
    fs.writeFileSync(fd, binary); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.chmodSync(record.executable, 0o500);
    record.snapshot.mode = String(fs.lstatSync(record.executable, { bigint: true }).mode);
    validateSnapshot(record); if (verifyLoad) loadPreparedHelper(record);
    return Object.freeze(record);
  } catch (error) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
    error.artifact_cleanup = cleanupPreparedHelper(record, { allowIncomplete: true }); throw error;
  }
}
function admitPreparedHelper(record) {
  if (!record || record.backend !== 'windows_job_object' || record.platform !== 'win32' || record.architecture !== process.arch ||
      !protocol.HEX.test(record.source_sha256 || '') || !protocol.HEX.test(record.binary_sha256 || '') ||
      !Number.isSafeInteger(record.binary_bytes) || record.binary_bytes < 1 || record.binary_bytes > 16777216 ||
      !record.snapshot || typeof record.snapshot.directory !== 'string' || !path.isAbsolute(record.snapshot.directory) ||
      !/^knowledge-command-native-[A-Za-z0-9]{6}$/.test(path.basename(record.snapshot.directory)) ||
      record.executable !== path.join(record.snapshot.directory, FILENAME) ||
      !['dev', 'ino'].every(key => /^(?:0|[1-9][0-9]{0,19})$/.test(record.snapshot[key] || ''))) throw failure('command_windows_snapshot_invalid');
  return record;
}
function validateSnapshot(input, { allowIncomplete = false } = {}) {
  const record = admitPreparedHelper(input), snap = record.snapshot;
  assertSafeContainmentRoot(snap.directory);
  assertSafeContainedPath(snap.directory, record.executable, { allowMissing: allowIncomplete });
  const directory = fs.lstatSync(snap.directory, { bigint: true });
  if (!directory.isDirectory() || directory.isSymbolicLink() || !same(directory, snap)) throw failure('command_windows_snapshot_changed');
  const entries = fs.readdirSync(snap.directory);
  if (entries.length > 1 || entries.some(name => name !== FILENAME)) throw failure('command_windows_snapshot_unowned_entry');
  if (!entries.length && allowIncomplete && !snap.file) return record;
  const file = fs.lstatSync(record.executable, { bigint: true });
  if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1n || !snap.file || !same(file, snap.file) ||
      !allowIncomplete && String(file.mode) !== snap.mode) throw failure('command_windows_snapshot_changed');
  if (!allowIncomplete) {
    const binary = read(snap.directory, record.executable, 16777216);
    if (binary.length !== record.binary_bytes || protocol.sha(binary) !== record.binary_sha256) throw failure('command_windows_snapshot_changed');
  }
  return record;
}
function loadPreparedHelper(record) {
  validateSnapshot(record);
  if (process.platform !== 'win32') throw failure('command_windows_platform_unavailable');
  const native = require(record.executable), info = native.info();
  if (info?.schema_version !== 'knowledge-command-windows-native.v1' || info.platform !== 'win32' || info.architecture !== record.architecture ||
      info.source_sha256 !== record.source_sha256 || info.napi_version !== 8 || info.assignment !== protocol.ASSIGNMENT ||
      info.watchdog !== 'native-pipe-process-handles.v1' ||
      !['currentIdentity', 'processIdentity', 'hostBinding', 'create', 'open', 'attachPeer', 'poll', 'stop', 'markDurable', 'retirePeer', 'close', 'observe', 'memberOf', 'armReadonlyGuard'].every(key => typeof native[key] === 'function')) throw failure('command_windows_native_handshake_invalid');
  validateSnapshot(record);
  return { native, binding: { schema_version: info.schema_version, source_sha256: info.source_sha256, binary_sha256: record.binary_sha256,
    architecture: info.architecture, assignment: info.assignment, watchdog: info.watchdog } };
}
function cleanupPreparedHelper(record, { allowIncomplete = false } = {}) {
  if (!record?.snapshot) return { status: 'not_owned' };
  try {
    validateSnapshot(record, { allowIncomplete });
    const snap = record.snapshot;
    if (fs.readdirSync(snap.directory).length) {
      // Windows read-only files must be made writable for deletion. Recheck
      // the original ID immediately before the single owned unlink.
      fs.chmodSync(record.executable, 0o600);
      if (!same(fs.lstatSync(record.executable, { bigint: true }), snap.file)) throw failure('command_windows_snapshot_changed');
      fs.unlinkSync(record.executable);
    }
    if (!same(fs.lstatSync(snap.directory, { bigint: true }), snap) || fs.readdirSync(snap.directory).length) throw failure('command_windows_snapshot_changed');
    fs.rmdirSync(snap.directory);
    return { status: 'completed', method: 'private_native_snapshot', directory: snap.directory };
  } catch (error) { return { status: 'unconfirmed', method: 'private_native_snapshot', code: error.code || 'command_windows_snapshot_cleanup_failed', directory: record.snapshot.directory }; }
}
function hostBinding(native) {
  const value = native.hostBinding();
  if (!value || !['machine_guid', 'computer_name', 'user_sid'].every(key => typeof value[key] === 'string' && value[key].length > 0 && value[key].length < 4096)) throw failure('command_windows_host_invalid');
  const result = { machine_guid_sha256: protocol.sha(value.machine_guid.toLowerCase()), computer_name_sha256: protocol.sha(value.computer_name.toLowerCase()),
    user_sid_sha256: protocol.sha(value.user_sid), session_id: value.session_id };
  if (!protocol.validHost(result)) throw failure('command_windows_host_invalid');
  return result;
}
module.exports = { preparePackagedHelper, admitPreparedHelper, validateSnapshot, loadPreparedHelper, cleanupPreparedHelper, hostBinding };
