'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertSafeContainmentRoot, assertSafeContainedPath } = require('./json-store');
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
let qualified = null;

function unavailable(reason, error) {
  return Object.assign(new Error(`Atomic lock publication is unavailable (${reason}).`), {
    code: 'lock_native_publication_unavailable', reason, os_code: error?.code || null
  });
}

function readPinnedFile(root, file, maximum) {
  assertSafeContainedPath(root, file);
  const initial = fs.lstatSync(file, { bigint: true });
  const same = (a, b) => ['dev', 'ino', 'size', 'nlink', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);
  if (!initial.isFile() || initial.isSymbolicLink() || initial.nlink !== 1n || initial.size < 1n || initial.size > BigInt(maximum)) throw unavailable('unsafe_artifact');
  const parents = [];
  let parent = root;
  for (const part of ['', ...path.relative(root, path.dirname(file)).split(path.sep).filter(Boolean)]) {
    if (part) parent = path.join(parent, part);
    const stat = fs.lstatSync(parent, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw unavailable('unsafe_artifact_parent');
    parents.push({ file: parent, dev: stat.dev, ino: stat.ino });
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let raw;
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile() || !same(initial, opened)) throw unavailable('artifact_changed');
    const bytes = Buffer.alloc(Number(opened.size) + 1); let used = 0;
    while (used < bytes.length) { const count = fs.readSync(fd, bytes, used, bytes.length - used, null); if (!count) break; used += count; }
    const after = fs.fstatSync(fd, { bigint: true }), live = fs.lstatSync(file, { bigint: true });
    if (BigInt(used) !== opened.size || !same(opened, after) || !same(after, live) || !live.isFile() || live.isSymbolicLink()) throw unavailable('artifact_changed');
    raw = bytes.subarray(0, used);
  } finally { fs.closeSync(fd); }
  for (const parent of parents) {
    const current = fs.lstatSync(parent.file, { bigint: true });
    if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== parent.dev || current.ino !== parent.ino) throw unavailable('artifact_parent_changed');
  }
  assertSafeContainedPath(root, file);
  return { raw, sha256: sha256(raw) };
}

function qualifyNativePublication() {
  if (qualified) return qualified;
  try {
    if (!['linux', 'darwin', 'win32'].includes(process.platform) || !['x64', 'arm64'].includes(process.arch) || Number(process.versions.napi) < 8) throw unavailable('unsupported_platform_or_abi');
    const root = assertSafeContainmentRoot(path.resolve(__dirname, '..'));
    const directory = path.join(root, 'lib', 'native', `${process.platform}-${process.arch}`);
    const manifestPath = path.join(directory, 'lock-publication.manifest.json');
    const manifestRead = readPinnedFile(root, manifestPath, 16384);
    const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestRead.raw));
    const fields = ['schema_version', 'platform', 'architecture', 'napi_version', 'source_sha256', 'binary_sha256', 'binary_bytes', 'binary'];
    if (!manifest || Object.keys(manifest).length !== fields.length || fields.some(k => !Object.hasOwn(manifest, k)) ||
        manifest.schema_version !== 'knowledge-lock-native-binary.v1' || manifest.platform !== process.platform || manifest.architecture !== process.arch ||
        manifest.napi_version !== 8 || manifest.binary !== 'lock-publication.node' || !/^[a-f0-9]{64}$/.test(manifest.source_sha256) ||
        !/^[a-f0-9]{64}$/.test(manifest.binary_sha256) || !Number.isSafeInteger(manifest.binary_bytes) || manifest.binary_bytes < 1 || manifest.binary_bytes > 16777216) throw unavailable('manifest_invalid');
    const source = readPinnedFile(root, path.join(root, 'native', 'lock-publication.c'), 262144);
    const binaryPath = path.join(directory, manifest.binary), binary = readPinnedFile(root, binaryPath, 16777216);
    if (source.sha256 !== manifest.source_sha256 || binary.sha256 !== manifest.binary_sha256 || binary.raw.length !== manifest.binary_bytes) throw unavailable('artifact_pin_mismatch');
    // The installed package is immutable for the duration of loading. Verify
    // both bytes and the compiled source handshake; never load via PATH or a
    // writable global compiler cache. A concurrent installer is detected and
    // cannot obtain a lock-acquisition acknowledgment from this load.
    const native = require(binaryPath);
    const info = native.info();
    if (info.schema_version !== 'knowledge-lock-publication-native.v1' || info.source_sha256 !== manifest.source_sha256 ||
        info.platform !== process.platform || info.architecture !== process.arch || info.napi_version !== 8 || info.lease_protocol !== 'owner-inode-lease.v1' ||
        typeof native.publish !== 'function' || typeof native.probeLease !== 'function' || typeof native.closeLease !== 'function') throw unavailable('native_handshake_mismatch');
    if (readPinnedFile(root, binaryPath, 16777216).sha256 !== binary.sha256 ||
        readPinnedFile(root, manifestPath, 16384).sha256 !== manifestRead.sha256 ||
        readPinnedFile(root, path.join(root, 'native', 'lock-publication.c'), 262144).sha256 !== source.sha256) throw unavailable('package_changed_during_load');
    qualified = Object.freeze({ publish: native.publish, probeLease: native.probeLease, closeLease: native.closeLease, info: Object.freeze(info), manifest: Object.freeze(manifest) });
    return qualified;
  } catch (error) { throw error?.code === 'lock_native_publication_unavailable' ? error : unavailable('qualification_failed', error); }
}

function publishPreparedLock(root, stageBasename, publicBasename, remainingMs = 30000) {
  return qualifyNativePublication().publish(root, stageBasename, publicBasename, remainingMs);
}

function probeOwnerLease(root, publicBasename) { return qualifyNativePublication().probeLease(root, publicBasename); }
function closeOwnerLease(token) { return qualifyNativePublication().closeLease(token); }

module.exports = { qualifyNativePublication, publishPreparedLock, probeOwnerLease, closeOwnerLease };
