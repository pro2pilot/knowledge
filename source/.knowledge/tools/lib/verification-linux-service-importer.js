'use strict';

// Fixed installed importer. Native service supplies only a fully sealed memfd
// and fresh private-UID directories. This process never opens a caller path.
// Native init drains its entire PID namespace before the readonly mount and
// fresh authority are admitted. The module does not itself assert native proof.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const SCHEMA = 'knowledge-linux-service-copy-input.v1';
const MAX_ENTRIES = 50000;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_WIRE_BYTES = 64 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 4096;
const SOURCE_DIRS = new Set(['tools', 'tests', 'docs', 'models', 'schemas', 'templates',
  'agent-integrations', 'commands', 'skills', 'assets', 'flows', 'github-action-templates',
  'memory-providers', '.release-notes']);
const SOURCE_FILES = new Set(['package.json', 'config.yaml', 'verification-policy.json', 'install-manifest.json',
  'release-policy.json', 'install-policy.json', 'lock-policy.json', 'README.md', 'INSTALL.md',
  'Quick-Start.md', 'RELEASE_NOTES.md', 'SECURITY.md', 'LICENSE', 'LICENSE.md', 'NOTICE',
  'THIRD_PARTY_NOTICES.md', 'Portal.md', 'SBOM.memory.json', '.gitignore', '.gitattributes',
  'inspector.js', 'open-inspector.vbs']);
const O_NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
const O_CLOEXEC = fs.constants.O_CLOEXEC || 0;

// Installed runtime identity excludes mutable maintenance, maps and memory
// roots even when the installed system root is also the caller's project.
function allowedSourcePath(relative) {
  if (typeof relative !== 'string' || relative.startsWith('/') || relative.includes('\\')) return false;
  const parts = relative.split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || ['.git', 'node_modules', '__pycache__'].includes(part))) return false;
  return parts.length === 1 ? SOURCE_FILES.has(parts[0]) : SOURCE_DIRS.has(parts[0]);
}
const sourcePolicy = Object.freeze({ directories: Object.freeze([...SOURCE_DIRS]), files: Object.freeze([...SOURCE_FILES]) });

function fail(code, message) { throw Object.assign(new Error(message), { code }); }
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function compareNames(a, b) { return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')); }
function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}
function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function isLowerSha(value) { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }

function portablePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\') || value.startsWith('/') ||
      value !== value.normalize('NFC') || /[\x00-\x1f\x7f]/.test(value)) {
    fail('import_path_invalid', 'Path must be canonical portable relative NFC text');
  }
  // Buffer.from() replaces unmatched UTF-16 surrogates with U+FFFD. Reject
  // those code units before hashing or touching the filesystem so the
  // manifest name cannot silently differ from the actual filesystem name.
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail('import_path_invalid', 'Path contains an unmatched UTF-16 surrogate');
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail('import_path_invalid', 'Path contains an unmatched UTF-16 surrogate');
    }
  }
  const parts = value.split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || /[<>:"|?*]/.test(part) ||
      /[. ]$/.test(part) || /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$)(?:\.|$)/i.test(part))) {
    fail('import_path_invalid', 'Path contains a nonportable component');
  }
  const partsFolded = parts.map(part => part.toLowerCase());
  const leaf = parts.at(-1);
  if (partsFolded.includes('.git') || partsFolded.some(part => ['.aws', '.ssh', '.gnupg', '.codex', '.claude', '.azure'].includes(part))) {
    fail('import_state_excluded', 'Credential and VCS state is not importable');
  }
  for (let i = 0; i < parts.length - 1; i++) {
    if (partsFolded[i] === '.knowledge' && !SOURCE_DIRS.has(parts[i + 1]) &&
        !(parts.length === i + 2 && SOURCE_FILES.has(parts[i + 1]))) {
      fail('import_state_excluded', 'Unrecognized .knowledge paths are runtime state');
    }
  }
  if (parts.includes('node_modules') && parts.includes('.cache')) fail('import_state_excluded', 'Dependency cache is excluded');
  if (/^\.env(?:\.|$)/i.test(leaf) && !/\.(?:example|sample|template)$/i.test(leaf)) {
    fail('import_state_excluded', 'Secret configuration is excluded');
  }
  if (/^(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|credentials|credentials\.json|\.npmrc|\.netrc)$/i.test(leaf) ||
      /\.(?:pem|p12|pfx|key)$/i.test(leaf)) fail('import_state_excluded', 'Sensitive files are excluded');
  return value;
}

function manifestDigest(files) {
  const normalized = [...files].sort((a, b) => compareNames(a.path, b.path))
    .map(({ path: name, bytes, sha256: digest, mode }) => ({ bytes, mode, path: name, sha256: digest }));
  return sha256(Buffer.from(JSON.stringify(normalized), 'utf8'));
}
function directoriesDigest(names) {
  return sha256(Buffer.from(JSON.stringify([...names].sort(compareNames)), 'utf8'));
}

function validateImport(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_WIRE_BYTES) {
    fail('import_wire_limit', 'Input must be a nonempty bounded Buffer');
  }
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) fail('import_wire_encoding', 'Input must be valid UTF-8');
  let input;
  try { input = JSON.parse(text); } catch { fail('import_json_invalid', 'Input is not valid JSON'); }
  if (JSON.stringify(input) !== text) fail('import_wire_noncanonical', 'Input must use compact canonical JSON without duplicate keys');
  if (!exactKeys(input, ['schema_version', 'directories', 'files', 'manifest_sha256', 'directories_sha256']) ||
      input.schema_version !== SCHEMA || !Array.isArray(input.directories) || !Array.isArray(input.files) ||
      !isLowerSha(input.manifest_sha256) || !isLowerSha(input.directories_sha256)) {
    fail('import_schema_invalid', 'Input schema or top-level fields are invalid');
  }
  if (input.directories.length + input.files.length > MAX_ENTRIES) fail('import_entry_limit', 'Import entry count exceeds the installed limit');

  const directories = input.directories.map(portablePath);
  const files = [];
  let total = 0;
  const allPaths = new Map();
  const keyOf = name => name.normalize('NFD').toUpperCase().toLowerCase();
  function addPath(name, kind) {
    const key = keyOf(name);
    if (allPaths.has(key)) fail('import_path_collision', 'Duplicate or case-colliding paths are rejected');
    allPaths.set(key, { name, kind });
  }
  for (const name of directories) addPath(name, 'directory');
  for (const entry of input.files) {
    if (!exactKeys(entry, ['path', 'bytes', 'mode', 'sha256', 'data_base64'])) fail('import_file_shape', 'File entry has unknown or missing fields');
    const name = portablePath(entry.path);
    if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || entry.bytes > MAX_FILE_BYTES) {
      fail('import_file_limit', 'File byte count is invalid or exceeds the installed limit');
    }
    // The current isolated-copy manifest accepts source modes 0644 or 0755.
    // Installed outputs become read-only 0440/0550 respectively.
    if (entry.mode !== 0o644 && entry.mode !== 0o755) fail('import_mode_invalid', 'Only regular data or executable source modes are supported');
    if (!isLowerSha(entry.sha256) || typeof entry.data_base64 !== 'string' ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(entry.data_base64)) {
      fail('import_encoding_invalid', 'File digest or canonical base64 encoding is invalid');
    }
    const payload = Buffer.from(entry.data_base64, 'base64');
    if (payload.toString('base64') !== entry.data_base64 || payload.length !== entry.bytes || sha256(payload) !== entry.sha256) {
      fail('import_file_digest_mismatch', 'File bytes, base64, or SHA-256 do not agree');
    }
    total += payload.length;
    if (total > MAX_TOTAL_BYTES) fail('import_total_limit', 'Import exceeds the installed source-byte limit');
    addPath(name, 'file');
    files.push({ path: name, bytes: payload.length, sha256: entry.sha256, mode: entry.mode, data: payload });
  }
  if (directories.some((name, i) => i && compareNames(directories[i - 1], name) >= 0) ||
      files.some((file, i) => i && compareNames(files[i - 1].path, file.path) >= 0)) {
    fail('import_order_invalid', 'Directory and file arrays must be strictly UTF-8 byte sorted');
  }
  const kindByName = new Map([...directories.map(name => [name, 'directory']), ...files.map(file => [file.path, 'file'])]);
  for (const name of [...directories, ...files.map(file => file.path)]) {
    const parts = name.split('/');
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(0, i).join('/');
      if (kindByName.get(parent) !== 'directory') fail('import_parent_missing', 'Every non-root parent directory must be listed');
    }
  }
  if (manifestDigest(files) !== input.manifest_sha256 || directoriesDigest(directories) !== input.directories_sha256) {
    fail('import_manifest_digest_mismatch', 'Manifest digest does not match the current isolated-copy contract');
  }
  return { schema_version: SCHEMA, directories, files, total_bytes: total,
    manifest_sha256: input.manifest_sha256, directories_sha256: input.directories_sha256 };
}

function assertPhysicalDirectory(directory, uid, gid, exactMode = null) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) !== directory) {
    fail('import_root_invalid', 'Native init must pass an absolute canonical directory');
  }
  const root = path.parse(directory).root;
  let current = root;
  for (const part of path.relative(root, directory).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const st = fs.lstatSync(current);
    if (!st.isDirectory() || st.isSymbolicLink()) fail('import_root_unsafe', 'A root directory component is not physical');
  }
  const st = fs.lstatSync(directory);
  if (st.uid !== uid || st.gid !== gid || (exactMode !== null && (st.mode & 0o777) !== exactMode)) {
    fail('import_root_owner_mode', 'Import directory owner, group, or mode differs from fixed contract');
  }
  return st;
}

function ensureEmptySource(sourceDir, authorityUid, workerGid) {
  const st = assertPhysicalDirectory(sourceDir, authorityUid, workerGid);
  if ((st.mode & 0o022) !== 0 || fs.readdirSync(sourceDir).length !== 0) {
    fail('import_source_not_fresh', 'Source directory must be fresh, empty, and not group/world writable');
  }
  fs.chmodSync(sourceDir, 0o700);
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    if (written <= 0) fail('import_short_write', 'A bounded output write was incomplete');
    offset += written;
  }
}

function createImportedFile(file, sourceDir, authorityUid, workerGid) {
  const destination = path.join(sourceDir, ...file.path.split('/'));
  const fd = fs.openSync(destination, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600);
  try {
    let st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.uid !== authorityUid || st.gid !== process.getgid() || (st.mode & 0o777) !== 0o600) {
      fail('import_file_create_identity', 'New file identity did not match the temporary owner-only contract');
    }
    writeAll(fd, file.data);
    fs.fsyncSync(fd);
    const readback = Buffer.alloc(file.data.length);
    let offset = 0;
    while (offset < readback.length) {
      const count = fs.readSync(fd, readback, offset, readback.length - offset, offset);
      if (count <= 0) fail('import_file_readback', 'New file readback ended early');
      offset += count;
    }
    if (sha256(readback) !== file.sha256 || !readback.equals(file.data)) fail('import_file_readback', 'New file readback digest mismatch');
    fs.fchownSync(fd, authorityUid, workerGid);
    fs.fchmodSync(fd, file.mode === 0o755 ? 0o550 : 0o440);
    fs.fsyncSync(fd);
    st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.uid !== authorityUid || st.gid !== workerGid ||
        (st.mode & 0o777) !== (file.mode === 0o755 ? 0o550 : 0o440) || st.size !== file.bytes) {
      fail('import_file_final_identity', 'Imported file final owner, mode, link count, or size mismatch');
    }
    const readFd = fs.openSync(destination, fs.constants.O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    try {
      const finalStat = fs.fstatSync(readFd), namedStat = fs.lstatSync(destination);
      if (!finalStat.isFile() || finalStat.nlink !== 1 || finalStat.uid !== authorityUid || finalStat.gid !== workerGid ||
          (finalStat.mode & 0o777) !== (file.mode === 0o755 ? 0o550 : 0o440) ||
          finalStat.dev !== st.dev || finalStat.ino !== st.ino || namedStat.dev !== st.dev || namedStat.ino !== st.ino) {
        fail('import_file_final_readback', 'Read-only final file identity changed');
      }
      const finalBytes = Buffer.alloc(file.bytes);
      let finalOffset = 0;
      while (finalOffset < finalBytes.length) {
        const count = fs.readSync(readFd, finalBytes, finalOffset, finalBytes.length - finalOffset, finalOffset);
        if (count <= 0) fail('import_file_final_readback', 'Read-only final file ended early');
        finalOffset += count;
      }
      if (sha256(finalBytes) !== file.sha256 || !finalBytes.equals(file.data)) {
        fail('import_file_final_readback', 'Read-only final file digest mismatch');
      }
    } finally { fs.closeSync(readFd); }
  } finally { fs.closeSync(fd); }
}

function writeReceipt(stateDir, receipt, authorityUid) {
  const body = Buffer.from(JSON.stringify(receipt), 'utf8');
  if (body.length > MAX_RECEIPT_BYTES) fail('import_receipt_limit', 'Generated receipt exceeds 4 KiB');
  for (let attempt = 0; attempt < 4; attempt++) {
    const name = `import-${crypto.randomBytes(12).toString('hex')}.json`;
    const destination = path.join(stateDir, name);
    let fd;
    try { fd = fs.openSync(destination, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600); }
    catch (error) { if (error.code === 'EEXIST') continue; throw error; }
    try {
      fs.fchownSync(fd, authorityUid, process.getgid());
      fs.fchmodSync(fd, 0o600);
      writeAll(fd, body);
      fs.fsyncSync(fd);
      const st = fs.fstatSync(fd);
      if (!st.isFile() || st.nlink !== 1 || st.uid !== authorityUid || (st.mode & 0o777) !== 0o600 || st.size !== body.length) {
        fail('import_receipt_identity', 'Generated receipt identity mismatch');
      }
    } finally { fs.closeSync(fd); }
    return name;
  }
  fail('import_receipt_collision', 'Could not allocate a unique receipt name');
}

function importProject(bytes, sourceDir, stateDir, { authorityUid, workerGid } = {}) {
  if (process.platform === 'win32') fail('import_platform_unsupported', 'This QA importer requires POSIX ownership and mode semantics');
  if (!Number.isSafeInteger(authorityUid) || authorityUid <= 0 || !Number.isSafeInteger(workerGid) || workerGid < 0 ||
      process.getuid() !== authorityUid) fail('import_identity_invalid', 'Importer must run as the expected non-root authority UID');
  if (!process.getgroups().includes(workerGid) && process.getgid() !== workerGid) {
    fail('import_worker_group_missing', 'Worker GID must be an existing supplementary or primary group');
  }
  const validated = validateImport(bytes);
  if (inside(sourceDir, stateDir) || inside(stateDir, sourceDir)) {
    fail('import_roots_overlap', 'Source and state directories must be disjoint');
  }
  ensureEmptySource(sourceDir, authorityUid, workerGid);
  assertPhysicalDirectory(stateDir, authorityUid, process.getgid(), 0o700);
  for (const name of validated.directories) {
    const destination = path.join(sourceDir, ...name.split('/'));
    fs.mkdirSync(destination, { mode: 0o700 });
    fs.chownSync(destination, authorityUid, workerGid);
  }
  for (const file of validated.files) createImportedFile(file, sourceDir, authorityUid, workerGid);
  for (const name of [...validated.directories].sort((a, b) => b.split('/').length - a.split('/').length || compareNames(b, a))) {
    const destination = path.join(sourceDir, ...name.split('/'));
    fs.chownSync(destination, authorityUid, workerGid);
    fs.chmodSync(destination, 0o550);
  }
  fs.chownSync(sourceDir, authorityUid, workerGid);
  fs.chmodSync(sourceDir, 0o550);
  const rootStat = fs.lstatSync(sourceDir);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || rootStat.uid !== authorityUid || rootStat.gid !== workerGid ||
      (rootStat.mode & 0o777) !== 0o550) fail('import_source_final_identity', 'Source root final owner, group, or mode mismatch');
  const receiptValue = { schema_version: 'knowledge-linux-service-import-receipt.v1',
    status: 'IMPORTED_BYTES_UNSEALED', manifest_sha256: validated.manifest_sha256,
    directories_sha256: validated.directories_sha256, files: validated.files.length,
    directories: validated.directories.length, total_bytes: validated.total_bytes };
  const receiptName = writeReceipt(stateDir, receiptValue, authorityUid);
  return { ...receiptValue, receipt_name: receiptName };
}

function parseId(text, label, allowZero) {
  if (typeof text !== 'string' || !/^(?:0|[1-9][0-9]{0,9})$/.test(text)) fail('import_argv_invalid', `${label} must be canonical decimal`);
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > 0xffffffff || (!allowZero && value === 0)) fail('import_argv_invalid', `${label} is out of range`);
  return value;
}

function readBoundedFd(fd, maximum) {
  const stat = fs.fstatSync(fd);
  if (!stat.isFile() || stat.size < 0 || stat.size > maximum) fail('import_fd_type', 'fd 3 must be a bounded regular sealed input descriptor');
  // SCM_RIGHTS duplicates an open-file description: a sender can still lseek
  // its descriptor after sealing. Explicit positions never consume that shared
  // offset. Kernel type/size/full-seal checks remain the native admission gate.
  const chunks = [];
  let total = 0;
  for (;;) {
    const chunk = Buffer.alloc(Math.min(65536, maximum + 1 - total));
    if (chunk.length === 0) fail('import_wire_limit', 'Input exceeds the wire size limit');
    const count = fs.readSync(fd, chunk, 0, chunk.length, total);
    if (count === 0) break;
    chunks.push(chunk.subarray(0, count));
    total += count;
    if (total > maximum) fail('import_wire_limit', 'Input exceeds the wire size limit');
  }
  if (total !== stat.size) fail('import_fd_size_mismatch', 'fd 3 did not deliver its complete bounded byte range');
  return Buffer.concat(chunks, total);
}

function main(argv = process.argv) {
  if (process.platform !== 'linux' || argv.length !== 6 || path.resolve(argv[1]) !== __filename) {
    fail('import_argv_invalid', 'Expected the fixed Linux importer argv');
  }
  const sourceDir = argv[2], stateDir = argv[3];
  const authorityUid = parseId(argv[4], 'authority UID', false);
  const workerGid = parseId(argv[5], 'worker GID', true);
  if (process.getuid() === 0 || process.getuid() !== authorityUid) fail('import_identity_invalid', 'Importer must run as its expected non-root UID');
  const inputInfo = fs.fstatSync(3), receiptInfo = fs.fstatSync(4);
  if (!inputInfo.isFile() || inputInfo.size > MAX_WIRE_BYTES || !receiptInfo.isFIFO()) {
    fail('import_fd_type', 'fd 3 must be a bounded sealed input descriptor and fd 4 a receipt pipe');
  }
  const envelopeBytes = readBoundedFd(3, MAX_WIRE_BYTES);
  const text = envelopeBytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(envelopeBytes)) fail('import_wire_encoding', 'Envelope must be valid UTF-8');
  let envelope;
  try { envelope = JSON.parse(text); } catch { fail('import_json_invalid', 'Envelope is not JSON'); }
  if (JSON.stringify(envelope) !== text || !exactKeys(envelope, ['source', 'authority']) ||
      !envelope.authority || typeof envelope.authority !== 'object' || Array.isArray(envelope.authority)) {
    fail('import_envelope_invalid', 'Expected canonical source and fixed-authority request envelope');
  }
  const result = importProject(Buffer.from(JSON.stringify(envelope.source)), sourceDir, stateDir, { authorityUid, workerGid });
  const receipt = Buffer.from(`KSI2 ${result.manifest_sha256} ${result.directories_sha256} ${result.files} ${result.total_bytes} ${result.directories}\n`, 'ascii');
  if (receipt.length > 256) fail('import_receipt_limit', 'fd 4 receipt exceeds 256 bytes');
  writeAll(4, receipt);
  return 0;
}

if (require.main === module) {
  try { process.exitCode = main(); }
  catch (error) {
    const code = typeof error.code === 'string' && /^[a-z0-9_]{1,64}$/.test(error.code) ? error.code : 'import_failed';
    const diagnostic = Buffer.from(`KSE1 ${code}\n`, 'ascii');
    try { if (fs.fstatSync(4).isFIFO() && diagnostic.length <= 128) writeAll(4, diagnostic); } catch {}
    process.exitCode = 1;
  }
}

module.exports = { SCHEMA, MAX_ENTRIES, MAX_TOTAL_BYTES, MAX_FILE_BYTES, MAX_WIRE_BYTES,
  validateImport, importProject, manifestDigest, directoriesDigest, readBoundedFd, portablePath,
  allowedSourcePath, sourcePolicy };
