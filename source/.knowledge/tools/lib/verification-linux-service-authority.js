'use strict';

// Fixed installed authority. The native init admits this program only after
// the importer namespace is empty and the source mount is read-only. It never
// executes repository code in this UID; every command goes through the fixed
// native worker protocol into a separate UID and PID namespace.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const signals = require('node:os').constants.signals;
const importer = require('./verification-linux-service-importer');
const { copyInertData } = require('./inert-data');
const core = require('./repair-on-touch').__runVerificationTestsCore;
const MAX_INPUT = 64 * 1024 * 1024;
const MAX_RESULT = 128 * 1024;
const MAX_STREAM = 16 * 1024 * 1024;
const fail = code => { throw Object.assign(new Error(code), { code }); };
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const clock = () => process.hrtime.bigint();
function exactRead(fd, length, position = null) {
  const bytes = Buffer.alloc(length);
  for (let offset = 0; offset < length;) {
    const count = fs.readSync(fd, bytes, offset, length - offset, position === null ? null : position + offset);
    if (count <= 0) fail('verification_linux_native_reply_truncated');
    offset += count;
  }
  return bytes;
}
function writeAll(fd, bytes) {
  for (let offset = 0; offset < bytes.length;) {
    const count = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    if (count <= 0) fail('verification_linux_native_request_truncated');
    offset += count;
  }
}
function commandHeader(op, ordinal, flags, argc, cwdBytes, bodyBytes, deadline) {
  const header = Buffer.alloc(40);
  [0x4b4c4331, 1, op, ordinal, flags, argc, cwdBytes, bodyBytes].forEach((value, i) => header.writeUInt32LE(value, i * 4));
  header.writeBigUInt64LE(deadline, 32);return header;
}
function stringPart(value) {
  if (typeof value !== 'string' || value.includes('\0') || Buffer.from(value).toString('utf8') !== value) {
    fail('verification_linux_native_argument_invalid');
  }
  const bytes = Buffer.from(value, 'utf8'), size = Buffer.alloc(4);size.writeUInt32LE(bytes.length);
  return Buffer.concat([size, bytes]);
}
async function run() {
  const sourceRoot = process.argv[2], stateRoot = process.argv[3];
  const authorityUid = Number(process.argv[4]), workerUid = Number(process.argv[5]);
  if (process.platform !== 'linux' || sourceRoot !== '/source' || stateRoot !== '/state' ||
      !Number.isSafeInteger(authorityUid) || !Number.isSafeInteger(workerUid) || authorityUid <= 0 ||
      workerUid <= 0 || workerUid === authorityUid || process.getuid() !== authorityUid || process.geteuid() !== authorityUid) {
    fail('verification_linux_authority_identity_invalid');
  }
  const st = fs.fstatSync(3);
  if (!st.isFile() || st.size < 1 || st.size > MAX_INPUT) fail('verification_linux_envelope_invalid');
  // Never depend on a shared open-file-description offset inherited from I.
  const envelopeBytes = exactRead(3, st.size, 0), text = envelopeBytes.toString('utf8');
  if (!Buffer.from(text).equals(envelopeBytes)) fail('verification_linux_envelope_invalid');
  const envelope = JSON.parse(text);
  if (JSON.stringify(envelope) !== text || Object.keys(envelope).sort().join(',') !== 'authority,source') {
    fail('verification_linux_envelope_invalid');
  }
  const plan = importer.validateImport(Buffer.from(JSON.stringify(envelope.source)));
  const a = envelope.authority;
  if (!a || Object.keys(a).sort().join(',') !== 'batch_id,deadline_ns,nonce,public_key,request,request_sha256' ||
      !/^KVB-[a-f0-9]{32}$/.test(a.batch_id) || !/^[a-f0-9]{64}$/.test(a.nonce) ||
      !/^[a-f0-9]{64}$/.test(a.request_sha256) || !/^[a-f0-9]{88}$/.test(a.public_key) ||
      typeof a.deadline_ns !== 'string' || !/^\d{1,20}$/.test(a.deadline_ns)) fail('verification_linux_authority_request_invalid');
  const deadline = BigInt(a.deadline_ns);
  function guard() { if (clock() >= deadline) fail('verification_timeout'); }
  guard();
  const files = new Map(plan.files.map(row => [row.path, row]));
  function readSource(name) {
    const expected = files.get(name);if (!expected) fail('verification_copy_required_source_excluded');
    const filename = path.posix.join(sourceRoot, importer.portablePath(name));
    const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const observed = fs.fstatSync(fd);
      if (!observed.isFile() || observed.nlink !== 1 || observed.uid !== authorityUid || observed.gid !== workerUid ||
          observed.size !== expected.bytes || (observed.mode & 0o777) !== (expected.mode === 0o755 ? 0o550 : 0o440)) {
        fail('verification_copy_source_changed');
      }
      const bytes = exactRead(fd, observed.size, 0);
      if (sha(bytes) !== expected.sha256) fail('verification_copy_source_changed');
      return { path: name, sha256: expected.sha256 };
    } finally { fs.closeSync(fd); }
  }
  // A independently checks the entire read-only imported manifest before the
  // native READY permit. W cannot write any of these files or A's private state.
  for (const row of plan.files) { guard();readSource(row.path); }
  for (const name of plan.directories) {
    guard();const observed = fs.lstatSync(path.posix.join(sourceRoot, name));
    if (!observed.isDirectory() || observed.isSymbolicLink() || observed.uid !== authorityUid || observed.gid !== workerUid ||
        (observed.mode & 0o777) !== 0o550) fail('verification_copy_source_changed');
  }
  const ready = Buffer.alloc(88);
  Buffer.from(plan.manifest_sha256, 'hex').copy(ready, 0);Buffer.from(plan.directories_sha256, 'hex').copy(ready, 32);
  ready.writeBigUInt64LE(BigInt(plan.files.length), 64);ready.writeBigUInt64LE(BigInt(plan.total_bytes), 72);
  ready.writeBigUInt64LE(BigInt(plan.directories.length), 80);
  writeAll(5, Buffer.concat([commandHeader(1, 0, 0, 0, 0, ready.length, deadline), ready]));
  const commands = [];
  async function runCommand(details) {
    guard();const invocation = details.nodeInvocation;
    if (!details.nodeCommand || details.generatedProducer || !invocation?.valid) fail('verification_linux_command_unsupported');
    const script = importer.portablePath(invocation.script);
    if (!files.has(script)) fail('verification_copy_required_source_excluded');
    const cwd = details.cwdRelative === '.' ? '.' : importer.portablePath(details.cwdRelative);
    const args = invocation.mode === 'test' ? [] : details.argv.slice(2);
    if (args.length > 32) fail('verification_linux_native_argument_limit');
    const cwdBuffer = Buffer.from(cwd, 'utf8');
    const body = Buffer.concat([stringPart(script), cwdBuffer, ...args.map(stringPart)]);
    if (body.length + 40 > 65536) fail('verification_linux_native_argument_limit');
    const ordinal = commands.length + 1;
    writeAll(5, Buffer.concat([commandHeader(2, ordinal, invocation.mode === 'test' ? 1 : 0,
      args.length, cwdBuffer.length, body.length, details.deadline), body]));
    const header = exactRead(6, 32);
    if (header.readUInt32LE(0) !== 0x4b4c5231 || header.readUInt32LE(4) !== 1 ||
        header.readUInt32LE(8) !== ordinal || header.readUInt32LE(28) !== 0) fail('verification_linux_native_reply_invalid');
    const status = header.readInt32LE(12), signal = header.readUInt32LE(16);
    const stdoutSize = header.readUInt32LE(20), stderrSize = header.readUInt32LE(24);
    if (stdoutSize > MAX_STREAM || stderrSize > MAX_STREAM || status < -1 || status > 255 || signal > 64) {
      fail('verification_linux_native_reply_invalid');
    }
    const stdout = exactRead(6, stdoutSize), stderr = exactRead(6, stderrSize);guard();
    const signalName = signal ? Object.keys(signals).find(name => signals[name] === signal) : null;
    if (signal && !signalName) fail('verification_linux_native_reply_invalid');
    commands.push({ ordinal, script, mode: invocation.mode, args, cwd, deadline_ns: String(details.deadline),
      status, signal: signalName, stdout_bytes: stdout.length, stderr_bytes: stderr.length,
      stdout_sha256: sha(stdout), stderr_sha256: sha(stderr) });
    return { status, signal: signalName, stdout, stderr };
  }
  const request = { ...a.request, repoRoot: sourceRoot, stateRoot };
  const result = await core(request, { nativeBackend: 'linux_native_service', deadline,
    batchId: a.batch_id, publicKey: a.public_key, requestSha256: a.request_sha256,
    phase: async () => guard(), committed: async () => guard(), runCommand,
    sourceSnapshot: async names => names.map(name => { guard();return readSource(name); }) });
  guard();
  const answer = { schema_version: 'knowledge-linux-service-authority-result.v1', nonce: a.nonce,
    batch_id: a.batch_id, request_sha256: a.request_sha256, public_key: a.public_key,
    authority_uid: authorityUid, worker_uid: workerUid, manifest_sha256: plan.manifest_sha256,
    directories_sha256: plan.directories_sha256, runtime_sha256: sha(fs.readFileSync(process.execPath)),
    result: result.map(({ record, relative_path, idempotent }) => ({ record, relative_path, idempotent })), commands };
  const output = Buffer.from(JSON.stringify(answer));
  if (output.length > MAX_RESULT) fail('verification_linux_authority_result_limit');
  writeAll(4, output);fs.closeSync(4);
}
if (require.main === module) run().then(() => process.exit(0)).catch(error => {
  const code = /^[a-zA-Z0-9_]{1,100}$/.test(error.code || '') ? error.code : 'verification_linux_authority_failed';
  process.stderr.write(code + '\n');process.exit(1);
});
module.exports = { run, exactRead, commandHeader, MAX_RESULT };
