'use strict';

// Closed component QA only. Native init supplies a fresh post-import process,
// readonly source mount and fixed private FD mapping. No project module loads.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const importer = require('./importer');
const fail = () => { throw new Error('slice_authority_invalid'); };
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const order = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
function checkedFile(name, uid, gid, modes, limit) {
  const before = fs.lstatSync(name);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.uid !== uid ||
      before.gid !== gid || !modes.includes(before.mode & 0o7777) || before.size > limit) fail();
  const fd = fs.openSync(name, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(fd);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1 || !opened.isFile()) fail();
    const bytes = fs.readFileSync(fd), after = fs.fstatSync(fd), named = fs.lstatSync(name);
    if (bytes.length !== before.size || after.size !== before.size || after.ino !== named.ino ||
        after.dev !== named.dev || named.isSymbolicLink() || named.nlink !== 1) fail();
    return { bytes, stat: after };
  } finally { fs.closeSync(fd); }
}
function readback(source, state, uid, workerGid) {
  const stateStat = fs.lstatSync(state);
  if (!stateStat.isDirectory() || stateStat.isSymbolicLink() || stateStat.uid !== uid ||
      stateStat.gid !== uid || (stateStat.mode & 0o7777) !== 0o700) fail();
  const receipts = fs.readdirSync(state);
  if (receipts.length !== 1 || !/^import-[a-f0-9]{24}\.json$/.test(receipts[0])) fail();
  const saved = JSON.parse(checkedFile(path.join(state, receipts[0]), uid, uid, [0o600], 4096).bytes);
  const fields = ['schema_version', 'status', 'manifest_sha256', 'directories_sha256', 'files', 'directories', 'total_bytes'];
  if (!saved || Object.keys(saved).length !== fields.length || !fields.every(key => Object.hasOwn(saved, key)) ||
      saved.schema_version !== 'knowledge-linux-service-import-receipt.v1' || saved.status !== 'IMPORTED_BYTES_UNSEALED') fail();
  const files = [], directories = [];
  let total = 0;
  function visit(relative) {
    const directory = path.join(source, relative), st = fs.lstatSync(directory);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== uid || st.gid !== workerGid ||
        (st.mode & 0o7777) !== 0o550) fail();
    for (const leaf of fs.readdirSync(directory).sort(order)) {
      const name = relative ? `${relative}/${leaf}` : leaf;
      const current = path.join(source, name), info = fs.lstatSync(current);
      if (info.isSymbolicLink()) fail();
      if (files.length + directories.length >= importer.MAX_ENTRIES) fail();
      if (info.isDirectory()) { directories.push(name); visit(name); }
      else {
        const checked = checkedFile(current, uid, workerGid, [0o440, 0o550], importer.MAX_FILE_BYTES);
        total += checked.bytes.length;
        if (total > importer.MAX_TOTAL_BYTES) fail();
        files.push({ path: name, bytes: checked.bytes.length, mode: (checked.stat.mode & 0o777) === 0o550 ? 0o755 : 0o644,
          sha256: hash(checked.bytes), data_base64: checked.bytes.toString('base64') });
      }
    }
  }
  visit(''); files.sort((a, b) => order(a.path, b.path)); directories.sort(order);
  const input = { schema_version: importer.SCHEMA, directories, files,
    manifest_sha256: importer.manifestDigest(files), directories_sha256: importer.directoriesDigest(directories) };
  importer.validateImport(Buffer.from(JSON.stringify(input)));
  if (saved.manifest_sha256 !== input.manifest_sha256 || saved.directories_sha256 !== input.directories_sha256 ||
      saved.files !== files.length || saved.directories !== directories.length || saved.total_bytes !== total) fail();
  return { ...input, total_bytes: total };
}
function main() {
  if (process.platform !== 'linux' || process.argv.length !== 6 || process.argv[2] !== '/source' ||
      process.argv[3] !== '/state' || !/^[1-9][0-9]{0,9}$/.test(process.argv[4]) ||
      !/^[1-9][0-9]{0,9}$/.test(process.argv[5])) fail();
  const uid = Number(process.argv[4]), workerGid = Number(process.argv[5]);
  if (uid === workerGid || uid > 0xfffffffe || workerGid > 0xfffffffe || process.getuid() !== uid ||
      process.geteuid() !== uid || process.getgid() !== uid || process.getegid() !== uid ||
      process.getgroups().some(gid => gid !== uid)) fail();
  if (!fs.fstatSync(3).isFIFO() || !fs.fstatSync(4).isFIFO()) fail();
  // Owner A could chmod a merely DAC-readonly tree. EROFS distinguishes the
  // actual readonly mount from an ordinary mode-bit denial.
  let readonly = false;
  try { fs.chmodSync('/source', 0o750); } catch (error) { readonly = error.code === 'EROFS'; }
  if (!readonly) fail();
  const observed = readback('/source', '/state', uid, workerGid);
  const answer = `KSA1 ${observed.manifest_sha256} ${observed.directories_sha256} ${observed.files.length} ${observed.total_bytes} EROFS\n`;
  if (Buffer.byteLength(answer) > 256 || fs.writeSync(4, answer) !== Buffer.byteLength(answer)) fail();
  fs.closeSync(4);
  let command = '';
  const stream = fs.createReadStream(null, { fd: 3, autoClose: true, highWaterMark: 16 });
  stream.on('data', bytes => { command += bytes.toString('ascii'); if (!'STOP\n'.startsWith(command)) process.exit(2); });
  stream.on('error', () => { process.exitCode = 2; });
  stream.on('end', () => { process.exitCode = command === 'STOP\n' ? 0 : 2; });
}
if (require.main === module) {
  try { main(); } catch { process.exitCode = 1; }
}
module.exports = { readback };
