'use strict';
// QA-only frozen-input verifier. Builtins only. No product execution.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const INPUT = Object.freeze({ bytes: 705049, sha256: '24df61b60ff43899a8e85884acf14bef6eb3a8c4a2537413033f5092b6965407',
  manifestSha256: '9eed50d5269173d2d1068c13554e5b7ee62b90ce5b099d92886fc110cff0d53d', payloads: 119, members: 120, payloadBytes: 2327077 });
const MAX_FILE = 2 * 1024 * 1024, MAX_TOTAL = 8 * 1024 * 1024;
const fail = code => { throw Object.assign(new Error(code), { code }); };
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Reject duplicate decoded object keys, excessive nesting and trailing bytes.
function strictJson(bytes) {
  if (bytes.length > 524288) fail('D5_JSON_LIMIT');
  let s; try { s = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail('D5_JSON_UTF8'); }
  let i = 0, nodes = 0;
  const ws = () => { while (i < s.length && /[ \t\r\n]/.test(s[i])) i++; };
  function string() {
    if (s[i++] !== '"') fail('D5_JSON_STRING');
    const begin = i - 1;
    while (i < s.length) {
      const c = s[i++];
      if (c === '"') { try { return JSON.parse(s.slice(begin, i)); } catch { fail('D5_JSON_STRING'); } }
      if (c === '\\') i++;
      else if (c.charCodeAt(0) < 32) fail('D5_JSON_STRING');
    }
    fail('D5_JSON_EOF');
  }
  function value(depth) {
    ws(); if (++nodes > 10000 || depth > 24) fail('D5_JSON_DEPTH');
    if (s[i] === '"') return string();
    if (s[i] === '{') {
      i++; ws(); const out = Object.create(null), keys = new Set();
      if (s[i] === '}') { i++; return out; }
      for (;;) {
        ws(); const key = string(); if (keys.has(key)) fail('D5_JSON_DUPLICATE'); keys.add(key);
        ws(); if (s[i++] !== ':') fail('D5_JSON_COLON'); out[key] = value(depth + 1); ws();
        const c = s[i++]; if (c === '}') return out; if (c !== ',') fail('D5_JSON_COMMA');
      }
    }
    if (s[i] === '[') {
      i++; ws(); const out = []; if (s[i] === ']') { i++; return out; }
      for (;;) { out.push(value(depth + 1)); ws(); const c = s[i++]; if (c === ']') return out; if (c !== ',') fail('D5_JSON_COMMA'); }
    }
    for (const [word, val] of [['true', true], ['false', false], ['null', null]]) if (s.startsWith(word, i)) { i += word.length; return val; }
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(s.slice(i));
    if (!m) fail('D5_JSON_VALUE'); i += m[0].length; const n = Number(m[0]); if (!Number.isFinite(n)) fail('D5_JSON_NUMBER'); return n;
  }
  const out = value(0); ws(); if (i !== s.length) fail('D5_JSON_TRAILING'); return out;
}

function safeName(name) {
  // The fixed archive is ASCII. Reject alternate Win32 path spellings entirely.
  if (typeof name !== 'string' || name.length > 240 || !/^[\x21-\x7e]+$/.test(name) || /[\\:<>"|?*]/.test(name) || name.startsWith('/')) fail('D5_ZIP_PATH');
  for (const component of name.split('/')) {
    if (!component || component === '.' || component === '..' || /[. ]$/.test(component) ||
        /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(component) || component.includes('~')) fail('D5_ZIP_PATH');
  }
  return name;
}
const crcTable = new Uint32Array(256);
for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[n] = c >>> 0; }
function crc32(buf) { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

function parseZip(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 22 || buffer.length > 16 * 1024 * 1024) fail('D5_ZIP_SIZE');
  const end = buffer.length - 22;
  const u16 = p => { if (p < 0 || p + 2 > buffer.length) fail('D5_ZIP_BOUNDS'); return buffer.readUInt16LE(p); };
  const u32 = p => { if (p < 0 || p + 4 > buffer.length) fail('D5_ZIP_BOUNDS'); return buffer.readUInt32LE(p); };
  if (u32(end) !== 0x06054b50 || u16(end + 4) || u16(end + 6) || u16(end + 20)) fail('D5_ZIP_EOCD');
  const count = u16(end + 10), centralSize = u32(end + 12), central = u32(end + 16);
  if (count < 1 || count > 200 || u16(end + 8) !== count || central + centralSize !== end) fail('D5_ZIP_DIRECTORY');
  let cursor = central, localCursor = 0, total = 0;
  const entries = new Map(), folded = new Set(), allNames = [];
  for (let index = 0; index < count; index++) {
    if (cursor + 46 > end || u32(cursor) !== 0x02014b50) fail('D5_ZIP_CENTRAL');
    const needed = u16(cursor + 6), flags = u16(cursor + 8), method = u16(cursor + 10), crc = u32(cursor + 16);
    const compressed = u32(cursor + 20), length = u32(cursor + 24), nameLen = u16(cursor + 28), extra = u16(cursor + 30), comment = u16(cursor + 32);
    const attrs = u32(cursor + 38), local = u32(cursor + 42), mode = (attrs >>> 16) & 0xf000;
    if (needed > 20 || flags !== 0 || ![0, 8].includes(method) || extra || comment || u16(cursor + 34) || u16(cursor + 36) ||
        ![0, 0x8000].includes(mode) || (attrs & (0x10 | 0x400)) || length > MAX_FILE || compressed > buffer.length || nameLen < 1 || cursor + 46 + nameLen > end) fail('D5_ZIP_METADATA');
    const nameBytes = buffer.subarray(cursor + 46, cursor + 46 + nameLen);
    if (nameBytes.some(b => b > 0x7f)) fail('D5_ZIP_PATH');
    const name = safeName(nameBytes.toString('ascii')), fold = name.toLowerCase();
    if (folded.has(fold)) fail('D5_ZIP_DUPLICATE'); folded.add(fold); allNames.push(fold);
    if (local !== localCursor || local + 30 > central || u32(local) !== 0x04034b50 || u16(local + 4) !== needed || u16(local + 6) !== flags ||
        u16(local + 8) !== method || u32(local + 14) !== crc || u32(local + 18) !== compressed || u32(local + 22) !== length ||
        u16(local + 26) !== nameLen || u16(local + 28) !== 0 || !buffer.subarray(local + 30, local + 30 + nameLen).equals(nameBytes)) fail('D5_ZIP_LOCAL');
    const offset = local + 30 + nameLen; if (offset + compressed > central) fail('D5_ZIP_OVERLAP');
    const packed = buffer.subarray(offset, offset + compressed); let bytes;
    try {
      if (method === 0) bytes = Buffer.from(packed);
      else { const unpack = zlib.inflateRawSync(packed, { maxOutputLength: Math.max(1, length), info: true });
        if (unpack.engine.bytesWritten !== packed.length) fail('D5_ZIP_DEFLATE_TRAILING'); bytes = unpack.buffer; }
    } catch (error) { if (error.code?.startsWith('D5_')) throw error; fail('D5_ZIP_DEFLATE'); }
    if (bytes.length !== length || crc32(bytes) !== crc) fail('D5_ZIP_CRC');
    total += bytes.length; if (total > MAX_TOTAL) fail('D5_ZIP_TOTAL');
    entries.set(name, bytes); localCursor = offset + compressed; cursor += 46 + nameLen;
  }
  if (cursor !== end || localCursor !== central) fail('D5_ZIP_UNCLAIMED');
  for (const name of allNames) { const parts = name.split('/'); for (let i = 1; i < parts.length; i++) if (folded.has(parts.slice(0, i).join('/'))) fail('D5_ZIP_FILE_DIRECTORY_ALIAS'); }
  return entries;
}

function verifyArchive(bytes) {
  if (bytes.length !== INPUT.bytes || sha(bytes) !== INPUT.sha256) fail('D5_INPUT_OUTER_PIN');
  const entries = parseZip(bytes), manifestBytes = entries.get('MANIFEST.json');
  if (entries.size !== INPUT.members || !manifestBytes || sha(manifestBytes) !== INPUT.manifestSha256) fail('D5_INPUT_MANIFEST_PIN');
  const manifest = strictJson(manifestBytes);
  if (manifest.schema !== 'windows-arm-team-test-input.v1' || manifest.label !== 'SOURCE_TEST_INPUT_ONLY_NOT_INSTALLER_OR_RELEASE' ||
      manifest.source_base_commit !== '65ec67ce3c806507aa2170a266699d2a2dcac4ab' || manifest.working_tree_bytes_pinned_separately !== true ||
      !manifest.files || Object.keys(manifest.files).length !== INPUT.payloads) fail('D5_INPUT_MANIFEST');
  let total = 0;
  for (const [name, pin] of Object.entries(manifest.files)) {
    safeName(name); const data = entries.get(name);
    if (!name.startsWith('runtime/.knowledge/') || !data || !pin || Object.keys(pin).sort().join(',') !== 'bytes,sha256' ||
        !Number.isSafeInteger(pin.bytes) || pin.bytes < 0 || !/^[a-f0-9]{64}$/.test(pin.sha256) || data.length !== pin.bytes || sha(data) !== pin.sha256) fail('D5_INPUT_PAYLOAD_PIN');
    total += data.length;
  }
  if (total !== INPUT.payloadBytes) fail('D5_INPUT_PAYLOAD_TOTAL');
  return { entries, manifest };
}

function equalPath(a, b) { return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b; }
function noReparseChain(target) {
  if (!path.isAbsolute(target) || target.startsWith('\\\\') || !equalPath(path.resolve(target), target)) fail('D5_FS_ABSOLUTE');
  const chain = []; let current = target;
  for (;;) { chain.push(current); const parent = path.dirname(current); if (parent === current) break; current = parent; }
  for (const item of chain.reverse()) {
    const st = fs.lstatSync(item, { bigint: true });
    if (st.isSymbolicLink() || !equalPath(fs.realpathSync.native(item), item)) fail('D5_FS_ALIAS');
  }
}
function identity(st) { return `${st.dev}:${st.ino}`; }
function readRegular(file, maximum) {
  noReparseChain(file); const before = fs.lstatSync(file, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maximum)) fail('D5_FS_REGULAR');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const pinned = fs.fstatSync(fd, { bigint: true }); if (identity(before) !== identity(pinned)) fail('D5_FS_CHANGED');
    const storage = Buffer.alloc(Number(pinned.size) + 1); let used = 0;
    while (used < storage.length) { const n = fs.readSync(fd, storage, used, storage.length - used, null); if (n === 0) break; used += n; }
    if (used > maximum || BigInt(used) !== pinned.size) fail('D5_FS_SIZE'); const bytes = storage.subarray(0, used);
    const after = fs.fstatSync(fd, { bigint: true });
    if (identity(after) !== identity(pinned) || after.size !== pinned.size || after.mtimeNs !== pinned.mtimeNs || after.ctimeNs !== pinned.ctimeNs ||
        identity(fs.lstatSync(file, { bigint: true })) !== identity(pinned)) fail('D5_FS_CHANGED');
    return bytes;
  } finally { fs.closeSync(fd); }
}
function verifyExisting(destination, entries) {
  noReparseChain(destination); const rootId = identity(fs.lstatSync(destination, { bigint: true }));
  const seen = new Set(), directories = new Set(); let nodes = 0;
  for (const name of entries.keys()) { const parts = name.split('/'); for (let i = 1; i < parts.length; i++) directories.add(parts.slice(0, i).join('/')); }
  function walk(directory) {
    noReparseChain(directory);
    for (const name of fs.readdirSync(directory)) {
      if (++nodes > 400) fail('D5_FS_INVENTORY_LIMIT');
      const full = path.join(directory, name), st = fs.lstatSync(full, { bigint: true });
      if (st.isSymbolicLink()) fail('D5_FS_ALIAS');
      if (st.isDirectory()) { if (!directories.has(path.relative(destination, full).split(path.sep).join('/'))) fail('D5_FS_UNDECLARED_DIRECTORY'); walk(full); }
      else {
        const rel = path.relative(destination, full).split(path.sep).join('/'), expected = entries.get(rel);
        if (!expected || !readRegular(full, MAX_FILE).equals(expected)) fail('D5_FS_SOURCE_CHANGED'); seen.add(rel);
      }
    }
  }
  walk(destination);
  if (seen.size !== entries.size || identity(fs.lstatSync(destination, { bigint: true })) !== rootId) fail('D5_FS_SOURCE_CHANGED');
}
function extractFresh(destination, entries) {
  const parent = path.dirname(destination); noReparseChain(parent);
  if (fs.existsSync(destination)) fail('D5_FS_FRESH_REQUIRED');
  fs.mkdirSync(destination, { mode: 0o700 }); const rootId = identity(fs.lstatSync(destination, { bigint: true }));
  for (const [name, data] of entries) {
    const full = path.join(destination, ...name.split('/'));
    let directory = destination;
    for (const part of name.split('/').slice(0, -1)) {
      directory = path.join(directory, part);
      if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
      noReparseChain(directory);
    }
    if (identity(fs.lstatSync(destination, { bigint: true })) !== rootId) fail('D5_FS_ROOT_CHANGED');
    const fd = fs.openSync(full, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0), 0o600);
    try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  verifyExisting(destination, entries);
}
function main(args) {
  if (args.length !== 3 || !['extract', 'verify-existing'].includes(args[0])) fail('D5_INPUT_ARGUMENTS');
  const [mode, archive, destination] = args;
  noReparseChain(path.dirname(destination));
  const { entries } = verifyArchive(readRegular(archive, 16 * 1024 * 1024));
  if (mode === 'extract') extractFresh(destination, entries); else verifyExisting(destination, entries);
  return { status: 'PASS_SOURCE_TEST_INPUT_INTEGRITY', mode, payloads: INPUT.payloads, members: INPUT.members, payload_bytes: INPUT.payloadBytes,
    input_sha256: INPUT.sha256, exact_internal_manifest: true, product_execution: 'NOT_RUN_BY_VERIFIER' };
}
module.exports = { INPUT, strictJson, safeName, crc32, parseZip, verifyArchive, readRegular, noReparseChain, verifyExisting, extractFresh, main };
if (require.main === module) {
  try { process.stdout.write(JSON.stringify(main(process.argv.slice(2))) + '\n'); }
  catch (error) { process.stderr.write((/^D5_[A-Z_]+$/.test(error.code || '') ? error.code : 'D5_INPUT_VERIFY_FAILED') + '\n'); process.exitCode = 1; }
}
