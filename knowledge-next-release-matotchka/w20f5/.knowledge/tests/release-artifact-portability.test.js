'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { test } = require('node:test');
const { readZipEntries, validate } = require('../tools/validate-release-artifact');
const { buildPackageEntries, createZip, readEntryData } = require('../tools/package-release');
const { loadReleaseContract, validateReleaseInventory } = require('../tools/lib/release-contract');
const { withTempFixture } = require('../tools/lib/strict-temp-cleanup');

const payload = Buffer.from('module.exports = true;\n');
function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let i = 0; i < 8; i++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
}

// These ZIPs are data only. Bodies and all size/CRC/header fields are coherent
// except the field a test explicitly varies; no archive is ever extracted.
function archive(definitions) {
  const locals = [], centrals = []; let offset = 0;
  for (const definition of definitions) {
    const name = Buffer.isBuffer(definition.name) ? definition.name : Buffer.from(definition.name);
    const localName = definition.localName || name, method = definition.method ?? 8;
    const flags = definition.flags ?? (0x0800 | (definition.descriptor ? 8 : 0));
    const compressed = method === 0 ? payload : zlib.deflateRawSync(payload), crc = definition.crc ?? crc32(payload);
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4);
    local.writeUInt16LE(definition.localFlags ?? flags, 6); local.writeUInt16LE(method, 8); local.writeUInt16LE(33, 12);
    if (!definition.descriptor) { local.writeUInt32LE(crc, 14); local.writeUInt32LE(compressed.length, 18); local.writeUInt32LE(payload.length, 22); }
    local.writeUInt16LE(localName.length, 26);
    const descriptor = Buffer.alloc(definition.descriptor ? 16 : 0);
    if (descriptor.length) { descriptor.writeUInt32LE(0x08074b50); descriptor.writeUInt32LE(crc, 4); descriptor.writeUInt32LE(compressed.length, 8); descriptor.writeUInt32LE(payload.length, 12); }
    const localBytes = Buffer.concat([local, localName, compressed, descriptor]);
    const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50); central.writeUInt16LE(0x0314, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8); central.writeUInt16LE(method, 10); central.writeUInt16LE(33, 14); central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20); central.writeUInt32LE(payload.length, 24); central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(definition.externalAttrs ?? 0, 38); central.writeUInt32LE(offset, 42);
    locals.push(localBytes); centrals.push(central, name); offset += localBytes.length;
  }
  const centralBytes = Buffer.concat(centrals), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(definitions.length, 8); end.writeUInt16LE(definitions.length, 10); end.writeUInt32LE(centralBytes.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBytes, end]);
}

function read(definitions) {
  return withTempFixture({ prefix: 'release-portability-' }, directory => {
    const zip = path.join(directory, 'data.zip'); fs.writeFileSync(zip, archive(definitions)); return readZipEntries(zip);
  });
}
function refused(definition, type) {
  const result = read([definition]);
  assert(result.violations.some(item => item.type === type), JSON.stringify(result.violations));
  assert.equal(result.violations.some(item => /crc|inflate|size_mismatch/.test(item.type)), false, 'Unrelated corrupt payload must not explain refusal');
  return result;
}

test('stored and deflated entries preserve ASCII flag-zero and NFC Unicode bodies', () => {
  for (const method of [0, 8]) {
    const result = read([{ name: '.knowledge/tools/probe.js', flags: 0, method }, { name: '.knowledge/tools/café.js', method }]);
    assert.deepEqual(result.violations, []); for (const entry of result.entries) assert.deepEqual(entry.body, payload);
  }
});

test('Deflate compression option flags remain supported', () => {
  for (const flags of [0x0802, 0x0804, 0x0806]) {
    const result = read([{ name: '.knowledge/tools/probe.js', flags }]);
    assert.deepEqual(result.violations, []); assert.deepEqual(result.entries[0].body, payload);
  }
});

test('valid data descriptor archives remain supported for both accepted methods', () => {
  for (const method of [0, 8]) {
    const result = read([{ name: '.knowledge/tools/probe.js', descriptor: true, method }]);
    assert.deepEqual(result.violations, []); assert.deepEqual(result.entries[0].body, payload);
  }
});

test('one decomposed Unicode filename is rejected before normalization', () => {
  refused({ name: '.knowledge/tools/cafe\u0301.js' }, 'zip_unicode_normalization');
});

test('NFC/NFD aliases still trigger duplicate-entry detection', () => {
  const result = read([{ name: '.knowledge/tools/café.js' }, { name: '.knowledge/tools/cafe\u0301.js' }]);
  assert(result.violations.some(item => item.type === 'zip_unicode_normalization'));
  assert(result.violations.some(item => item.type === 'zip_duplicate_entry'));
});

test('reserved device names are refused in any path segment, including extensions', () => {
  for (const name of ['NUL.js', 'con', 'COM1/probe.js', 'lpt9.log', 'COM¹.txt', 'LPT²/a.js', 'NUL .js', 'CONOUT$.txt']) {
    refused({ name: '.knowledge/tools/' + name }, 'zip_path_invalid');
  }
});

test('portable path checks refuse stream syntax, special characters and trailing aliases', () => {
  for (const name of ['probe.js:shadow', 'probe.js.', 'probe.js ', 'bad?.js', 'bad*.js', 'bad<name.js', 'bad|name.js', 'bad\u007f.js']) {
    refused({ name: '.knowledge/tools/' + name }, 'zip_path_invalid');
  }
});

test('invalid UTF-8 sequences are rejected while a literal replacement character is valid', () => {
  for (const sequence of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80]]) {
    refused({ name: Buffer.concat([Buffer.from('.knowledge/tools/'), Buffer.from(sequence), Buffer.from('.js')]) }, 'zip_filename_encoding');
  }
  const result = read([{ name: '.knowledge/tools/\ufffd.js' }]);
  assert.deepEqual(result.violations, []); assert.deepEqual(result.entries[0].body, payload);
});

test('non-ASCII filenames require an explicit UTF-8 encoding flag', () => {
  refused({ name: '.knowledge/tools/café.js', flags: 0 }, 'zip_filename_encoding');
});

test('encryption, reserved flags and method-inapplicable options cannot validate as plaintext', () => {
  for (const flag of [1, 0x10, 0x20, 0x40, 0x100, 0x1000, 0x2000, 0x4000, 0x8000]) {
    const result = refused({ name: '.knowledge/tools/probe.js', flags: 0x0800 | flag }, 'zip_flags_unsupported');
    assert.equal(result.entries[0].body.length, 0);
  }
  refused({ name: '.knowledge/tools/probe.js', method: 0, flags: 0x0802 }, 'zip_flags_unsupported');
});

test('local-only unsupported flags are refused independently of central flags', () => {
  const result = refused({ name: '.knowledge/tools/probe.js', localFlags: 0x0801 }, 'zip_flags_unsupported');
  assert(result.violations.some(item => item.type === 'zip_local_central_mismatch')); assert.equal(result.entries[0].body.length, 0);
});

test('all local and central general-purpose flags must agree', () => {
  refused({ name: '.knowledge/tools/probe.js', localFlags: 0x0802 }, 'zip_local_central_mismatch');
  refused({ name: '.knowledge/tools/probe.js', localFlags: 0 }, 'zip_local_central_mismatch');
});

test('raw local and central name bytes must agree even if lossy decoding would match', () => {
  const prefix = Buffer.from('.knowledge/tools/'), suffix = Buffer.from('.js');
  refused({ name: Buffer.concat([prefix, Buffer.from([0xff]), suffix]), localName: Buffer.concat([prefix, Buffer.from([0xfe]), suffix]) }, 'zip_local_central_mismatch');
});

test('existing case-collision, traversal and Unix symlink refusals remain enforced', () => {
  const result = read([{ name: '.knowledge/tools/probe.js' }, { name: '.knowledge/tools/PROBE.js' }]);
  assert(result.violations.some(item => item.type === 'zip_duplicate_entry'));
  refused({ name: '.knowledge/tools/../probe.js' }, 'zip_path_invalid');
  refused({ name: '.knowledge/tools/link.js', externalAttrs: (0o120777 << 16) >>> 0 }, 'zip_external_attr_forbidden');
});

test('CRC mismatch remains distinguishable from filename and flag violations', () => {
  const result = read([{ name: '.knowledge/tools/probe.js', crc: (crc32(payload) ^ 1) >>> 0 }]);
  assert.deepEqual(result.violations.map(item => item.type), ['zip_crc_mismatch']);
});

const sourceRoot = path.resolve(__dirname, '..');
const contract = loadReleaseContract(sourceRoot);
const version = JSON.parse(fs.readFileSync(path.join(sourceRoot, 'package.json'), 'utf8')).version;
const runtimeEntries = () => buildPackageEntries(sourceRoot).entries;
const runtimeInventory = entries => validateReleaseInventory(entries, contract, { prefix: '.knowledge/' });
const systemOnlyExamples = ['tools/lib/queue-lifecycle.js', 'tools/lib/watcher-state-store.js'];

function validateRuntime(entries, check) {
  return withTempFixture({ prefix: 'release-inventory-' }, directory => {
    const zipPath = path.join(directory, `knowledge-v${version}.zip`);
    createZip(entries, zipPath);
    const physical = readZipEntries(zipPath);
    assert.deepEqual(physical.violations, [], 'Inventory mutations must preserve valid ZIP bodies, CRCs and headers');
    const result = validate(zipPath);
    if (check) check(physical, result);
    return result;
  });
}

function withoutRequired(entries, required) {
  assert(contract.manifest.required_system_files.includes(required), 'The omitted file is required by the installer');
  assert(!contract.required_public_paths.includes(required), 'This regression reaches the independent install-required contract');
  assert(entries.some(entry => entry.name === `.knowledge/${required}`));
  return entries.filter(entry => entry.name !== `.knowledge/${required}`);
}

function assertMissing(result, type, required) {
  assert(result.violations.some(item => item.type === type && item.entry === `.knowledge/${required}`), JSON.stringify(result.violations));
  assert.equal(result.violations.some(item => /crc|inflate|size_mismatch/.test(item.type)), false);
}

test('canonical runtime satisfies install inventory and preserves generated gitignore and source-only exclusions', () => {
  const entries = runtimeEntries(), names = new Set(entries.map(entry => entry.name));
  for (const required of [...contract.required_public_paths, ...contract.manifest.required_system_files]) {
    assert(names.has(`.knowledge/${required}`), required);
  }
  for (const excluded of ['tools/package-release.js', 'tools/validate-release-artifact.js', 'tools/lib/release-contract.js', 'tests/release-artifact-portability.test.js']) {
    assert(!names.has(`.knowledge/${excluded}`), excluded);
  }
  const gitignore = entries.find(entry => entry.name === '.knowledge/.gitignore');
  assert.equal(gitignore.abs, path.join(sourceRoot, 'templates', 'git-policy', '.knowledge.gitignore'));
  assert.deepEqual(runtimeInventory(entries).violations, []);
  const result = validateRuntime(entries, physical => {
    assert.deepEqual(physical.entries.find(entry => entry.name === '.knowledge/.gitignore').body, readEntryData(gitignore));
  });
  assert.equal(result.status, 'ok', JSON.stringify(result.violations));
  assert.equal(result.entries, entries.length);
});

for (const required of systemOnlyExamples) {
  test(`staging refuses install-required omission ${required}`, () => {
    const result = runtimeInventory(withoutRequired(runtimeEntries(), required));
    assertMissing(result, 'required_system_entry_missing', required);
    assert.equal(result.violations.length, 1);
  });

  test(`physical CRC-valid ZIP refuses install-required omission ${required}`, () => {
    const entries = runtimeEntries(), result = validateRuntime(withoutRequired(entries, required));
    assert.equal(result.status, 'failed');
    assert.equal(result.entries, entries.length - 1);
    assertMissing(result, 'required_system_entry_missing', required);
    assert.equal(result.violations.length, 1);
  });
}

test('required system names use exact spelling independently of case-collision detection', () => {
  for (const required of systemOnlyExamples) {
    const entries = runtimeEntries().map(entry => entry.name === `.knowledge/${required}`
      ? { ...entry, name: `.knowledge/${path.posix.dirname(required)}/${path.posix.basename(required).toUpperCase()}` } : entry);
    for (const result of [runtimeInventory(entries), validateRuntime(entries)]) {
      assertMissing(result, 'required_system_entry_missing', required);
      assert.equal(result.violations.some(item => item.type === 'zip_duplicate_entry'), false, 'One wrong-case entry is not a duplicate');
    }
  }
});

test('required public names also require exact spelling when one case variant is present', () => {
  const required = 'tools/field-report.js';
  assert(contract.required_public_paths.includes(required));
  const entries = runtimeEntries().map(entry => entry.name === `.knowledge/${required}`
    ? { ...entry, name: '.knowledge/tools/FIELD-REPORT.js' } : entry);
  for (const result of [runtimeInventory(entries), validateRuntime(entries)]) {
    assertMissing(result, 'required_entry_missing', required);
    assert.equal(result.violations.some(item => item.type === 'zip_duplicate_entry'), false);
  }
});

test('the complete manifest system-required list is enforced without an ad hoc helper inventory', () => {
  const entries = runtimeEntries();
  for (const required of contract.manifest.required_system_files) {
    assert(entries.some(entry => entry.name === `.knowledge/${required}`), required);
    const result = runtimeInventory(entries.filter(entry => entry.name !== `.knowledge/${required}`));
    assertMissing(result, 'required_system_entry_missing', required);
  }
});

test('a source-only tool is still refused when all required runtime files are present', () => {
  const entries = [...runtimeEntries(), {
    abs: path.join(sourceRoot, 'tools', 'package-release.js'), rel: 'tools/package-release.js', name: '.knowledge/tools/package-release.js'
  }];
  for (const result of [runtimeInventory(entries), validateRuntime(entries)]) {
    assert(result.violations.some(item => item.type === 'manifest_excluded_path' && item.entry === '.knowledge/tools/package-release.js'));
    assert.equal(result.violations.some(item => item.type === 'required_system_entry_missing'), false);
  }
});

for (const parent of ['.knowledge/tools', '.knowledge/TOOLS']) {
  for (const position of ['first', 'last']) {
    test(`full valid runtime refuses regular parent ${parent} in ${position} position`, () => {
      withTempFixture({ prefix: 'release-file-parent-' }, directory => {
        const extraFile = path.join(directory, 'parent-body');
        fs.writeFileSync(extraFile, 'ordinary file conflicting with runtime children\n');
        const blocker = { abs: extraFile, rel: parent.slice('.knowledge/'.length), name: parent };
        const complete = runtimeEntries();
        const entries = position === 'first' ? [blocker, ...complete] : [...complete, blocker];
        for (const result of [runtimeInventory(entries), validateRuntime(entries)]) {
          assert(result.violations.some(item => item.type === 'zip_file_directory_conflict'), JSON.stringify(result.violations));
          assert.equal(result.violations.some(item => /crc|inflate|size_mismatch|missing/.test(item.type)), false,
            'All required payloads and ZIP integrity remain valid');
        }
      });
    });
  }
}
