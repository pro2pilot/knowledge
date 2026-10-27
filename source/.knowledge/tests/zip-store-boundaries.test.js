'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { test } = require('node:test');
const { writeZip } = require('../tools/lib/zip-store');
const { readZipEntries } = require('../tools/validate-release-artifact');
const { removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');

function fixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-zip-store-'));
  const target = path.join(root, 'data.zip');
  fs.writeFileSync(target, 'existing destination');
  try { run(target); } finally { removeTempDirStrict(root); }
}

test('ZIP preserves Unicode filenames, UTF-8 flags and Buffer/string bodies', () => fixture(target => {
  const files = [{ name: 'notes/заметка café 日本語.txt', data: 'точные bytes\n' },
    { name: 'notes/binary.dat', data: Buffer.from([0, 1, 128, 255]) }];
  writeZip(target, files);
  const parsed = readZipEntries(target);
  assert.deepEqual(parsed.violations, []);
  assert.deepEqual(parsed.entries.map(e => e.name), files.map(e => e.name));
  for (let i = 0; i < files.length; i++) assert.deepEqual(parsed.entries[i].body, Buffer.from(files[i].data));
  const bytes = fs.readFileSync(target), end = bytes.length - 22;
  let central = bytes.readUInt32LE(end + 16);
  for (let i = 0; i < files.length; i++) {
    assert.equal(bytes.readUInt32LE(central), 0x02014b50);
    assert.equal(bytes.readUInt16LE(central + 8) & 0x0800, 0x0800);
    const local = bytes.readUInt32LE(central + 42);
    assert.equal(bytes.readUInt16LE(local + 6) & 0x0800, 0x0800);
    central += 46 + bytes.readUInt16LE(central + 28) + bytes.readUInt16LE(central + 30) + bytes.readUInt16LE(central + 32);
  }
}));

for (const [kind, names] of [
  ['slash collision', ['notes/a.txt', 'notes\\a.txt']],
  ['case collision', ['Readme.md', 'readme.md']],
  ['Unicode normalization collision', ['café.txt', 'cafe\u0301.txt']],
  ['file as later parent', ['notes', 'notes/a.txt']],
  ['file as earlier parent', ['notes/a.txt', 'notes']],
]) test(`ZIP rejects ${kind} before touching destination`, () => fixture(target => {
  assert.throws(() => writeZip(target, names.map(name => ({ name, data: 'test' }))), { code: 'zip_entry_collision' });
  assert.equal(fs.readFileSync(target, 'utf8'), 'existing destination');
}));

for (const name of ['../escape.txt', '/absolute.txt', 'C:\\absolute.txt', 'notes//a.txt', 'notes/./a.txt',
  'notes/NUL.txt', 'notes/a. ', 'notes/unsafe\u0000name', 'notes/lone-\ud800.txt',
  'notes/cafe\u0301.txt', 'notes/COM\u00b9.txt', 'notes/LPT\u00b2/a.js',
  'notes/NUL .js', 'notes/CONIN$.txt', 'notes/CONOUT$.txt']) {
  test(`ZIP rejects unsafe name ${JSON.stringify(name)} before touching destination`, () => fixture(target => {
    assert.throws(() => writeZip(target, [{ name, data: 'test' }]), { code: 'zip_entry_name_invalid' });
    assert.equal(fs.readFileSync(target, 'utf8'), 'existing destination');
  }));
}

test('ZIP bounds filename UTF-8 bytes, classic entry count and rejects unsupported bodies', () => fixture(target => {
  assert.throws(() => writeZip(target, [{ name: 'я'.repeat(32768), data: '' }]), { code: 'zip_size_unsupported' });
  assert.throws(() => writeZip(target, Array(65536)), { code: 'zip_inventory_invalid' });
  let invoked = 0;
  assert.throws(() => writeZip(target, [{ name: 'safe.txt', data: { toString() { invoked++; return 'unexpected'; } } }]), { code: 'zip_entry_data_invalid' });
  assert.equal(invoked, 0);
  assert.equal(fs.readFileSync(target, 'utf8'), 'existing destination');
}));

test('ZIP date errors preserve the previous destination', () => fixture(target => {
  const OriginalDate = Date;
  try {
    global.Date = class extends OriginalDate { constructor(...args) { super(...(args.length ? args : ['2200-01-01T00:00:00Z'])); } };
    assert.throws(() => writeZip(target, [{ name: 'safe.txt', data: '' }]), { code: 'zip_date_unsupported' });
    assert.equal(fs.readFileSync(target, 'utf8'), 'existing destination');
  } finally { global.Date = OriginalDate; }
}));
