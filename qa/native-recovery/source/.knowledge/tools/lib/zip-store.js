'use strict';

const fs = require('fs');
const path = require('path');

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function dosTime(date = new Date()) {
  if (!Number.isFinite(date.getTime()) || date.getFullYear() > 2107) {
    throw Object.assign(new Error('ZIP timestamp is outside the supported DOS date range.'), { code: 'zip_date_unsupported' });
  }
  const year = Math.max(date.getFullYear(), 1980);
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

function prepareEntries(files) {
  const invalid = (code, message) => Object.assign(new Error(message), { code });
  if (!Array.isArray(files) || files.length > 0xffff) throw invalid('zip_inventory_invalid', 'ZIP requires a bounded array of regular file entries.');
  const names = new Set();
  const entries = files.map((file) => {
    if (!file || typeof file.name !== 'string') throw invalid('zip_entry_name_invalid', 'ZIP entry requires a string name.');
    const name = file.name.replace(/\\/g, '/');
    const segments = name.split('/');
    if (!name || /[\x00-\x1f\x7f<>:"|?*]/.test(name) ||
        segments.some(segment => {
          const stem = segment.split('.')[0].replace(/[. ]+$/u, '');
          return !segment || segment === '.' || segment === '..' || /[. ]$/.test(segment) ||
            /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³]|conin\$|conout\$)$/iu.test(stem);
        }) ||
        Buffer.from(name, 'utf8').toString('utf8') !== name) {
      throw invalid('zip_entry_name_invalid', 'ZIP entry name must be a portable relative file path.');
    }
    const key = name.normalize('NFC').toLowerCase();
    if (names.has(key)) throw invalid('zip_entry_collision', 'ZIP entry names collide after portable normalization.');
    names.add(key);
    const encodedName = Buffer.from(name, 'utf8');
    if (encodedName.length > 0xffff) throw invalid('zip_size_unsupported', 'ZIP entry name exceeds the classic ZIP limit.');
    if (!Buffer.isBuffer(file.data) && typeof file.data !== 'string') throw invalid('zip_entry_data_invalid', 'ZIP entry data must be a Buffer or string.');
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data, 'utf8');
    if (data.length > 0xffffffff) throw invalid('zip_size_unsupported', 'ZIP64 data is not supported by this writer.');
    return { name: encodedName, data, key };
  });
  if (entries.some(entry => {
    const name = entry.name.toString('utf8');
    return name !== name.normalize('NFC');
  })) throw invalid('zip_entry_name_invalid', 'ZIP entry names must use NFC normalization.');
  let localSize = 0, centralSize = 0;
  for (const entry of entries) {
    const segments = entry.key.split('/');
    for (let count = 1; count < segments.length; count++) {
      if (names.has(segments.slice(0, count).join('/'))) throw invalid('zip_entry_collision', 'A ZIP file entry cannot also be another entry\'s directory.');
    }
    localSize += 30 + entry.name.length + entry.data.length;
    centralSize += 46 + entry.name.length;
    if (localSize > 0xffffffff || centralSize > 0xffffffff || localSize + centralSize + 22 > 0xffffffff) {
      throw invalid('zip_size_unsupported', 'ZIP64 archives are not supported by this writer.');
    }
  }
  return entries;
}

function writeZip(zipPath, files) {
  // Reject ambiguous paths before touching an existing destination. Both ZIP
  // headers declare UTF-8 so independent readers preserve non-ASCII names.
  const entries = prepareEntries(files);
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const stamp = dosTime();
  for (const { name, data } of entries) {
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(stamp.time, 10);
    local.writeUInt16LE(stamp.day, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(stamp.time, 12);
    central.writeUInt16LE(stamp.day, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  fs.mkdirSync(path.dirname(zipPath), { recursive: true });
  fs.writeFileSync(zipPath, Buffer.concat([...localParts, ...centralParts, end]));
}

module.exports = { writeZip, crc32 };
