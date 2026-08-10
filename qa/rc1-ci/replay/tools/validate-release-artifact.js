#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const {
  loadReleasePolicy,
  compileRule,
  contentAllowed
} = require('./lib/release-policy');
const {
  loadReleaseContract,
  normalizeReleasePath,
  validateReleaseInventory
} = require('./lib/release-contract');

const root = path.resolve(__dirname, '..');
const releasePolicy = loadReleasePolicy(root);
const releaseContract = loadReleaseContract(root);
const packageVersion = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version || null;

function parseArgs(argv) {
  const args = { artifact: null, json: false, profile: 'public_runtime' };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') args.json = true;
    else if (arg === '--profile') args.profile = argv[++i] || args.profile;
    else if (arg.startsWith('--profile=')) args.profile = arg.slice('--profile='.length);
    else if (!args.artifact) args.artifact = arg;
  }
  return args;
}

function fail(message) {
  const error = new Error(message);
  error.releaseValidation = true;
  throw error;
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function eocdOffset(buffer) {
  for (let i = buffer.length - 22; i >= 0; i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) return i;
  }
  fail('ZIP end of central directory not found.');
}

function assertBounds(buffer, offset, length, label) {
  if (offset < 0 || length < 0 || offset + length > buffer.length) fail(`ZIP ${label} is out of bounds.`);
}

function textEntry(name) {
  const ext = path.posix.extname(name).toLowerCase();
  return new Set(['.cjs', '.css', '.csv', '.html', '.js', '.json', '.md', '.mjs', '.ps1', '.snippet', '.svg', '.toml', '.ts', '.txt', '.vbs', '.xml', '.yaml', '.yml']).has(ext) ||
    new Set(['.gitattributes', '.gitignore', '.knowledge.gitignore', 'LICENSE', 'NOTICE', 'README', 'SECURITY']).has(path.posix.basename(name));
}

function artifactVersionFromName(zipPath) {
  const match = path.basename(zipPath).match(/^knowledge-v(\d+\.\d+\.\d+(?:-rc\d+)?)(?:-step\d+-rc\d+(?:-r\d+)?)?\.zip$/i);
  return match ? match[1] : null;
}

function parseSemver(value) {
  const match = String(value || '').match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  return match ? match.slice(1, 4).map(Number) : null;
}

function compareSemver(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  }
  return 0;
}

function normalizeZipName(rawName) {
  return normalizeReleasePath(rawName).path;
}

function normalizeRel(value) {
  return normalizeReleasePath(value).path;
}

function pathViolations(rawName) {
  return normalizeReleasePath(rawName, { rejectBackslash: true }).errors
    .map((reason) => ({ type: 'zip_path_invalid', reason }));
}

function externalAttributeViolation(externalAttrs, name) {
  const mode = (externalAttrs >>> 16) & 0xffff;
  if (!mode) return null;
  const type = mode & 0o170000;
  if (!type || type === 0o100000 || type === 0o040000) return null;
  return { type: 'zip_external_attr_forbidden', entry: name, reason: `non-regular zip entry mode ${mode.toString(8)}` };
}

function readZipEntries(zipPath) {
  const limits = releasePolicy.zip_limits || {};
  const buffer = fs.readFileSync(zipPath);
  const eocd = eocdOffset(buffer);
  const count = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  let ptr = buffer.readUInt32LE(eocd + 16);
  const violations = [];
  const entries = [];
  const seen = new Set();
  let totalUncompressed = 0;

  if (count === 0xffff) fail('ZIP64 central directory is not supported by this validator.');
  if (limits.max_entries && count > limits.max_entries) {
    violations.push({ type: 'zip_bomb_guard', reason: `entry count ${count} exceeds limit ${limits.max_entries}` });
  }
  assertBounds(buffer, ptr, centralSize, 'central directory');

  for (let i = 0; i < count; i += 1) {
    assertBounds(buffer, ptr, 46, 'central directory header');
    if (buffer.readUInt32LE(ptr) !== 0x02014b50) fail(`Invalid central directory header at ${ptr}.`);
    const flags = buffer.readUInt16LE(ptr + 8);
    const method = buffer.readUInt16LE(ptr + 10);
    const expectedCrc = buffer.readUInt32LE(ptr + 16);
    const compressedSize = buffer.readUInt32LE(ptr + 20);
    const uncompressedSize = buffer.readUInt32LE(ptr + 24);
    const nameLength = buffer.readUInt16LE(ptr + 28);
    const extraLength = buffer.readUInt16LE(ptr + 30);
    const commentLength = buffer.readUInt16LE(ptr + 32);
    const externalAttrs = buffer.readUInt32LE(ptr + 38);
    const localOffset = buffer.readUInt32LE(ptr + 42);
    assertBounds(buffer, ptr + 46, nameLength + extraLength + commentLength, 'central directory variable fields');
    const rawName = buffer.slice(ptr + 46, ptr + 46 + nameLength).toString('utf8');
    const normalizedName = normalizeZipName(rawName);
    const name = normalizeRel(rawName);
    const duplicateKey = name.toLowerCase();

    for (const item of pathViolations(rawName)) violations.push({ ...item, entry: rawName });
    if (name !== normalizedName) {
      violations.push({ type: 'zip_unicode_normalization', entry: normalizedName, reason: 'entry name is not NFC-normalized' });
    }
    if (seen.has(duplicateKey)) violations.push({ type: 'zip_duplicate_entry', entry: name, reason: 'duplicate normalized entry name' });
    seen.add(duplicateKey);

    const attrViolation = externalAttributeViolation(externalAttrs, name);
    if (attrViolation) violations.push(attrViolation);
    if (![0, 8].includes(method)) {
      violations.push({ type: 'zip_compression_unsupported', entry: name, reason: `method ${method} is not allowed` });
    }
    let skipInflate = ![0, 8].includes(method);
    const maxOutputLength = limits.max_entry_uncompressed_bytes || 10 * 1024 * 1024;
    if (limits.max_entry_uncompressed_bytes && uncompressedSize > limits.max_entry_uncompressed_bytes) {
      violations.push({ type: 'zip_bomb_guard', entry: name, reason: `entry uncompressed size ${uncompressedSize} exceeds limit ${limits.max_entry_uncompressed_bytes}` });
      skipInflate = true;
    }
    if (compressedSize > 0 && limits.max_compression_ratio && uncompressedSize / compressedSize > limits.max_compression_ratio) {
      violations.push({ type: 'zip_bomb_guard', entry: name, reason: `compression ratio ${(uncompressedSize / compressedSize).toFixed(2)} exceeds limit ${limits.max_compression_ratio}` });
      skipInflate = true;
    }
    if (limits.max_entry_uncompressed_bytes && compressedSize > limits.max_entry_uncompressed_bytes) {
      violations.push({ type: 'zip_bomb_guard', entry: name, reason: `entry compressed size ${compressedSize} exceeds limit ${limits.max_entry_uncompressed_bytes}` });
      skipInflate = true;
    }

    assertBounds(buffer, localOffset, 30, `local header for ${name}`);
    if (buffer.readUInt32LE(localOffset) !== 0x04034b50) fail(`Invalid local header for ${name}.`);
    const localFlags = buffer.readUInt16LE(localOffset + 6);
    const localMethod = buffer.readUInt16LE(localOffset + 8);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    assertBounds(buffer, localOffset + 30, localNameLength + localExtraLength, `local header fields for ${name}`);
    const localName = buffer.slice(localOffset + 30, localOffset + 30 + localNameLength).toString('utf8');
    if (localName !== rawName) violations.push({ type: 'zip_local_central_mismatch', entry: name, reason: 'local filename differs from central directory filename' });
    if (localMethod !== method) violations.push({ type: 'zip_local_central_mismatch', entry: name, reason: 'local compression method differs from central directory method' });
    if ((localFlags & 0x0800) !== (flags & 0x0800)) violations.push({ type: 'zip_local_central_mismatch', entry: name, reason: 'UTF-8 filename flag differs between local and central headers' });

    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    assertBounds(buffer, dataStart, compressedSize, `compressed data for ${name}`);
    const compressed = buffer.slice(dataStart, dataStart + compressedSize);
    let body = Buffer.alloc(0);
    if (!skipInflate && (method === 0 || method === 8)) {
      try {
        body = method === 0 ? compressed : zlib.inflateRawSync(compressed, { maxOutputLength });
      } catch (error) {
        violations.push({ type: 'zip_inflate_failed', entry: name, reason: error.message });
      }
      if (body.length !== uncompressedSize) {
        violations.push({ type: 'zip_size_mismatch', entry: name, reason: `inflated size ${body.length} != central size ${uncompressedSize}` });
      }
      if (body.length > 0 || uncompressedSize === 0) {
        const actualCrc = crc32(body);
        if (actualCrc !== expectedCrc) violations.push({ type: 'zip_crc_mismatch', entry: name, reason: `crc ${actualCrc.toString(16)} != ${expectedCrc.toString(16)}` });
      }
    }

    totalUncompressed += uncompressedSize;
    entries.push({ name, body, method, compressed_size: compressedSize, uncompressed_size: uncompressedSize });
    ptr += 46 + nameLength + extraLength + commentLength;
  }

  if (ptr !== buffer.readUInt32LE(eocd + 16) + centralSize) {
    violations.push({
      type: 'zip_central_directory_size_mismatch',
      reason: `parsed central directory ends at ${ptr}, expected ${buffer.readUInt32LE(eocd + 16) + centralSize}`
    });
  }

  if (limits.max_total_uncompressed_bytes && totalUncompressed > limits.max_total_uncompressed_bytes) {
    violations.push({ type: 'zip_bomb_guard', reason: `total uncompressed size ${totalUncompressed} exceeds limit ${limits.max_total_uncompressed_bytes}` });
  }
  return { entries, violations, total_uncompressed_bytes: totalUncompressed };
}

function validate(zipPath, options = {}) {
  const profile = options.profile || 'public_runtime';
  const zip = readZipEntries(zipPath);
  const entries = zip.entries;
  const violations = [...zip.violations];
  const names = new Set(entries.map((entry) => normalizeRel(entry.name)));
  const artifactVersion = artifactVersionFromName(zipPath);

  if (packageVersion) {
    const currentReleaseNote = `.knowledge/.release-notes/v${packageVersion}.md`;
    if (!names.has(currentReleaseNote)) {
      violations.push({
        type: 'current_release_note_missing',
        entry: currentReleaseNote,
        reason: `artifact must contain the release note for ${packageVersion}`
      });
    }
    for (const name of names) {
      const match = name.match(/^\.knowledge\/\.release-notes\/v(\d+\.\d+\.\d+(?:[-+][^/]+)?)\.md$/i);
      if (match && compareSemver(match[1], packageVersion) > 0) {
        violations.push({
          type: 'future_release_note',
          entry: name,
          reason: `release note ${match[1]} is newer than artifact version ${packageVersion}`
        });
      }
    }
  }

  if (!artifactVersion) {
    violations.push({
      type: 'artifact_name_invalid',
      entry: path.basename(zipPath),
      reason: 'artifact name must be knowledge-v<version>.zip or knowledge-v<version>-stepN-rcN.zip'
    });
  } else if (packageVersion && artifactVersion !== packageVersion) {
    violations.push({
      type: 'artifact_version_mismatch',
      entry: path.basename(zipPath),
      reason: `artifact version ${artifactVersion} != package version ${packageVersion}`
    });
  }

  const configEntry = entries.find((entry) => normalizeRel(entry.name) === '.knowledge/config.yaml');
  if (configEntry && packageVersion) {
    const configText = configEntry.body.toString('utf8');
    const versionMatch = configText.match(/^version:\s*([^\s#]+)/m);
    const configVersion = versionMatch ? versionMatch[1] : null;
    if (!configVersion) {
      violations.push({
        type: 'config_version_missing',
        entry: '.knowledge/config.yaml',
        reason: 'config.yaml must declare version'
      });
    } else if (configVersion !== packageVersion) {
      violations.push({
        type: 'config_version_mismatch',
        entry: '.knowledge/config.yaml',
        reason: `config version ${configVersion} != package version ${packageVersion}`
      });
    }
  }

  const inventory = validateReleaseInventory(entries, releaseContract, {
    prefix: '.knowledge/',
    rejectBackslash: true
  });
  violations.push(...inventory.violations);
  for (const entry of entries) {
    const name = normalizeRel(entry.name);
    if (textEntry(name)) {
      const text = entry.body.toString('utf8');
      if (name.toLowerCase().endsWith('.json')) {
        try {
          const parsed = JSON.parse(text);
          const schemaVersion = parsed && typeof parsed === 'object' ? parsed.schema_version : null;
          if (schemaVersion && parseSemver(schemaVersion) && packageVersion && compareSemver(schemaVersion, packageVersion) > 0) {
            violations.push({
              type: 'future_schema_version',
              entry: name,
              reason: `schema_version ${schemaVersion} is newer than package version ${packageVersion}`
            });
          }
        } catch (error) {
          violations.push({ type: 'json_invalid', entry: name, reason: error.message });
        }
      }
      for (const rule of releasePolicy.forbidden_content || []) {
        if (contentAllowed(rule, name)) continue;
        if (compileRule(rule).test(text)) violations.push({ type: 'content_forbidden', entry: name, rule: rule.id || rule.pattern });
      }
    }
  }

  return {
    schema_version: 'release-validation.v1',
    package_version: packageVersion,
    artifact_version: artifactVersion,
    profile,
    artifact: path.resolve(zipPath),
    status: violations.length ? 'failed' : 'ok',
    entries: entries.length,
    inventory,
    total_uncompressed_bytes: zip.total_uncompressed_bytes,
    violations
  };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args.artifact) fail('Usage: node tools/validate-release-artifact.js dist/knowledge-v<package.version>.zip [--json]');
  const result = validate(path.resolve(args.artifact), { profile: args.profile });
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else if (result.status === 'ok') console.log(`release artifact ok: ${result.entries} entries`);
  else {
    console.log(`release artifact failed: ${result.violations.length} violation(s)`);
    for (const violation of result.violations.slice(0, 40)) console.log(`- ${violation.entry || '<zip>'}: ${violation.reason || violation.rule || violation.type}`);
  }
  if (result.status !== 'ok') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseArgs(process.argv.slice(2));
    const result = { schema_version: 'release-validation.v1', package_version: packageVersion, status: 'failed', error: error.message };
    if (parsed.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}

module.exports = { validate, readZipEntries };
