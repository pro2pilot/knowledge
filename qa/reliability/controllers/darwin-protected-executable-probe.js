#!/usr/bin/env node
'use strict';

// Ordinary-user, read-only physical probe of one exact compiled addon.
// Raw records remain runner-private; the public reducer accepts fixed enums.
const assert = require('node:assert/strict');
const path = require('node:path');
const chunks = [];let bytes = 0;
process.stdin.on('data', chunk => {
  bytes += chunk.length;if (bytes > 16384) process.exit(2);chunks.push(chunk);
});
process.stdin.once('end', () => {
  assert.equal(process.platform, 'darwin');assert.notEqual(process.getuid(), 0);
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  assert.deepEqual(Object.keys(input).sort(), ['addon', 'path']);
  assert.ok(path.isAbsolute(input.addon) && path.isAbsolute(input.path));
  const addon = require(input.addon);const info = addon.info();
  let result;
  try {
    const value = addon.verifyProtectedExecutable(input.path, 1024 * 1024, 10000);
    result = { accepted: value?.status === 'verified', sha256: value.sha256, source_sha256: info.source_sha256 };
  } catch (error) {
    result = { accepted: false, code: error.code, native_error: error.native_error, source_sha256: info.source_sha256 };
  }
  process.stdout.write(JSON.stringify(result) + '\n');
});
