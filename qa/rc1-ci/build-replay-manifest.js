#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const root = path.resolve(process.argv[2] || 'replay');
const files = [];

function visit(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === '.self-test-tmp') continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) visit(full);
    else if (entry.isFile() && path.relative(root, full) !== 'manifest.json') {
      files.push(full);
    }
  }
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

visit(root);
const manifest = {
  schema_version: 'matrix-replay-manifest.v1',
  files: files.sort().map((file) => ({
    path: path.relative(root, file).replace(/\\/g, '/'),
    sha256: sha256(file)
  }))
};
fs.writeFileSync(
  path.join(root, 'manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
  'utf8'
);
process.stdout.write(`${JSON.stringify({ status: 'pass', files: manifest.files.length })}\n`);
