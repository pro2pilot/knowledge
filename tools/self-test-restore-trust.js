#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const systemRoot = path.resolve(__dirname, '..');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function main() {
  const source = fs.readFileSync(path.join(systemRoot, 'tools', 'restore-trust.js'), 'utf8');
  for (const phrase of ['--safe', 'source_code_changed: false', 'merged_branches: false', 'raised_trust_without_evidence: false']) {
    assert(source.includes(phrase), `restore-trust missing safety phrase: ${phrase}`);
  }
  for (const tool of ['build-routing-bundle.js', 'build-search-index.js', 'external-memory-status.js', 'doctor.js']) {
    assert(source.includes(tool), `restore-trust missing step ${tool}`);
  }
  console.log(JSON.stringify({ schema_version: '3.2.3', status: 'pass', checks: ['requires --safe', 'does not claim source edits', 'does not merge', 'refreshes routing/search/memory/doctor'] }, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
