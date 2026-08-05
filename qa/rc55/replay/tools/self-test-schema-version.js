#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { systemVersion } = require('./lib/system-version');

const root = path.resolve(__dirname, '..');
const version = systemVersion(root);
const allowedLegacyRuntimeSchema = new Set([
  'tools/self-test-memory-providers.js',
  'tools/self-test-inspector-ui.js'
]);

function walk(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walk(abs));
    else if (entry.isFile()) files.push(abs);
  }
  return files;
}

function rel(filePath) {
  return path.relative(root, filePath).replace(/\\/g, '/');
}

function compareSemver(left, right) {
  const parse = (value) => {
    const match = String(value || '').match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
    return match ? match.slice(1, 4).map(Number) : null;
  };
  const a = parse(left);
  const b = parse(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  }
  return 0;
}

function main() {
  const errors = [];
  const runtimeRoots = [path.join(root, 'tools'), path.join(root, 'benchmarks')];
  for (const filePath of runtimeRoots.flatMap((dir) => walk(dir)).filter((file) => file.endsWith('.js'))) {
    const relative = rel(filePath);
    if (allowedLegacyRuntimeSchema.has(relative)) continue;
    const text = fs.readFileSync(filePath, 'utf8');
    const matches = [...text.matchAll(/schema_version\s*:\s*['"](\d+\.\d+\.\d+)['"]/g)];
    for (const match of matches) {
      if (match[1] !== version) errors.push(`${relative} hardcodes stale runtime schema_version ${match[1]}`);
    }
  }

  const benchmarkSource = fs.readFileSync(path.join(root, 'benchmarks', 'run-benchmarks.js'), 'utf8');
  if (benchmarkSource.includes("require('../tools/package-release')")) {
    errors.push('public benchmark runner depends on excluded maintainer packager');
  }

  const ignoredJsonSegments = new Set(['dist', 'maintenance', 'benchmark-runs', '.qa-tmp', '.self-test-tmp', 'internal']);
  for (const filePath of walk(root).filter((file) => file.endsWith('.json'))) {
    const relative = rel(filePath);
    if (relative.split('/').some((segment) => ignoredJsonSegments.has(segment))) continue;
    let parsed = null;
    try { parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')); }
    catch (error) {
      errors.push(`${relative} is invalid JSON: ${error.message}`);
      continue;
    }
    if (parsed?.schema_version && compareSemver(parsed.schema_version, version) > 0) {
      errors.push(`${relative} schema_version ${parsed.schema_version} is newer than package ${version}`);
    }
  }

  const result = {
    schema_version: version,
    status: errors.length ? 'fail' : 'pass',
    checks: [
      'runtime report schemas use systemVersion()',
      'benchmark runner does not depend on maintainer packager',
      'canonical JSON schemas are not newer than package version'
    ],
    errors
  };
  console.log(JSON.stringify(result, null, 2));
  if (errors.length) process.exit(2);
}

try { main(); }
catch (error) {
  console.log(JSON.stringify({ schema_version: version, status: 'fail', errors: [error.message] }, null, 2));
  process.exit(2);
}
