#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs } = require('./lib/path-context');
const { validate } = require('./validate-release-artifact');

const root = path.resolve(__dirname, '..');

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    const rel = normalizeRel(path.relative(root, abs));
    if (entry.isDirectory()) {
      if (['node_modules'].includes(entry.name)) continue;
      walk(abs, out);
    } else if (entry.isFile()) {
      out.push({ abs, rel });
    }
  }
  return out;
}

function textFile(rel) {
  return /\.(cjs|css|csv|html|js|json|md|mjs|svg|toml|ts|txt|xml|ya?ml)$/i.test(rel) ||
    ['README', 'LICENSE', 'NOTICE', 'SECURITY'].includes(path.posix.basename(rel));
}

function scanSource() {
  const files = walk(root);
  const devOnly = [];
  const runtime = [];
  const localLeaks = [];
  const forbiddenDirs = [
    ['.git/', 'git metadata'],
    ['.github/', 'source hosting metadata'],
    ['.qa-tmp/', 'qa temp'],
    ['.self-test-tmp/', 'self-test temp'],
    ['dist/', 'release output'],
    ['maintenance/flow-logs/', 'runtime flow logs'],
    ['benchmark-runs/', 'benchmark runtime reports']
  ];
  for (const file of files) {
    for (const [prefix, reason] of forbiddenDirs) {
      if (file.rel === prefix.replace(/\/$/, '') || file.rel.startsWith(prefix)) {
        devOnly.push({ path: file.rel, reason });
        break;
      }
    }
    if (/^(maintenance|metrics|search|inspector|sessions)\//.test(file.rel)) runtime.push(file.rel);
    if (textFile(file.rel)) {
      const text = fs.readFileSync(file.abs, 'utf8');
      if (/[A-Z]:\\(?:Users\\(?![\[<^])[\w .-]{1,64}(?=\\)|MyProject)|\/mnt\/data|\/tmp\/knowledge/i.test(text)) {
        localLeaks.push(file.rel);
      }
    }
  }
  return { files_total: files.length, dev_only_entries: devOnly, runtime_entries: runtime, local_path_leaks: localLeaks };
}

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const artifact = path.join(root, 'dist', `knowledge-v${pkg.version}.zip`);
  const source = scanSource();
  const release = fs.existsSync(artifact)
    ? validate(artifact)
    : { status: 'missing', violations: [{ type: 'missing_artifact', entry: 'dist' }] };
  const issues = [];
  if (release.status !== 'ok') issues.push('release artifact is missing or invalid');
  const result = {
    schema_version: '3.2.6',
    generated_at: new Date().toISOString(),
    status: issues.length ? 'failed' : 'ok',
    distinction: {
      source_checkout: 'dev/source deliverable with tests, docs, temp-output exclusions and package tooling',
      install_artifact: `dist/knowledge-v${pkg.version}.zip`
    },
    source,
    release_artifact: {
      path: `dist/knowledge-v${pkg.version}.zip`,
      status: release.status,
      entries: release.entries || 0,
      violations: release.violations || []
    },
    warnings: [
      ...(source.dev_only_entries.length ? ['source checkout contains dev-only/runtime paths; package-release must exclude them'] : []),
      ...(source.local_path_leaks.length ? ['source checkout contains local-path test strings or docs; release artifact validation is authoritative for public surface'] : [])
    ],
    issues
  };
  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`source deliverable ${result.status}`);
  if (result.status !== 'ok') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const { flags } = parseCliArgs(process.argv.slice(2));
    const result = { schema_version: '3.2.6', status: 'failed', error: error.message };
    if (flags.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}
