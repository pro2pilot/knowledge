#!/usr/bin/env node
'use strict';

// This is an external CI diagnostic harness, never a candidate runtime tool.
// It preserves the complete macOS Node 22 verify-upgrade result before the
// conformance smoke reporter applies its deliberately short stdout tail.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) continue;
    values[item.slice(2)] = argv[++index] || null;
  }
  return values;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function write(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

const args = parseArgs(process.argv.slice(2));
const required = ['candidate', 'replay', 'baseline', 'out'];
for (const name of required) {
  if (!args[name]) throw new Error(`Missing --${name}`);
}
const out = path.resolve(args.out);
const captured = [];
const nativeSpawnSync = childProcess.spawnSync;
childProcess.spawnSync = (command, commandArgs, options = {}) => {
  const result = nativeSpawnSync(command, commandArgs, options);
  if (Array.isArray(commandArgs) && commandArgs.includes('--verify-upgrade')) {
    captured.push({
      command,
      args: commandArgs,
      cwd: options.cwd || null,
      status: result.status,
      signal: result.signal || null,
      error: result.error ? { code: result.error.code || null, message: result.error.message } : null,
      stdout: typeof result.stdout === 'string' ? result.stdout : String(result.stdout || ''),
      stderr: typeof result.stderr === 'string' ? result.stderr : String(result.stderr || '')
    });
  }
  return result;
};

const { smoke } = require(path.join(path.resolve(args.replay), 'tools', 'conformance-install-smoke.js'));
let report;
try {
  report = smoke(path.resolve(args.candidate), {
    previousArtifact: path.resolve(args.baseline),
    keepFailed: true
  });
} catch (error) {
  report = {
    schema_version: 'conformance-install-smoke.v1',
    status: 'fail',
    error: { message: error.message, stack: error.stack || null }
  };
}
write(path.join(out, 'upgrade-report.json'), report);
write(path.join(out, 'upgrade-verify-raw.json'), {
  schema_version: 'rc53-macos-node22-upgrade-diagnostic.v1',
  candidate_sha256: sha256(args.candidate),
  baseline_sha256: sha256(args.baseline),
  captured_verify_upgrade_invocations: captured
});
write(path.join(out, 'result.json'), {
  schema_version: 'rc53-macos-node22-upgrade-diagnostic.v1',
  status: report.status,
  classification: report.status === 'pass' ? 'candidate' : 'candidate_or_environment_unclassified',
  verify_upgrade_invocations: captured.length,
  candidate_sha256: sha256(args.candidate),
  baseline_sha256: sha256(args.baseline)
});
