#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const { spawnSync } = require('child_process');
const { ensureDir, writeJsonAtomic } = require('./lib/json-store');
const { parseCliArgs } = require('./lib/path-context');

const root = path.resolve(__dirname, '..');
const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version || '3.2.4';
const artifactRel = `dist/knowledge-v${version}.zip`;

function sanitizeText(value) {
  return String(value || '')
    .replace(/[A-Z]:\\(?:Users\\[^\s"',}\\]+|MyProject)[^\s"',}]+/gi, '<local-path>')
    .replace(/\/mnt\/data[^\s"',}]*/gi, '<local-path>')
    .replace(/\/tmp\/knowledge[^\s"',}]*/gi, '<local-path>')
    .replace(/Users\\[^\\\s"',}]+/gi, 'Users\\<local-user>')
    .replace(/Users\/[^\/\s"',}]+/gi, 'Users/<local-user>')
    .replace(new RegExp(`knowledge${'-'}kit`, 'gi'), 'workspace');
}

function run(command, args, options = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 300000
  });
  return {
    name: options.name || [path.basename(command), ...args].join(' '),
    command: [path.basename(command), ...args].join(' '),
    status: result.status === 0 ? 'pass' : 'fail',
    exit_code: result.status,
    duration_ms: Date.now() - started,
    stdout_tail: sanitizeText(String(result.stdout || '').slice(-3000)),
    stderr_tail: sanitizeText(String(result.stderr || '').slice(-3000))
  };
}

function eocdOffset(buffer) {
  for (let i = buffer.length - 22; i >= 0; i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) return i;
  }
  throw new Error('ZIP end of central directory not found');
}

function extractZip(zipPath, dest) {
  const buffer = fs.readFileSync(zipPath);
  const eocd = eocdOffset(buffer);
  const count = buffer.readUInt16LE(eocd + 10);
  let ptr = buffer.readUInt32LE(eocd + 16);
  for (let i = 0; i < count; i += 1) {
    if (buffer.readUInt32LE(ptr) !== 0x02014b50) throw new Error(`Invalid central directory header at ${ptr}`);
    const method = buffer.readUInt16LE(ptr + 10);
    const compressedSize = buffer.readUInt32LE(ptr + 20);
    const nameLength = buffer.readUInt16LE(ptr + 28);
    const extraLength = buffer.readUInt16LE(ptr + 30);
    const commentLength = buffer.readUInt16LE(ptr + 32);
    const localOffset = buffer.readUInt32LE(ptr + 42);
    const name = buffer.slice(ptr + 46, ptr + 46 + nameLength).toString('utf8');
    if (buffer.readUInt32LE(localOffset) !== 0x04034b50) throw new Error(`Invalid local header for ${name}`);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.slice(dataStart, dataStart + compressedSize);
    const body = method === 0 ? compressed : zlib.inflateRawSync(compressed);
    const target = path.resolve(dest, name);
    if (!target.startsWith(path.resolve(dest) + path.sep)) throw new Error(`Unsafe zip entry: ${name}`);
    ensureDir(path.dirname(target));
    fs.writeFileSync(target, body);
    ptr += 46 + nameLength + extraLength + commentLength;
  }
}

function cleanInstallSmoke(artifactPath) {
  const smokeRoot = fs.mkdtempSync(path.join(root, '.qa-tmp', 'release-gate-clean-smoke-'));
  extractZip(artifactPath, smokeRoot);
  fs.writeFileSync(path.join(smokeRoot, 'app.js'), 'module.exports = 1;\n', 'utf8');
  const steps = [];
  const gitSteps = [
    ['git init', 'git', ['init']],
    ['git config email', 'git', ['config', 'user.email', 'knowledge-smoke@example.invalid']],
    ['git config name', 'git', ['config', 'user.name', 'Knowledge Smoke']],
    ['git add fixture', 'git', ['add', 'app.js', '.knowledge']],
    ['git commit fixture', 'git', ['commit', '-m', 'clean install smoke fixture']]
  ];
  for (const [name, cmd, args] of gitSteps) steps.push(run(cmd, args, { cwd: smokeRoot, name, timeoutMs: 120000 }));
  const nodeSteps = [
    ['install-check', ['.knowledge/tools/install-check.js', '--json']],
    ['flow import', ['.knowledge/tools/flow.js', 'import', '--no-color', '--json']],
    ['doctor', ['.knowledge/tools/doctor.js', '--json']],
    ['build Inspector', ['.knowledge/tools/build-visual-inspector.js']],
    ['self-test Inspector UI', ['.knowledge/tools/self-test-inspector-ui.js']],
    ['self-test Team Mode', ['.knowledge/tools/self-test-team-mode.js']],
    ['memory status all', ['.knowledge/tools/memory-provider.js', 'status-all', '--json']]
  ];
  for (const [name, args] of nodeSteps) steps.push(run(process.execPath, args, { cwd: smokeRoot, name, timeoutMs: name.includes('Team Mode') ? 300000 : 180000 }));
  return {
    status: steps.every((step) => step.status === 'pass') ? 'pass' : 'fail',
    root: '<clean-install-smoke>',
    steps
  };
}

function renderMarkdown(report) {
  const lines = [
    '# Release Gate Report',
    '',
    `Generated: ${report.generated_at}`,
    '',
    `Status: ${report.status}`,
    '',
    '## Commands',
    '',
    '| Command | Status | Duration ms |',
    '|---|---|---:|'
  ];
  for (const step of report.steps) lines.push(`| ${step.command} | ${step.status} | ${step.duration_ms} |`);
  lines.push('', '## Clean Install Smoke', '', `Status: ${report.clean_install.status}`, '', '| Step | Status | Duration ms |', '|---|---|---:|');
  for (const step of report.clean_install.steps) lines.push(`| ${step.name} | ${step.status} | ${step.duration_ms} |`);
  if (report.failures.length) {
    lines.push('', '## Failures', '');
    for (const failure of report.failures) lines.push(`- ${failure.command || failure.name}: ${failure.stderr_tail || failure.stdout_tail || 'failed'}`);
  }
  return `${lines.join('\n')}\n`;
}

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  ensureDir(path.join(root, 'maintenance'));
  ensureDir(path.join(root, '.qa-tmp'));
  const commands = [
    ['self-test Inspector Launcher', [process.execPath, ['tools/self-test-inspector-launcher.js', '--json'], 180000]],
    ['self-test Inspector Actions', [process.execPath, ['tools/self-test-inspector-actions.js', '--json'], 180000]],
    ['self-test Agent Activity', [process.execPath, ['tools/self-test-agent-activity.js', '--json'], 120000]],
    ['self-test Safe Queue', [process.execPath, ['tools/self-test-safe-queue.js', '--json'], 180000]],
    ['self-test Agent Footer', [process.execPath, ['tools/self-test-agent-footer.js', '--json'], 120000]],
    ['self-test Restore Trust', [process.execPath, ['tools/self-test-restore-trust.js', '--json'], 120000]],
    ['self-test Update Checks', [process.execPath, ['tools/self-test-update-checks.js'], 120000]],
    ['self-test install policy', [process.execPath, ['tools/self-test-install-policy.js'], 420000]],
    ['self-test memory providers', [process.execPath, ['tools/self-test-memory-providers.js'], 180000]],
    ['self-test external memory', [process.execPath, ['tools/self-test-external-memory.js'], 180000]],
    ['self-test Free Core Graph', [process.execPath, ['tools/self-test-free-core-graph.js'], 120000]],
    ['self-test PR Impact', [process.execPath, ['tools/self-test-pr-impact.js'], 180000]],
    ['self-test Team Mode', [process.execPath, ['tools/self-test-team-mode.js'], 360000]],
    ['self-test Team Inspector JSON', [process.execPath, ['tools/self-test-team-inspector-json.js'], 360000]],
    ['build Inspector', [process.execPath, ['tools/build-visual-inspector.js'], 180000]],
    ['self-test Inspector UI', [process.execPath, ['tools/self-test-inspector-ui.js'], 180000]],
    ['flow release', [process.execPath, ['tools/flow.js', 'release', '--no-color', '--json'], 360000]],
    ['doctor', [process.execPath, ['tools/doctor.js', '--json'], 180000]],
    ['package release', [process.execPath, ['tools/package-release.js'], 180000]],
    ['validate release artifact', [process.execPath, ['tools/validate-release-artifact.js', artifactRel, '--json'], 180000]]
  ];
  const steps = [];
  for (const [name, spec] of commands) {
    const [cmd, args, timeoutMs] = spec;
    const step = run(cmd, args, { name, timeoutMs });
    steps.push(step);
    if (step.status !== 'pass') break;
  }
  const artifactPath = path.join(root, artifactRel);
  const cleanInstall = steps.every((step) => step.status === 'pass') && fs.existsSync(artifactPath)
    ? cleanInstallSmoke(artifactPath)
    : { status: 'skipped', root: '<clean-install-smoke>', steps: [] };
  const failures = [...steps, ...(cleanInstall.steps || [])].filter((step) => step.status !== 'pass');
  const report = {
    schema_version: '3.2.4',
    generated_at: new Date().toISOString(),
    status: failures.length ? 'failed' : 'passed',
    gate_status: failures.length ? 'blocked' : 'benchmark-ready',
    artifact: artifactRel,
    steps,
    clean_install: cleanInstall,
    failures
  };
  writeJsonAtomic(path.join(root, 'maintenance', 'release-gate-report.json'), report);
  fs.writeFileSync(path.join(root, 'maintenance', 'release-gate-report.md'), renderMarkdown(report), 'utf8');
  if (flags.json) console.log(JSON.stringify(report, null, 2));
  else console.log(`release gate ${report.status}`);
  if (report.status !== 'passed') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const failed = {
      schema_version: '3.2.4',
      generated_at: new Date().toISOString(),
      status: 'failed',
      gate_status: 'blocked',
      error: sanitizeText(error.message)
    };
    writeJsonAtomic(path.join(root, 'maintenance', 'release-gate-report.json'), failed);
    fs.writeFileSync(path.join(root, 'maintenance', 'release-gate-report.md'), `# Release Gate Report\n\nStatus: failed\n\n${failed.error}\n`, 'utf8');
    const { flags } = parseCliArgs(process.argv.slice(2));
    if (flags.json) console.log(JSON.stringify(failed, null, 2));
    else console.error(failed.error);
    process.exit(2);
  }
}
