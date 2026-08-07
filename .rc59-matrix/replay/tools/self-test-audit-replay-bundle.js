#!/usr/bin/env node
'use strict';

// Builds a disposable audit archive and proves that its replay closure runs
// after a clean extraction.  The replay itself is intentionally executed from
// the extracted audit tree; this test never imports a verifier from there.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { createZip } = require('./package-release');
const { readZipEntries } = require('./validate-release-artifact');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

function parseArgs(argv) {
  const args = { zip: null, out: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--zip') args.zip = argv[++index] || null;
    else if (value.startsWith('--zip=')) args.zip = value.slice(6);
    else if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice(6);
  }
  if (!args.zip) throw new Error('--zip=<candidate ZIP> is required');
  return args;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function walk(root, out = []) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) walk(target, out);
    else if (entry.isFile()) out.push(target);
    else throw new Error(`audit fixture contains a non-regular file: ${target}`);
  }
  return out;
}

function archiveDirectory(root, archive) {
  const base = path.resolve(root);
  const entries = walk(base).map((file) => ({
    abs: file,
    rel: path.relative(base, file).replace(/\\/g, '/'),
    name: path.relative(base, file).replace(/\\/g, '/')
  })).sort((left, right) => left.name.localeCompare(right.name));
  createZip(entries, archive);
  return entries;
}

function containedOutput(root, name) {
  const normalized = String(name || '').replace(/\\/g, '/');
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) throw new Error(`unsafe audit ZIP entry: ${name}`);
  const output = path.resolve(root, ...normalized.split('/'));
  if (output !== root && !output.startsWith(`${root}${path.sep}`)) throw new Error(`audit ZIP entry escapes extraction root: ${name}`);
  return output;
}

function extractArchive(archive, output) {
  const root = path.resolve(output);
  for (const entry of readZipEntries(archive).entries) {
    if (entry.name.endsWith('/')) continue;
    const target = containedOutput(root, entry.name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.body);
  }
}

function verifyReplayManifest(replay) {
  const manifestPath = path.join(replay, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const seen = new Set();
  const failures = [];
  for (const entry of manifest.files || []) {
    const relative = String(entry?.path || '');
    if (!relative || relative.startsWith('/') || relative.split('/').some((part) => !part || part === '.' || part === '..') || seen.has(relative)) {
      failures.push({ path: relative, reason: 'unsafe_or_duplicate_path' });
      continue;
    }
    seen.add(relative);
    const target = path.resolve(replay, ...relative.split('/'));
    const contained = target.startsWith(`${path.resolve(replay)}${path.sep}`);
    const present = contained && fs.existsSync(target);
    const actual = present ? sha256(target) : null;
    if (!present || actual !== entry.sha256) failures.push({ path: relative, reason: present ? 'sha256_mismatch' : 'missing', expected: entry.sha256, actual });
  }
  return { files: Array.isArray(manifest.files) ? manifest.files.length : 0, failures, valid: failures.length === 0 };
}

function mutateNewline(file) {
  const original = fs.readFileSync(file);
  const index = original.indexOf(0x0a);
  if (index < 0) throw new Error(`newline mutation fixture has no LF: ${file}`);
  fs.writeFileSync(file, Buffer.concat([original.subarray(0, index), Buffer.from('\r\n'), original.subarray(index + 1)]));
}

function mutateOneByte(file) {
  const original = Buffer.from(fs.readFileSync(file));
  if (!original.length) throw new Error(`byte mutation fixture is empty: ${file}`);
  original[Math.min(1, original.length - 1)] ^= 0x01;
  fs.writeFileSync(file, original);
}

function cleanEnvironment() {
  const environment = { ...process.env, NODE_PATH: '' };
  for (const key of Object.keys(environment)) {
    if (/^KNOWLEDGE_(?:SYSTEM|TARGET|PROJECT|STATE|TEAM|WORKSPACE|REPO)_ROOT$/i.test(key) || /^KNOWLEDGE_(?:TEAM_ROOT|WORKSPACE_ID|REPO_ID)$/i.test(key)) delete environment[key];
  }
  return environment;
}

function invoke(replay, candidate) {
  const child = spawnSync(process.execPath, [path.join(replay, 'run-all.js'), '--candidate', candidate], {
    cwd: path.dirname(replay),
    env: cleanEnvironment(),
    encoding: 'utf8',
    windowsHide: true,
    timeout: 240000
  });
  let report = null;
  try { report = JSON.parse(String(child.stdout || '').trim()); } catch (_) { /* reported as a failed result */ }
  return {
    exit_code: child.status,
    stdout: child.stdout || '',
    stderr: child.stderr || '',
    report,
    spawn_error: child.error ? { code: child.error.code || null, message: child.error.message } : null
  };
}

function result(id, expected, actual, pass) { return { id, expected, actual, pass: Boolean(pass) }; }

function main() {
  const args = parseArgs(process.argv.slice(2));
  const candidate = path.resolve(args.zip);
  if (!fs.existsSync(candidate)) throw new Error(`candidate ZIP not found: ${candidate}`);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-audit-replay-'));
  const results = [];
  try {
    const auditRoot = path.join(temporary, 'audit-source');
    const replay = path.join(auditRoot, 'replay');
    const artifactDir = path.join(auditRoot, 'artifacts');
    fs.mkdirSync(artifactDir, { recursive: true });
    const embeddedCandidate = path.join(artifactDir, path.basename(candidate));
    fs.copyFileSync(candidate, embeddedCandidate);

    const builder = path.join(__dirname, 'build-audit-replay-bundle.js');
    const built = spawnSync(process.execPath, [builder, '--out', replay], { encoding: 'utf8', windowsHide: true, timeout: 120000 });
    results.push(result('build_replay_closure', { exit_code: 0 }, { exit_code: built.status, stderr: built.stderr || '' }, built.status === 0));
    const sourceManifest = verifyReplayManifest(replay);
    results.push(result('dependency_manifest_sha256', { all_files_present_and_hashed: true }, sourceManifest, sourceManifest.valid && sourceManifest.files > 0));

    const archive = path.join(temporary, 'audit-replay.zip');
    const entries = archiveDirectory(auditRoot, archive);
    results.push(result('audit_zip_created', { entries: 'nonempty', sha256: '64 hex' }, { entries: entries.length, sha256: sha256(archive) }, entries.length > 0 && /^[a-f0-9]{64}$/.test(sha256(archive))));

    const extraction = path.join(temporary, 'clean extraction with spaces');
    extractArchive(archive, extraction);
    const required = ['replay/run-all.js', 'replay/manifest.json', `artifacts/${path.basename(candidate)}`];
    const requiredPresent = required.every((relative) => fs.existsSync(path.join(extraction, ...relative.split('/'))));
    results.push(result('clean_archive_extraction', { required_entries: required }, { required_present: requiredPresent }, requiredPresent));

    const extractedReplay = path.join(extraction, 'replay');
    const extractedCandidate = path.join(extraction, 'artifacts', path.basename(candidate));
    const extractedManifest = verifyReplayManifest(extractedReplay);
    results.push(result('nested_manifest_matches_final_zip_bytes', { all_files_present_and_hashed: true }, extractedManifest, extractedManifest.valid && extractedManifest.files > 0));
    const replayResult = invoke(extractedReplay, extractedCandidate);
    const replayPass = replayResult.exit_code === 0 && replayResult.report?.status === 'pass' && replayResult.report?.checks_total === 4 && replayResult.report?.passed === 4;
    results.push(result('replay_runs_from_clean_extraction', { exit_code: 0, status: 'pass', checks_total: 4 }, { exit_code: replayResult.exit_code, status: replayResult.report?.status || null, checks_total: replayResult.report?.checks_total || null, stderr: replayResult.stderr }, replayPass));
    const noSourceCwd = path.resolve(path.dirname(extractedReplay)) !== path.resolve(__dirname) && !path.resolve(path.dirname(extractedReplay)).startsWith(`${path.resolve(__dirname)}${path.sep}`);
    results.push(result('replay_cwd_outside_maintainer_source', { outside_source: true, node_path: '' }, { outside_source: noSourceCwd, node_path_empty: true }, noSourceCwd));

    const mutations = [
      { id: 'newline_mutation_blocks_before_tools', relative: 'install-manifest.json', mutate: mutateNewline },
      { id: 'one_byte_mutation_blocks_before_tools', relative: 'release-policy.json', mutate: mutateOneByte }
    ];
    for (const mutation of mutations) {
      const mutationRoot = path.join(temporary, mutation.id);
      extractArchive(archive, mutationRoot);
      const mutationReplay = path.join(mutationRoot, 'replay');
      const mutationCandidate = path.join(mutationRoot, 'artifacts', path.basename(candidate));
      mutation.mutate(path.join(mutationReplay, mutation.relative));
      const blocked = invoke(mutationReplay, mutationCandidate);
      const pass = blocked.exit_code !== 0
        && blocked.report?.status === 'fail'
        && blocked.report?.phase === 'manifest_preflight'
        && blocked.report?.verifiers_started === 0
        && blocked.report?.error?.manifest_path === mutation.relative;
      results.push(result(mutation.id, { exit_code: 'nonzero', phase: 'manifest_preflight', verifiers_started: 0, manifest_path: mutation.relative }, { exit_code: blocked.exit_code, phase: blocked.report?.phase || null, verifiers_started: blocked.report?.verifiers_started ?? null, manifest_path: blocked.report?.error?.manifest_path || null, stderr: blocked.stderr }, pass));
    }

    const report = {
      schema_version: 'knowledge-audit-replay-self-test.v1',
      generated_at: new Date().toISOString(),
      candidate: { path: candidate, sha256: sha256(candidate) },
      checks_total: results.length,
      passed: results.filter((item) => item.pass).length,
      failed: results.filter((item) => !item.pass).length,
      status: results.every((item) => item.pass) ? 'pass' : 'fail',
      results,
      limitations: [{ id: 'source_read_only_fixture', status: 'not_required', reason: 'the replay has no maintainer-source dependency; altering a shared dirty source tree is intentionally avoided.' }]
    };
    const text = `${JSON.stringify(report, null, 2)}\n`;
    if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), text, 'utf8'); }
    process.stdout.write(text);
    if (report.failed) process.exitCode = 1;
  } finally {
    removeTempDirStrict(temporary);
  }
}

if (require.main === module) {
  try { main(); } catch (error) { process.stderr.write(`${error.stack || error.message}\n`); process.exitCode = 1; }
}

module.exports = { main };
