#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { readEntryData } = require('./package-release');

const knowledgeRoot = path.resolve(__dirname, '..');
const toolsRoot = path.join(knowledgeRoot, 'tools');
const DEFAULT_ENTRIES = Object.freeze([
  'verify-contained-lock-rc39.js',
  'verify-contained-lock-usage.js',
  'verify-context-lock-safety-rc40.js',
  'verify-evidence-report-contract.js'
]);
const RUNTIME_DATA = Object.freeze(['package.json', 'release-policy.json', 'install-manifest.json']);

function parseArgs(argv) {
  const args = { out: null, entries: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice(6);
    else if (value === '--entry') args.entries.push(argv[++index] || '');
    else if (value.startsWith('--entry=')) args.entries.push(value.slice(8));
  }
  if (!args.out) throw new Error('--out=<new replay directory> is required');
  return args;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function portable(value) { return String(value).replace(/\\/g, '/'); }
function isContained(root, target) { const relative = path.relative(root, target); return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative)); }

// The evidence archive uses package-release's canonical text bytes.  Replay
// files must be written in that same representation *before* the manifest is
// hashed; otherwise a Windows CRLF source file produces a stale hash once the
// archive writer converts it to LF.
function copyCanonical(source, output, archiveRelativePath) {
  const bytes = readEntryData({ abs: source, rel: archiveRelativePath, name: archiveRelativePath });
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, bytes);
  return output;
}

function resolveLocalRequire(fromPath, request) {
  const base = path.resolve(path.dirname(fromPath), request);
  const candidates = [base, `${base}.js`, `${base}.json`, path.join(base, 'index.js')];
  const file = candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
  if (!file || !isContained(toolsRoot, file)) throw new Error(`unresolved local require ${request} from ${portable(path.relative(toolsRoot, fromPath))}`);
  return file;
}

function dependencyClosure(entryNames) {
  const files = new Set();
  const unresolved = [];
  const visit = (filePath) => {
    const resolved = path.resolve(filePath);
    if (files.has(resolved)) return;
    files.add(resolved);
    const source = fs.readFileSync(resolved, 'utf8');
    const pattern = /require\(\s*['"](\.[^'"]+)['"]\s*\)/g;
    let match;
    while ((match = pattern.exec(source))) {
      try { visit(resolveLocalRequire(resolved, match[1])); }
      catch (error) { unresolved.push(error.message); }
    }
  };
  for (const name of entryNames) {
    const entry = path.resolve(toolsRoot, name);
    if (!isContained(toolsRoot, entry) || !fs.existsSync(entry) || !fs.statSync(entry).isFile()) throw new Error(`audit replay entry is not a local tool: ${name}`);
    visit(entry);
  }
  // verify-contained-lock-usage performs a source scan by design. Its local
  // dependency closure is therefore the public tools corpus it scans, rather
  // than an ambient maintainer checkout.
  if (entryNames.includes('verify-contained-lock-usage.js')) {
    const collect = (directory) => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const target = path.join(directory, entry.name);
        if (entry.isDirectory()) collect(target);
        else if (entry.isFile() && entry.name.endsWith('.js')) files.add(target);
      }
    };
    collect(toolsRoot);
  }
  if (unresolved.length) throw new Error(`audit replay has unresolved local requires: ${Array.from(new Set(unresolved)).join('; ')}`);
  return Array.from(files).sort();
}

function runAllSource() {
  return `#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
let phase = 'manifest_preflight';
let verifiersStarted = 0;
function arg(name) { const exact = process.argv.indexOf(name); if (exact >= 0) return process.argv[exact + 1] || null; const prefix = name + '='; return process.argv.find((item) => item.startsWith(prefix))?.slice(prefix.length) || null; }
function candidate(root) { const explicit = arg('--candidate'); if (explicit) return path.resolve(explicit); const artifacts = path.join(root, 'artifacts'); const entries = fs.existsSync(artifacts) ? fs.readdirSync(artifacts).filter((item) => /^knowledge-v3\\.3\\.0-step1-rc4-r\\d+\\.zip$/i.test(item)) : []; if (entries.length !== 1) throw new Error('replay requires exactly one candidate in artifacts/ or --candidate'); return path.join(artifacts, entries[0]); }
function sha256(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function manifestPath(root, relative) { if (typeof relative !== 'string' || !relative || relative.includes('\\\\') || relative.startsWith('/') || relative.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error('invalid replay manifest path: ' + String(relative)); const target = path.resolve(root, ...relative.split('/')); if (!target.startsWith(root + path.sep)) throw new Error('replay manifest path escapes root: ' + relative); return target; }
function verifyManifest(root) { const file = path.join(__dirname, 'manifest.json'); if (!fs.existsSync(file)) throw new Error('replay manifest is missing'); const manifest = JSON.parse(fs.readFileSync(file, 'utf8')); if (!Array.isArray(manifest.files) || manifest.files.length === 0) throw new Error('replay manifest has no files'); const seen = new Set(); for (const entry of manifest.files) { const relative = entry && entry.path; if (seen.has(relative)) throw new Error('duplicate replay manifest path: ' + relative); seen.add(relative); if (!entry || !/^[a-f0-9]{64}$/.test(entry.sha256 || '')) throw new Error('invalid replay manifest SHA-256: ' + relative); const target = manifestPath(__dirname, relative); let stat; try { stat = fs.lstatSync(target); } catch (_) { throw new Error('replay manifest file is missing: ' + relative); } if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('replay manifest path is not a regular file: ' + relative); const actual = sha256(target); if (actual !== entry.sha256) { const error = new Error('replay manifest SHA-256 mismatch: ' + relative); error.manifest_path = relative; error.expected_sha256 = entry.sha256; error.actual_sha256 = actual; throw error; } } return { files: manifest.files.length }; }
function invoke(script, args, root) { verifiersStarted += 1; const child = spawnSync(process.execPath, [path.join(__dirname, 'tools', script), ...args], { cwd: path.dirname(root), env: { ...process.env, NODE_PATH: '' }, encoding: 'utf8', windowsHide: true, timeout: 180000 }); return { exit_code: child.status, stdout: child.stdout || '', stderr: child.stderr || '', spawn_error: child.error ? { code: child.error.code || null, message: child.error.message } : null }; }
function main() { const root = path.resolve(__dirname, '..'); const manifest = verifyManifest(root); phase = 'verifiers'; const zip = candidate(root); const checks = [ ['contained_lock_usage', 'verify-contained-lock-usage.js', []], ['contained_lock_physical', 'verify-contained-lock-rc39.js', ['--zip', zip]], ['context_lock_safety', 'verify-context-lock-safety-rc40.js', ['--zip', zip, '--expect', 'pass']], ['evidence_report_contract', 'verify-evidence-report-contract.js', ['--root', root]] ]; const results = checks.map(([id, script, args]) => { const actual = invoke(script, args, root); return { id, expected: { exit_code: 0 }, actual, pass: actual.exit_code === 0 }; }); const report = { schema_version: 'knowledge-audit-replay.v1', candidate: path.basename(zip), manifest, verifiers_started: verifiersStarted, checks_total: results.length, passed: results.filter((item) => item.pass).length, failed: results.filter((item) => !item.pass).length, status: results.every((item) => item.pass) ? 'pass' : 'fail', results }; process.stdout.write(JSON.stringify(report, null, 2) + '\\n'); if (report.failed) process.exitCode = 1; }
try { main(); } catch (error) { process.stdout.write(JSON.stringify({ schema_version: 'knowledge-audit-replay.v1', status: 'fail', phase, verifiers_started: verifiersStarted, error: { message: error.message, manifest_path: error.manifest_path || null, expected_sha256: error.expected_sha256 || null, actual_sha256: error.actual_sha256 || null } }, null, 2) + '\\n'); process.stderr.write((error.stack || error.message) + '\\n'); process.exitCode = 1; }
`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const out = path.resolve(args.out);
  if (fs.existsSync(out)) throw new Error(`refusing existing replay directory: ${out}`);
  const entries = args.entries.length ? args.entries : [...DEFAULT_ENTRIES];
  const closure = dependencyClosure(entries);
  fs.mkdirSync(out, { recursive: true });
  const copied = [];
  for (const filePath of closure) {
    const relative = path.relative(toolsRoot, filePath);
    const output = path.join(out, 'tools', relative);
    copied.push(copyCanonical(filePath, output, `tools/${portable(relative)}`));
  }
  for (const relative of RUNTIME_DATA) {
    const source = path.join(knowledgeRoot, relative);
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) throw new Error(`replay runtime data missing: ${relative}`);
    const output = path.join(out, relative);
    copied.push(copyCanonical(source, output, portable(relative)));
  }
  const fixtures = path.join(out, 'fixtures');
  fs.mkdirSync(fixtures, { recursive: true });
  const fixtureReadme = path.join(fixtures, 'README.md');
  fs.writeFileSync(fixtureReadme, 'Replay fixtures are created by the verifier in a fresh temporary directory.\n', 'utf8');
  copied.push(fixtureReadme);
  const runAll = path.join(out, 'run-all.js');
  fs.writeFileSync(runAll, runAllSource(), 'utf8');
  copied.push(runAll);
  const manifest = {
    schema_version: 'knowledge-audit-replay-manifest.v1',
    generated_at: new Date().toISOString(),
    entries: entries.map((item) => `tools/${portable(item)}`),
    files: copied.map((filePath) => ({ path: portable(path.relative(out, filePath)), sha256: sha256(filePath) })).sort((left, right) => left.path.localeCompare(right.path))
  };
  fs.writeFileSync(path.join(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({ status: 'pass', output: out, files: manifest.files.length, entries: manifest.entries }, null, 2)}\n`);
}

if (require.main === module) main();
module.exports = { dependencyClosure, main };
