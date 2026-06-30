#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');
const keepTemp = process.argv.includes('--keep-temp');
let rootForCleanup = null;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeFile(file, body) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, body, 'utf8');
}

function writeJson(file, value) {
  writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: options.cwd,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 20000
  });
}

function git(repo, args) {
  const result = run('git', ['-C', repo, ...args], { cwd: repo });
  assert(result.status === 0, `git ${args.join(' ')} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  return result;
}

function seedFixture(parent, name) {
  const repo = path.join(parent, name);
  const knowledge = path.join(repo, '.knowledge');
  ensureDir(repo);
  writeFile(path.join(repo, 'src', 'auth.js'), 'export function login() { return true; }\n');
  writeFile(path.join(repo, 'src', 'stale.js'), 'export const stale = true;\n');
  writeFile(path.join(repo, 'src', 'no-evidence.js'), 'export const evidence = false;\n');
  writeJson(path.join(knowledge, 'evidence', 'auth.json'), { file: 'src/auth.js', checked: true });
  writeJson(path.join(knowledge, 'modules', 'module_registry.json'), {
    schema_version: '3.2.4',
    modules: [
      {
        module_id: 'auth',
        path: 'src/auth.js',
        card: '.knowledge/modules/auth.json',
        confidence: 'high',
        key_files: ['src/auth.js'],
        evidence_files: ['.knowledge/evidence/auth.json']
      },
      {
        module_id: 'stale',
        path: 'src/stale.js',
        card: '.knowledge/modules/stale.json',
        confidence: 'medium',
        key_files: ['src/stale.js'],
        evidence_files: ['.knowledge/evidence/stale.json']
      },
      {
        module_id: 'no_evidence',
        path: 'src/no-evidence.js',
        card: '.knowledge/modules/no-evidence.json',
        confidence: 'medium',
        key_files: ['src/no-evidence.js'],
        evidence_files: []
      }
    ]
  });
  writeJson(path.join(knowledge, 'modules', 'auth.json'), {
    module_id: 'auth',
    key_files: ['src/auth.js'],
    evidence_files: ['.knowledge/evidence/auth.json']
  });
  writeJson(path.join(knowledge, 'modules', 'stale.json'), {
    module_id: 'stale',
    key_files: ['src/stale.js'],
    evidence_files: ['.knowledge/evidence/stale.json']
  });
  writeJson(path.join(knowledge, 'modules', 'no-evidence.json'), {
    module_id: 'no_evidence',
    key_files: ['src/no-evidence.js'],
    evidence_files: []
  });
  writeJson(path.join(knowledge, 'maintenance', 'trust_report.json'), {
    schema_version: '3.2.4',
    modules: {
      trusted: ['auth', 'no_evidence'],
      routing_trusted: ['stale'],
      near_trusted: [],
      advisory_only: [],
      suspect: [],
      low_confidence: []
    },
    module_statuses: [
      { module_id: 'auth', trust_status: 'trusted', freshness_status: 'fresh', confidence: 'high' },
      { module_id: 'stale', trust_status: 'routing_trusted', freshness_status: 'stale', confidence: 'medium' },
      { module_id: 'no_evidence', trust_status: 'trusted', freshness_status: 'fresh', confidence: 'medium' }
    ]
  });
  writeJson(path.join(knowledge, 'freshness.json'), {
    artifact_statuses: {
      'src/stale.js': { status: 'stale', reason: 'fixture stale source' }
    }
  });
  writeJson(path.join(knowledge, 'maps', 'file_criticality.json'), {
    files: [
      { path: 'src/auth.js', classification: 'critical', reason: 'authentication path', modules: ['auth'] }
    ]
  });
  writeJson(path.join(knowledge, 'maintenance', 'repair_queue.json'), {
    queue: [
      {
        id: 'repair-stale-module',
        priority: 'high',
        status: 'open',
        affected_artifacts: ['src/stale.js'],
        reason: 'stale module needs evidence refresh'
      }
    ]
  });
  git(repo, ['init']);
  git(repo, ['add', '.']);
  git(repo, ['-c', 'user.name=Knowledge Test', '-c', 'user.email=knowledge-test@example.invalid', 'commit', '-m', 'initial fixture']);
  return { repo, knowledge };
}

function runImpact(fixture) {
  const result = run(process.execPath, [
    path.join(systemRoot, 'tools', 'pr-impact.js'),
    '--json',
    '--no-write',
    '--system-root', systemRoot,
    '--target-root', fixture.repo,
    '--project-knowledge-root', fixture.knowledge,
    '--state-root', fixture.knowledge
  ], { cwd: systemRoot });
  assert(result.status === 0, `pr-impact failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`pr-impact did not emit JSON: ${error.message}\n${result.stdout}`);
  }
}

function hasPolicy(result, id) {
  return (result.policy_warnings || []).some((item) => item.id === id);
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge pr impact '));
  rootForCleanup = root;

  const empty = seedFixture(root, 'empty');
  const emptyResult = runImpact(empty);
  assert(emptyResult.status === 'empty', 'clean fixture should return empty status');
  assert(emptyResult.empty_state?.title === 'No changed files', 'empty state missing');

  const critical = seedFixture(root, 'critical');
  fs.appendFileSync(path.join(critical.repo, 'src', 'auth.js'), 'export const authTouched = true;\n', 'utf8');
  const criticalResult = runImpact(critical);
  assert(hasPolicy(criticalResult, 'critical-file-touched'), 'critical file policy warning missing');
  assert(criticalResult.critical_files.some((item) => item.path === 'src/auth.js'), 'critical file entry missing');

  const stale = seedFixture(root, 'stale');
  fs.appendFileSync(path.join(stale.repo, 'src', 'stale.js'), 'export const staleTouched = true;\n', 'utf8');
  const staleResult = runImpact(stale);
  assert(hasPolicy(staleResult, 'stale-module-touched'), 'stale module policy warning missing');
  assert(staleResult.repair_delta.count >= 1, 'repair delta should include stale repair item');

  const evidence = seedFixture(root, 'evidence');
  fs.appendFileSync(path.join(evidence.repo, 'src', 'no-evidence.js'), 'export const changedWithoutEvidence = true;\n', 'utf8');
  const evidenceResult = runImpact(evidence);
  assert(hasPolicy(evidenceResult, 'source-changed-evidence-missing'), 'missing evidence policy warning missing');

  const runtime = seedFixture(root, 'runtime');
  writeJson(path.join(runtime.repo, '.knowledge', 'inspector', 'data.json'), { generated: true });
  git(runtime.repo, ['add', '.knowledge/inspector/data.json']);
  const runtimeResult = runImpact(runtime);
  assert(hasPolicy(runtimeResult, 'generated-runtime-staged'), 'generated runtime staged warning missing');
  assert(runtimeResult.status === 'block', 'staged runtime file should block');

  const output = {
    schema_version: '3.2.4',
    status: 'pass',
    temp_root: keepTemp ? root : null,
    temp_root_cleaned: !keepTemp,
    checks: [
      'no changed files empty state',
      'critical file touched',
      'stale module touched',
      'source changed but evidence missing',
      'generated runtime file staged'
    ]
  };
  if (!keepTemp) fs.rmSync(root, { recursive: true, force: true });
  console.log(JSON.stringify(output, null, 2));
}

process.on('exit', () => {
  if (!keepTemp && rootForCleanup && fs.existsSync(rootForCleanup)) {
    try { fs.rmSync(rootForCleanup, { recursive: true, force: true }); } catch {}
  }
});

try { main(); }
catch (error) { console.error(error.stack || error.message); process.exit(1); }
