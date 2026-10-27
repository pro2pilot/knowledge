#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const evaluationHarness = require('./evaluation-harness');
const { systemVersion } = require('./lib/system-version');

const systemRoot = path.resolve(__dirname, '..');

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function writeFile(filePath, contents) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, contents, 'utf8');
}

function runNode(script, targetRoot, projectKnowledgeRoot, stateRoot) {
  const result = spawnSync(process.execPath, [path.join(systemRoot, 'tools', script)], {
    cwd: targetRoot,
    env: {
      ...process.env,
      KNOWLEDGE_AGENT_ID: 'self-test-evaluation-metrics',
      KNOWLEDGE_MODE: 'repo',
      KNOWLEDGE_SYSTEM_ROOT: systemRoot,
      KNOWLEDGE_TARGET_ROOT: targetRoot,
      KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: projectKnowledgeRoot,
      KNOWLEDGE_STATE_ROOT: stateRoot,
      KNOWLEDGE_TEAM_ROOT: '',
      KNOWLEDGE_WORKSPACE_ID: '',
      KNOWLEDGE_FLOW_NO_OPEN: '1'
    },
    encoding: 'utf8',
    timeout: 180000,
    windowsHide: true
  });
  return {
    exit: result.status,
    signal: result.signal || null,
    error: result.error?.message || null,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim()
  };
}

function parseJson(result, label) {
  try { return JSON.parse(result.stdout); }
  catch (error) {
    throw new Error(`${label} did not emit one valid JSON report: ${error.message}\n${result.stdout}\n${result.stderr}`);
  }
}

function assert(condition, message, details = null) {
  if (!condition) {
    const error = new Error(message);
    error.details = details;
    throw error;
  }
}

function test(name, fn, results) {
  try {
    results.push({ name, status: 'pass', details: fn() });
  } catch (error) {
    results.push({ name, status: 'fail', message: error.message, details: error.details || null });
  }
}

function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-eval-metrics-'));
  const results = [];
  try {
    test('evaluation child empty exits use bounded exact-step retry', () => {
      let transientCalls = 0;
      const waits = [];
      const transient = evaluationHarness.runCheck(
        { name: 'injected_transient', command: 'fake.js' },
        {
          spawnSync: () => {
            transientCalls += 1;
            return transientCalls === 1
              ? { status: 1, signal: null, stdout: '', stderr: '' }
              : { status: 0, signal: null, stdout: '{"status":"pass"}', stderr: '' };
          },
          sleepSync: (ms) => waits.push(ms)
        }
      );
      assert(transient.status === 'pass' && transient.attempts === 2 &&
        transient.empty_exit_retries === 1 && waits.length === 1,
      'Transient empty child exit did not recover on the exact check.', transient);

      const persistent = evaluationHarness.runCheck(
        { name: 'injected_persistent', command: 'fake.js' },
        {
          spawnSync: () => ({ status: 1, signal: null, stdout: '', stderr: '' }),
          sleepSync: () => {}
        }
      );
      assert(persistent.status === 'fail' && persistent.attempts === 3 &&
        persistent.failure_code === 'child_empty_exit_persistent' &&
        persistent.semantic_errors.some((value) => value.includes('after 3 attempts')),
      'Persistent empty child exit was not diagnosed after bounded retries.', persistent);
      return { transient, persistent };
    }, results);

    test('evaluation CLI fails closed after emitting its semantic report', () => {
      const targetRoot = path.join(tempRoot, 'evaluation-target');
      const knowledgeRoot = path.join(targetRoot, '.knowledge');
      ensureDir(knowledgeRoot);
      writeFile(path.join(targetRoot, 'README.md'), '# Deliberately incomplete fixture\n');

      const run = runNode('evaluation-harness.js', targetRoot, knowledgeRoot, knowledgeRoot);
      const report = parseJson(run, 'evaluation-harness');
      const persisted = JSON.parse(fs.readFileSync(path.join(knowledgeRoot, 'evaluation', 'results', 'latest.json'), 'utf8'));

      assert(run.exit === 2, 'Semantic evaluation failure must exit with code 2.', run);
      assert(report.status !== 'release_candidate', 'Incomplete fixture unexpectedly became a release candidate.', report);
      assert(report.failed_count > 0, 'Incomplete fixture report has no failed checks.', report);
      assert(persisted.status === report.status && persisted.failed_count === report.failed_count,
        'Persisted evaluation report does not match emitted semantic result.', { report, persisted });
      assert(evaluationHarness.exitCodeForReport({ status: 'release_candidate', failed_count: 0, results: [] }) === 0,
        'Synthetic release-candidate report should map to exit code 0.');
      assert(evaluationHarness.exitCodeForReport({ status: 'release_candidate', failed_count: 0, results: [{ status: 'fail' }] }) === 2,
        'A failed check must override an inconsistent release-candidate status.');
      return { exit: run.exit, status: report.status, failed_count: report.failed_count };
    }, results);

    test('co-located metrics roots are counted once', () => {
      const targetRoot = path.join(tempRoot, 'co-located-target');
      const knowledgeRoot = path.join(targetRoot, '.knowledge');
      writeFile(path.join(knowledgeRoot, 'fixture.json'), '{}\n');
      writeFile(path.join(knowledgeRoot, 'fixture.md'), '# Fixture\n');

      const run = runNode('collect-metrics.js', targetRoot, knowledgeRoot, knowledgeRoot);
      const report = parseJson(run, 'collect-metrics co-located');
      assert(run.exit === 0, 'collect-metrics failed for co-located roots.', run);
      assert(report.files.roots_overlap === true, 'Co-located roots were not disclosed as overlapping.', report.files);
      assert(report.files.curated_total === 2, 'Curated count should include each fixture file once.', report.files);
      assert(report.files.runtime_total === 0, 'Co-located runtime count must not duplicate curated files.', report.files);
      assert(report.files.unique_total === 2 && report.files.json === 1 && report.files.markdown === 1,
        'Co-located file-type totals were double-counted.', report.files);
      assert(report.files.runtime_total_accounting === 'included_in_curated_total',
        'Co-located accounting policy is not explicit.', report.files);
      return report.files;
    }, results);

    test('nested runtime root is not counted twice', () => {
      const targetRoot = path.join(tempRoot, 'runtime-nested-target');
      const knowledgeRoot = path.join(targetRoot, '.knowledge');
      const stateRoot = path.join(knowledgeRoot, 'runtime-state');
      writeFile(path.join(knowledgeRoot, 'curated.json'), '{}\n');
      writeFile(path.join(stateRoot, 'runtime.md'), '# Runtime\n');

      const run = runNode('collect-metrics.js', targetRoot, knowledgeRoot, stateRoot);
      const report = parseJson(run, 'collect-metrics nested runtime');
      assert(run.exit === 0, 'collect-metrics failed with runtime root nested under curated root.', run);
      assert(report.files.roots_overlap === true && report.files.roots_relation === 'state_within_knowledge',
        'Nested runtime root was not classified correctly.', report.files);
      assert(report.files.curated_total === 2 && report.files.runtime_total === 0 && report.files.unique_total === 2,
        'Nested runtime files were counted twice.', report.files);
      assert(report.files.json === 1 && report.files.markdown === 1,
        'Nested runtime file-type totals were counted incorrectly.', report.files);
      assert(report.files.runtime_total_accounting === 'included_in_curated_total',
        'Nested runtime accounting policy is not explicit.', report.files);
      return report.files;
    }, results);

    test('parent runtime root excludes nested curated files', () => {
      const targetRoot = path.join(tempRoot, 'curated-nested-target');
      const stateRoot = path.join(tempRoot, 'curated-nested-state');
      const knowledgeRoot = path.join(stateRoot, 'project-knowledge');
      ensureDir(targetRoot);
      writeFile(path.join(knowledgeRoot, 'curated.json'), '{}\n');
      writeFile(path.join(stateRoot, 'runtime.md'), '# Runtime\n');

      const run = runNode('collect-metrics.js', targetRoot, knowledgeRoot, stateRoot);
      const report = parseJson(run, 'collect-metrics nested curated');
      assert(run.exit === 0, 'collect-metrics failed with curated root nested under runtime root.', run);
      assert(report.files.roots_overlap === true && report.files.roots_relation === 'knowledge_within_state',
        'Nested curated root was not classified correctly.', report.files);
      assert(report.files.curated_total === 1 && report.files.runtime_total === 1 && report.files.unique_total === 2,
        'Parent runtime root did not exclude nested curated files.', report.files);
      assert(report.files.json === 1 && report.files.markdown === 1,
        'Nested curated file-type totals were counted incorrectly.', report.files);
      assert(report.files.runtime_total_accounting === 'runtime_total_excludes_curated_overlap',
        'Nested curated accounting policy is not explicit.', report.files);
      return report.files;
    }, results);

    test('separate metrics roots retain separate accounting', () => {
      const targetRoot = path.join(tempRoot, 'separate-target');
      const knowledgeRoot = path.join(targetRoot, '.knowledge');
      const stateRoot = path.join(tempRoot, 'separate-state');
      writeFile(path.join(knowledgeRoot, 'curated.json'), '{}\n');
      writeFile(path.join(stateRoot, 'runtime.md'), '# Runtime\n');

      const run = runNode('collect-metrics.js', targetRoot, knowledgeRoot, stateRoot);
      const report = parseJson(run, 'collect-metrics separate');
      assert(run.exit === 0, 'collect-metrics failed for separate roots.', run);
      assert(report.files.roots_overlap === false, 'Separate roots were incorrectly marked as overlapping.', report.files);
      assert(report.files.curated_total === 1 && report.files.runtime_total === 1 && report.files.unique_total === 2,
        'Separate roots did not retain transparent per-root totals.', report.files);
      assert(report.files.json === 1 && report.files.markdown === 1,
        'Separate root file-type totals are incorrect.', report.files);
      assert(report.files.runtime_total_accounting === 'separate_state_root',
        'Separate-root accounting policy is not explicit.', report.files);
      return report.files;
    }, results);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }

  const failed = results.filter((result) => result.status === 'fail');
  const report = {
    schema_version: systemVersion(),
    status: failed.length ? 'fail' : 'pass',
    tests_total: results.length,
    tests_passed: results.length - failed.length,
    tests_failed: failed.length,
    results
  };
  console.log(JSON.stringify(report, null, 2));
  if (failed.length) process.exit(2);
}

try { main(); }
catch (error) {
  console.log(JSON.stringify({
    schema_version: systemVersion(),
    status: 'fail',
    tests_total: 0,
    tests_passed: 0,
    tests_failed: 1,
    errors: [error.message]
  }, null, 2));
  process.exit(2);
}
