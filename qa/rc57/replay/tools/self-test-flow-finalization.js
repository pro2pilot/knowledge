#!/usr/bin/env node
'use strict';

const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const { runFlow, runOne } = require('./flow');
const { systemVersion } = require('./lib/system-version');

function assert(condition, message, details = {}) {
  if (condition) return;
  const error = new Error(message);
  error.details = details;
  throw error;
}

function makeContext(targetRoot) {
  const knowledgeRoot = path.join(targetRoot, '.knowledge');
  fs.mkdirSync(path.join(knowledgeRoot, 'maintenance'), { recursive: true });
  return {
    mode: 'repo',
    systemRoot: path.resolve(__dirname, '..'),
    targetRoot,
    projectKnowledgeRoot: knowledgeRoot,
    stateRoot: knowledgeRoot,
    teamRoot: null,
    repoId: 'flow-finalization-test',
    workspaceId: null,
    agentId: 'flow-finalization-test',
    branch: null,
    headSha: null,
    warnings: []
  };
}

function fakeStepResult() {
  return {
    step: 'fake',
    command: 'fake.js',
    exit: 0,
    success: true,
    status: 'pass',
    json_status: 'pass',
    semantic_errors: [],
    duration_ms: 1,
    parsed: { status: 'pass' },
    stdout: '',
    stderr: ''
  };
}

function flowOptions(context) {
  return {
    name: 'doctor',
    quiet: true,
    json: true,
    noColor: true,
    exclusive: false,
    context
  };
}

function baseHooks(extra = {}) {
  return {
    stepsForFlow: () => ['fake.js'],
    runOne: () => fakeStepResult(),
    ...extra
  };
}

function absoluteLogPath(out, context) {
  if (path.isAbsolute(out.flow_log)) return out.flow_log;
  return path.resolve(context.targetRoot, ...String(out.flow_log).split('/'));
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-flow-final-'));
  const checks = [];
  try {
    const normalContext = makeContext(path.join(root, 'normal'));
    const normal = runFlow(flowOptions(normalContext), baseHooks());
    assert(normal.status === 'ok', 'normal flow did not pass', normal);
    assert(normal.flow_log_status === 'written', 'normal flow log was not finalized', normal);
    assert(normal.flow_log_error === null, 'normal flow exposed a log error', normal);
    const normalLogPath = absoluteLogPath(normal, normalContext);
    const normalLog = JSON.parse(fs.readFileSync(normalLogPath, 'utf8'));
    assert(normalLog.flow === normal.flow, 'normal log flow does not match output');
    assert(normalLog.started_at === normal.started_at, 'normal log started_at does not match output');
    assert(normalLog.steps_total === normal.steps_total, 'normal log step count does not match output');
    assert(normalLog.steps_total === normalLog.steps.length, 'normal log steps_total does not match persisted steps');
    assert(normalLog.steps_ok === normal.steps_ok, 'normal log steps_ok does not match output');
    assert(normalLog.overall_status === normal.overall_status, 'normal log status does not match output');
    const normalLogBody = fs.readFileSync(normalLogPath);
    assert(normal.flow_log_bytes === normalLogBody.length, 'normal log byte binding does not match readback');
    assert(
      normal.flow_log_sha256 ===
        crypto.createHash('sha256').update(normalLogBody).digest('hex'),
      'normal log SHA-256 binding does not match readback'
    );
    checks.push('successful flow is read back and correlated before reporting written');

    const writeFailureContext = makeContext(path.join(root, 'write-failure'));
    const writeError = new Error('injected persistent Windows lock');
    writeError.stage = 'write';
    writeError.code = 'atomic_write_retry_exhausted';
    writeError.os_code = 'EPERM';
    writeError.attempts = 6;
    writeError.temp_cleanup_status = 'removed';
    const writeFailure = runFlow(flowOptions(writeFailureContext), baseHooks({
      writeFlowLog: () => { throw writeError; }
    }));
    assert(writeFailure.status === 'failed', 'flow accepted a failed final log write', writeFailure);
    assert(writeFailure.checks_status === 'ok', 'flow lost completed check status after log failure', writeFailure);
    assert(writeFailure.flow_log_status === 'failed', 'flow log failure status is missing', writeFailure);
    assert(writeFailure.failure_code === 'flow_log_write_failed', 'stable top-level failure code is missing', writeFailure);
    assert(writeFailure.flow_log_error?.stage === 'write', 'write failure stage is missing', writeFailure);
    assert(writeFailure.flow_log_error?.code === 'atomic_write_retry_exhausted', 'atomic failure code is missing', writeFailure);
    assert(writeFailure.flow_log_error?.os_code === 'EPERM', 'atomic OS code is missing', writeFailure);
    assert(writeFailure.flow_log_error?.attempts === 6, 'atomic attempt count is missing', writeFailure);
    JSON.parse(JSON.stringify(writeFailure));
    checks.push('persistent log write failure returns one serializable fail-closed result');

    const corruptContext = makeContext(path.join(root, 'corrupt-readback'));
    const corrupt = runFlow(flowOptions(corruptContext), baseHooks({
      flowLog: {
        readFileSync: () => '{"broken":'
      }
    }));
    assert(corrupt.status === 'failed', 'flow accepted corrupt log readback', corrupt);
    assert(corrupt.flow_log_error?.stage === 'readback', 'corrupt readback stage is missing', corrupt);
    assert(corrupt.flow_log_error?.code === 'flow_log_readback_invalid_json', 'corrupt readback code is wrong', corrupt);
    checks.push('invalid JSON readback fails closed');

    const mismatchContext = makeContext(path.join(root, 'mismatch-readback'));
    const mismatch = runFlow(flowOptions(mismatchContext), baseHooks({
      flowLog: {
        readFileSync: (filePath) => {
          const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          value.started_at = '2000-01-01T00:00:00.000Z';
          return JSON.stringify(value);
        }
      }
    }));
    assert(mismatch.status === 'failed', 'flow accepted mismatched log readback', mismatch);
    assert(mismatch.flow_log_error?.stage === 'validation', 'mismatch validation stage is missing', mismatch);
    assert(mismatch.flow_log_error?.code === 'flow_log_validation_failed', 'mismatch validation code is wrong', mismatch);
    checks.push('mismatched log correlation fields fail closed');

    const nestedMismatchContext = makeContext(path.join(root, 'nested-mismatch-readback'));
    const nestedMismatch = runFlow(flowOptions(nestedMismatchContext), baseHooks({
      flowLog: {
        readFileSync: (filePath) => {
          const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          value.steps[0].exit = 1;
          value.steps[0].success = false;
          value.steps[0].status = 'fail';
          return JSON.stringify(value);
        }
      }
    }));
    assert(nestedMismatch.status === 'failed', 'flow accepted a substituted nested step with unchanged aggregates', nestedMismatch);
    assert(nestedMismatch.flow_log_error?.stage === 'validation', 'nested mismatch validation stage is missing', nestedMismatch);
    assert(nestedMismatch.flow_log_error?.code === 'flow_log_validation_failed', 'nested mismatch validation code is wrong', nestedMismatch);
    checks.push('nested step substitution with unchanged aggregates fails closed');

    const contextMismatchContext = makeContext(path.join(root, 'context-mismatch-readback'));
    const contextMismatch = runFlow(flowOptions(contextMismatchContext), baseHooks({
      flowLog: {
        readFileSync: (filePath) => {
          const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          value.context.targetRoot = path.join(root, 'other-target');
          return JSON.stringify(value);
        }
      }
    }));
    assert(contextMismatch.status === 'failed', 'flow accepted a substituted persisted context', contextMismatch);
    assert(contextMismatch.flow_log_error?.stage === 'validation', 'context mismatch validation stage is missing', contextMismatch);
    assert(contextMismatch.flow_log_error?.code === 'flow_log_validation_failed', 'context mismatch validation code is wrong', contextMismatch);
    checks.push('persisted context substitution fails closed');

    const transientContext = makeContext(path.join(root, 'transient-readback'));
    let readAttempts = 0;
    const readSleeps = [];
    const transient = runFlow(flowOptions(transientContext), baseHooks({
      flowLog: {
        sleepSync: (ms) => readSleeps.push(ms),
        readFileSync: (filePath, encoding) => {
          readAttempts += 1;
          if (readAttempts <= 2) {
            const error = new Error('injected transient read lock');
            error.code = 'EBUSY';
            throw error;
          }
          return fs.readFileSync(filePath, encoding);
        }
      }
    }));
    assert(transient.status === 'ok', 'transient readback lock did not recover', transient);
    assert(readAttempts === 3, 'transient readback attempt count is wrong', { readAttempts });
    assert(JSON.stringify(readSleeps) === JSON.stringify([50, 100]), 'transient readback backoff is wrong', { readSleeps });
    checks.push('transient readback lock recovers with bounded backoff');

    let transientCalls = 0;
    const transientWaits = [];
    const transientChild = runOne('fake.js', normalContext, {
      spawnSync: () => {
        transientCalls += 1;
        return transientCalls === 1
          ? { status: 1, signal: null, stdout: '', stderr: '' }
          : { status: 0, signal: null, stdout: '{"status":"pass"}', stderr: '' };
      },
      sleepSync: (ms) => transientWaits.push(ms)
    });
    assert(
      transientChild.success && transientChild.attempts === 2 &&
      transientChild.empty_exit_retries === 1 &&
      transientWaits.length === 1,
      'transient empty child exit did not recover with bounded retry',
      transientChild
    );
    checks.push('transient empty child exit retries the exact flow step');

    const persistentChild = runOne('fake.js', normalContext, {
      spawnSync: () => ({
        status: 1,
        signal: null,
        stdout: '',
        stderr: ''
      }),
      sleepSync: () => {}
    });
    assert(
      !persistentChild.success && persistentChild.attempts === 3 &&
      persistentChild.failure_code === 'child_empty_exit_persistent' &&
      persistentChild.stderr.includes('after 3 attempts'),
      'persistent empty child exit did not fail with a resource diagnostic',
      persistentChild
    );
    checks.push('persistent empty child exit fails with a clear diagnostic');

    return {
      schema_version: systemVersion(),
      status: 'pass',
      checks_total: checks.length,
      checks
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    console.log(JSON.stringify(main(), null, 2));
  } catch (error) {
    console.error(error.stack || error.message);
    if (error.details) console.error(JSON.stringify(error.details, null, 2));
    process.exitCode = 1;
  }
}

module.exports = main;
