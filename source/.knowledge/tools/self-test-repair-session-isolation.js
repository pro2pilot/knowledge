#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const {
  buildTaskScope,
  repairSessionKey,
  repairSessionPlanRelative,
  validateRepairPlanArtifact
} = require('./lib/repair-on-touch');
const { receiptMatchesScope } = require('./repair-on-touch');

const schemaVersion = '3.3.0';
const systemRoot = path.resolve(__dirname, '..');
const toolPath = path.join(__dirname, 'repair-on-touch.js');

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function runCli(root, env, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [toolPath, ...args], {
      cwd: root,
      env,
      windowsHide: true
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`CLI timed out: ${args.join(' ')}`));
    }, 60000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (status, signal) => {
      clearTimeout(timer);
      let json = null;
      try {
        json = JSON.parse(String(stdout || stderr).trim() || '{}');
      } catch {
        return reject(new Error(
          `CLI returned non-JSON output (${status}/${signal}): ${
            stdout || stderr
          }`
        ));
      }
      resolve({ status, signal, stdout, stderr, json });
    });
  });
}

function unexplainedEmptyExit(result) {
  return result.status === 1 && result.signal === null &&
    result.stdout === '' && result.stderr === '' &&
    result.json && Object.keys(result.json).length === 0;
}

async function runConcurrentPair(root, env, args) {
  const attempts = [];
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const results = await Promise.all([
      runCli(root, env, args),
      runCli(root, env, args)
    ]);
    attempts.push(results.map((result) => ({
      status: result.status,
      signal: result.signal,
      stdout_bytes: Buffer.byteLength(result.stdout),
      stderr_bytes: Buffer.byteLength(result.stderr)
    })));
    if (!results.some(unexplainedEmptyExit)) {
      return { results, attempts };
    }
    if (attempt < 3) {
      await new Promise((resolve) => setTimeout(resolve, 50 * attempt));
    }
  }
  const error = new Error(
    `Persistent unexplained empty child exit during concurrent CLI test: ${JSON.stringify(attempts)}`
  );
  error.code = 'concurrent_cli_empty_exit_persistent';
  throw error;
}

function residualAtomicFiles(root) {
  const residual = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, {
      withFileTypes: true
    })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (
        entry.name.includes('.tmp-') ||
        entry.name.includes('.bak-')
      ) residual.push(path.relative(root, absolute).replace(/\\/g, '/'));
    }
  };
  visit(root);
  return residual.sort();
}

function rmWithRetry(target) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      fs.rmSync(target, { recursive: true, force: true });
      return;
    } catch (error) {
      if (attempt === 7) throw error;
      const until = Date.now() + 25 * (attempt + 1);
      while (Date.now() < until) {
        // Short synchronous retry only during fixture cleanup.
      }
    }
  }
}

async function main() {
  const checks = [];
  const first = buildTaskScope({
    task_id: 'TASK-repeat',
    user_task: 'Inspect repeated task'
  });
  const second = buildTaskScope({
    task_id: 'TASK-repeat',
    user_task: 'Inspect repeated task'
  });
  assert.match(first.session_id, /^session-[0-9a-f-]{36}$/i);
  assert.match(second.session_id, /^session-[0-9a-f-]{36}$/i);
  assert.notStrictEqual(first.session_id, second.session_id);
  checks.push('implicit sessions remain unique');

  const explicit = buildTaskScope({
    task_id: 'TASK-repeat',
    session_id: 'SESSION-explicit',
    user_task: 'Inspect repeated task'
  });
  assert.strictEqual(explicit.session_id, 'SESSION-explicit');
  const entry = {
    task_id: first.task_id,
    session_id: first.session_id
  };
  assert.strictEqual(receiptMatchesScope(entry, first), true);
  assert.strictEqual(receiptMatchesScope(entry, second), false);
  assert.strictEqual(
    receiptMatchesScope(entry, {
      task_id: 'OTHER',
      session_id: first.session_id
    }),
    false
  );
  assert.strictEqual(
    receiptMatchesScope(entry, { task_id: first.task_id }),
    false
  );
  assert.notStrictEqual(
    repairSessionPlanRelative(first.task_id, first.session_id),
    repairSessionPlanRelative(second.task_id, second.session_id)
  );
  checks.push('receipt and plan identity bind task plus session');

  const tempRoot = fs.mkdtempSync(path.join(
    os.tmpdir(),
    'knowledge-repair-session-concurrency-'
  ));
  const projectRoot = path.join(tempRoot, 'project');
  const knowledgeRoot = path.join(projectRoot, '.knowledge');
  const stateRoot = knowledgeRoot;
  try {
    fs.mkdirSync(path.join(projectRoot, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(projectRoot, 'src', 'app.js'),
      'module.exports = { ready: true };\n',
      'utf8'
    );
    writeJson(path.join(knowledgeRoot, 'settings', 'repository.json'), {
      maintenance: {
        repair_on_touch: {
          mode: 'scoped',
          max_findings_per_task: 2,
          max_extra_minutes: 5,
          max_extra_context_percent: 10
        }
      }
    });
    writeJson(
      path.join(knowledgeRoot, 'modules', 'module_registry.json'),
      {
        modules: [{
          module_id: 'app',
          name: 'App',
          path: 'src',
          card: '.knowledge/modules/app.json'
        }]
      }
    );
    writeJson(path.join(knowledgeRoot, 'modules', 'app.json'), {
      module_id: 'app',
      name: 'App',
      path: 'src',
      confidence: 'medium',
      current_trust_level: 'routing_trusted',
      target_trust_level: 'near_trusted',
      verification_status: 'routing_verified',
      key_files: ['src/app.js'],
      evidence_files: []
    });
    writeJson(
      path.join(stateRoot, 'maintenance', 'routing_bundle.json'),
      {
        schema_version: 'knowledge-routing-bundle.v1',
        modules: [{
          module_id: 'app',
          path: 'src',
          key_files: ['src/app.js']
        }]
      }
    );
    writeJson(path.join(stateRoot, 'maps', 'file_criticality.json'), {
      files: []
    });

    const taskId = 'TASK-concurrent-session';
    const sessionId = 'SESSION-concurrent-session';
    const env = {
      ...process.env,
      KNOWLEDGE_SYSTEM_ROOT: systemRoot,
      KNOWLEDGE_TARGET_ROOT: projectRoot,
      KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: knowledgeRoot,
      KNOWLEDGE_STATE_ROOT: stateRoot,
      KNOWLEDGE_AGENT_ID: 'session-isolation-test',
      KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1'
    };
    const planArgs = [
      'plan',
      `--task-id=${taskId}`,
      `--session-id=${sessionId}`,
      '--task=Inspect concurrent session writes',
      '--module=app',
      '--changed-file=src/app.js'
    ];
    const planAttempt = await runConcurrentPair(projectRoot, env, planArgs);
    const planRuns = planAttempt.results;
    assert(
      planRuns.every((result) =>
        result.status === 0 &&
        result.signal === null &&
        result.json.status === 'planned' &&
        result.json.task_scope?.task_id === taskId &&
        result.json.task_scope?.session_id === sessionId),
      `Concurrent plan failed: ${JSON.stringify(planRuns)}`
    );
    const planRelative = repairSessionPlanRelative(taskId, sessionId);
    const planPath = path.join(
      stateRoot,
      ...planRelative.split('/')
    );
    const plan = readJson(planPath);
    const planValidation = validateRepairPlanArtifact(plan);
    assert(
      planValidation.ok &&
      plan.task_scope.task_id === taskId &&
      plan.task_scope.session_id === sessionId,
      `Concurrent plan artifact is invalid: ${
        planValidation.errors.join(', ')
      }`
    );
    checks.push('same-session concurrent plans serialize to valid JSON');

    const telemetryArgs = [
      'telemetry',
      `--task-id=${taskId}`,
      `--session-id=${sessionId}`
    ];
    const telemetryAttempt = await runConcurrentPair(
      projectRoot,
      env,
      telemetryArgs
    );
    const telemetryRuns = telemetryAttempt.results;
    assert(
      telemetryRuns.every((result) =>
        result.status === 0 &&
        result.signal === null &&
        result.json.task_id === taskId &&
        result.json.session_id === sessionId &&
        result.json.scope_source === 'explicit_session'),
      `Concurrent telemetry failed: ${JSON.stringify(telemetryRuns)}`
    );
    const key = repairSessionKey(taskId, sessionId);
    const telemetryPath = path.join(
      stateRoot,
      'maintenance',
      'repair_sessions',
      `${key}.telemetry.json`
    );
    const telemetry = readJson(telemetryPath);
    const latest = readJson(path.join(
      stateRoot,
      'maintenance',
      'repair_opportunities.json'
    ));
    assert.strictEqual(telemetry.task_id, taskId);
    assert.strictEqual(telemetry.session_id, sessionId);
    assert.strictEqual(latest.task_scope.task_id, taskId);
    assert.strictEqual(latest.task_scope.session_id, sessionId);
    assert.deepStrictEqual(residualAtomicFiles(knowledgeRoot), []);
    checks.push(
      'same-session telemetry and latest advisory remain valid and clean'
    );

    process.stdout.write(`${JSON.stringify({
      schema_version: schemaVersion,
      status: 'pass',
      checks_total: checks.length,
      checks,
      task_id: taskId,
      session_id: sessionId,
      plan_artifact: planRelative,
      telemetry_artifact: path.relative(
        stateRoot,
        telemetryPath
      ).replace(/\\/g, '/'),
      concurrent_plan_attempts: planAttempt.attempts.length,
      concurrent_telemetry_attempts: telemetryAttempt.attempts.length,
      fixture_cleaned: true
    }, null, 2)}\n`);
  } finally {
    rmWithRetry(tempRoot);
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});
