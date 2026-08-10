#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const workflow = require('./lib/agent-task-workflow');

function list(value) {
  if (value === undefined || value === null || value === false) return [];
  return Array.isArray(value) ? value : String(value).split(',').map((item) => item.trim()).filter(Boolean);
}
function usage() {
  return {
    status: 'ok',
    schema_version: 'knowledge-agent-task-cli.v1',
    usage: [
      'agent-task begin --task=<text> --scope-module=<id> [--scope-path=<path>] --json',
      'agent-task finish --workflow-id=<ATW-id> --request=<finish.json> --json',
      'agent-task status --workflow-id=<ATW-id> --json'
    ],
    finish_request: {
      schema_version: workflow.REQUEST_SCHEMA,
      route_first_read_sha256: '<SHA returned by begin>',
      changed_files: ['src/file.js'],
      source_files: ['src/file.js', 'tests/file.test.js'],
      tests_to_run: [{ argv: ['node', 'tests/file.test.js'], cwd: '.', timeout_ms: 120000 }],
      run_release_flow: true
    },
    notes: [
      'Read begin.route.first_read.content before broad repository exploration.',
      'Finish executes physical verification once and may reuse the native KVE for one exact safe scoped KVR/apply.',
      workflow.DISCLAIMER
    ]
  };
}
function contained(root, candidate) {
  const rel = path.relative(path.resolve(root), path.resolve(candidate));
  return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel));
}
function parseRequestBody(body, source) {
  if (Buffer.byteLength(body, 'utf8') > 1024 * 1024) {
    throw Object.assign(new Error(`Finish request exceeds 1 MiB: ${source}`), {
      code: 'agent_task_request_oversized'
    });
  }
  let value;
  try {
    value = JSON.parse(String(body).replace(/^\uFEFF/, ''));
  } catch (cause) {
    throw Object.assign(new Error(`Unable to parse finish request JSON: ${source}`), {
      code: 'agent_task_request_json_invalid',
      detail: { cause: cause.message }
    });
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw Object.assign(new Error('Finish request must be a JSON object.'), {
      code: 'agent_task_finish_request_invalid'
    });
  }
  return value;
}
function readRequest(context, file) {
  if (!file) {
    throw Object.assign(new Error('--request=<repo-relative-file|-> is required'), {
      code: 'agent_task_request_required'
    });
  }
  if (String(file) === '-') {
    return parseRequestBody(fs.readFileSync(0, 'utf8'), '<stdin>');
  }
  const absolute = path.isAbsolute(String(file))
    ? path.resolve(String(file))
    : path.resolve(context.targetRoot, String(file));
  if (!contained(context.targetRoot, absolute)) {
    throw Object.assign(new Error('Finish request file must be inside target root or supplied through stdin.'), {
      code: 'agent_task_request_path_escape'
    });
  }
  let stat;
  try { stat = fs.lstatSync(absolute); }
  catch {
    throw Object.assign(new Error(`Finish request file is missing: ${String(file)}`), {
      code: 'agent_task_request_missing'
    });
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw Object.assign(new Error('Finish request path must be a regular non-symlink file.'), {
      code: 'agent_task_request_unsafe'
    });
  }
  if (Number(stat.nlink || 1) > 1) {
    throw Object.assign(new Error('Hardlinked finish request files are rejected.'), {
      code: 'agent_task_request_hardlinked'
    });
  }
  const physicalTarget = fs.realpathSync(context.targetRoot);
  const physicalRequest = fs.realpathSync(absolute);
  if (!contained(physicalTarget, physicalRequest)) {
    throw Object.assign(new Error('Finish request file resolves outside target root.'), {
      code: 'agent_task_request_physical_escape'
    });
  }
  return parseRequestBody(fs.readFileSync(absolute, 'utf8'), String(file));
}
function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const command = parsed.positional[0] || (parsed.flags.help ? 'help' : 'help');
  if (command === 'help' || parsed.flags.help) return usage();
  const context = resolveKnowledgeContext(parsed.flags);
  if (command === 'begin') {
    return workflow.begin(context, {
      task: parsed.flags.task,
      taskClass: parsed.flags.taskClass,
      modules: list(parsed.flags.scopeModule),
      paths: list(parsed.flags.scopePath),
      excludeModules: list(parsed.flags.excludeModule),
      excludePaths: list(parsed.flags.excludePath),
      constraints: list(parsed.flags.constraint),
      scopeSource: parsed.flags.scopeSource || 'explicit'
    });
  }
  if (command === 'finish') return workflow.finish(context, parsed.flags.workflowId, readRequest(context, parsed.flags.request));
  if (command === 'status') return workflow.status(context, parsed.flags.workflowId);
  throw Object.assign(new Error(`Unknown agent-task command: ${command}`), { code: 'agent_task_command_invalid' });
}
if (require.main === module) {
  const json = process.argv.includes('--json');
  try {
    const result = main();
    if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    else console.log(JSON.stringify(result, null, 2));
  } catch (cause) {
    const result = { status: 'failed', error: { code: cause.code || 'agent_task_failed', message: cause.message, detail: cause.detail || null } };
    if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    else console.error(cause.stack || cause.message);
    process.exitCode = 2;
  }
}
module.exports = { main, usage, __test: { readRequest, parseRequestBody, contained } };
