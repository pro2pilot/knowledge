'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const workflowModule = require.resolve('../tools/lib/agent-task-workflow');

function observeBegin(t, mode) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'workflow-child-audit-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const project = path.join(root, 'проект с пробелами');
  const state = path.join(project, '.knowledge');
  const system = path.join(root, 'system');
  const marker = path.join(root, 'physical-child.json');
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(system, 'package.json'), '{"version":"3.4.4"}\n');
  // This explicit offline profile belongs only to disposable fixtures.
  for (const directory of [system, state]) {
    fs.writeFileSync(path.join(directory, 'config.json'), '{"updates":{"enabled":false}}\n');
  }
  const validOutput = "JSON.stringify({ok:true,session:{session_id:process.env.KNOWLEDGE_SESSION_ID,status:'running'}})";
  const childAction = {
    empty: '',
    whitespace: "process.stdout.write(' \\n\\t');",
    malformed: "process.stdout.write('{broken-json');",
    valid: `process.stdout.write(${validOutput});`,
    native_signal: "process.kill(process.pid, 'SIGTERM');"
  }[mode] || '';
  fs.writeFileSync(path.join(system, 'tools', 'agent-session.js'),
    `require('fs').writeFileSync(${JSON.stringify(marker)},JSON.stringify({argv:process.argv.slice(2),session_id:process.env.KNOWLEDGE_SESSION_ID}));\n${childAction}\n`);

  // Only contradictory transport tuples are simulated. The other cases execute
  // a real on-disk agent-session child through the production runTool boundary.
  const injected = mode === 'zero_error' || mode === 'zero_signal'
    ? `require('child_process').spawnSync=()=>({status:0,signal:${mode === 'zero_signal' ? "'SIGTERM'" : 'null'},error:${mode === 'zero_error' ? "Object.assign(new Error('synthetic transport error'),{code:'EPERM'})" : 'undefined'},stdout:'{"ok":true,"session":{"status":"running"}}',stderr:''});\n`
    : '';
  const context = {
    mode: 'repo', systemRoot: system, targetRoot: project,
    projectKnowledgeRoot: state, stateRoot: state, teamRoot: null,
    repoId: 'workflow-child-audit', workspaceId: null, agentId: 'workflow-child-audit',
    branch: 'fixture', headSha: 'a'.repeat(40), git: { is_git_repo: false }, warnings: []
  };
  const route = {
    task_scope_hash: 'a'.repeat(64), snapshot_hash: 'b'.repeat(64), routing_snapshot_hash: 'b'.repeat(64),
    scope: { modules: ['feature'], paths: ['src/feature.js'] },
    state: { current_status: 'current', task_readiness: 'ready', effective_claim_eligible: false,
      claim_ineligible_reasons: [], bundle: { selected_modules: ['feature'] }, metrics: {} },
    first_read: { path: 'synthetic-first-read.md', sha256: 'c'.repeat(64), bytes: 18, content: 'Synthetic fixture\n' }
  };
  const driver = path.join(root, 'driver.js');
  fs.writeFileSync(driver, `${injected}
const fs=require('fs'),path=require('path');
const workflow=require(${JSON.stringify(workflowModule)});
const context=${JSON.stringify(context)};
let result;
try {
  result={returned:workflow.begin(context,{task:'Read synthetic feature',modules:['feature'],paths:['src/feature.js']},
    {taskRoute:()=>(${JSON.stringify(route)}),doctor:()=>({quality_score:90,status:'usable_with_warnings'})})};
} catch (error) { result={error:{code:error.code,message:error.message,detail:error.detail}}; }
const directory=path.join(context.stateRoot,'sessions','task-workflows');
result.workflows=fs.existsSync(directory)?fs.readdirSync(directory).filter(name=>/^ATW-[a-f0-9]{64}\\.json$/.test(name)).map(name=>JSON.parse(fs.readFileSync(path.join(directory,name),'utf8'))):[];
result.child=fs.existsSync(${JSON.stringify(marker)})?JSON.parse(fs.readFileSync(${JSON.stringify(marker)},'utf8')):null;
process.stdout.write(JSON.stringify(result));
`);
  const run = spawnSync(process.execPath, [driver], {
    cwd: project, encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024,
    env: { ...process.env, KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' }
  });
  assert.equal(run.error, undefined, run.error?.message);
  assert.equal(run.signal, null);
  assert.equal(run.status, 0, run.stderr);
  const observed = JSON.parse(run.stdout);
  t.diagnostic(JSON.stringify({ mode, physical_child_ran: !!observed.child,
    returned_status: observed.returned?.status || null, error_code: observed.error?.code || null,
    workflow_sessions: observed.workflows.map(row => row.agent_session ?? null) }));
  return observed;
}

for (const mode of ['empty', 'whitespace']) {
  test(`workflow child audit: begin rejects physical exit-zero ${mode} JSON output`, t => {
    const observed = observeBegin(t, mode);
    assert(observed.child, 'The production boundary must execute the physical child.');
    assert.equal(observed.error?.code, 'agent_task_tool_output_empty');
    assert.equal(observed.returned, undefined);
    assert(observed.workflows.every(row => !row.agent_session));
  });
}

for (const mode of ['zero_error', 'zero_signal']) {
  test(`workflow child audit: begin rejects contradictory transport ${mode}`, t => {
    const observed = observeBegin(t, mode);
    assert.equal(observed.child, null, 'This case is an explicitly synthetic transport tuple.');
    assert.equal(observed.error?.code, mode === 'zero_error' ? 'agent_task_tool_spawn_failed' : 'agent_task_tool_failed');
    assert.equal(observed.returned, undefined);
    assert(observed.workflows.every(row => !row.agent_session));
  });
}

test('workflow child audit: begin rejects a physical child terminated by signal', t => {
  const observed = observeBegin(t, 'native_signal');
  assert(observed.child);
  assert.equal(observed.error?.code, 'agent_task_tool_failed');
  if (process.platform === 'win32') {
    // Windows terminates this physical child with an exit code; Node reports
    // no POSIX signal. The synthetic zero+signal case above remains strict.
    assert.equal(observed.error?.detail?.signal, null);
    assert.equal(observed.error?.detail?.exit_code, 1);
  } else {
    assert.equal(observed.error?.detail?.signal, 'SIGTERM');
  }
  assert.equal(observed.returned, undefined);
});

test('workflow child audit: begin rejects physical malformed JSON without recording a session', t => {
  const observed = observeBegin(t, 'malformed');
  assert(observed.child);
  assert.equal(observed.error?.code, 'agent_task_tool_output_invalid');
  assert.equal(observed.returned, undefined);
  assert(observed.workflows.every(row => !row.agent_session));
});

test('workflow child audit: begin accepts physical valid JSON and persists its exact session', t => {
  const observed = observeBegin(t, 'valid');
  assert(observed.child);
  assert.equal(observed.error, undefined);
  assert.equal(observed.returned.status, 'ready');
  assert.equal(observed.workflows.length, 1);
  assert.deepEqual(observed.workflows[0].agent_session,
    { session_id: observed.returned.workflow_id, status: 'running' });
  assert.equal(observed.child.session_id, observed.returned.workflow_id);
  assert(observed.child.argv.includes('--json'));
});
