'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const store = require('../tools/lib/team-store');
const flow = require('../tools/flow');
const { resolveKnowledgeContext } = require('../tools/lib/path-context');
const { removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');
const { sanitizeInspectorData } = require('../tools/build-visual-inspector');

const systemRoot = path.resolve(__dirname, '..');

test('Inspector binds the visible Team result to its attempt and selected state', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-team-inspector-'));
  const priorGit = process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY;
  // This test exercises the Team store, flow log writer and actual Inspector
  // CLI. Git discovery is irrelevant to the selected-state display contract.
  process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY = '1';
  try {
    const project = path.join(root, 'project');
    const projectKnowledgeRoot = path.join(project, '.knowledge');
    const teamRoot = path.join(root, 'team');
    const stateRoot = path.join(teamRoot, 'selected-state');
    fs.mkdirSync(projectKnowledgeRoot, { recursive: true });
    fs.writeFileSync(path.join(projectKnowledgeRoot, 'config.yaml'), 'updates:\n  enabled: false\n');
    const flags = ['--mode', 'team', '--system-root', systemRoot, '--target-root', project,
      '--project-knowledge-root', projectKnowledgeRoot, '--team-root', teamRoot,
      '--workspace-id', 'workspace', '--agent-id', 'inspector-test', '--state-root', stateRoot];
    const context = resolveKnowledgeContext({ __skipCli: true, mode: 'team', systemRoot,
      targetRoot: project, projectKnowledgeRoot, teamRoot, workspaceId: 'workspace',
      agentId: 'inspector-test', stateRoot });
    store.registerWorkspace(context);
    const start = store.beginTeamFlow(context, 'doctor');
    const result = flow.runFlow({ name: 'doctor', context: { ...context, teamRunId: start.run_id }, json: true }, {
      stepsForFlow: () => ['explicit-synthetic-display-step.js'],
      runOne: () => ({ step: 'display fixture', command: 'explicit-synthetic-display-step.js',
        success: true, exit: 0, status: 'pass', duration_ms: 1, semantic_errors: [], parsed: { status: 'pass' } })
    });
    store.finalizeTeamFlow(context, start, result, { status: 'not_requested' });
    const canonicalState = store.workspaceStateDir(teamRoot, context.repoId, context.workspaceId);
    fs.mkdirSync(path.join(canonicalState, 'maintenance'), { recursive: true });
    fs.writeFileSync(path.join(canonicalState, 'maintenance/quality_report.json'), '{"status":"wrong-canonical-state","quality_score":1}');
    fs.writeFileSync(path.join(stateRoot, 'maintenance/quality_report.json'), '{"status":"selected-state","quality_score":91}');
    function build() {
      const child = spawnSync(process.execPath, [path.join(systemRoot, 'tools/build-visual-inspector.js'), ...flags, '--json'], {
        cwd: project, env: { ...process.env, KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1' },
        encoding: 'utf8', timeout: 20000, windowsHide: true
      });
      assert.ifError(child.error);
      assert.equal(child.status, 0, child.stderr || child.stdout);
      const report = JSON.parse(child.stdout);
      assert(report.features.includes('team_mode_panel'));
      const data = JSON.parse(fs.readFileSync(path.join(stateRoot, 'inspector/data.json'), 'utf8'));
      const html = fs.readFileSync(path.join(stateRoot, 'inspector/index.html'), 'utf8');
      const workspace = data.team.repos.find(repo => repo.repoId === context.repoId).workspaces
        .find(item => item.workspaceId === context.workspaceId);
      return { data, html, workspace };
    }
    const completed = build();
    assert.equal(completed.workspace.last_run_id, start.run_id);
    assert.equal(completed.workspace.last_status, 'ok');
    // The physical authority must bind the selected root even when the public
    // presentation masks the local pathname under the existing privacy policy.
    assert.equal(store.readTeamFlowStatus(teamRoot, context.repoId, context.workspaceId, start.run_id).stateRoot, stateRoot);
    const displayedRoot = sanitizeInspectorData(stateRoot);
    assert.equal(completed.workspace.stateRoot, displayedRoot);
    // JSON may mask only the username (macOS), the whole path (Windows),
    // or leave a temporary path visible (Linux). HTML masks the context root.
    assert(!completed.html.includes(stateRoot));
    assert.equal(completed.workspace.binding_version, 'run_bound_v2');
    assert.equal(completed.data.quality.quality_score, 91);
    assert(completed.html.includes(`<th>Flow attempt</th><td>${start.run_id}</td>`));
    assert(completed.html.includes('<th>Evidence binding</th><td>run_bound_v2</td>'));
    assert(completed.html.includes('<th>Flow state root</th>'));

    // A newer incomplete/corrupt attempt must stay visible even while an older
    // successful finalization and its valid checks log still exist.
    const pending = store.beginTeamFlow(context, 'doctor');
    const incomplete = build();
    assert.equal(incomplete.workspace.last_run_id, pending.run_id);
    assert.equal(incomplete.workspace.last_status, 'incomplete');
    assert(incomplete.html.includes(`<th>Flow attempt</th><td>${pending.run_id}</td>`));
    fs.writeFileSync(path.join(store.workspaceDir(teamRoot, context.repoId, context.workspaceId),
      'flow-runs', pending.run_id + '.final.json'), 'null');
    const invalid = build();
    assert.equal(invalid.workspace.last_run_id, pending.run_id);
    assert.equal(invalid.workspace.last_status, 'unknown');
    assert.equal(invalid.workspace.finalization_status, 'invalid');
    assert(invalid.html.includes('<th>Flow final status</th><td>unknown</td>'));
    assert(invalid.html.includes('<th>Finalization evidence</th><td>invalid</td>'));
  } finally {
    if (priorGit === undefined) delete process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY;
    else process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY = priorGit;
    removeTempDirStrict(root);
  }
});

// Independent literals guard the presentation policy without deriving the
// expected value by calling the sanitizer that is under test.
test('Inspector path presentation preserves its platform-specific masking policy', () => {
  const cases = [
    ['/Users/runner/work/project/team/selected-state', '/Users/<local-user>/work/project/team/selected-state'],
    ['C:\\Users\\runner\\tmp\\team\\selected-state', '<local-path>'],
    ['C:\\MyProject\\fixture\\team\\selected-state', '<local-path>'],
    ['/tmp/fixture/team/selected-state', '/tmp/fixture/team/selected-state'],
    ['/mnt/data/fixture/team/selected-state', '<local-path>']
  ];
  for (const [input, expected] of cases) {
    assert.equal(sanitizeInspectorData(input), expected, `presentation for ${input}`);
  }
});
