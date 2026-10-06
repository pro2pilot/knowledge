#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// The optional root is useful for replaying this regression against the exact
// pre-fix archive. Normal invocation tests the installed runtime beside it.
const systemRoot = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));
const { resolveKnowledgeContext } = require(path.join(systemRoot, 'tools/lib/path-context'));
const team = require(path.join(systemRoot, 'tools/lib/team-store'));
const { readContainedJson } = require(path.join(systemRoot, 'tools/lib/contained-artifact'));
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-root-boundaries-'));
const results = [];

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value));
}
function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function context(root, overrides = {}) {
  return {
    mode: 'team', systemRoot, projectKnowledgeRoot: systemRoot,
    targetRoot: root, teamRoot: path.join(root, 'team'), repoId: 'repo-a',
    workspaceId: 'task-a', agentId: 'audit', git: {}, branch: 'audit',
    headSha: null, warnings: [], ...overrides
  };
}
function test(name, callback) {
  const root = path.join(base, String(results.length));
  fs.mkdirSync(root);
  try { callback(root); results.push({ name, status: 'pass' }); }
  catch (error) { results.push({ name, status: 'fail', error: error.stack || error.message }); }
}

try {
  for (const id of ['../../../../escaped', '..\\..\\escaped', '.', '..', 'CON', 'nul.json', 'task.', 'task ', 'task\u0000x', true]) {
    test(`context rejects unsafe workspace ID ${JSON.stringify(id)}`, (root) => {
      assert.throws(() => resolveKnowledgeContext({
        __skipCli: true, systemRoot, targetRoot: root, mode: 'team',
        teamRoot: path.join(root, 'team'), workspaceId: id, agentId: 'audit'
      }), (error) => error.code === 'path_segment_invalid');
      assert(!fs.existsSync(path.join(root, 'team')), 'invalid context created team state');
    });
  }

  test('direct registration rejects traversal before writing registry or external workspace', (root) => {
    const ctx = context(root, { workspaceId: '../../../../escaped' });
    assert.throws(() => team.registerWorkspace(ctx), (error) => error.code === 'path_segment_invalid');
    assert(!fs.existsSync(path.join(root, 'team')));
    assert(!fs.existsSync(path.join(root, 'escaped')));
  });
  test('Unicode workspace names remain distinct and usable', (root) => {
    const ctx = context(root, { workspaceId: 'задача α 1' });
    const result = team.registerWorkspace(ctx);
    assert.equal(result.workspaceId, ctx.workspaceId);
    assert.equal(team.findWorkspace(ctx.teamRoot, ctx.workspaceId, ctx.repoId).workspace.status, 'active');
  });
  test('repository directory symlink cannot receive registry or workspace writes', (root) => {
    const ctx = context(root);
    const outside = path.join(root, 'outside');
    fs.mkdirSync(outside);
    fs.mkdirSync(path.join(ctx.teamRoot, 'repos'), { recursive: true });
    fs.symlinkSync(outside, path.join(ctx.teamRoot, 'repos', ctx.repoId), process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(() => team.registerWorkspace(ctx), (error) => error.code === 'contained_path_unsafe');
    assert.deepEqual(fs.readdirSync(outside), []);
    assert(!fs.existsSync(path.join(ctx.teamRoot, 'registry.json')));
  });
  test('hardlinked registry is rejected and original bytes stay unchanged', (root) => {
    const ctx = context(root);
    fs.mkdirSync(ctx.teamRoot);
    const outside = path.join(root, 'outside.json');
    write(outside, { repos: [{ repoId: 'sentinel' }] });
    fs.linkSync(outside, path.join(ctx.teamRoot, 'registry.json'));
    assert.throws(() => team.initTeam(ctx), (error) => error.code === 'contained_path_unsafe');
    assert.deepEqual(read(outside), { repos: [{ repoId: 'sentinel' }] });
  });
  test('corrupt existing registry is preserved instead of being replaced by defaults', (root) => {
    const ctx = context(root);
    fs.mkdirSync(ctx.teamRoot);
    const file = path.join(ctx.teamRoot, 'registry.json');
    fs.writeFileSync(file, '{broken');
    assert.throws(() => team.initTeam(ctx));
    assert.equal(fs.readFileSync(file, 'utf8'), '{broken');
  });
  test('null registry fails with a structured validation error', (root) => {
    const ctx = context(root);
    write(path.join(ctx.teamRoot, 'registry.json'), null);
    assert.throws(() => team.initTeam(ctx), (error) => error.code === 'team_registry_invalid');
    assert.equal(read(path.join(ctx.teamRoot, 'registry.json')), null);
  });
  for (const [role, invalid] of [['repo', []], ['repo', null], ['repo', 'broken'], ['workspace', []], ['workspace', null]]) {
    test(`${role} rejects valid JSON with the wrong shape before any registry write: ${JSON.stringify(invalid)}`, (root) => {
      const ctx = context(root);
      team.registerWorkspace(ctx);
      const registry = path.join(ctx.teamRoot, 'registry.json');
      const registryBytes = fs.readFileSync(registry);
      const file = role === 'repo' ? path.join(team.repoDir(ctx.teamRoot, ctx.repoId), 'repo.json') :
        path.join(team.workspaceDir(ctx.teamRoot, ctx.repoId, ctx.workspaceId), 'workspace.json');
      write(file, invalid);
      assert.throws(() => team.registerWorkspace(ctx), (error) => error.code === 'team_state_invalid');
      assert.deepEqual(read(file), invalid);
      assert.deepEqual(fs.readFileSync(registry), registryBytes);
    });
  }
  test('workspace identity tampering cannot be updated or archived', (root) => {
    const ctx = context(root);
    team.registerWorkspace(ctx);
    const file = path.join(team.workspaceDir(ctx.teamRoot, ctx.repoId, ctx.workspaceId), 'workspace.json');
    write(file, { ...read(file), repoId: 'other-repo', workspaceId: 'other-task' });
    const previous = fs.readFileSync(file);
    assert.throws(() => team.updateWorkspaceFlow(ctx, { flow: 'scan' }), (error) => error.code === 'team_state_identity_mismatch');
    assert.throws(() => team.unregisterWorkspace(ctx.teamRoot, ctx.workspaceId, ctx.repoId), (error) => error.code === 'team_state_identity_mismatch');
    assert.deepEqual(fs.readFileSync(file), previous);
  });
  test('flow updates select the repository owning this workspace ID', (root) => {
    const a = context(root);
    const b = context(root, { repoId: 'repo-b' });
    team.registerWorkspace(a); team.registerWorkspace(b);
    const first = path.join(team.workspaceDir(a.teamRoot, a.repoId, a.workspaceId), 'workspace.json');
    const firstBytes = fs.readFileSync(first);
    team.updateWorkspaceFlow(b, { flow: 'scan', overall_status: 'pass' });
    assert.deepEqual(fs.readFileSync(first), firstBytes, 'another repository workspace was changed');
    assert.equal(team.findWorkspace(b.teamRoot, b.workspaceId, b.repoId).workspace.last_flow, 'scan');
  });
  test('ambiguous unregister refuses and exact repo ID archives only that workspace', (root) => {
    const a = context(root);
    const b = context(root, { repoId: 'repo-b' });
    team.registerWorkspace(a); team.registerWorkspace(b);
    assert.throws(() => team.unregisterWorkspace(a.teamRoot, a.workspaceId), (error) => error.code === 'workspace_id_ambiguous');
    assert.equal(team.findWorkspace(a.teamRoot, a.workspaceId, a.repoId).workspace.status, 'active');
    assert.equal(team.findWorkspace(b.teamRoot, b.workspaceId, b.repoId).workspace.status, 'active');
    const result = spawnSync(process.execPath, [path.join(systemRoot, 'tools/workspace-unregister.js'),
      '--team-root', b.teamRoot, '--workspace-id', b.workspaceId, '--repo-id', b.repoId, '--json'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(team.findWorkspace(a.teamRoot, a.workspaceId, a.repoId).workspace.status, 'active');
    assert.equal(team.findWorkspace(b.teamRoot, b.workspaceId, b.repoId).workspace.status, 'archived');
  });
  test('duplicate registration failure preserves current registry and workspace bytes', (root) => {
    const a = context(root);
    team.registerWorkspace(a);
    const file = path.join(a.teamRoot, 'registry.json');
    const previous = fs.readFileSync(file);
    assert.throws(() => team.registerWorkspace({ ...a, agentId: 'different' }), /duplicate/);
    assert.deepEqual(fs.readFileSync(file), previous);
  });
  test('fallback metadata identifies the actual lower-priority artifact', (root) => {
    const curated = path.join(root, 'curated');
    const state = path.join(root, 'state');
    fs.mkdirSync(curated);
    write(path.join(state, 'data.json'), { source: 'state' });
    const result = readContainedJson({ projectKnowledgeRoot: curated, stateRoot: state }, 'data.json', 'curated');
    assert.equal(result.fallback_used, true);
    assert.equal(result.root, state);
    assert.equal(result.candidates.length, 1);
  });
  test('invalid preferred artifact remains authoritative and cannot fall back to old state', (root) => {
    const curated = path.join(root, 'curated');
    const state = path.join(root, 'state');
    write(path.join(state, 'data.json'), { source: 'state' });
    fs.mkdirSync(curated);
    fs.writeFileSync(path.join(curated, 'data.json'), '{broken');
    const result = readContainedJson({ projectKnowledgeRoot: curated, stateRoot: state }, 'data.json', 'curated');
    assert.equal(result.error, 'role_source_invalid_json');
    assert.equal(result.root, curated);
    assert.equal(result.fallback_used, false);
  });
} finally {
  fs.rmSync(base, { recursive: true, force: true });
}

const failed = results.filter((row) => row.status === 'fail');
console.log(JSON.stringify({ suite: 'root-boundaries', status: failed.length ? 'fail' : 'pass',
  total: results.length, passed: results.length - failed.length, failed: failed.length, results }, null, 2));
if (failed.length) process.exitCode = 1;
