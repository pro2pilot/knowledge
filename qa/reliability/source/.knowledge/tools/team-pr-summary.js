#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs } = require('./lib/path-context');
const { detectGitContext } = require('./lib/git-context');
const { findWorkspace, appendTeamEvent, readTeamFlowStatus, workspaceStateDir, eventPath } = require('./lib/team-store');
const { readJson, writeFileAtomicContained, assertSafeContainmentRoot, assertSafeContainedPath, assertSafeContainedFile, ensureContainedDir } = require('./lib/json-store');
const { systemVersion } = require('./lib/system-version');

function listChangedFiles(targetRoot) {
  const git = detectGitContext(targetRoot);
  return {
    git,
    source: (git.changed_files || []).filter((file) => !file.startsWith('.knowledge/')),
    knowledge: (git.changed_files || []).filter((file) => file.startsWith('.knowledge/'))
  };
}

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const teamRoot = path.resolve(flags.teamRoot || process.env.KNOWLEDGE_TEAM_ROOT || '');
  const workspaceId = flags.workspaceId || process.env.KNOWLEDGE_WORKSPACE_ID;
  if (!teamRoot || teamRoot === path.resolve('')) throw new Error('team-pr-summary requires --team-root');
  if (!workspaceId) throw new Error('team-pr-summary requires --workspace-id');
  const outputRoot = assertSafeContainmentRoot(teamRoot);
  const found = findWorkspace(teamRoot, workspaceId, flags.repoId || process.env.KNOWLEDGE_REPO_ID || null);
  if (!found) throw new Error(`Workspace not found: ${workspaceId}`);
  const flow = readTeamFlowStatus(teamRoot, found.repoId, workspaceId, found.workspace.last_run_id);
  const canonicalState = workspaceStateDir(teamRoot, found.repoId, workspaceId);
  const samePath = (left, right) => process.platform === 'win32'
    ? path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase()
    : path.resolve(left) === path.resolve(right);
  const boundState = flow.binding_version === 'run_bound_v2' && flow.stateRoot;
  if (!boundState && found.workspace.stateRoot && !samePath(found.workspace.stateRoot, canonicalState)) {
    throw Object.assign(new Error('Custom Team state requires a valid v2 flow binding for this workspace.'), { code: 'team_state_root_unattested' });
  }
  const stateRoot = boundState || canonicalState;
  assertSafeContainedPath(outputRoot, stateRoot, { allowMissing: true });
  const workspace = { ...found.workspace, ...flow, stateRoot };
  const outPath = path.join(stateRoot, 'maintenance', 'team_pr_summary.md');
  ensureContainedDir(outputRoot, path.dirname(outPath));
  assertSafeContainedFile(outputRoot, outPath, { allowMissing: true });
  assertSafeContainedFile(outputRoot, eventPath(teamRoot, found.repoId), { allowMissing: true });

  const changed = listChangedFiles(workspace.targetRoot);
  const doctor = readJson(path.join(stateRoot, 'maintenance', 'quality_report.json'), {});
  const trust = readJson(path.join(stateRoot, 'maintenance', 'trust_report.json'), {});
  const repair = readJson(path.join(stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
  const critical = readJson(path.join(stateRoot, 'maps', 'file_criticality.json'), { files: [] });
  const criticalTouched = (critical.files || []).filter((item) => changed.source.includes(item.path) && ['critical', 'important'].includes(item.classification));

  const md = `# Team PR Summary

Workspace: ${workspace.workspaceId}
Agent: ${workspace.agentId}
Repo: ${workspace.repoId}
Branch: ${changed.git.branch || workspace.branch || 'unknown'}
Head: ${changed.git.head_sha || workspace.headSha || 'unknown'}

## Health

- Flow final status: ${workspace.last_status} (${workspace.finalization_status})
- Flow attempt: ${workspace.last_run_id || 'unknown'} (${workspace.binding_version || 'unattested'})
- Doctor: ${doctor.status || 'unknown'} (${doctor.quality_score ?? 'n/a'}/100)
- Trust low confidence: ${(trust.modules?.low_confidence || []).join(', ') || '-'}
- Trust suspect: ${(trust.modules?.suspect || []).join(', ') || '-'}

## Changed source files

${changed.source.map((file) => `- ${file}`).join('\n') || '- none detected'}

## Changed curated knowledge files

${changed.knowledge.map((file) => `- ${file}`).join('\n') || '- none detected'}

## Critical or important files touched

${criticalTouched.map((item) => `- ${item.classification}: ${item.path}`).join('\n') || '- none detected'}

## Repair queue preview

${(repair.queue || []).slice(0, 10).map((item) => `- ${item.priority || 'medium'}: ${item.subject || item.id}`).join('\n') || '- empty'}

## Reviewer notes

- Current code and tests remain the source of truth.
- Re-read source for suspect or low-confidence modules before behavior-sensitive merge.
- Confirm generated runtime artifacts are not staged unless intentionally tracked.
`;

  writeFileAtomicContained(outPath, md, outputRoot);
  const result = {
    schema_version: systemVersion(),
    generated_at: new Date().toISOString(),
    workspace,
    branch: changed.git.branch,
    head_sha: changed.git.head_sha,
    changed_source_files: changed.source,
    changed_curated_knowledge_files: changed.knowledge,
    doctor_score: doctor.quality_score ?? null,
    trust_buckets: trust.modules || {},
    repair_queue_items: (repair.queue || []).length,
    critical_files_touched: criticalTouched,
    pr_summary: outPath
  };
  appendTeamEvent({
    teamRoot,
    repoId: found.repoId,
    workspaceId,
    agentId: workspace.agentId,
    branch: changed.git.branch,
    headSha: changed.git.head_sha,
    targetRoot: workspace.targetRoot
  }, 'pr_summary_generated', { pr_summary: outPath });
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(JSON.stringify({ ok: false, error: error.message }, null, 2)); process.exit(1); }
}

module.exports = main;
