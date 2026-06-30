#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs } = require('./lib/path-context');
const { detectGitContext } = require('./lib/git-context');
const { findWorkspace, appendTeamEvent } = require('./lib/team-store');
const { ensureDir, readJson, writeFileAtomic } = require('./lib/json-store');

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
  const found = findWorkspace(teamRoot, workspaceId);
  if (!found) throw new Error(`Workspace not found: ${workspaceId}`);
  const workspace = found.workspace;
  const stateRoot = workspace.stateRoot || path.join(teamRoot, 'repos', found.repoId, 'workspaces', workspaceId, 'state');
  ensureDir(path.join(stateRoot, 'maintenance'));

  const changed = listChangedFiles(workspace.targetRoot);
  const doctor = readJson(path.join(stateRoot, 'maintenance', 'quality_report.json'), {});
  const trust = readJson(path.join(stateRoot, 'maintenance', 'trust_report.json'), {});
  const repair = readJson(path.join(stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
  const critical = readJson(path.join(stateRoot, 'maps', 'file_criticality.json'), { files: [] });
  const criticalTouched = (critical.files || []).filter((item) => changed.source.includes(item.path) && ['critical', 'important'].includes(item.classification));
  const outPath = path.join(stateRoot, 'maintenance', 'team_pr_summary.md');

  const md = `# Team PR Summary

Workspace: ${workspace.workspaceId}
Agent: ${workspace.agentId}
Repo: ${workspace.repoId}
Branch: ${changed.git.branch || workspace.branch || 'unknown'}
Head: ${changed.git.head_sha || workspace.headSha || 'unknown'}

## Health

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

  writeFileAtomic(outPath, md);
  const result = {
    schema_version: '3.2.4',
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

