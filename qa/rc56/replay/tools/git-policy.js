#!/usr/bin/env node
'use strict';

const policy = {
  status: 'ok',
  docs: '.knowledge/docs/git-policy.md',
  templates: {
    knowledge_gitignore: '.knowledge/templates/git-policy/.knowledge.gitignore',
    gitattributes_snippet: '.knowledge/templates/git-policy/gitattributes.snippet'
  },
  commit_by_default: [
    '.knowledge/README.md',
    '.knowledge/Quick-Start.md',
    '.knowledge/config.yaml',
    '.knowledge/modules/',
    '.knowledge/evidence/',
    '.knowledge/decisions.json',
    '.knowledge/glossary.json',
    '.knowledge/invariants/',
    '.knowledge/wiki/',
    '.knowledge/docs/',
    '.knowledge/templates/',
    '.knowledge/prompts/',
    '.knowledge/skills/',
    '.knowledge/commands/',
    '.knowledge/agent-integrations/'
  ],
  do_not_commit_by_default: [
    '.knowledge/.lock',
    '.knowledge/locks/',
    '.knowledge/.runtime/',
    '.knowledge/project_index.json',
    '.knowledge/freshness.json',
    '.knowledge/maintenance/install-backups/',
    '.knowledge/maintenance/install_check_report.json',
    '.knowledge/maintenance/update_system_files_report.json',
    '.knowledge/maintenance/update_status.json',
    '.knowledge/maintenance/flow-logs/',
    '.knowledge/maintenance/events/',
    '.knowledge/maintenance/hook_errors.log',
    '.knowledge/maintenance/watcher_*.log',
    '.knowledge/maintenance/wiki_lint_report.json',
    '.knowledge/maintenance/external_memory_status.json',
    '.knowledge/maintenance/secret_scan_report.json',
    '.knowledge/maintenance/sync_log.json',
    '.knowledge/maintenance/stale_items.json',
    '.knowledge/maintenance/repair_queue.json',
    '.knowledge/maintenance/repair_opportunities.json',
    '.knowledge/maintenance/repair_on_touch_telemetry.json',
    '.knowledge/maintenance/verification_receipts/',
    '.knowledge/maintenance/verification_executions/',
    '.knowledge/maintenance/dedicated_verification_receipts/',
    '.knowledge/maintenance/repair_sessions/',
    '.knowledge/maintenance/transactions/',
    '.knowledge/maintenance/integration-transactions/',
    '.knowledge/maintenance/automation_status.json',
    '.knowledge/maintenance/handoff_summary.json',
    '.knowledge/maintenance/graphs/',
    '.knowledge/search/index.json',
    '.knowledge/search/query_log.ndjson',
    '.knowledge/inspector/',
    '.knowledge/inspector/data.json',
    '.knowledge/inspector/status.json',
    '.knowledge/metrics/baseline.json',
    '.knowledge/metrics/README.md',
    '.knowledge/maps/wiki_graph.json',
    '.knowledge/maps/file_criticality.json',
    '.knowledge/maps/dependency_map.json',
    '.knowledge/maps/directory_map.json',
    '.knowledge/maps/entrypoints.json',
    '.knowledge/sessions/active_task.json',
    '.knowledge/sessions/active_tasks/',
    '.knowledge/evaluation/results/',
    '.knowledge/cache/',
    '.knowledge/.cache/',
    '.knowledge/.git/',
    '.knowledge/.github/',
    '*.tmp-*',
    '*.bak-*',
    '*.log',
    '*.zip'
  ],
  optional_team_policy: [
    '.knowledge/maintenance/routing_bundle.json',
    '.knowledge/maintenance/trust_report.json',
    '.knowledge/maintenance/quality_report.json',
    '.knowledge/maintenance/pr_summary.md',
    '.knowledge/maps/wiki_graph.json',
    '.knowledge/maps/file_criticality.json',
    '.knowledge/metrics/baseline.json'
  ]
};

function main() {
  console.log(JSON.stringify(policy, null, 2));
}

if (require.main === module) main();

module.exports = policy;
