'use strict';

const fs = require('fs');
const path = require('path');

const RISKS = new Set(['read_only', 'local_write', 'network_or_provider', 'destructive', 'extension_locked']);
const RISK_REQUIRES_CONFIRMATION = new Set(['network_or_provider', 'destructive']);

const ACTIONS = [
  {
    id: 'doctor.run',
    label: 'Run Health Check',
    risk: 'read_only',
    command: ['tools/doctor.js', '--json'],
    description: 'Check local .knowledge health and quality reports.'
  },
  {
    id: 'flow.release',
    label: 'Run Release Flow',
    risk: 'local_write',
    command: ['tools/flow.js', 'release', '--no-color', '--json'],
    description: 'Refresh generated routing, trust, search, inspector, metrics and release reports.'
  },
  {
    id: 'inspector.rebuild',
    label: 'Rebuild Inspector',
    risk: 'local_write',
    command: ['tools/build-visual-inspector.js', '--json'],
    description: 'Rebuild the static Inspector fallback artifacts.'
  },
  {
    id: 'trust.restore.safe',
    label: 'Restore Trust',
    risk: 'local_write',
    command: ['tools/restore-trust.js', '--safe', '--json'],
    description: 'Safely refresh routing/search/trust/freshness/repair without changing source code.'
  },
  {
    id: 'pr.review.basic',
    label: 'Review Current Changes',
    risk: 'local_write',
    command: ['tools/generate-pr-summary.js', '--json'],
    description: 'Generate the local basic PR summary.'
  },
  {
    id: 'pr.impact.basic',
    label: 'Run Basic PR Impact',
    risk: 'local_write',
    command: ['tools/pr-impact.js', '--json'],
    description: 'Map changed files to modules, trust, freshness and policy warnings.'
  },
  {
    id: 'repair.queue.refresh',
    label: 'Refresh Repair Queue',
    risk: 'local_write',
    command: ['tools/doctor.js', '--json'],
    description: 'Refresh local health signals that feed the repair queue.'
  },
  {
    id: 'memory.status',
    label: 'Memory Provider Status',
    risk: 'read_only',
    command: ['tools/memory-provider.js', 'status-all', '--json'],
    description: 'Show advisory-only memory provider status.'
  },
  {
    id: 'team.status',
    label: 'Team Status',
    risk: 'read_only',
    command: ['tools/team-status.js', '--json'],
    description: 'Show active workspaces, locks and Safe Queue status.'
  },
  {
    id: 'agent.sessions.refresh',
    label: 'Refresh Agent Sessions',
    risk: 'read_only',
    command: ['tools/agent-session.js', 'report', '--json'],
    description: 'Read active agent sessions and recent activity reports.'
  },
  {
    id: 'queue.status',
    label: 'Queue Status',
    risk: 'read_only',
    command: ['tools/team-status.js', '--json'],
    description: 'Read Safe Queue lock and waiting state.'
  },
  {
    id: 'merge.readiness',
    label: 'Merge Readiness',
    risk: 'read_only',
    command: ['tools/worktree-status.js', '--json'],
    description: 'Check local worktree and merge-readiness signals.'
  },
  {
    id: 'evaluation.summary',
    label: 'Local Evaluation Summary',
    risk: 'local_write',
    command: ['tools/evaluation-harness.js'],
    description: 'Run the installed local evaluation harness and record deterministic repository evidence.'
  },
];

function normalizeAction(action) {
  if (!action || !action.id) throw new Error('Action id is required.');
  if (!RISKS.has(action.risk)) throw new Error(`Invalid action risk: ${action.id}`);
  return {
    timeout_ms: action.risk === 'read_only' ? 120000 : 300000,
    ...action
  };
}

const NORMALIZED = ACTIONS.map(normalizeAction);
const ACTION_MAP = new Map(NORMALIZED.map((action) => [action.id, action]));

function listActions() {
  return NORMALIZED.map((action) => ({
    id: action.id,
    label: action.label,
    risk: action.risk,
    description: action.description,
    required_entitlement: action.required_entitlement || null,
    command: action.command ? ['node', ...action.command].join(' ') : null
  }));
}

function getAction(id) {
  return ACTION_MAP.get(String(id || '')) || null;
}

function readJson(filePath, fallback) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return fallback; }
}

function loadEntitlements(knowledgeRoot, env = process.env) {
  const entitlementsPath = path.join(knowledgeRoot, 'extensions', 'entitlements.json');
  const licensePath = path.join(knowledgeRoot, 'extensions', 'license.json');
  const data = readJson(entitlementsPath, readJson(licensePath, {}));
  const devMode = env.KNOWLEDGE_EXTENSION_DEV_ENTITLEMENT === '1';
  const entitlements = Array.from(new Set([
    ...(Array.isArray(data.entitlements) ? data.entitlements : []),
    ...(devMode ? ['extension_base', 'repair_planner', 'policy_packs'] : [])
  ]));
  return {
    active: Boolean(devMode || data.active || data.plan),
    source: devMode ? 'dev_env' : data.source || (data.plan ? 'local_license' : 'free'),
    plan: data.plan || (devMode ? 'dev_extension' : 'free'),
    dev_mode: devMode,
    entitlements,
    expires_at: data.expires_at || null,
    offline_grace_until: data.offline_grace_until || null
  };
}

function canRunAction(action, entitlementState = {}) {
  if (!action) return { ok: false, reason: 'unknown_action' };
  if (action.risk === 'extension_locked') {
    const needed = action.required_entitlement || 'extension_base';
    if (!entitlementState.entitlements?.includes(needed)) {
      return { ok: false, reason: 'missing_entitlement', required_entitlement: needed };
    }
  }
  return { ok: true };
}

module.exports = {
  RISKS,
  RISK_REQUIRES_CONFIRMATION,
  listActions,
  getAction,
  loadEntitlements,
  canRunAction
};
