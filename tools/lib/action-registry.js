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
  const currentRoot = path.join(knowledgeRoot, 'extensions');
  const legacyRoot = path.join(knowledgeRoot, 'pro');
  const stateRoot = ['entitlements.json', 'license.json'].some((file) => fs.existsSync(path.join(currentRoot, file)))
    ? currentRoot : legacyRoot;
  const record = (name) => {
    const file = path.join(stateRoot, name);
    if (!fs.existsSync(file)) return { value: {}, valid: true };
    const value = readJson(file, null);
    return { value: value && typeof value === 'object' && !Array.isArray(value) ? value : {},
      valid: Boolean(value && typeof value === 'object' && !Array.isArray(value)) };
  };
  const license = record('license.json');
  const grant = record('entitlements.json');
  const data = { ...license.value, ...grant.value };
  const devMode = env.KNOWLEDGE_EXTENSION_DEV_ENTITLEMENT === '1';
  const declaredTimes = [data.expires_at, data.offline_grace_until].filter((value) => value !== undefined && value !== null);
  const validTimes = declaredTimes.every((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)));
  const deadline = declaredTimes.length && validTimes ? Math.max(...declaredTimes.map(Date.parse)) : null;
  const localActive = license.valid && grant.valid && validTimes && (deadline === null || deadline > Date.now()) &&
    data.active !== false && !['inactive', 'expired', 'revoked', 'deactivated'].includes(data.status) &&
    (data.active === true || data.status === 'active' || (typeof data.plan === 'string' && data.plan !== '' && data.plan !== 'free'));
  const localEntitlements = localActive && Array.isArray(data.entitlements) ? data.entitlements.filter((item) => typeof item === 'string' && item.length > 0) : [];
  const entitlements = Array.from(new Set([
    ...localEntitlements,
    ...(localEntitlements.includes('pro_base') ? ['extension_base'] : []),
    ...(devMode ? ['extension_base', 'repair_planner', 'policy_packs'] : [])
  ]));
  return {
    active: Boolean(devMode || localActive),
    source: devMode ? 'dev_env' : data.source || (data.plan ? 'local_license' : 'free'),
    plan: data.plan || (devMode ? 'dev_extension' : 'free'),
    dev_mode: devMode,
    entitlements,
    expires_at: data.expires_at || null,
    offline_grace_until: data.offline_grace_until || null,
    ...(license.valid && grant.valid && validTimes ? {} : { reason: 'invalid_entitlement_metadata' }),
    ...(deadline !== null && deadline <= Date.now() ? { reason: 'entitlement_expired' } : {})
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
