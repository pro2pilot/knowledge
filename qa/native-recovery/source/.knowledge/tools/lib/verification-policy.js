'use strict';

// Pure timing policy and progress state. Neither stdout nor a heartbeat is a
// semantic checkpoint. All native timers share monotonic timestamps; timers
// longer than the platform's signed 32-bit range are rearmed in chunks.
const defaults = require('../../verification-policy.json');
const { copyInertData } = require('./inert-data');
const MAX_WORK_MS = 600000 * 100000;
const MAX_CLEANUP_MS = 3600000;
const TIMER_MAX_MS = 2147483647;
function invalid() {
  throw Object.assign(new Error('Invalid native verification timing policy'), { code: 'verification_policy_invalid' });
}
function duration(value, max, zero = false) {
  if (!Number.isSafeInteger(value) || value < (zero ? 0 : 1) || value > max) invalid();
  return value;
}
function resolvePolicy(override, legacyBudget) {
  const value = override === undefined ? {} : copyInertData(override);
  if (!value || Array.isArray(value) || typeof value !== 'object') invalid();
  if (Object.keys(value).some(k => !['profile', 'work_budget_ms', 'no_progress_ms', 'cleanup_budget_ms'].includes(k))) invalid();
  if (Object.values(value).some(v => v === null)) invalid();
  const profile = value.profile === undefined ? defaults.default_profile : value.profile;
  if (typeof profile !== 'string' || !Object.prototype.hasOwnProperty.call(defaults.profiles, profile)) invalid();
  const baseline = defaults.profiles[profile];
  // Existing callers retain their explicitly calculated batch budget. An
  // explicitly chosen profile supplies the budget when no override is given.
  const work = value.work_budget_ms ?? (value.profile === undefined && legacyBudget !== undefined ? legacyBudget : baseline.work_budget_ms);
  return Object.freeze({
    schema_version: defaults.schema_version, profile,
    work_budget_ms: duration(work, MAX_WORK_MS),
    no_progress_ms: duration(value.no_progress_ms ?? baseline.no_progress_ms, MAX_WORK_MS, true),
    cleanup_budget_ms: duration(value.cleanup_budget_ms ?? baseline.cleanup_budget_ms, MAX_CLEANUP_MS),
    automatic_work_budget_extension: false, command_progress_signal: 'unavailable',
    control_poll_ms: defaults.control_poll_ms
  });
}
function timerDelay(milliseconds) {
  if (!Number.isFinite(milliseconds)) invalid();
  return Math.max(1, Math.min(TIMER_MAX_MS, Math.ceil(milliseconds)));
}
function createProgress(policy, startedNs) {
  let lastNs = startedNs, phase = 'preparation', ordinal = -1, rank = -1, committed = 0;
  let signalAvailable = true;
  const executions = new Set();
  const ranks = { test_setup: 0, command: 1, finalization: 2, receipt_commit: 3 };
  return {
    advance(event, nowNs) {
      if (!event || nowNs < lastNs) return false;
      if (event.type === 'phase' && Number.isSafeInteger(event.ordinal) && event.ordinal >= 0 &&
          Object.prototype.hasOwnProperty.call(ranks, event.phase)) {
        const nextRank = ranks[event.phase];
        if (event.ordinal !== committed || event.ordinal < ordinal ||
            (event.ordinal === ordinal ? nextRank !== rank + 1 : nextRank !== 0)) return false;
        ordinal = event.ordinal; rank = nextRank; phase = event.phase;
        // A silent command has no trusted item/checkpoint channel. Its work
        // budget is enforced, but silence is never classified as a hang.
        signalAvailable = phase !== 'command';
      } else if (event.type === 'committed' && event.ordinal === committed &&
          event.ordinal === ordinal && rank === ranks.receipt_commit &&
          /^KVE-[a-f0-9]{64}$/.test(event.execution_id || '') && !executions.has(event.execution_id)) {
        executions.add(event.execution_id);
        committed++; phase = 'between_tests'; signalAvailable = true;
      } else return false;
      lastNs = nowNs;
      return true;
    },
    snapshot(nowNs) {
      return { phase, committed, last_meaningful_progress_elapsed_ms: Number(lastNs - startedNs) / 1e6,
        since_meaningful_progress_ms: Number(nowNs - lastNs) / 1e6,
        progress_signal_available: signalAvailable };
    },
    isStalled(nowNs) {
      return signalAvailable && policy.no_progress_ms > 0 &&
        nowNs - lastNs >= BigInt(policy.no_progress_ms) * 1000000n;
    }
  };
}
module.exports = { resolvePolicy, timerDelay, createProgress, MAX_WORK_MS, MAX_CLEANUP_MS };
