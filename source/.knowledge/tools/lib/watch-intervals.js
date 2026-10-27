'use strict';

// Validate before process admission as well as at the storage-worker boundary.
module.exports = function watchIntervals(env) {
  const intervals = {
    debounceMs: Number(env.KNOWLEDGE_WATCH_DEBOUNCE_MS || 1500),
    watcherStaleMs: Number(env.KNOWLEDGE_WATCHER_STALE_MS || 120000),
    heartbeatMs: Number(env.KNOWLEDGE_WATCH_HEARTBEAT_MS || 30000)
  };
  for (const [name, value] of Object.entries(intervals)) {
    if (!Number.isSafeInteger(value) || value <= 0 || value > 2147483647) {
      throw Object.assign(new Error(`${name} must be a positive timer interval`), { code: 'watcher_timing_invalid' });
    }
  }
  return intervals;
};
