'use strict';

// can both add files without duplicating the bookkeeping logic.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function sha256File(absPath) {
  return crypto.createHash('sha256').update(fs.readFileSync(absPath)).digest('hex');
}

function normalizeRelative(relPath) {
  return String(relPath || '').replace(/\\/g, '/').replace(/^\.?\//, '');
}

function buildTrackedIndex(freshness) {
  const tracked = freshness.tracked_files || [];
  return new Map(tracked.map((entry) => [entry.path, entry]));
}

// Adds an entry to freshness.tracked_files unless already present.
// Returns true if newly added, false if already there.
function addTracked(freshness, repoRoot, relativePath, options = {}) {
  freshness.tracked_files = freshness.tracked_files || [];
  const index = options.index || buildTrackedIndex(freshness);
  const rel = normalizeRelative(relativePath);
  if (index.has(rel)) return false;
  const abs = path.join(repoRoot, rel);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return false;
  const entry = {
    path: rel,
    sha256: sha256File(abs),
    last_scanned_at: options.timestamp || new Date().toISOString(),
    status: 'clean',
    first_seen_by: options.agentId || null,
    first_seen_at: options.timestamp || new Date().toISOString(),
    auto_tracked: options.autoTracked || false,
    source: options.source || 'ingest'
  };
  freshness.tracked_files.push(entry);
  index.set(rel, entry);
  return true;
}

// Auto-track all critical/important files from file_criticality.json,
// capped by limit. Returns { added, considered, capped, limit }.
function autoTrackFromCriticality(freshness, repoRoot, fileCriticality, opts = {}) {
  const limit = Number.isFinite(opts.limit) && opts.limit >= 0 ? opts.limit : 1000;
  const scopes = new Set(opts.scopes || ['critical', 'important']);
  const index = buildTrackedIndex(freshness);
  const candidates = (fileCriticality.files || [])
    .filter((entry) => entry && entry.path && scopes.has(entry.classification));
  const considered = candidates.length;
  let added = 0;
  let capped = false;
  for (const candidate of candidates) {
    if (freshness.tracked_files.length >= limit) {
      capped = true;
      break;
    }
    const newlyAdded = addTracked(freshness, repoRoot, candidate.path, {
      index,
      timestamp: opts.timestamp,
      agentId: opts.agentId,
      autoTracked: true,
      source: opts.source || 'auto_track_criticality'
    });
    if (newlyAdded) added += 1;
  }
  return { added, considered, capped, limit, tracked_total: freshness.tracked_files.length };
}

module.exports = {
  sha256File,
  normalizeRelative,
  buildTrackedIndex,
  addTracked,
  autoTrackFromCriticality
};
