'use strict';

const STATUS_RANK = Object.freeze({
  healthy: 1,
  usable_with_warnings: 2,
  structurally_broken: 3
});

function statusValues(wikiLint = {}, wikiGraph = {}) {
  return [
    wikiLint.status,
    wikiLint.structural_status,
    wikiLint.graph?.structural_status,
    wikiGraph.status,
    wikiGraph.structural_status,
    wikiGraph.summary?.structural_status
  ]
    .map((value) => String(value || '').trim().toLowerCase())
    .filter(Boolean);
}

function canonicalWikiStatus(wikiLint = {}, wikiGraph = {}) {
  const brokenEdges = [
    wikiGraph.broken_edge_count,
    wikiGraph.summary?.broken_edges,
    Array.isArray(wikiGraph.broken_edges) ? wikiGraph.broken_edges.length : wikiGraph.broken_edges,
    wikiLint.graph?.broken_edges
  ];
  if (brokenEdges.some((value) => Number(value || 0) > 0)) {
    return 'structurally_broken';
  }

  const values = statusValues(wikiLint, wikiGraph);
  let selected = null;
  for (const value of values) {
    const normalized = Object.prototype.hasOwnProperty.call(STATUS_RANK, value)
      ? value
      : 'usable_with_warnings';
    if (!selected || STATUS_RANK[normalized] > STATUS_RANK[selected]) selected = normalized;
  }

  // Missing or unknown machine state must not silently downgrade routing or
  // health consumers to healthy.
  return selected || 'usable_with_warnings';
}

module.exports = {
  STATUS_RANK,
  canonicalWikiStatus,
  __test: {
    statusValues
  }
};
