#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runNode(script, args = []) {
  const res = spawnSync(process.execPath, [path.join(root, script), ...args], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 30000
  });
  assert(res.status === 0, `${script} ${args.join(' ')} failed\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
  return res;
}

function readJson(relPath) {
  return JSON.parse(fs.readFileSync(path.join(root, relPath), 'utf8'));
}

function main() {
  runNode('tools/build-wiki-graph.js', ['--quiet']);
  const graph = readJson('maps/wiki_graph.json');

  assert(graph.schema_version === '3.2.4', 'graph schema_version must be 3.2.4');
  assert(graph.view === 'free_core_trust_graph', 'graph view must be free_core_trust_graph');
  assert(graph.node_count >= 12, `graph should have useful nodes, got ${graph.node_count}`);
  assert(graph.edge_count >= 12, `graph should have useful relations, got ${graph.edge_count}`);
  assert(graph.source_truth_node_count >= 8, 'source-of-truth order nodes are missing');
  assert(graph.module_node_count >= 1, 'module graph nodes are missing');
  assert((graph.nodes || []).some((node) => node.id === 'truth:code'), 'truth:code node missing');
  assert((graph.nodes || []).some((node) => node.id === 'truth:external-memory'), 'truth:external-memory node missing');
  assert((graph.nodes || []).some((node) => node.id === 'module:root'), 'module:root node missing');
  assert((graph.edges || []).some((edge) => edge.from === 'truth:modules' && edge.to === 'module:root' && edge.type === 'routes'), 'module routing edge missing');
  assert((graph.edges || []).some((edge) => edge.type === 'advisory'), 'advisory boundary edge missing');
  assert(!JSON.stringify(graph).toLowerCase().includes('graphiti'), 'free-core graph must not include Graphiti implementation nodes');
  assert(!JSON.stringify(graph).toLowerCase().includes('zep'), 'free-core graph must not include Zep implementation nodes');

  runNode('tools/build-visual-inspector.js', ['--quiet']);
  const html = fs.readFileSync(path.join(root, 'inspector', 'index.html'), 'utf8');
  for (const needle of [
    'data-free-core-graph="true"',
    'Free Core Trust Graph',
    'Source-of-truth order',
    'Graph diagnostics',
    'Trust order:',
    'edge-swatch outranks'
  ]) {
    assert(html.includes(needle), `Inspector graph UI missing ${needle}`);
  }

  console.log(JSON.stringify({
    schema_version: '3.2.4',
    status: 'pass',
    graph: {
      nodes: graph.node_count,
      edges: graph.edge_count,
      broken_edges: graph.broken_edge_count,
      orphan_pages: graph.orphan_page_count,
      readiness: graph.readiness
    },
    checks: [
      'source-of-truth nodes exist',
      'module routing edge exists',
      'graph has nonzero useful relations',
      'advisory boundary is visible',
      'free graph excludes Graphiti/Zep implementation nodes',
      'Inspector renders free-core graph UI'
    ]
  }, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
