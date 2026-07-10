#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const systemVersion = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version || '3.2.11';

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

  assert(graph.schema_version === systemVersion, `graph schema_version must be ${systemVersion}`);
  assert(graph.view === 'free_core_trust_graph', 'graph view must be free_core_trust_graph');
  assert(graph.source_truth_node_count >= 8, 'source-of-truth order nodes are missing');
  assert(graph.module_node_count >= 1, 'module graph nodes are missing');
  assert(
    graph.node_count >= graph.source_truth_node_count + graph.module_node_count,
    `graph node count is inconsistent: total=${graph.node_count}, truth=${graph.source_truth_node_count}, modules=${graph.module_node_count}`
  );
  assert(graph.edge_count > 0, 'graph should have useful relations');
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
    'data-graph-shelf="free-core"',
    'data-graph-toggle="free-core"',
    'data-graph-node="true"',
    'graph-hit-target',
    'data-graph-detail="true"',
    'data-graph-detail-json',
    'Trust Graph',
    'graph-toggle-arrow',
    'Source-of-truth order',
    'Incoming links',
    'Why trust is this',
    'Evidence / tests / code',
    'advisory only, verify against code/tests/evidence',
    'inspectorFileHref(action)',
    '/api/files/open?path=',
    'data-open-path',
    'class="edge routes bundled"',
    'Graph diagnostics',
    'Trust order:',
    'edge-swatch outranks'
  ]) {
    assert(html.includes(needle), `Inspector graph UI missing ${needle}`);
  }
  assert(html.includes('.graph-node .label{pointer-events:all;cursor:pointer}'), 'Inspector graph labels should be clickable.');
  assert(!html.includes('Free Core Trust Graph'), 'Inspector graph title should be Trust Graph.');
  assert(!html.includes('class="graph-link"'), 'Inspector graph nodes must not navigate to raw pages');

  console.log(JSON.stringify({
    schema_version: systemVersion,
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
      ,'Inspector graph is collapsible and uses in-page node drilldown'
    ]
  }, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
