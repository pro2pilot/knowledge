#!/usr/bin/env node
'use strict';

const path = require('path');
const { ensureDir, writeFileAtomic } = require('./lib/json-store');
const { resolveKnowledgeContext } = require('./lib/path-context');

const context = resolveKnowledgeContext();
const outDir = path.join(context.stateRoot, 'maintenance', 'graphs');

function main() {
  ensureDir(outDir);
  const graphs = {
    'knowledge-flow.mmd': `flowchart TD
  A[Agent task] --> B[Read routing bundle]
  B --> C{Trust bucket}
  C -->|trusted or near_trusted| D[Read module card]
  C -->|suspect or low_confidence| E[Re-read source and tests]
  D --> F[Targeted source check]
  E --> F
  F --> G[Update evidence, modules, wiki]
  G --> H[Run release flow]
`,
    'maintenance-flow.mmd': `flowchart LR
  scan[sync-tracked --scan] --> graph[build-wiki-graph]
  graph --> lint[lint-wiki]
  lint --> external[external-memory-status]
  external --> route[build-routing-bundle]
  route --> index[build-search-index]
  index --> inspector[build-visual-inspector]
  inspector --> doctor[doctor]
  doctor --> pr[generate-pr-summary]
`,
    'agent-handoff-flow.mmd': `sequenceDiagram
  participant A as Agent A
  participant K as .knowledge
  participant B as Agent B
  A->>K: update source/evidence/modules
  A->>K: run flow release
  A->>K: write handoff and PR summary
  B->>K: read routing bundle
  B->>K: inspect trust and handoff
  B->>B: re-read code where required
`,
    'team-mode-topology.mmd': `flowchart TB
  Main[main worktree curated .knowledge]
  W1[codex-task-1 worktree]
  W2[claude-task-2 worktree]
  Team[team root registry]
  S1[workspace state codex-task-1]
  S2[workspace state claude-task-2]
  L[locks]
  E[events]
  Main --> W1
  Main --> W2
  W1 --> S1
  W2 --> S2
  S1 --> Team
  S2 --> Team
  Team --> L
  Team --> E
`,
    'pr-impact-flow.mmd': `flowchart TD
  A[Changed files] --> B[Map to modules]
  B --> C[Overlay trust buckets]
  C --> D[Overlay freshness]
  D --> E[Check critical files]
  E --> F[Repair queue delta]
  F --> G[Reviewer notes]
  G --> H[PR summary markdown]
`,
    'source-of-truth-order.mmd': `flowchart TD
  A[Current source code] --> B[Current tests]
  B --> C[Evidence JSON]
  C --> D[Module cards]
  D --> E[Decisions]
  E --> F[Wiki]
  F --> G[Sessions]
  G --> H[External memory]
  H -. advisory only .-> A
`,
    'external-memory-bridge.mmd': `flowchart LR
  Mem0[Mem0 OSS recommended optional provider] --> Registry[memory provider registry]
  Pinecone[Pinecone optional vector/cloud retrieval] --> Registry
  Legacy[Legacy Claude MEM artifacts] -. advisory legacy .-> Registry
  Registry --> Status[memory-provider status]
  Status --> Inspector[Memory Providers panel]
  Status -. advisory only .-> Knowledge[.knowledge reports]
  Code[Current code] --> Trust[Trust]
  Tests[Current tests] --> Trust
  Knowledge --> Trust
`,
    'inspector-ui-map.mmd': `flowchart LR
  Home[Readiness] --> Routing[Routing bundle]
  Home --> Trust[Trust buckets]
  Home --> Repair[Repair queue]
  Home --> Stale[Stale items]
  Home --> Critical[Critical files]
  Home --> Search[Search preview]
  Home --> PR[PR summary]
  Home --> Team[Team mode]
  Home --> Memory[Memory providers]
  Home --> Commands[Command Center]
`
  };
  for (const [name, content] of Object.entries(graphs)) writeFileAtomic(path.join(outDir, name), content);
  const written = Object.keys(graphs).map((name) => context.mode === 'repo' ? `.knowledge/maintenance/graphs/${name}` : path.join(outDir, name));
  const result = { schema_version: '3.2.1', mode: context.mode, written };
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) main();
module.exports = main;
