#!/usr/bin/env node
'use strict';
const fs=require('fs'); const path=require('path'); const {ensureDir,writeFileAtomic}=require('./lib/json-store');
const knowledgeRoot=path.resolve(__dirname,'..');
const outDir=path.join(knowledgeRoot,'maintenance','graphs');
function main(){ ensureDir(outDir); const graphs={
'knowledge-flow.mmd':`flowchart TD\n  A[Agent Task] --> B[Read routing_bundle.json]\n  B --> C{Trust status?}\n  C -->|trusted/near| D[Read relevant module card]\n  C -->|suspect/low| E[Mandatory source + test recheck]\n  D --> F[Targeted source read]\n  E --> F\n  F --> G[Update evidence/modules/wiki if verified]\n  G --> H[sync -> graph -> lint -> route -> index -> doctor]\n`,
'maintenance-flow.mmd':`flowchart LR\n  scan[sync-tracked --scan] --> graph[build-wiki-graph]\n  graph --> lint[lint-wiki]\n  lint --> external[external-memory-status]\n  external --> route[build-routing-bundle]\n  route --> index[build-search-index]\n  index --> doctor[doctor]\n  doctor --> pr[generate-pr-summary]\n`,
'agent-handoff-flow.mmd':`sequenceDiagram\n  participant A as Agent A\n  participant K as .knowledge\n  participant B as Agent B\n  A->>K: update task/evidence/modules\n  A->>K: run sync + doctor\n  A->>K: write handoff_summary\n  B->>K: read routing_bundle\n  B->>K: inspect trust_report + handoff\n  B->>B: re-read code where required\n`
}; for(const [name,content] of Object.entries(graphs)) writeFileAtomic(path.join(outDir,name),content); console.log(JSON.stringify({written:Object.keys(graphs).map(n=>`.knowledge/maintenance/graphs/${n}`)},null,2));}
if(require.main===module) main();
