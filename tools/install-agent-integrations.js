#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, writeFileAtomic, withLock } = require('./lib/json-store');

const MANAGED_START = '<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->';
const MANAGED_END = '<!-- END DOT-KNOWLEDGE MANAGED BLOCK -->';

function upsertManagedBlock(filePath, blockBody, options = {}) {
  ensureDir(path.dirname(filePath));
  const block = `${MANAGED_START}\n${blockBody.trim()}\n${MANAGED_END}\n`;
  if (!fs.existsSync(filePath)) {
    writeFileAtomic(filePath, options.prefix ? `${options.prefix.trim()}\n\n${block}` : block);
    return 'created';
  }
  const current = fs.readFileSync(filePath, 'utf8');
  const regex = new RegExp(`${MANAGED_START}[\\s\\S]*?${MANAGED_END}\\n?`, 'm');
  if (regex.test(current)) {
    writeFileAtomic(filePath, current.replace(regex, block));
    return 'updated';
  }
  writeFileAtomic(filePath, `${current.replace(/\s*$/, '')}\n\n${block}`);
  return 'appended';
}

function copyDir(srcDir, dstDir) {
  const written = [];
  if (!fs.existsSync(srcDir)) return written;
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const src = path.join(srcDir, entry.name);
    const dst = path.join(dstDir, entry.name);
    if (entry.isDirectory()) written.push(...copyDir(src, dst));
    else if (entry.isFile()) {
      ensureDir(path.dirname(dst));
      fs.copyFileSync(src, dst);
      written.push(dst);
    }
  }
  return written;
}

function updatePackageJson(repoRoot) {
  const packagePath = path.join(repoRoot, 'package.json');
  if (!fs.existsSync(packagePath)) return { status: 'not_found' };
  const pkg = readJson(packagePath);
  pkg.scripts = pkg.scripts || {};
  const scripts = {
    'kb:ingest': 'node .knowledge/tools/ingest-existing-project.js --merge',
    'kb:sync': 'node .knowledge/tools/sync-tracked.js',
    'kb:scan': 'node .knowledge/tools/sync-tracked.js --scan',
    'kb:discover': 'node .knowledge/tools/sync-tracked.js --scan --discover',
    'kb:watch': 'node .knowledge/tools/watch-maintenance.js',
    'kb:hooks': 'node .knowledge/tools/install-git-hooks.js',
    'kb:integrations': 'node .knowledge/tools/install-agent-integrations.js',
    'kb:routing': 'node .knowledge/tools/build-routing-bundle.js',
    'kb:index': 'node .knowledge/tools/build-search-index.js',
    'kb:search': 'node .knowledge/tools/search-knowledge.js',
    'kb:doctor': 'node .knowledge/tools/doctor.js',
    'kb:wikigraph': 'node .knowledge/tools/build-wiki-graph.js',
    'kb:lint-wiki': 'node .knowledge/tools/lint-wiki.js',
    'kb:external:status': 'node .knowledge/tools/external-memory-status.js',
    'kb:metrics': 'node .knowledge/tools/collect-metrics.js',
    'kb:evaluate': 'node .knowledge/tools/evaluation-harness.js',
    'kb:pr-summary': 'node .knowledge/tools/generate-pr-summary.js',
    'kb:inspector': 'node .knowledge/tools/serve-inspector.js',
    'kb:flow': 'node .knowledge/tools/flow.js release',
    'kb:smoke': 'node .knowledge/tools/watch-smoke.js'
  };
  const changed = [];
  for (const [name, value] of Object.entries(scripts)) {
    if (pkg.scripts[name] !== value) {
      pkg.scripts[name] = value;
      changed.push(name);
    }
  }
  writeJsonAtomic(packagePath, pkg);
  return { status: changed.length ? 'updated' : 'unchanged', changed };
}

function installAgentIntegrations(options = {}) {
  const knowledgeRoot = path.resolve(__dirname, '..');
  const repoRoot = path.basename(knowledgeRoot) === '.knowledge' ? path.dirname(knowledgeRoot) : process.cwd();
  const kitRoot = knowledgeRoot;
  const lockDir = path.join(knowledgeRoot, '.lock');
  return withLock(lockDir, () => {
    const installed = {};
    const agentsBlock = `# .knowledge trust/routing layer

Use \`.knowledge/\` as the first trust/routing layer for this repository.

## First file to read

1. \`.knowledge/maintenance/routing_bundle.json\`

Then read only what the bundle says is relevant:

- \`.knowledge/project_index.json\`
- \`.knowledge/maintenance/trust_report.json\`
- \`.knowledge/maintenance/handoff_summary.json\`
- \`.knowledge/wiki/index.md\`
- relevant \`.knowledge/modules/*.json\`
- relevant source files and tests

## Source-of-truth order

1. Current code
2. Current tests
3. \`.knowledge/evidence/*.json\`
4. \`.knowledge/modules/*.json\`
5. \`.knowledge/decisions.json\`
6. \`.knowledge/wiki/*.md\`
7. \`.knowledge/sessions/*\`

Code beats summaries. Tests beat prose. Wiki is advisory unless backed by evidence and current code/tests.

## Trust rules

- \`trusted\`: usable for routing and limited planning; re-read code before critical behavior edits.
- \`near_trusted\`: usable after targeted code checks.
- \`routing_trusted\`: use only to choose files, modules, and boundaries.
- \`advisory_only\`: context only; never source of truth.
- \`suspect\`, \`needs_recheck\`, \`low_confidence\`: re-read source code before behavior claims or edits.

## Maintenance

After significant changes, run:

\`node .knowledge/tools/sync-tracked.js\`

When new files, wiki pages, or module summaries changed, also run:

\`node .knowledge/tools/build-routing-bundle.js\`
\`node .knowledge/tools/build-search-index.js\`
\`node .knowledge/tools/doctor.js\`

For concurrent agent work, set a stable \`KNOWLEDGE_AGENT_ID\` and use separate git worktrees/branches.`;

    installed.agents_md = upsertManagedBlock(path.join(repoRoot, 'AGENTS.md'), agentsBlock);

    const claudeBlock = `@AGENTS.md

# Claude Code notes

Use the same \`.knowledge/\` trust rules as \`AGENTS.md\`. Prefer installed skills under \`.claude/skills/\` for audit, routing bundle refresh, search index, doctor checks, sync, handoff, ingest, and concurrent-agent checks.`;
    const claudePath = path.join(repoRoot, 'CLAUDE.md');
    if (!fs.existsSync(claudePath)) {
      writeFileAtomic(claudePath, `${claudeBlock}\n`);
      installed.claude_md = 'created';
    } else {
      const current = fs.readFileSync(claudePath, 'utf8');
      installed.claude_md = current.includes('@AGENTS.md') ? 'unchanged' : upsertManagedBlock(claudePath, claudeBlock);
    }

    installed.codex_skills = copyDir(path.join(kitRoot, 'agent-integrations', 'codex', 'skills'), path.join(repoRoot, '.agents', 'skills')).length;
    installed.claude_skills = copyDir(path.join(kitRoot, 'agent-integrations', 'claude', 'skills'), path.join(repoRoot, '.claude', 'skills')).length;
    installed.opencode_commands = copyDir(path.join(kitRoot, 'agent-integrations', 'opencode', 'commands'), path.join(repoRoot, '.opencode', 'commands')).length;
    if (options.updatePackageScripts !== false) installed.package_json = updatePackageJson(repoRoot);
    return installed;
  });
}

module.exports = installAgentIntegrations;

if (require.main === module) {
  try {
    console.log(JSON.stringify(installAgentIntegrations({ updatePackageScripts: !process.argv.includes('--no-package-scripts') }), null, 2));
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}
