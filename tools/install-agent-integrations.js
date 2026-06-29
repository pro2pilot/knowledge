#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { ensureDir, readJson, writeJsonAtomic, writeFileAtomic, withLock } = require('./lib/json-store');
const { resolveKnowledgeContext, contextEnv, parseCliArgs } = require('./lib/path-context');

const LEGACY_MANAGED_MARKER = ['KNOWLEDGE', 'KIT'].join('-');
const MANAGED_MARKERS = ['DOT-KNOWLEDGE', LEGACY_MANAGED_MARKER];
const MANAGED_START = '<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->';
const MANAGED_END = '<!-- END DOT-KNOWLEDGE MANAGED BLOCK -->';

const RUNTIME_ALIASES = {
  agents: 'codex',
  codex: 'codex',
  'codex-cli': 'codex',
  claude: 'claude',
  'claude-code': 'claude',
  anthropic: 'claude',
  opencode: 'opencode',
  'open-code': 'opencode',
  openclaw: 'openclaw',
  'open-claw': 'openclaw',
  'openclaw-cli': 'openclaw',
  hermes: 'hermes',
  'hermes-cli': 'hermes',
  gemini: 'gemini',
  'gemini-cli': 'gemini',
  copilot: 'copilot',
  'github-copilot': 'copilot',
  devin: 'devin',
  windsurf: 'windsurf',
  cascade: 'windsurf',
  'windsurf-cascade': 'windsurf',
  continue: 'continue',
  'continue-dev': 'continue',
  roo: 'roo',
  'roo-code': 'roo',
  aider: 'aider'
};

function normalizeRuntime(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return RUNTIME_ALIASES[normalized] || null;
}

function supportedRuntimeIds() {
  return ['codex', 'claude', 'opencode', 'openclaw', 'hermes', 'gemini', 'copilot', 'devin', 'windsurf', 'continue', 'roo', 'aider'];
}

function runtimeCommands() {
  return supportedRuntimeIds().map((id) => `node .knowledge/tools/install-agent-integrations.js --runtime ${id}`);
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function htmlManagedBlockRegex() {
  const families = MANAGED_MARKERS.map(escapeRegex).join('|');
  return new RegExp(`<!-- BEGIN (?:${families}) MANAGED BLOCK -->[\\s\\S]*?<!-- END (?:${families}) MANAGED BLOCK -->\\n?`, 'g');
}

function hashManagedBlockRegex() {
  const families = MANAGED_MARKERS.map(escapeRegex).join('|');
  return new RegExp(`# BEGIN (?:${families}) MANAGED BLOCK[\\s\\S]*?# END (?:${families}) MANAGED BLOCK\\n?`, 'g');
}

function replaceManagedBlocks(current, block, regex) {
  let replaced = false;
  let count = 0;
  const next = current.replace(regex, () => {
    count += 1;
    if (replaced) return '';
    replaced = true;
    return block;
  });
  return { next, count };
}

function upsertManagedBlock(filePath, blockBody, options = {}) {
  ensureDir(path.dirname(filePath));
  const block = `${MANAGED_START}\n${blockBody.trim()}\n${MANAGED_END}\n`;
  if (!fs.existsSync(filePath)) {
    writeFileAtomic(filePath, options.prefix ? `${options.prefix.trim()}\n\n${block}` : block);
    return 'created';
  }
  const current = fs.readFileSync(filePath, 'utf8');
  const replaced = replaceManagedBlocks(current, block, htmlManagedBlockRegex());
  if (replaced.count > 0) {
    writeFileAtomic(filePath, replaced.next);
    return replaced.count > 1 ? 'deduplicated' : 'updated';
  }
  writeFileAtomic(filePath, `${current.replace(/\s*$/, '')}\n\n${block}`);
  return 'appended';
}

function upsertHashManagedBlock(filePath, blockBody, options = {}) {
  ensureDir(path.dirname(filePath));
  const start = '# BEGIN DOT-KNOWLEDGE MANAGED BLOCK';
  const end = '# END DOT-KNOWLEDGE MANAGED BLOCK';
  const block = `${start}\n${blockBody.trim()}\n${end}\n`;
  if (!fs.existsSync(filePath)) {
    writeFileAtomic(filePath, options.prefix ? `${options.prefix.trim()}\n\n${block}` : block);
    return 'created';
  }
  const current = fs.readFileSync(filePath, 'utf8');
  const replaced = replaceManagedBlocks(current, block, hashManagedBlockRegex());
  if (replaced.count > 0) {
    writeFileAtomic(filePath, replaced.next);
    return replaced.count > 1 ? 'deduplicated' : 'updated';
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

function readTemplate(kitRoot, relPath, fallback) {
  const templatePath = path.join(kitRoot, 'agent-integrations', relPath);
  if (!fs.existsSync(templatePath)) return fallback;
  return fs.readFileSync(templatePath, 'utf8');
}

function sharedTemplate(kitRoot, name, fallback) {
  return readTemplate(kitRoot, path.join('_shared', name), fallback);
}

function renderTemplate(kitRoot, relPath, fallback, replacements = {}) {
  let rendered = readTemplate(kitRoot, relPath, fallback);
  const common = {
    TRUST_ROUTING: sharedTemplate(kitRoot, 'trust-routing.md', trustRoutingBlock()),
    FINAL_REPORT_CONTRACT: sharedTemplate(kitRoot, 'final-report-contract.md', finalReportContractLines().join('\n')),
    ...replacements
  };
  for (const [key, value] of Object.entries(common)) {
    rendered = rendered.replace(new RegExp(`{{${escapeRegex(key)}}}`, 'g'), String(value).trim());
  }
  return rendered;
}

function upsertGitAttributes(repoRoot, relPaths) {
  const unique = Array.from(new Set(relPaths.map((item) => String(item || '').trim()).filter(Boolean))).sort();
  const body = [
    '# .knowledge installed integration files',
    '.gitattributes text eol=lf',
    ...unique.map((item) => `${item} text eol=lf`)
  ].join('\n');
  return upsertHashManagedBlock(path.join(repoRoot, '.gitattributes'), body);
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
    'kb:install-check': 'node .knowledge/tools/install-check.js --json',
    'kb:update-system': 'node .knowledge/tools/update-system-files.js',
    'kb:update-system:verify': 'node .knowledge/tools/update-system-files.js --verify-upgrade --json',
    'kb:git-policy': 'node .knowledge/tools/git-policy.js --json',
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
    'kb:inspector': 'node .knowledge/inspector.js',
    'kb:flow': 'node .knowledge/tools/flow.js release',
    'kb:smoke': 'node .knowledge/tools/watch-smoke.js',
    'kb:team:init': 'node .knowledge/tools/team-init.js --json',
    'kb:team:register': 'node .knowledge/tools/workspace-register.js --json',
    'kb:team:status': 'node .knowledge/tools/team-status.js --json',
    'kb:team:unregister': 'node .knowledge/tools/workspace-unregister.js --json',
    'kb:worktree-status': 'node .knowledge/tools/worktree-status.js --json',
    'kb:team:pr-summary': 'node .knowledge/tools/team-pr-summary.js --json'
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

function finalReportContractLines() {
  return [
    '## Final report after meaningful work',
    '',
    'After meaningful work or before handoff, run:',
    '',
    '`node .knowledge/tools/flow.js release`',
    '',
    'Then report:',
    '',
    '- doctor score/status;',
    '- wiki lint score/status;',
    '- suspect or low-confidence modules;',
    '- repair queue items;',
    '- routing bundle path;',
    '- PR summary path;',
    '- metrics path;',
    '- estimated tokens saved and percent saved when `.knowledge/metrics/baseline.json` contains routing metrics;',
    '- an explicit note when metrics are unavailable or were not regenerated in this run.'
  ];
}

function trustRoutingBlock() {
  return `Use \`.knowledge/\` as the first trust/routing layer for this repository.

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
\`node .knowledge/tools/doctor.js\``;
}

function commonAgentBlock(kitRoot, relPath, title) {
  const fallback = `# ${title}

{{TRUST_ROUTING}}

{{FINAL_REPORT_CONTRACT}}

For concurrent agent work, set a stable \`KNOWLEDGE_AGENT_ID\` and use separate git worktrees/branches.`;
  return renderTemplate(kitRoot, relPath, fallback);
}

function installMarkdownFile(repoRoot, kitRoot, targetRel, templateRel, title, installed, key) {
  const block = commonAgentBlock(kitRoot, templateRel, title);
  installed[key] = upsertManagedBlock(path.join(repoRoot, targetRel), block);
}

function installCodex(context, installed) {
  const repoRoot = context.targetRoot;
  const kitRoot = context.systemRoot;
  installMarkdownFile(repoRoot, kitRoot, 'AGENTS.md', path.join('codex', 'AGENTS.md'), '.knowledge trust/routing layer', installed, 'agents_md');
  installed.codex_skills = copyDir(path.join(kitRoot, 'agent-integrations', 'codex', 'skills'), path.join(repoRoot, '.agents', 'skills')).length;
}

function installClaude(context, installed) {
  const repoRoot = context.targetRoot;
  const kitRoot = context.systemRoot;
  const fallback = `# Claude Code .knowledge notes

{{TRUST_ROUTING}}

Prefer installed skills under \`.claude/skills/\` for audit, routing bundle refresh, search index, doctor checks, sync, handoff, ingest, concurrent-agent checks, metrics collection, and PR summary generation.

Do not omit routing or metrics outcomes from the final reply. If \`.knowledge/metrics/baseline.json\` is missing or stale, say so explicitly instead of silently skipping token-savings reporting.

{{FINAL_REPORT_CONTRACT}}

For concurrent agent work, set a stable \`KNOWLEDGE_AGENT_ID\` and use separate git worktrees/branches.`;
  const block = renderTemplate(kitRoot, path.join('claude', 'CLAUDE.md'), fallback);
  installed.claude_md = upsertManagedBlock(path.join(repoRoot, 'CLAUDE.md'), block);
  installed.claude_skills = copyDir(path.join(kitRoot, 'agent-integrations', 'claude', 'skills'), path.join(repoRoot, '.claude', 'skills')).length;
}

function installOpenCode(context, installed) {
  installed.opencode_commands = copyDir(
    path.join(context.systemRoot, 'agent-integrations', 'opencode', 'commands'),
    path.join(context.targetRoot, '.opencode', 'commands')
  ).length;
}

function installOpenClaw(context, installed) {
  const repoRoot = context.targetRoot;
  const kitRoot = context.systemRoot;
  installMarkdownFile(repoRoot, kitRoot, 'AGENTS.md', path.join('openclaw', 'AGENTS.md'), 'OpenClaw .knowledge instructions', installed, 'agents_md');
  installed.openclaw_skills = copyDir(path.join(kitRoot, 'agent-integrations', 'codex', 'skills'), path.join(repoRoot, '.agents', 'skills')).length;
}

function installHermes(context, installed) {
  installMarkdownFile(context.targetRoot, context.systemRoot, 'AGENTS.md', path.join('hermes', 'AGENTS.md'), 'Hermes .knowledge bridge', installed, 'agents_md');
}

function installGemini(context, installed) {
  installMarkdownFile(context.targetRoot, context.systemRoot, 'GEMINI.md', path.join('gemini', 'GEMINI.md'), 'Gemini CLI .knowledge notes', installed, 'gemini_md');
}

function installCopilot(context, installed) {
  installMarkdownFile(
    context.targetRoot,
    context.systemRoot,
    path.join('.github', 'copilot-instructions.md'),
    path.join('copilot', 'copilot-instructions.md'),
    'GitHub Copilot .knowledge instructions',
    installed,
    'copilot_instructions'
  );
}

function installRuleFile(context, installed, runtime, targetRel, templateRel, title, key) {
  installMarkdownFile(context.targetRoot, context.systemRoot, targetRel, templateRel, title, installed, key || `${runtime}_rules`);
}

function installAider(context, installed) {
  installMarkdownFile(
    context.targetRoot,
    context.systemRoot,
    'CONVENTIONS.md',
    path.join('aider', 'CONVENTIONS.md'),
    'Aider .knowledge conventions',
    installed,
    'conventions_md'
  );
  const configPath = path.join(context.targetRoot, '.aider.conf.yml');
  if (fs.existsSync(configPath) && fs.readFileSync(configPath, 'utf8').includes('CONVENTIONS.md')) {
    installed.aider_config = 'unchanged';
  } else {
    installed.aider_config = upsertHashManagedBlock(configPath, 'read:\n  - CONVENTIONS.md');
  }
}

const INTEGRATIONS = {
  codex: {
    label: 'Codex',
    paths: ['AGENTS.md', '.agents/skills/**'],
    install: installCodex
  },
  claude: {
    label: 'Claude Code',
    paths: ['CLAUDE.md', '.claude/skills/**'],
    install: installClaude
  },
  opencode: {
    label: 'OpenCode',
    paths: ['.opencode/commands/**'],
    install: installOpenCode
  },
  openclaw: {
    label: 'OpenClaw',
    paths: ['AGENTS.md', '.agents/skills/**'],
    install: installOpenClaw
  },
  hermes: {
    label: 'Hermes',
    paths: ['AGENTS.md'],
    install: installHermes
  },
  gemini: {
    label: 'Gemini CLI',
    paths: ['GEMINI.md'],
    install: installGemini
  },
  copilot: {
    label: 'GitHub Copilot',
    paths: ['.github/copilot-instructions.md'],
    install: installCopilot
  },
  devin: {
    label: 'Devin',
    paths: ['.devin/rules/knowledge.md'],
    install: (context, installed) => installRuleFile(context, installed, 'devin', path.join('.devin', 'rules', 'knowledge.md'), path.join('devin', 'rules', 'knowledge.md'), 'Devin .knowledge rules')
  },
  windsurf: {
    label: 'Windsurf Cascade',
    paths: ['.devin/rules/knowledge.md'],
    install: (context, installed) => installRuleFile(context, installed, 'windsurf', path.join('.devin', 'rules', 'knowledge.md'), path.join('windsurf', 'rules', 'knowledge.md'), 'Windsurf Cascade .knowledge rules')
  },
  continue: {
    label: 'Continue',
    paths: ['.continue/rules/knowledge.md'],
    install: (context, installed) => installRuleFile(context, installed, 'continue', path.join('.continue', 'rules', 'knowledge.md'), path.join('continue', 'rules', 'knowledge.md'), 'Continue .knowledge rules')
  },
  roo: {
    label: 'Roo Code',
    paths: ['.roo/rules/knowledge.md'],
    install: (context, installed) => installRuleFile(context, installed, 'roo', path.join('.roo', 'rules', 'knowledge.md'), path.join('roo', 'rules', 'knowledge.md'), 'Roo Code .knowledge rules')
  },
  aider: {
    label: 'Aider',
    paths: ['CONVENTIONS.md', '.aider.conf.yml'],
    install: installAider
  }
};

function detectRuntimeFromEnv(env = process.env) {
  const explicit = normalizeRuntime(env.KNOWLEDGE_AGENT_RUNTIME || env.KNOWLEDGE_RUNTIME);
  if (explicit) return { runtime: explicit, source: 'env:KNOWLEDGE_AGENT_RUNTIME' };
  const hints = [
    ['codex', ['CODEX_HOME', 'CODEX_SANDBOX', 'CODEX_CLI_SANDBOX', 'CODEX_ENV_PWD']],
    ['claude', ['CLAUDECODE', 'CLAUDE_CODE', 'ANTHROPIC_CLAUDE_CODE']],
    ['opencode', ['OPENCODE', 'OPENCODE_APP']],
    ['openclaw', ['OPENCLAW_HOME', 'OPENCLAW_WORKSPACE']],
    ['hermes', ['HERMES_HOME', 'HERMES_AGENT']],
    ['gemini', ['GEMINI_CLI', 'GEMINI_API_KEY']],
    ['copilot', ['GITHUB_COPILOT_AGENT', 'COPILOT_AGENT']],
    ['continue', ['CONTINUE_GLOBAL_DIR']],
    ['aider', ['AIDER_MODEL', 'AIDER_ANALYTICS']]
  ];
  for (const [runtime, names] of hints) {
    if (names.some((name) => env[name])) return { runtime, source: `env:${names.find((name) => env[name])}` };
  }
  return null;
}

function resolveRequestedRuntime(options = {}) {
  if (options.all) return { all: true, runtimes: supportedRuntimeIds(), source: 'flag:--all' };
  const requested = normalizeRuntime(options.runtime);
  if (requested) return { all: false, runtimes: [requested], source: 'flag:--runtime' };
  if (options.runtime) return { all: false, runtimes: [], unknown: String(options.runtime), source: 'flag:--runtime' };
  const detected = detectRuntimeFromEnv();
  if (detected?.runtime) return { all: false, runtimes: [detected.runtime], source: detected.source };
  return { all: false, runtimes: [], source: 'none' };
}

function runtimeRequired(reason = 'No supported agent runtime was detected.') {
  return {
    status: 'runtime_required',
    reason,
    supported_runtimes: supportedRuntimeIds(),
    commands: runtimeCommands(),
    all_command: 'node .knowledge/tools/install-agent-integrations.js --all'
  };
}

function installAgentIntegrations(options = {}) {
  const context = resolveKnowledgeContext(options);
  const repoRoot = context.targetRoot;
  const lockDir = path.join(context.stateRoot, '.lock');
  const requested = resolveRequestedRuntime(options);

  if (!requested.runtimes.length) {
    const reason = requested.unknown
      ? `Unknown agent runtime: ${requested.unknown}.`
      : 'No supported agent runtime was detected.';
    return {
      ...runtimeRequired(reason),
      repo_root: repoRoot,
      knowledge_root: context.systemRoot
    };
  }

  const installed = withLock(lockDir, () => {
    const installed = {
      status: 'ok',
      mode: requested.all ? 'all' : 'runtime',
      runtimes: requested.runtimes,
      source: requested.source,
      installed: {}
    };
    const attributePaths = [];
    for (const runtime of requested.runtimes) {
      const integration = INTEGRATIONS[runtime];
      if (!integration) continue;
      const runtimeInstalled = {};
      integration.install(context, runtimeInstalled);
      installed.installed[runtime] = runtimeInstalled;
      attributePaths.push(...integration.paths);
    }
    if (options.updatePackageScripts !== false) {
      installed.package_json = updatePackageJson(repoRoot);
      if (installed.package_json.status !== 'not_found') attributePaths.push('package.json');
    }
    installed.gitattributes = upsertGitAttributes(repoRoot, attributePaths);
    return installed;
  });

  const installCheckScript = path.join(context.systemRoot, 'tools', 'install-check.js');
  if (fs.existsSync(installCheckScript) && options.runInstallCheck !== false) {
    const res = spawnSync(process.execPath, [installCheckScript, '--json'], { cwd: repoRoot, encoding: 'utf8', env: contextEnv(context), windowsHide: true });
    installed.install_check = {
      command: 'node .knowledge/tools/install-check.js --json',
      exit: res.status,
      status: null
    };
    try {
      installed.install_check.result = JSON.parse((res.stdout || '').trim() || '{}');
      installed.install_check.status = installed.install_check.result.status || null;
    } catch {
      installed.install_check.stdout = (res.stdout || '').trim().slice(0, 4000);
    }
    if (res.stderr) installed.install_check.stderr = res.stderr.trim().slice(0, 2000);
  } else {
    installed.install_check = { recommendation: 'Run node .knowledge/tools/install-check.js --json' };
  }
  return installed;
}

module.exports = installAgentIntegrations;
module.exports.INTEGRATIONS = INTEGRATIONS;
module.exports.supportedRuntimeIds = supportedRuntimeIds;

if (require.main === module) {
  try {
    const parsed = parseCliArgs(process.argv.slice(2)).flags;
    const options = {
      runtime: parsed.runtime,
      all: parsed.all === true,
      updatePackageScripts: !process.argv.includes('--no-package-scripts')
    };
    if (parsed.listRuntimes) {
      console.log(JSON.stringify({ status: 'ok', supported_runtimes: supportedRuntimeIds(), commands: runtimeCommands() }, null, 2));
    } else {
      console.log(JSON.stringify(installAgentIntegrations(options), null, 2));
    }
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}
