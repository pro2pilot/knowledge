#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function parseArgs(argv) {
  const args = { artifact: null, json: false };
  for (const arg of argv) {
    if (arg === '--json') args.json = true;
    else if (!args.artifact) args.artifact = arg;
  }
  return args;
}

function fail(message) {
  const error = new Error(message);
  error.releaseValidation = true;
  throw error;
}

function eocdOffset(buffer) {
  for (let i = buffer.length - 22; i >= 0; i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) return i;
  }
  fail('ZIP end of central directory not found.');
}

function textEntry(name) {
  const ext = path.posix.extname(name).toLowerCase();
  return new Set(['.cjs', '.css', '.csv', '.html', '.js', '.json', '.md', '.mjs', '.ps1', '.snippet', '.svg', '.toml', '.ts', '.txt', '.vbs', '.xml', '.yaml', '.yml']).has(ext) ||
    new Set(['.gitattributes', '.gitignore', '.knowledge.gitignore', 'LICENSE', 'NOTICE', 'README', 'SECURITY']).has(path.posix.basename(name));
}

function readZipEntries(zipPath) {
  const buffer = fs.readFileSync(zipPath);
  const eocd = eocdOffset(buffer);
  const count = buffer.readUInt16LE(eocd + 10);
  let ptr = buffer.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i += 1) {
    if (buffer.readUInt32LE(ptr) !== 0x02014b50) fail(`Invalid central directory header at ${ptr}.`);
    const method = buffer.readUInt16LE(ptr + 10);
    const compressedSize = buffer.readUInt32LE(ptr + 20);
    const nameLength = buffer.readUInt16LE(ptr + 28);
    const extraLength = buffer.readUInt16LE(ptr + 30);
    const commentLength = buffer.readUInt16LE(ptr + 32);
    const localOffset = buffer.readUInt32LE(ptr + 42);
    const name = buffer.slice(ptr + 46, ptr + 46 + nameLength).toString('utf8');
    if (buffer.readUInt32LE(localOffset) !== 0x04034b50) fail(`Invalid local header for ${name}.`);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.slice(dataStart, dataStart + compressedSize);
    const body = method === 0 ? compressed : zlib.inflateRawSync(compressed);
    entries.push({ name, body });
    ptr += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function validate(zipPath) {
  const entries = readZipEntries(zipPath);
  const forbiddenEntryPatterns = [
    /(^|\/)\.git(\/|$)/,
    /^\.knowledge\/\.github\//,
    /(^|\/)node_modules(\/|$)/,
    /^\.knowledge\/dist\//,
    /^\.knowledge\/internal\//,
    /^\.knowledge\/maintenance\/knowledge-[^/]+-(?:10-10-inventory|final-qa)\.(?:md|json)$/i,
    /^\.knowledge\/memory-providers\/(graphiti|zep)(\/|$)/i,
    /^\.knowledge\/models\/pro-(entitlement|extension-manifest|license-token)\.schema\.json$/i,
    /^\.knowledge\/tools\/self-test-(canonical-e2e|pro-ready-gates)\.js$/i,
    /^\.knowledge\/maintenance\/flow-logs\//,
    /^\.knowledge\/external_memory\/(mem0|legacy|claude_mem|claude|claude-auto-memory)(\/|$)/,
    /^\.knowledge\/metrics\/external_memory\.json$/,
    /^\.knowledge\/inspector\/index\.html$/
  ];
  const commercialTextPattern = new RegExp([
    '\\$\\d{2,}',
    '\\/mo\\b',
    'per user\\b',
    'per seat\\b',
    ['\\bpri', 'cing\\b'].join(''),
    '\\bprices?\\b',
    '\\btariff\\b',
    ['feature', 'to', 'plan'].join('-'),
    ['plan', 'packaging'].join(' ')
  ].join('|'), 'i');
  const forbiddenContent = [
    { id: 'local_windows_project_path', pattern: /[A-Z]:\\(?:Users\\[^\\]+|MyProject)/i },
    { id: 'mnt_data_path', pattern: /\/mnt\/data/i },
    { id: 'tmp_knowledge_path', pattern: /\/tmp\/knowledge/i },
    { id: 'local_user_path', pattern: /Users[\\/](?![\[<^])[\w .-]{1,64}(?=[\\/])/i },
    { id: 'workspace_name_leak', pattern: new RegExp(`knowledge${'-'}kit`, 'i') },
    { id: 'free_core_commercial_text', pattern: commercialTextPattern }
  ];
  const violations = [];
  const names = new Set(entries.map((entry) => normalizeRel(entry.name)));
  for (const required of [
    '.knowledge/INSTALL.md',
    '.knowledge/install-policy.json',
    '.knowledge/inspector.js',
    '.knowledge/open-inspector.vbs',
    '.knowledge/assets/knowledge-trust-gate-light-readme.svg',
    '.knowledge/agent-integrations/codex/skills/kb-repair-trust/SKILL.md',
    '.knowledge/agent-integrations/claude/skills/kb-repair-trust/SKILL.md',
    '.knowledge/tools/lib/action-registry.js',
    '.knowledge/tools/lib/action-runner.js',
    '.knowledge/tools/lib/python-discovery.js',
    '.knowledge/tools/agent-session.js',
    '.knowledge/tools/restore-trust.js',
    '.knowledge/tools/agent-footer.js',
    '.knowledge/docs/free-core.md',
    '.knowledge/docs/inspector.md',
    '.knowledge/docs/memory-providers.md',
    '.knowledge/docs/release-artifact.md'
  ]) {
    if (!names.has(required)) violations.push({ type: 'required_entry_missing', entry: required, reason: 'public release file missing' });
  }
  for (const entry of entries) {
    const name = normalizeRel(entry.name);
    if (!name.startsWith('.knowledge/')) violations.push({ type: 'entry_root', entry: name, reason: 'entry is outside .knowledge/' });
    for (const pattern of forbiddenEntryPatterns) {
      if (pattern.test(name)) violations.push({ type: 'entry_forbidden', entry: name, pattern: String(pattern) });
    }
    if (textEntry(name)) {
      const text = entry.body.toString('utf8');
      for (const item of forbiddenContent) {
        if (item.id === 'free_core_commercial_text' && name === '.knowledge/tools/validate-release-artifact.js') continue;
        if (item.pattern.test(text)) violations.push({ type: 'content_forbidden', entry: name, pattern: item.id });
      }
    }
  }
  return {
    schema_version: '3.2.5',
    artifact: path.resolve(zipPath),
    status: violations.length ? 'failed' : 'ok',
    entries: entries.length,
    violations
  };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args.artifact) fail('Usage: node tools/validate-release-artifact.js dist/knowledge-v3.2.5.zip [--json]');
  const result = validate(path.resolve(args.artifact));
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else if (result.status === 'ok') console.log(`release artifact ok: ${result.entries} entries`);
  else {
    console.log(`release artifact failed: ${result.violations.length} violation(s)`);
    for (const violation of result.violations.slice(0, 40)) console.log(`- ${violation.entry}: ${violation.reason || violation.pattern}`);
  }
  if (result.status !== 'ok') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.json) console.log(JSON.stringify({ schema_version: '3.2.5', status: 'failed', error: error.message }, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}

module.exports = { validate };
