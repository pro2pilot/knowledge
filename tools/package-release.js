#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const sourceRoot = path.resolve(__dirname, '..');
const distRoot = path.join(sourceRoot, 'dist');

function normalizeRel(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function parseArgs(argv) {
  const args = { json: false, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') args.json = true;
    else if (arg === '--out') args.out = argv[++i];
    else if (arg.startsWith('--out=')) args.out = arg.slice('--out='.length);
  }
  return args;
}

function shouldExclude(relPath, entry) {
  const rel = normalizeRel(relPath);
  const base = path.posix.basename(rel);
  const segments = rel.split('/');

  if (!rel) return { exclude: false };
  if (rel === '.gitignore') return { exclude: true, reason: 'source_gitignore_replaced_by_installed_template' };
  if (segments.includes('.git')) return { exclude: true, reason: 'git_metadata' };
  if (segments[0] === '.github') return { exclude: true, reason: 'source_github_dir' };
  if (segments.includes('node_modules')) return { exclude: true, reason: 'node_modules' };
  if (segments[0] === 'dist') return { exclude: true, reason: 'dist_output' };
  if (segments[0] === '.self-test-tmp') return { exclude: true, reason: 'self_test_tmp' };
  if (segments[0] === '.qa-tmp') return { exclude: true, reason: 'qa_tmp' };
  if (segments.includes('.lock')) return { exclude: true, reason: 'runtime_lock' };
  if (segments.includes('.runtime')) return { exclude: true, reason: 'runtime_state' };
  if (rel.startsWith('maintenance/flow-logs/')) return { exclude: true, reason: 'flow_logs' };
  if (rel.startsWith('maintenance/events/')) return { exclude: true, reason: 'events' };
  if (rel.startsWith('maintenance/dev-notes/')) return { exclude: true, reason: 'source_dev_notes' };
  if (rel.startsWith('maintenance/install-backups/')) return { exclude: true, reason: 'install_backups' };
  if (rel.startsWith('evaluation/results/')) return { exclude: true, reason: 'evaluation_results' };
  if (rel.startsWith('maintenance/graphs/')) return { exclude: true, reason: 'generated_graphs' };
  if (rel.startsWith('search/')) return { exclude: true, reason: 'search_index' };
  if (rel === 'metrics/baseline.json' || rel === 'metrics/README.md') return { exclude: true, reason: 'metrics_runtime' };
  if (rel === 'inspector/data.json' || rel === 'inspector/status.json') return { exclude: true, reason: 'inspector_runtime' };
  if (rel === 'sessions/active_task.json' || rel.startsWith('sessions/active_tasks/')) return { exclude: true, reason: 'session_runtime' };
  if (rel === 'project_index.json' || rel === 'freshness.json') return { exclude: true, reason: 'project_runtime' };

  const generatedMaintenance = new Set([
    'maintenance/routing_bundle.json',
    'maintenance/quality_report.json',
    'maintenance/trust_report.json',
    'maintenance/wiki_lint_report.json',
    'maintenance/external_memory_status.json',
    'maintenance/secret_scan_report.json',
    'maintenance/pr_summary.md',
    'maintenance/sync_log.json',
    'maintenance/stale_items.json',
    'maintenance/repair_queue.json',
    'maintenance/automation_status.json',
    'maintenance/handoff_summary.json',
    'maintenance/update_status.json',
    'maintenance/install_check_report.json',
    'maintenance/update_system_files_report.json',
    'maintenance/applied_templates.json'
  ]);
  if (generatedMaintenance.has(rel)) return { exclude: true, reason: 'maintenance_runtime' };

  const generatedMaps = new Set([
    'maps/wiki_graph.json',
    'maps/file_criticality.json',
    'maps/dependency_map.json',
    'maps/directory_map.json',
    'maps/entrypoints.json'
  ]);
  if (generatedMaps.has(rel)) return { exclude: true, reason: 'generated_map' };

  if (/\.tmp-/i.test(base)) return { exclude: true, reason: 'tmp_file' };
  if (/\.bak-/i.test(base)) return { exclude: true, reason: 'backup_file' };
  if (/\.zip$/i.test(base)) return { exclude: true, reason: 'archive_artifact' };
  if (/\.log$/i.test(base) || /\.cache$/i.test(base)) return { exclude: true, reason: 'log_or_cache' };
  if (/^\.env($|\.)/i.test(base)) return { exclude: true, reason: 'env_file' };
  if (/\.(pem|key|p12|pfx)$/i.test(base)) return { exclude: true, reason: 'secret_like_file' };
  if (entry && entry.isDirectory() && /(^|\/)(cache|\.cache)(\/|$)/i.test(rel)) return { exclude: true, reason: 'cache_dir' };

  return { exclude: false };
}

function countFilesRecursive(absPath, entry) {
  if (!entry) return 0;
  if (entry.isFile()) return 1;
  if (!entry.isDirectory()) return 0;
  let total = 0;
  for (const child of fs.readdirSync(absPath, { withFileTypes: true })) {
    total += countFilesRecursive(path.join(absPath, child.name), child);
  }
  return total;
}

function walkFiles(root) {
  const files = [];
  const excluded = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      const rel = normalizeRel(path.relative(root, abs));
      const decision = shouldExclude(rel, entry);
      if (decision.exclude) {
        excluded.push({ path: rel, reason: decision.reason, entries: 1, files: countFilesRecursive(abs, entry) });
        continue;
      }
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) files.push({ abs, rel });
      else excluded.push({ path: rel, reason: 'non_regular_file', entries: 1, files: 0 });
    }
  }
  walk(root);
  files.sort((a, b) => a.rel.localeCompare(b.rel));
  return { files, excluded };
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date = new Date()) {
  const year = Math.max(1980, date.getFullYear());
  const dosTime = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const dosDate = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { dosTime, dosDate };
}

function u16(value) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(value & 0xffff, 0);
  return b;
}

function u32(value) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(value >>> 0, 0);
  return b;
}

function isTextEntry(entry) {
  const rel = normalizeRel(entry.rel || entry.name || '');
  const ext = path.posix.extname(rel).toLowerCase();
  const textExts = new Set([
    '.cjs', '.css', '.csv', '.html', '.js', '.json', '.md', '.mjs', '.svg',
    '.toml', '.ts', '.txt', '.xml', '.yaml', '.yml'
  ]);
  const textNames = new Set([
    '.gitattributes', '.gitignore', '.knowledge.gitignore', 'LICENSE', 'NOTICE', 'README', 'SECURITY'
  ]);
  return textExts.has(ext) || textNames.has(path.posix.basename(rel));
}

function readEntryData(entry) {
  const raw = fs.readFileSync(entry.abs);
  if (!isTextEntry(entry)) return raw;
  const body = raw.toString('utf8').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return Buffer.from(body, 'utf8');
}

function createZip(entries, outputPath) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = readEntryData(entry);
    const compressed = zlib.deflateRawSync(data);
    const crc = crc32(data);
    const { dosTime, dosDate } = dosDateTime(fs.statSync(entry.abs).mtime);
    const method = 8;

    const localHeader = Buffer.concat([
      u32(0x04034b50), u16(20), u16(0x0800), u16(method), u16(dosTime), u16(dosDate),
      u32(crc), u32(compressed.length), u32(data.length), u16(name.length), u16(0), name
    ]);
    localParts.push(localHeader, compressed);

    const centralHeader = Buffer.concat([
      u32(0x02014b50), u16(20), u16(20), u16(0x0800), u16(method), u16(dosTime), u16(dosDate),
      u32(crc), u32(compressed.length), u32(data.length), u16(name.length), u16(0), u16(0),
      u16(0), u16(0), u32(0), u32(offset), name
    ]);
    centralParts.push(centralHeader);
    offset += localHeader.length + compressed.length;
  }

  const centralOffset = offset;
  const central = Buffer.concat(centralParts);
  const end = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length),
    u32(central.length), u32(centralOffset), u16(0)
  ]);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, Buffer.concat([...localParts, central, end]));
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const pkg = readJson(path.join(sourceRoot, 'package.json'));
  const version = pkg.version;
  const outputPath = path.resolve(sourceRoot, args.out || path.join('dist', `knowledge-v${version}.zip`));
  const { files, excluded } = walkFiles(sourceRoot);
  const entries = files.map((file) => ({ ...file, name: `.knowledge/${file.rel}` }));
  entries.push({
    abs: path.join(sourceRoot, 'templates', 'git-policy', '.knowledge.gitignore'),
    rel: '.gitignore',
    name: '.knowledge/.gitignore'
  });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  const warnings = [];
  const errors = [];

  if (!version) errors.push('package.json version is missing.');
  if (entries.some((entry) => /(^|\/)\.git(\/|$)/.test(entry.name))) errors.push('Unsafe artifact would include .knowledge/.git.');
  if (entries.some((entry) => entry.name.startsWith('.knowledge/.github/'))) errors.push('Unsafe artifact would include .knowledge/.github/.');
  if (!entries.some((entry) => entry.name === '.knowledge/Quick-Start.md')) errors.push('Quick-Start.md is missing from artifact.');
  if (!entries.some((entry) => entry.name === '.knowledge/.gitignore')) errors.push('Installed .knowledge/.gitignore is missing from artifact.');
  if (!entries.some((entry) => entry.name === '.knowledge/tools/flow.js')) errors.push('tools/flow.js is missing from artifact.');
  if (!entries.some((entry) => entry.name === '.knowledge/tools/install-check.js')) warnings.push('tools/install-check.js is not present yet.');

  if (errors.length === 0) createZip(entries, outputPath);
  const excludedEntriesCount = excluded.reduce((sum, item) => sum + (item.entries || 1), 0);
  const excludedFilesCount = excluded.reduce((sum, item) => sum + (item.files || 0), 0);

  const summary = {
    version,
    output_path: outputPath,
    included_files_count: entries.length,
    excluded_entries_count: excludedEntriesCount,
    excluded_files_count: excludedFilesCount,
    warnings,
    errors,
    status: errors.length ? 'failed' : 'ok'
  };
  console.log(JSON.stringify(summary, null, 2));
  if (errors.length) process.exit(2);
}

if (require.main === module) main();

module.exports = { shouldExclude, walkFiles, createZip };
