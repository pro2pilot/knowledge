#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const knowledgeRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(knowledgeRoot, '..');
const configPath = path.join(knowledgeRoot, 'config.yaml');
const statusPath = path.join(knowledgeRoot, 'maintenance', 'update_status.json');
const packagePath = path.join(knowledgeRoot, 'package.json');
const OFFICIAL_UPDATE_REPOSITORY = 'pro2pilot/knowledge';

function nowIso() { return new Date().toISOString(); }
function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); }
function readJson(file, fallback = {}) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')); }
  catch { return fallback; }
}
function writeJson(file, data) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', 'utf8');
}
function parseBool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['true', '1', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}
function parseIntervalDays(raw, fallback = 7) {
  if (raw === undefined || raw === null || raw === '') return fallback;
  const value = String(raw).trim().toLowerCase();
  const match = value.match(/^(\d+)(d|day|days)?$/);
  if (!match) throw new Error(`Invalid interval: ${raw}. Use a value like 7d or 14d.`);
  return Math.max(1, Number(match[1]));
}
function parseArgs(argv) {
  const opts = { json: false, quiet: false, status: false, enable: false, disable: false, auto: false, intervalDays: null };
  for (const arg of argv) {
    if (arg === '--json') opts.json = true;
    else if (arg === '--quiet') opts.quiet = true;
    else if (arg === '--status') opts.status = true;
    else if (arg === '--enable') opts.enable = true;
    else if (arg === '--disable') opts.disable = true;
    else if (arg === '--auto') opts.auto = true;
    else if (arg.startsWith('--interval=')) opts.intervalDays = parseIntervalDays(arg.slice('--interval='.length));
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}
function readPackageVersion() {
  const pkg = readJson(packagePath, {});
  return String(pkg.version || '0.0.0');
}
function readConfigText() {
  if (!fs.existsSync(configPath)) return '';
  return fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, '');
}
function parseUpdatesBlock(text) {
  const lines = String(text || '').split(/\r?\n/);
  let inBlock = false;
  const data = {};
  for (const line of lines) {
    if (/^updates:\s*$/.test(line)) { inBlock = true; continue; }
    if (inBlock && /^\S/.test(line) && line.trim()) break;
    if (!inBlock) continue;
    const match = line.match(/^\s{2}([a-zA-Z0-9_]+):\s*(.*?)\s*$/);
    if (match) data[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
  return data;
}
function getConfig() {
  const block = parseUpdatesBlock(readConfigText());
  return {
    enabled: parseBool(block.enabled, false),
    mode: block.mode || 'advisory_only',
    interval_days: Number(block.interval_days || 7),
    source: block.source || 'github_releases',
    repository: OFFICIAL_UPDATE_REPOSITORY,
    current_version_source: block.current_version_source || 'package.json',
    auto_check_on_inspector_open: parseBool(block.auto_check_on_inspector_open, true),
    allow_prerelease: parseBool(block.allow_prerelease, false),
    auto_update: parseBool(block.auto_update, false),
    telemetry: parseBool(block.telemetry, false),
    timeout_ms: Number(block.timeout_ms || 5000)
  };
}
function removeUpdatesBlock(text) {
  const lines = String(text || '').split(/\r?\n/);
  const out = [];
  let skipping = false;
  for (const line of lines) {
    if (/^updates:\s*$/.test(line)) { skipping = true; continue; }
    if (skipping && /^\S/.test(line) && line.trim()) skipping = false;
    if (!skipping) out.push(line);
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n').replace(/\s+$/, '') + '\n';
}
function writeConfig(updates) {
  const base = removeUpdatesBlock(readConfigText());
  const block = [
    'updates:',
    `  enabled: ${updates.enabled ? 'true' : 'false'}`,
    `  mode: ${updates.mode || 'advisory_only'}`,
    `  interval_days: ${Number(updates.interval_days || 7)}`,
    `  source: ${updates.source || 'github_releases'}`,
    `  repository: ${OFFICIAL_UPDATE_REPOSITORY}`,
    `  current_version_source: ${updates.current_version_source || 'package.json'}`,
    `  auto_check_on_inspector_open: ${updates.auto_check_on_inspector_open !== false ? 'true' : 'false'}`,
    `  allow_prerelease: ${updates.allow_prerelease ? 'true' : 'false'}`,
    `  auto_update: ${updates.auto_update ? 'true' : 'false'}`,
    `  telemetry: ${updates.telemetry ? 'true' : 'false'}`,
    `  timeout_ms: ${Number(updates.timeout_ms || 5000)}`,
    ''
  ].join('\n');
  fs.writeFileSync(configPath, `${base.trimEnd()}\n\n${block}`, 'utf8');
}
function semverParts(version) {
  return String(version || '0.0.0').replace(/^v/i, '').split(/[.+-]/)[0].split('.').map((p) => Number(p.replace(/\D/g, '') || 0));
}
function compareVersions(a, b) {
  const aa = semverParts(a); const bb = semverParts(b);
  const max = Math.max(aa.length, bb.length, 3);
  for (let i = 0; i < max; i += 1) {
    const av = aa[i] || 0; const bv = bb[i] || 0;
    if (av > bv) return 1;
    if (av < bv) return -1;
  }
  return 0;
}
function readStatus() { return readJson(statusPath, { status: 'never_checked' }); }
function isDue(config, status) {
  if (!config.enabled) return false;
  if (!status.last_checked_at) return true;
  const elapsed = Date.now() - Date.parse(status.last_checked_at);
  if (!Number.isFinite(elapsed)) return true;
  return elapsed >= Number(config.interval_days || 7) * 24 * 60 * 60 * 1000;
}
async function fetchLatestRelease(config) {
  if (process.env.KNOWLEDGE_UPDATE_MOCK_LATEST) {
    const mockAssetUrl = process.env.KNOWLEDGE_UPDATE_MOCK_ASSET_URL || process.env.KNOWLEDGE_UPDATE_LOCAL_ZIP || null;
    return {
      tag_name: process.env.KNOWLEDGE_UPDATE_MOCK_LATEST,
      html_url: 'mock://latest-release',
      source: 'mock',
      prerelease: false,
      assets: mockAssetUrl ? [{ name: `knowledge-v${process.env.KNOWLEDGE_UPDATE_MOCK_LATEST}.zip`, browser_download_url: mockAssetUrl }] : []
    };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Number(config.timeout_ms || 5000));
  try {
    const url = config.allow_prerelease
      ? `https://api.github.com/repos/${OFFICIAL_UPDATE_REPOSITORY}/releases`
      : `https://api.github.com/repos/${OFFICIAL_UPDATE_REPOSITORY}/releases/latest`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'dot-knowledge-update-check' },
      signal: controller.signal
    });
    const body = await response.text();
    let json = null;
    try { json = body ? JSON.parse(body) : null; } catch { json = null; }
    if (!response.ok) throw new Error(`GitHub Releases request failed: ${response.status} ${response.statusText}`);
    const release = Array.isArray(json)
      ? json.find((item) => item && !item.draft && (config.allow_prerelease || !item.prerelease))
      : json;
    return {
      tag_name: release?.tag_name || release?.name || '',
      html_url: release?.html_url || null,
      source: 'github_releases',
      prerelease: Boolean(release?.prerelease),
      assets: Array.isArray(release?.assets) ? release.assets.map((asset) => ({
        name: asset.name,
        browser_download_url: asset.browser_download_url,
        size: asset.size,
        content_type: asset.content_type
      })) : []
    };
  } finally {
    clearTimeout(timeout);
  }
}

function selectReleaseAsset(latest) {
  const assets = Array.isArray(latest?.assets) ? latest.assets : [];
  const version = String(latest?.tag_name || '').replace(/^v/i, '');
  return assets.find((asset) => /^knowledge-v\d+\.\d+\.\d+.*\.zip$/i.test(asset.name || '')) ||
    assets.find((asset) => version && String(asset.name || '').toLowerCase() === `knowledge-v${version}.zip`.toLowerCase()) ||
    assets.find((asset) => /\.zip$/i.test(asset.name || '')) ||
    null;
}

function makeStatusBase(config) {
  return {
    schema_version: '3.2.3',
    generated_at: nowIso(),
    repository: OFFICIAL_UPDATE_REPOSITORY,
    source: config.source,
    mode: config.mode,
    enabled: Boolean(config.enabled),
    interval_days: Number(config.interval_days || 7),
    auto_check_on_inspector_open: config.auto_check_on_inspector_open !== false,
    allow_prerelease: Boolean(config.allow_prerelease),
    auto_update: false,
    telemetry: false,
    current_version: readPackageVersion()
  };
}
async function checkNow(config, reason = 'manual') {
  const base = makeStatusBase(config);
  try {
    const latest = await fetchLatestRelease(config);
    const asset = selectReleaseAsset(latest);
    const latestVersion = String(latest.tag_name || '').replace(/^v/i, '') || null;
    const cmp = latestVersion ? compareVersions(base.current_version, latestVersion) : 0;
    const status = {
      ...base,
      status: latestVersion && cmp < 0 ? 'update_available' : 'up_to_date',
      reason,
      last_checked_at: nowIso(),
      latest_version: latestVersion,
      latest_tag: latest.tag_name || null,
      latest_url: latest.html_url || null,
      latest_prerelease: Boolean(latest.prerelease),
      asset_name: asset ? asset.name : null,
      asset_url: asset ? asset.browser_download_url : null,
      assets: (latest.assets || []).map((item) => ({ name: item.name, size: item.size || null, content_type: item.content_type || null })),
      advisory: latestVersion && cmp < 0 ? `Update available: ${base.current_version} -> ${latestVersion}. Updates are advisory-only; run a system update only when you choose to.` : 'No update available.',
      note: 'Update checks query GitHub Releases only. They do not upload repository content and do not auto-update.'
    };
    writeJson(statusPath, status);
    return status;
  } catch (error) {
    const status = { ...base, status: 'check_failed', reason, last_checked_at: nowIso(), error: error.message, note: 'Update check failed. This does not affect local .knowledge operation.' };
    writeJson(statusPath, status);
    return status;
  }
}
function printHuman(status) {
  if (status.status === 'disabled') {
    console.log('Update checks are disabled. Run `node .knowledge/tools/check-updates.js` to check manually.');
    return;
  }
  if (status.status === 'not_due') {
    console.log(`Update check not due. Current: ${status.current_version}. Last checked: ${status.last_checked_at || 'never'}.`);
    return;
  }
  if (status.status === 'update_available') {
    console.log(`Update available: ${status.current_version} -> ${status.latest_version}`);
    if (status.latest_url) console.log(`Release: ${status.latest_url}`);
    console.log('Advisory only. Review release notes before updating system files.');
    return;
  }
  if (status.status === 'up_to_date') {
    console.log(`Up to date: ${status.current_version}`);
    return;
  }
  if (status.status === 'check_failed') {
    console.log(`Update check failed: ${status.error}`);
    return;
  }
  console.log(JSON.stringify(status, null, 2));
}
async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  let config = getConfig();
  if (opts.intervalDays) config.interval_days = opts.intervalDays;
  if (opts.enable || opts.disable || opts.intervalDays) {
    if (opts.enable) config.enabled = true;
    if (opts.disable) config.enabled = false;
    writeConfig(config);
  }

  let result;
  if (opts.status) {
    result = { ...makeStatusBase(config), status: config.enabled ? 'enabled' : 'disabled', last_status: readStatus() };
  } else if (opts.auto) {
    const status = readStatus();
    if (!config.enabled) result = { ...makeStatusBase(config), status: 'disabled', reason: 'auto_check_disabled' };
    else if (!isDue(config, status)) result = { ...makeStatusBase(config), status: 'not_due', last_checked_at: status.last_checked_at || null, reason: 'interval_not_elapsed' };
    else result = await checkNow(config, 'auto_interval_elapsed');
  } else if (opts.enable || opts.disable || opts.intervalDays) {
    result = { ...makeStatusBase(config), status: config.enabled ? 'enabled' : 'disabled', configured: true };
  } else {
    result = await checkNow(config, 'manual');
  }

  if (opts.json) console.log(JSON.stringify(result, null, 2));
  else if (!opts.quiet) printHuman(result);
  return result;
}

module.exports = Object.assign(main, {
  getConfig,
  readStatus,
  checkNow,
  isDue,
  fetchLatestRelease,
  selectReleaseAsset,
  compareVersions,
  OFFICIAL_UPDATE_REPOSITORY
});
if (require.main === module) {
  main().catch((error) => { console.error(error.stack || error.message); process.exit(1); });
}
