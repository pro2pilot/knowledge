#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { validate } = require('./validate-release-artifact');
const { smoke } = require('./conformance-install-smoke');

const root = path.resolve(__dirname, '..');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const version = packageJson.version;

function parseArgs(argv = process.argv.slice(2)) {
  const args = {
    json: false,
    tag: `v${version}`,
    repo: 'pro2pilot/knowledge',
    expectedOwner: 'pro2pilot',
    keepFailed: false,
    dir: null,
    cleanDir: false
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') args.json = true;
    else if (arg === '--keep-failed' || arg === '--keep') args.keepFailed = true;
    else if (arg === '--tag') args.tag = argv[++i];
    else if (arg.startsWith('--tag=')) args.tag = arg.slice('--tag='.length);
    else if (arg === '--repo') args.repo = argv[++i];
    else if (arg.startsWith('--repo=')) args.repo = arg.slice('--repo='.length);
    else if (arg === '--expected-owner') args.expectedOwner = argv[++i];
    else if (arg.startsWith('--expected-owner=')) args.expectedOwner = arg.slice('--expected-owner='.length);
    else if (arg === '--dir') args.dir = argv[++i];
    else if (arg.startsWith('--dir=')) args.dir = arg.slice('--dir='.length);
    else if (arg === '--clean-dir') args.cleanDir = true;
  }
  return args;
}

function run(command, args, options = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 180000
  });
  return {
    command: [command, ...args].join(' '),
    status: result.status === 0 ? 'pass' : 'fail',
    exit_code: result.status,
    duration_ms: Date.now() - started,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error ? result.error.message : null
  };
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function parseReleaseView(stdout) {
  try { return JSON.parse(stdout || '{}'); }
  catch { return {}; }
}

function releaseApiPath(repo, tag) {
  return `repos/${repo}/releases/tags/${encodeURIComponent(tag)}`;
}

function isInside(parent, child) {
  const rel = path.relative(parent, child);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function prepareDownloadDir(args) {
  const allowedRoot = path.resolve(root, '.qa-tmp', 'live-release');
  const defaultDir = path.join(allowedRoot, args.tag);
  const downloadDir = path.resolve(args.dir || defaultDir);
  const shouldClean = !args.dir || args.cleanDir;

  if (shouldClean) {
    if (!isInside(allowedRoot, downloadDir)) {
      throw new Error(`Refusing to delete custom download dir outside ${allowedRoot}: ${downloadDir}`);
    }
    fs.rmSync(downloadDir, { recursive: true, force: true });
  }
  fs.mkdirSync(downloadDir, { recursive: true });
  return downloadDir;
}

function digestSha256(value) {
  const text = String(value || '').trim();
  const prefixed = text.match(/^sha256:([a-f0-9]{64})$/i);
  if (prefixed) return prefixed[1].toLowerCase();
  if (/^[a-f0-9]{64}$/i.test(text)) return text.toLowerCase();
  return null;
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const assetName = `knowledge-v${version}.zip`;
  const expectedOwner = args.expectedOwner || 'pro2pilot';
  const downloadDir = prepareDownloadDir(args);

  const releaseView = run('gh', ['release', 'view', args.tag, '--repo', args.repo, '--json', 'author,assets,tagName'], { timeoutMs: 120000 });
  const releaseApi = run('gh', ['api', releaseApiPath(args.repo, args.tag)], { timeoutMs: 120000 });
  const download = run('gh', ['release', 'download', args.tag, '--repo', args.repo, '--pattern', assetName, '--dir', downloadDir], { timeoutMs: 300000 });
  const assetPath = path.join(downloadDir, assetName);
  const releaseMeta = parseReleaseView(releaseView.stdout);
  const releaseApiMeta = parseReleaseView(releaseApi.stdout);
  const viewAssetMeta = Array.isArray(releaseMeta.assets) ? releaseMeta.assets.find((asset) => asset.name === assetName) : null;
  const apiAssetMeta = Array.isArray(releaseApiMeta.assets) ? releaseApiMeta.assets.find((asset) => asset.name === assetName) : null;
  const releaseTagName = releaseApiMeta.tag_name || releaseMeta.tagName || null;
  const releaseAuthor = releaseApiMeta.author?.login || releaseMeta.author?.login || null;
  const assetUploader = apiAssetMeta?.uploader?.login || viewAssetMeta?.uploader?.login || null;
  const assetDigest = apiAssetMeta?.digest || viewAssetMeta?.digest || null;

  let validation = null;
  let installSmoke = null;
  let assetHash = null;
  if (download.status === 'pass' && fs.existsSync(assetPath)) {
    assetHash = sha256(assetPath);
    validation = validate(assetPath);
    if (validation.status === 'ok') installSmoke = smoke(assetPath, { keepFailed: args.keepFailed });
  }

  const failures = [];
  if (releaseView.status !== 'pass') failures.push({ step: 'release_view', reason: releaseView.stderr || releaseView.error || 'gh release view failed' });
  if (releaseApi.status !== 'pass') failures.push({ step: 'release_api', reason: releaseApi.stderr || releaseApi.error || 'gh api release lookup failed' });
  if ((releaseView.status === 'pass' || releaseApi.status === 'pass') && releaseTagName !== args.tag) {
    failures.push({ step: 'release_tag_identity', reason: `release tag ${releaseTagName || '<missing>'} != ${args.tag}` });
  }
  if ((releaseView.status === 'pass' || releaseApi.status === 'pass') && releaseAuthor !== expectedOwner) {
    failures.push({ step: 'release_author_identity', reason: `release author ${releaseAuthor || '<missing>'} != ${expectedOwner}` });
  }
  if (releaseView.status === 'pass' || releaseApi.status === 'pass') {
    if (!apiAssetMeta && !viewAssetMeta) {
      failures.push({ step: 'asset_metadata_present', reason: `${assetName} missing from release metadata` });
    } else if (assetUploader !== expectedOwner) {
      failures.push({ step: 'asset_uploader_identity', reason: `asset uploader ${assetUploader || '<missing>'} != ${expectedOwner}` });
    }
  }
  if (download.status !== 'pass') failures.push({ step: 'release_download', reason: download.stderr || download.error || 'gh release download failed' });
  if (!fs.existsSync(assetPath)) failures.push({ step: 'asset_present', reason: `${assetName} was not downloaded` });
  const githubDigestSha256 = digestSha256(assetDigest);
  if (githubDigestSha256 && assetHash && githubDigestSha256 !== assetHash) {
    failures.push({ step: 'asset_digest_match', reason: `GitHub digest ${githubDigestSha256} != downloaded sha256 ${assetHash}` });
  }
  if (validation && validation.status !== 'ok') failures.push({ step: 'validate_release_artifact', reason: `${validation.violations.length} violation(s)` });
  if (installSmoke && installSmoke.status !== 'pass') failures.push({ step: 'conformance_install_smoke', reason: `${installSmoke.failures.length} failure(s)` });

  const result = {
    schema_version: 'post-release-live-asset.v1',
    status: failures.length ? 'fail' : 'pass',
    asset_source: 'github_release',
    repo: args.repo,
    release_tag: args.tag,
    expected_owner: expectedOwner,
    package_version: version,
    asset_name: assetName,
    asset_path: fs.existsSync(assetPath) ? assetPath : null,
    asset_sha256: assetHash,
    github_asset_digest: assetDigest,
    github_release_author: releaseAuthor,
    asset_uploader: assetUploader,
    release_view: {
      status: releaseView.status,
      exit_code: releaseView.exit_code,
      duration_ms: releaseView.duration_ms
    },
    release_api: {
      status: releaseApi.status,
      exit_code: releaseApi.exit_code,
      duration_ms: releaseApi.duration_ms
    },
    download: {
      status: download.status,
      exit_code: download.exit_code,
      duration_ms: download.duration_ms
    },
    validation,
    install_smoke: installSmoke,
    failures
  };

  if (args.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`post-release live asset ${result.status}`);
  if (result.status !== 'pass') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseArgs(process.argv.slice(2));
    const result = { schema_version: 'post-release-live-asset.v1', status: 'fail', error: error.message };
    if (parsed.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}
