#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');

function parseArgs(argv = process.argv.slice(2)) {
  return { json: argv.includes('--json') };
}

function validUrl(value) {
  return !value || /^https?:\/\//.test(String(value));
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const sbomPath = path.join(root, 'SBOM.memory.json');
  const issues = [];
  if (!fs.existsSync(sbomPath)) issues.push({ id: 'missing_sbom', message: 'SBOM.memory.json is missing' });
  const sbom = fs.existsSync(sbomPath) ? JSON.parse(fs.readFileSync(sbomPath, 'utf8')) : {};
  if (!sbom.schema_version) issues.push({ id: 'missing_schema_version' });
  if (!Array.isArray(sbom.providers)) issues.push({ id: 'providers_not_array' });
  for (const provider of sbom.providers || []) {
    for (const key of ['id', 'name', 'license_spdx', 'install_method', 'bundled', 'update_policy']) {
      if (provider[key] === undefined || provider[key] === null || provider[key] === '') issues.push({ id: `provider_missing_${key}`, provider: provider.id || '<unknown>' });
    }
    if (!validUrl(provider.source_url)) issues.push({ id: 'provider_invalid_source_url', provider: provider.id, source_url: provider.source_url });
    if (!validUrl(provider.package_url)) issues.push({ id: 'provider_invalid_package_url', provider: provider.id, package_url: provider.package_url });
    if (provider.bundled === true) issues.push({ id: 'provider_should_not_be_bundled', provider: provider.id });
  }

  const result = {
    schema_version: 'sbom-validation.v1',
    status: issues.length ? 'fail' : 'pass',
    sbom: 'SBOM.memory.json',
    providers_checked: Array.isArray(sbom.providers) ? sbom.providers.length : 0,
    bundled_provider_code: sbom.bundled_provider_code === true,
    issues
  };
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`sbom ${result.status}`);
  if (result.status !== 'pass') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const args = parseArgs(process.argv.slice(2));
    const result = { schema_version: 'sbom-validation.v1', status: 'fail', error: error.message };
    if (args.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}
