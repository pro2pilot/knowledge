#!/usr/bin/env node
'use strict';

const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const { systemVersion } = require('./lib/system-version');
const {
  listProviders,
  previewProvider,
  recordInstall,
  recordUpdate,
  setupMem0Provider,
  configureMem0Embeddings,
  writeMem0Recipe,
  validateMem0Recipe,
  uninstallProvider,
  migrateLegacy,
  statusProvider,
  buildExternalMemoryReport
} = require('./lib/memory-providers');

function print(result, json) {
  if (json) console.log(JSON.stringify(result, null, 2));
  else if (result && typeof result === 'object') {
    if (Array.isArray(result.providers)) {
      for (const provider of result.providers) {
        console.log(`${provider.id}\t${provider.layer}\t${provider.type}\t${provider.license_spdx}\t${provider.version_pin || '-'}`);
      }
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
  } else {
    console.log(String(result));
  }
}

function help() {
  return {
    schema_version: systemVersion(),
    tool: 'memory-provider.js',
    usage: 'node .knowledge/tools/memory-provider.js <command> [provider] [options] --json',
    commands: [
      { name: 'list', usage: 'node .knowledge/tools/memory-provider.js list --json' },
      { name: 'preview', usage: 'node .knowledge/tools/memory-provider.js preview mem0-oss --json' },
      { name: 'install', usage: 'node .knowledge/tools/memory-provider.js install mem0-oss --version mem0ai==2.0.4 --yes-i-reviewed-license --json' },
      { name: 'setup', usage: 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json' },
      { name: 'configure-embeddings', usage: 'node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 [--provider-scope shared|project] --json' },
      { name: 'write-recipe', usage: 'node .knowledge/tools/memory-provider.js write-recipe mem0-oss --json' },
      { name: 'validate-recipe', usage: 'node .knowledge/tools/memory-provider.js validate-recipe mem0-oss --json' },
      { name: 'status', usage: 'node .knowledge/tools/memory-provider.js status mem0-oss --json' },
      { name: 'status-all', usage: 'node .knowledge/tools/memory-provider.js status-all --json' },
      { name: 'update', usage: 'node .knowledge/tools/memory-provider.js update mem0-oss --to mem0ai==2.0.4 --yes-i-reviewed-license --json' },
      { name: 'uninstall', usage: 'node .knowledge/tools/memory-provider.js uninstall mem0-oss --json' },
      { name: 'migrate-legacy', usage: 'node .knowledge/tools/memory-provider.js migrate-legacy --json' },
      { name: 'help', usage: 'node .knowledge/tools/memory-provider.js help --json' }
    ],
    recommended_flow: 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json',
    status_report_mode: 'offline',
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  };
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const flags = parsed.flags;
  const command = parsed.positional[0] || (flags.help ? 'help' : 'list');
  const providerId = parsed.positional[1];
  if (flags.help || command === 'help') {
    const result = help();
    print(result, Boolean(flags.json));
    return result;
  }
  const context = resolveKnowledgeContext(flags);
  const options = { paidRoot: flags.paidRoot, write: true };
  let result;

  if (command === 'list') result = listProviders(context, options);
  else if (command === 'preview') result = previewProvider(context, providerId, options);
  else if (command === 'install') result = recordInstall(context, providerId, flags, options);
  else if (command === 'setup') result = setupMem0Provider(context, providerId, flags, options);
  else if (command === 'configure-embeddings') result = configureMem0Embeddings(context, providerId, flags, options);
  else if (command === 'write-recipe') result = writeMem0Recipe(context, providerId, options);
  else if (command === 'validate-recipe') result = validateMem0Recipe(context, providerId, options);
  else if (command === 'update') result = recordUpdate(context, providerId, flags, options);
  else if (command === 'uninstall') result = uninstallProvider(context, providerId, flags, options);
  else if (command === 'status') result = statusProvider(context, providerId, options);
  else if (command === 'status-all') result = buildExternalMemoryReport(context, options);
  else if (command === 'migrate-legacy') result = migrateLegacy(context, options);
  else throw new Error(`Unknown memory-provider command: ${command}`);

  print(result, Boolean(flags.json));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseCliArgs(process.argv.slice(2));
    if (parsed.flags.json) console.log(JSON.stringify({ ok: false, error: error.message }, null, 2));
    else console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = main;
