#!/usr/bin/env node
'use strict';
// Maintainer/CI Windows build only; runtime holders never compile or download.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const { spawnSync } = require('child_process');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function main() {
  const options = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    const key = process.argv[i];
    if (!['--headers', '--compiler', '--node-lib', '--output'].includes(key) || !process.argv[i + 1]) throw new Error('Explicit --headers, --compiler and --node-lib are required.');
    options[key.slice(2)] = path.resolve(process.argv[i + 1]);
  }
  if (process.platform !== 'win32' || !['x64', 'arm64'].includes(process.arch)) throw new Error('This builder requires actual Windows x64/ARM64.');
  for (const file of [path.join(options.headers || '', 'node_api.h'), options.compiler, options['node-lib']]) if (!file || !path.isAbsolute(file) || !fs.statSync(file).isFile()) throw new Error('Verified physical build inputs are required.');
  const source = path.join(__dirname, 'native/command-windows-job.c'), bytes = fs.readFileSync(source), sourceSha = sha(bytes);
  const output = options.output || path.join(__dirname, 'lib/native', `win32-${process.arch}`); fs.mkdirSync(output, { recursive: true });
  const stage = fs.mkdtempSync(path.join(output, '.command-build-')), snapshot = path.join(stage, 'command-windows-job.c'), binary = path.join(stage, 'command-windows-job.node');
  fs.writeFileSync(snapshot, bytes, { flag: 'wx' });
  const args = ['/nologo', '/LD', '/std:c11', '/W4', '/O2', '/DWIN32', '/DNAPI_VERSION=8', `/DKNOWLEDGE_COMMAND_JOB_SOURCE_SHA256=\"${sourceSha}\"`,
    `/I${options.headers}`, snapshot, '/link', `/OUT:${binary}`, options['node-lib'], 'advapi32.lib'];
  const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'TMP', 'TEMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
  const result = spawnSync(options.compiler, args, { cwd: stage, env, encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 * 1024, windowsHide: true });
  const receipt = { schema_version: 'knowledge-command-windows-build.v1', platform: process.platform, architecture: process.arch, node: process.version,
    source_sha256: sourceSha, compiler: options.compiler, arguments: args, headers: options.headers, node_lib: options['node-lib'],
    status: result.status, signal: result.signal, error: result.error ? { code: result.error.code, message: result.error.message } : null, stdout: result.stdout || '', stderr: result.stderr || '' };
  fs.writeFileSync(path.join(stage, 'BUILD.json'), JSON.stringify(receipt, null, 2) + '\n');
  if (result.error || result.status !== 0 || sha(fs.readFileSync(snapshot)) !== sourceSha || sha(fs.readFileSync(source)) !== sourceSha) throw new Error(`Build failed or source changed; retained ${stage}`);
  const artifact = fs.readFileSync(binary), manifest = { schema_version: 'knowledge-command-windows-binary.v1', platform: 'win32', architecture: process.arch,
    napi_version: 8, binary: 'command-windows-job.node', source_sha256: sourceSha, binary_sha256: sha(artifact), binary_bytes: artifact.length };
  fs.copyFileSync(binary, path.join(output, manifest.binary)); fs.writeFileSync(path.join(output, 'command-windows-job.manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  process.stdout.write(JSON.stringify({ status: 'built', output, receipt: path.join(stage, 'BUILD.json'), ...manifest }) + '\n');
}
try { main(); } catch (error) { process.stderr.write(error.stack + '\n'); process.exitCode = 1; }
