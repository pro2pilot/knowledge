#!/usr/bin/env node
'use strict';

// Maintainer/CI build only. Runtime acquisition never compiles or downloads.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function main() {
  const options = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    const name = process.argv[i];
    if (!['--headers', '--compiler', '--node-lib', '--output'].includes(name) || !process.argv[i + 1]) {
      throw new Error('Usage: node tools/build-lock-native.js --headers /absolute/include/node [--compiler /absolute/compiler] [--node-lib /absolute/node.lib] [--output /absolute/directory]');
    }
    options[name.slice(2)] = path.resolve(process.argv[i + 1]);
  }
  if (!options.headers || !fs.statSync(path.join(options.headers, 'node_api.h')).isFile()) throw new Error('Exact Node >=18 N-API headers are required.');
  if (!['linux', 'darwin', 'win32'].includes(process.platform) || !['x64', 'arm64'].includes(process.arch)) throw new Error('Unsupported platform/architecture.');
  const compiler = options.compiler || (process.platform === 'win32' ? null : '/usr/bin/cc');
  if (!compiler || !path.isAbsolute(compiler) || !fs.statSync(compiler).isFile()) throw new Error('An explicit physical compiler executable is required.');
  if (process.platform === 'win32' && !options['node-lib']) throw new Error('Windows requires the matching, verified Node import library (--node-lib).');
  const source = path.join(__dirname, 'native', 'lock-publication.c');
  const bytes = fs.readFileSync(source), sourceSha = hash(bytes);
  const output = options.output || path.join(__dirname, 'lib', 'native', `${process.platform}-${process.arch}`);
  fs.mkdirSync(output, { recursive: true });
  const work = fs.mkdtempSync(path.join(output, '.build-'));
  const snapshot = path.join(work, 'lock-publication.c');
  fs.writeFileSync(snapshot, bytes, { flag: 'wx', mode: 0o600 });
  const binary = path.join(work, 'lock-publication.node');
  const define = `KNOWLEDGE_LOCK_SOURCE_SHA256=\"${sourceSha}\"`;
  let args;
  if (process.platform === 'win32') {
    args = ['/nologo', '/LD', '/std:c11', '/W4', '/O2', '/DWIN32', '/DNAPI_VERSION=8', `/D${define}`, `/I${options.headers}`, snapshot,
      '/link', `/OUT:${binary}`, options['node-lib']];
  } else {
    args = ['-std=c11', '-Wall', '-Wextra', '-O2', '-fPIC', '-DNAPI_VERSION=8', `-D${define}`, '-I', options.headers,
      ...(process.platform === 'darwin' ? ['-bundle', '-undefined', 'dynamic_lookup'] : ['-shared']), snapshot, '-o', binary];
  }
  // Reject compiler injection from user shell variables. Windows INCLUDE/LIB
  // are the explicit developer-toolchain environment supplied by CI.
  const env = process.platform === 'win32'
    ? Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'TMP', 'TEMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]))
    : { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', TMPDIR: work };
  const started = new Date().toISOString();
  const result = spawnSync(compiler, args, { cwd: work, env, encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 * 1024, windowsHide: true });
  const receipt = {
    schema_version: 'knowledge-lock-native-build.v1', started_at: started, platform: process.platform, architecture: process.arch,
    node: process.version, napi_version: 8, compiler, arguments: args, headers: options.headers,
    source_sha256: sourceSha, source_bytes: bytes.length, status: result.status, signal: result.signal,
    error: result.error ? { code: result.error.code, message: result.error.message } : null,
    stdout: result.stdout || '', stderr: result.stderr || ''
  };
  fs.writeFileSync(path.join(work, 'BUILD.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  if (result.error || result.status !== 0 || hash(fs.readFileSync(snapshot)) !== sourceSha || hash(fs.readFileSync(source)) !== sourceSha) {
    process.stderr.write(receipt.stderr); throw new Error(`Native build failed or source changed; evidence retained at ${work}`);
  }
  const binaryBytes = fs.readFileSync(binary);
  const manifest = {
    schema_version: 'knowledge-lock-native-binary.v1', platform: process.platform, architecture: process.arch,
    napi_version: 8, source_sha256: sourceSha, binary_sha256: hash(binaryBytes), binary_bytes: binaryBytes.length, binary: 'lock-publication.node'
  };
  // A runtime package is assembled only after this command completes; no live
  // installation is used as a build destination by the release pipeline.
  fs.copyFileSync(binary, path.join(output, manifest.binary));
  fs.writeFileSync(path.join(output, 'lock-publication.manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  receipt.binary = manifest;
  fs.writeFileSync(path.join(work, 'BUILD.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ status: 'built', output, receipt: path.join(work, 'BUILD.json'), ...manifest }, null, 2)}\n`);
}
try { main(); } catch (error) { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; }
