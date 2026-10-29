'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const out = path.resolve(process.argv[2]), fixture = path.join(__dirname, 'fixtures/windows-arm64');
fs.mkdirSync(out, { recursive: true });
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const report = { schema_version: 'knowledge-audit9-windows-arm-prerequisite.v1', status: 'BLOCKED_PREREQUISITE',
  source_commit: process.env.GITHUB_SHA, workflow_run: process.env.GITHUB_RUN_ID, workflow_attempt: process.env.GITHUB_RUN_ATTEMPT,
  release_qualified: false, forced_cancellation_qualified: false,
  scope: 'Native Windows ARM kernel, Node and historical pinned addon availability only.' };
function need(value, code) { if (!value) throw new Error(code); }
function machine(bytes) {
  need(bytes.length > 64 && bytes.toString('ascii', 0, 2) === 'MZ', 'pe_dos_header_invalid');
  const offset = bytes.readUInt32LE(60);
  need(offset >= 64 && offset + 6 <= bytes.length && bytes.readUInt32LE(offset) === 0x00004550, 'pe_header_invalid');
  return bytes.readUInt16LE(offset + 4);
}
try {
  need(process.platform === 'win32' && process.arch === 'arm64', 'native_windows_arm_node_required');
  need(process.version === 'v22.17.1', 'node_version_mismatch');
  const host = JSON.parse(fs.readFileSync(path.join(out, 'HOST.json'), 'utf8').replace(/^\uFEFF/, ''));
  report.host = host;
  need(host.api_success === true && host.native_machine === 0xaa64, 'native_windows_arm_kernel_required');
  const node = fs.readFileSync(process.execPath);
  need(machine(node) === 0xaa64, 'node_pe_architecture_mismatch');
  report.runtime = { platform: process.platform, architecture: process.arch, version: process.version,
    pe_machine: machine(node), executable_sha256: hash(node) };
  const origin = JSON.parse(fs.readFileSync(path.join(fixture, 'ORIGIN.json')));
  need(origin.candidate_sha256 === '81a6d8d4daf8d3d73f4ac298297893fe40b488627d1f176f7960e5179c8cb542', 'fixture_origin_mismatch');
  need(origin.schema_version === 'knowledge-audit9-arm-fixture-origin.v1'
    && Object.keys(origin.files || {}).sort().join(',') === 'lock-publication.manifest.json,lock-publication.node', 'fixture_inventory_mismatch');
  need(origin.files['lock-publication.manifest.json'] === 'f66852c49bf8a2280166682303185c68599ba41789aed76a438d4e8453dd97a7'
    && origin.files['lock-publication.node'] === 'e866065510a925efaf9be2b6a925ee95b639566d2273ae6e35342df086e93cd3'
    && origin.source_sha256 === 'ed200e1c901cf65387188a3804380826e5cd56bca411543cd293baabbcd247d0', 'fixture_literal_pin_mismatch');
  for (const [name, digest] of Object.entries(origin.files)) {
    need(['lock-publication.node', 'lock-publication.manifest.json'].includes(name), 'fixture_name_invalid');
    need(hash(fs.readFileSync(path.join(fixture, name))) === digest, 'fixture_pin_mismatch');
  }
  const binary = fs.readFileSync(path.join(fixture, 'lock-publication.node'));
  const manifest = JSON.parse(fs.readFileSync(path.join(fixture, 'lock-publication.manifest.json')));
  need(manifest.schema_version === 'knowledge-lock-native-binary.v1' && manifest.napi_version === 8
    && manifest.source_sha256 === 'ed200e1c901cf65387188a3804380826e5cd56bca411543cd293baabbcd247d0', 'addon_source_contract_mismatch');
  need(machine(binary) === 0xaa64 && manifest.architecture === 'arm64' && manifest.platform === 'win32', 'addon_architecture_mismatch');
  need(hash(binary) === 'e866065510a925efaf9be2b6a925ee95b639566d2273ae6e35342df086e93cd3'
    && hash(binary) === manifest.binary_sha256 && binary.length === manifest.binary_bytes, 'addon_pin_mismatch');
  const info = require(path.join(fixture, 'lock-publication.node')).info();
  need(info.platform === 'win32' && info.architecture === 'arm64' && info.napi_version === 8
    && info.source_sha256 === manifest.source_sha256, 'addon_runtime_contract_mismatch');
  report.addon = { pe_machine: machine(binary), manifest, info, fixture_origin: origin };
  report.status = 'PASS_PREREQUISITE_ONLY';
} catch (error) { report.error = { code: error.message, type: error.name }; process.exitCode = 2; }
finally {
  report.probe_sha256 = hash(fs.readFileSync(__filename));
  fs.writeFileSync(path.join(out, 'RESULT.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ status: report.status, error: report.error }));
}
