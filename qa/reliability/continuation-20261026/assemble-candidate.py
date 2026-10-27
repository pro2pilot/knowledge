#!/usr/bin/env python3
"""Source-bound assembly only. Never a release/post-ZIP runtime qualification."""
import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import zipfile
from prepare import LIMIT, bounded, encoded, new_output, relative, rows, sha, verify_zip, write_new

TARGETS = {f'{label}-{arch}': (platform, arch) for label, platform in
    [('linux', 'linux'), ('windows', 'win32'), ('macos', 'darwin')] for arch in ('x64', 'arm64')}
HASH = re.compile(r'^[a-f0-9]{64}$')
COMMIT = re.compile(r'^[a-f0-9]{40}$')


def demand(condition, code):
    if not condition:
        raise ValueError(code)


def native_contract():
    result = []
    for platform in ('linux', 'darwin', 'win32'):
        for arch in ('x64', 'arm64'):
            root = f'tools/lib/native/{platform}-{arch}/'
            result.append({'platform': platform, 'architecture': arch, 'binary': root + 'lock-publication.node',
                'manifest': root + 'lock-publication.manifest.json', 'source': 'tools/native/lock-publication.c',
                'schema_version': 'knowledge-lock-native-binary.v1', 'napi_version': 8})
            if platform == 'linux':
                result.append({'platform': platform, 'architecture': arch, 'binary': root + 'verification-linux-namespace',
                    'manifest': root + 'verification-linux-namespace.manifest.json', 'source': 'tools/lib/verification-linux-namespace.c',
                    'schema_version': 'knowledge-command-native-binary.v1'})
            elif platform == 'win32':
                result.append({'platform': platform, 'architecture': arch, 'binary': root + 'command-windows-job.node',
                    'manifest': root + 'command-windows-job.manifest.json', 'source': 'tools/native/command-windows-job.c',
                    'schema_version': 'knowledge-command-windows-binary.v1', 'napi_version': 8})
    return sorted(result, key=lambda item: item['binary'])


def binary_architecture(body, platform, arch):
    """Independently check the native file header, not only its JSON label."""
    demand(len(body) >= 64, 'native_header_truncated')
    if platform == 'linux':
        demand(body[:4] == b'\x7fELF' and body[4:6] == b'\x02\x01', 'native_header_not_elf64_le')
        demand(int.from_bytes(body[18:20], 'little') == {'x64': 62, 'arm64': 183}[arch], 'native_elf_architecture_mismatch')
    elif platform == 'win32':
        demand(body[:2] == b'MZ', 'native_header_not_pe')
        offset = int.from_bytes(body[60:64], 'little')
        demand(64 <= offset <= len(body) - 24 and body[offset:offset+4] == b'PE\0\0', 'native_pe_header_invalid')
        demand(int.from_bytes(body[offset+4:offset+6], 'little') == {'x64': 0x8664, 'arm64': 0xaa64}[arch], 'native_pe_architecture_mismatch')
    else:
        demand(body[:4] == b'\xcf\xfa\xed\xfe', 'native_header_not_thin_macho64_le')
        demand(int.from_bytes(body[4:8], 'little') == {'x64': 0x01000007, 'arm64': 0x0100000c}[arch], 'native_macho_architecture_mismatch')


class Inputs:
    def __init__(self):
        self.pins = {}
        self.total = 0

    def read(self, file, maximum=LIMIT):
        file = Path(file).absolute()
        body = bounded(file, maximum)
        value = {'bytes': len(body), 'sha256': sha(body)}
        if file in self.pins:
            demand(self.pins[file] == value, 'input_changed_during_assembly')
        else:
            self.total += len(body)
            demand(self.total <= 512 * 1024 * 1024 and len(self.pins) < 20000, 'evidence_input_budget_exceeded')
            self.pins[file] = value
        return body

    def json(self, file, maximum=8 * 1024 * 1024):
        return json.loads(self.read(file, maximum))

    def inventory(self, root):
        root = Path(root).absolute()
        inventory = self.json(root / 'SHA256SUMS.json')
        demand(isinstance(inventory, dict) and 1 <= len(inventory) <= 8192, 'public_inventory_invalid')
        actual = set()
        for file in root.rglob('*'):
            demand(not file.is_symlink(), 'public_inventory_symlink')
            if file.is_file():
                actual.add(file.relative_to(root).as_posix())
            else:
                demand(file.is_dir(), 'public_inventory_nonregular')
        demand(actual == set(inventory) | {'SHA256SUMS.json'}, 'public_inventory_membership_mismatch')
        for name, expected in inventory.items():
            relative(name)
            demand(name != 'SHA256SUMS.json' and isinstance(expected, dict) and
                type(expected.get('bytes')) is int and 0 <= expected['bytes'] <= LIMIT and
                HASH.fullmatch(expected.get('sha256', '')), 'public_inventory_row_invalid')
            body = self.read(root / name)
            demand(expected == {'bytes': len(body), 'sha256': sha(body)}, 'public_inventory_hash_mismatch')
        return root

    def verify_again(self):
        for file, expected in list(self.pins.items()):
            body = bounded(file)
            demand(expected == {'bytes': len(body), 'sha256': sha(body)}, 'input_changed_after_validation')


def qualification_contract(inputs, file, diagnostic):
    # This is a separately supplied expectation, never inferred from the result
    # being verified or the mutable checkout that happens to run this assembler.
    demand(diagnostic or file is not None, 'explicit_qualification_contract_required')
    if file is None:
        return None
    contract = inputs.json(file, 1024 * 1024)
    demand(isinstance(contract, dict) and contract.get('schema_version') == 'knowledge-assembly-ci-contract.v1' and
        HASH.fullmatch(contract.get('controller_sha256', '')) and
        HASH.fullmatch(contract.get('extra_case_policy_sha256', '')) and
        isinstance(contract.get('targets'), dict) and set(contract['targets']) == set(TARGETS), 'qualification_contract_invalid')
    for key, (platform, _) in TARGETS.items():
        row = contract['targets'][key]
        demand(isinstance(row, dict) and row.get('phase') in {'diagnostic', 'full'} and
            row.get('macos_cohort') in {'combined', 'basic', 'failures', 'writable', 'writer-sandbox', 'physical'}, 'qualification_target_invalid')
        steps = row.get('required_steps')
        demand(isinstance(steps, list) and 3 <= len(steps) <= 128 and
            all(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,100}', name) for name in steps) and
            len(steps) == len(set(steps)) and steps[0] == 'host' and 'report-generation' in steps and
            ('native-build' if platform == 'darwin' else 'native-runtime') in steps, 'qualification_steps_invalid')
        if not diagnostic:
            demand(row['phase'] == 'full', 'qualification_requires_full_phase')
            if platform == 'darwin':
                demand(row['macos_cohort'] in {'combined', 'physical'} and
                    {'macos-physical', 'macos-physical-summary'} <= set(steps),
                    'qualification_requires_macos_physical_steps')
    return contract


def verify_qualification(outer, key, contract, diagnostic):
    steps = outer.get('steps')
    demand(isinstance(steps, list) and bool(steps) and all(isinstance(row, dict) for row in steps), 'evidence_steps_missing')
    names = [row.get('name') for row in steps]
    demand(all(isinstance(name, str) for name in names) and len(names) == len(set(names)), 'evidence_step_names_invalid')
    demand(all(row.get('status') in {'PASS', 'FAIL'} for row in steps), 'evidence_step_status_invalid')
    if contract is not None:
        expected = contract['targets'][key]
        demand(outer.get('controller_sha256') == contract['controller_sha256'] and
            outer.get('extra_case_policy_sha256') == contract['extra_case_policy_sha256'] and
            outer.get('phase') == expected['phase'] and outer.get('macos_cohort') == expected['macos_cohort'],
            'evidence_controller_policy_or_phase_mismatch')
        required = expected['required_steps']
        # A controller can stop early on a real diagnostic failure. Such a
        # partial record must still be the exact ordered prefix of the fixed
        # expectation; it cannot invent, reorder, or silently skip steps.
        demand(names == (required[:len(names)] if diagnostic else required), 'evidence_required_steps_mismatch')
    all_pass = all(row.get('status') == 'PASS' for row in steps)
    if not diagnostic:
        demand(outer['status'] == 'PASS_SCOPED_CONTINUATION' and all_pass and not outer.get('failure_type'),
            'scoped_runtime_qualification_incomplete')
        demand(all(row.get('exit_code') == 0 and row.get('timed_out') is False and
            row.get('cleanup_unconfirmed') is False and not row.get('failure') and not row.get('failure_type')
            for row in steps), 'scoped_runtime_step_completion_unconfirmed')
    return all_pass


def gather(prepared, evidence, expected_commit, diagnostic=False, qualification_blocker='', qualification_contract_file=None):
    demand(COMMIT.fullmatch(expected_commit or ''), 'expected_commit_required')
    demand(set(evidence) == set(TARGETS), 'exact_six_evidence_keys_required')
    demand(not diagnostic or isinstance(qualification_blocker, str) and 0 < len(qualification_blocker.strip()) <= 2048,
        'diagnostic_mode_requires_qualification_blocker')
    demand(diagnostic or not qualification_blocker, 'blocker_requires_explicit_diagnostic_mode')
    inputs = Inputs()
    qualification = qualification_contract(inputs, qualification_contract_file, diagnostic)
    manifest_bytes = inputs.read(Path(prepared) / 'SOURCE_MANIFEST.json', 8 * 1024 * 1024)
    manifest = json.loads(manifest_bytes)
    source_files = verify_zip(inputs.read(Path(prepared) / 'SOURCE.zip'), manifest)
    expected_source = {name: row['sha256'] for name, row in rows(manifest).items()}
    demand(inputs.json(Path(prepared) / 'SOURCE_PINS.json') == {'files': expected_source}, 'prepared_source_pins_mismatch')
    install = json.loads(source_files['install-manifest.json'][0])
    contract = native_contract()
    demand(sorted(install['release_contract']['native_runtime_artifacts'], key=lambda item: item['binary']) == contract,
        'exact_ten_pair_native_contract_required')
    demand(not any(name.startswith('tools/lib/native/') for name in source_files), 'frozen_source_contains_runtime_native_bytes')
    native_files, receipts = {}, []
    for key, (platform, arch) in TARGETS.items():
        directory = inputs.inventory(evidence[key])
        outer_bytes = inputs.read(directory / 'RESULT.json')
        outer = json.loads(outer_bytes)
        runtime = {'platform': platform, 'arch': arch, 'node': 'v22.17.1'}
        demand(outer.get('schema_version') == 'knowledge-continuation-ci.v1' and outer.get('commit') == expected_commit and
            outer.get('platform') == platform and outer.get('architecture') == arch and outer.get('runtime') == runtime,
            'evidence_host_runtime_or_commit_mismatch')
        demand(outer.get('source_zip_sha256') == manifest['archive_sha256'] and outer.get('source_manifest_sha256') == sha(manifest_bytes) and
            outer.get('source_file_count') == len(source_files) and outer.get('source_after_unchanged') is True and
            outer.get('runtime_source_after_unchanged') is True, 'evidence_source_binding_or_readback_mismatch')
        demand(outer.get('status') in {'PASS_SCOPED_CONTINUATION', 'FAIL_OR_INCOMPLETE'}, 'evidence_not_final')
        all_steps_pass = verify_qualification(outer, key, qualification, diagnostic)
        receipt = {'target': key, 'commit': expected_commit, 'result_sha256': sha(outer_bytes), 'reported_status': outer['status'],
            'all_reported_steps_pass': all_steps_pass, 'macos_cohort': outer.get('macos_cohort'),
            'phase': outer.get('phase'), 'controller_sha256': outer.get('controller_sha256'),
            'extra_case_policy_sha256': outer.get('extra_case_policy_sha256'),
            'explicit_qualification_contract_checked': qualification is not None,
            'reported_step_names': [row['name'] for row in outer['steps']],
            'expected_steps_fully_present': ([row['name'] for row in outer['steps']] ==
                qualification['targets'][key]['required_steps']) if qualification is not None else None,
            'source_zip_sha256': manifest['archive_sha256'], 'native_files': {}}
        if platform == 'darwin':
            native_root = directory / 'native' / key
            build_bytes = inputs.read(native_root / 'BUILD.json')
            build = json.loads(build_bytes)
            demand(build.get('schema') == 'knowledge-reliability-native-build.v1' and build.get('status') == 'PASS_COMPILE_AND_LOAD' and
                build.get('commit') == expected_commit and build.get('runtime') == runtime and build.get('source_pins') == {'files': expected_source},
                'macos_build_source_host_or_commit_mismatch')
            demand(any(row.get('name') == 'native-build' and row.get('status') == 'PASS' for row in outer['steps']), 'macos_build_step_not_passed')
            receipt['build_receipt_sha256'] = sha(build_bytes)
            receipt['native_evidence_scope'] = 'compile and loader smoke; reported outer scoped tests are separate evidence'
            receipt['separate_native_support_files'] = {}
            for name in ('verification-darwin-broker', 'verification-darwin-stub'):
                body = inputs.read(native_root / name, 16 * 1024 * 1024)
                demand(build['binaries'].get(f'native/darwin-{arch}/' + name) == sha(body), 'macos_support_build_pin_mismatch')
                binary_architecture(body, platform, arch)
                receipt['separate_native_support_files'][name] = {'bytes': len(body), 'sha256': sha(body),
                    'included_in_installer_native20': False, 'runtime_qualification': False}
        else:
            inner_bytes = inputs.read(directory / 'native-runtime/RESULT.json')
            inner = json.loads(inner_bytes)
            demand(inner.get('schema_version') == 'knowledge-native-runtime-qa.v1' and inner.get('commit') == expected_commit and
                inner.get('source_zip_sha256') == manifest['archive_sha256'] and
                inner.get('runtime', {}).get('platform') == platform and inner['runtime'].get('architecture') == arch and
                inner['runtime'].get('node') == 'v22.17.1', 'native_qa_source_host_or_commit_mismatch')
            demand(inner.get('native_artifacts_unchanged_after_tests') is True and inner.get('source_changes_during_build_and_tests') == [] and
                inner.get('native_after_build') == inner.get('native_after_tests'), 'native_qa_after_test_readback_unconfirmed')
            demand(inner.get('status') in {'PASS_SCOPED_NATIVE_RUNTIME', 'FAIL'}, 'native_qa_not_final')
            if not diagnostic:
                demand(inner['status'] == 'PASS_SCOPED_NATIVE_RUNTIME', 'native_qa_runtime_qualification_incomplete')
            native_root = directory / 'native-runtime/native' / f'{platform}-{arch}'
            receipt['native_qa_receipt_sha256'] = sha(inner_bytes)
            receipt['native_qa_reported_status'] = inner['status']
            receipt['native_evidence_scope'] = 'native build and exact after-test readback; failures are not qualification'
        for expected in [item for item in contract if item['platform'] == platform and item['architecture'] == arch]:
            pair = {}
            for field in ('binary', 'manifest'):
                name = expected[field]
                demand(name not in native_files, 'duplicate_native_destination')
                body = inputs.read(native_root / Path(name).name, 16 * 1024 * 1024)
                if platform == 'darwin':
                    demand(build['binaries'].get(f'native/darwin-{arch}/' + Path(name).name) == sha(body), 'macos_export_build_pin_mismatch')
                else:
                    observed = inner['native_after_tests'].get(Path(name).name, {})
                    demand(observed.get('sha256') == sha(body) and observed.get('bytes') == len(body), 'native_export_after_test_pin_mismatch')
                pair[field] = body
                mode = '0755' if name.endswith('/verification-linux-namespace') else '0644'
                native_files[name] = (body, mode)
                receipt['native_files'][name] = {'bytes': len(body), 'sha256': sha(body), 'package_mode': mode}
            record = json.loads(pair['manifest'])
            demand(record.get('schema_version') == expected['schema_version'] and record.get('platform') == platform and
                record.get('architecture') == arch and record.get('binary') == Path(expected['binary']).name and
                record.get('source_sha256') == sha(source_files[expected['source']][0]) and
                record.get('binary_sha256') == sha(pair['binary']) and record.get('binary_bytes') == len(pair['binary']) and
                ('napi_version' not in expected or record.get('napi_version') == expected['napi_version']), 'native_manifest_source_binary_or_schema_mismatch')
            binary_architecture(pair['binary'], platform, arch)
        receipts.append(receipt)
    demand(len(native_files) == 20, 'exact_twenty_native_files_required')
    demand(sum(len(value[0]) for value in list(source_files.values()) + list(native_files.values())) <= LIMIT, 'combined_package_source_budget_exceeded')
    return inputs, manifest, source_files, native_files, receipts


VERIFY_SCRIPT = r"""
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const [root,zip,replay]=process.argv.slice(1),pack=require(path.join(root,'tools/package-release.js'));
const validator=require(path.join(root,'tools/validate-release-artifact.js'));
const mode=require(path.join(root,'tools/lib/runtime-file-mode.js')).runtimeFileMode;
const entries=pack.buildPackageEntries(root).entries;
pack.createZip(entries,replay);
console.log(JSON.stringify({runtime:{node:process.version,platform:process.platform,arch:process.arch},
 physical:validator.validate(zip),replay_physical:validator.validate(replay),
 expected:entries.map(entry=>{const bytes=pack.readEntryData(entry);return {path:entry.name,bytes:bytes.length,
 sha256:crypto.createHash('sha256').update(bytes).digest('hex'),mode:mode(entry.name).toString(8).padStart(4,'0')}})}));
"""


def assemble(prepared, evidence, expected_commit, out, diagnostic=False, qualification_blocker='', qualification_contract_file=None):
    inputs, manifest, source_files, native_files, receipts = gather(prepared, evidence, expected_commit, diagnostic, qualification_blocker, qualification_contract_file)
    inputs.verify_again()
    output = new_output(out)
    private = output / 'private';private.mkdir(mode=0o700)
    source = private / 'source/.knowledge'
    all_files = {**source_files, **native_files}
    for name, (body, mode) in sorted(all_files.items()):
        file = source / name;write_new(file, body);file.chmod(int(mode, 8))
    package = json.loads(source_files['package.json'][0])
    version = package.get('version', '')
    demand(re.fullmatch(r'\d+\.\d+\.\d+(?:-rc\d+)?', version), 'package_version_invalid')
    filename = 'knowledge-v' + version + '.zip'
    canonical = private / filename
    replay = private / 'replay' / filename
    env = {key: value for key, value in os.environ.items() if not key.startswith(('KNOWLEDGE_', 'NODE_'))}
    env.update({'TMPDIR': str(private), 'TMP': str(private), 'TEMP': str(private)})
    node = shutil.which('node');demand(bool(node), 'node_packager_unavailable')
    def run(name, command):
        result = subprocess.run(command, cwd=source, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        demand(len(result.stdout) <= 8 * 1024 * 1024 and len(result.stderr) <= 1024 * 1024, 'packager_output_limit')
        write_new(private / (name + '.stdout.log'), result.stdout);write_new(private / (name + '.stderr.log'), result.stderr)
        demand(result.returncode == 0, name + '_failed')
        return json.loads(result.stdout)
    packaged = run('package', [node, str(source / 'tools/package-release.js'), '--out', str(canonical), '--json'])
    demand(packaged.get('status') == 'ok' and packaged.get('errors') == [], 'canonical_packager_rejected_candidate')
    checked = run('verify', [node, '-e', VERIFY_SCRIPT, str(source), str(canonical), str(replay)])
    demand(checked['physical'].get('status') == 'ok' and checked['replay_physical'].get('status') == 'ok', 'physical_zip_validation_failed')
    archive = bounded(canonical)
    demand(archive == bounded(replay), 'canonical_zip_not_reproducible')
    expected = {row['path']: row for row in checked['expected']}
    demand(len(expected) == len(checked['expected']), 'packaged_inventory_duplicate')
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        infos = zipped.infolist()
        demand(len(infos) == len(expected) and {item.filename for item in infos} == set(expected), 'final_zip_membership_mismatch')
        packaged_native = {item.filename for item in infos if item.filename.startswith('.knowledge/tools/lib/native/')}
        demand(packaged_native == {'.knowledge/' + name for name in native_files}, 'final_zip_native20_membership_mismatch')
        for item in infos:
            demand(item.filename.startswith('.knowledge/'), 'final_zip_root_mismatch')
            relative(item.filename[len('.knowledge/'):])
            data = zipped.read(item)
            row = expected[item.filename]
            mode = item.external_attr >> 16
            demand(stat.S_ISREG(mode) and stat.S_IMODE(mode) == int(row['mode'], 8) and not item.flag_bits & 1 and
                len(data) == row['bytes'] and sha(data) == row['sha256'], 'final_zip_bytes_or_mode_mismatch')
            if item.filename in packaged_native:
                demand(data == native_files[item.filename[len('.knowledge/'):]][0], 'final_zip_native_bytes_mismatch')
        demand(zipped.testzip() is None, 'final_zip_crc_mismatch')
    for name, (body, mode) in all_files.items():
        demand(bounded(source / name) == body, 'staged_source_or_native_changed_during_packaging')
    inputs.verify_again()
    delivered_name = ('NOT-QUALIFIED-' if diagnostic else '') + filename
    write_new(output / delivered_name, archive)
    demand(bounded(output / delivered_name) == archive, 'delivered_zip_readback_mismatch')
    inventory = {'schema_version': 'knowledge-candidate-package-inventory.v1', 'files': checked['expected'],
        'archive_sha256': sha(archive), 'archive_bytes': len(archive)}
    write_new(output / 'PACKAGE_INVENTORY.json', encoded(inventory))
    report = {'schema_version': 'knowledge-source-bound-assembly.v1',
        'status': 'NOT_QUALIFIED_DIAGNOSTIC_ASSEMBLY' if diagnostic else 'ASSEMBLED_SOURCE_BOUND_CANDIDATE',
        'created_utc': datetime.now(timezone.utc).isoformat(), 'expected_commit': expected_commit,
        'source_zip_sha256': manifest['archive_sha256'], 'source_file_count': len(source_files),
        'candidate_file': delivered_name, 'candidate_sha256': sha(archive), 'candidate_bytes': len(archive),
        'diagnostic_filename_not_release_asset': diagnostic, 'qualification_blocker': qualification_blocker if diagnostic else None,
        'qualification_contract_sha256': sha(inputs.read(qualification_contract_file)) if qualification_contract_file is not None else None,
        'native_pairs': 10, 'native_files': 20, 'source_bound_evidence': receipts,
        'assembly_runtime': checked['runtime'], 'physical_zip_bytes_validated_under_canonical_filename': True,
        'deterministic_second_build_matches': True, 'input_and_staged_source_readback': 'PASS',
        'delivered_zip_fresh_readback': 'PASS', 'installer_native20_exact_membership_and_bytes': True,
        'macos_broker_and_stub_are_separate_support_evidence': True,
        'native_compile_binding_is_runtime_qualification': False, 'post_zip_runtime_qualification': 'NOT_RUN',
        'release_gate_qualified': False, 'release_ready': False,
        'scope': 'Local assembly and exact provenance only. No release publication, tag, production approval, or new native execution.'}
    write_new(output / 'ASSEMBLY.json', encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', required=True)
    parser.add_argument('--evidence', action='append', required=True, metavar='TARGET=PUBLIC_DIRECTORY')
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--diagnostic-unqualified', action='store_true')
    parser.add_argument('--qualification-blocker', default='')
    parser.add_argument('--qualification-contract', help='Explicit expected controller, policy, phase and ordered six-target step contract; required outside diagnostic mode')
    args = parser.parse_args()
    evidence = {}
    for value in args.evidence:
        key, separator, directory = value.partition('=')
        demand(separator and key in TARGETS and directory and key not in evidence, 'invalid_or_duplicate_evidence_key')
        evidence[key] = directory
    report = assemble(args.prepared, evidence, args.expected_commit, args.out, args.diagnostic_unqualified, args.qualification_blocker, args.qualification_contract)
    print(json.dumps({key: report[key] for key in ('status', 'candidate_file', 'candidate_sha256', 'native_pairs', 'post_zip_runtime_qualification', 'release_gate_qualified')}))


if __name__ == '__main__':
    main()
