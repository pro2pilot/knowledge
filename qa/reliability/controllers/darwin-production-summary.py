#!/usr/bin/env python3
"""Strict public evidence for the normal production gate; raw stays private."""
import argparse, hashlib, json, math, os, re
from pathlib import Path

HEX = re.compile(r'^[a-f0-9]{64}$')
FILES = {'darwin-production-lifecycle.py', 'run_pipeline4.py', 'external-frame'}
TYPES = {'QAError', 'FileNotFoundError', 'PermissionError', 'TypeError', 'AttributeError', 'KeyError', 'ValueError',
    'OSError', 'TimeoutExpired', 'RuntimeError', 'ImportError', 'ModuleNotFoundError', 'SyntaxError', 'UnknownException'}
PHASES = {'input', 'public-run', 'finalization-reader', 'complete'}
FAILURES = set('runner_architecture_mismatch runtime_copy_pin_mismatch node_version_failed node_version_invalid '
    'node_checksums_oversized node_headers_checksum_missing node_headers_checksum_mismatch node_headers_archive_unsafe '
    'node_headers_archive_truncated native_addon_build_failed native_addon_pin_mismatch ordinary_owner_required '
    'installed_binary_pin_mismatch normal_install_failed normal_daemon_not_observed normal_daemon_birth_unconfirmed '
    'normal_socket_unavailable normal_mode_not_admissible normal_registry_unreadable duplicate_production_result '
    'public_production_normal_failed project_source_mutated normal_service_exit_unconfirmed normal_daemon_exit_unconfirmed '
    'normal_UID_cleanup_unconfirmed source_changed compile_shipping_broker_failed compile_shipping_stub_failed '
    'stub_pair_mismatch_shipping uid_scan_compile_failed birth_observer_compile_failed protected_install_parent_unavailable '
    'install_parent_creation_unconfirmed public_writer_cleanup_unconfirmed_preserve_fixture'.split())
STAGES = set('node-version node-exec-path node-system-dylibs compile-lock-addon compile-uid-scan compile-birth-observer '
    'canonical-roots-must-be-absent init-production bootstrap-production capture-production-daemon probe-production '
    'read-production-registry public-production-normal bootout-production post-stop-production-uid '
    'verify-owned-canonical-inodes remove-owned-canonical-inodes verify-owned-fixture remove-owned-fixture '
    'protect-fixture mode-fixture launchctl-print-own-label launchctl-verify-own-label-absent compare-native-process-birth '
    'ensure-protected-install-parent remove-created-install-parent'.split())


def digest(value): return value if isinstance(value, str) and HEX.fullmatch(value) else None
def number(value): return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
def boolean(value): return value if type(value) is bool else None
def exit_code(value): return value if type(value) is int and -255 <= value <= 255 else None
def sha(data): return hashlib.sha256(data).hexdigest()
def compile_excerpt(data, private, source):
    text = data[:32768].decode('utf8', errors='replace')
    for old, new in ((str(private), '<private-evidence>'), (str(source), '<pinned-source>'),
        (os.environ.get('GITHUB_WORKSPACE', ''), '<workspace>'), (os.environ.get('RUNNER_TEMP', ''), '<runner-temp>')):
        if old: text = text.replace(old, new)
    text = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b', '<redacted-token>', text)
    text = re.sub(r'\b[a-fA-F0-9]{24,128}\b', '<opaque-hex>', text)
    return '\n'.join(line[:300] for line in text.splitlines()[:8])[:1600]
def load(path, maximum=16*1024*1024):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum: return {}
        value = json.loads(path.read_bytes());return value if isinstance(value, dict) else {}
    except (OSError, ValueError): return {}


def error_codes(source):
    # Only enum-shaped literals in the exact publicly supplied first-party
    # source are eligible, never arbitrary error messages or payload output.
    codes = {'ERR_ASSERTION', 'controller_assertion_failed'}
    for name in ('verification-darwin-production.js', 'verification-darwin-preparation.js', 'verification-darwin-preparer.js',
        'verification-darwin-session.js', 'verification-darwin-session-protocol.js', 'verification-darwin-client.js',
        'verification-darwin-control.js', 'verification-darwin-finalization.js', 'verification-darwin-store.js',
        'verification-control.js', 'verification-finalization.js', 'verification-execution.js', 'lock-publication.js'):
        p = source/'tools/lib'/name
        if p.is_file() and not p.is_symlink():
            codes.update(re.findall(r"['\"]((?:verification_|native_lock_)[A-Za-z0-9_]{1,100})['\"]", p.read_text()))
    native = source/'tools/lib/verification-darwin-broker.m'
    if native.is_file() and not native.is_symlink(): codes.update(re.findall(r'@"([A-Z][A-Z0-9_]{2,100})"', native.read_text()))
    protected = source/'tools/native/lock-publication.c'
    if protected.is_file() and not protected.is_symlink(): codes.update(re.findall(r'"(darwin_protected_[a-z_]{1,80})"', protected.read_text()))
    return codes


def input_inventory_valid(source, rows):
    if not isinstance(rows, list) or not rows: return False
    expected = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256', 'executable'}: return False
        name = row['path'];parts = Path(name) if isinstance(name, str) else None
        if parts is None or parts.is_absolute() or '..' in parts.parts or '\\' in name or len(parts.parts) < 2 or \
            parts.parts[0] != source.name or name in expected or type(row['bytes']) is not int or row['bytes'] < 0 or \
            type(row['executable']) is not bool or not digest(row['sha256']): return False
        expected[name] = row
    actual = {}
    try:
        for base, dirs, files in os.walk(source, followlinks=False):
            if any((Path(base)/name).is_symlink() for name in dirs): return False
            for name in files:
                file = Path(base)/name;st = file.lstat()
                if file.is_symlink() or not file.is_file() or st.st_nlink != 1: return False
                data = file.read_bytes();key = file.relative_to(source.parent).as_posix()
                actual[key] = {'path': key, 'bytes': len(data), 'sha256': sha(data), 'executable': bool(st.st_mode & 0o111)}
    except OSError: return False
    return actual == expected


def build(private, source, controller_status, architecture):
    raw = load(private/'SUMMARY.json');inputs = load(private/'INPUTS.json', 4*1024*1024)
    fallback = load(private/'DIAGNOSTIC.json', 65536);codes = error_codes(source)
    cases = []
    for item in raw.get('cases', []) if isinstance(raw.get('cases'), list) else []:
        if not isinstance(item, dict) or item.get('name') != 'normal': continue
        terminal = item.get('terminal') if isinstance(item.get('terminal'), dict) else {}
        err = terminal.get('error') if isinstance(terminal.get('error'), dict) else {}
        containment = err.get('containment') if isinstance(err.get('containment'), dict) else {}
        cases.append({'name': 'normal', 'status': item.get('status') if item.get('status') in ('PASS_PHYSICAL_PRODUCTION', 'FAIL') else 'UNCONFIRMED',
            'elapsed_ms': number(item.get('elapsed_ms')), 'controller_exit_code': exit_code(item.get('controller_exit_code')),
            'KVE_KVF_ACK_verified': boolean(item.get('KVE_KVF_ACK_verified')), 'phase': terminal.get('stage') if terminal.get('stage') in PHASES else 'unknown',
            'success': boolean(terminal.get('success')), 'error_code': terminal.get('error_code') if terminal.get('error_code') in codes else None,
            'containment_reason': containment.get('reason') if containment.get('reason') in codes else None,
            'stdout_sha256': digest(item.get('stdout_sha256')), 'stderr_sha256': digest(item.get('stderr_sha256'))})
    diagnostics = []
    values = raw.get('diagnostics', fallback.get('diagnostics', []))
    for item in values[:4] if isinstance(values, list) else []:
        if not isinstance(item, dict): continue
        frames = []
        for frame in item.get('frames', [])[:16] if isinstance(item.get('frames'), list) else []:
            if isinstance(frame, dict) and frame.get('file') in FILES and type(frame.get('line')) is int and 0 < frame['line'] < 1000000:
                frames.append({'file': frame['file'], 'line': frame['line']})
        diagnostics.append({'type': item.get('type') if item.get('type') in TYPES else 'UnknownException',
            'stage': item.get('stage') if item.get('stage') in ('execute', 'cleanup', 'bootstrap') else 'unknown', 'frames': frames})
    stages = [];compiler_diagnostics = []
    for item in raw.get('records', []) if isinstance(raw.get('records'), list) else []:
        if not isinstance(item, dict): continue
        name = item.get('name');match = re.fullmatch(r'(\d{3,6})-(.+)', name or '')
        if not match: continue
        suffix = match[2]
        known = suffix in STAGES or re.fullmatch(r'(?:create|identify)-canonical-(?:registry|allocator|anchors|workspaces|control)', suffix) or \
            re.fullmatch(r'(?:mkdir|chown|chmod)-(?:bin|runtime|logs|launchd)', suffix) or \
            re.fullmatch(r'install-production-(?:broker|stub|node|plist)', suffix) or \
            re.fullmatch(r'(?:compile|describe)-shipping-\d{2}-(?:broker|stub)', suffix)
        stages.append({'stage': name if known else match[1]+'-unclassified-stage', 'stage_name_sha256': sha(name.encode()),
            'exit_code': exit_code(item.get('exit_code')), 'timed_out': boolean(item.get('timed_out')),
            'elapsed_ms': number(item.get('elapsed_ms')), 'stdout_sha256': digest(item.get('stdout_sha256')), 'stderr_sha256': digest(item.get('stderr_sha256'))})
        if known and re.fullmatch(r'compile-(?:lock-addon|uid-scan|birth-observer|shipping-\d{2}-(?:broker|stub))', suffix):
            stderr = private/(name+'.stderr.raw')
            if stderr.is_file() and not stderr.is_symlink() and stderr.stat().st_size <= 4*1024*1024:
                compiler_diagnostics.append({'stage': name, 'stderr_excerpt': compile_excerpt(stderr.read_bytes(), private, source)})
    binaries = []
    for item in raw.get('binary_history', []) if isinstance(raw.get('binary_history'), list) else []:
        if not isinstance(item, dict): continue
        binaries.append({**{key: digest(item.get(key)) for key in ('broker_sha256', 'stub_sha256', 'source_sha256', 'stub_source_sha256')},
            'kind': 'shipping' if item.get('kind') == 'shipping' else 'unknown', 'qa_io_enabled': boolean(item.get('qa_io_enabled'))})
    addon = raw.get('native_addon') if isinstance(raw.get('native_addon'), dict) else {}
    source_rows = inputs.get('files') if isinstance(inputs.get('files'), list) else []
    valid_inputs = input_inventory_valid(source, source_rows) and all(digest(inputs.get(key)) for key in
        ('controller_sha256', 'lifecycle_sha256', 'reference_runner_sha256'))
    actual_arch = 'x64' if architecture == 'x86_64' else 'arm64'
    passed = controller_status == 0 and raw.get('status') == 'PASS_PHYSICAL_PRODUCTION_NORMAL' and raw.get('source_unchanged') is True and \
        raw.get('cleanup_confirmed') is True and raw.get('architecture') == architecture and len(cases) == 1 and \
        cases[0]['status'] == 'PASS_PHYSICAL_PRODUCTION' and cases[0]['success'] is True and cases[0]['KVE_KVF_ACK_verified'] is True and \
        len(binaries) == 1 and binaries[0]['kind'] == 'shipping' and binaries[0]['qa_io_enabled'] is False and \
        all(binaries[0][key] for key in ('broker_sha256', 'stub_sha256', 'source_sha256', 'stub_source_sha256')) and \
        digest(addon.get('source_sha256')) and digest(addon.get('binary_sha256')) and \
        addon.get('platform') == 'darwin' and addon.get('architecture') == actual_arch and valid_inputs
    manifest_sha = sha(json.dumps(source_rows, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()) if source_rows else None
    summary = {'schema': 'knowledge-darwin-production-public.v1', 'status': 'PASS_PRODUCTION_NORMAL_GATE' if passed else 'FAIL_OR_INCOMPLETE',
        'controller_exit_code': controller_status, 'architecture': raw.get('architecture') if raw.get('architecture') in ('x86_64', 'arm64') else None,
        'expected_architecture': architecture, 'source_unchanged': boolean(raw.get('source_unchanged')), 'cleanup_confirmed': boolean(raw.get('cleanup_confirmed')),
        'exact_source_inventory_verified': bool(valid_inputs),
        'source_manifest_sha256': manifest_sha, 'source_manifest_file_count': len(source_rows),
        'controller_sha256': digest(inputs.get('controller_sha256')), 'lifecycle_sha256': digest(inputs.get('lifecycle_sha256')),
        'reference_runner_sha256': digest(inputs.get('reference_runner_sha256')), 'cases': cases, 'compiled_pairs': binaries,
        'native_addon': {key: digest(addon.get(key)) for key in ('source_sha256', 'binary_sha256')}, 'diagnostics': diagnostics,
        'compiler_diagnostics': compiler_diagnostics,
        'failure_code': raw.get('failure') if raw.get('failure') in FAILURES else ('private_failure' if raw.get('failure') else None),
        'workflow_commit': os.environ.get('GITHUB_SHA') if re.fullmatch('[a-f0-9]{40}', os.environ.get('GITHUB_SHA', '')) else None,
        'workflow_run_id': os.environ.get('GITHUB_RUN_ID') if re.fullmatch('[0-9]+', os.environ.get('GITHUB_RUN_ID', '')) else None,
        'release_gate_qualified': False, 'scope': 'Normal public KVE/KVF/ACK only; independent stop and other failures remain separately qualified.',
        'raw_evidence_scope': 'runner-private; tokens, raw native replies, account/host identifiers, paths and payload output excluded'}
    parent = raw.get('installation_parent') if isinstance(raw.get('installation_parent'), dict) else {}
    summary['installation_parent'] = {key: boolean(parent.get(key)) for key in
        ('ok', 'created', 'removed', 'exists_before', 'directory_before', 'symlink_before', 'root_owned_before')}
    summary['installation_parent']['errno'] = parent.get('errno') if type(parent.get('errno')) is int and 0 < parent['errno'] < 4096 else None
    summary['installation_parent']['mode_before'] = parent.get('mode_before') if type(parent.get('mode_before')) is int and 0 <= parent['mode_before'] <= 0o7777 else None
    return summary, {'schema': 'knowledge-darwin-production-public-stages.v1', 'stages': stages}


def main():
    ap = argparse.ArgumentParser();ap.add_argument('--private', required=True);ap.add_argument('--public', required=True)
    ap.add_argument('--source', required=True);ap.add_argument('--controller-status', type=int, required=True)
    ap.add_argument('--expected-arch', choices=('x86_64', 'arm64'), required=True);args = ap.parse_args()
    private = Path(args.private).resolve();public = Path(args.public).resolve();source = Path(args.source).resolve()
    if public == private or public.is_relative_to(private) or private.is_relative_to(public): raise SystemExit('public_private_overlap')
    summary, stages = build(private, source, args.controller_status, args.expected_arch)
    public.mkdir(mode=0o755, parents=True, exist_ok=False)
    for name, value in (('summary.json', summary), ('stages.json', stages)):
        p = public/name;p.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n');p.chmod(0o644)
    print(json.dumps({'status': summary['status'], 'public_files': ['summary.json', 'stages.json'], 'release_gate_qualified': False}))
    return 0 if summary['status'] == 'PASS_PRODUCTION_NORMAL_GATE' else 1


if __name__ == '__main__': raise SystemExit(main())
