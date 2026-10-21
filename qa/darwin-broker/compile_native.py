"""Native macOS compile diagnostics. Infrastructure PASS is not backend PASS."""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'evidence'
OUT.mkdir(exist_ok=False)
source = ROOT / 'verification-darwin-broker.m'
stub_source = ROOT / 'verification-darwin-stub.c'
expected = json.loads((ROOT / 'SOURCE_RECEIPT.json').read_bytes())
digest = hashlib.sha256(source.read_bytes()).hexdigest()
assert digest == expected['native_sha256']
stub_digest = hashlib.sha256(stub_source.read_bytes()).hexdigest()
assert stub_digest == expected['stub_sha256']
argv = ['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra', '-Wno-deprecated-declarations',
        '-framework', 'Foundation', '-DKNOWLEDGE_BROKER_SOURCE_SHA="' + digest + '"',
        '-DKNOWLEDGE_DARWIN_STUB_SOURCE_SHA="' + stub_digest + '"',
        str(source), '-o', str(OUT / 'knowledge-native-broker')]
start = time.monotonic()
with (OUT / 'compile.stdout.log').open('wb') as stdout, (OUT / 'compile.stderr.log').open('wb') as stderr:
    result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=120)
stub_argv = []
stub_result = None
pair_describe = None
kernel_groups_import_verified = False
broker_digest = None
stub_binary_digest = None
if result.returncode == 0:
    broker_digest = hashlib.sha256((OUT / 'knowledge-native-broker').read_bytes()).hexdigest()
    stub_argv = ['/usr/bin/clang', '-std=c11', '-D_DARWIN_C_SOURCE', '-O2', '-Wall', '-Wextra',
                 '-Wno-deprecated-declarations', '-DKNOWLEDGE_BROKER_BINARY_SHA="' + broker_digest + '"',
                 '-DKNOWLEDGE_BROKER_SOURCE_SHA="' + digest + '"',
                 '-DKNOWLEDGE_DARWIN_STUB_SOURCE_SHA="' + stub_digest + '"',
                 str(stub_source), '-o', str(OUT / 'knowledge-native-stub')]
    with (OUT / 'compile-stub.stdout.log').open('wb') as stdout, (OUT / 'compile-stub.stderr.log').open('wb') as stderr:
        stub_result = subprocess.run(stub_argv, stdout=stdout, stderr=stderr, timeout=120)
    if stub_result.returncode == 0:
        stub_binary_digest = hashlib.sha256((OUT / 'knowledge-native-stub').read_bytes()).hexdigest()
        symbols = subprocess.run(['/usr/bin/nm', '-u', str(OUT / 'knowledge-native-stub')], capture_output=True, timeout=10)
        (OUT / 'stub-symbols.stdout.log').write_bytes(symbols.stdout)
        (OUT / 'stub-symbols.stderr.log').write_bytes(symbols.stderr)
        imports = symbols.stdout.decode('utf-8', errors='strict').split()
        kernel_groups_import_verified = symbols.returncode == 0 and '_getgroups' in imports and '_getgroups$DARWIN_EXTSN' not in imports
        describe = subprocess.run([str(OUT / 'knowledge-native-stub'), '--describe'], capture_output=True, timeout=10)
        (OUT / 'stub-describe.stdout.log').write_bytes(describe.stdout)
        (OUT / 'stub-describe.stderr.log').write_bytes(describe.stderr)
        pair_describe = json.loads(describe.stdout) if describe.returncode == 0 else None
        assert pair_describe == {'schema': 'knowledge-darwin-stub.v1', 'broker_binary_sha256': broker_digest,
                                'broker_source_sha256': digest, 'stub_source_sha256': stub_digest,
                                'capability_qualified': False}
code = result.returncode if result.returncode else stub_result.returncode
if code == 0 and not kernel_groups_import_verified:
    code = 65
record = {'scope': 'preliminary native clang compile only; no backend qualification, release gate or publication',
          'status': 'PASS' if code == 0 else 'FAIL', 'argv': argv, 'stub_argv': stub_argv,
          'exit_code': code, 'stub_exit_code': stub_result.returncode if stub_result else None,
          'stub_source_sha256': stub_digest, 'stub_pair_description': pair_describe,
          'broker_binary_sha256': broker_digest, 'stub_binary_sha256': stub_binary_digest,
          'kernel_groups_import_verified': kernel_groups_import_verified,
          'elapsed_ms': round((time.monotonic()-start)*1000, 3),
          'platform': platform.platform(), 'machine': platform.machine(), 'source_sha256': digest,
          'source_unchanged': hashlib.sha256(source.read_bytes()).hexdigest() == digest and hashlib.sha256(stub_source.read_bytes()).hexdigest() == stub_digest,
          'backend_certified': False}
for channel in ['stdout', 'stderr']:
    record[channel + '_sha256'] = hashlib.sha256((OUT / f'compile.{channel}.log').read_bytes()).hexdigest()
(OUT / 'COMPILE_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
sys.exit(code)
