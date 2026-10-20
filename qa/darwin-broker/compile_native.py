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
expected = json.loads((ROOT / 'SOURCE_RECEIPT.json').read_bytes())
digest = hashlib.sha256(source.read_bytes()).hexdigest()
assert digest == expected['native_sha256']
argv = ['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra', '-Wno-deprecated-declarations',
        '-framework', 'Foundation', '-DKNOWLEDGE_BROKER_SOURCE_SHA="' + digest + '"',
        str(source), '-o', str(OUT / 'knowledge-native-broker')]
start = time.monotonic()
with (OUT / 'compile.stdout.log').open('wb') as stdout, (OUT / 'compile.stderr.log').open('wb') as stderr:
    result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=120)
record = {'scope': 'preliminary native clang compile only; no backend qualification, release gate or publication',
          'status': 'PASS' if result.returncode == 0 else 'FAIL', 'argv': argv,
          'exit_code': result.returncode, 'elapsed_ms': round((time.monotonic()-start)*1000, 3),
          'platform': platform.platform(), 'machine': platform.machine(), 'source_sha256': digest,
          'source_unchanged': hashlib.sha256(source.read_bytes()).hexdigest() == digest,
          'backend_certified': False}
for channel in ['stdout', 'stderr']:
    record[channel + '_sha256'] = hashlib.sha256((OUT / f'compile.{channel}.log').read_bytes()).hexdigest()
(OUT / 'COMPILE_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
sys.exit(result.returncode)
