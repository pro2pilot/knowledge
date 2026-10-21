"""Verify exact source bytes around actual portable tests on a CI platform."""
from pathlib import Path
import hashlib
import json
import platform
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
OUT = HERE / 'evidence'
OUT.mkdir(exist_ok=True)
receipt = json.loads((HERE / 'COPY_SOURCE_RECEIPT.json').read_bytes())
def pins():
    return {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in receipt['files']}
record = {'scope': 'portable copy/client tests only, not native backend acceptance',
          'platform': platform.platform(), 'machine': platform.machine(), 'backend_certified': False,
          'expected': receipt, 'before': pins()}
assert record['before'] == receipt['files'], 'copy-source bytes mismatch before test'
argv = [shutil.which('node'), '--test', str(HERE / 'copy/tests/verification-isolated-copy.test.js'),
        str(HERE / 'copy/tests/verification-darwin-client.test.js')]
start = time.monotonic()
with (OUT / 'copy-tests.tap').open('wb') as stdout, (OUT / 'copy-tests.stderr.log').open('wb') as stderr:
    r = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=120)
record.update(argv=argv, exit_code=r.returncode, elapsed_ms=round((time.monotonic()-start)*1000, 3), after=pins())
record['status'] = 'PASS' if r.returncode == 0 and record['after'] == record['before'] else 'FAIL'
(OUT / 'PORTABLE_COPY_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({k: v for k, v in record.items() if k not in ['expected', 'before', 'after']}))
raise SystemExit(0 if record['status'] == 'PASS' else 1)
