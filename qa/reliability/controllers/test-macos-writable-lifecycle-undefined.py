#!/usr/bin/env python3
"""Regression guard for undefined names in the Team writable controller trio.

Uses an already-installed Ruff executable; it never installs dependencies.
An optional controller directory lets the same check compare an older or
candidate controller set without copying files into this checkout.
"""
import shutil
import subprocess
import sys
from pathlib import Path


FILES = (
    'macos-writable-lifecycle.py',
    'macos-writable-summary.py',
    'test-macos-writable-summary.py',
)


def main():
    ruff = shutil.which('ruff')
    if not ruff:
        print('ruff_unavailable; no dependency installation attempted', file=sys.stderr)
        return 2
    directory = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent
    paths = [directory / name for name in FILES]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        print('controller_file_missing: ' + ', '.join(missing), file=sys.stderr)
        return 2
    return subprocess.run([
        ruff, 'check', '--no-cache', '--select', 'F821,F823', *map(str, paths)
    ], check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
