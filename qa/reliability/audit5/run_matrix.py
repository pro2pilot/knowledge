#!/usr/bin/env python3
"""Bounded, exact-source build and scoped platform checks; never a release gate."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, platform, re, shutil, signal
import subprocess, sys, tarfile, time, urllib.request

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--pins', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    source = pathlib.Path(args.source).resolve()
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    public = out / 'public'; public.mkdir()
    temp = out / 'tmp'; temp.mkdir()
    pins = json.loads(pathlib.Path(args.pins).read_text())
    for name, digest in pins['files'].items():
        if sha(source / name) != digest:
            raise RuntimeError('source pin mismatch: ' + name)
    node = shutil.which('node')
    runtime = json.loads(subprocess.check_output([node, '-p',
        'JSON.stringify({platform:process.platform,arch:process.arch,node:process.version})'], timeout=15))
    if runtime['node'] != 'v22.17.1':
        raise RuntimeError('exact Node runtime is required')
    record = {'schema_version': 'knowledge-audit5-platform.v1', 'status': 'RUNNING',
        'scope': 'native build, loader and selected source tests; not installed ZIP or release qualification',
        'production_qualified': False, 'release_qualified': False,
        'commit': os.environ.get('GITHUB_SHA'), 'host': platform.platform(), 'runtime': runtime,
        'source_pins_sha256': sha(args.pins), 'steps': [], 'blocked': []}
    (public / 'SOURCE_PINS.json').write_text(json.dumps(pins, sort_keys=True, indent=2) + '\n')
    env = dict(os.environ, TMPDIR=str(temp), TMP=str(temp), TEMP=str(temp),
               KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH='1', KNOWLEDGE_INSPECTOR_NO_OPEN='1',
               KNOWLEDGE_FLOW_NO_OPEN='1')
    def save():
        (public / 'RESULT.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    def run(name, argv, timeout=120, required=True, tap=False):
        output = public / (name + '.stdout.log'); errors = public / (name + '.stderr.log')
        started = time.monotonic(); timed_out = False
        with output.open('wb') as sout, errors.open('wb') as serr:
            proc = subprocess.Popen([str(x) for x in argv], cwd=source, env=env,
                stdin=subprocess.DEVNULL, stdout=sout, stderr=serr,
                start_new_session=os.name != 'nt')
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # CI's independent job deadline is the final containment boundary.
                # This is fixed build/test scaffolding, not a production tree proof.
                if os.name != 'nt':
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                else:
                    subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                        stdin=subprocess.DEVNULL, stdout=serr, stderr=serr, timeout=15, check=False)
                try: code = proc.wait(timeout=15)
                except subprocess.TimeoutExpired: code = None
        step = {'name': name, 'exit_code': code, 'timed_out': timed_out,
            'elapsed_s': round(time.monotonic() - started, 3),
            'stdout_sha256': sha(output), 'stderr_sha256': sha(errors),
            'stdout_bytes': output.stat().st_size, 'stderr_bytes': errors.stat().st_size}
        ok = code == 0 and not timed_out
        if tap:
            text = output.read_text(errors='replace')
            counts = {}
            for field in ('tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'):
                matches = re.findall(r'^# ' + field + r' (\d+)\s*$', text, re.M)
                counts[field] = int(matches[-1]) if len(matches) == 1 else None
            step['tap'] = counts
            ok = ok and all(type(v) is int for v in counts.values()) and counts['tests'] > 0 \
                and counts['pass'] > 0 and counts['fail'] == counts['cancelled'] == counts['todo'] == 0 \
                and counts['tests'] == counts['pass'] + counts['skipped'] \
                and re.search(r'^\s*(?:not ok\b|Bail out!)', text, re.M | re.I) is None
            step['skipped_cases'] = [line.strip() for line in text.splitlines() if re.search(r'# SKIP\b', line, re.I)]
        step['status'] = 'PASS' if ok else 'FAIL'
        record['steps'].append(step); save()
        print(json.dumps(step), flush=True)
        if required and not ok:
            raise RuntimeError(name + ' did not pass')
        return step
    def download(url, target, limit):
        with urllib.request.urlopen(url, timeout=45) as response:
            body = response.read(limit + 1)
        if len(body) > limit: raise RuntimeError('toolchain download exceeds limit')
        target.write_bytes(body)
        return body
    try:
        version = '22.17.1' if runtime['platform'] == 'win32' and runtime['arch'] == 'arm64' else '18.20.8'
        base = 'https://nodejs.org/dist/v' + version + '/'
        sums = download(base + 'SHASUMS256.txt', public / 'SHASUMS256.txt', 1024 * 1024)
        table = {row.split()[1]: row.split()[0] for row in sums.decode().splitlines() if len(row.split()) == 2}
        def checked(name, target, limit):
            body = download(base + name, target, limit)
            if hashlib.sha256(body).hexdigest() != table[name]: raise RuntimeError('toolchain digest mismatch')
            return target
        header_archive = checked('node-v' + version + '-headers.tar.gz', out / 'headers.tar.gz', 64 * 1024 * 1024)
        with tarfile.open(header_archive) as archive:
            members = archive.getmembers()
            if len(members) > 8192 or sum(m.size for m in members) > 96 * 1024 * 1024:
                raise RuntimeError('toolchain archive exceeds bounds')
            for member in members:
                target = (out / member.name).resolve()
                if not target.is_relative_to(out) or not (member.isdir() or member.isfile()):
                    raise RuntimeError('unsafe toolchain member')
            archive.extractall(out, filter='data')
        headers = out / ('node-v' + version) / 'include/node'
        dest = public / 'native' / (runtime['platform'] + '-' + runtime['arch'])
        dest.mkdir(parents=True)
        build_args = ['--headers', headers, '--output', dest]
        if runtime['platform'] == 'win32':
            lib = checked('win-' + runtime['arch'] + '/node.lib', out / 'node.lib', 32 * 1024 * 1024)
            compiler = shutil.which('cl.exe')
            if not compiler: raise RuntimeError('Visual C environment unavailable')
            build_args += ['--compiler', compiler, '--node-lib', lib]
        run('build-lock', [node, source / 'tools/build-lock-native.js', *build_args])
        run('load-lock', [node, '-e',
            'const n=require(process.argv[1]);const i=n.info();if(i.napi_version!==8)process.exit(2);console.log(JSON.stringify(i));',
            dest / 'lock-publication.node'])
        if runtime['platform'] == 'win32':
            run('build-command-job', [node, source / 'tools/build-command-native.js', *build_args])
        elif runtime['platform'] == 'linux':
            c = source / 'tools/lib/verification-linux-namespace.c'
            binary = dest / 'verification-linux-namespace'
            run('build-namespace', ['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-Wno-misleading-indentation', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', c, '-o', binary])
            binary.chmod(0o755)
            (dest / 'verification-linux-namespace.manifest.json').write_text(json.dumps({
                'schema_version': 'knowledge-command-native-binary.v1', 'platform': 'linux',
                'architecture': runtime['arch'], 'binary': binary.name, 'source_sha256': sha(c),
                'binary_sha256': sha(binary), 'binary_bytes': binary.stat().st_size}, indent=2) + '\n')
        elif runtime['platform'] == 'darwin':
            lib = source / 'tools/lib'
            mapping = {'BROKER_SOURCE': 'verification-darwin-broker.m', 'DARWIN_STUB_SOURCE': 'verification-darwin-stub.c',
                'DARWIN_UID_HISTORY_HEADER': 'verification-darwin-uid-history.h',
                'DARWIN_UID_HISTORY_SOURCE': 'verification-darwin-uid-history.m', 'DARWIN_TRANSPORT_HEADER': 'verification-darwin-transport.h'}
            definitions = ['-DKNOWLEDGE_' + key + '_SHA="' + sha(lib / name) + '"' for key, name in mapping.items()]
            broker = dest / 'verification-darwin-broker'; stub = dest / 'verification-darwin-stub'
            run('build-macos-broker', ['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra', '-Wno-deprecated-declarations',
                '-framework', 'Foundation', *definitions, '-I', lib, lib / 'verification-darwin-broker.m',
                lib / 'verification-darwin-uid-history.m', '-o', broker])
            run('build-macos-stub', ['/usr/bin/clang', '-std=c11', '-D_DARWIN_C_SOURCE', '-O2', '-Wall', '-Wextra',
                '-Wno-deprecated-declarations', '-DKNOWLEDGE_BROKER_BINARY_SHA="' + sha(broker) + '"',
                definitions[0], definitions[1], lib / 'verification-darwin-stub.c', '-o', stub])
            run('describe-macos-stub', [stub, '--describe'])
            run('host-sip-observation', ['/usr/bin/csrutil', 'status'], required=False)
            record['blocked'].append('stock-SIP user-host acceptance is not supplied by hosted build checks')
        runtime_dest = source / 'tools/lib/native' / dest.name
        runtime_dest.mkdir(parents=True, exist_ok=True)
        for file in dest.iterdir():
            if file.is_file(): shutil.copy2(file, runtime_dest / file.name)
        common = ['reliability-command-authority-entry', 'reliability-runtime-install-completeness',
            'reliability-watcher-control', 'reliability-watcher-startup', 'reliability-watcher-smoke-deadline',
            'verification-policy', 'verification-evidence-guards', 'verification-cleanup-transcript',
            'verification-linux-proof-shapes', 'reliability-recovery-adapter-budget', 'reliability-recovery-adapter-ledger',
            'reliability-lock-loader', 'verification-finalization-v2', 'verification-control']
        files = [source / 'tests' / (name + '.test.js') for name in common]
        if any(not file.is_file() for file in files): raise RuntimeError('required test file missing')
        run('portable-contracts', [node, '--test', '--test-reporter=tap', '--test-concurrency=1', *files], 300, tap=True)
        if runtime['platform'] == 'linux':
            tests = ['reliability-linux-pidfd-binding', 'reliability-linux-report-backpressure', 'reliability-native-close-order',
                     'verification-linux-absence-visibility']
            run('linux-identity-contracts', [node, '--test', '--test-reporter=tap', '--test-concurrency=1',
                *[source / 'tests' / (name + '.test.js') for name in tests]], 120, tap=True)
            probe = run('local-namespace-capability', [node, '-e',
                'const p=require("./tools/lib/verification-linux-namespace").containmentCapability();console.log(JSON.stringify(p));process.exit(p.status==="requires_runtime_setup"?0:2);'], required=False)
            if probe['status'] == 'PASS':
                run('linux-physical-lifecycle', [node, '--test', '--test-reporter=tap', '--test-concurrency=1',
                    source / 'tests/reliability-native-clock.test.js',
                    source / 'tests/reliability-linux-namespace-link.test.js',
                    source / 'tests/reliability-linux-natural-exit.test.js',
                    source / 'tests/verification-native-recovery-linux.test.js'], 240, tap=True)
            else:
                record['blocked'].append('local PID namespace backend unavailable under actual host policy')
        elif runtime['platform'] == 'win32':
            run('windows-physical-lifecycle', [node, '--test', '--test-reporter=tap', '--test-concurrency=1',
                source / 'tests/windows-job-lifecycle.test.js',
                source / 'tests/verification-native-recovery-windows.test.js'], 240, tap=True)
            run('windows-public-cancellation', [node, '--test', '--test-reporter=tap',
                '--test-name-pattern=cancellation of a blocked first claim',
                source / 'tests/reliability-kve-invocation-public.test.js'], 150, tap=True)
        record['binaries'] = {p.relative_to(public).as_posix(): sha(p) for p in sorted(dest.iterdir()) if p.is_file()}
        # Source was not replaced while build/test actors were running.
        for name, digest in pins['files'].items():
            if sha(source / name) != digest: raise RuntimeError('source changed during checks: ' + name)
        record['status'] = 'PASS_SCOPED_WITH_BLOCKERS' if record['blocked'] else 'PASS_SCOPED'
    except Exception as error:
        record['status'] = 'FAIL'; record['error'] = str(error)
        raise
    finally:
        save()

if __name__ == '__main__':
    main()
