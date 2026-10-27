#!/usr/bin/env python3
"""One exact packaged ZIP, six extracted-runtime smoke cells. No release qualification."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, signal, stat, subprocess, sys, time, zipfile

P = pathlib.Path
RUN_ID = 40576756772
INPUT_COMMIT = '2b2300426c7e18013b083e143a9e964e3667aa12'
ARTIFACTS = {
    'linux-x64': 'audit5-native-ubuntu-22.04-x64',
    'linux-arm64': 'audit5-native-ubuntu-24.04-arm-arm64',
    'darwin-x64': 'audit5-native-macos-15-intel-x64',
    'darwin-arm64': 'audit5-native-macos-15-arm64',
    'win32-x64': 'audit5-native-windows-2022-x64',
    'win32-arm64': 'audit5-native-windows-11-arm-arm64',
}
SELFTESTS = ['self-test-update-checks.js', 'self-test-update-metadata.js',
             'self-test-json-store-windows-writes.js', 'self-test-recording-blocker-contract.js']
LIMITS = ['Extracted ZIP runtime smoke only; no full installation or release gate.',
          'Linux production broker integration and drain-owner crash matrix are not covered.',
          'Hosted macOS smoke does not establish stock-SIP macOS qualification.']

def digest(body):
    return hashlib.sha256(body).hexdigest()

def sha(file):
    return digest(P(file).read_bytes())

def save(file, value):
    P(file).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf8')

def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)

def safe_name(name):
    rel = pathlib.PurePosixPath(name)
    need(bool(name) and not rel.is_absolute() and '..' not in rel.parts and '\\' not in name and ':' not in name,
         'unsafe archive/source path: ' + name)
    return rel

def execute(name, argv, cwd, out, steps, timeout=45):
    start = time.monotonic()
    stdout = out / (name + '.stdout.json')
    stderr = out / (name + '.stderr.txt')
    timed_out = False
    env = dict(os.environ, CI='1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH='1')
    with stdout.open('wb') as a, stderr.open('wb') as b:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=a, stderr=b, start_new_session=(os.name != 'nt'))
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'],
                               stdout=b, stderr=b, timeout=10, check=False)
            else:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            code = child.wait(timeout=10)
    row = {'name': name, 'exit_code': code, 'timed_out': timed_out,
           'elapsed_s': round(time.monotonic() - start, 3),
           'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
           'stdout_bytes': stdout.stat().st_size, 'stderr_bytes': stderr.stat().st_size,
           'status': 'PASS' if code == 0 and not timed_out else 'FAIL'}
    steps.append(row)
    need(row['status'] == 'PASS', name + ' failed; retained output has details')
    need(stdout.stat().st_size <= 2 * 1024 * 1024, name + ' unexpectedly large output')
    return json.loads(stdout.read_text(encoding='utf8'))

def native_pair(source, expected, binary, manifest):
    need(binary.is_file() and manifest.is_file() and not binary.is_symlink() and not manifest.is_symlink(), 'missing native pair')
    record = json.loads(manifest.read_text(encoding='utf8'))
    for key in ['schema_version', 'platform', 'architecture']:
        need(record[key] == expected[key], 'native metadata mismatch: ' + key)
    need(record['binary'] == binary.name, 'native basename mismatch')
    if 'napi_version' in expected:
        need(type(record['napi_version']) is int and record['napi_version'] == expected['napi_version'], 'native N-API mismatch')
    need(record['binary_sha256'] == sha(binary) and record['binary_bytes'] == binary.stat().st_size, 'native binary bytes mismatch')
    need(record['source_sha256'] == sha(source / expected['source']), 'native source mismatch')
    return record

def pack(args, out, steps, report):
    source = P(args.source).resolve()
    pin_file = P(args.pins).resolve()
    pin_bytes = pin_file.read_bytes()
    pins = json.loads(pin_bytes)
    need(pins['file_count'] == len(pins['files']), 'source inventory count mismatch')
    stage = out / 'stage' / '.knowledge'
    stage.mkdir(parents=True)
    for name, expected in pins['files'].items():
        safe_name(name)
        original = source / name
        need(original.is_file() and not original.is_symlink() and sha(original) == expected, 'source pin mismatch: ' + name)
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
    contract = json.loads((stage / 'install-manifest.json').read_text(encoding='utf8'))['release_contract']
    need(len(contract['native_runtime_artifacts']) == 10, 'expected ten native pairs')
    pairs = []
    for expected in contract['native_runtime_artifacts']:
        target = expected['platform'] + '-' + expected['architecture']
        root = P(args.native_input).resolve() / ARTIFACTS[target]
        original = root / 'native' / target
        binary, manifest = original / P(expected['binary']).name, original / P(expected['manifest']).name
        record = native_pair(stage, expected, binary, manifest)
        receipt = json.loads((root / 'RESULT.json').read_text(encoding='utf8'))
        need(receipt['commit'] == INPUT_COMMIT, 'unexpected native source revision')
        build = 'build-namespace' if binary.name == 'verification-linux-namespace' else ('build-command-job' if binary.name == 'command-windows-job.node' else 'build-lock')
        need(any(row['name'] == build and row['status'] == 'PASS' for row in receipt['steps']), 'native build not PASS')
        for key, original_file in [('binary', binary), ('manifest', manifest)]:
            destination = stage / expected[key]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original_file, destination)
            destination.chmod(0o755 if destination.name == 'verification-linux-namespace' else 0o644)
        pairs.append({'target': target, 'artifact_name': ARTIFACTS[target], 'input_run': RUN_ID,
                      'input_commit': receipt['commit'], 'input_overall_status': receipt['status'],
                      'build_step_status': 'PASS', 'binary': expected['binary'], 'manifest': expected['manifest'],
                      'binary_sha256': record['binary_sha256'], 'manifest_sha256': sha(manifest),
                      'source_sha256': record['source_sha256']})
    public = out / 'public'
    public.mkdir()
    version = json.loads((stage / 'package.json').read_text(encoding='utf8'))['version']
    zip_path = public / ('knowledge-v' + version + '.zip')
    built = execute('package', ['node', str(stage / 'tools/package-release.js'), '--out', str(zip_path), '--json'], stage, public, steps, 60)
    need(built['status'] == 'ok', 'shipping packager rejected ZIP')
    validated = execute('validate', ['node', str(stage / 'tools/validate-release-artifact.js'), str(zip_path), '--json'], stage, public, steps, 45)
    need(validated['status'] == 'ok' and validated['violations'] == [], 'shipping validator rejected ZIP')
    contents = {}
    with zipfile.ZipFile(zip_path) as archive:
        need(archive.testzip() is None, 'ZIP CRC mismatch')
        need(len(archive.namelist()) == len(set(archive.namelist())), 'ZIP duplicate entries')
        for info in archive.infolist():
            safe_name(info.filename)
            need(info.filename.startswith('.knowledge/') and not info.is_dir(), 'unexpected ZIP layout')
            body = archive.read(info)
            contents[info.filename] = {'sha256': digest(body), 'bytes': len(body), 'mode': (info.external_attr >> 16) & 0o777}
    need(pin_file.read_bytes() == pin_bytes, 'source pins changed while packing')
    for name, expected in pins['files'].items():
        need(sha(source / name) == expected, 'source changed while packing')
    (public / 'SOURCE_PINS.json').write_bytes(pin_bytes)
    save(public / 'PACKAGE_CONTENTS.json', contents)
    report.update(status='PASS_PACKAGED_STRUCTURAL_VALIDATION', artifact_name=zip_path.name,
                  artifact_sha256=sha(zip_path), artifact_bytes=zip_path.stat().st_size,
                  entries=len(contents), native_pairs=pairs, source_pins_sha256=digest(pin_bytes),
                  source_pin_count=len(pins['files']), package_contents_sha256=sha(public / 'PACKAGE_CONTENTS.json'),
                  installed_runtime_smoke='PENDING_SEPARATE_MATRIX', structurally_valid_zip=True)
    save(public / 'BUILD_PROVENANCE.json', report)

NATIVE_JS = r"""
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=process.cwd(),target=process.platform+'-'+process.arch;
assert.equal(process.versions.node,'22.17.1');
const checks=[];
for(const name of ['lock-publication',...(process.platform==='win32'?['command-windows-job']:[])]){
 const base=path.join(root,'tools/lib/native',target,name);
 const manifest=JSON.parse(fs.readFileSync(base+'.manifest.json','utf8'));
 const info=require(base+'.node').info();
 assert.equal(info.platform,process.platform);assert.equal(info.architecture,process.arch);
 assert.equal(info.napi_version,8);assert.equal(info.source_sha256,manifest.source_sha256);
 checks.push({name,info});
}
if(process.platform==='linux'){
 const helper=require(path.join(root,'tools/lib/verification-linux-namespace.js')).preparePackagedHelper();
 assert.equal(helper.platform,'linux');assert.equal(helper.architecture,process.arch);
 checks.push({name:'linux-packaged-helper-admission',source_sha256:helper.source_sha256,binary_sha256:helper.binary_sha256});
}
console.log(JSON.stringify({status:'pass',platform:process.platform,arch:process.arch,node:process.version,checks}));
"""

def smoke(args, out, steps, report):
    package = P(args.package).resolve()
    provenance = json.loads((package / 'BUILD_PROVENANCE.json').read_text(encoding='utf8'))
    need(provenance['status'] == 'PASS_PACKAGED_STRUCTURAL_VALIDATION', 'package provenance not PASS')
    zip_path = package / provenance['artifact_name']
    need(sha(zip_path) == provenance['artifact_sha256'], 'ZIP SHA256 mismatch')
    need(sha(package / 'PACKAGE_CONTENTS.json') == provenance['package_contents_sha256'], 'entry manifest hash mismatch')
    need(sha(package / 'SOURCE_PINS.json') == provenance['source_pins_sha256'], 'pins hash mismatch')
    contents = json.loads((package / 'PACKAGE_CONTENTS.json').read_text(encoding='utf8'))
    extracted = out / 'fresh-install'
    extracted.mkdir()
    with zipfile.ZipFile(zip_path) as archive:
        need(len(archive.namelist()) == len(contents) and set(archive.namelist()) == set(contents), 'ZIP entries mismatch')
        need(archive.testzip() is None, 'ZIP CRC mismatch')
        for info in archive.infolist():
            safe_name(info.filename)
            need(info.filename.startswith('.knowledge/') and not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16), 'unsafe ZIP entry')
            body = archive.read(info)
            entry = contents[info.filename]
            need(digest(body) == entry['sha256'] and len(body) == entry['bytes'], 'ZIP bytes mismatch')
            destination = extracted / info.filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            if os.name != 'nt':
                destination.chmod(entry['mode'])
    installed = extracted / '.knowledge'
    contract = json.loads((installed / 'install-manifest.json').read_text(encoding='utf8'))['release_contract']
    for expected in contract['native_runtime_artifacts']:
        native_pair(installed, expected, installed / expected['binary'], installed / expected['manifest'])
    runtime = execute('installed-native-load', ['node', '-e', NATIVE_JS], installed, out, steps)
    need(runtime['status'] == 'pass' and runtime['arch'] == args.arch, 'native runtime mismatch')
    for script in SELFTESTS:
        result = execute(script[:-3], ['node', str(installed / 'tools' / script)], installed, out, steps)
        need(result['status'] == 'pass', 'self-test non-pass: ' + script)
        steps[-1]['checks_total'] = result.get('checks_total', len(result.get('checks', [])))
    for name, expected in contents.items():
        need(sha(extracted / name) == expected['sha256'], 'shipped bytes changed during smoke: ' + name)
    report.update(status='PASS_EXTRACTED_ZIP_SMOKE', artifact_name=zip_path.name,
                  artifact_sha256=sha(zip_path), artifact_bytes=zip_path.stat().st_size,
                  source_pins_sha256=provenance['source_pins_sha256'], entries_verified=len(contents),
                  runtime=runtime, selftests=SELFTESTS, installed_bytes_unchanged=True,
                  installability_qualification='SCOPED_EXTRACTED_RUNTIME_SMOKE_ONLY')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['pack', 'smoke'])
    parser.add_argument('--out', required=True)
    parser.add_argument('--source')
    parser.add_argument('--pins')
    parser.add_argument('--native-input')
    parser.add_argument('--package')
    parser.add_argument('--arch')
    args = parser.parse_args()
    out = P(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    steps = []
    report = {'schema_version': 'knowledge-audit5-installed-smoke.v1', 'status': 'FAIL',
              'mode': args.mode, 'commit': os.environ.get('GITHUB_SHA'),
              'workflow_run': os.environ.get('GITHUB_RUN_ID'), 'steps': steps,
              'production_qualified': False, 'release_gate_qualified': False,
              'full_release_gate': 'NOT_RUN', 'stock_sip_macos': 'NOT_CONFIRMED', 'limitations': LIMITS}
    try:
        (pack if args.mode == 'pack' else smoke)(args, out, steps, report)
        return 0
    except Exception as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        save(out / 'RESULT.json', report)
        print(json.dumps({'status': report['status'], 'steps': len(steps), 'artifact_sha256': report.get('artifact_sha256')}))

if __name__ == '__main__':
    sys.exit(main())
