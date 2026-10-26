#!/usr/bin/env python3
"""Actual normal-install public request -> native work -> KVE/KVF/ACK.

The hosted disposable runner must have no existing canonical installation.
Never replaces an existing installation. Raw evidence remains private.
This early gate is deliberately separate from the diagnostic stop matrix.
"""
import argparse, hashlib, importlib.util, json, os, platform, plistlib, pwd, re, shutil, signal, stat, subprocess, sys, tarfile, time, traceback, urllib.request
from pathlib import Path

CANONICAL = {
    'registry': '/Library/PrivilegedHelperTools/KnowledgeVerification-state',
    'allocator': '/Library/PrivilegedHelperTools/KnowledgeVerification-allocator',
    'anchors': '/Library/PrivilegedHelperTools/KnowledgeVerification-anchors',
    'workspaces': '/Library/PrivilegedHelperTools/KnowledgeVerification-workspaces',
    'control': '/Library/PrivilegedHelperTools/KnowledgeVerification-control',
}
NATIVE = {'broker': 'verification-darwin-broker.m', 'stub': 'verification-darwin-stub.c',
    'history_header': 'verification-darwin-uid-history.h', 'history_source': 'verification-darwin-uid-history.m',
    'transport_header': 'verification-darwin-transport.h'}
BEFORE_PROTECTED_SOURCE_SHA = '48f8a3c6c945b79c27ee6c46311dc6706809b1062f1db6618f67878e1601691b'

# Fixed QA installer preflight. Existing parents are only observed; the
# controller never chmods, deletes or replaces an existing installation root.
# Error output contains typed facts, not an exception message or pathname.
INSTALL_PARENT_SCRIPT = '''import errno,json,os,stat,sys
p=sys.argv[1];value={'ok':False,'created':False,'exists_before':None,'directory_before':None,'symlink_before':None,'root_owned_before':None,'mode_before':None,'errno':None,'identity':None}
try:
 assert os.getuid()==0 and os.geteuid()==0
 outer=os.lstat(os.path.dirname(p))
 if not stat.S_ISDIR(outer.st_mode) or outer.st_uid!=0 or outer.st_mode&0o022: raise OSError(errno.EPERM,'unsafe ancestor')
 try: before=os.lstat(p)
 except FileNotFoundError: before=None
 value['exists_before']=before is not None
 if before is not None:
  value.update(directory_before=stat.S_ISDIR(before.st_mode),symlink_before=stat.S_ISLNK(before.st_mode),root_owned_before=before.st_uid==0,mode_before=stat.S_IMODE(before.st_mode))
  if not stat.S_ISDIR(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022: raise OSError(errno.EPERM,'unsafe existing parent')
 else:
  os.mkdir(p,0o755);value['created']=True;os.chmod(p,0o755)
 after=os.lstat(p)
 if not stat.S_ISDIR(after.st_mode) or after.st_uid!=0 or after.st_mode&0o022: raise OSError(errno.EPERM,'unsafe created parent')
 if before is not None and (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino): raise OSError(errno.ESTALE,'parent changed')
 value['identity']={'dev':after.st_dev,'ino':after.st_ino,'mode':stat.S_IMODE(after.st_mode)};value['ok']=True
except OSError as error: value['errno']=error.errno
except BaseException: value['errno']=errno.EINVAL
print(json.dumps(value,separators=(',',':')))
raise SystemExit(0 if value['ok'] else 1)
'''


def inventory(source):
    rows = []
    for base, dirs, files in os.walk(source, followlinks=False):
        for name in dirs:
            if (Path(base)/name).is_symlink(): raise RuntimeError('source_symlink')
        for name in files:
            p = Path(base)/name;st = p.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1: raise RuntimeError('source_not_unique_regular')
            data = p.read_bytes()
            rows.append({'path': p.relative_to(source.parent).as_posix(), 'bytes': len(data),
                'sha256': hashlib.sha256(data).hexdigest(), 'executable': bool(st.st_mode & 0o111)})
    return sorted(rows, key=lambda item: item['path'])


def diagnostic(error, stage):
    allowed = {'darwin-production-lifecycle.py', 'run_pipeline4.py'}
    types = {'QAError', 'FileNotFoundError', 'PermissionError', 'TypeError', 'AttributeError', 'KeyError',
        'ValueError', 'OSError', 'TimeoutExpired', 'RuntimeError', 'ImportError', 'ModuleNotFoundError', 'SyntaxError'}
    frames = [];current = error.__traceback__
    while current is not None and len(frames) < 16:
        name = Path(current.tb_frame.f_code.co_filename).name
        frames.append({'file': name if name in allowed else 'external-frame', 'line': current.tb_lineno})
        current = current.tb_next
    return {'type': type(error).__name__ if type(error).__name__ in types else 'UnknownException',
        'stage': stage, 'frames': frames}


def main():
    ap = argparse.ArgumentParser();ap.add_argument('--source', required=True);ap.add_argument('--reference', required=True)
    ap.add_argument('--evidence', required=True);ap.add_argument('--expected-arch', required=True, choices=('x86_64', 'arm64'))
    ap.add_argument('--case-set', choices=('normal', 'basic', 'failures'), default='normal')
    args = ap.parse_args()
    evidence = Path(args.evidence).resolve();source = Path(args.source).resolve(strict=True)
    if platform.system() != 'Darwin' or os.environ.get('GITHUB_ACTIONS') != 'true':
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        (evidence/'SUMMARY.json').write_text(json.dumps({'status': 'NOT_RUN_DISPOSABLE_DARWIN_REQUIRED',
            'cases': [], 'architecture': platform.machine(), 'source_unchanged': True})+'\n');return 2
    reference = Path(args.reference).resolve(strict=True);module_path = reference/'qa/darwin-pipeline4/run_pipeline4.py'
    sys.path.insert(0, str(module_path.parent))
    spec = importlib.util.spec_from_file_location('production_fixture_utilities', module_path)
    base = importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    controller = Path(__file__).with_name('darwin-production-controller.js')
    matrix_controller = Path(__file__).with_name('darwin-production-matrix-controller.js')
    matrix_workloads = Path(__file__).with_name('darwin-production-workloads.js')
    failure_module = None
    if args.case_set == 'failures':
        failure_path = Path(__file__).with_name('darwin-production-failure-cases.py')
        failure_spec = importlib.util.spec_from_file_location('production_failure_cases', failure_path)
        failure_module = importlib.util.module_from_spec(failure_spec);failure_spec.loader.exec_module(failure_module)

    class Runner(base.Runner):
        def __init__(self):
            super().__init__(module_path.parent/'PINS.json', evidence, args.expected_arch, evidence/'unused-public')
            self.workspace = reference;self.source = source.parent;self.input_pins = inventory(source)
            self.pins = {'files': self.input_pins, 'native': {k: '.knowledge/tools/lib/'+v for k, v in NATIVE.items()},
                'qa': {'build_id': base.sha_bytes(base.canonical(self.input_pins)), 'socket_relative': 'qa/gate.sock'}}
            self.account_policy = 'admin_reserved_interval_no_runtime_nss.v1'
            self.roots = {};self.root_identities = {};self.case_results = [];self.daemon_birth = None
            self.native_manifest = None;self.runtime_copy = None;self.cleanup_confirmed = False
            self.fixture_identity = None
            self.public_started = False;self.public_completed = False
            self.install_parent_observation = None;self.install_parent_identity = None
            self.protected_contract = {'cases': [], 'status': 'NOT_RUN'}
            self.addon_path = None;self.before_addon_path = None
            self.failure_helpers = None

        def run(self, name, argv, timeout=120, data=None, root=False):
            result = super().run(name, argv, timeout=timeout, data=data, root=root)
            self.records[-1].update(argv=list(map(str, argv)), cwd=str(Path.cwd()), timeout_s=timeout,
                input_bytes=len(data) if data is not None else 0,
                input_sha256=base.sha_bytes(data) if data is not None else None)
            return result

        def prepare_runtime(self):
            self.runtime_copy = evidence/'runtime' / '.knowledge'
            shutil.copytree(source, self.runtime_copy, symlinks=False)
            self.check(inventory(self.runtime_copy) == self.input_pins, 'runtime_copy_pin_mismatch')
            node = self.node_path()
            version = self.run('node-version', [str(node), '-p', 'process.versions.node'], timeout=10)
            self.check(version.returncode == 0, 'node_version_failed')
            version = version.stdout.decode('ascii').strip()
            self.check(re.fullmatch(r'\d+\.\d+\.\d+', version) is not None, 'node_version_invalid')
            url = 'https://nodejs.org/dist/v'+version+'/'
            with urllib.request.urlopen(url+'SHASUMS256.txt', timeout=60) as reply: checksums = reply.read(1024*1024+1)
            self.check(len(checksums) <= 1024*1024, 'node_checksums_oversized')
            base.private_file(evidence/'NODE_SHASUMS256.txt', checksums)
            table = {line.split()[1]: line.split()[0] for line in checksums.decode('ascii').splitlines() if len(line.split()) == 2}
            name = 'node-v'+version+'-headers.tar.gz'
            self.check(re.fullmatch('[a-f0-9]{64}', table.get(name, '')) is not None, 'node_headers_checksum_missing')
            with urllib.request.urlopen(url+name, timeout=60) as reply: body = reply.read(80*1024*1024+1)
            self.check(len(body) <= 80*1024*1024 and base.sha_bytes(body) == table[name], 'node_headers_checksum_mismatch')
            archive = evidence/name;base.private_file(archive, body);headers_root = evidence/'headers';headers_root.mkdir(mode=0o700)
            with tarfile.open(archive, 'r:gz') as packed:
                seen = set()
                for item in packed.getmembers():
                    relative = Path(item.name)
                    self.check(not relative.is_absolute() and '..' not in relative.parts and '\\' not in item.name and
                        relative.parts and relative.parts[0] == 'node-v'+version and item.name not in seen and
                        (item.isdir() or item.isfile()) and item.size <= 16*1024*1024, 'node_headers_archive_unsafe')
                    seen.add(item.name);target = headers_root/relative
                    if item.isdir(): target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with packed.extractfile(item) as stream: data = stream.read(item.size+1)
                        self.check(len(data) == item.size, 'node_headers_archive_truncated');target.write_bytes(data)
            built = self.run('compile-lock-addon', [str(node), str(self.runtime_copy/'tools/build-lock-native.js'),
                '--headers', str(headers_root/('node-v'+version)/'include/node')], timeout=180)
            self.check(built.returncode == 0, 'native_addon_build_failed')
            architecture = 'x64' if args.expected_arch == 'x86_64' else 'arm64'
            manifest_path = self.runtime_copy/'tools/lib/native'/('darwin-'+architecture)/'lock-publication.manifest.json'
            manifest = json.loads(manifest_path.read_bytes())
            self.check(manifest.get('platform') == 'darwin' and manifest.get('architecture') == architecture and
                manifest.get('source_sha256') == base.sha_file(source/'tools/native/lock-publication.c') and
                manifest.get('binary_sha256') == base.sha_file(manifest_path.parent/'lock-publication.node'), 'native_addon_pin_mismatch')
            self.native_manifest = manifest
            self.addon_path = manifest_path.parent/'lock-publication.node'
            before_source = Path(__file__).with_name('lock-publication-before-search.c')
            self.check(base.sha_file(before_source) == BEFORE_PROTECTED_SOURCE_SHA, 'protected_baseline_source_pin_mismatch')
            self.before_addon_path = evidence/'lock-publication-before-search.node'
            built = self.run('compile-protected-before-addon', ['/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-O2', '-fPIC',
                '-DNAPI_VERSION=8', '-DKNOWLEDGE_LOCK_SOURCE_SHA256="'+BEFORE_PROTECTED_SOURCE_SHA+'"', '-I',
                str(headers_root/('node-v'+version)/'include/node'), '-bundle', '-undefined', 'dynamic_lookup',
                str(before_source), '-o', str(self.before_addon_path)], timeout=180)
            self.check(built.returncode == 0, 'protected_baseline_compile_failed')
            self.protected_contract.update(before_source_sha256=BEFORE_PROTECTED_SOURCE_SHA,
                after_source_sha256=manifest['source_sha256'], before_binary_sha256=base.sha_file(self.before_addon_path),
                after_binary_sha256=manifest['binary_sha256'])

        def setup_normal(self):
            # Canonical installation has no path override relaxation. The job
            # is disposable, but absence and created inode identity are still
            # checked; a preexisting installation is never replaced.
            self.check(os.getuid() != 0, 'ordinary_owner_required')
            parent = str(Path(CANONICAL['registry']).parent)
            observed = self.sudo(sys.executable, '-c', INSTALL_PARENT_SCRIPT, parent,
                name='ensure-protected-install-parent', timeout=20)
            try: value = json.loads(observed.stdout)
            except Exception: value = None
            self.install_parent_observation = value
            self.check(observed.returncode == 0 and isinstance(value, dict) and value.get('ok') is True,
                'protected_install_parent_unavailable')
            if value.get('created') is True: self.install_parent_identity = value['identity']
            base.private_file(evidence/'installation-parent.json', base.canonical(value))
            probe = 'import os,sys; raise SystemExit(1 if any(os.path.lexists(p) for p in sys.argv[1:]) else 0)'
            self.root('canonical-roots-must-be-absent', sys.executable, '-c', probe, *CANONICAL.values())
            for role, name in CANONICAL.items():
                mode = '0700' if role in ('registry', 'allocator') else '0755' if role == 'anchors' else '0711'
                self.root('create-canonical-'+role, '/bin/mkdir', '-m', mode, name)
                observed = self.root('identify-canonical-'+role, sys.executable, '-c',
                    'import os,json,stat,sys;s=os.lstat(sys.argv[1]);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0;print(json.dumps({"dev":s.st_dev,"ino":s.st_ino,"mode":stat.S_IMODE(s.st_mode)}))', name)
                identity = json.loads(observed.stdout);self.root_identities[name] = identity;self.roots[role] = Path(name)
                base.private_file(evidence/('created-'+role+'.json'), base.canonical({'path': name, **identity}))
            for role, mode in (('bin', '0711'), ('runtime', '0711'), ('logs', '0700'), ('launchd', '0700')):
                self.root_dir(role, mode)
            binary = self.fixture/'bin/broker';stub = self.fixture/'bin/knowledge-native-stub';node = self.fixture/'runtime/node'
            for role, original, target in (('broker', self.binaries['shipping']['broker'], binary),
                ('stub', self.binaries['shipping']['stub'], stub), ('node', self.node_path(), node)):
                self.root('install-production-'+role, '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0555', str(original), str(target))
                self.check(base.sha_file(original) == base.sha_file(target), 'installed_binary_pin_mismatch')
                self.installed_bindings.append({'role': role, 'source_sha256': base.sha_file(original), 'installed_sha256': base.sha_file(target)})
            sock = self.roots['control']/'broker.sock'
            info = {'binary': binary, 'stub': stub, 'node': node, 'socket': sock}
            initial = self.sudo(str(binary), '--init-install', '--confirm-reserved-uid-range=1000000000:1900000000',
                '--account-policy='+self.account_policy, '--allow-owner='+str(os.getuid()), '--runtime='+str(node),
                name='init-production', timeout=120)
            try: initialized = json.loads(initial.stdout)
            except Exception: initialized = None
            self.check(initial.returncode == 0 and isinstance(initialized, dict) and initialized.get('ok') is True, 'normal_install_failed')
            self.fixture_initialized = True
            plist = {'Label': self.label, 'ProgramArguments': [str(binary), '--serve', '--runtime='+str(node)],
                'RunAtLoad': True, 'KeepAlive': False, 'StandardOutPath': str(self.fixture/'logs/daemon.stdout.log'),
                'StandardErrorPath': str(self.fixture/'logs/daemon.stderr.log')}
            stage = evidence/'production-launchd.plist';base.private_file(stage, plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=True))
            installed = self.fixture/'launchd/job.plist'
            self.root('install-production-plist', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0444', str(stage), str(installed))
            self.bootstrapped = True
            self.root('bootstrap-production', '/bin/launchctl', 'bootstrap', 'system', str(installed), timeout=45)
            self.check(self.label_exists(timeout=20), 'normal_daemon_not_observed')
            observation = self.root('capture-production-daemon', str(self.birth_observer), str(self.broker_pid))
            birth = json.loads(observation.stdout)
            self.check(birth.get('state') == 'same_running' and birth.get('ruid') == 0 and birth.get('image') == str(binary), 'normal_daemon_birth_unconfirmed')
            self.daemon_birth = birth
            deadline = time.monotonic()+30
            while time.monotonic() < deadline and not sock.exists(): time.sleep(.1)
            self.check(sock.exists() and stat.S_ISSOCK(sock.lstat().st_mode), 'normal_socket_unavailable')
            probe = self.native_request(info, {'op': 'probe'}, 'probe-production', timeout=30)
            self.check(probe.get('capability_qualified') is True and probe.get('qualification_mode') is False and
                probe.get('qa_persistence_gate') is False and probe.get('source_sha256') == self.binaries['shipping']['source_sha256'], 'normal_mode_not_admissible')
            base.private_file(evidence/'normal-probe.private.json', base.canonical(probe))
            return info

        def case_protected_executable(self, info):
            # Test one exact 0711 directory boundary with the actual old/new
            # compiled addon, before any production request can be admitted.
            # Other directories here are 0755; the real broker fixture stays
            # 0711 throughout, so normal public success also covers that path.
            folder = self.roots['anchors']/'qa-protected-executable';leaf = folder/'program'
            body = b'#!/bin/sh\nexit 0\n';expected_sha = base.sha_bytes(body)
            self.root('create-protected-fixture', sys.executable, '-c',
                'import os,sys;os.mkdir(sys.argv[1],0o711);os.chmod(sys.argv[1],0o711);f=os.open(sys.argv[2],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o555);os.write(f,bytes.fromhex(sys.argv[3]));os.fchmod(f,0o555);os.fsync(f);os.close(f)',
                str(folder), str(leaf), body.hex())
            probe = Path(__file__).with_name('darwin-protected-executable-probe.js')

            def pair(name, expected, target=leaf):
                values = {}
                for version, addon, source_sha in (('before', self.before_addon_path, BEFORE_PROTECTED_SOURCE_SHA),
                    ('after', self.addon_path, self.native_manifest['source_sha256'])):
                    result = self.run('protected-'+version+'-'+name, [str(info['node']), str(probe)],
                        data=base.canonical({'addon': str(addon), 'path': str(target)}), timeout=20)
                    try: value = json.loads(result.stdout)
                    except Exception: value = {}
                    values[version] = {'exit_code': result.returncode, **value}
                row = {'name': name, 'required_acceptance': expected, **values, 'status': 'FAIL'}
                self.protected_contract['cases'].append(row)
                for version in ('before', 'after'):
                    value = values[version];required = False if version == 'before' and name == 'search_only_ancestor' else expected
                    self.check(value.get('exit_code') == 0 and value.get('accepted') is required and
                        value.get('source_sha256') == (BEFORE_PROTECTED_SOURCE_SHA if version == 'before' else self.native_manifest['source_sha256']),
                        'protected_executable_contract_failed')
                    if required: self.check(value.get('sha256') == expected_sha, 'protected_executable_hash_mismatch')
                if name == 'search_only_ancestor':
                    self.check(values['before'].get('native_error') == 13, 'protected_search_denial_not_observed')
                row['status'] = 'PASS_PHYSICAL_PAIRED'

            pair('search_only_ancestor', True)
            self.root('mode-protected-readable', '/bin/chmod', '0755', str(folder));pair('readable_ancestor', True)
            username = pwd.getpwuid(os.getuid()).pw_name
            self.root('acl-protected-leaf-write', '/bin/chmod', '+a', 'user:'+username+' allow write', str(leaf))
            pair('leaf_write_acl', False)
            actual_write = self.run('prove-protected-leaf-write', [sys.executable, '-c',
                'import os,sys;f=os.open(sys.argv[1],os.O_WRONLY);os.write(f,b"X");os.close(f)', str(leaf)], timeout=10)
            self.check(actual_write.returncode == 0, 'protected_write_acl_fixture_inactive')
            self.root('acl-protected-leaf-reset', '/bin/chmod', '-N', str(leaf))
            self.root('restore-protected-fixture', sys.executable, '-c',
                'import os,sys;f=os.open(sys.argv[1],os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW);os.write(f,bytes.fromhex(sys.argv[2]));os.fsync(f);os.close(f)', str(leaf), body.hex())
            self.root('acl-protected-parent-write', '/bin/chmod', '+a', 'user:'+username+' allow add_file,delete_child', str(folder))
            pair('parent_write_acl', False)
            marker = folder/'marker'
            actual_create = self.run('prove-protected-parent-write', [sys.executable, '-c',
                'import os,sys;f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(f);os.unlink(sys.argv[1])', str(marker)], timeout=10)
            self.check(actual_create.returncode == 0, 'protected_write_acl_fixture_inactive')
            self.root('acl-protected-parent-reset', '/bin/chmod', '-N', str(folder))
            self.root('acl-protected-leaf-read', '/bin/chmod', '+a', 'user:'+username+' allow read,readattr,readextattr,readsecurity', str(leaf))
            pair('leaf_read_acl', True)
            self.root('acl-protected-leaf-reset', '/bin/chmod', '-N', str(leaf))
            alias = folder/'alias';self.root('symlink-protected-fixture', '/bin/ln', '-s', 'program', str(alias));pair('leaf_symlink', False, alias)
            self.root('mode-protected-writable', '/bin/chmod', '0757', str(folder));pair('writable_ancestor', False)
            self.root('mode-protected-no-search', '/bin/chmod', '0700', str(folder));pair('unsearchable_ancestor', False)
            self.root('mode-protected-readable', '/bin/chmod', '0755', str(folder))
            self.protected_contract.update(status='PASS_PHYSICAL_PAIRED', write_acl_effects_verified=True)

        def fixture_registry_snapshot(self):
            if 'registry' not in self.roots: return None
            file = self.roots['registry']/'registry.json'
            reader = ('import os,stat,sys;\ntry: f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)\n'
                'except FileNotFoundError: raise SystemExit(44)\n'
                's=os.fstat(f);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not stat.S_IMODE(s.st_mode)&0o077 and s.st_size<=1048576\n'
                'b=os.read(f,1048577);assert len(b)<=1048576 and not os.read(f,1);os.close(f);sys.stdout.buffer.write(b)')
            read = self.sudo(sys.executable, '-c', reader, str(file), name='read-production-registry', timeout=20)
            if read.returncode == 44 and not self.fixture_initialized: return None
            self.check(read.returncode == 0, 'normal_registry_unreadable');return json.loads(read.stdout)

        def case_normal(self, info):
            project = evidence/'project-normal';project.mkdir(mode=0o700)
            script = b"'use strict';\nconsole.log('production-normal');\n";(project/'run.js').write_bytes(script)
            request = {'source': str(self.runtime_copy), 'project': str(project),
                'config': {key: str(info[key]) for key in ('binary', 'socket')}}
            begin = time.monotonic()
            self.public_started = True
            # subprocess.run records direct caller exit; native/common claims
            # and separate UID observations remain necessary for cleanup.
            result = self.run('public-production-normal', [str(info['node']), str(controller)],
                data=base.canonical(request), timeout=330)
            terminal = None
            for line in result.stdout.splitlines():
                try: event = json.loads(line)
                except Exception: continue
                if event.get('type') == 'result':
                    self.check(terminal is None, 'duplicate_production_result');terminal = event
            row = {'name': 'normal', 'status': 'FAIL', 'elapsed_ms': (time.monotonic()-begin)*1000,
                'controller_exit_code': result.returncode, 'terminal': terminal,
                'stdout_sha256': base.sha_bytes(result.stdout), 'stderr_sha256': base.sha_bytes(result.stderr)}
            self.case_results.append(row)
            self.check(result.returncode == 0 and terminal and terminal.get('success') is True, 'public_production_normal_failed')
            self.check(terminal.get('source_unchanged') is True and (project/'run.js').read_bytes() == script, 'project_source_mutated')
            row['status'] = 'PASS_PHYSICAL_PRODUCTION';row['KVE_KVF_ACK_verified'] = True
            self.public_completed = True

        def case_basic(self, info, name):
            self.check(name in ('scratch_readonly', 'silent_long', 'exit7'), 'public_production_case_invalid')
            project = evidence/('project-'+name);project.mkdir(mode=0o700)
            request = {'source': str(self.runtime_copy), 'project': str(project), 'case_name': name,
                'config': {key: str(info[key]) for key in ('binary', 'socket')}}
            begin = time.monotonic();self.public_started = True;self.public_completed = False
            result = self.run('public-production-'+name, [str(info['node']), str(matrix_controller)],
                data=base.canonical(request), timeout=660 if name == 'exit7' else 330)
            terminal = None
            for line in result.stdout.splitlines():
                try: event = json.loads(line)
                except Exception: continue
                if event.get('type') == 'result':
                    self.check(terminal is None, 'duplicate_production_result');terminal = event
            row = {'name': name, 'status': 'FAIL', 'elapsed_ms': (time.monotonic()-begin)*1000,
                'controller_exit_code': result.returncode, 'terminal': terminal,
                'stdout_sha256': base.sha_bytes(result.stdout), 'stderr_sha256': base.sha_bytes(result.stderr)}
            self.case_results.append(row)
            self.check(result.returncode == 0 and terminal and terminal.get('success') is True and
                terminal.get('case_name') == name and terminal.get('source_unchanged') is True,
                'public_production_basic_failed')
            row['status'] = 'PASS_PHYSICAL_PRODUCTION';row['KVE_KVF_ACK_verified'] = name != 'exit7'
            if name == 'exit7':
                self.check(terminal.get('failed_KVE_verified') is True and terminal.get('failed_attempt_no_ACK') is True
                    and terminal.get('failed_cleanup_confirmed') is True and terminal.get('retry_accepted') is True
                    and terminal.get('retry_distinct_attempt') is True, 'public_production_basic_failed')
                row['failed_observation_verified'] = True
            self.public_completed = True

        def cleanup(self):
            if self.fixture is None and not self.root_identities and self.install_parent_identity is None: return
            if self.bootstrapped:
                stopped = self.sudo('/bin/launchctl', 'bootout', 'system/'+self.label, name='bootout-production', timeout=60)
                deadline = time.monotonic()+20
                while time.monotonic() < deadline and not self.label_absent(): time.sleep(.2)
                self.check(stopped.returncode == 0 and self.label_absent(), 'normal_service_exit_unconfirmed')
                self.bootstrapped = False
            if self.daemon_birth:
                deadline = time.monotonic()+20;gone = False
                while time.monotonic() < deadline:
                    observation = self.compare_birth(self.daemon_birth)
                    if observation.get('state') in ('absent', 'replaced'): gone = True;break
                    time.sleep(.1)
                self.check(gone, 'normal_daemon_exit_unconfirmed')
            self.check(not self.public_started or self.public_completed, 'public_writer_cleanup_unconfirmed_preserve_fixture')
            self.collect_fixture_allocations()
            for uid in sorted(self.task_uids):
                observed = self.sudo(str(self.uid_scan), str(uid), name='post-stop-production-uid', timeout=20)
                try: value = json.loads(observed.stdout)
                except Exception: value = None
                self.check(observed.returncode == 0 and isinstance(value, dict) and value.get('observation_valid') is True and
                    value.get('member_count') == 0, 'normal_UID_cleanup_unconfirmed')
            # Revalidate every originally created root before removing any.
            # The normal broker is stopped and every reserved UID is empty.
            validate = ('import os,stat,json,sys; d=json.loads(sys.argv[1]);\n'
                'for p,e in d.items():\n s=os.lstat(p);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and '
                's.st_dev==e["dev"] and s.st_ino==e["ino"] and stat.S_IMODE(s.st_mode)==e["mode"]\n')
            self.root('verify-owned-canonical-inodes', sys.executable, '-c', validate, json.dumps(self.root_identities))
            state = self.fixture_registry_snapshot()
            if state:
                self.check(state.get('active_attempt') == '', 'normal_active_allocation_preserve_fixture')
                for entry in state['attempts'].values():
                    self.check(entry.get('state') == 'closed' and entry.get('admission_closed') is True and
                        entry.get('spawn_intent') is False and entry.get('authority_spawn_intent') is False,
                        'normal_unresolved_spawn_preserve_fixture')
                    for role in ('launch_stub', 'root_child', 'authority', 'controller', 'command_identity'):
                        if entry.get(role):
                            observed = self.compare_birth(entry[role])
                            self.check(observed.get('state') in ('absent', 'replaced'), 'normal_actor_birth_preserve_fixture')
            # A root actor before credential drop is not visible in the private
            # UID scan. Take every exact admission inode lock and repeat birth
            # and UID observations while those exclusions remain held through
            # removal. The stopped service cannot create another allocation.
            remove = validate + '''import fcntl,subprocess,shutil
state=json.loads(sys.argv[2]);registry=sys.argv[3];birth_observer=sys.argv[4];uid_scan=sys.argv[5];held=[]
for attempt,entry in (state or {}).get('attempts',{}).items():
 assert entry.get('state')=='closed' and entry.get('admission_closed') is True and entry.get('spawn_intent') is False and entry.get('authority_spawn_intent') is False
 saved=entry['admission_inode'];fd=os.open(os.path.join(registry,attempt+'.admission'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not stat.S_IMODE(s.st_mode)&0o077 and s.st_dev==saved['device'] and s.st_ino==saved['inode']
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);held.append(fd)
 for role in ('launch_stub','root_child','authority','controller','command_identity'):
  identity=entry.get(role)
  if identity:
   r=subprocess.run([birth_observer,str(identity['pid']),str(identity['unique_id']),str(identity['start_sec']),str(identity['start_usec'])],capture_output=True,timeout=10)
   observed=json.loads(r.stdout);assert r.returncode==0 and observed.get('state') in ('absent','replaced')
 r=subprocess.run([uid_scan,str(entry['descriptor']['task_ruid'])],capture_output=True,timeout=20)
 observed=json.loads(r.stdout);assert r.returncode==0 and observed.get('observation_valid') is True and observed.get('member_count')==0
for p,e in d.items():
 s=os.lstat(p);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_dev==e['dev'] and s.st_ino==e['ino'] and stat.S_IMODE(s.st_mode)==e['mode']
for p in d: shutil.rmtree(p)
for fd in held: os.close(fd)
'''
            self.root('remove-owned-canonical-inodes', sys.executable, '-c', remove, json.dumps(self.root_identities),
                json.dumps(state), str(self.roots.get('registry', '')), str(self.birth_observer), str(self.uid_scan), timeout=90)
            self.root_identities = {};self.roots = {};self.fixture_initialized = False
            self.check(not (isinstance(self.install_parent_observation, dict) and self.install_parent_observation.get('created') is True)
                or self.install_parent_identity is not None or self.install_parent_observation.get('removed') is True,
                'install_parent_creation_unconfirmed')
            if self.install_parent_identity is not None:
                remove_parent = ('import os,stat,json,sys;p=sys.argv[1];e=json.loads(sys.argv[2]);s=os.lstat(p);'
                    'assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_dev==e["dev"] and s.st_ino==e["ino"] and stat.S_IMODE(s.st_mode)==e["mode"];'
                    'os.rmdir(p)')
                self.root('remove-created-install-parent', sys.executable, '-c', remove_parent,
                    str(Path(CANONICAL['registry']).parent), json.dumps(self.install_parent_identity), timeout=20)
                self.install_parent_identity = None
                # The creation receipt remains history; do not treat a later
                # idempotent cleanup call as an unknown created inode.
                self.install_parent_observation = {**self.install_parent_observation, 'removed': True}
            if self.fixture:
                # The reference created this unique protected fixture and the
                # exact service/UID gates above are already satisfied.
                inspect = ('import os,stat,sys,json; p=sys.argv[1];s=os.lstat(p);e=json.loads(sys.argv[2]);assert stat.S_ISDIR(s.st_mode) and '
                    's.st_uid==0 and stat.S_IMODE(s.st_mode)==0o711 and os.path.dirname(p)=="/private/tmp" and '
                    'os.path.basename(p).startswith("knowledge-pipeline4.") and s.st_dev==e["dev"] and s.st_ino==e["ino"]')
                self.root('verify-owned-fixture', sys.executable, '-c', inspect, str(self.fixture), json.dumps(self.fixture_identity))
                self.root('remove-owned-fixture', sys.executable, '-c', inspect+';import shutil;shutil.rmtree(p)',
                    str(self.fixture), json.dumps(self.fixture_identity), timeout=60);self.fixture = None
            self.cleanup_confirmed = True

        def execute(self):
            self.check(platform.machine() == args.expected_arch, 'runner_architecture_mismatch')
            self.make_private_evidence()
            inputs = {'files': self.input_pins,
                'controller_sha256': base.sha_file(controller), 'lifecycle_sha256': base.sha_file(Path(__file__)),
                'reference_runner_sha256': base.sha_file(module_path)}
            if args.case_set == 'basic':
                inputs.update(matrix_controller_sha256=base.sha_file(matrix_controller), workloads_sha256=base.sha_file(matrix_workloads))
            if args.case_set == 'failures':
                inputs['failure_assets'] = {name: base.sha_file(Path(__file__).with_name(name)) for name in (
                    'darwin-production-failure-cases.py', 'darwin-production-failure-caller.js', 'darwin-production-control.js',
                    'darwin-production-process-observer.c', 'darwin-test-signal.c', 'darwin-production-failure-summary.py')}
            base.private_file(evidence/'INPUTS.json', base.canonical(inputs))
            self.prepare_runtime();self.compile_uid_scan();self.compile_birth_observer();self.compile_pair(False)
            if args.case_set == 'failures':
                self.failure_helpers = failure_module.compile_helpers(self, base, Path(__file__).parent)
            self.fixture_path();st = self.fixture.lstat();self.fixture_identity = {'dev': st.st_dev, 'ino': st.st_ino}
            base.private_file(evidence/'created-fixture.json', base.canonical(self.fixture_identity))
            info = self.setup_normal();self.case_protected_executable(info);self.case_normal(info)
            if args.case_set == 'basic':
                for name in ('scratch_readonly', 'silent_long', 'exit7'): self.case_basic(info, name)
            if args.case_set == 'failures':
                for name in failure_module.CASES:
                    failure_module.run_case(self, base, info, Path(__file__).parent, self.failure_helpers, name)
            self.cleanup()
            self.status = {'basic': 'PASS_PHYSICAL_PRODUCTION_BASIC', 'failures': 'PASS_PHYSICAL_PRODUCTION_FAILURES',
                           'normal': 'PASS_PHYSICAL_PRODUCTION_NORMAL'}[args.case_set]

    runner = Runner();failure = None;diagnostics = [];raw_traceback = None
    try: runner.execute()
    except BaseException as error:
        failure = str(error);runner.status = 'FAIL';diagnostics.append(diagnostic(error, 'execute'));raw_traceback = traceback.format_exc()
    finally:
        try: runner.cleanup()
        except BaseException as error:
            runner.status = 'FAIL';failure = (failure or '')+';cleanup:'+str(error);diagnostics.append(diagnostic(error, 'cleanup'))
        if evidence.exists():
            try: unchanged = inventory(source) == runner.input_pins
            except BaseException: unchanged = False
            if not unchanged: runner.status = 'FAIL';failure = (failure or '')+';source_changed'
            summary = {'schema': 'knowledge-darwin-production-physical.v1', 'status': runner.status, 'failure': failure,
                'case_set': args.case_set,
                'architecture': platform.machine(), 'source_unchanged': unchanged, 'cases': runner.case_results,
                'cleanup_confirmed': runner.cleanup_confirmed, 'binary_history': runner.binary_history,
                'native_addon': runner.native_manifest, 'installed_bindings': runner.installed_bindings,
                'failure_helper_pins': {name: value for name, value in (runner.failure_helpers or {}).items() if name.endswith('_pin')},
                'protected_executable_contract': runner.protected_contract,
                'installation_parent': runner.install_parent_observation,
                'records': runner.records, 'diagnostics': diagnostics, 'raw_traceback': raw_traceback,
                'release_gate_qualified': False, 'scope': 'Normal public production request on disposable hosted macOS; other production failures have separate gates.'}
            (evidence/'SUMMARY.json').write_text(json.dumps(summary, indent=2)+'\n')
    return 0 if runner.status == {'basic': 'PASS_PHYSICAL_PRODUCTION_BASIC', 'failures': 'PASS_PHYSICAL_PRODUCTION_FAILURES',
                                  'normal': 'PASS_PHYSICAL_PRODUCTION_NORMAL'}[args.case_set] else 1


if __name__ == '__main__':
    try: raise SystemExit(main())
    except SystemExit: raise
    except BaseException as error:
        try:
            output = Path(sys.argv[sys.argv.index('--evidence')+1]).resolve();output.mkdir(mode=0o700, parents=True, exist_ok=True)
            with (output/'DIAGNOSTIC.json').open('x') as f: json.dump({'diagnostics': [diagnostic(error, 'bootstrap')]}, f)
            with (output/'bootstrap.traceback.private').open('x') as f: traceback.print_exc(file=f)
        except BaseException: pass
        raise SystemExit(1)
