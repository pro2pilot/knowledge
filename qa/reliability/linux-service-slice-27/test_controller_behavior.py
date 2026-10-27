"""Behavioral QA regressions: actual controller, inert OS, ordinary Node TAP only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('controller.py')
spec = importlib.util.spec_from_file_location('controller_review_frozen', SOURCE)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class P:
    def __init__(self, name): self.name = str(name)
    def __truediv__(self, leaf): return P(self.name + '/' + str(leaf))
    def __str__(self): return self.name
    def exists(self): return False
    def is_symlink(self): return False
    def iterdir(self): return []
    def mkdir(self, *args, **kwargs): pass
    def lstat(self): return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755, st_dev=1, st_ino=3)
    def read_text(self, **kwargs): raise OSError('injected fdinfo failure')


class Behavior(unittest.TestCase):
    def test_actual_node22_tap_positive_and_negative(self):
        code = "require('node:test')(%s,()=>{});" % json.dumps(c.EXPECTED_TEST_NAME)
        result = subprocess.run(['node', '--test-reporter=tap', '-e', code], capture_output=True, timeout=10, check=True)
        self.assertEqual(subprocess.check_output(['node', '--version'], timeout=5).strip(), b'v22.17.1')
        self.assertEqual(c.tap_inventory(result.stdout)['tests'], 1)
        self.assertIsNone(c.tap_inventory(result.stdout.replace(b'# skipped 0', b'# skipped 1')))
        self.assertIsNone(c.tap_inventory(result.stdout + b'not ok 2 - unexpected\n'))

    def test_claim_fsync_failure_retains_exact_custody(self):
        obj = c.RootRun.__new__(c.RootRun)
        obj.run_id = 'fixed'; obj.claim_created = False; obj.claim_identity = None
        obj.unit_confirmed = True; obj.install_created = False
        obj.helpers = types.SimpleNamespace(physical_file=lambda *a, **k: (None, b''))
        fake = types.SimpleNamespace(O_WRONLY=1, O_CREAT=2, O_EXCL=4,
            open=lambda *a: 8, fstat=lambda fd: types.SimpleNamespace(st_uid=0,st_gid=0,st_mode=0o600,st_dev=1,st_ino=5),
            write=lambda fd, view: len(view), fsync=lambda fd: (_ for _ in ()).throw(OSError('injected fsync failure')), close=lambda fd: None)
        with patch.multiple(c, Path=P, os=fake, require_no_acl=lambda p: None, physical_read=lambda *a:(None,b'')):
            with self.assertRaises(OSError): obj.reserve_uids()
        self.assertTrue(obj.claim_created); self.assertEqual(obj.claim_identity[:2], (1,5))
        with patch.object(c, 'physical_read', side_effect=OSError('partial claim')):
            self.assertFalse(obj.release_claim())

    def test_install_acl_failure_retains_exact_custody(self):
        obj = c.RootRun.__new__(c.RootRun)
        obj.install_root=P('/var/lib/fixed'); obj.install_created=False; obj.root_identity=None
        obj.unit_confirmed=True; obj.native_child_reaped=False
        fake=types.SimpleNamespace(mkdir=lambda *a: None, chown=lambda *a:None, chmod=lambda *a:None)
        with patch.multiple(c, os=fake, no_symlink_dir=lambda *a: obj.install_root.lstat(),
                            require_no_acl=lambda p: (_ for _ in ()).throw(OSError('injected ACL failure'))):
            with self.assertRaises(OSError): obj.install_files()
        self.assertTrue(obj.install_created); self.assertEqual(obj.root_identity,(1,3))
        self.assertFalse(obj.cleanup_install())

    def test_fdinfo_exception_reaps_native_client_before_closing_pidfd(self):
        events=[]
        class Child:
            pid=123; returncode=None
            def poll(self): return self.returncode
            def kill(self): events.append('kill')
            def wait(self, **kw): events.append('wait'); self.returncode=-9; return -9
        child=Child()
        fake=types.SimpleNamespace(O_RDWR=0,O_WRONLY=0,O_CREAT=0,O_EXCL=0,
            open=lambda *a:8, pidfd_open=lambda *a:42, close=lambda fd: events.append(('close',fd)))
        obj=c.RootRun.__new__(c.RootRun)
        obj.private=P('/private'); obj.unit='fixed'; obj.install_root=P('/fixed'); obj.result={}
        obj.native_child_reaped=False
        obj.helpers=types.SimpleNamespace(signal_pidfd=lambda *a:events.append('signal'))
        with patch.multiple(c, os=fake, Path=P, signal=types.SimpleNamespace(SIGKILL=9), physical_read=lambda *a,**kw: (_ for _ in ()).throw(OSError('no raw output'))), \
             patch.object(c.subprocess,'Popen',return_value=child):
            with self.assertRaises(OSError): obj.run_native()
        self.assertTrue(obj.native_child_reaped)
        self.assertLess(events.index('wait'),events.index(('close',42)))

    def test_export_pidfd_allocation_failure_drains_registered_child(self):
        obj=c.RootRun.__new__(c.RootRun)
        obj.public_dir=P('/public'); obj.result={'status':'PASS_COMPONENT_QA'}; obj.native_json_body=None
        registry={}; calls=[]
        def fork(): registry[123]=None; raise OSError('injected pidfd allocation failure after fork')
        def cleanup(): calls.append('cleanup'); registry.clear(); return True
        obj.helpers=types.SimpleNamespace(fork_owned_helper=fork, cleanup_owned_helpers=cleanup, OWNED_HELPERS=registry)
        st=types.SimpleNamespace(st_uid=1001,st_gid=1001,st_mode=stat.S_IFDIR|0o755,st_dev=1,st_ino=3)
        obj.public_dir.lstat=lambda:st
        fake=types.SimpleNamespace(O_RDONLY=0,O_DIRECTORY=0,
            open=lambda *a:77, fstat=lambda fd:st, stat=lambda *a,**k: (_ for _ in ()).throw(FileNotFoundError()),
            pipe2=lambda *a:(81,82), close=lambda fd:None)
        with patch.multiple(c, os=fake, no_symlink_dir=lambda *a:st, require_no_acl=lambda *a:None):
            with self.assertRaises(OSError): obj.write_public()
        self.assertTrue(calls, 'Registered child must be drained before exception escapes')
        self.assertFalse(registry, 'No lost registered exporter child')

    def test_partial_export_never_publishes_terminal_controller_pass(self):
        self._partial_export_case('NATIVE.json')

    def test_late_export_fsync_failure_leaves_only_candidate(self):
        self._partial_export_case('directory_fsync')

    def _partial_export_case(self, fail_at):
        obj=c.RootRun.__new__(c.RootRun)
        obj.public_dir=P('/public'); obj.native_json_body=b'{}\n'
        obj.result={'status':'PASS_COMPONENT_QA','native_proof_sha256':hashlib.sha256(obj.native_json_body).hexdigest()}
        dirs=types.SimpleNamespace(st_uid=1001,st_gid=1001,st_mode=stat.S_IFDIR|0o755,st_dev=1,st_ino=3)
        obj.public_dir.lstat=lambda:dirs
        opened={}; payloads={}; published={}; events=[]
        def open_file(name,*a,**kw):
            if not kw: return 77
            fd=100+len(opened); opened[name]=fd; payloads[fd]=bytearray(); return fd
        def write(fd,body):
            if fd in payloads: payloads[fd].extend(body)
            return len(body)
        def file_stat(fd):
            if fd==77:return dirs
            return types.SimpleNamespace(st_uid=1001,st_gid=1001,st_mode=stat.S_IFREG|0o644,st_nlink=1,st_size=len(payloads[fd]))
        def link(src,dst,**kw):
            if dst==fail_at: raise OSError('injected artifact publication failure')
            published[dst]=bytes(payloads[opened[src]])
        def fsync(fd):
            if fd==77 and fail_at=='directory_fsync': raise OSError('injected final directory fsync failure')
        def exit_child(code): raise SystemExit(code)
        obj.helpers=types.SimpleNamespace(fork_owned_helper=lambda:0,close_unlisted_fds=lambda keep:None,
            drop_ids=lambda *a:events.append('dropped'))
        fake=types.SimpleNamespace(O_RDONLY=0,O_DIRECTORY=0,O_WRONLY=0,O_CREAT=0,O_EXCL=0,
            open=open_file,fstat=file_stat,stat=lambda *a,**k: (_ for _ in ()).throw(FileNotFoundError()),
            pipe2=lambda *a:(81,82),close=lambda fd:None,write=write,fchmod=lambda *a:None,fsync=fsync,
            link=link,unlink=lambda *a,**kw:None,_exit=exit_child)
        with patch.multiple(c,os=fake,no_symlink_dir=lambda *a:dirs,require_no_acl=lambda *a:None):
            with self.assertRaises(SystemExit) as result:obj.write_public()
        self.assertEqual(result.exception.code,23)
        self.assertEqual(events,['dropped'])
        if fail_at=='directory_fsync': self.assertIn('RESULT.json',published)
        if 'RESULT.json' in published:
            self.assertNotEqual(json.loads(published['RESULT.json'])['status'],'PASS_COMPONENT_QA',
                'Export failure must not leave an artifact claiming terminal controller qualification')
            self.assertEqual(json.loads(published['RESULT.json'])['status'],'CANDIDATE_COMPONENT_QA')

    def test_export_reap_exception_drains_registered_child(self):
        obj=c.RootRun.__new__(c.RootRun)
        obj.public_dir=P('/public'); obj.result={'status':'PASS_COMPONENT_QA'}; obj.native_json_body=None
        registry={}; calls=[]
        def fork(): registry[123]=42; return 123
        def cleanup(): calls.append('cleanup'); registry.clear(); return True
        obj.helpers=types.SimpleNamespace(fork_owned_helper=fork, cleanup_owned_helpers=cleanup, OWNED_HELPERS=registry,
            reap_exact_child=lambda *a: (_ for _ in ()).throw(OSError('injected wait failure')))
        st=types.SimpleNamespace(st_uid=1001,st_gid=1001,st_mode=stat.S_IFDIR|0o755,st_dev=1,st_ino=3)
        obj.public_dir.lstat=lambda:st
        fake=types.SimpleNamespace(O_RDONLY=0,O_DIRECTORY=0,
            open=lambda *a:77,fstat=lambda fd:st,stat=lambda *a,**k: (_ for _ in ()).throw(FileNotFoundError()),
            pipe2=lambda *a:(81,82),close=lambda fd:None)
        with patch.multiple(c,os=fake,no_symlink_dir=lambda *a:st,require_no_acl=lambda *a:None):
            with self.assertRaises(OSError):obj.write_public()
        self.assertTrue(calls,'Exceptional wait must still invoke bounded owned-child cleanup')
        self.assertFalse(registry)


if __name__=='__main__':
    print('controller_sha256='+hashlib.sha256(SOURCE.read_bytes()).hexdigest(),flush=True)
    unittest.main()
