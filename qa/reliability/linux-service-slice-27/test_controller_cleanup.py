"""Actual cleanup/diagnostic behavior with inert cgroup/process fixtures."""
import importlib.util
import json
from pathlib import Path
import stat
import types
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('controller_cleanup',Path(__file__).with_name('controller.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


class Group:
    def __init__(self,*states):self.states=list(states or ['present'])
    def lstat(self):
        state=self.states.pop(0) if len(self.states)>1 else self.states[0]
        if state=='absent':raise FileNotFoundError()
        return types.SimpleNamespace(st_uid=1001 if state=='foreign' else 0,
            st_mode=(stat.S_IFLNK if state=='symlink' else stat.S_IFDIR)|0o755)


class Cleanup(unittest.TestCase):
    def obj(self,**unit):
        obj=c.RootRun.__new__(c.RootRun);obj.unit='fixed';obj.unit_intent=True;obj.result={};obj.unit_confirmed=False
        values={'LoadState':'loaded','ActiveState':'failed','MainPID':'0','ControlGroup':''};values.update(unit)
        obj.inspect_unit=lambda:values;obj.admin=lambda *a:None
        obj.service_cgroup=Group();obj.work_cgroup=Group()
        obj.helpers=types.SimpleNamespace(read_cgroup_events=lambda p:{'populated':0},OWNED_HELPERS={},HELPER_UNCONFIRMED=False)
        return obj

    def test_loaded_terminal_empty_or_expected_cgroup(self):
        for active in ['inactive','failed']:
            for cg in ['', '/system.slice/fixed.service']:
                with self.subTest(active=active,cg=cg):
                    obj=self.obj(ActiveState=active,ControlGroup=cg)
                    self.assertTrue(obj.stop_confirmed());self.assertEqual(obj.result['final_unit_state']['ControlGroup'],cg)
                    self.assertEqual(obj.result['final_expected_cgroups'],{'service':'empty','work':'empty'})

    def test_both_expected_groups_independently_gone_or_gc(self):
        obj=self.obj(LoadState='not-found');obj.service_cgroup=Group('absent');obj.work_cgroup=Group('absent')
        self.assertTrue(obj.stop_confirmed())
        obj=self.obj();obj.service_cgroup=Group('present','absent')
        obj.helpers.read_cgroup_events=lambda p: (_ for _ in ()).throw(FileNotFoundError()) if p is obj.service_cgroup else {'populated':0}
        self.assertTrue(obj.stop_confirmed());self.assertEqual(obj.result['final_expected_cgroups']['service'],'absent_after_gc')

    def test_foreign_active_missing_pid_and_nonempty_denied(self):
        for change in [{'ControlGroup':'/foreign/private/path'},{'MainPID':'77'},{'MainPID':''},{'ActiveState':'active'},{'LoadState':'unexpected'}]:
            obj=self.obj(**change);self.assertFalse(obj.stop_confirmed())
        obj=self.obj(ControlGroup='/foreign/private/path');obj.stop_confirmed()
        self.assertEqual(obj.result['final_unit_state']['ControlGroup'],'foreign_or_invalid')
        for which in ['service','work']:
            obj=self.obj(LoadState='not-found');group=getattr(obj,which+'_cgroup')
            obj.helpers.read_cgroup_events=lambda p:{'populated':1 if p is group else 0}
            self.assertFalse(obj.stop_confirmed())

    def test_events_missing_existing_dir_and_unsafe_groups_denied(self):
        obj=self.obj();obj.helpers.read_cgroup_events=lambda p: (_ for _ in ()).throw(FileNotFoundError())
        self.assertFalse(obj.stop_confirmed())
        for state in ['foreign','symlink']:
            obj=self.obj();obj.work_cgroup=Group(state);self.assertFalse(obj.stop_confirmed())

    def test_install_cleanup_still_requires_native_and_helper_drain(self):
        for child,registry,unconfirmed in [(False,{},False),(True,{123:42},False),(True,{},True)]:
            obj=self.obj();obj.install_created=True;obj.root_identity=(1,2);obj.unit_confirmed=True;obj.native_child_reaped=child
            obj.helpers.OWNED_HELPERS=registry;obj.helpers.HELPER_UNCONFIRMED=unconfirmed
            with patch.object(c,'remove_owned_tree') as remove:
                self.assertFalse(obj.cleanup_install());remove.assert_not_called()

    def test_bounded_failure_is_diagnostic_only(self):
        good=b'{"status":"FAIL"}\n'
        self.assertTrue(c.bounded_native_failure(good))
        for body in [None,b'{"status":"WORK_CLOSED"}\n',b'{"status":"FAIL"}',good+good,b'not json\n',b'x'*(c.MAX_NATIVE_JSON+1)]:
            self.assertFalse(c.bounded_native_failure(body))
        obj=self.obj();obj.observer_acknowledged=False
        with self.assertRaises(c.SliceFailure) as err:obj.observe_native_and_ack(good)
        self.assertEqual(err.exception.code,'native_reported_failure');self.assertFalse(obj.observer_acknowledged)

    def test_already_exited_native_failure_changes_only_missing_ack_reason(self):
        class InertPath:
            def __init__(self,name):self.name=str(name)
            def __truediv__(self,name):return InertPath(self.name+'/'+name)
            def __str__(self):return self.name
            def mkdir(self,**kw):pass
            def read_text(self,**kw):return 'Pid:\t123\n'
        child=types.SimpleNamespace(pid=123,returncode=1,poll=lambda:1,wait=lambda **kw:1)
        fake=types.SimpleNamespace(O_RDWR=0,O_WRONLY=0,O_CREAT=0,O_EXCL=0,open=lambda *a:8,pidfd_open=lambda *a:42,close=lambda fd:None)
        for raw,reason in [(b'{"status":"FAIL"}\n','native_reported_failure'),
                           (b'{"status":"WORK_CLOSED"}\n','observer_ack_missing')]:
            obj=self.obj();obj.private=InertPath('/private');obj.install_root=InertPath('/fixed')
            obj.native_child_reaped=False;obj.observer_acknowledged=False;obj.native_json_body=None
            with patch.multiple(c,os=fake,Path=InertPath,physical_read=lambda *a,**kw:(types.SimpleNamespace(st_uid=0),raw),write_new_file=lambda *a:None), \
                 patch.object(c.subprocess,'Popen',return_value=child):
                with self.assertRaises(c.SliceFailure) as err:obj.run_native()
            self.assertEqual(err.exception.code,reason);self.assertTrue(obj.native_child_reaped)
            self.assertFalse(obj.observer_acknowledged)

    def native(self):
        tap=('TAP version 13\n# Subtest: '+c.EXPECTED_TEST_NAME+'\nok 1 - '+c.EXPECTED_TEST_NAME+
            "\n  ---\n  duration_ms: 1\n  type: 'test'\n  ...\n1..1\n# tests 1\n# suites 0\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1\n").encode()
        value={'status':'WORK_CLOSED','production_admission':False,'release_gate_qualified':False,'observer_ack_required':True,
            'component':'readonly_node_namespace','phase':4,'work_ms':1,'cleanup_ms':1,'proof_emitted_ms':1,'stop_reason':4,
            'output_bytes':len(tap),'output_hex':tap.hex(),'input_manifest_sha256':'a'*64,'directories_sha256':'b'*64,
            'importer_report_hex':('KSM1 chroot_root_not_mountpoint EINVAL\nKSI1 '+'a'*64+' '+'b'*64+' 2 7\nKSD1 writable_alias_ready\n').encode().hex()}
        value.update({k:True for k in ['cleanup_confirmed','importer_namespace_drained','importer_detached_writer_ready','source_readonly','authority_readback','cgroup_empty','output_eof']})
        value.update({k:0 for k in ['init_wait_status','keeper_wait_status','worker_wait_status','authority_wait_status','importer_wait_status']})
        return value

    def parse(self,value):
        obj=self.obj();obj.result={'reasons':[]};obj.private=Path('/inert');obj.observer_acknowledged=True;obj.native_child_reaped=True
        obj.plan={'blob':{'manifest_sha256':'a'*64,'directories_sha256':'b'*64,'files':2,'total_bytes':7}}
        with patch.object(c,'write_new_file'):obj.parse_native(0,json.dumps(value).encode()+b'\n')
        return obj

    def test_new_importer_fields_strict_and_nonzero_wait_never_passes(self):
        self.assertEqual(self.parse(self.native()).result['reasons'],[])
        for wait in [-1,256]:
            value=self.native();value['importer_wait_status']=wait
            self.assertIn('native_component_contract_failed',self.parse(value).result['reasons'])
        for report in ['a','AA','0g','aa'*258]:
            value=self.native();value['importer_report_hex']=report
            with self.assertRaises(c.SliceFailure):self.parse(value)
        value=self.native();value['importer_wait_status']=True
        with self.assertRaises(c.SliceFailure):self.parse(value)

    def test_importer_receipt_binds_legacy_failure_and_exact_prepared_manifest(self):
        for old,new in [(b'EINVAL',b'EPERM'),(b' 2 7\n',b' 2 8\n'),(b'KSD1 writable_alias_ready',b'KSD1 missing_alias'),(b'KSM1 ',b'KSM1  ')]:
            value=self.native()
            value['importer_report_hex']=bytes.fromhex(value['importer_report_hex']).replace(old,new).hex()
            with self.assertRaises(c.SliceFailure) as caught:self.parse(value)
            self.assertEqual(caught.exception.code,'native_importer_report_mismatch')


if __name__=='__main__':unittest.main()
