#!/usr/bin/env python3
import importlib.util, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

here=Path(__file__).resolve().parent
target=Path(os.environ.get('KNOWLEDGE_DARWIN_PUBLIC_SUMMARY',here/'darwin-public-summary.py')).resolve()
spec=importlib.util.spec_from_file_location('darwin_public_summary',target)
public=importlib.util.module_from_spec(spec);spec.loader.exec_module(public)

class PublicAllowlist(unittest.TestCase):
    def test_bootstrap_diagnostics_allow_code_coordinates_only(self):
        with tempfile.TemporaryDirectory() as folder:
            private=Path(folder)/'private';private.mkdir();source=Path(folder)/'source';source.mkdir()
            secret='DO_NOT_PUBLISH_exception_args_or_path'
            value={'diagnostics':[{'type':'FileNotFoundError','stage':'bootstrap','message':secret,'args':[secret],
                'frames':[{'file':'run_pipeline4.py','line':973,'locals':secret,'path':secret},
                          {'file':secret,'line':123},{'file':'persistence_gate.py','line':-2}]}]}
            (private/'DIAGNOSTIC.json').write_text(json.dumps(value))
            summary,_=public.build(private,source,1,'arm64')
            self.assertNotIn(secret,json.dumps(summary))
            self.assertEqual(summary['diagnostics'],[{'type':'FileNotFoundError','stage':'bootstrap',
                'frames':[{'file':'run_pipeline4.py','line':973}]}])

    def test_cli_fails_incomplete_matrix_even_when_controller_exited_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            private=Path(folder)/'private';private.mkdir();source=Path(folder)/'source';source.mkdir()
            good={'status':'PASS_PHYSICAL_NATIVE_DIAGNOSTIC_ONLY','architecture':'arm64','source_unchanged':True,
                'cases':[{'name':name,'status':'PASS_PHYSICAL_NATIVE_DIAGNOSTIC'} for name in public.CASES]}
            cases=[('complete',good,0),('missing',{**good,'cases':good['cases'][:-1]},1),
                ('duplicate',{**good,'cases':good['cases']+[good['cases'][0]]},1),
                ('other-arch',{**good,'architecture':'x86_64'},1),
                ('source-mutated',{**good,'source_unchanged':False},1)]
            for name,value,expected in cases:
                with self.subTest(case=name):
                    (private/'SUMMARY.json').write_text(json.dumps(value));destination=Path(folder)/name
                    result=subprocess.run([sys.executable,str(target),'--private',str(private),'--public',str(destination),
                        '--source',str(source),'--controller-status','0','--expected-arch','arm64'],
                        capture_output=True,text=True,timeout=15)
                    self.assertEqual(result.returncode,expected,result.stdout+result.stderr)
                    self.assertEqual(sorted(p.name for p in destination.iterdir()),['stages.json','summary.json'])
                    actual=json.loads((destination/'summary.json').read_text())
                    self.assertEqual(actual['status'],'PASS_NATIVE_DIAGNOSTIC_MATRIX' if not expected else 'FAIL_OR_INCOMPLETE')

    def test_raw_native_values_do_not_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            private=Path(folder)/'private';private.mkdir();source=Path(folder)/'source';source.mkdir()
            secret='DO_NOT_PUBLISH_NATIVE_PAYLOAD_0123456789'
            value={'status':'FAIL','failure':secret,'architecture':'arm64','source_unchanged':True,
                'token':secret,'nonce':secret,'workspace_path':secret,'native_proofs':[{'token':secret}],
                'cases':[{'name':'io-stop','status':'FAIL','reason':secret,'stdout':secret,'token':secret,
                    'gate':{'entered':{'token':secret},'result':secret,'facts_observed_before_release':True}}],
                'records':[{'name':'001-'+secret,'exit_code':1,'timed_out':False,'raw':secret},
                           {'name':'002-compile-shipping-01-broker','exit_code':1,'timed_out':False}]}
            (private/'SUMMARY.json').write_text(json.dumps(value))
            (private/'INPUTS.json').write_text(json.dumps({'source':secret,'files':[],'token':secret}))
            (private/'002-compile-shipping-01-broker.stderr.raw').write_text('clang: error: compile failed\n')
            summary,stages=public.build(private,source,1,'arm64')
            text=json.dumps([summary,stages]);self.assertNotIn(secret,text);self.assertNotIn('workspace_path',text)
            self.assertEqual(summary['failure_code'],'controller_failure_details_private')
            self.assertEqual(stages['stages'][0]['stage'],'001-unclassified-stage')
            self.assertEqual(summary['compiler_diagnostics'][0]['stderr_excerpt'],'clang: error: compile failed')
            self.assertFalse(summary['backend_qualified']);self.assertEqual(summary['production_KVE_KVF_ACK'],'NOT_RUN')
    def test_subset_bad_arch_and_duplicates_cannot_claim_full_matrix(self):
        with tempfile.TemporaryDirectory() as folder:
            private=Path(folder)/'private';private.mkdir();source=Path(folder)/'source';source.mkdir()
            good={'status':'PASS_PHYSICAL_NATIVE_DIAGNOSTIC_ONLY','architecture':'arm64','source_unchanged':True,
                'cases':[{'name':name,'status':'PASS_PHYSICAL_NATIVE_DIAGNOSTIC'} for name in public.CASES]}
            for names,arch,expected in ((list(public.CASES),'arm64','PASS_NATIVE_DIAGNOSTIC_MATRIX'),
                (['io-stop'],'arm64','FAIL_OR_INCOMPLETE'),(list(public.CASES),'x86_64','FAIL_OR_INCOMPLETE'),
                (list(public.CASES)+['normal'],'arm64','FAIL_OR_INCOMPLETE')):
                value={**good,'cases':[{'name':name,'status':'PASS_PHYSICAL_NATIVE_DIAGNOSTIC'} for name in names]}
                (private/'SUMMARY.json').write_text(json.dumps(value))
                summary,_=public.build(private,source,0,arch);self.assertEqual(summary['status'],expected)

if __name__=='__main__':unittest.main()
