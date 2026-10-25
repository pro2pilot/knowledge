#!/usr/bin/env python3
import importlib.util, json, tempfile, unittest
from pathlib import Path

here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('darwin_public_summary',here/'darwin-public-summary.py')
public=importlib.util.module_from_spec(spec);spec.loader.exec_module(public)

class PublicAllowlist(unittest.TestCase):
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
