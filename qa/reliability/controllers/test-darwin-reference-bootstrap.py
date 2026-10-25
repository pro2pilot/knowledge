#!/usr/bin/env python3
"""Exact reference bootstrap pin check; the compiler call is explicitly modeled."""
import importlib.util, os, subprocess, sys, tempfile, unittest
from pathlib import Path

reference=Path(os.environ.get('KNOWLEDGE_DARWIN_REFERENCE',Path(__file__).resolve().parents[2]/'reference')).resolve()
module_path=reference/'qa/darwin-pipeline4/run_pipeline4.py'
sys.path.insert(0,str(module_path.parent))
spec=importlib.util.spec_from_file_location('native_reference_bootstrap',module_path)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

class Bootstrap(unittest.TestCase):
    def test_exact_uid_observer_reaches_compiler_without_relaxing_reference_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner=base.Runner(module_path.parent/'PINS.json',Path(temporary),'arm64',Path(temporary)/'public')
            runner.workspace=reference;calls=[]
            def modeled_compiler(name,argv,**kwargs):
                calls.append((name,argv));return subprocess.CompletedProcess(argv,0,b'',b'')
            runner.run=modeled_compiler
            runner.compile_uid_scan()
            self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][0],'compile-uid-scan')
            self.assertEqual(base.sha_file(reference/'qa/darwin-broker/uid-scan.c'),base.UID_SCAN_SHA256)
            self.assertEqual(runner.uid_scan,Path(temporary)/'uid-scan')
if __name__=='__main__':unittest.main()
