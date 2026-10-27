#!/usr/bin/env python3
"""One bounded ordinary-user probe of the exact audit6 installed ZIP."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess

HERE = Path(__file__).resolve().parent
EXPECTED_ZIP = '0cf11f0bd207066c01ae78472d0884d5d7fc34ae8a77e0b1a095d16656bd00bf'

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--package',required=True)
    parser.add_argument('--out',required=True)
    args=parser.parse_args()
    if os.getuid()!=1001 or os.geteuid()!=1001 or platform.machine().lower() not in {'aarch64','arm64'}:
        raise RuntimeError('native ARM64 ordinary UID1001 required')
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
    report={'schema_version':'knowledge-linux-exact-installed-diagnostic.v1','status':'FAIL',
            'diagnostic_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),
            'policy_changed':False,'ptrace_used':False,'release_qualification':False,
            'timed_out':False,'cleanup_confirmed':False}
    try:
        spec=importlib.util.spec_from_file_location('installed_contract',HERE/'run_installed_contract.py')
        installed=importlib.util.module_from_spec(spec);spec.loader.exec_module(installed)
        root,contents=installed.extract(args,out,report)
        if report['artifact_sha256']!=EXPECTED_ZIP:raise RuntimeError('not the exact failing installed archive')
        temp=out/'tmp';temp.mkdir()
        env={k:v for k,v in os.environ.items() if not k.startswith('KNOWLEDGE_')}
        env.update(TMPDIR=str(temp),TMP=str(temp),TEMP=str(temp))
        argv=['node',str(HERE/'diagnose_linux_nested.cjs'),str(root/'.knowledge/tools/lib/verification-linux-namespace.js')]
        try:
            result=subprocess.run(argv,env=env,capture_output=True,timeout=45)
        except subprocess.TimeoutExpired as error:
            # subprocess kills/reaps the exact controller child. Its native
            # keeper has an independent 20s lifetime, but absence of its full
            # receipt is never promoted to an observed cleanup completion.
            (out/'nested.stdout.json').write_bytes(error.stdout or b'')
            (out/'nested.stderr.txt').write_bytes(error.stderr or b'')
            report.update(timed_out=True,cleanup_confirmed=False,
                          cleanup_status='unconfirmed_after_controller_timeout')
            raise
        (out/'nested.stdout.json').write_bytes(result.stdout)
        (out/'nested.stderr.txt').write_bytes(result.stderr)
        report['exit_code']=result.returncode
        report['diagnostic_source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),HERE/'diagnose_linux_nested.cjs']}
        report['installed_byte_changes']=[name for name,row in contents.items() if hashlib.sha256((root/name).read_bytes()).hexdigest()!=row['sha256']]
        observed=json.loads(result.stdout)
        report['native_status']=observed['status']
        report['outer_cleanup']=observed.get('cleanup')
        report['prepared_artifact_cleanup']=observed.get('artifact_cleanup')
        report['inner_started']=observed.get('inner',{}).get('inner_started',False)
        report['inner_failure']=observed.get('inner',{}).get('failure')
        report['cleanup_confirmed']=observed.get('cleanup',{}).get('status')=='completed' and observed.get('artifact_cleanup',{}).get('status')=='completed'
        if result.returncode or report['installed_byte_changes']:raise RuntimeError('diagnostic incomplete or installed bytes changed')
        report['status']='DIAGNOSTIC_OBSERVED'
        return 0
    except Exception as error:
        report['error']=repr(error)
        return 1
    finally:
        (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))

if __name__=='__main__':raise SystemExit(main())
