#!/usr/bin/env python3
"""Reproducible local audit runner. Raw attempts are immutable, never replaced.

Each suite gets an exact source copy, an isolated Git index and owned tmp.
The test harness's timeout/cleanup is not evidence of product native cleanup.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
NODE = Path('/opt/codex/runtimes/codex-primary-runtime/dependencies/node/bin/node')
GIT = Path('/usr/local/bin/git')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def manifest(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in sorted(root.rglob('*')) if p.is_file()}

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def inventory(source):
    result=[]
    for p in sorted((source/'tools').glob('self-test*.js')):
        args=[p.relative_to(source).as_posix()]
        if p.name=='self-test-team-mode.js': args+=['--keep-temp']
        if p.name=='self-test-install-policy.js': args+=['--keep']
        result.append({'id':p.stem,'argv':args,'kind':'self-test-program'})
    for p in sorted((source/'tests').rglob('*')):
        if p.is_file() and (p.name.endswith(('.test.js','.test.cjs','.test.mjs')) or p.name.startswith('self-test-') and p.suffix in ('.js','.cjs','.mjs')):
            rel=p.relative_to(source).as_posix()
            result.append({'id':rel.replace('/','__'),'argv':['--test','--test-concurrency=1',rel],'kind':'node-test'})
    result.append({'id':'recording-blockers-workflow','argv':['tools/self-test-recording-blockers.js','--workflow-fixture'],'kind':'workflow-variant'})
    return result

def env_for(fixture):
    env={k:v for k,v in os.environ.items() if not (k.startswith(('GIT_','KNOWLEDGE_','LD_')) or k in ('NODE_OPTIONS','NODE_PATH'))}
    temp=fixture/'tmp'; temp.mkdir(parents=True,exist_ok=True)
    overrides={'PATH':str(NODE.parent)+os.pathsep+os.environ.get('PATH',''),
      'TMPDIR':str(temp),'TMP':str(temp),'TEMP':str(temp),
      'GIT_CEILING_DIRECTORIES':str(temp),'GIT_TERMINAL_PROMPT':'0','CI':'1',
      'KNOWLEDGE_AGENT_ID':'independent-posix-recovery-audit',
      'KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH':'1',
      'KNOWLEDGE_AUDIT_SYSTEM_ROOT':str(fixture/'.knowledge'),
      'KNOWLEDGE_ROUTING_TEST_TMP':str(temp/'typed-scope'),
      'KNOWLEDGE_TRANSACTION_TEST_TMP':str(temp/'transaction'),
      'KNOWLEDGE_SYNC_TEST_TMP':str(temp/'sync-history')}
    env.update(overrides)
    return env,overrides

def run(argv,cwd,env,output,timeout):
    output.mkdir(parents=True,exist_ok=False)
    start=time.monotonic(); started_at=datetime.now(timezone.utc).isoformat(); timed_out=False; error=None
    with (output/'stdout.log').open('wb') as out,(output/'stderr.log').open('wb') as err:
        try:
            p=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
            try: code=p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                os.killpg(p.pid,signal.SIGKILL)
                try: code=p.wait(timeout=10)
                except subprocess.TimeoutExpired: code=None
        except Exception as e: code=None; error=type(e).__name__+': '+str(e)
    record={'argv':list(map(str,argv)),'cwd':str(cwd),'started_at_utc':started_at,
      'duration_ms':round((time.monotonic()-start)*1000,3),'timeout_seconds':timeout,'exit_code':code,
      'timed_out':timed_out,'error':error,'status':'PASS' if code==0 and not timed_out and error is None else 'FAIL',
      'stdout_sha256':digest(output/'stdout.log'),'stderr_sha256':digest(output/'stderr.log')}
    write(output/'result.json',record)
    return record

def main():
    global NODE, GIT
    a=argparse.ArgumentParser();a.add_argument('--source',type=Path,default=ROOT/'candidate/source/.knowledge')
    a.add_argument('--node',type=Path,default=NODE);a.add_argument('--git',type=Path,default=GIT)
    a.add_argument('--label',required=True);a.add_argument('--only',action='append');a.add_argument('--timeout',type=int,default=900)
    a.add_argument('--inventory-only',action='store_true');a.add_argument('--syntax',action='store_true')
    args=a.parse_args();NODE=args.node.resolve();GIT=args.git.resolve();source=args.source.resolve();out=ROOT/'evidence'/args.label
    if out.exists():raise SystemExit('Attempt already exists; choose a new label')
    out.mkdir(parents=True);suites=inventory(source)
    if args.only:
        unknown=set(args.only)-{s['id'] for s in suites}
        if unknown:raise SystemExit('Unknown suites: '+repr(sorted(unknown)))
        suites=[s for s in suites if s['id'] in args.only]
    before=manifest(source)
    write(out/'source-before.json',before);write(out/'inventory.json',suites)
    write(out/'environment.json',{'platform':os.uname().sysname,'release':os.uname().release,
      'node':str(NODE),'node_sha256':digest(NODE),'runner_sha256':digest(Path(__file__)),
      'scope':'local physical Linux source-context execution; Windows/macOS not executed',
      'full_release_gate':'NOT_RUN','source':str(source)})
    if args.inventory_only:return
    rows=[]
    for index,suite in enumerate(suites,1):
        label=f'{index:03d}-{suite["id"]}'
        fixture=ROOT/'work'/args.label/f'{index:03d}'
        fixture.mkdir(parents=True)
        shutil.copytree(source,fixture/'.knowledge')
        copied=manifest(fixture/'.knowledge')
        if copied!=before:raise RuntimeError('Source drift during fixture creation')
        write(out/'fixture-manifests'/f'{index:03d}.json',copied)
        env,overrides=env_for(fixture)
        for action,argv in [('init',[str(GIT),'init','--quiet']),('add',[str(GIT),'-c','core.autocrlf=false','add','.knowledge'])]:
            setup=run(argv,fixture,env,out/'setup'/f'{index:03d}-{action}',60)
            if setup['status']!='PASS':raise RuntimeError('Fixture Git setup failed')
        row=run([str(NODE),*suite['argv']],fixture/'.knowledge',env,out/'commands'/label,args.timeout)
        row.update({'id':suite['id'],'kind':suite['kind'],'environment_overrides':overrides})
        raw=(out/'commands'/label/'stdout.log').read_text(errors='replace')
        # A skip is visible partial coverage, never an unconditional PASS.
        row['has_skips']=bool(re.search(r'# SKIP|(?:# skip|\u2139 skipped)\s+[1-9]\d*\b',raw))
        if row['has_skips'] and row['status']=='PASS':row['status']='PARTIAL'
        write(out/'commands'/label/'result.json',row)
        rows.append(row);write(out/'results-in-progress.json',rows)
        print(f'{index}/{len(suites)} {suite["id"]} {row["status"]} {row["duration_ms"]}ms',flush=True)
    syntax=[]
    if args.syntax:
        for index,p in enumerate(sorted(p for p in source.rglob('*') if p.is_file() and p.suffix in ('.js','.cjs','.mjs')),1):
            r=run([str(NODE),'--check',str(p)],source,os.environ.copy(),out/'syntax'/f'{index:04d}',30)
            r['file']=p.relative_to(source).as_posix();syntax.append(r)
    after=manifest(source);write(out/'source-after.json',after)
    summary={'counts':{s:sum(x['status']==s for x in rows) for s in ('PASS','FAIL','PARTIAL')},
      'suites':rows,'syntax_total':len(syntax),'syntax_failures':[x for x in syntax if x['status']!='PASS'],
      'source_unchanged':before==after}
    write(out/'summary.json',summary);print(json.dumps({k:v for k,v in summary.items() if k not in ('suites','syntax_failures')}),flush=True)
    raise SystemExit(1 if summary['counts']['FAIL'] or summary['syntax_failures'] or before!=after else 0)

if __name__=='__main__':main()
