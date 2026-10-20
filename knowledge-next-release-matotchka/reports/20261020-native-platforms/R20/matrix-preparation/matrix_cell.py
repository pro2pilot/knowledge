#!/usr/bin/env python3
"""Run one frozen Node 22.17.1 Linux/macOS diagnostic cell, never a release gate."""
from __future__ import annotations
import argparse, hashlib, json, os, platform, re, signal, subprocess, sys, time
import collect_results as audit_collection
from pathlib import Path

MATRIX_SCHEMA='knowledge-platform-matrix-freeze.v1'
NODE_VERSION='v22.17.1'
TOTAL_BUDGET_SECONDS=110*60
INACTIVITY_SECONDS=20*60
CLEANUP_BUDGET_SECONDS=30
ACTIVE_PROCESS=None
CANCEL_SIGNAL=None

def manifest(root):
    root=Path(root).resolve(strict=True)
    out={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink(): raise ValueError(f'symlink in frozen source: {path}')
        if path.is_file(): out[path.relative_to(root).as_posix()]={'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    return out

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def pin(path):
    data=Path(path).read_bytes();return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def verify_commit_binding(freeze, workspace, source, actual_ci, run=subprocess.run):
    """Bind a prior source commit without requiring a self-referential receipt hash."""
    commit=freeze.get('workflow',{}).get('source_commit')
    if not isinstance(commit,str) or not re.fullmatch(r'[a-f0-9]{40}',commit):
        raise ValueError('reviewed full source_commit is required')
    if not isinstance(actual_ci,str) or not re.fullmatch(r'[a-fA-F0-9]{40}',actual_ci):
        raise ValueError('actual GITHUB_SHA is required')
    actual_ci=actual_ci.lower()
    def git(*args):
        return run(['git','-C',str(workspace),*args],capture_output=True,check=True,timeout=30).stdout
    if git('rev-parse','HEAD').decode().strip().lower()!=actual_ci:
        raise ValueError('checkout HEAD differs from actual CI commit')
    git('merge-base','--is-ancestor',commit,actual_ci)
    prefix=source.relative_to(workspace).as_posix().rstrip('/')+'/'
    tree=git('ls-tree','-r','-z',commit,'--',prefix)
    expected={}
    for row in tree.split(b'\0'):
        if not row: continue
        header,name=row.split(b'\t',1); mode,kind,oid=header.decode().split()
        name=name.decode('utf-8')
        if mode not in ('100644','100755') or kind!='blob' or not name.startswith(prefix):
            raise ValueError('unsupported committed source entry')
        expected[name[len(prefix):]]=oid
    if not expected: raise ValueError('source_commit contains no source at repository_path')
    actual={}
    for name in manifest(source):
        data=(source/name).read_bytes()
        actual[name]=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if actual!=expected: raise ValueError('source_commit tree differs from frozen checkout source')
    return {'source_commit':commit,'actual_ci_commit':actual_ci,'committed_source_files':len(actual)}

def stop_owned_group(process, reason):
    actions=[]
    try:
        os.killpg(process.pid, signal.SIGTERM); actions.append('SIGTERM_owned_session')
    except ProcessLookupError:
        actions.append('session_already_gone')
    except OSError as error:
        actions.append({'SIGTERM_error':type(error).__name__})
    deadline=time.monotonic()+CLEANUP_BUDGET_SECONDS-5
    while process.poll() is None and time.monotonic()<deadline: time.sleep(0.25)
    leader_exited=process.poll() is not None
    group_remains=False
    try: os.killpg(process.pid,0); group_remains=True
    except ProcessLookupError: pass
    except OSError: group_remains=True
    if process.poll() is None:
        try: os.killpg(process.pid, signal.SIGKILL); actions.append('SIGKILL_owned_session')
        except ProcessLookupError: actions.append('session_gone_before_SIGKILL')
        except OSError as error: actions.append({'SIGKILL_error':type(error).__name__})
    elif group_remains:
        actions.append('leader_exited_group_remains_not_killed_by_recyclable_pid')
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: actions.append('process_not_reaped_within_cleanup_budget')
    return {'reason':reason,'pid':process.pid,'process_group':process.pid,'actions':actions,
            'quarantined':True,'containment_confirmed':False,
            'cleanup_scope':'initial_process_group_only_detached_descendants_not_contained'}

def progress_signature(path):
    path=Path(path)
    if not path.exists(): return None
    rows=[]
    if path.is_dir():
        for item in path.rglob('result.json'):
            try: rows.append((item.relative_to(path).as_posix(),item.stat().st_size,item.stat().st_mtime_ns))
            except OSError: continue
        for item in path.rglob('PROGRESS.json'):
            try: rows.append((item.relative_to(path).as_posix(),item.stat().st_size,item.stat().st_mtime_ns))
            except OSError: continue
    else:
        try: rows.append((path.name,path.stat().st_size,path.stat().st_mtime_ns))
        except OSError: pass
    return tuple(sorted(rows))

def run_controller(label, argv, output, progress_path, deadline):
    global ACTIVE_PROCESS
    log_stdout=output/f'{label}.stdout.log';log_stderr=output/f'{label}.stderr.log'
    started=time.monotonic(); last_progress=started; signature=progress_signature(progress_path); reason=None
    with log_stdout.open('wb') as stdout, log_stderr.open('wb') as stderr:
        process=subprocess.Popen(argv,stdout=stdout,stderr=stderr,start_new_session=True)
        ACTIVE_PROCESS=process
        try:
            while process.poll() is None:
                now=time.monotonic(); current=progress_signature(progress_path)
                if current!=signature: signature=current;last_progress=now
                if CANCEL_SIGNAL is not None: reason='outer_signal_'+str(CANCEL_SIGNAL);break
                if now>=deadline: reason='total_work_budget_exhausted';break
                if now-last_progress>=INACTIVITY_SECONDS: reason='no_meaningful_progress';break
                time.sleep(2)
            if reason:
                cleanup=stop_owned_group(process,reason)
                cancellation={'label':label,'argv':[str(x) for x in argv],'cwd':str(Path.cwd()),**cleanup,
                              'total_budget_seconds':TOTAL_BUDGET_SECONDS,'inactivity_budget_seconds':INACTIVITY_SECONDS,
                              'cleanup_budget_seconds':CLEANUP_BUDGET_SECONDS}
                (output/f'CANCELLATION_{label}.json').write_text(json.dumps(cancellation,indent=2)+'\n',encoding='utf-8')
            code=process.poll()
            stdout.flush();stderr.flush()
        except KeyboardInterrupt:
            cleanup=stop_owned_group(process,'outer_keyboard_interrupt')
            cancellation={'label':label,'argv':[str(x) for x in argv],'cwd':str(Path.cwd()),**cleanup,
                          'cleanup_budget_seconds':CLEANUP_BUDGET_SECONDS}
            (output/f'CANCELLATION_{label}.json').write_text(json.dumps(cancellation,indent=2)+'\n',encoding='utf-8')
            stdout.flush();stderr.flush()
            raise
        finally:
            ACTIVE_PROCESS=None
    out=log_stdout.read_bytes();err=log_stderr.read_bytes()
    record={'label':label,'argv':[str(x) for x in argv],'cwd':str(Path.cwd()),'exit_code':code,
            'stdout_bytes':len(out),'stdout_sha256':hashlib.sha256(out).hexdigest(),
            'stderr_bytes':len(err),'stderr_sha256':hashlib.sha256(err).hexdigest(),
            'elapsed_seconds':round(time.monotonic()-started,3)}
    if reason:
        cancellation=json.loads((output/f'CANCELLATION_{label}.json').read_text(encoding='utf-8'))
        record.update(cancelled=True,cancellation=cancellation)
        return 124,record
    return code,record

def on_cancel(signum, frame):
    global CANCEL_SIGNAL
    CANCEL_SIGNAL=signum
    raise KeyboardInterrupt(f'outer cancellation signal {signum}')

def main():
    signal.signal(signal.SIGTERM,on_cancel)
    signal.signal(signal.SIGINT,on_cancel)
    job_started=time.monotonic(); deadline=job_started+TOTAL_BUDGET_SECONDS
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('freeze','node','docs','output','work','workspace'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--suite-timeout',type=int,default=900)
    a=p.parse_args()
    freeze=json.loads(a.freeze.read_text(encoding='utf-8-sig'))
    if freeze.get('schema_version')!=MATRIX_SCHEMA: p.error('freeze receipt schema mismatch')
    actual_ci=os.environ.get('GITHUB_SHA')
    workspace=a.workspace.resolve(strict=True)
    freeze_path=a.freeze.resolve(strict=True)
    if not freeze_path.is_relative_to(workspace): p.error('freeze receipt must be inside the checked-out workspace')
    a.freeze=freeze_path
    def repo_file(section):
        rel=freeze.get(section,{}).get('repository_path')
        if not isinstance(rel,str) or not rel or Path(rel).is_absolute() or '..' in Path(rel).parts: raise ValueError(f'unsafe {section} repository_path in freeze')
        path=(workspace/rel).resolve(strict=True)
        if not path.is_relative_to(workspace): raise ValueError(f'{section} escapes checkout')
        return path
    src=repo_file('source'); archive=repo_file('archive'); node=a.node.resolve(strict=True)
    expected_source=freeze.get('source',{}); expected_archive=freeze.get('archive',{})
    source_now=manifest(src)
    if len(source_now)!=expected_source.get('files') or source_now!=expected_source.get('entries') or digest(source_now)!=expected_source.get('manifest_sha256'):
        p.error('current source does not match frozen source manifest')
    try: commit_binding=verify_commit_binding(freeze,workspace,src,actual_ci)
    except (ValueError,subprocess.SubprocessError) as error: p.error(f'commit binding failed: {error}')
    if pin(archive)!={'bytes':expected_archive.get('bytes'),'sha256':expected_archive.get('sha256')}:
        p.error('candidate ZIP bytes differ from freeze receipt')
    runtime=audit_collection.archive_manifest(archive)
    if runtime!=expected_archive.get('runtime_entries') or digest(runtime)!=expected_archive.get('runtime_manifest_sha256'):
        p.error('runtime ZIP entry map differs from reviewed freeze receipt')
    projection=freeze.get('runtime_projection',{})
    if projection.get('canonical_packager_parity') is not True or projection.get('difference_count')!=0:
        p.error('freeze receipt does not establish source/ZIP projection parity')
    version=subprocess.run([str(node),'--version'],text=True,capture_output=True,timeout=10,check=True).stdout.strip()
    ident=json.loads(subprocess.run([str(node),'-p','JSON.stringify({execPath:process.execPath,platform:process.platform,arch:process.arch,version:process.version})'],text=True,capture_output=True,timeout=10,check=True).stdout)
    expected_platform='linux' if sys.platform.startswith('linux') else 'darwin' if sys.platform=='darwin' else None
    if freeze.get('required_node_version')!=NODE_VERSION or expected_platform not in ('linux','darwin') or ident.get('platform')!=expected_platform or version!=NODE_VERSION:
        p.error(f'cell runtime mismatch: platform={ident.get("platform")}, version={version}')
    if Path(ident['execPath']).resolve()!=node: p.error('Node execPath does not match selected binary')
    a.output.mkdir(parents=True,exist_ok=False);a.work.mkdir(parents=True,exist_ok=False)
    names=['matrix_cell.py','run_full_validation.py','run_candidate_base.py','collect_results.py','run_installed_suites.py','verify-docs.test.cjs','classify_cell.py','knowledge-platform-matrix.yml']
    controller_pins={name:pin(Path(__file__).with_name(name)) for name in names}
    if freeze.get('controllers',{}).get('files') != controller_pins: p.error('controller byte pins differ from reviewed freeze receipt')
    meta={'schema_version':'knowledge-platform-matrix-cell.v1','os':platform.platform(),'os_name':expected_platform,'node':ident, 'node_pin':pin(node), 'required_node_version':freeze['required_node_version'],
          'source_path':str(src),'source_manifest_sha256':digest(expected_source['entries']),'source_files':len(expected_source['entries']),
          'archive_path':str(archive),'archive_pin':pin(archive),'runtime_files':len(expected_archive.get('runtime_entries',{})),
          'runtime_manifest_sha256':expected_archive.get('runtime_manifest_sha256'), 'release_identity':freeze.get('release_identity'),'freeze_receipt_sha256':pin(a.freeze)['sha256'],
          'workflow_commit':actual_ci,'commit_binding':commit_binding,'controller_files':{},'work_budget_seconds':TOTAL_BUDGET_SECONDS,'inactivity_budget_seconds':INACTIVITY_SECONDS,'cleanup_budget_seconds':CLEANUP_BUDGET_SECONDS,'classification_policy':{'exit_or_assertion_failure':'FAIL','explicit_node_test_skip':'PARTIAL','native_windows_containment':'UNAVAILABLE_SEPARATE_BLOCKER'},
          'scope':'full source suite and source/runtime syntax replay; installed focused smoke; no release gate or provider setup'}
    meta['controller_files']=controller_pins
    (a.output/'CELL_INPUTS.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    runner=Path(__file__).with_name('run_full_validation.py')
    cmd=[sys.executable,str(runner),'--source',str(src),'--archive',str(archive),'--node',str(node),'--docs',str(a.docs.resolve(strict=True)),
         '--output',str(a.output/'full-source'),'--work',str(a.work/'full-source'),'--suite-timeout',str(a.suite_timeout),'--syntax-timeout','30','--shard-index','0','--shard-count','1']
    (a.output/'FULL_SOURCE_ARGV.json').write_text(json.dumps(cmd,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    full_exit,full_record=run_controller('full-source-controller',cmd,a.output,a.output/'full-source'/'commands',deadline)
    records=[full_record]
    replay_path=a.output/'full-source'/'replay-results.json'
    if not replay_path.is_file() or full_record.get('cancelled'):
        (a.output/'CONTROLLER_PROCESSES.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8');return 1
    replay_summary=json.loads(replay_path.read_text(encoding='utf-8-sig'))
    if replay_summary.get('fatal_error') is not None:
        (a.output/'CONTROLLER_PROCESSES.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8');return 1
    # This portable installed wrapper runs ten ZIP-installed suites, including install-check and doctor audit.
    installed=Path(__file__).with_name('run_installed_suites.py')
    installed_output=a.output/'installed-suites'
    installed_work=a.work/'installed-suites'
    installed_cmd=[sys.executable,str(installed),'--archive',str(archive),'--expected-archive-sha256',expected_archive['sha256'],'--freeze',str(a.freeze.resolve(strict=True)),'--node',str(node),'--output',str(installed_output),'--fixture-root',str(installed_work)]
    (a.output/'INSTALLED_ARGV.json').write_text(json.dumps(installed_cmd,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    installed_exit,installed_record=run_controller('installed-suites-controller',installed_cmd,a.output,a.output/'installed-suites'/'PROGRESS.json',deadline)
    records.append(installed_record)
    collector=Path(__file__).with_name('collect_results.py')
    collect_cmd=[sys.executable,str(collector),'--run',str(a.output/'full-source'),'--source',str(src),'--archive',str(archive),'--freeze',str(a.freeze.resolve(strict=True)),'--receipt',str(a.output/'COLLECTED.json')]
    (a.output/'COLLECTOR_ARGV.json').write_text(json.dumps(collect_cmd,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    collector_exit,collector_record=run_controller('strict-collector',collect_cmd,a.output,a.output/'COLLECTED.json',deadline)
    records.append(collector_record)
    (a.output/'CONTROLLER_PROCESSES.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
    if collector_exit!=0: return 1
    receipt=json.loads((a.output/'COLLECTED.json').read_text(encoding='utf-8'))
    installed_summary=a.output/'installed-suites'/'SUMMARY.json'
    if not installed_summary.is_file(): return 1
    installed_status=json.loads(installed_summary.read_text(encoding='utf-8-sig')).get('status')
    (a.output/'CELL_STATUS.json').write_text(json.dumps({'full_source':receipt.get('status'),'installed_10':installed_status,'native_windows_capability':'unavailable_separate_release_blocker','overall_status':'partial','process_containment':'unavailable'},indent=2)+'\n',encoding='utf-8')
    if receipt.get('status') not in ('pass','partial') or installed_status not in ('pass','partial'): return 1
    if (receipt['status']=='pass' and full_exit!=0) or (receipt['status']=='partial' and full_exit!=1) or installed_exit!=0: return 1
    if any(row.get('cancellation',{}).get('quarantined') for row in records): return 1
    # Successful portable diagnostics do not certify an unavailable native backend.
    return 2
if __name__=='__main__': raise SystemExit(main())
