#!/usr/bin/env python3
"""Execute the manifest's public tests from one verified installed ZIP.

This is installed-contract evidence, not an invented replacement for the
missing maintainer release gate or the separate production platform matrix.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, math, os, pathlib, platform, re
import shutil, signal, stat, subprocess, sys, tempfile, time, zipfile

P = pathlib.Path
ROOT = P(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('audit5_pack', ROOT/'qa/reliability/audit5/run_installed.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
sha, save, need = base.sha, base.save, base.need
MAX_OUTPUT = 8 * 1024 * 1024
REGRESSIONS = ['reliability-recovery-adapter-ledger', 'reliability-recovery-adapter-budget',
               'reliability-recovery-outer-budget', 'reliability-recovery-deadline',
               'verification-cleanup-transcript', 'verification-finalization-v2', 'verification-isolated-copy', 'reliability-macos-failed-observation',
               'repair-producer-dependency-closure', 'verification-control']

def strict_json(body):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate JSON key: '+key)
            value[key] = item
        return value
    def finite(value): raise ValueError('nonfinite JSON value: '+value)
    def number(value):
        result=float(value)
        if not math.isfinite(result):raise ValueError('overflowed JSON number: '+value)
        return result
    return json.loads(body, object_pairs_hook=unique, parse_constant=finite, parse_float=number)

def fixture_environment(tmp, out):
    env = {k:v for k,v in os.environ.items() if not k.upper().startswith(('KNOWLEDGE_', 'GIT_'))}
    inherited = os.environ.get('TEMP', os.environ.get('TMP', os.environ.get('TMPDIR','')))
    env.update(CI='1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH='1', TMPDIR=str(tmp), TMP=str(tmp), TEMP=str(tmp),
               KNOWLEDGE_AUDIT5_INHERITED_TEMP=inherited,
               KNOWLEDGE_TEAM_MODE_FAILURE_DIR=str(out/'team-failure-evidence'),
               GIT_AUTHOR_NAME='Knowledge fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
               GIT_COMMITTER_NAME='Knowledge fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
    return env

def prepare_fixture_temp(out, report, deadline):
    requested = os.environ.get('RUNNER_TEMP')
    need(bool(requested), 'RUNNER_TEMP_required_for_isolated_fixtures')
    parent = P(requested).resolve(strict=True)
    need(parent.is_dir(), 'fixture_temp_parent_not_directory')
    tmp = P(tempfile.mkdtemp(prefix='knowledge-installed-contract-', dir=parent)).resolve(strict=True)
    checkout = ROOT.resolve(strict=True)
    report['fixture_parent'] = {'requested_runner_temp':requested, 'canonical_runner_temp':str(parent),
        'path':str(tmp), 'checkout':str(checkout), 'outside_checkout':checkout != tmp and checkout not in tmp.parents,
        'inherited_temp':os.environ.get('TEMP', os.environ.get('TMP', os.environ.get('TMPDIR',''))),
        'retained_for_diagnostics':True}
    need(report['fixture_parent']['outside_checkout'], 'fixture_temp_is_inside_checkout')
    allowance = min(10, deadline-time.monotonic());need(allowance>0,'fixture_probe_budget_exhausted')
    environment = fixture_environment(tmp,out);environment.update(LANG='C',LC_ALL='C')
    probe = subprocess.run(['git','rev-parse','--show-toplevel'],cwd=tmp,env=environment,
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=allowance)
    (out/'fixture-git-probe.stdout.txt').write_bytes(probe.stdout)
    (out/'fixture-git-probe.stderr.txt').write_bytes(probe.stderr)
    report['fixture_parent'].update(git_probe_exit=probe.returncode,
        git_probe_stdout_sha256=hashlib.sha256(probe.stdout).hexdigest(),
        git_probe_stderr_sha256=hashlib.sha256(probe.stderr).hexdigest())
    need(probe.returncode != 0 and b'not a git repository' in probe.stderr.lower(),
         'fixture_temp_inherits_git_repository_or_git_probe_failed')
    return tmp

def execute(name, argv, cwd, out, deadline, timeout=90, fixture_tmp=None):
    before = time.monotonic()
    row = {'name':name, 'argv':argv, 'status':'FAIL', 'timed_out':False}
    stdout, stderr = out/(name+'.stdout.json'), out/(name+'.stderr.txt')
    tmp = P(fixture_tmp if fixture_tmp is not None else tempfile.gettempdir()).resolve(strict=True)
    env = fixture_environment(tmp,out)
    allowance = min(timeout, deadline-before)
    if allowance <= 0:
        row.update(status='NOT_RUN_BUDGET_EXHAUSTED', cleanup_confirmed=False)
        return row, None
    print(json.dumps({'event':'step_start','name':name,'cap_s':round(allowance,3),
                      'cohort_remaining_s':round(deadline-before,3)}),flush=True)
    with stdout.open('wb') as a, stderr.open('wb') as b:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=a, stderr=b, start_new_session=(os.name != 'nt'))
        expires = before + allowance
        next_progress = before + 15
        while child.poll() is None:
            observed = time.monotonic()
            if observed >= next_progress:
                print(json.dumps({'event':'step_running','name':name,'elapsed_s':round(observed-before,3),
                    'step_remaining_s':round(max(0,expires-observed),3)}),flush=True)
                next_progress = observed + 15
            if max(stdout.stat().st_size, stderr.stat().st_size) > MAX_OUTPUT:
                row['output_limit_exceeded'] = True
                break
            if time.monotonic() >= expires:
                row['timed_out'] = True
                break
            try: child.wait(timeout=min(0.1, max(0.001, expires-time.monotonic())))
            except subprocess.TimeoutExpired: pass
        if row['timed_out'] or row.get('output_limit_exceeded'):
            # Emergency harness cleanup is diagnostic; it cannot qualify a
            # product cleanup barrier or let the matrix silently continue.
            try:
                if os.name == 'nt':
                    subprocess.run(['taskkill','/PID',str(child.pid),'/T','/F'],stdout=b,stderr=b,timeout=10,check=False)
                else:
                    try: os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                child.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as error:
                row['emergency_cleanup_error'] = type(error).__name__+': '+str(error)
        code = child.returncode
    row.update(exit_code=code, elapsed_s=round(time.monotonic()-before,3),
        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
        stdout_bytes=stdout.stat().st_size, stderr_bytes=stderr.stat().st_size)
    print(json.dumps({'event':'step_exit','name':name,'exit_code':code,'elapsed_s':row['elapsed_s'],
                      'timed_out':row['timed_out'],'output_limit_exceeded':row.get('output_limit_exceeded',False)}),flush=True)
    if row['timed_out'] or row.get('output_limit_exceeded'):
        row.update(status='TIMEOUT_CLEANUP_UNCONFIRMED' if row['timed_out'] else 'OUTPUT_LIMIT_CLEANUP_UNCONFIRMED', cleanup_confirmed=False)
        return row, None
    if max(stdout.stat().st_size,stderr.stat().st_size)>MAX_OUTPUT:
        row.update(status='OUTPUT_LIMIT_CLEANUP_UNCONFIRMED', output_limit_exceeded=True,
                   cleanup_confirmed=False, error='output_size_exceeded');return row,None
    value = None
    try: value=strict_json(stdout.read_text(encoding='utf8'))
    except (ValueError,UnicodeError): pass
    row['status']='PASS_PROCESS' if code==0 else 'FAIL_PROCESS'
    return row,value

def admit_report(script, row, value):
    if row['status']!='PASS_PROCESS': return
    if not isinstance(value,dict):
        row.update(status='FAIL_REPORT',error='complete_json_object_required');return
    if script=='tools/self-test-linux-namespace.js':
        valid=value.get('schema_version')=='knowledge-linux-namespace-selftest.v1' and \
          type(value.get('fail')) is int and value['fail']==0 and \
          type(value.get('blocked')) is int and value['blocked']==0 and \
          type(value.get('pass')) is int and value['pass']>0
    else:
        valid=value.get('status') in ('pass','passed')
    for key in ['fail','failed','tests_failed','failed_count']:
        if key in value:
            count=value[key]
            if type(count) is int: valid=valid and count==0
            elif isinstance(count,list): valid=valid and not count
            else: valid=False
    row['reported_status']=value.get('status')
    row['status']='PASS_SELFTEST' if valid else 'FAIL_REPORT'
    for key in ['schema_version','checks_total','tests_total','tests_passed','tests_failed',
                'total','passed','pass','fail','blocked','skipped','evidence_kind',
                'native_lock_recovery','native_execution_capability','child_processes_executed',
                'workflow_fixture','temp_root_cleaned']:
        if key in value: row[key]=value[key]
    if 'checks_total' not in row and isinstance(value.get('checks'),list):row['checks_total']=len(value['checks'])

def extract(args,out,report):
    package=P(args.package).resolve(strict=True)
    prov=strict_json((package/'BUILD_PROVENANCE.json').read_text())
    need(prov['status']=='PASS_PACKAGED_STRUCTURAL_VALIDATION','package_not_validated')
    archive_path=package/prov['artifact_name']
    need(sha(archive_path)==prov['artifact_sha256'],'package_digest_mismatch')
    need(sha(package/'PACKAGE_CONTENTS.json')==prov['package_contents_sha256'],'entry_manifest_digest_mismatch')
    need(sha(package/'SOURCE_PINS.json')==prov['source_pins_sha256'],'source_inventory_digest_mismatch')
    contents=strict_json((package/'PACKAGE_CONTENTS.json').read_text())
    extracted=out/'fresh-install';extracted.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        need(len(archive.namelist())==len(contents) and set(archive.namelist())==set(contents),'entry_inventory_mismatch')
        need(archive.testzip() is None,'zip_crc_failed')
        for info in archive.infolist():
            base.safe_name(info.filename)
            need(info.filename.startswith('.knowledge/') and not info.is_dir() and
                 not stat.S_ISLNK(info.external_attr>>16),'invalid_archive_entry')
            data=archive.read(info);entry=contents[info.filename]
            need(hashlib.sha256(data).hexdigest()==entry['sha256'] and len(data)==entry['bytes'],'entry_digest_mismatch')
            dest=extracted/info.filename;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
            if os.name!='nt':dest.chmod(entry['mode'])
    report.update(artifact_sha256=prov['artifact_sha256'],artifact_bytes=archive_path.stat().st_size,
                  artifact_name=archive_path.name,source_pins_sha256=prov['source_pins_sha256'],entries_verified=len(contents))
    return extracted,contents

def installed(args,out,report):
    targeted=args.mode=='targeted'
    final_windows=args.mode=='final_windows'
    regressions=REGRESSIONS+(['reliability-linux-nested-preflight'] if final_windows else [])
    sharded=getattr(args,'shard_index',None) is not None
    need(not final_windows or sys.platform=='win32','final_windows_requires_windows')
    cohort_cap=900 if sharded else 1200 if final_windows else 330 if targeted else 660
    deadline=time.monotonic()+cohort_cap
    extracted,contents=extract(args,out,report);system=extracted/'.knowledge'
    contract=strict_json((system/'install-manifest.json').read_text())['release_contract']
    scripts=contract['public_self_test_paths']
    need(len(scripts)==54 and len(set(scripts))==54,'public_contract_inventory_changed')
    need(all((system/s).is_file() for s in scripts),'missing_public_selftest')
    for expected in contract['native_runtime_artifacts']:
        base.native_pair(system,expected,system/expected['binary'],system/expected['manifest'])
    node=shutil.which('node');need(bool(node),'node_unavailable')
    fixture_tmp = prepare_fixture_temp(out,report,deadline)
    row,runtime=execute('installed-native-load',[node,'-e',base.NATIVE_JS],system,out,deadline,fixture_tmp=fixture_tmp)
    report['steps'].append(row)
    need(row['status']=='PASS_PROCESS' and runtime and runtime.get('status')=='pass' and
         runtime.get('arch')==args.arch,'native_runtime_not_qualified')
    row['status']='PASS_NATIVE_LOAD';report['runtime']=runtime
    # The ZIP is installed into an actual disposable Git project. Public
    # self-tests create their own fixtures using these installed modules.
    for name,argv in [('git-init',['git','init','--initial-branch=main']),
                      ('install-check',[node,str(system/'tools/install-check.js'),'--json'])]:
        row,value=execute(name,argv,extracted,out,deadline,fixture_tmp=fixture_tmp)
        report['steps'].append(row)
        if name=='install-check':
            row['report']=value
            row['status']='PASS_INSTALL_CHECK' if row['status']=='PASS_PROCESS' and isinstance(value,dict) and value.get('status') in ('ok','warning','warnings','pass') else 'FAIL_INSTALL_CHECK'
        need(row['status'].startswith('PASS'),name+'_failed')
    # New source tests are deliberately absent from the public archive. Stage
    # just their pinned test bodies beside a copy of the actual installed code.
    report['source_regressions']=[]
    report['source_regression_inventory']=regressions
    if final_windows:report['source_regression_expected_test_count']=144
    if not report.get('cohort_halted'):
        pins=strict_json((P(args.package)/'SOURCE_PINS.json').read_text())
        testroot=out/'source-regressions'/'.knowledge';shutil.copytree(system,testroot)
        for name in regressions:
            rel='tests/'+name+'.test.js';original=ROOT/'source/.knowledge'/rel
            need(rel in pins['files'] and sha(original)==pins['files'][rel],'regression_source_pin_mismatch:'+rel)
            target=testroot/rel;target.parent.mkdir(exist_ok=True);shutil.copyfile(original,target)
        for name in regressions:
            selected_pattern='^status reader handles .* between open and fstat without accepting a stale row$' if name=='verification-control' else None
            test_argv=[node,'--test','--test-reporter=tap']+(['--test-name-pattern='+selected_pattern] if selected_pattern else [])+[str(testroot/'tests'/(name+'.test.js'))]
            row,_=execute('source-'+name,test_argv,testroot,out,deadline,35,fixture_tmp=fixture_tmp)
            if selected_pattern:row['explicit_test_name_pattern']=selected_pattern
            body=(out/('source-'+name+'.stdout.json')).read_text() if 'stdout_sha256' in row else ''
            inventory=re.findall(r'^# (tests|pass|fail|skipped|cancelled|todo) (\d+)\s*$',body,re.M)
            counts={k:int(v) for k,v in inventory}
            tap_ok=len(inventory)==6 and len(counts)==6 and counts.get('tests',0)>0 and counts.get('pass')==counts.get('tests') and all(counts.get(k)==0 for k in ('fail','skipped','cancelled','todo'))
            expected_count={'repair-producer-dependency-closure':11,'reliability-linux-nested-preflight':19}.get(name)
            if expected_count is not None:
                tap_ok=tap_ok and counts.get('tests')==expected_count
                row['expected_test_count']=expected_count
            if selected_pattern:
                # This declares the four race cases before execution; other
                # ledger scenarios are not part of this targeted regression.
                tap_ok=len(inventory)==6 and len(counts)==6 and counts.get('pass')==4 and \
                    counts.get('tests')==counts.get('pass',0)+counts.get('skipped',0) and \
                    counts.get('skipped') in (0,37) and all(counts.get(k)==0 for k in ('fail','cancelled','todo'))
            row['tap']=counts;row['status']='PASS_SOURCE_REGRESSION' if row['status']=='PASS_PROCESS' and tap_ok else row['status'] if row['status']!='PASS_PROCESS' else 'FAIL_TAP'
            if selected_pattern and sys.platform=='win32' and row['status']=='FAIL_TAP':
                reason='POSIX open-inode unlink race; Windows denies atomic replacement while this synchronous reader handle is open'
                expected={f'status reader handles {mode} between open and fstat without accepting a stale row # SKIP {reason}' for mode in ['atomic cancellation','continuous replacement','corrupt replacement']}
                skipped_lines={re.sub(r'^ok \d+ - ','',line) for line in body.splitlines() if '# SKIP' in line}
                scoped=len(inventory)==6 and counts=={'tests':4,'pass':1,'fail':0,'skipped':3,'cancelled':0,'todo':0} and skipped_lines==expected
                if scoped:row.update(status='PASS_SCOPED_SOURCE_REGRESSION',reason='One hardlink refusal case executed; three POSIX open-inode unlink cases explicitly excluded on Windows',platform_exclusions=sorted(expected))

            excluded_count = 4 if name=='reliability-recovery-adapter-ledger' and sys.platform in ('darwin','win32') else 8 if name=='reliability-recovery-adapter-budget' and sys.platform=='darwin' else None
            all_skipped = len(inventory)==6 and len(counts)==6 and counts.get('tests')==excluded_count and counts.get('skipped')==counts.get('tests') and all(counts.get(k)==0 for k in ('pass','fail','cancelled','todo'))
            if row['status']=='FAIL_TAP' and excluded_count is not None and all_skipped:
                row.update(status='NOT_APPLICABLE_SOURCE', reason='source fixture selects Linux only' if name=='reliability-recovery-adapter-ledger' else 'source fixture selects Linux/Windows recovery adapters', excluded_test_count=excluded_count)
            if row['status']=='FAIL_TAP' and sys.platform=='win32' and name=='verification-isolated-copy':
                expected_skips = {
                    'special files':'Windows does not expose a project-local FIFO through Node filesystem APIs',
                    'snapshot rejects a parent replacement during read even when the file inode is preserved':'Windows prevents renaming a parent of the open source file; the pre-open replacement is tested separately',
                    'regular-file to FIFO race cannot block the open before fstat rejection':'FIFO replacement is a POSIX filesystem scenario'
                }
                skipped_rows=re.findall(r'^\s*ok \d+ - (.*?) # SKIP(?: (.*))?$',body,re.M)
                exact_skips=len(skipped_rows)==3 and dict(skipped_rows)==expected_skips
                if len(inventory)==6 and len(counts)==6 and counts=={'tests':27,'pass':24,'fail':0,'skipped':3,'cancelled':0,'todo':0} and exact_skips:
                    row.update(status='PASS_SCOPED_SOURCE_REGRESSION', limitations=expected_skips,
                               reason='24 executed cases passed; exactly three named POSIX filesystem scenarios excluded on Windows')
            report['source_regressions'].append(row)
            if row.get('timed_out') or row.get('output_limit_exceeded') or row['status']=='NOT_RUN_BUDGET_EXHAUSTED':
                report['cohort_halted']=True;break
    # Run cheap contract checks first. The heavier physical lifecycle scripts
    # retain independent per-script deadlines and cannot outlive this cohort.
    heavy=['tools/self-test-team-registry-concurrency.js','tools/self-test-recording-blockers.js',
           'tools/self-test-team-mode.js','tools/self-test-dedicated-verification.js',
           'tools/self-test-linux-namespace.js','tools/self-test-agent-task-workflow.js']
    ordered=[s for s in scripts if s not in heavy]+[s for s in heavy if s in scripts]
    if targeted:
        common=['tools/self-test-field-report.js','tools/self-test-native-verification-boundaries.js']
        # The classic public worker/repair path is usable on these hosts. The
        # macOS canonical broker and the ARM AppArmor rejection have separate
        # physical evidence; this subset does not recertify those paths.
        classic=sys.platform=='win32' or (sys.platform=='linux' and args.arch=='x64')
        ordered=common+(['tools/self-test-verification-finalization.js','tools/self-test-repair-on-touch.js'] if classic else [])
        need(all(s in scripts for s in ordered),'targeted_test_missing_from_public_contract')
        report['full_installed_product_acceptance']='NOT_RUN_IN_THIS_TARGETED_COHORT'
        report['public_scripts_excluded_from_targeted_scope']=[s for s in scripts if s not in ordered]
        report['scope']='Explicit final installed regression subset: public error envelope, field-report lock recovery, four ledger race cases, producer closure and pinned reliability tests; classic finalization/repair additionally on Linux x64 and Windows. No full contract or platform qualification claim.'
    report['public_selftests']=scripts;report['selftests']=[]
    report['planned_public_order']=ordered
    if sharded:
        full_order=ordered
        ordered=[s for index,s in enumerate(full_order) if index%args.shard_count==args.shard_index]
        report['shard']={'index':args.shard_index,'count':args.shard_count,'selection':'full_order_index_modulo_count',
            'planned_public_order':ordered,'assigned_to_other_shard':[s for s in full_order if s not in ordered],
            'source_regression_cohort':'complete_repeated_in_each_shard_not_additional_unique_tests'}
    report['script_time_caps_s']={'default':90,'heavy':150,'tools/self-test-agent-task-workflow.js':240}
    report['cohort_time_cap_s']=cohort_cap
    if targeted:report['script_time_caps_s']['tools/self-test-repair-on-touch.js']=180
    if final_windows:
        # These are harness caps for entire serial public self-test suites.
        # Individual product work/cleanup deadlines and fixture assertions are
        # unchanged. Keep all 54 script entries and the original source cohort.
        report['script_time_caps_s'].update({'tools/self-test-repair-audit.js':240,
            'tools/self-test-repair-on-touch.js':360,'tools/self-test-update-safety.js':240,
            'tools/self-test-doctor-audit.js':150,'tools/self-test-field-report.js':150})
        report['retries']=0
        report['scope']='Complete 54-entry public contract and pinned source regression cohort from one exact installed ZIP on Windows; existing named platform exclusions retained. Harness suite caps do not change product deadlines or qualify the separate production platform/release gates.'
        if sharded:report['scope']='One fixed 27-entry shard of the complete 54-entry public contract, plus the complete repeated source regression cohort. A matching pair of successful disjoint shards is required for aggregate public-contract acceptance; no release qualification.'
    if report.get('cohort_halted'):report['remaining_not_run']=ordered
    for script in ([] if report.get('cohort_halted') else ordered):
        name=P(script).stem
        if script=='tools/self-test-linux-namespace.js' and sys.platform!='linux':
            report['selftests'].append({'name':name,'script':script,'status':'NOT_APPLICABLE',
                'reason':'physical_linux_namespace_requires_linux'});continue
        args_extra=['--keep-temp'] if script=='tools/self-test-team-mode.js' else []
        if script=='tools/self-test-recording-blockers.js' and sys.platform in ('linux','win32'):
            args_extra=['--workflow-fixture']
        cap=report['script_time_caps_s'].get(script,
            report['script_time_caps_s']['heavy' if script in heavy else 'default'])
        row,value=execute(name,[node,str(system/script)]+args_extra,system,out,deadline,
                          timeout=cap,fixture_tmp=fixture_tmp)
        row['script']=script;admit_report(script,row,value);report['selftests'].append(row)
        if row['status'] in ('TIMEOUT_CLEANUP_UNCONFIRMED','OUTPUT_LIMIT_CLEANUP_UNCONFIRMED','NOT_RUN_BUDGET_EXHAUSTED'):
            report['cohort_halted']=True
            report['remaining_not_run']=[s for s in ordered[ordered.index(script)+1:]];break
        if script=='tools/self-test-linux-namespace.js' and isinstance(value,dict):
            closure=[x for x in value.get('results',[]) if x.get('name')=='physical_fixture_cleanup_requires_all_original_native_births_exited']
            if not closure or closure[0].get('status')!='PASS':
                report['fixture_cleanup_unconfirmed']=True;report['cohort_halted']=True;break
    changes=[name for name,entry in contents.items() if not (extracted/name).is_file() or sha(extracted/name)!=entry['sha256']]
    report['installed_byte_changes']=changes;report['installed_bytes_unchanged']=not changes
    rows=report['selftests'];report['selftest_counts']={s:sum(x['status']==s for x in rows) for s in sorted({x['status'] for x in rows})}
    complete=len(rows)==len(ordered) and all(x['status'] in ('PASS_SELFTEST','NOT_APPLICABLE') for x in rows) and \
      len(report['source_regressions'])==len(regressions) and all(x['status'] in ('PASS_SOURCE_REGRESSION','PASS_SCOPED_SOURCE_REGRESSION','NOT_APPLICABLE_SOURCE') for x in report['source_regressions']) and \
      (not final_windows or sum(x.get('tap',{}).get('tests',0) for x in report['source_regressions'])==144)
    need(complete and not changes and not report.get('fixture_cleanup_unconfirmed'),'installed_contract_incomplete')
    report['status']='PASS_INSTALLED_PUBLIC_CONTRACT_SHARD' if sharded else 'PASS_TARGETED_INSTALLED_REGRESSIONS' if targeted else 'PASS_INSTALLED_PUBLIC_CONTRACT'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['pack','installed','targeted','final_windows'])
    ap.add_argument('--shard-index',type=int,choices=[0,1])
    ap.add_argument('--shard-count',type=int,choices=[2])
    for name in ['out','source','pins','native-input','package','arch']:ap.add_argument('--'+name,required=name=='out')
    args=ap.parse_args();out=P(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
    report={'schema_version':'knowledge-audit6-installed-contract.v1','status':'FAIL','mode':args.mode,
      'commit':os.environ.get('GITHUB_SHA'),'workflow_run':os.environ.get('GITHUB_RUN_ID'),'steps':[],
      'host':{'system':platform.system(),'machine':platform.machine(),'python':platform.python_version()},
      'release_qualified':False,'full_release_gate':'BLOCKED_MAINTAINER_GATE_MISSING',
      'production_platform_qualification':'SEPARATE_REQUIRED_EVIDENCE',
      'scope':'Manifest-listed public tests from identical extracted ZIP plus explicit source regression cohort; internal skips and refusal-only tests retain their own narrower scope.'}
    try:
        need((args.shard_index is None and args.shard_count is None) or
             (args.mode=='final_windows' and args.shard_index in (0,1) and args.shard_count==2),
             'sharding_requires_final_windows_and_both_fixed_shard_arguments')
        if args.mode=='pack':base.pack(args,out,report['steps'],report)
        else:installed(args,out,report)
        return 0
    except BaseException as error:
        report['error']={'type':type(error).__name__,'message':str(error)};return 1
    finally:
        save(out/'RESULT.json',report)
        print(json.dumps({'status':report['status'],'selftest_counts':report.get('selftest_counts'),
                          'error':report.get('error'),'artifact_sha256':report.get('artifact_sha256')}))

if __name__=='__main__':sys.exit(main())
