#!/usr/bin/env python3
"""Rebuild only the changed Linux native pair and observe old/new public APIs.

A denied hosted kernel is accepted only as an explicit refusal regression, not
as Linux availability, service integration or release qualification.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, signal, stat, subprocess, tempfile, time, zipfile
P = pathlib.Path
ROOT = P(__file__).resolve().parents[3]
EXPECTED_ZIP = '159c2e800fd23bf8f914137ab4b397fbe954403a5961d40ba7dfa20091b6f32a'
BASELINE_COMMIT = 'd02c27b71b0e8e971e0de2b6a880620446a3fa85'

def sha(file): return hashlib.sha256(P(file).read_bytes()).hexdigest()
def save(file, value): P(file).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n', encoding='utf8')
def need(ok, why):
    if not ok: raise RuntimeError(why)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--package', required=True);ap.add_argument('--out',required=True);ap.add_argument('--pins',default=str(ROOT/'qa/reliability/audit7/SOURCE_PINS.json'));args=ap.parse_args()
    out=P(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
    parent=P(os.environ['RUNNER_TEMP']).resolve(strict=True)
    fixture=P(tempfile.mkdtemp(prefix='knowledge-audit7-linux-',dir=parent)).resolve(strict=True)
    need(ROOT.resolve() not in fixture.parents, 'fixture must be outside checkout')
    source=ROOT/'source/.knowledge'; node=shutil.which('node');deadline=time.monotonic()+270
    report={'schema_version':'knowledge-audit7-linux-nested-preflight.v1','commit':os.environ.get('GITHUB_SHA'),
      'baseline_commit':BASELINE_COMMIT,'baseline_zip_sha256':EXPECTED_ZIP,'status':'RUNNING',
      'workflow_run':os.environ.get('GITHUB_RUN_ID'),
      'policy_changed':False,'production_service_qualified':False,'release_qualified':False,'steps':[],
      'fixture_root':str(fixture),'source_sha256':{n:sha(source/'tools/lib'/n) for n in ['verification-linux-namespace.c','verification-linux-namespace.js']}}
    def run(name,argv,cwd=None,timeout=45,pipe_capture=False):
        began=time.monotonic();allowance=min(timeout,deadline-began);need(allowance>0,'cohort budget exhausted')
        env=dict(os.environ,TMPDIR=str(fixture),TMP=str(fixture),TEMP=str(fixture),CI='1',KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH='1')
        for key in list(env):
            if key.startswith('LD_') or key.startswith('NODE_') or key.startswith('GIT_'):env.pop(key)
        a=out/(name+'.stdout.txt');b=out/(name+'.stderr.txt')
        print(json.dumps({'event':'step_start','name':name,'cap_s':allowance}),flush=True)
        with a.open('wb') as stdout,b.open('wb') as stderr:
            # The native report primitive deliberately rejects regular files.
            # Keep real pipes for these fixed <=64KiB native transcripts; never
            # relax that runtime boundary merely for an evidence harness.
            child=subprocess.Popen([str(x) for x in argv],cwd=cwd,env=env,stdin=subprocess.DEVNULL,
              stdout=subprocess.PIPE if pipe_capture else stdout,stderr=subprocess.PIPE if pipe_capture else stderr,start_new_session=True)
            try:
                if pipe_capture:
                    captured,error=child.communicate(timeout=allowance)
                    stdout.write(captured);stderr.write(error)
                    need(len(captured)<=65536 and len(error)<=65536,'native transcript cap exceeded')
                    code=child.returncode
                else:code=child.wait(timeout=allowance)
            except subprocess.TimeoutExpired as timed:
                os.killpg(child.pid,signal.SIGKILL)
                if pipe_capture:
                    try:captured,error=child.communicate(timeout=5)
                    except subprocess.TimeoutExpired as drain:
                        captured=drain.output or b'';error=drain.stderr or b''
                        child.stdout.close();child.stderr.close()
                    stdout.write(captured);stderr.write(error)
                else:child.wait(timeout=5)
                report['steps'].append({'name':name,'status':'TIMEOUT_CLEANUP_UNCONFIRMED','exit_code':child.returncode})
                save(out/'RESULT.json',report);raise RuntimeError(name+' timed out; no native cleanup proof claimed')
        need(a.stat().st_size<=8*1024*1024 and b.stat().st_size<=8*1024*1024,'output cap exceeded')
        row={'name':name,'exit_code':code,'elapsed_s':round(time.monotonic()-began,3),
          'stdout_sha256':sha(a),'stderr_sha256':sha(b),'pipe_capture':pipe_capture,'status':'PASS_PROCESS' if code==0 else 'FAIL_PROCESS'}
        report['steps'].append(row);save(out/'RESULT.json',report)
        return code,a.read_text(encoding='utf8'),row
    try:
        code,text,_=run('runtime',[node,'-p','JSON.stringify({platform:process.platform,arch:process.arch,node:process.version,uid:process.getuid()})'])
        need(code==0,'runtime discovery failed');runtime=json.loads(text);report['runtime']=runtime
        need(runtime['platform']=='linux' and runtime['arch'] in ['x64','arm64'] and runtime['uid']!=0,'ordinary native Linux runtime required')
        package=P(args.package)/'knowledge-v3.4.4.zip';need(sha(package)==EXPECTED_ZIP,'baseline package digest differs')
        old=fixture/'old';old.mkdir()
        with zipfile.ZipFile(package) as archive:
            need(len(archive.infolist())==499 and archive.testzip() is None,'baseline inventory/CRC differs')
            for item in archive.infolist():
                rel=P(item.filename);mode=item.external_attr>>16
                need(not rel.is_absolute() and '..' not in rel.parts and '\\' not in item.filename and not stat.S_ISLNK(mode),'unsafe ZIP entry')
                dest=old/rel;dest.parent.mkdir(parents=True,exist_ok=True)
                need(not item.is_dir(),'unexpected baseline directory entry')
                dest.write_bytes(archive.read(item));dest.chmod(0o755 if mode&0o111 else 0o644)
        old=old/'.knowledge';need(old.is_dir(),'baseline root missing')
        pins_path=P(args.pins);pins=json.loads(pins_path.read_text());need(pins['file_count']==len(pins['files']),'source pin count differs')
        report['source_pins_sha256']=sha(pins_path);report['source_file_count']=pins['file_count']
        current=fixture/'new'/'.knowledge';current.mkdir(parents=True)
        for name,expected in pins['files'].items():
            rel=P(name);need(not rel.is_absolute() and '..' not in rel.parts and '\\' not in name,'unsafe source path')
            original=source/rel;need(original.is_file() and not original.is_symlink() and sha(original)==expected,'source pin mismatch: '+name)
            target=current/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target)
        target_name='linux-'+runtime['arch'];dest=current/'tools/lib/native'/target_name;dest.mkdir(parents=True,exist_ok=True)
        # Reuse only the host lock addon, whose source is unchanged and checked.
        old_native=old/'tools/lib/native'/target_name
        lock_manifest=json.loads((old_native/'lock-publication.manifest.json').read_text())
        need(lock_manifest['source_sha256']==sha(current/'tools/native/lock-publication.c'),'unchanged lock source pin differs')
        need(lock_manifest['binary_sha256']==sha(old_native/'lock-publication.node'),'old lock binary digest differs')
        for name in ['lock-publication.node','lock-publication.manifest.json']:shutil.copyfile(old_native/name,dest/name)
        binary=dest/'verification-linux-namespace'
        code,_,_=run('build-namespace',['/usr/bin/cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
          '-fstack-protector-strong','-D_FORTIFY_SOURCE=2',current/'tools/lib/verification-linux-namespace.c','-o',binary],timeout=60)
        need(code==0,'strict native compilation failed');binary.chmod(0o755)
        manifest={'schema_version':'knowledge-command-native-binary.v1','platform':'linux','architecture':runtime['arch'],
          'binary':binary.name,'source_sha256':sha(source/'tools/lib/verification-linux-namespace.c'),
          'binary_sha256':sha(binary),'binary_bytes':binary.stat().st_size}
        save(dest/'verification-linux-namespace.manifest.json',manifest)
        public=out/'public'/'native'/('linux-'+runtime['arch']);public.mkdir(parents=True)
        shutil.copyfile(binary,public/binary.name);(public/binary.name).chmod(0o755)
        shutil.copyfile(dest/'verification-linux-namespace.manifest.json',public/'verification-linux-namespace.manifest.json')
        report['native_pair']=manifest
        def inventory(tree): return {str(file.relative_to(tree)):sha(file) for file in sorted(tree.rglob('*')) if file.is_file()}
        original_current=inventory(current);report['runtime_inventory_before']=original_current
        report['runtime_materialization']={'source_pins_sha256':report['source_pins_sha256'],
          'source_file_count':report['source_file_count'],'host_native_pairs':2,
          'scope':'Complete exact pinned current source outside Git, unchanged host lock addon from verified baseline ZIP, rebuilt host namespace pair; final installed ZIP acceptance is separate.'}
        report['native_build']={'status':'PASS','source_sha256':manifest['source_sha256'],
          'binary_sha256':manifest['binary_sha256'],'binary_bytes':manifest['binary_bytes']}
        next(row for row in report['steps'] if row['name']=='build-namespace')['status']='PASS'
        run('compiler-version',['/usr/bin/cc','--version'])
        for name,tree in [('old',old),('new',current)]:
            native=tree/'tools/lib/native'/('linux-'+runtime['arch'])/'verification-linux-namespace'
            code,text,row=run(name+'-legacy-probe',[native,'--probe'],timeout=20,pipe_capture=True)
            row['native_records']=[json.loads(line) for line in text.splitlines() if line.strip()]
            need(code==0 and [x.get('status') for x in row['native_records']]==['ready','closed'],'legacy one-level native probe failed')
            if name=='new':
                code,text,row=run('new-nested-probe',[native,'--probe-nested'],timeout=20,pipe_capture=True)
                row['native_records']=[json.loads(line) for line in text.splitlines() if line.strip()]
                row['scope']='two new native namespace levels; not Node or public API acceptance'
            case=fixture/(name+'-project');case.mkdir()
            code,text,row=run(name+'-public',[node,ROOT/'qa/reliability/audit7/linux_preflight_public.cjs',tree,case],cwd=case,timeout=60)
            need(code==0,'public observer did not finish');value=json.loads(text);save(out/(name+'-public.json'),value)
            report[name+'_public']=value
            if value['public']['status']=='accepted':
                need(value['work_ran'] and value['public']['final_reader']=='accepted' and value['public']['acceptance_count']==1,'public accepted result lacks strict KVE/ACK')
                need(value['active_attempt'] and value['active_attempt'].get('claimed') is False,'accepted attempt still claimed')
                row['qualification']='PASS_PUBLIC_ACCEPTED'
            else:
                err=value['public']['error'];outer=err.get('delivery_teardown',err.get('cleanup',{}))
                need(err.get('code')=='verification_containment_unavailable' and not value['work_ran'],'unexpected public failure/work execution')
                need(value['active_attempt'] is None,'preflight denial published an attempt claim')
                need(not any('/verification_executions/' in '/'+x['path'] or '/verification_finalizations/' in '/'+x['path'] for x in value['state_after']),'preflight denial wrote execution/finality')
                need(outer.get('status')=='completed','outer public scope cleanup was not confirmed')
                row['qualification']='PASS_REFUSAL_BEFORE_ATTEMPT_ONLY'
            save(out/'RESULT.json',report)
        new=report['new_public'];oldvalue=report['old_public']
        if new['host_capability']['status']=='unavailable':
            need(new['public']['status']=='failed','unavailable host unexpectedly executed work')
            report['observed_change']='NESTED_HOST_PREREQUISITE_REFUSED' if oldvalue['host_capability']['status']!='unavailable' else 'BOTH_HOST_PROBES_UNAVAILABLE'
        else:
            need(new['host_capability'].get('probe_depth')==2 and new['public']['status']=='accepted','nested probe did not qualify actual public path')
            report['observed_change']='NESTED_PREREQUISITE_AND_PUBLIC_PATH_ACCEPTED'
        if new['public']['status']=='accepted':
            for script in ['self-test-verification-finalization.js','self-test-linux-namespace.js']:
                code,text,row=run('positive-'+script.removesuffix('.js'),[node,current/'tools'/script],cwd=current,timeout=90)
                need(code==0,script+' failed');value=json.loads(text)
                if script=='self-test-linux-namespace.js':
                    need(value.get('fail')==0 and value.get('blocked')==0 and value.get('pass',0)>0,'namespace physical acceptance incomplete')
                else:need(value.get('status')=='pass','finalization acceptance not pass')
                row['reported_result']=value
        else:
            report['positive_full_selftests']='NOT_RUN_NATIVE_BACKEND_UNAVAILABLE; refusal is not public execution acceptance'
        code,_,_=run('parser-regressions',[node,'--test','--test-reporter=tap',source/'tests/reliability-linux-nested-preflight.test.js'],timeout=30)
        need(code==0,'strict parser regressions failed')
        report['runtime_inventory_after']=inventory(current)
        need(report['runtime_inventory_after']==original_current,'runtime bytes changed during physical QA')
        report['status']='PASS_SCOPED_PREFLIGHT_QA'
    except Exception as error:
        report['status']='FAIL';report['error']=str(error);raise
    finally:
        report['fixture_retained_for_diagnostics']=True
        save(out/'RESULT.json',report)
        if 'native_pair' in report:
            save(out/'public'/'BUILD.json',{'schema_version':'knowledge-audit7-native-pair-build.v1','commit':report['commit'],
              'workflow_run':report['workflow_run'],'runtime':report.get('runtime'),'native_pair':report['native_pair'],'qa_status':report['status'],
              'steps':report['steps'],'production_service_qualified':False,'release_qualified':False})
if __name__=='__main__':main()
