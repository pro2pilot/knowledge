#!/usr/bin/env python3
"""One bounded Windows filesystem diagnosis and the corrected fixture scope."""
import argparse, importlib.util, json, pathlib, shutil, sys, time, os, platform, re
P=pathlib.Path
HERE=P(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('installed',HERE/'run_installed_contract.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def main():
 ap=argparse.ArgumentParser()
 for name in ['package','arch','out']:ap.add_argument('--'+name,required=True)
 a=ap.parse_args();out=P(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
 report={'schema_version':'knowledge-audit6-windows-reader-qa.v1','status':'FAIL','commit':os.environ.get('GITHUB_SHA'),
  'workflow_run':os.environ.get('GITHUB_RUN_ID'),'host':{'system':platform.system(),'machine':platform.machine()},
  'steps':[],'release_qualified':False,'scope':'Windows read-handle sharing diagnostic and corrected POSIX-only test applicability. No repeat or promotion of the full installed contract.'}
 deadline=time.monotonic()+90
 try:
  m.need(sys.platform=='win32','windows_required');extracted,contents=m.extract(a,out,report);system=extracted/'.knowledge'
  m.need(report['artifact_sha256']=='b15ceba62e6c542f3419416397b03844c97a65663f3c533c54943d99d6aec608','wrong_runtime_zip')
  temp=m.prepare_fixture_temp(out,report,deadline);node=shutil.which('node');m.need(bool(node),'node_required')
  row,value=m.execute('native-load',[node,'-e',m.base.NATIVE_JS],system,out,deadline,20,fixture_tmp=temp);report['steps'].append(row)
  m.need(row['status']=='PASS_PROCESS' and value.get('status')=='pass' and value.get('arch')==a.arch,'native_load_failed')
  row,value=m.execute('windows-open-reader',[node,str(HERE/'windows_open_reader_probe.cjs'),str(system)],system,out,deadline,30,fixture_tmp=temp);report['steps'].append(row)
  m.need(row['status']=='PASS_PROCESS' and value and value.get('status')=='PASS_WINDOWS_READER_SHARING_OBSERVATION' and value.get('fixture_removed') is True,'windows_observation_failed')
  report['observation']=value
  pins_file=m.ROOT/'qa/reliability/audit6/SOURCE_PINS.json';pins=m.strict_json(pins_file.read_text())
  rel='tests/verification-control.test.js';test=m.ROOT/'source/.knowledge'/rel
  m.need(m.sha(test)==pins['files'][rel],'current_test_pin_mismatch')
  stage=out/'source-regression'/'.knowledge';shutil.copytree(system,stage);(stage/'tests').mkdir();shutil.copyfile(test,stage/rel)
  pattern='^status reader handles .* between open and fstat without accepting a stale row$'
  row,_=m.execute('corrected-control-fixture',[node,'--test','--test-reporter=tap','--test-name-pattern='+pattern,str(stage/rel)],stage,out,deadline,30,fixture_tmp=temp)
  report['steps'].append(row);body=(out/'corrected-control-fixture.stdout.json').read_text();counts=dict((k,int(v)) for k,v in re.findall(r'^# (tests|pass|fail|skipped|cancelled|todo) (\d+)\s*$',body,re.M))
  report['selected_test_counts']=counts;report['corrected_test_sha256']=m.sha(test);report['corrected_source_pins_sha256']=m.sha(pins_file)
  reason='POSIX open-inode unlink race; Windows denies atomic replacement while this synchronous reader handle is open'
  expected={f'status reader handles {mode} between open and fstat without accepting a stale row # SKIP {reason}' for mode in ['atomic cancellation','continuous replacement','corrupt replacement']}
  skips={re.sub(r'^ok \d+ - ','',line) for line in body.splitlines() if '# SKIP' in line}
  m.need(row['status']=='PASS_PROCESS' and counts=={'tests':4,'pass':1,'fail':0,'skipped':3,'cancelled':0,'todo':0} and skips==expected,'corrected_fixture_scope_mismatch')
  changes=[n for n,v in contents.items() if m.sha(extracted/n)!=v['sha256']]
  report['installed_byte_changes']=changes;report['installed_bytes_unchanged']=not changes;m.need(not changes,'installed_bytes_changed')
  report['status']='PASS_WINDOWS_READER_DIAGNOSTIC_AND_SCOPED_FIXTURE';return 0
 except BaseException as e:report['error']={'type':type(e).__name__,'message':str(e)};return 1
 finally:m.save(out/'RESULT.json',report);print(json.dumps({'status':report['status'],'error':report.get('error')}))
if __name__=='__main__':sys.exit(main())
