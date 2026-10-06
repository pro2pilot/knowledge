#!/usr/bin/env python3
"""Verify immutable matrix inputs and collect complete, hash-bound raw receipts."""
import argparse, hashlib, json, os, shutil, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='42554f5f93fd0aa08098bf6547768876a185f4ae71b1c8f3d44fb9520699d499'
BASE='b7f4e912e8bcffff1e2ffb35756d68850a980b6b841306ac7a51c9d88fc59d79'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def inputs():
    manifest=json.loads((HERE/'inputs.json').read_text())
    assert sha(HERE/'knowledge-v3.4.3.zip')==SHA
    assert sha(HERE/'knowledge-v3.2.11.zip')==BASE
    for item in manifest['files']:
        p=(HERE/item['path']).resolve()
        assert HERE in p.parents and not p.is_symlink()
        assert sha(p)==item['sha256'],item['path']
    return manifest
def collect(work,out):
    assert not out.exists(), 'refusing existing receipt directory'
    out.mkdir(parents=True)
    for group in ('replay','cli'):
        source=work/group
        if not source.exists(): continue
        for file in source.rglob('*'):
            if not file.is_file(): continue
            relative=file.relative_to(source)
            # Preserve every command result and raw stream; omit only disposable fixture inputs.
            if relative.parts[0] in ('fixtures','fixture','snapshot','temporary','external-cwd'): continue
            dst=out/group/relative; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(file,dst)
    save(out/'binding.json',{'candidate_sha256':SHA,'baseline_sha256':BASE,
        'github_sha':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),
        'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'runner_os':os.environ.get('RUNNER_OS'),
        'workflow':os.environ.get('GITHUB_WORKFLOW'),'inputs_manifest_sha256':sha(HERE/'inputs.json')})
    files=[{'path':p.relative_to(out).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(out.rglob('*')) if p.is_file()]
    save(out/'checksums.json',{'files':files})
def enforce(out):
    binding=json.loads((out/'binding.json').read_text())
    assert binding['candidate_sha256']==SHA and binding['github_sha']==os.environ.get('GITHUB_SHA')
    for item in json.loads((out/'checksums.json').read_text())['files']:
        p=(out/item['path']).resolve(); assert out.resolve() in p.parents
        assert sha(p)==item['sha256'] and p.stat().st_size==item['bytes']
    replay=json.loads((out/'replay/replay-results.json').read_text())
    assert replay['status']=='pass' and replay['archive_sha256']==SHA
    assert replay['self_tests']=={'total':44,'passed':44,'failed':0,'expected':44,'not_run':0,'skipped':0}
    assert replay['syntax_checks']=={'total':144,'passed':144,'failed':0,'expected':144,'not_run':0}
    assert replay['source_unchanged'] and replay['archive_unchanged'] and replay['node_binary_unchanged']
    for command in replay['commands']:
        assert command['status']=='pass'
        for key in ('stdout','stderr'):
            # The replay runner binds full raw stream SHA values; verify the same bytes after collection.
            raw=(out/'replay'/command[key]).resolve()
            assert out.resolve() in raw.parents and raw.is_file()
            assert sha(raw)==command[key+'_sha256'] and raw.stat().st_size==command[key+'_bytes']
    result=json.loads((out/'cli/result.json').read_text())
    assert result['status']=='pass' and result['candidate_sha256']==SHA
    assert result['tests']['shipped_self_tests']=='44/44'
    assert result['tests']['integrations']=='12/12' and result['active_locks']==0
    commands=json.loads((out/'cli/commands.json').read_text())['commands']
    required={'install-check-before','install-check-after','install-agent-integrations','flow-import','flow-release','doctor','inspector-build','inspector-live','task-routing','field-report-start','lock-safety-final'}
    assert required.issubset({c['id'] for c in commands})
    assert result['command_count']==len(commands)
    for command in commands:
        assert command['status']=='pass' and command['exit_code']==0 and not command.get('spawn_error')
        for key in ('stdout','stderr'):
            raw=(out/'cli'/command[key]).resolve()
            assert out.resolve() in raw.parents and raw.is_file()
    inspector=json.loads((out/'cli/inspector-live.json').read_text())
    assert inspector['status']=='pass' and inspector['state_ok'] and inspector['shutdown_ok']
    print(json.dumps({'status':'pass','candidate_sha256':SHA,'github_sha':binding['github_sha'],'raw_files':len(json.loads((out/'checksums.json').read_text())['files'])}))
if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('mode',choices=['inputs','collect','enforce']); p.add_argument('--work',type=Path); p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.mode=='inputs': print(json.dumps({'status':'pass','files':len(inputs()['files'])}))
    elif a.mode=='collect': collect(a.work.resolve(),a.out.resolve())
    else: enforce(a.out.resolve())
