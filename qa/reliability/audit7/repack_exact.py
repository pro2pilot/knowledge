#!/usr/bin/env python3
"""Repack pinned source with eight unchanged and two newly built native pairs.

Reuse the product packager, product validator and existing native-pair verifier.
This combines exact build inputs; it never upgrades their physical test scope.
"""
import argparse, hashlib, importlib.util, json, os, pathlib, shutil, sys, zipfile

P = pathlib.Path
ROOT = P(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('installed', ROOT/'qa/reliability/audit6/run_installed_contract.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
BASE_ZIP_SHA256 = '159c2e800fd23bf8f914137ab4b397fbe954403a5961d40ba7dfa20091b6f32a'

def main():
    ap = argparse.ArgumentParser()
    for name in ['source','pins','base-package','linux-input','linux-commit','linux-run','out']:
        ap.add_argument('--'+name, required=True)
    args = ap.parse_args(); out = P(args.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'schema_version':'knowledge-audit7-repack.v1','status':'FAIL',
        'commit':os.environ.get('GITHUB_SHA'),'workflow_run':os.environ.get('GITHUB_RUN_ID'),
        'release_qualified':False,'steps':[],
        'scope':'Exact source repack with separately authenticated Linux native build inputs; physical qualification remains separate.'}
    try:
        source = P(args.source).resolve(strict=True); pinfile = P(args.pins).resolve(strict=True)
        pinbytes = pinfile.read_bytes(); pins = m.strict_json(pinbytes.decode('utf8'))
        m.need(pins['file_count'] == len(pins['files']) > 0, 'source_pin_count_invalid')
        stage = out/'stage'/'.knowledge'; stage.mkdir(parents=True)
        for name, digest in pins['files'].items():
            m.base.safe_name(name); original = source/name
            m.need(original.is_file() and not original.is_symlink() and m.sha(original)==digest, 'source_pin_mismatch:'+name)
            target=stage/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target)
        args.package = args.base_package
        parent_report = {}; parent_root, _ = m.extract(args,out,parent_report)
        m.need(parent_report['artifact_sha256']==BASE_ZIP_SHA256,'base_zip_identity_mismatch')
        parent = parent_root/'.knowledge'
        base_provenance = m.strict_json((P(args.base_package)/'BUILD_PROVENANCE.json').read_text())
        contract = m.strict_json((stage/'install-manifest.json').read_text())['release_contract']
        pairs = []; found = set()
        for expected in contract['native_runtime_artifacts']:
            target = expected['platform']+'-'+expected['architecture']
            rebuilt = expected['platform']=='linux' and P(expected['binary']).name=='verification-linux-namespace'
            if rebuilt:
                candidates=list(P(args.linux_input).rglob(target+'/verification-linux-namespace.manifest.json'))
                m.need(len(candidates)==1,'linux_native_input_not_unique:'+target)
                manifest=candidates[0]; binary=manifest.with_name('verification-linux-namespace')
                receipt_files=[p for p in P(args.linux_input).rglob('RESULT.json')
                    if p.parent in manifest.parents]
                m.need(len(receipt_files)==1,'linux_build_receipt_not_unique:'+target)
                receipt_file=receipt_files[0]; receipt=m.strict_json(receipt_file.read_text())
                m.need(receipt.get('commit')==args.linux_commit and str(receipt.get('workflow_run'))==args.linux_run,
                    'linux_build_identity_mismatch:'+target)
                m.need(any(r.get('name')=='build-namespace' and r.get('status')=='PASS' for r in receipt.get('steps',[])),
                    'linux_native_build_not_pass:'+target)
                origin={'input_commit':receipt['commit'],'input_run':receipt['workflow_run'],
                    'input_overall_status':receipt['status'],'build_step_status':'PASS',
                    'build_receipt_sha256':m.sha(receipt_file),'new_linux_build':True}
                found.add(target)
            else:
                binary=parent/expected['binary'];manifest=parent/expected['manifest']
                matches=[p for p in base_provenance['native_pairs'] if p['binary']==expected['binary']]
                m.need(len(matches)==1,'base_native_provenance_missing')
                origin=dict(matches[0]);origin['new_linux_build']=False
            record=m.base.native_pair(stage,expected,binary,manifest)
            if rebuilt:
                build=receipt.get('native_build',{})
                m.need(receipt.get('native_pair')==record and build.get('status')=='PASS' and
                    all(build.get(k)==record[k] for k in ['source_sha256','binary_sha256','binary_bytes']) and
                    receipt.get('runtime',{}).get('arch')==expected['architecture'],
                    'linux_build_receipt_pair_binding_mismatch:'+target)
            for key, original in [('binary',binary),('manifest',manifest)]:
                destination=stage/expected[key];destination.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(original,destination)
                destination.chmod(0o755 if destination.name=='verification-linux-namespace' else 0o644)
            pairs.append({**origin,'target':target,'binary':expected['binary'],'manifest':expected['manifest'],
                'binary_sha256':record['binary_sha256'],'source_sha256':record['source_sha256'],
                'manifest_sha256':m.sha(manifest)})
        m.need(len(pairs)==10 and found=={'linux-x64','linux-arm64'},'native_pair_inventory_invalid')
        public=out/'public';public.mkdir()
        version=m.strict_json((stage/'package.json').read_text())['version']; archive=public/('knowledge-v'+version+'.zip')
        built=m.base.execute('package',['node',str(stage/'tools/package-release.js'),'--out',str(archive),'--json'],stage,public,report['steps'],60)
        m.need(built.get('status')=='ok','product_packager_rejected')
        valid=m.base.execute('validate',['node',str(stage/'tools/validate-release-artifact.js'),str(archive),'--json'],stage,public,report['steps'],45)
        m.need(valid.get('status')=='ok' and valid.get('violations')==[],'product_validator_rejected')
        contents={}
        with zipfile.ZipFile(archive) as z:
            m.need(z.testzip() is None and len(z.namelist())==len(set(z.namelist())),'zip_crc_or_inventory_failed')
            for info in z.infolist():
                m.base.safe_name(info.filename);m.need(info.filename.startswith('.knowledge/') and not info.is_dir(),'zip_layout_invalid')
                body=z.read(info);contents[info.filename]={'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),'mode':(info.external_attr>>16)&0o777}
        m.need(pinfile.read_bytes()==pinbytes,'source_pins_changed')
        for name,digest in pins['files'].items():m.need(m.sha(source/name)==digest,'source_changed:'+name)
        (public/'SOURCE_PINS.json').write_bytes(pinbytes);m.save(public/'PACKAGE_CONTENTS.json',contents)
        shutil.copyfile(P(args.base_package)/'BUILD_PROVENANCE.json',public/'BASE_BUILD_PROVENANCE.json')
        report.update(status='PASS_PACKAGED_STRUCTURAL_VALIDATION',artifact_name=archive.name,
            artifact_sha256=m.sha(archive),artifact_bytes=archive.stat().st_size,entries=len(contents),native_pairs=pairs,
            source_pins_sha256=hashlib.sha256(pinbytes).hexdigest(),source_pin_count=len(pins['files']),
            package_contents_sha256=m.sha(public/'PACKAGE_CONTENTS.json'),structurally_valid_zip=True,
            base_zip_sha256=BASE_ZIP_SHA256,base_build_provenance_sha256=m.sha(public/'BASE_BUILD_PROVENANCE.json'),
            installed_runtime_smoke='PENDING_SEPARATE_MATRIX')
        m.save(public/'BUILD_PROVENANCE.json',report);return 0
    except BaseException as error:
        report['error']={'type':type(error).__name__,'message':str(error)};return 1
    finally:
        m.save(out/'RESULT.json',report)
        print(json.dumps({k:report.get(k) for k in ['status','artifact_sha256','entries','error']}),flush=True)

if __name__=='__main__':raise SystemExit(main())
