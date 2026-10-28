#!/usr/bin/env python3
"""Extract and bind one final candidate using the existing strict reader."""
import argparse, importlib.util, json, pathlib, re, sys
P=pathlib.Path
ROOT=P(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('installed',ROOT/'qa/reliability/audit6/run_installed_contract.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
a=argparse.ArgumentParser()
a.add_argument('--package',required=True)
a.add_argument('--out',required=True)
a.add_argument('--expected-zip-sha256',required=True)
a=a.parse_args();out=P(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
r={'schema_version':'knowledge-audit8-installed-extraction.v1','status':'FAIL','release_qualified':False}
try:
    m.need(re.fullmatch('[0-9a-f]{64}',a.expected_zip_sha256) is not None,'expected_digest_required')
    root,entries=m.extract(a,out,r)
    m.need(r['artifact_sha256']==a.expected_zip_sha256,'expected_zip_identity_mismatch')
    system=root/'.knowledge'
    contract=m.strict_json((system/'install-manifest.json').read_text())['release_contract']
    pairs=contract['native_runtime_artifacts']
    m.need(len(pairs)==10 and len({item[key] for item in pairs for key in ['binary','manifest']})==20,
           'exact_unique_native_pair_inventory_required')
    for item in pairs:
        m.base.native_pair(system,item,system/item['binary'],system/item['manifest'])
    r.update(status='PASS_EXACT_INSTALLED_EXTRACTION',system_root=str(system),entries_verified=len(entries),native_pairs_verified=len(pairs))
except BaseException as error:
    r['error']={'type':type(error).__name__,'message':str(error)}
finally:
    m.save(out/'EXTRACTION.json',r)
    print(json.dumps(r))
sys.exit(0 if r['status']=='PASS_EXACT_INSTALLED_EXTRACTION' else 1)
