#!/usr/bin/env python3
"""Verify pinned controller/reference bytes before a native CI fixture starts."""
import argparse, hashlib, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',required=True);ap.add_argument('--inventory',required=True)
    args=ap.parse_args();root=Path(args.root).resolve(strict=True)
    value=json.loads(Path(args.inventory).read_bytes())
    if value.get('schema')!='knowledge-darwin-ci-assets.v1' or not isinstance(value.get('files'),list):
        raise SystemExit('invalid_ci_asset_manifest')
    seen=set()
    native=value.get('native_sources',[])
    if not isinstance(native,list) or len(native)!=5:raise SystemExit('native_source_pins_missing')
    for row in value['files']+native:
        name=row.get('repository_path');relative=Path(name) if isinstance(name,str) else None
        if relative is None or relative.is_absolute() or '..' in relative.parts or name in seen:
            raise SystemExit('invalid_ci_asset_path')
        seen.add(name);file=root/relative
        if file.is_symlink() or not file.is_file() or not file.resolve(strict=True).is_relative_to(root):
            raise SystemExit('unsafe_ci_asset')
        data=file.read_bytes()
        if len(data)!=row.get('bytes') or hashlib.sha256(data).hexdigest()!=row.get('sha256'):
            raise SystemExit('ci_asset_hash_mismatch:'+name)
    print(json.dumps({'status':'PASS_EXACT_ASSET_PINS','files':len(seen),'production_qualified':False}))
    return 0
if __name__=='__main__':raise SystemExit(main())
