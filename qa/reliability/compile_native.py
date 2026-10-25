#!/usr/bin/env python3
"""Build pinned native sources on their actual OS. This is not qualification."""
import argparse, hashlib, json, os, pathlib, platform, shutil, subprocess, sys, tarfile, time, urllib.request

def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',required=True);ap.add_argument('--pins',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    source=pathlib.Path(a.source).resolve();out=pathlib.Path(a.out).resolve();out.mkdir(parents=True,exist_ok=True)
    pins=json.loads(pathlib.Path(a.pins).read_text())
    for name,digest in pins['files'].items():
        if sha(source/name)!=digest: raise RuntimeError('source pin mismatch: '+name)
    node=shutil.which('node'); pinfo=json.loads(subprocess.check_output([node,'-p','JSON.stringify({platform:process.platform,arch:process.arch,node:process.version})'],text=True))
    record={'schema':'knowledge-reliability-native-build.v1','scope':'compile and loader smoke only; no reliability qualification','platform':platform.platform(),'runtime':pinfo,'commit':os.environ.get('GITHUB_SHA'),'source_pins':pins,'steps':[],'status':'RUNNING'}
    def save(): (out/'BUILD.json').write_text(json.dumps(record,indent=2)+'\n')
    def run(name,argv,timeout=180):
        start=time.monotonic();r=subprocess.run([str(x) for x in argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        (out/(name+'.stdout.log')).write_bytes(r.stdout);(out/(name+'.stderr.log')).write_bytes(r.stderr)
        record['steps'].append({'name':name,'argv':[str(x) for x in argv],'exit_code':r.returncode,'elapsed_s':time.monotonic()-start,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()});save()
        if r.returncode: raise RuntimeError(name+' failed: '+r.stderr.decode(errors='replace')[-10000:])
        return r
    try:
        version='22.17.1' if pinfo['platform']=='win32' and pinfo['arch']=='arm64' else '18.20.8'
        base='https://nodejs.org/dist/v'+version+'/'
        sums=urllib.request.urlopen(base+'SHASUMS256.txt',timeout=60).read();(out/'SHASUMS256.txt').write_bytes(sums)
        table={line.split()[1]:line.split()[0] for line in sums.decode().splitlines() if len(line.split())==2}
        def download(name,destination):
            raw=urllib.request.urlopen(base+name,timeout=90).read()
            if hashlib.sha256(raw).hexdigest()!=table[name]: raise RuntimeError('toolchain hash mismatch')
            destination.write_bytes(raw);return destination
        headers=download('node-v'+version+'-headers.tar.gz',out/'headers.tar.gz')
        with tarfile.open(headers) as archive:
            for member in archive.getmembers():
                resolved=(out/member.name).resolve()
                if not resolved.is_relative_to(out) or member.issym() or member.islnk(): raise RuntimeError('unsafe toolchain archive')
            archive.extractall(out,filter='data')
        headerdir=out/('node-v'+version)/'include/node'
        dest=out/'native'/(pinfo['platform']+'-'+pinfo['arch']);dest.mkdir(parents=True)
        args=[node,source/'tools/build-lock-native.js','--headers',headerdir,'--output',dest]
        if pinfo['platform']=='win32':
            lib=download('win-'+pinfo['arch']+'/node.lib',out/'node.lib')
            compiler=shutil.which('cl.exe')
            if not compiler: raise RuntimeError('Visual C compiler environment is unavailable')
            args+=['--compiler',compiler,'--node-lib',lib]
        run('lock-addon',args)
        run('lock-addon-load',[node,'-e',"const n=require(process.argv[1]);const i=n.info();if(i.napi_version!==8)process.exit(2);console.log(JSON.stringify(i))",dest/'lock-publication.node'])
        if pinfo['platform']=='linux':
            c=source/'tools/lib/verification-linux-namespace.c';binary=dest/'verification-linux-namespace'
            run('linux-namespace',['/usr/bin/cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fstack-protector-strong','-D_FORTIFY_SOURCE=2',c,'-o',binary])
            binary.chmod(0o755)
            (dest/'verification-linux-namespace.manifest.json').write_text(json.dumps({'schema_version':'knowledge-command-native-binary.v1','platform':'linux','architecture':pinfo['arch'],'binary':binary.name,'source_sha256':sha(c),'binary_sha256':sha(binary),'binary_bytes':binary.stat().st_size},indent=2)+'\n')
        if pinfo['platform']=='darwin':
            lib=source/'tools/lib'
            mapping={'BROKER_SOURCE':'verification-darwin-broker.m','DARWIN_STUB_SOURCE':'verification-darwin-stub.c','DARWIN_UID_HISTORY_HEADER':'verification-darwin-uid-history.h','DARWIN_UID_HISTORY_SOURCE':'verification-darwin-uid-history.m','DARWIN_TRANSPORT_HEADER':'verification-darwin-transport.h'}
            definitions=['-DKNOWLEDGE_'+key+'_SHA="'+sha(lib/name)+'"' for key,name in mapping.items()]
            broker=dest/'verification-darwin-broker';stub=dest/'verification-darwin-stub'
            run('darwin-broker',['/usr/bin/clang','-fobjc-arc','-Wall','-Wextra','-Wno-deprecated-declarations','-framework','Foundation',*definitions,'-I',lib,lib/'verification-darwin-broker.m',lib/'verification-darwin-uid-history.m','-o',broker])
            run('darwin-stub',['/usr/bin/clang','-std=c11','-D_DARWIN_C_SOURCE','-O2','-Wall','-Wextra','-Wno-deprecated-declarations','-DKNOWLEDGE_BROKER_BINARY_SHA="'+sha(broker)+'"',definitions[0],definitions[1],lib/'verification-darwin-stub.c','-o',stub])
            run('darwin-stub-describe',[stub,'--describe'])
        record['binaries']={str(p.relative_to(out)):sha(p) for p in sorted(dest.rglob('*')) if p.is_file() and '.build-' not in str(p)}
        record['status']='PASS_COMPILE_AND_LOAD'
    except Exception as e:
        record['status']='FAIL';record['error']=str(e);raise
    finally: save()
if __name__=='__main__':main()
