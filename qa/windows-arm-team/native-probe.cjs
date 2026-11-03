'use strict';
// QA-only actual Windows native loading. No installation, compilation,
// fallback, Job creation, or authority inferred from an on-disk hash.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const SHA = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const EXPECTED = Object.freeze({
  command: { binary:'command-windows-job.node',bytes:180224,
    sha:'f61852f8aacf7b4b056a5e122f4199a9ab8c990049fb42dea35215da8021a565',
    source:'command-windows-job.c',sourceBytes:44323,
    sourceSha:'8f5539ba12ee05ab090a75625cd6a362b66b99911a784010e7fd6ecb4b004aad',
    manifest:'command-windows-job.manifest.json',schema:'knowledge-command-windows-binary.v1' },
  lock: { binary:'lock-publication.node',bytes:162816,
    sha:'e866065510a925efaf9be2b6a925ee95b639566d2273ae6e35342df086e93cd3',
    source:'lock-publication.c',sourceSha:'ed200e1c901cf65387188a3804380826e5cd56bca411543cd293baabbcd247d0',
    manifest:'lock-publication.manifest.json',schema:'knowledge-lock-native-binary.v1' }
});
function peArm64(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length<256 || bytes.toString('ascii',0,2)!=='MZ') fail('qa_pe_dos');
  const at=bytes.readUInt32LE(0x3c);
  if (at<64 || at+26>bytes.length || bytes.readUInt32LE(at)!==0x00004550 || bytes.readUInt16LE(at+4)!==0xaa64 ||
      bytes.readUInt16LE(at+20)<112 || at+24+bytes.readUInt16LE(at+20)>bytes.length || bytes.readUInt16LE(at+24)!==0x20b) fail('qa_pe_arm64');
  return {machine:'AA64',optional_header:'PE32+'};
}
function stableFile(file,maximum) {
  const before=fs.lstatSync(file,{bigint:true});
  if (!before.isFile() || before.isSymbolicLink() || before.nlink!==1n || before.size>BigInt(maximum)) fail('qa_native_nonregular');
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  try{
    const opened=fs.fstatSync(fd,{bigint:true});
    const same=st=>st.isFile()&&!st.isSymbolicLink()&&st.nlink===1n&&['dev','ino','size','mtimeNs','ctimeNs'].every(k=>before[k]===st[k]);
    if(!same(opened))fail('qa_native_changed');
    const bytes=Buffer.alloc(Number(before.size)+1);let used=0;
    while(used<bytes.length){const count=fs.readSync(fd,bytes,used,bytes.length-used,null);if(!count)break;used+=count;}
    if(used!==Number(before.size)||!same(fs.fstatSync(fd,{bigint:true}))||!same(fs.lstatSync(file,{bigint:true})))fail('qa_native_changed');
    return bytes.subarray(0,used);
  }finally{fs.closeSync(fd);}
}
function validateArtifacts(source) {
  const result={};
  for (const [name,pin] of Object.entries(EXPECTED)) {
    const dir=path.join(source,'tools/lib/native/win32-arm64');
    const bytes=stableFile(path.join(dir,pin.binary),2097152),sourceBytes=stableFile(path.join(source,'tools/native',pin.source),262144);
    const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(stableFile(path.join(dir,pin.manifest),16384)));
    const fields=['architecture','binary','binary_bytes','binary_sha256','napi_version','platform','schema_version','source_sha256'];
    if (JSON.stringify(Object.keys(manifest).sort())!==JSON.stringify(fields) || manifest.schema_version!==pin.schema ||
        manifest.platform!=='win32' || manifest.architecture!=='arm64' || manifest.napi_version!==8 || manifest.binary!==pin.binary ||
        manifest.binary_bytes!==pin.bytes || manifest.binary_sha256!==pin.sha || manifest.source_sha256!==pin.sourceSha ||
        bytes.length!==pin.bytes || SHA(bytes)!==pin.sha || SHA(sourceBytes)!==pin.sourceSha || pin.sourceBytes && sourceBytes.length!==pin.sourceBytes) fail('qa_native_pin');
    result[name]={manifest,pe:peArm64(bytes),source_bytes:sourceBytes.length};
  }
  return result;
}
function main(source,probeOwned,productOwned) {
  if (process.platform!=='win32' || process.arch!=='arm64' || process.version!=='v24.22.1' || Number(process.versions.napi)<8) fail('qa_native_scope_not_run');
  const os=require('node:os');
  function ownedIdentity(value){
    if(!path.isAbsolute(value)||fs.realpathSync.native(value)!==value)fail('qa_native_path');
    const st=fs.lstatSync(value,{bigint:true});if(!st.isDirectory()||st.isSymbolicLink())fail('qa_native_temp');
    return{directory:value,dev:String(st.dev),ino:String(st.ino)};
  }
  if(!path.isAbsolute(source))fail('qa_native_path');
  const probeTemp=ownedIdentity(probeOwned),productTemp=ownedIdentity(productOwned);
  if(probeOwned===productOwned||path.dirname(probeOwned)!==path.dirname(productOwned)||
    probeTemp.dev===productTemp.dev&&probeTemp.ino===productTemp.ino||os.tmpdir()!==probeOwned||
    process.env.KNOWLEDGE_QA_OWNED_TEMP!==probeOwned||fs.readdirSync(productOwned).length)fail('qa_native_separate_temp');
  const artifacts=validateArtifacts(source),exe=stableFile(process.execPath,268435456);
  const executable={pe:peArm64(exe),sha256:SHA(exe),bytes:exe.length};
  const loader=require(path.join(source,'tools/lib/command-windows-native.js'));
  // The original loader still performs its real snapshot/ABI handshake. This
  // QA probe intentionally retains that snapshot in its separate owned TEMP:
  // deleting a currently mapped addon is not a prerequisite for product QA.
  const snapshot=loader.preparePackagedHelper(),loaded=loader.loadPreparedHelper(snapshot),info=loaded.native.info();
  if (loaded.binding.architecture!=='arm64' || loaded.binding.source_sha256!==EXPECTED.command.sourceSha ||
      loaded.binding.binary_sha256!==EXPECTED.command.sha || info.bootstrap!=='job-list-at-birth.v1') fail('qa_native_handshake');
  const lock=require(path.join(source,'tools/lib/lock-publication.js')).qualifyNativePublication();
  if(path.dirname(snapshot.snapshot.directory)!==probeOwned)fail('qa_native_snapshot_scope');
  return {schema:'knowledge-d5-native-probe.v1',status:'PASS_NATIVE_LOAD_SCOPE_ONLY',
    node:{platform:process.platform,architecture:process.arch,version:process.version,napi:Number(process.versions.napi),executable},
    artifacts,command_binding:loaded.binding,command_info:info,lock_info:lock.info,lock_manifest:lock.manifest,
    probe_temp:probeTemp,product_temp:productTemp,product_tests:'NOT_RUN',
    snapshot_disposition:{status:'RETAINED_LOADED_DLL_IN_SEPARATE_OWNED_PROBE_ROOT',cleanup_claimed:false,snapshot}};
}
module.exports={peArm64,validateArtifacts,EXPECTED};
if (require.main===module) {
  try {if (process.argv.length!==5) fail('qa_native_arguments');process.stdout.write(JSON.stringify(main(process.argv[2],process.argv[3],process.argv[4]))+'\n');}
  catch(error){process.stdout.write(JSON.stringify({schema:'knowledge-d5-native-probe.v1',status:'NOT_RUN',code:/^qa_[a-z0-9_]+$/.test(error.code||'')?error.code:'qa_native_probe_failed',product_tests:'NOT_RUN'})+'\n');process.exitCode=1;}
}
