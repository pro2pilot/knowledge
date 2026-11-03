'use strict';
// The sole production encryption owner. It runs AFTER the outer supervisor
// capture, snapshots fixed private files, and encrypts exactly once. Diagnostics
// never reach public stdout except inside the authenticated ciphertext.
const fs = require('node:fs'), path = require('node:path');
const T = require('./evidence-transport.cjs');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const KNOWN = Object.freeze(['product.stdout','product.stderr','supervisor.json','guard.json','native.json',
  'analysis.json','analysis-run.json','source-before.json','source-after.json','observations.ndjson',
  'guard-proof.ndjson','preflight-proof.ndjson','commands.json','node-scope.json','node-scope.stderr',
  'node-help.stdout','node-help.stderr','source-before.stderr','source-after.stderr','native.stderr',
  'guard-preflight.stdout','guard-preflight.stderr','guard-preflight-check.json','guard-preflight-check.stderr',
  'analysis.stdout','analysis.stderr']);
const CAPTURE_KEYS = Object.freeze(['schema','started','exited','stdout_eof','stderr_eof','overflow','pipe_failure',
  'timed_out','kill_attempted','kill_succeeded','retained_handle_captured','stdout_observed_bytes',
  'stderr_observed_bytes','elapsed_ms','original_supervisor_exit','failure_code']);
const UNKNOWN = 'UNKNOWN_SUPERVISOR_CAPTURE_INCOMPLETE_OR_NO_VALID_RECEIPT';
const kind = name => /\.(stdout|stderr)$/.test(name) ? 'stream' : 'receipt';
function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value,k));
}
function record(name, bytes, type = kind(name)) {
  return {name,kind:type,bytes:bytes.length,sha256:T.sha256(bytes),encoding:'base64',data:bytes.toString('base64')};
}
function validCapture(capture) {
  return exactKeys(capture,CAPTURE_KEYS) && capture.schema === 'knowledge-d5-bootstrap-capture.v1' &&
    ['started','exited','stdout_eof','stderr_eof','overflow','pipe_failure','timed_out','kill_attempted',
      'kill_succeeded','retained_handle_captured'].every(k=>typeof capture[k]==='boolean') &&
    ['stdout_observed_bytes','stderr_observed_bytes','elapsed_ms'].every(k=>Number.isSafeInteger(capture[k])&&capture[k]>=0) &&
    (capture.original_supervisor_exit===null || Number.isSafeInteger(capture.original_supervisor_exit)) &&
    (capture.failure_code===null || typeof capture.failure_code==='string'&&/^D5_[A-Z0-9_]{1,80}$/.test(capture.failure_code));
}
function completeCapture(capture, stdout, stderr) {
  return validCapture(capture) && capture.started && capture.exited && capture.original_supervisor_exit===0 &&
    capture.stdout_eof && capture.stderr_eof && !capture.overflow && !capture.pipe_failure && !capture.timed_out &&
    !capture.kill_attempted && !capture.kill_succeeded && capture.retained_handle_captured && capture.failure_code===null &&
    capture.elapsed_ms<=740000 && capture.stdout_observed_bytes===stdout.length &&
    capture.stderr_observed_bytes===stderr.length && stderr.length===0;
}
function readJSON(bytes, cap) { return T.parseStrictJSON(bytes,cap || T.LIMITS.file); }
function recoverProduct(snapshot, allowRecovery, boundRequest) {
  const recovered=[];
  const facts=p=>({started:p.started,original_child_exit:p.original_child_exit,timed_out:p.timed_out,overflow:p.overflow});
  if (allowRecovery && snapshot.records.has('supervisor.json')) {
    try {
      const supervisor = readJSON(snapshot.records.get('supervisor.json'));
      const p=supervisor.product;
      if (supervisor.schema==='knowledge-d5-supervisor.v1' && p && typeof p.started==='boolean' &&
          typeof p.exited==='boolean' && typeof p.timed_out==='boolean' && typeof p.overflow==='boolean' &&
          (p.original_child_exit===null || Number.isInteger(p.original_child_exit) && p.original_child_exit>=-2147483648 && p.original_child_exit<=4294967295) &&
          (p.started || p.original_child_exit===null && !p.timed_out) &&
          (p.original_child_exit===null || p.exited===true)) recovered.push({source:'supervisor.json/product',facts:facts(p)});
    } catch { /* Exact raw bytes remain diagnostic evidence; no guessed facts. */ }
  }
  if(allowRecovery && boundRequest?.result) {
    const r=boundRequest.result;
    if(r.scope===T.SCOPE && ['PASS','FAIL','NOT_RUN','UNCERTAIN'].includes(r.status) &&
        typeof r.product_started==='boolean' && typeof r.timed_out==='boolean' && typeof r.overflow==='boolean' &&
        (r.original_child_exit===null || Number.isInteger(r.original_child_exit)&&r.original_child_exit>=-2147483648&&r.original_child_exit<=4294967295) &&
        (r.product_started || r.original_child_exit===null&&!r.timed_out))
      recovered.push({source:'same-run request.json/result',facts:{started:r.product_started,original_child_exit:r.original_child_exit,timed_out:r.timed_out,overflow:r.overflow}});
  }
  const conflict=recovered.length>1 && JSON.stringify(recovered[0].facts)!==JSON.stringify(recovered[1].facts);
  const product=!conflict&&recovered.length?recovered[0].facts:null;
  const result={status:'UNCERTAIN',scope:T.SCOPE,product_started:product?product.started:null,
    original_child_exit:product?product.original_child_exit:null,timed_out:product?product.timed_out:false,
    overflow:product?product.overflow:false,evidence_complete:false,
    tests:{expected:2,passed:0,failed:0,skipped:0},guard_worker_proof:false,native_custody_complete:false,
    source_unchanged:false,native_arm_scope_verified:false,
    details:{product_start_knowledge:product?'RECOVERED_TYPED_SAME_RUN_SUPERVISOR_PRODUCT_FACTS':UNKNOWN,
      original_child_exit_source:product?recovered.map(x=>x.source).join(' AND '):'UNKNOWN',
      conflicting_product_receipts:conflict,diagnostic_product_candidates:recovered,
      root_acceptance:'Requires private authenticated evidence review; no quality acceptance from encryption'}};
  return result;
}
function buildBody(snapshot, expected, options={}) {
  const metadata=T.normalizeMetadata(expected,options), issues=[...snapshot.readProblems];
  let request=null,capture=null,candidate=false,bindingMismatch=false,boundRequest=null;
  try { capture=readJSON(snapshot.captureBytes,8192); if(!validCapture(capture)) throw new Error(); }
  catch { capture=null;issues.push('BOOTSTRAP_CAPTURE_INVALID_OR_MISSING'); }
  try {
    request=readJSON(snapshot.requestBytes,T.LIMITS.request);
    if(!exactKeys(request,['schema','metadata','private_root','result','files']) ||
        request.schema!=='knowledge-d5-evidence-request.v1' || request.private_root!==snapshot.privateRoot) fail('REQUEST_FIELDS_OR_ROOT');
    let binding;
    try { binding=T.canonicalAAD(request.metadata,options); }
    catch { bindingMismatch=true;throw new Error(); }
    if(!binding.equals(T.canonicalAAD(metadata,options))) {bindingMismatch=true;fail('REQUEST_RUN_BINDING');}
    boundRequest=request; // Preserve typed same-run rc even if an attachment is missing.
    if(!Array.isArray(request.files)||request.files.length>KNOWN.length) fail('REQUEST_FILE_LIST');
    const names=new Set();
    for(const f of request.files) {
      if(!exactKeys(f,['name','kind'])||!KNOWN.includes(f.name)||f.kind!==kind(f.name)||names.has(f.name)||!snapshot.records.has(f.name)) fail('REQUEST_FILE_LIST');
      names.add(f.name);
    }
    if(!request.result || typeof request.result!=='object') fail('REQUEST_RESULT');
    candidate=true;
  } catch {issues.push(bindingMismatch?'REQUEST_RUN_BINDING_REJECTED':'NO_COMPLETE_VALID_REQUEST');}
  function assemble(useCandidate) {
    const result=useCandidate?structuredClone(request.result):recoverProduct(snapshot,!bindingMismatch,boundRequest);
    if(!result.details||typeof result.details!=='object'||Array.isArray(result.details)) result.details={};
    result.details.supervisor_capture=capture;
    result.details.export_status='SINGLE_OUTER_ENCRYPTION_PREPARED_AFTER_SUPERVISOR_CAPTURE';
    result.details.outer_finalizer={schema:'knowledge-d5-export-preparation.v1',candidate_request_used:useCandidate,
      diagnostic_mapping:useCandidate?'STANDARD_EVIDENCE_NAMES':'partial/<original-name>',issues:[...issues],omitted:[],
      one_encryption_per_run:'CREATE_NEW_ATTEMPT_MARKER_AND_NO_RETRY',windows_execution_by_finalizer:'NONE'};
    const controlOk=capture && completeCapture(capture,snapshot.stdout,snapshot.stderr);
    const expectedLine=useCandidate?`D5_CANDIDATE ${result.status} REQUEST_READY\n`:'';
    const exactSummary=useCandidate && snapshot.stdout.toString('utf8').replace(/\r\n/g,'\n')===expectedLine;
    if(!controlOk || !exactSummary || issues.length) {
      if(result.status==='PASS') result.status='UNCERTAIN';
      result.evidence_complete=false;
      result.details.outer_finalizer.issues.push('SUPERVISOR_CONTROL_OR_REQUEST_NOT_COMPLETE');
    }
    if(capture?.overflow) {result.overflow=true;result.evidence_complete=false;if(result.status==='PASS')result.status='UNCERTAIN';}
    const body={schema:T.FORMAT,metadata,result,files:[]};
    const offered=[record('bootstrap-capture.json',snapshot.captureBytes),record('bootstrap.stdout',snapshot.stdout,'stream'),
      record('bootstrap.stderr',snapshot.stderr,'stream')];
    const selection=useCandidate?request.files.map(x=>x.name):KNOWN.filter(name=>snapshot.records.has(name));
    for(const name of selection) offered.push(record(useCandidate?name:'partial/'+name,snapshot.records.get(name),kind(name)));
    if(snapshot.requestBytes.length) offered.push(record('supervisor-request.json',snapshot.requestBytes));
    for(const item of offered) {
      // Reserve bounded space for details/omission accounting. No truncated file
      // can masquerade as complete: whole files are either authenticated or omitted.
      if(item.bytes>T.LIMITS.file || body.files.length>=T.LIMITS.files ||
          Buffer.byteLength(JSON.stringify({...body,files:[...body.files,item]}))>T.LIMITS.plaintext-65536) {
        result.details.outer_finalizer.omitted.push(item.name);result.overflow=true;result.evidence_complete=false;
        if(result.status==='PASS')result.status='UNCERTAIN';
      } else body.files.push(item);
    }
    if(!useCandidate) result.evidence_complete=false;
    T.validateBody(body,metadata,options);
    return body;
  }
  if(candidate) {
    try {return assemble(true);} catch {issues.push('CANDIDATE_BODY_VALIDATION_FAILED');}
  }
  return assemble(false);
}
function unchanged(record) {
  const now=T.physicalDirectory(record.root);
  if(now.dev!==record.dev||now.ino!==record.ino) fail('D5_FINALIZER_ROOT_CHANGED');
}
function collect(jobRoot) {
  const root=T.physicalDirectory(jobRoot), privateRoot=path.join(root.root,'private');
  const snapshot={privateRoot,records:new Map(),readProblems:[],requestBytes:Buffer.alloc(0),captureBytes:Buffer.alloc(0),
    stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)};
  function readFixed(directory,name,maximum,missingOkay=false) {
    unchanged(directory);
    try {const bytes=T.readBoundedFile(path.join(directory.root,name),maximum);unchanged(directory);return bytes;}
    catch(error) {if(!missingOkay||error.code!=='ENOENT')snapshot.readProblems.push('UNREADABLE_'+name.replace(/[^a-z0-9]/gi,'_').toUpperCase());return null;}
  }
  snapshot.captureBytes=readFixed(root,'bootstrap-capture.json',8192)||Buffer.alloc(0);
  snapshot.stdout=readFixed(root,'supervisor.private.stdout',T.LIMITS.file)||Buffer.alloc(0);
  snapshot.stderr=readFixed(root,'supervisor.private.stderr',T.LIMITS.file)||Buffer.alloc(0);
  let privateRecord;
  try {privateRecord=T.physicalDirectory(privateRoot);} catch {snapshot.readProblems.push('PRIVATE_DIRECTORY_UNAVAILABLE');}
  if(privateRecord) {
    snapshot.requestBytes=readFixed(privateRecord,'request.json',T.LIMITS.request,true)||Buffer.alloc(0);
    for(const name of KNOWN) {const bytes=readFixed(privateRecord,name,T.LIMITS.file,true);if(bytes)snapshot.records.set(name,bytes);}
    unchanged(privateRecord);
  }
  unchanged(root);return {root,snapshot};
}
function finalize(jobRoot,expected,publicPem,options={}) {
  // Production main supplies no override. Test modules use only ephemeral keys.
  if(T.keyId(publicPem)!==(options.expectedKeyId||T.ROOT_KEY_ID)) fail('PUBLIC_KEY_PIN_MISMATCH');
  const {root,snapshot}=collect(jobRoot),body=buildBody(snapshot,expected,options);unchanged(root);
  const attempt={schema:'knowledge-d5-single-encryption-attempt.v1',metadata:body.metadata,
    body_sha256:T.sha256(Buffer.from(JSON.stringify(body))),policy:'ONE_ATTEMPT_NO_RETRY'};
  fs.writeFileSync(path.join(root.root,'outer-encryption-attempt.json'),JSON.stringify(attempt)+'\n',{flag:'wx',mode:0o600});
  unchanged(root);
  const encrypted=T.encryptBody(body,publicPem,options); // Sole production AES/GCM invocation.
  return {publicCandidate:encrypted.log+`D5_STATUS ${body.result.status} EXPORT_OK\n`,body,
    exitCode:body.result.status==='PASS'?0:1};
}
function argumentsFor(argv) {
  const fields=['--job-root','--public-key','--repository','--run-id','--run-attempt','--commit'];
  if(argv.length!==fields.length*2)fail('D5_FINALIZER_ARGUMENTS');const args=Object.create(null);
  for(let i=0;i<argv.length;i+=2){if(!fields.includes(argv[i])||Object.hasOwn(args,argv[i])||!argv[i+1])fail('D5_FINALIZER_ARGUMENTS');args[argv[i]]=argv[i+1];}
  if(!fields.every(k=>Object.hasOwn(args,k))||!path.isAbsolute(args['--job-root'])||!path.isAbsolute(args['--public-key']))fail('D5_FINALIZER_ARGUMENTS');
  return args;
}
function main(argv) {
  const args=argumentsFor(argv),expected={repository:args['--repository'],run_id:args['--run-id'],run_attempt:args['--run-attempt'],
    commit:args['--commit'],input_sha256:T.INPUT_SHA256,key_id:T.ROOT_KEY_ID};
  return finalize(args['--job-root'],expected,T.readBoundedFile(args['--public-key'],T.LIMITS.key));
}
module.exports={KNOWN,CAPTURE_KEYS,UNKNOWN,validCapture,completeCapture,buildBody,collect,finalize,argumentsFor,main};
if(require.main===module){
  process.stdout.on('error',()=>{process.exitCode=74;});
  try{const result=main(process.argv.slice(2));process.stdout.write(result.publicCandidate);process.exitCode=result.exitCode;}
  catch{process.stderr.write('D5_SINGLE_OUTER_ENCRYPTION_FAILED_NO_PLAINTEXT\n');process.exitCode=74;}
}
