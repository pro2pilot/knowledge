#!/usr/bin/env node
'use strict';
const {resolveKnowledgeContext,parseCliArgs}=require('./lib/path-context');
const {copyInertData}=require('./lib/inert-data');
const control=require('./lib/verification-control');
function main(argv=process.argv.slice(2)) {
  const parsed=parseCliArgs(copyInertData(argv)),context=resolveKnowledgeContext(parsed.flags);
  const action=parsed.positional[0]||'status';
  const allowed=new Set(['stateRoot','targetRoot','systemRoot','projectKnowledgeRoot','mode','teamRoot','workspaceId','attempt','generation','reasonCode','json']);
  if(Object.keys(parsed.flags).some(k=>!allowed.has(k)))throw Object.assign(new Error('Unknown control flag'),{code:'verification_control_flag_invalid'});
  if(action==='status'){
    const result=control.readStatus(context);
    if(parsed.flags.attempt && result.attempt?.attempt_id!==parsed.flags.attempt || parsed.flags.generation && result.attempt?.generation!==parsed.flags.generation)throw Object.assign(new Error('Attempt mismatch'),{code:'verification_attempt_mismatch'});
    return result;
  }
  const input={attempt_id:parsed.flags.attempt,generation:parsed.flags.generation};
  if(action==='cancel')return control.requestCancel(context,{...input,reason_code:parsed.flags.reasonCode||'user_requested'});
  if(action==='recover')return require('./lib/verification-recovery').recoverAttempt(context,input);
  throw Object.assign(new Error('Use status|cancel|recover'),{code:'verification_control_command_invalid'});
}
if(require.main===module){try{const result=main();console.log(JSON.stringify(result,null,2));if(result.status==='requires_native_recovery')process.exitCode=2;}catch(error){console.error(JSON.stringify({status:'rejected',reason:error.code||'verification_control_failed'}));process.exitCode=2;}}
module.exports={main};
