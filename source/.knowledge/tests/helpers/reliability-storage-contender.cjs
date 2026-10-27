'use strict';
const control=require('../../tools/lib/verification-control');
const context={stateRoot:process.argv[2]};
process.send({stage:'starting'},()=>{
  let result;
  try{result={stage:'result',value:control.beginAttempt(context,{request_sha256:'1'.repeat(64)})};}
  catch(error){result={stage:'result',error:error.code||error.message};}
  process.send(result,()=>process.disconnect());
});
