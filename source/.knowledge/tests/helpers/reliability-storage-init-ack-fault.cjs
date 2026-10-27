'use strict';
// Source-only fault schedule: stop the real fixed storage worker after its
// durable init transaction, immediately before its first IPC acknowledgment.
const fs=require('node:fs');
const original=process.send;
process.send=function(message,...args){
  if(message?.protocol==='knowledge-darwin-storage.v1' && message.id===1 && message.ok===true && message.value?.owner){
    fs.writeSync(1,'DURABLE_INIT_BEFORE_ACK\n');
    const fifo=process.env.KNOWLEDGE_TEST_STORAGE_ACK_FIFO;
    if(fifo)fs.closeSync(fs.openSync(fifo,fs.constants.O_RDONLY));
    else Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);
  }
  return original.call(this,message,...args);
};
