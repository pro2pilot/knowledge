'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const net = require('net');
const { once } = require('events');
const { createServer, createClient } = require('../tools/lib/command-holder-channel');
async function fixture(t) { const server = await createServer(); t.after(() => server.close()); return server; }
function raw(server) { return net.createConnection({host:'127.0.0.1',port:Number(server.arguments[1])}); }
async function authenticated(server) {
 const connected=once(server,'connected'),socket=raw(server);await once(socket,'connect');
 socket.write(JSON.stringify({type:'hello',token:server.arguments[2]})+'\n');await connected;return socket;
}
test('holder channel binds one peer and preserves the final message before actual EOF',async t=>{
 const server=await fixture(t),connected=once(server,'connected'),client=createClient(server.arguments);t.after(()=>client.close());await connected;
 const got=once(server,'message'),ended=once(server,'disconnect');client.send({type:'terminal',value:'x'.repeat(60000)},()=>client.socket.end());
 assert.equal((await got)[0].value.length,60000);assert.equal((await ended)[0],'eof');assert.equal(server.complete,true);
});
test('holder channel rejects an incorrect capability without consuming the valid peer slot',async t=>{
 const server=await fixture(t),bad=raw(server);await once(bad,'connect');bad.end(JSON.stringify({type:'hello',token:'0'.repeat(64)})+'\n');await once(bad,'close');assert.equal(server.everConnected,false);
 const socket=await authenticated(server);t.after(()=>socket.destroy());assert.equal(server.connected,true);
});
for(const [name,bytes,reason] of [
 ['truncated final message',Buffer.from('{"type":"terminal"'),'truncated'],
 ['invalid UTF8',Buffer.from([0xff,10]),'malformed'],
 ['nonobject JSON',Buffer.from('null\n'),'malformed'],
 ['oversized line',Buffer.from('x'.repeat(65537)),'oversized']
])test('holder channel rejects '+name,async t=>{
 const server=await fixture(t),socket=await authenticated(server);t.after(()=>socket.destroy());const ended=once(server,'disconnect');socket.end(bytes);
 assert.equal((await ended)[0],reason);assert.equal(server.complete,false);
});
