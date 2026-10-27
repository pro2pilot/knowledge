'use strict';

// The guardian's actual permit-edge expression and state core are compiled
// verbatim; clock and kernel callbacks are models, not native macOS proof.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const input = process.env.KNOWLEDGE_DARWIN_STUB_TEST_SOURCE ||
  path.join(__dirname, '../tools/lib/verification-darwin-stub.c');
const source = fs.readFileSync(input, 'utf8');
const marker = 'if(n==1){uint64_t live_now=0;bool live=';
const gateStart = source.indexOf(marker);
const gateEnd = source.indexOf('char child_token=0;', gateStart);
const coreStart = source.indexOf('enum { KVG_STOP_REQUEST=');
const coreEnd = source.indexOf('/* END EXACT PORTABLE GUARDIAN STATE MACHINE */', coreStart);
const compiler = process.env.CC || 'cc';
const available = cp.spawnSync(compiler, ['--version'], { encoding: 'utf8' });

test('guardian permit clock observation remains the monotonic lower bound for later decisions',
  { skip: available.error ? 'Portable C compiler unavailable: ' + available.error.code : false }, async t => {
    assert.ok(gateStart >= 0 && gateEnd > gateStart && coreStart >= 0 && coreEnd > coreStart);
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'guardian-permit-clock-'));
    const cfile = path.join(root, 'gate.c'), binary = path.join(root, process.platform === 'win32' ? 'gate.exe' : 'gate');
    const fixture = `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
${source.slice(coreStart, coreEnd)}
static uint64_t observed;
static bool clock_ok=true,guardian_stop;
static int parent_state=1;
static bool guardian_clock(void *p,uint64_t *now){(void)p;*now=observed;return clock_ok;}
static int guardian_parent(void *p){(void)p;return parent_state;}
static bool sample(struct KGuardState *saved,uint64_t now){
  struct KGuardState state=*saved;struct {uint64_t deadline;} config={1000},*c=&config;
  int g=0;observed=now;
  ${source.slice(gateStart + 'if(n==1){'.length, gateEnd)}
  *saved=state;return live;
}
static int reap_model(void *p,int *status){(void)p;*status=0;return 0;}
static void signal_model(void *p){(void)p;}
static int drain_model(void *p){(void)p;return 1;}
static struct KGuardOps ops={guardian_clock,guardian_parent,reap_model,signal_model,drain_model};
int main(int argc,char **argv){
  if(argc!=2)return 64;
  struct KGuardState state={.deadline=1000,.cleanup_budget=100,.last_now=100};
  const char *name=argv[1];bool ok=false,first=false,second=false;
  if(!strcmp(name,"accepted-sample-retained"))ok=sample(&state,500)&&state.last_now==500;
  else if(!strcmp(name,"rollback-before-next-permit")){first=sample(&state,500);second=sample(&state,499);ok=first&&!second&&state.last_now==500;}
  else if(!strcmp(name,"rollback-at-next-loop")){first=sample(&state,500);observed=499;kvg_step(&state,&ops,NULL,false);ok=first&&state.clock_failed&&state.stopped&&!state.complete&&state.last_now==500;}
  else if(!strcmp(name,"equal-clock-is-valid"))ok=sample(&state,100)&&state.last_now==100;
  else if(!strcmp(name,"deadline-is-not-an-accepted-sample"))ok=!sample(&state,1000)&&state.last_now==100;
  else if(!strcmp(name,"failed-clock-is-not-an-accepted-sample")){clock_ok=false;ok=!sample(&state,500)&&state.last_now==100;}
  else if(!strcmp(name,"owner-loss-is-not-an-accepted-sample")){parent_state=0;ok=!sample(&state,500)&&state.last_now==100;}
  else if(!strcmp(name,"stop-is-not-an-accepted-sample")){guardian_stop=true;ok=!sample(&state,500)&&state.last_now==100;}
  printf("GATE last=%llu clock_failed=%u stopped=%u first=%u second=%u\\n",(unsigned long long)state.last_now,state.clock_failed,state.stopped,first,second);
  return ok?0:1;
}
`;
    fs.writeFileSync(cfile, fixture);
    try {
      const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', cfile, '-o', binary],
        { encoding: 'utf8', timeout: 60000 });
      assert.equal(built.status, 0, (built.stderr || '') + (built.error?.message || ''));
      console.log(JSON.stringify({ scope: 'exact-production-guardian-permit-and-core; modeled-clock; not-native-Darwin',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'),
        binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex') }));
      for (const name of ['accepted-sample-retained', 'rollback-before-next-permit', 'rollback-at-next-loop',
        'equal-clock-is-valid', 'deadline-is-not-an-accepted-sample', 'failed-clock-is-not-an-accepted-sample',
        'owner-loss-is-not-an-accepted-sample', 'stop-is-not-an-accepted-sample']) await t.test(name, () => {
        const run = cp.spawnSync(binary, [name], { encoding: 'utf8', timeout: 3000 });
        console.log(JSON.stringify({ case: name, status: run.status, signal: run.signal,
          stdout: run.stdout, stderr: run.stderr, error: run.error?.code || null }));
        assert.equal(run.status, 0, run.stdout + run.stderr + (run.error?.message || ''));
        assert.equal(run.signal, null);
      });
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
