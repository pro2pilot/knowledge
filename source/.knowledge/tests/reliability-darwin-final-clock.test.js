'use strict';

// Exact production C functions, compiled on the local host. Only clock/kernel
// callbacks are modeled. These tests are not a macOS native qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const sourcePath = process.env.KNOWLEDGE_DARWIN_STUB_TEST_SOURCE ||
  path.join(__dirname, '../tools/lib/verification-darwin-stub.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const clockStart = source.indexOf('static uint64_t now_ms(void)');
const clockEnd = source.indexOf('static bool hex64(', clockStart);
const coreStart = source.indexOf('enum { KVG_STOP_REQUEST=');
const coreEnd = source.indexOf('/* END EXACT PORTABLE GUARDIAN STATE MACHINE */', coreStart);
const compiler = process.env.CC || 'cc';
const available = cp.spawnSync(compiler, ['--version'], { encoding: 'utf8' });

test('native child and guardian check the last clock boundary without inventing process finality',
  { skip: available.error ? 'Portable C compiler unavailable: ' + available.error.code : false }, async t => {
    assert.ok(clockStart >= 0 && clockEnd > clockStart && coreStart >= 0 && coreEnd > coreStart);
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-final-clock-'));
    const cfile = path.join(root, 'clock.c'), binary = path.join(root, process.platform === 'win32' ? 'clock.exe' : 'clock');
    const fixture = `
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#define K_BOOTSTRAP_MS 60000ull
static const char *mode;
static unsigned clock_reads;
static int clock_fixture(clockid_t which,struct timespec *t){
  (void)which;clock_reads++;t->tv_sec=1;t->tv_nsec=0;
  if(!strcmp(mode,"clock-error")){errno=EIO;return -1;}
  if(!strcmp(mode,"clock-nsec-range"))t->tv_nsec=1000000000;
  if(!strcmp(mode,"clock-negative-sec"))t->tv_sec=-1;
  if(!strcmp(mode,"clock-overflow"))t->tv_sec=(time_t)(UINT64_MAX/1000ull+1);
  if(!strcmp(mode,"clock-near-overflow")){t->tv_sec=(time_t)((UINT64_MAX-2000)/1000ull);t->tv_nsec=0;}
  if(!strcmp(mode,"clock-rollback")&&clock_reads>1){t->tv_sec=0;t->tv_nsec=500000000;}
  return 0;
}
#define clock_gettime clock_fixture
${source.slice(clockStart, clockEnd)}
#undef clock_gettime
${source.slice(coreStart, coreEnd)}
struct Model { uint64_t now; bool clock_ok; int wait,members; };
static bool clock_model(void *p,uint64_t *now){struct Model *m=p;*now=m->now;return m->clock_ok;}
static int parent_model(void *p){(void)p;return 1;}
static int reap_model(void *p,int *status){struct Model *m=p;*status=0;
  if(!strcmp(mode,"guardian-slow-reap"))m->now+=100;
  return m->wait;}
static void signal_model(void *p){(void)p;}
static int drain_model(void *p){struct Model *m=p;
  if(!strcmp(mode,"guardian-cleanup-boundary"))m->now+=100;
  else if(!strcmp(mode,"guardian-work-boundary"))m->now=1000;
  else if(!strcmp(mode,"guardian-clock-loss"))m->clock_ok=false;
  else if(!strcmp(mode,"guardian-clock-rollback"))m->now=100;
  else if(!strcmp(mode,"guardian-slow-reap"))m->now++;
  else m->now++;
  return m->members;}
static struct KGuardOps ops={clock_model,parent_model,reap_model,signal_model,drain_model};
int main(int argc,char **argv){
  if(argc!=2)return 64;
  mode=argv[1];
  if(!strncmp(mode,"clock-",6)){
    uint64_t first=now_ms(),second=now_ms();
    printf("OBSERVED_TIME %llu %llu\\n",(unsigned long long)first,(unsigned long long)second);return 0;
  }
  struct Model m={.now=101,.clock_ok=true,.wait=1,.members=0};
  struct KGuardState s={.deadline=1000,.cleanup_budget=100,.last_now=100};
  if(!strcmp(mode,"guardian-live-child"))m.wait=0;
  if(!strcmp(mode,"guardian-live-member"))m.members=1;
  kvg_step(&s,&ops,&m,!strncmp(mode,"guardian-live-",14));
  bool ok=false;
  if(!strcmp(mode,"guardian-normal"))ok=s.complete&&!s.cleanup_expired&&!s.clock_failed&&s.reasons==KVG_CHILD_EXIT;
  else if(!strcmp(mode,"guardian-cleanup-boundary")||!strcmp(mode,"guardian-slow-reap"))ok=s.complete&&s.cleanup_expired&&!s.clock_failed;
  else if(!strcmp(mode,"guardian-work-boundary"))ok=s.complete&&(s.reasons&KVG_DEADLINE)&&s.cleanup_expired;
  else if(!strcmp(mode,"guardian-clock-loss")||!strcmp(mode,"guardian-clock-rollback"))ok=s.complete&&s.clock_failed&&s.cleanup_expired&&(s.reasons&KVG_CLOCK);
  else if(!strcmp(mode,"guardian-live-child"))ok=!s.complete&&!s.child_reaped;
  else if(!strcmp(mode,"guardian-live-member"))ok=!s.complete&&s.child_reaped;
  printf("GUARD complete=%u clock_failed=%u expired=%u reasons=%u last=%llu\\n",s.complete,s.clock_failed,s.cleanup_expired,s.reasons,(unsigned long long)s.last_now);
  return ok?0:1;
}
`;
    fs.writeFileSync(cfile, fixture);
    try {
      const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', cfile, '-o', binary],
        { encoding: 'utf8', timeout: 60000 });
      assert.equal(built.status, 0, (built.stderr || '') + (built.error?.message || ''));
      console.log(JSON.stringify({ scope: 'exact-production-C; modeled-clock-and-kernel-callbacks; not-native-Darwin',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'),
        binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex') }));
      const cases = ['clock-normal', 'clock-error', 'clock-nsec-range', 'clock-negative-sec', 'clock-overflow',
        'clock-near-overflow', 'clock-rollback', 'guardian-normal', 'guardian-cleanup-boundary',
        'guardian-slow-reap', 'guardian-work-boundary', 'guardian-clock-loss', 'guardian-clock-rollback',
        'guardian-live-child', 'guardian-live-member'];
      for (const name of cases) await t.test(name, () => {
        const run = cp.spawnSync(binary, [name], { encoding: 'utf8', timeout: 3000 });
        const expected = name.startsWith('clock-') && name !== 'clock-normal' ? 119 : 0;
        console.log(JSON.stringify({ case: name, status: run.status, signal: run.signal,
          stdout: run.stdout, stderr: run.stderr, error: run.error?.code || null }));
        assert.equal(run.status, expected, run.stdout + run.stderr + (run.error?.message || ''));
        assert.equal(run.signal, null);
        if (expected === 119) assert.equal(run.stdout, '', 'invalid time must not be returned as an observation');
      });
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
