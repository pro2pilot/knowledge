'use strict';

// Compiles the actual broker's permit-stop expression. Only the checked clock
// and state are modeled; this is not Objective-C or native macOS qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const input = process.env.KNOWLEDGE_DARWIN_BROKER_TEST_SOURCE || path.join(__dirname, '../tools/lib/verification-darwin-broker.m');
const source = fs.readFileSync(input, 'utf8');
const start = source.indexOf('if((gRun.birth_permit_pending||gRun.permit_pending)&&gRun.gate>=0)');
const block = source.slice(start, source.indexOf('pthread_mutex_unlock(&gObservationMutex)', start));
const exact = block.match(/(?:uint64_t permitNow=nowMS\(\);\s*)?bool stopped=[\s\S]*?;/)?.[0];
const compiler = process.env.CC || 'cc';
const available = cp.spawnSync(compiler, ['--version'], { encoding: 'utf8' });

test('clock failure occurring at the permit edge closes admission in the same decision',
  { skip: available.error ? 'Portable C compiler unavailable: ' + available.error.code : false }, () => {
    assert.ok(start >= 0 && exact, 'exact broker permit-stop expression must be extractable');
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-permit-clock-'));
    const cfile = path.join(root, 'gate.c'), binary = path.join(root, process.platform === 'win32' ? 'gate.exe' : 'gate');
    fs.writeFileSync(cfile, `
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
static bool gStopping,clock_fault;
static _Atomic bool gClockFailed;
static _Atomic uint64_t gStopGeneration;
static uint64_t observed;
static struct { bool abort_latched,admission_closed;uint64_t generation; } gObservation;
static struct { uint64_t deadline; } gRun;
static uint64_t nowMS(void){if(clock_fault){gStopping=true;atomic_store(&gClockFailed,true);}return observed;}
static bool decision(void){bool current=true;${exact}return stopped;}
static void reset(void){gStopping=false;clock_fault=false;atomic_store(&gClockFailed,false);atomic_store(&gStopGeneration,0);
  gObservation.abort_latched=false;gObservation.admission_closed=false;gObservation.generation=7;gRun.deadline=1000;observed=100;}
static void check(bool ok,const char *name){if(!ok){fprintf(stderr,"FAIL %s\\n",name);exit(1);}printf("PASS %s\\n",name);}
int main(void){
  reset();check(!decision(),"live-budget-does-not-stop-silent-work");
  reset();observed=1000;check(decision(),"deadline-boundary-closes-permit");
  reset();clock_fault=true;check(decision(),"clock-failure-latched-during-observation-closes-this-permit");
  reset();atomic_store(&gClockFailed,true);check(decision(),"previous-clock-failure-cannot-reopen-admission");
  reset();gObservation.abort_latched=true;check(decision(),"stop-latch-precedes-permit");
  reset();gObservation.admission_closed=true;check(decision(),"closed-admission-precedes-permit");
  reset();atomic_store(&gStopGeneration,7);check(decision(),"same-generation-stop-precedes-permit");
  reset();atomic_store(&gStopGeneration,6);check(!decision(),"old-generation-stop-does-not-cancel-current-generation");
  return 0;
}
`);
    try {
      const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', cfile, '-o', binary], { encoding: 'utf8', timeout: 60000 });
      assert.equal(built.status, 0, built.stderr || built.error?.message);
      const run = cp.spawnSync(binary, [], { encoding: 'utf8', timeout: 10000 });
      console.log(JSON.stringify({ scope: 'exact-production-C-permit-expression; modeled-clock; not-native-Darwin',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'), stdout: run.stdout, stderr: run.stderr }));
      assert.equal(run.status, 0, (run.stderr || '') + (run.error?.message || ''));
      assert.equal(run.stdout.trim().split('\n').length, 8);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
