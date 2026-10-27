'use strict';

// Exact production C transition core; kernel callbacks are deliberately
// simulated here. This is not Darwin fork/UID/Mach qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const sourcePath = path.join(__dirname, '../tools/lib/verification-darwin-stub.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const begin = source.indexOf('enum { KVG_STOP_REQUEST=');
const end = source.indexOf('/* END EXACT PORTABLE GUARDIAN STATE MACHINE */', begin);
const compiler = process.env.CC || 'cc';
const available = cp.spawnSync(compiler, ['--version'], { encoding: 'utf8' });

test('production guardian C core never treats time/unknown observations as cleanup', { skip: available.error ? `C compiler unavailable: ${available.error.code}` : false }, () => {
  assert.ok(begin >= 0 && end > begin, 'exact production guardian core must be present');
  const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-guardian-core-'));
  const cfile = path.join(root, 'core.c'), binary = path.join(root, process.platform === 'win32' ? 'core.exe' : 'core');
  const fixture = `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
${source.slice(begin, end)}
struct Model { uint64_t now; bool clock_ok; int parent,wait,status,members,signals,scans; };
static bool clock_model(void *p,uint64_t *now){struct Model *m=p;*now=m->now;return m->clock_ok;}
static int parent_model(void *p){return ((struct Model *)p)->parent;}
static int wait_model(void *p,int *status){struct Model *m=p;*status=m->status;return m->wait;}
static void signal_model(void *p){((struct Model *)p)->signals++;}
static int drain_model(void *p){struct Model *m=p;m->scans++;return m->members;}
static struct KGuardOps ops={clock_model,parent_model,wait_model,signal_model,drain_model};
static void check(bool condition,const char *label){if(!condition){fprintf(stderr,"FAIL %s\\n",label);exit(1);}printf("PASS %s\\n",label);}
static struct KGuardState state(void){struct KGuardState s={.deadline=1000,.cleanup_budget=100,.last_now=100};return s;}
static struct Model model(void){struct Model m={.now=101,.clock_ok=true,.parent=1,.wait=0,.members=1};return m;}
int main(void){struct KGuardState s;struct Model m;
  s=state();m=model();kvg_step(&s,&ops,&m,false);
  check(!s.stopped&&m.signals==0&&m.scans==0,"silence-is-not-a-stop");
  kvg_step(&s,&ops,&m,true);check(s.stopped&&m.signals==1&&!s.complete,"explicit-stop-drains-live-child");
  m.now=50000;m.members=0;kvg_step(&s,&ops,&m,true);
  check(s.cleanup_expired&&!s.complete&&m.signals==2,"timeout-and-UID-zero-do-not-reap-child");
  m.wait=1;m.status=77;kvg_step(&s,&ops,&m,true);
  check(s.complete&&s.child_status==77&&s.reasons&KVG_STOP_REQUEST,"actual-reap-and-zero-finish-aborted-cleanup");
  s=state();m=model();m.parent=0;kvg_step(&s,&ops,&m,false);
  check(s.stopped&&(s.reasons&KVG_PARENT_LOST)&&m.signals==1,"daemon-death-does-not-depend-on-storage");
  s=state();m=model();m.parent=-1;kvg_step(&s,&ops,&m,false);
  check(s.stopped&&(s.reasons&KVG_PARENT_LOST)&&!s.complete,"unknown-parent-is-stop-not-cleanup");
  s=state();m=model();m.clock_ok=false;kvg_step(&s,&ops,&m,false);
  check(s.clock_failed&&s.stopped&&s.cleanup_expired&&m.signals==1&&!s.complete,"clock-failure-keeps-enforcer-alive");
  m.now=200;m.clock_ok=true;kvg_step(&s,&ops,&m,false);
  check(s.clock_failed&&s.stopped&&!s.complete,"clock-recovery-never-reopens-admission");
  s=state();m=model();m.now=99;kvg_step(&s,&ops,&m,false);
  check(s.clock_failed&&s.stopped&&s.last_now==100,"backwards-monotonic-clock-latches-stop");
  s=state();m=model();m.now=999;kvg_step(&s,&ops,&m,false);
  check(!s.stopped,"full-work-budget-before-boundary");
  m.now=1000;kvg_step(&s,&ops,&m,false);
  check(s.stopped&&(s.reasons&KVG_DEADLINE),"deadline-boundary-closes-admission");
  s=state();m=model();m.wait=1;m.status=0;m.members=2;kvg_step(&s,&ops,&m,false);
  check(s.child_reaped&&!s.complete&&m.scans==1,"zero-exit-does-not-hide-detached-descendants");
  m.members=1;m.now=102;kvg_step(&s,&ops,&m,false);
  check(!s.complete&&m.scans==2,"child-born-between-scan-and-kill-requires-another-scan");
  m.members=0;m.now=103;kvg_step(&s,&ops,&m,false);
  check(s.complete&&s.reasons==KVG_CHILD_EXIT,"normal-exit-only-after-reap-and-fresh-full-zero");
  s=state();m=model();m.wait=-1;m.members=0;kvg_step(&s,&ops,&m,false);
  check((s.reasons&KVG_WAIT_UNKNOWN)&&!s.child_reaped&&!s.complete,"ECHILD-never-invents-owned-exit");
  s=state();m=model();m.wait=1;m.members=-1;kvg_step(&s,&ops,&m,false);
  check(!s.complete,"failed-or-overflowed-UID-enumeration-is-not-empty");
  s=state();m=model();kvg_step(&s,&ops,&m,true);uint64_t deadline=s.cleanup_deadline;
  m.now=150;kvg_step(&s,&ops,&m,true);
  check(s.cleanup_deadline==deadline&&deadline==201,"repeated-stop-never-restarts-cleanup-budget");
  s=state();m=model();s.deadline=60000000000ull;m.now=50000000000ull;kvg_step(&s,&ops,&m,false);
  check(!s.stopped,"long-work-budget-is-not-truncated-to-32-bits");
  s=state();m=model();s.last_now=UINT64_MAX-10;m.now=UINT64_MAX-9;s.deadline=UINT64_MAX;
  kvg_step(&s,&ops,&m,true);check(s.cleanup_deadline==UINT64_MAX&&!s.complete,"cleanup-addition-does-not-wrap");
  s=state();m=model();m.wait=1;m.members=0;kvg_step(&s,&ops,&m,true);
  check(s.complete&&(s.reasons&KVG_STOP_REQUEST),"simultaneous-success-and-cancel-remains-aborted");
  return 0;
}
`;
  fs.writeFileSync(cfile, fixture);
  try {
    const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', cfile, '-o', binary], { encoding: 'utf8', timeout: 60000 });
    assert.equal(built.status, 0, built.stderr || built.error?.message);
    const run = cp.spawnSync(binary, [], { encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}\n${run.error?.message || ''}`);
    const checks = run.stdout.trim().split('\n');
    assert.equal(checks.length, 20);
    assert.ok(checks.every(line => line.startsWith('PASS ')));
    console.log(JSON.stringify({ scope: 'exact-production-C-core; simulated-kernel-callbacks; not-native-Darwin',
      source_sha256: crypto.createHash('sha256').update(source).digest('hex'), checks }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
