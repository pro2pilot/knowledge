'use strict';

// Exact final guard statements compiled as portable C. Objective-C property
// reads, owner observations and clocks are explicit models, not native macOS.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const input = process.env.KNOWLEDGE_DARWIN_BROKER_TEST_SOURCE || path.join(__dirname, '../tools/lib/verification-darwin-broker.m');
const source = fs.readFileSync(input, 'utf8');
function between(first, last) {
  const start = source.indexOf(first), end = source.indexOf(last, start);
  assert.ok(start >= 0 && end > start, 'exact production guard range must exist');
  return source.slice(start, end);
}
function translate(text) {
  return text.replaceAll('NSMutableDictionary *e', 'int e')
    .replaceAll('[e[@"work_deadline_ms"] unsignedLongLongValue]', 'workDeadline')
    .replaceAll('[e[@"cleanup_deadline_ms"] unsignedLongLongValue]', 'cleanupDeadline')
    .replaceAll('[e[@"admission_closed"] boolValue]', 'admissionClosed')
    .replaceAll('[e[@"proof"][@"native_cleanup_facts_confirmed"] boolValue]', 'closedProof')
    .replaceAll('e[@"controller"]', '1').replaceAll('e[@"authority"]', '2');
}
let work = between('static bool workStopped(NSMutableDictionary *e)', 'static bool revalidateWorkPeer(');
const latch = work.indexOf('    if(stop&&e){');
assert.ok(latch > 0);
work = translate(work.slice(0, latch) + '    if(stop&&e)latchCount++;\n    return stop;\n}\n');
const rawTail = between('    /* Fresh allocation and clock/owner guards AFTER', '    NSDictionary *reply=failure(@"COPY_READBACK_UNCONFIRMED");');
const tail = translate(rawTail);
const readback = between('static NSDictionary *readbackCopy(', 'static NSString *sbplString(');
const timestamp = readback.match(/@"observed_monotonic_ms":@\(([A-Za-z_][A-Za-z0-9_]*(?:\(\))?)\)/)?.[1];
assert.ok(timestamp, 'reply timestamp must be extracted');
assert.equal((work + tail).includes('@'), false, 'only declared Objective-C property reads may be modeled');
const compiler = process.env.CC || 'cc';
const available = cp.spawnSync(compiler, ['--version'], { encoding: 'utf8' });
const workCases = ['healthy', 'no-entry', 'clock-fault', 'no-entry-clock-fault', 'prior-clock-fault',
  'peer-delay', 'entry-delay', 'generation-delay', 'peer-cancel', 'early-stop', 'peer-absent',
  'entry-absent', 'prior-cancel', 'deadline'];
const readbackCases = ['sealed-healthy', 'drained-healthy', 'closed-healthy', 'sealed-clock-fault',
  'drained-clock-fault', 'closed-clock-fault', 'sealed-final-clock-fault', 'peer-cancel',
  'owners-cancel', 'owners-delay', 'closed-deadline', 'sealed-deadline', 'drained-deadline',
  'allocation-missing', 'closed-proof-missing', 'owner-missing', 'prior-cancel', 'closed-stop'];

test('final positive observations resample clocks after owner I/O and reload cancellation',
  { skip: available.error ? 'Portable C compiler unavailable: ' + available.error.code : false }, async t => {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-final-observation-'));
    const cfile = path.join(root, 'model.c'), binary = path.join(root, 'model');
    fs.writeFileSync(cfile, `
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
struct Work { _Atomic bool cancelled; } workValue;
static struct Work *gCurrentWork=&workValue;
struct KIdentity { int unused; };
static bool gStopping,gPoisoned,admissionClosed,closedProof=true;
static _Atomic bool gClockFailed;
static uint64_t timeValue=100,workDeadline=1000,cleanupDeadline=1000;
static unsigned clockCalls,peerCalls,latchCount,faultNth;
static const char *mode;
static bool is(const char *s){return !strcmp(mode,s);}
static uint64_t nowMS(void){clockCalls++;
  if(faultNth&&clockCalls==faultNth){atomic_store(&gClockFailed,true);gStopping=true;return 100;}
  return timeValue;
}
static bool currentPeerAlive(void){peerCalls++;
  if(is("peer-delay"))timeValue=1000;
  if(is("peer-cancel"))atomic_store(&workValue.cancelled,true);
  return !is("peer-absent");
}
static bool currentEntry(int e){(void)e;if(is("entry-delay"))timeValue=1000;return !is("entry-absent");}
static bool stoppedAttempt(int e){(void)e;if(is("generation-delay"))timeValue=1000;return false;}
static bool abortedAttempt(int e){(void)e;return gStopping;}
static bool validUIDAllocation(int e){(void)e;return !is("allocation-missing");}
static int observeExact(int role,struct KIdentity *v){(void)v;
  if(role==2&&is("owners-delay"))timeValue=1000;
  if(role==2&&is("owners-cancel"))atomic_store(&workValue.cancelled,true);
  return is("owner-missing")?0:1;
}
${work}
static bool readbackModel(bool sealed,bool drained,bool closed,uint64_t *embedded){int e=1;bool ok=true;
${tail}
  if(ok)*embedded=${timestamp};
  return ok;
}
int main(int argc,char **argv){
  if(argc!=3)return 64;mode=argv[2];uint64_t embedded=0;bool accepted=false,expected=false;
  if(strstr(mode,"clock-fault"))faultNth=is("sealed-final-clock-fault")?2:1;
  if(is("prior-clock-fault")){faultNth=0;atomic_store(&gClockFailed,true);}
  if(is("prior-cancel"))atomic_store(&workValue.cancelled,true);
  if(strstr(mode,"deadline"))timeValue=1000;
  if(!strcmp(argv[1],"work")){
    int e=is("no-entry")||is("no-entry-clock-fault")?0:1;
    if(is("early-stop"))gStopping=true;
    expected=is("healthy")||is("no-entry");accepted=!workStopped(e);
    if(is("early-stop")&&peerCalls)return 2;
  }else{
    bool sealed=!strncmp(mode,"sealed-",7),closed=!strncmp(mode,"closed-",7),drained=!sealed&&!closed;
    if(is("closed-proof-missing"))closedProof=false;
    if(is("closed-stop"))gStopping=true;
    admissionClosed=closed;
    expected=strstr(mode,"healthy")!=NULL;accepted=readbackModel(sealed,drained,closed,&embedded);
    if(accepted&&expected&&embedded!=timeValue)return 2;
  }
  printf("accepted=%u expected=%u clock_failed=%u cancel=%u calls=%u embedded=%llu\\n",
    accepted,expected,atomic_load(&gClockFailed),atomic_load(&workValue.cancelled),clockCalls,(unsigned long long)embedded);
  return accepted==expected?0:1;
}
`);
    try {
      const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', cfile, '-o', binary],
        { encoding: 'utf8', timeout: 60000 });
      assert.equal(built.status, 0, (built.stderr || '') + (built.error?.message || ''));
      console.log(JSON.stringify({ scope: 'portable exact final predicates; modeled owner/clock callbacks; NOT native macOS',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'),
        generated_C_sha256: crypto.createHash('sha256').update(fs.readFileSync(cfile)).digest('hex') }));
      for (const [edge, cases] of [['work', workCases], ['readback', readbackCases]]) for (const name of cases) {
        await t.test(edge + '/' + name, () => {
          const run = cp.spawnSync(binary, [edge, name], { encoding: 'utf8', timeout: 3000 });
          console.log(JSON.stringify({ edge, name, status: run.status, signal: run.signal, stdout: run.stdout, stderr: run.stderr }));
          assert.equal(run.status, 0, run.stdout + run.stderr + (run.error?.message || ''));
          assert.equal(run.signal, null);
        });
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
