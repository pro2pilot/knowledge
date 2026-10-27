'use strict';

// Exact independent native custody sweep; kernel observations are modeled.
// Physical hostile scheduling/FIFO/controller-death cases run separately on macOS.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const cp = require('node:child_process'), crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../tools/lib/verification-darwin-broker.m'), 'utf8');
const compiler = process.env.CC || 'cc';
function section(from, to) {
  const a = source.indexOf(from), b = source.indexOf(to, a);
  assert.ok(a >= 0 && b > a);return source.slice(a, b);
}
test('independent custody survives planned command retirement and kills double-fault writers without storage',
  { skip: cp.spawnSync(compiler, ['--version']).status !== 0 }, () => {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'macos-custody-core-'));
    try {
      const code = `#define _GNU_SOURCE 1
#include <sys/types.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
struct KIdentity { unsigned pid,birth; };
struct KExactBirth { struct KIdentity identity;bool present; };
struct KObservation { bool valid,abort_latched,planned_terminal;char attempt[65]; };
static struct KObservation observation;
static _Atomic bool gClockFailed,gStopping;
static uint64_t clockValue;
static int kernel[16],signals[16];
static uint64_t nowMS(void){return clockValue;}
static uint64_t kvsNow(void){return clockValue*1000000ull;}
static struct KObservation observationCopy(void){return observation;}
static int observeBirth(struct KExactBirth saved,struct KIdentity *out){*out=saved.identity;return saved.present?kernel[saved.identity.pid]:0;}
static bool sameObservedBirth(const struct KIdentity *a,const struct KIdentity *b){return a->pid==b->pid&&a->birth==b->birth;}
static void signalObservedBirth(struct KExactBirth saved,uid_t owner,uid_t alternate,int sig){
 (void)owner;(void)alternate;if(sig!=SIGKILL)exit(90);if(kernel[saved.identity.pid]==1)signals[saved.identity.pid]++;}
${section('#define K_MACOS_WRITER_CUSTODY_CAP', 'static bool macosRetainActor(')}
${section('static bool macosSweepWriterCustody(', 'static bool validFixedWriterCustody(')}
static void check(bool ok,const char *label){if(!ok){fprintf(stderr,"FAIL %s\\n",label);exit(1);}printf("PASS %s\\n",label);}
static void reset(void){memset(gMacosCustody,0,sizeof(gMacosCustody));memset(&observation,0,sizeof(observation));
 memset(signals,0,sizeof(signals));for(unsigned i=0;i<16;i++)kernel[i]=1;clockValue=100;gClockFailed=false;gStopping=false;
 struct KMacosWriterCustody item={.valid=true,.owner=501,.deadline=1000,
 .controller={.identity={1,1},.present=true},.writer={.identity={2,2},.present=true},.guardian={.identity={3,3},.present=true}};
 strcpy(item.attempt,"attempt");gMacosCustody[0]=item;}
int main(void){
 reset();check(macosSweepWriterCustody()&&signals[2]==0&&signals[3]==0,"healthy-writer-retained");
 observation.valid=false;observation.planned_terminal=true;strcpy(observation.attempt,"attempt");
 check(macosSweepWriterCustody()&&signals[2]==0,"planned-command-retirement-does-not-release-or-kill-writer");
 kernel[1]=0;check(macosSweepWriterCustody()&&signals[2]==1&&signals[3]==1&&gMacosCustody[0].stopped,"controller-loss-stops-both-exact-actors");
 kernel[1]=1;macosSweepWriterCustody();check(signals[2]==2&&gMacosCustody[0].stopped,"owner-reappearance-cannot-reopen-stopped-custody");
 reset();kernel[1]=kernel[3]=0;check(macosSweepWriterCustody()&&signals[2]==1,"guardian-and-controller-death-still-kills-writer");
 reset();kernel[3]=-1;check(macosSweepWriterCustody()&&signals[2]==1,"unknown-guardian-is-stop-not-cleanup");
 reset();clockValue=1000;check(macosSweepWriterCustody()&&signals[2]==1,"original-deadline-is-not-renewed");
 reset();gClockFailed=true;check(macosSweepWriterCustody()&&signals[2]==1,"clock-failure-keeps-custody-and-stops-writer");
 reset();gStopping=true;check(macosSweepWriterCustody()&&signals[2]==1,"daemon-stop-preserves-enforcement");
 reset();kernel[2]=0;check(macosSweepWriterCustody()&&gMacosCustody[0].valid&&signals[3]==0,"writer-exit-alone-retains-live-guardian");
 kernel[3]=0;check(!macosSweepWriterCustody()&&!gMacosCustody[0].valid,"only-both-exact-exits-retire-custody");
 reset();observation.abort_latched=true;strcpy(observation.attempt,"other");macosSweepWriterCustody();check(signals[2]==0,"other-attempt-abort-does-not-kill-this-writer");
 strcpy(observation.attempt,"attempt");macosSweepWriterCustody();check(signals[2]==1,"matching-abort-stops-writer");
 reset();gMacosCustody[1]=gMacosCustody[0];gMacosCustody[1].authority=true;
 gMacosCustody[1].writer.identity.pid=4;gMacosCustody[1].guardian.identity.pid=5;kernel[4]=kernel[5]=0;
 check(macosSweepWriterCustody()&&gMacosCustody[0].valid&&!gMacosCustody[1].valid,"authority-retirement-does-not-release-state-writer");
 reset();gMacosCustody[0].stopped=true;check(macosSweepWriterCustody()&&signals[2]==1,"restart-kill-only-ticket-cannot-resume-work");
 reset();gMacosCustody[0].standalone=true;gMacosCustody[0].continuous_deadline=200000000ull;
 check(!macosAdmissionCustodyActive()&&gMacosCustody[0].valid,"fixed-storage-custody-does-not-block-private-UID-prepare");
 clockValue=200;check(macosSweepWriterCustody()&&signals[2]==1,"fixed-storage-original-raw-deadline-is-enforced");
 reset();gMacosCustody[0].standalone=true;observation.abort_latched=true;strcpy(observation.attempt,"attempt");
 macosSweepWriterCustody();check(signals[2]==0,"fixed-storage-ticket-is-not-an-unrelated-UID-command-scope");
 reset();struct KMacosWriterCustody retry=gMacosCustody[0];gMacosCustody[7]=retry;gMacosCustody[0].valid=false;
 check(macosKeepCustodyTicket(retry,false)&&!gMacosCustody[0].valid&&gMacosCustody[7].valid,"retry-finds-existing-ticket-after-an-earlier-free-slot");
 gMacosCustody[7].stopped=true;check(!macosKeepCustodyTicket(retry,false)&&gMacosCustody[7].stopped&&!gMacosCustody[0].valid,
 "retry-cannot-revive-a-stopped-ticket-in-a-new-free-slot");
 reset();retry=gMacosCustody[0];retry.deadline++;
 check(!macosKeepCustodyTicket(retry,false)&&gMacosCustody[0].deadline==1000,"retry-cannot-extend-original-ticket-deadline");
 retry=gMacosCustody[0];retry.controller.identity.birth++;
 check(!macosKeepCustodyTicket(retry,false),"retry-cannot-transfer-custody-to-another-controller-birth");
 return 0;}
`;
      const file = path.join(root, 'custody.c'), binary = path.join(root, 'custody');fs.writeFileSync(file, code);
      const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-pthread', file, '-o', binary], { encoding: 'utf8', timeout: 15000 });
      assert.equal(built.status, 0, built.stderr || built.error?.message);
      const result = cp.spawnSync(binary, [], { encoding: 'utf8', timeout: 5000 });
      assert.equal(result.status, 0, result.stderr || result.stdout);assert.equal(result.stdout.trim().split('\n').length, 22);
      console.log(JSON.stringify({ scope: 'exact-native-custody-sweep; modeled-kernel; not-macOS-qualification',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'), checks: result.stdout.trim().split('\n') }));
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });

test('fixed writer exit fallback preserves birth across exec and signals only the fresh audit-token version',
  { skip: cp.spawnSync(compiler, ['--version']).status !== 0 }, () => {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'macos-writer-birth-'));
    try {
      const code = `#define _GNU_SOURCE 1
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct { uint32_t val[8]; } audit_token_t;
typedef int (*KSignalToken)(const audit_token_t *,int);
${section('struct KStorageBirth {', 'static volatile sig_atomic_t kvsSignal;')}
static struct KStorageBirth observed;
static int observedState=1,signalCount;
static uint32_t signaledVersion;
static bool kvsReadBirth(pid_t pid,struct KStorageBirth *out){
 if(observedState!=1){errno=observedState==0?ESRCH:EPERM;return false;}
 if(pid!=observed.pid)exit(90);*out=observed;return true;}
static int modelSignal(const audit_token_t *token,int sig){
 if(sig!=SIGKILL||token->val[5]!=(uint32_t)observed.pid)exit(91);
 signalCount++;signaledVersion=token->val[7];return token->val[7]==observed.version?0:ESRCH;}
#define RTLD_DEFAULT ((void*)0)
static void *modelDlsym(void *ignored,const char *name){
 (void)ignored;if(strcmp(name,"proc_signal_with_audittoken"))exit(92);
 KSignalToken fn=modelSignal;void *symbol=NULL;memcpy(&symbol,&fn,sizeof(symbol));return symbol;}
#define dlsym modelDlsym
#ifndef __APPLE__
#define __APPLE__ 1
#endif
${section('static bool kvsSame(', 'static int kvsBirthJSON(')}
static void check(bool ok,const char *name){if(!ok){fprintf(stderr,"FAIL %s\\n",name);exit(1);}printf("PASS %s\\n",name);}
int main(void){
 struct KStorageBirth saved={.pid=10,.uid=501,.unique=100,.parent_unique=5,.start_sec=50,.start_usec=10,.version=7};
 observed=saved;observed.version=8;
 check(kvsSame(&saved,&observed)&&kvsObserve(&saved)==1,"same-kernel-birth-after-exec-is-still-active");
 check(kvsSignalExact(&saved)&&signalCount==1&&signaledVersion==8,"post-exec-signal-uses-fresh-current-version");
 observed.unique++;check(kvsObserve(&saved)==0&&kvsSignalExact(&saved)&&signalCount==1,"recycled-pid-is-never-signaled");
 observed=saved;observed.start_usec++;check(kvsObserve(&saved)==0,"different-start-birth-is-not-old-writer");
 observed=saved;observedState=-1;check(kvsObserve(&saved)==-1&&!kvsSignalExact(&saved)&&signalCount==1,"unknown-birth-is-not-exit-proof");
 observedState=0;check(kvsObserve(&saved)==0&&kvsSignalExact(&saved),"kernel-ESRCH-proves-old-writer-exit");
 return 0;}
`;
      const file = path.join(root, 'birth.c'), binary = path.join(root, 'birth');fs.writeFileSync(file, code);
      const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', file, '-o', binary], { encoding: 'utf8', timeout: 15000 });
      assert.equal(built.status, 0, built.stderr || built.error?.message);
      const result = cp.spawnSync(binary, [], { encoding: 'utf8', timeout: 5000 });
      assert.equal(result.status, 0, result.stderr || result.stdout);assert.equal(result.stdout.trim().split('\n').length, 6);
      console.log(JSON.stringify({ scope: 'exact-native-storage-birth-and-signal; modeled-kernel; not-macOS-qualification',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'), checks: result.stdout.trim().split('\n') }));
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
