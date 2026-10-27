'use strict';

// Exact broker boolean ordering, compiled as C. Objective-C readback booleans
// and the clock callback are explicitly modeled; no native Darwin claim.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const input = process.env.KNOWLEDGE_DARWIN_BROKER_TEST_SOURCE ||
  path.join(__dirname, '../tools/lib/verification-darwin-broker.m');
const source = fs.readFileSync(input, 'utf8');
function expression(marker, statement, prefix) {
  const base = source.indexOf(marker), start = source.indexOf(statement, base);
  const end = source.indexOf('){', start);
  assert.ok(base >= 0 && start > base && end > start, 'exact drain branch must be extractable');
  const head = source.slice(base, start).match(new RegExp('uint64_t '+prefix+'=nowMS\\(\\);'))?.[0] || '';
  const condition = source.slice(start + 3, end)
    .replace('![drainReply[@"allocation_tuple_verified_current"] boolValue]', '!allocationCurrent')
    .replace('![drainReply[@"registry_healthy"] boolValue]', '!registryHealthy');
  assert.equal(condition.includes('@'), false, 'only the two declared Objective-C boolean reads are modeled');
  return head + '\nreturn ' + condition + ';';
}
const initial = expression('if(gDrainOnly){struct KIdentity controller;', 'if(!ownerAlive||', 'drainNow');
const final = expression('/* Status performs another disk readback.', 'if(gStopping||', 'drainCompletionNow');
const compiler = process.env.CC || 'cc';
const available = cp.spawnSync(compiler, ['--version'], { encoding: 'utf8' });

test('clock errors latched by the final drain time sample reject that same positive phase',
  { skip: available.error ? 'Portable C compiler unavailable: ' + available.error.code : false }, async t => {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-drain-clock-'));
    const cfile = path.join(root, 'drain.c'), binary = path.join(root, process.platform === 'win32' ? 'drain.exe' : 'drain');
    fs.writeFileSync(cfile, `
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
static bool gStopping,gPoisoned,fault,latched;
static _Atomic bool gClockFailed;
static uint64_t observed=100,gCloseDeadline=1000;
static uint64_t nowMS(void){if(fault){atomic_store(&gClockFailed,true);gStopping=true;}return observed;}
static bool stoppedAttempt(int e){(void)e;return latched;}
static bool initial(void){int e=0;bool ownerAlive=true,uidExclusive=true;${initial}}
static bool final(void){int e=0;bool historyStillConfirmed=true,ownersStillAlive=true,allocationCurrent=true,registryHealthy=true;${final}}
int main(int argc,char **argv){
  if(argc!=3)return 64;
  const char *mode=argv[2];bool expected=true;
  if(!strcmp(mode,"healthy"))expected=false;
  else if(!strcmp(mode,"new-clock-failure"))fault=true;
  else if(!strcmp(mode,"prior-clock-failure"))atomic_store(&gClockFailed,true);
  else if(!strcmp(mode,"deadline"))observed=gCloseDeadline;
  else if(!strcmp(mode,"stopping"))gStopping=true;
  else if(!strcmp(mode,"generation-stop"))latched=true;
  else return 64;
  bool rejected=!strcmp(argv[1],"initial")?initial():final();
  printf("DRAIN rejected=%u clock_failed=%u stopped=%u\\n",rejected,atomic_load(&gClockFailed),gStopping);
  return rejected==expected?0:1;
}
`);
    try {
      const built = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', cfile, '-o', binary],
        { encoding: 'utf8', timeout: 60000 });
      assert.equal(built.status, 0, (built.stderr || '') + (built.error?.message || ''));
      console.log(JSON.stringify({ scope: 'exact-production-drain-condition-order; modeled-clock/readback; not-native-Darwin',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'),
        binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex') }));
      for (const edge of ['initial', 'final']) for (const name of ['healthy', 'new-clock-failure',
        'prior-clock-failure', 'deadline', 'stopping', 'generation-stop']) await t.test(edge + '/' + name, () => {
        const run = cp.spawnSync(binary, [edge, name], { encoding: 'utf8', timeout: 3000 });
        console.log(JSON.stringify({ edge, case: name, status: run.status, signal: run.signal,
          stdout: run.stdout, stderr: run.stderr, error: run.error?.code || null }));
        assert.equal(run.status, 0, run.stdout + run.stderr + (run.error?.message || ''));
        assert.equal(run.signal, null);
      });
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
