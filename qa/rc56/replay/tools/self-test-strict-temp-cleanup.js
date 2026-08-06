#!/usr/bin/env node
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { removeTempDirStrict, withTempFixture } = require('./lib/strict-temp-cleanup');
const outputArg = process.argv.find((arg) => arg.startsWith('--output='));
const outputPath = outputArg ? path.resolve(outputArg.slice('--output='.length)) : null;
const results = [];
function check(id, fn) { try { fn(); results.push({ id, status: 'pass' }); } catch (error) { results.push({ id, status: 'fail', error: error.message }); } }
function fixture(name) { const dir = fs.mkdtempSync(path.join(os.tmpdir(), `strict-cleanup-${name}-`)); fs.writeFileSync(path.join(dir, 'left.txt'), 'x'); return dir; }
function retry(code, failures) { let n = 0; return (dir) => { n++; if (n <= failures) { const e = new Error(code); e.code = code; throw e; } fs.rmSync(dir, { recursive: true, force: true }); }; }
check('first-attempt', () => { const d = fixture('first'); const r = removeTempDirStrict(d); if (r.attempts !== 1) throw new Error('attempts'); });
for (const [code, failures] of [['EBUSY', 3], ['EPERM', 1], ['ENOTEMPTY', 1]]) check(`transient-${code}`, () => { const d = fixture(code); const r = removeTempDirStrict(d, { remove: retry(code, failures), initialDelayMs: 0 }); if (r.attempts !== failures + 1) throw new Error('retry count'); });
for (const code of ['EBUSY', 'EPERM', 'ENOTEMPTY']) check(`persistent-${code}`, () => { const d = fixture(`p-${code}`); try { removeTempDirStrict(d, { attempts: 2, initialDelayMs: 0, remove: retry(code, 99) }); throw new Error('accepted'); } catch (e) { if (e.code !== 'TEMP_FIXTURE_CLEANUP_FAILED' || e.reason !== 'persistent_resource_lock' || !e.cause || !e.remaining_entries.includes('left.txt')) throw e; } finally { fs.rmSync(d, { recursive: true, force: true }); } });
check('non-retryable-EACCES', () => { const d = fixture('eacces'); try { removeTempDirStrict(d, { remove: retry('EACCES', 1) }); throw new Error('accepted'); } catch (e) { if (e.reason !== 'non_retryable_cleanup_error' || e.attempts !== 1) throw e; } finally { fs.rmSync(d, { recursive: true, force: true }); } });
check('still-exists', () => { const d = fixture('still'); try { removeTempDirStrict(d, { attempts: 1, remove: () => {} }); throw new Error('accepted'); } catch (e) { if (e.last_error_code !== 'STILL_EXISTS') throw e; } finally { fs.rmSync(d, { recursive: true, force: true }); } });
for (const [id, options] of [
  ['invalid-options', []],
  ['invalid-attempts', { attempts: 0 }],
  ['invalid-initial-delay', { initialDelayMs: -1 }],
  ['invalid-max-delay', { maxDelayMs: -1 }],
  ['invalid-elapsed', { maxElapsedMs: 0 }],
  ['invalid-remove', { remove: 1 }],
  ['invalid-exists', { exists: 1 }],
  ['invalid-list-entries', { listEntries: 1 }],
  ['invalid-sleep', { sleep: 1 }]
]) check(id, () => { try { removeTempDirStrict('unused', options); throw new Error('accepted'); } catch (e) { if (!(e instanceof TypeError)) throw e; } });
check('attempts-one-not-defaulted', () => { const d = fixture('attempt-one'); try { removeTempDirStrict(d, { attempts: 1, initialDelayMs: 0, remove: retry('EBUSY', 99) }); throw new Error('accepted'); } catch (e) { if (e.attempts !== 1 || e.diagnostics.length !== 1) throw e; } finally { fs.rmSync(d, { recursive: true, force: true }); } });
check('initial-delay-zero-not-defaulted', () => { const d = fixture('zero-delay'); const waits = []; const r = removeTempDirStrict(d, { initialDelayMs: 0, remove: retry('EBUSY', 1), sleep: (ms) => waits.push(ms) }); if (r.attempts !== 2 || waits.length !== 0) throw new Error(`unexpected waits: ${waits}`); });
check('max-delay-caps-backoff', () => { const d = fixture('max-delay'); const waits = []; const r = removeTempDirStrict(d, { initialDelayMs: 25, maxDelayMs: 30, remove: retry('EBUSY', 3), sleep: (ms) => waits.push(ms) }); if (r.attempts !== 4 || JSON.stringify(waits) !== JSON.stringify([25, 30, 30])) throw new Error(`unexpected waits: ${waits}`); });
check('default-max-delay-is-1600', () => { const d = fixture('default-max-delay'); const waits = []; removeTempDirStrict(d, { initialDelayMs: 1000, remove: retry('EBUSY', 3), sleep: (ms) => waits.push(ms) }); if (JSON.stringify(waits) !== JSON.stringify([1000, 1600, 1600])) throw new Error(`unexpected default cap: ${waits}`); });
check('injected-exists-and-list-entries', () => { const d = fixture('injected-probes'); let existsCalls = 0; let listCalls = 0; try { removeTempDirStrict(d, { attempts: 1, initialDelayMs: 0, remove: retry('EBUSY', 99), exists: () => { existsCalls++; return true; }, listEntries: () => { listCalls++; return ['injected.txt']; } }); throw new Error('accepted'); } catch (e) { if (!e.remaining_entries.includes('injected.txt') || existsCalls < 1 || listCalls < 1) throw e; } finally { fs.rmSync(d, { recursive: true, force: true }); } });
check('bounded-elapsed-structured', () => { const d = fixture('bounded'); const t = Date.now(); try { removeTempDirStrict(d, { attempts: 99, initialDelayMs: 1, maxDelayMs: 2, maxElapsedMs: 8, remove: retry('EBUSY', 999) }); throw new Error('accepted'); } catch (e) { if (e.name !== 'TempFixtureCleanupError' || e.code !== 'TEMP_FIXTURE_CLEANUP_FAILED' || e.reason !== 'persistent_resource_lock' || e.elapsed_ms < 0 || e.last_error_code !== 'EBUSY' || !Array.isArray(e.remaining_entries) || !Array.isArray(e.diagnostics) || !e.cause || Date.now() - t > 250) throw e; } finally { fs.rmSync(d, { recursive: true, force: true }); } });
check('fixture-lifecycle-success-cleanup', () => { let observed; withTempFixture({ prefix: 'strict-lifecycle-' }, (dir) => { observed = dir; fs.writeFileSync(path.join(dir, 'canary.txt'), 'x'); }); if (!observed || fs.existsSync(observed)) throw new Error('successful fixture was not cleaned'); });
check('fixture-lifecycle-failure-preserved', () => { const evidence = fs.mkdtempSync(path.join(os.tmpdir(), 'strict-lifecycle-evidence-')); let observed; try { withTempFixture({ prefix: 'strict-lifecycle-', evidenceDir: evidence, evidenceLabel: 'failure' }, (dir) => { observed = dir; fs.writeFileSync(path.join(dir, 'canary.txt'), 'x'); throw new Error('EXPECTED_FIXTURE_FAILURE'); }); throw new Error('accepted'); } catch (error) { const preserved = fs.readdirSync(evidence); if (error.message !== 'EXPECTED_FIXTURE_FAILURE' || !error.fixture_evidence_path || preserved.length !== 1 || !fs.existsSync(path.join(error.fixture_evidence_path, 'canary.txt')) || !fs.existsSync(path.join(error.fixture_evidence_path, 'failure.txt'))) throw error; if (fs.existsSync(observed)) throw new Error('failed original fixture was not cleaned'); } finally { fs.rmSync(evidence, { recursive: true, force: true }); } });
check('fixture-lifecycle-combined-error', () => { const evidence = fs.mkdtempSync(path.join(os.tmpdir(), 'strict-lifecycle-combined-')); let observed; try { withTempFixture({ prefix: 'strict-lifecycle-', evidenceDir: evidence, evidenceLabel: 'combined', cleanupOptions: { attempts: 1, initialDelayMs: 0, remove: retry('EBUSY', 99) } }, (dir) => { observed = dir; fs.writeFileSync(path.join(dir, 'canary.txt'), 'x'); throw new Error('EXPECTED_CALLBACK_FAILURE'); }); throw new Error('accepted'); } catch (error) { if (!(error instanceof AggregateError) || error.name !== 'TempFixtureLifecycleError' || error.code !== 'TEMP_FIXTURE_CALLBACK_AND_CLEANUP_FAILED' || error.callback_error?.message !== 'EXPECTED_CALLBACK_FAILURE' || error.cleanup_error?.code !== 'TEMP_FIXTURE_CLEANUP_FAILED' || error.errors.length !== 2 || !error.fixture_evidence_path) throw error; } finally { if (observed) fs.rmSync(observed, { recursive: true, force: true }); fs.rmSync(evidence, { recursive: true, force: true }); } });
const failed = results.filter((r) => r.status !== 'pass');
const report = { schema_version: 'strict-temp-cleanup-test.v1', status: failed.length ? 'fail' : 'pass', checks_total: results.length, results };
if (outputPath) { fs.mkdirSync(path.dirname(outputPath), { recursive: true }); fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8'); }
console.log(JSON.stringify(report, null, 2));
if (failed.length) process.exit(1);
