# Pro2Pilot .knowledge 3.3.0 RC57 — remaining OS/Node compatibility matrix

Work only with the immutable files in `rc57-release-matrix-kit.zip`.
Do not modify the RC57 candidate, do not patch extracted fixtures, and do not publish,
push, deploy, create a GitHub Release, or create a Discussion.

## Frozen inputs

- Candidate: `knowledge-v3.3.0-step1-rc4-r57.zip`
- Candidate SHA-256: `49bb9054512fdfab05fe8c30a5ff591bdff6c0f206cfde18fea224434802f5c5`
- Public upgrade baseline: `knowledge-v3.2.11.zip`
- Baseline SHA-256: `b7f4e912e8bcffff1e2ffb35756d68850a980b6b841306ac7a51c9d88fc59d79`
- RC57 source commit: `4472a92dc3b31d6c111fa169a6d5dc37e62cb485`

Linux x64 / Node 22.16.0 is already included as a passing physical cell. Do not
count it twice. The remaining required cells are:

1. Linux x64 / Node 18
2. Linux x64 / Node 20
3. Windows x64 / Node 18
4. Windows x64 / Node 20
5. Windows x64 / Node 22
6. macOS x64 / Node 18
7. macOS x64 / Node 20
8. macOS x64 / Node 22

Use a real runtime for every cell. Emulation or changing `process.version` is not valid.

## Per-cell procedure

1. Verify `CHECKSUMS.sha256` before execution.
2. Create a new short, empty work root. On Windows use a path such as `C:\km\r57-w18`.
3. Keep the candidate and `replay/` immutable and external to the extracted `.knowledge` fixture.
4. Invoke the current cell's Node executable:

```text
node run-matrix-cell.js
  --candidate <absolute>/knowledge-v3.3.0-step1-rc4-r57.zip
  --replay <absolute>/replay
  --baseline <absolute>/knowledge-v3.2.11.zip
  --out <new-cell-output>
  --os <linux|windows|macos>
  --node-major <18|20|22>
  --upgrade=<true only for Windows/macOS Node 22; false otherwise>
  --expected-candidate 49bb9054512fdfab05fe8c30a5ff591bdff6c0f206cfde18fea224434802f5c5
  --expected-baseline b7f4e912e8bcffff1e2ffb35756d68850a980b6b841306ac7a51c9d88fc59d79
  --source-commit 4472a92dc3b31d6c111fa169a6d5dc37e62cb485
```

5. Require:
   - candidate validation pass;
   - JavaScript syntax pass;
   - 26/26 shipped self-tests;
   - 12/12 agent integrations;
   - install-check before and after pass;
   - flow import and release pass;
   - Doctor command pass;
   - Inspector build and live start/state/shutdown pass;
   - task routing pass;
   - Field Report start pass;
   - no active, stale, or unsafe lock remains;
   - exact 3.2.11 upgrade pass in Windows/macOS Node 22 cells.
6. Preserve the complete output directory, including `result.json`, `environment.json`,
   `commands.json`, stdout, stderr, self-test report, workflow report, lock report,
   upgrade report, and checksums.

## Failure loop

If a cell fails:

1. Preserve the first failure unchanged.
2. Repeat only the failing command three times in new fixtures.
3. Classify the result as `candidate`, `harness`, `environment`, or `unsupported`.
4. Do not patch RC57 inside a cell.
5. A reproducible candidate defect blocks the matrix and requires a new RC58 candidate.
6. A harness defect may be fixed only outside the candidate; rerun every affected cell afterward.

## Return

Return one portable archive containing:

- `MATRIX-SUMMARY.md`;
- `matrix.json` and `matrix.csv`;
- all eight new cell directories;
- the included Linux Node 22 result;
- candidate and baseline SHA verification;
- per-cell checksum verification;
- exact-upgrade summary;
- unsupported/limitations list;
- final verdict.

Do not claim `9/9` unless all eight pending cells pass and the supplied Linux Node 22 cell
is independently checksum-valid.
