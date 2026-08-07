# RC57 release matrix kit

This kit tests the exact frozen RC57 candidate from an external replay harness. It never copies
source-only tools into the candidate `.knowledge` directory.

Linux x64 / Node 22.16.0 is included as a completed cell. Execute the eight pending cells in
`MATRIX-PLAN.json` using the instructions in `RC57-OS-NODE-MATRIX-PROMPT.md`.

Verify `CHECKSUMS.sha256` before running anything.
