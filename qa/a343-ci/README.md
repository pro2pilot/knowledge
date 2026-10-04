# Knowledge 3.4.3 compatibility test inputs

This branch contains the exact candidate ZIP and an external, offline test harness.
It is a test branch, not an official release. Conformance remains blocked until
all required evidence, including a fresh live memory-provider comparison, passes.

Each OS/Node cell runs all 44 bundled self-tests, 144 JavaScript syntax checks,
installation, all 12 agent integrations, import/release flows, Doctor, authenticated
Inspector state/shutdown, and final lock safety. Node 22 additionally checks the
exact pinned 3.2.11 upgrade. Only synthetic fixtures disable automatic updates;
the frozen candidate and its source snapshot remain unchanged. No optional
providers are installed and no model APIs are called by this workflow.

Raw receipts bind the candidate hash, executing commit, runtime and workflow run.
