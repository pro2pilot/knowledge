#!/usr/bin/env sh
set -eu
node .knowledge/benchmarks/run-benchmarks.js --suite all --runs 5 --json
node .knowledge/benchmarks/generate-marketing-pack.js --latest --json
