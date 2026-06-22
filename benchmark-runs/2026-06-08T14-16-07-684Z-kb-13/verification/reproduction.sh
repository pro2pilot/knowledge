#!/usr/bin/env sh
set -eu
node .knowledge/benchmarks/run-benchmarks.js --suite KB-13 --runs 3 --json
node .knowledge/benchmarks/generate-marketing-pack.js --latest --json
