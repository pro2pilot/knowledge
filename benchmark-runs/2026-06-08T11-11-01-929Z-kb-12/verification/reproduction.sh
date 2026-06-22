#!/usr/bin/env sh
set -eu
node .knowledge/benchmarks/run-benchmarks.js --suite KB-12 --runs 1 --json
node .knowledge/benchmarks/generate-marketing-pack.js --latest --json
