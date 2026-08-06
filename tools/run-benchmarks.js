#!/usr/bin/env node
'use strict';

const { main } = require('../benchmarks/run-benchmarks');

main(process.argv.slice(2));
