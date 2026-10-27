from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("slice_controller_under_test", HERE / "controller.py")
assert spec and spec.loader
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)

NODE_HARNESS = r"""
const vm = require('node:vm');
const path = require('node:path').posix;
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const mode = process.argv[1];
let source = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => source += chunk);
process.stdin.on('end', async () => {
  const registered = [];
  let compiled = false;
  const readyPath = '/scratch/descendant-ready.json';
  const markerPath = '/scratch/descendant.txt';
  const fakeFs = {
    readFileSync(file, encoding) {
      if (String(file).endsWith('/input.txt')) return 'component-slice-input-v1\n';
      if (mode === 'early-exit') {
        const e = new Error('not ready'); e.code = 'ENOENT'; throw e;
      }
      if (String(file) === readyPath) return JSON.stringify({pid: 777, uid: 1000010301, version: 'v22.17.1'});
      if (String(file) === markerPath) return '1\n2\n';
      throw new Error('unexpected fake fs read: ' + file);
    },
    writeFileSync(file) {
      if (String(file).endsWith('/input.txt')) { const e = new Error('read only'); e.code = 'EROFS'; throw e; }
    }
  };
  const fakeProcess = {
    env: {KNOWLEDGE_SLICE_SCRATCH: '/scratch'},
    version: 'v22.17.1',
    pid: 99,
    getuid: () => 1000010301,
    geteuid: () => 1000010301,
    getgid: () => 1000010301,
    cwd: () => '/source'
  };
  const spawn = (_exe, args) => {
    new vm.Script(args[1]);
    compiled = true;
    const child = new EventEmitter();
    child.pid = 777;
    child.unref = () => {};
    queueMicrotask(() => {
      child.emit('spawn');
      if (mode === 'early-exit') child.emit('exit', 1, null);
    });
    return child;
  };
  const sandbox = {
    require(name) {
      if (name === 'node:test') return (_name, fn) => registered.push(fn);
      if (name === 'node:assert/strict') return assert;
      if (name === 'node:fs') return fakeFs;
      if (name === 'node:path') return path;
      if (name === 'node:child_process') return {spawn};
      throw new Error('unexpected require ' + name);
    },
    process: fakeProcess,
    console,
    Buffer,
    Date,
    JSON,
    Promise,
    setTimeout: fn => setImmediate(fn),
    clearTimeout,
    setInterval,
    clearInterval
  };
  try {
    vm.runInNewContext(source, sandbox, {filename: 'generated-tests/read-only.test.js'});
    if (registered.length !== 1) throw new Error('expected exactly one generated test');
    await registered[0]();
    process.stdout.write(JSON.stringify({ok: true, compiledChild: compiled}) + '\n');
  } catch (error) {
    process.stdout.write(JSON.stringify({ok: false, compiledChild: compiled, error: String(error && error.message || error)}) + '\n');
  }
});
"""


def run_generated(mode: str) -> dict:
    node = os.environ.get("NODE_BINARY") or shutil.which("node")
    if not node:
        raise unittest.SkipTest("Node.js is unavailable")
    result = subprocess.run(
        [node, "-e", NODE_HARNESS, mode],
        input=controller.test_script_bytes(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"Node harness exited {result.returncode}: {result.stderr.decode('utf-8', 'replace')}")
    return json.loads(result.stdout.decode("utf-8").splitlines()[-1])


class GeneratedChildFixtureTests(unittest.TestCase):
    def test_actual_generated_detached_writer_source_parses_and_runs_readiness(self):
        result = run_generated("normal")
        self.assertEqual(result, {"ok": True, "compiledChild": True})

    def test_actual_generated_fixture_reports_child_early_exit(self):
        result = run_generated("early-exit")
        self.assertFalse(result["ok"])
        self.assertTrue(result["compiledChild"])
        self.assertIn("detached writer exited before readiness", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
